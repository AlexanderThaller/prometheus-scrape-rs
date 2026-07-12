//! Minimal HTTP endpoint for Kubernetes-style probes and the Prometheus
//! lifecycle API.
//!
//! Serves exactly what an agent deployment needs and nothing more — no web
//! UI, no TSDB endpoints, no TLS:
//!
//! - `GET /-/healthy` — liveness, always 200 while the process runs
//! - `GET /-/ready`   — readiness, 200 once scraping has started
//! - `POST /-/reload` — config reload (403 unless `--web.enable-lifecycle`)
//! - `POST /-/quit`   — graceful shutdown (403 unless lifecycle is enabled)
//!
//! The server is hand-rolled on a `TcpListener`: probe traffic is a handful
//! of tiny GET requests per second, not worth an HTTP framework dependency.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    time::Duration,
};

use anyhow::Context as _;
use tokio::{
    io::{
        AsyncReadExt as _,
        AsyncWriteExt as _,
    },
    net::{
        TcpListener,
        TcpStream,
    },
    sync::{
        mpsc,
        oneshot,
    },
    task::JoinHandle,
};
use tracing::{
    debug,
    info,
    warn,
};

/// Shared readiness flag; flipped by the main loop.
#[derive(Debug, Default)]
pub struct WebState {
    pub ready: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleCommand {
    Reload,
    Quit,
}

/// A lifecycle request from the HTTP API; the main loop answers via
/// `respond` so the HTTP status reflects the actual outcome.
#[derive(Debug)]
pub struct LifecycleRequest {
    pub command: LifecycleCommand,
    pub respond: oneshot::Sender<Result<(), String>>,
}

/// Bind `listen_address` and serve probes forever.
///
/// `lifecycle` is `None` when `--web.enable-lifecycle` is not set; the
/// lifecycle endpoints then answer 403 like Prometheus.
pub async fn serve(
    listen_address: &str,
    state: Arc<WebState>,
    lifecycle: Option<mpsc::Sender<LifecycleRequest>>,
) -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(listen_address)
        .await
        .with_context(|| format!("binding web listen address {listen_address}"))?;
    let local_addr = listener
        .local_addr()
        .context("resolving web listen address")?;
    info!(address = %local_addr, lifecycle = lifecycle.is_some(), "web endpoint listening");

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let state = Arc::clone(&state);
            let lifecycle = lifecycle.clone();
            tokio::spawn(async move {
                let served = tokio::time::timeout(
                    Duration::from_secs(5),
                    handle_connection(stream, &state, lifecycle.as_ref()),
                )
                .await;
                match served {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => debug!(%peer, %err, "web connection error"),
                    Err(_) => debug!(%peer, "web connection timed out"),
                }
            });
        }
    });
    Ok((local_addr, handle))
}

async fn handle_connection(
    mut stream: TcpStream,
    state: &WebState,
    lifecycle: Option<&mpsc::Sender<LifecycleRequest>>,
) -> std::io::Result<()> {
    // Read until end of headers; probe requests have no meaningful body.
    let mut request = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..n]);
        if request.windows(4).any(|w| w == b"\r\n\r\n") || request.len() > 8192 {
            break;
        }
    }

    let request_line = std::str::from_utf8(&request)
        .ok()
        .and_then(|s| s.lines().next())
        .unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("").split('?').next().unwrap_or("");

    let (status, body) = route(method, path, state, lifecycle).await;
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: \
         {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

async fn route(
    method: &str,
    path: &str,
    state: &WebState,
    lifecycle: Option<&mpsc::Sender<LifecycleRequest>>,
) -> (&'static str, String) {
    match (method, path) {
        ("GET" | "HEAD", "/metrics") => ("200 OK", crate::telemetry::METRICS.render()),
        ("GET" | "HEAD", "/-/healthy") => ("200 OK", "Healthy.\n".to_owned()),
        ("GET" | "HEAD", "/-/ready") => {
            if state.ready.load(Ordering::Relaxed) {
                ("200 OK", "Ready.\n".to_owned())
            } else {
                ("503 Service Unavailable", "Not ready.\n".to_owned())
            }
        }
        ("POST" | "PUT", "/-/reload") => {
            lifecycle_request(
                lifecycle,
                LifecycleCommand::Reload,
                "Configuration reloaded.\n",
            )
            .await
        }
        ("POST" | "PUT", "/-/quit") => {
            lifecycle_request(
                lifecycle,
                LifecycleCommand::Quit,
                "Requesting termination.\n",
            )
            .await
        }
        ("GET" | "HEAD", "/-/reload" | "/-/quit") => (
            "405 Method Not Allowed",
            "Only POST or PUT requests allowed.\n".to_owned(),
        ),
        _ => (
            "404 Not Found",
            "404 - this agent serves no web UI; probe endpoints are /-/healthy and /-/ready\n"
                .to_owned(),
        ),
    }
}

async fn lifecycle_request(
    lifecycle: Option<&mpsc::Sender<LifecycleRequest>>,
    command: LifecycleCommand,
    success: &str,
) -> (&'static str, String) {
    let Some(lifecycle) = lifecycle else {
        return (
            "403 Forbidden",
            "Lifecycle API is not enabled. Pass --web.enable-lifecycle.\n".to_owned(),
        );
    };
    let (respond, outcome) = oneshot::channel();
    if lifecycle
        .send(LifecycleRequest { command, respond })
        .await
        .is_err()
    {
        return (
            "500 Internal Server Error",
            "lifecycle handler is gone\n".to_owned(),
        );
    }
    match outcome.await {
        Ok(Ok(())) => ("200 OK", success.to_owned()),
        Ok(Err(message)) => {
            warn!(?command, message, "lifecycle request failed");
            ("500 Internal Server Error", format!("{message}\n"))
        }
        Err(_) => (
            "500 Internal Server Error",
            "lifecycle handler dropped the request\n".to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(addr: SocketAddr, path: &str) -> (u16, String) {
        request(addr, "GET", path).await
    }

    async fn request(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
        crate::auth::ensure_crypto_provider();
        let client = reqwest::Client::new();
        let url = format!("http://{addr}{path}");
        let response = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            other => panic!("unsupported test method {other}"),
        }
        .send()
        .await
        .expect("request must succeed");
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        (status, body)
    }

    #[tokio::test]
    async fn probes_reflect_readiness() -> anyhow::Result<()> {
        let state = Arc::new(WebState::default());
        let (addr, _server) = serve("127.0.0.1:0", Arc::clone(&state), None).await?;

        assert_eq!(get(addr, "/-/healthy").await.0, 200);
        assert_eq!(get(addr, "/-/ready").await.0, 503);
        state.ready.store(true, Ordering::Relaxed);
        assert_eq!(get(addr, "/-/ready").await.0, 200);
        assert_eq!(get(addr, "/graph").await.0, 404);
        assert_eq!(get(addr, "/-/reload").await.0, 405);
        Ok(())
    }

    #[tokio::test]
    async fn lifecycle_disabled_returns_forbidden() -> anyhow::Result<()> {
        let (addr, _server) = serve("127.0.0.1:0", Arc::new(WebState::default()), None).await?;
        let (status, body) = request(addr, "POST", "/-/reload").await;
        assert_eq!(status, 403);
        assert!(body.contains("--web.enable-lifecycle"));
        Ok(())
    }

    #[tokio::test]
    async fn lifecycle_round_trips_to_handler() -> anyhow::Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        let (addr, _server) = serve("127.0.0.1:0", Arc::new(WebState::default()), Some(tx)).await?;

        let handler = tokio::spawn(async move {
            let first = rx.recv().await.expect("must receive reload");
            assert_eq!(first.command, LifecycleCommand::Reload);
            first.respond.send(Ok(())).expect("respond ok");
            let second = rx.recv().await.expect("must receive reload");
            second
                .respond
                .send(Err("bad config".to_owned()))
                .expect("respond err");
        });

        assert_eq!(request(addr, "POST", "/-/reload").await.0, 200);
        let (status, body) = request(addr, "POST", "/-/reload").await;
        assert_eq!(status, 500);
        assert!(body.contains("bad config"));
        handler.await?;
        Ok(())
    }
}
