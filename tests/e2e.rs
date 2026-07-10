//! End-to-end test: a fake exporter is scraped and the samples must arrive
//! at a fake remote-write endpoint as a valid snappy-compressed protobuf
//! `WriteRequest`.

use std::{
    io::{
        Read as _,
        Write as _,
    },
    net::TcpListener,
    sync::{
        Arc,
        mpsc,
    },
    time::Duration,
};

use prometheus_scrape_rs::{
    config,
    model::WriteRequest,
    remote_write,
    scrape,
};
use prost::Message as _;

const SCRAPE_BODY: &str = "\
# HELP test_metric A test metric.
# TYPE test_metric counter
test_metric{case=\"e2e\"} 42
";

/// Minimal single-request HTTP server: answer one GET with `body`.
fn serve_scrapes(listener: &TcpListener) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: \
             {}\r\nconnection: close\r\n\r\n{SCRAPE_BODY}",
            SCRAPE_BODY.len()
        );
        let _ = stream.write_all(response.as_bytes());
    }
}

/// Accept one remote-write POST, send its decoded body to `tx`, respond 204.
fn serve_remote_write(listener: &TcpListener, tx: &mpsc::Sender<WriteRequest>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        // Read until the full body (content-length) is in.
        let body = loop {
            let Ok(n) = stream.read(&mut buf) else { return };
            raw.extend_from_slice(&buf[..n]);
            if let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&raw[..header_end]).to_lowercase();
                let content_length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let body_start = header_end + 4;
                if raw.len() >= body_start + content_length {
                    break raw[body_start..body_start + content_length].to_vec();
                }
            }
            if n == 0 {
                return;
            }
        };
        let _ = stream.write_all(
            b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        );

        let decompressed = snap::raw::Decoder::new()
            .decompress_vec(&body)
            .expect("body must be snappy compressed");
        let request =
            WriteRequest::decode(decompressed.as_slice()).expect("body must be a WriteRequest");
        let _ = tx.send(request);
    }
}

#[test]
fn scraped_samples_arrive_via_remote_write() -> anyhow::Result<()> {
    let exporter = TcpListener::bind("127.0.0.1:0")?;
    let exporter_addr = exporter.local_addr()?;
    std::thread::spawn(move || serve_scrapes(&exporter));

    let receiver = TcpListener::bind("127.0.0.1:0")?;
    let receiver_addr = receiver.local_addr()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || serve_remote_write(&receiver, &tx));

    let config_yaml = format!(
        r#"
global:
  scrape_interval: 1s
  external_labels:
    origin: e2e-test
scrape_configs:
  - job_name: e2e
    static_configs:
      - targets: ["{exporter_addr}"]
remote_write:
  - url: http://{receiver_addr}/api/v1/write
    queue_config:
      batch_send_deadline: 200ms
"#
    );
    let dir = std::env::temp_dir().join(format!("prom-scrape-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let config_path = dir.join("prometheus.yml");
    std::fs::write(&config_path, config_yaml)?;

    let config = Arc::new(config::load(&config_path)?);
    std::fs::remove_dir_all(&dir).ok();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let request = runtime.block_on(async move {
        let (handle, _senders) = remote_write::spawn(&config.remote_write)?;
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let _jobs = scrape::spawn_jobs(&config, &handle, &shutdown_rx);
        tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(15)))
            .await?
            .map_err(|_| anyhow::anyhow!("no WriteRequest arrived within 15s"))
    })?;

    let mut found_metric = false;
    let mut found_up = false;
    for series in &request.timeseries {
        let name = series
            .labels
            .iter()
            .find(|l| l.name == "__name__")
            .map_or("", |l| l.value.as_str());
        // Labels must be sorted per the remote-write spec.
        assert!(
            series.labels.windows(2).all(|w| w[0].name < w[1].name),
            "labels of {name} are not sorted: {:?}",
            series.labels
        );
        let get = |want: &str| {
            series
                .labels
                .iter()
                .find(|l| l.name == want)
                .map(|l| l.value.as_str())
        };
        assert_eq!(get("origin"), Some("e2e-test"), "external label missing");
        assert_eq!(get("job"), Some("e2e"));
        match name {
            "test_metric" => {
                found_metric = true;
                assert_eq!(get("case"), Some("e2e"));
                assert_eq!(get("instance"), Some(exporter_addr.to_string().as_str()));
                assert!((series.samples[0].value - 42.0).abs() < f64::EPSILON);
                assert!(series.samples[0].timestamp > 1_700_000_000_000);
            }
            "up" => {
                found_up = true;
                assert!((series.samples[0].value - 1.0).abs() < f64::EPSILON);
            }
            _ => {}
        }
    }
    assert!(found_metric, "test_metric not found in WriteRequest");
    assert!(found_up, "up series not found in WriteRequest");
    Ok(())
}
