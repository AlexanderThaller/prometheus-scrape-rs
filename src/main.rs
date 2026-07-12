use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::Ordering,
    },
};

use anyhow::Context as _;
use clap::Parser as _;
use tokio::{
    signal::unix::{
        SignalKind,
        signal,
    },
    sync::mpsc,
};
use tracing::{
    error,
    info,
    warn,
};

use prometheus_scrape_rs::{
    config,
    model::Label,
    remote_write,
    remote_write::RemoteWriteHandle,
    scrape,
    telemetry::METRICS,
    web,
    web::{
        LifecycleCommand,
        LifecycleRequest,
        WebState,
    },
};

/// mimalloc outperforms the system allocator for this allocation pattern
/// (many short-lived label/sample strings) and, unlike musl's malloc, stays
/// fast in fully static musl builds.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// A lightweight Prometheus agent: scrape targets, forward via `remote_write`.
#[derive(Debug, clap::Parser)]
#[command(version, about)]
struct Args {
    /// Path to the Prometheus configuration file.
    #[arg(long = "config.file", default_value = "prometheus.yml")]
    config_file: PathBuf,

    /// Log filter, e.g. "info" or "`prometheus_scrape_rs=debug`".
    #[arg(long = "log.level", default_value = "info")]
    log_level: String,

    /// Address for the probe/lifecycle HTTP endpoint (no web UI is served).
    #[arg(long = "web.listen-address", default_value = "0.0.0.0:9090")]
    web_listen_address: String,

    /// Enable the /-/reload and /-/quit lifecycle endpoints.
    #[arg(long = "web.enable-lifecycle")]
    web_enable_lifecycle: bool,

    // Prometheus server flags accepted for drop-in compatibility (e.g. when
    // deployed via prometheus-operator) but without function here. Hidden
    // from --help.
    /// Accepted for Prometheus compatibility; this binary is always an agent.
    #[arg(long = "agent", hide = true)]
    agent: bool,

    /// Accepted for Prometheus compatibility; there is no local storage/WAL.
    #[arg(long = "storage.agent.path", hide = true)]
    storage_agent_path: Option<PathBuf>,

    /// Accepted for Prometheus compatibility; TLS/auth for the web endpoint
    /// is not supported, probes are served over plain HTTP.
    #[arg(long = "web.config.file", hide = true)]
    web_config_file: Option<PathBuf>,

    /// Accepted for Prometheus compatibility; only "/" is supported.
    #[arg(long = "web.route-prefix", hide = true, default_value = "/")]
    web_route_prefix: String,

    /// Run the PGO training workload and exit (container build only).
    #[arg(long = "pgo-training", hide = true)]
    pgo_training: bool,

    /// Directory of *.prom exposition bodies for PGO training.
    #[arg(long = "pgo-corpus", hide = true)]
    pgo_corpus: Option<PathBuf>,
}

impl Args {
    fn warn_ignored(&self) {
        if self.agent {
            info!("--agent: this binary is always an agent; flag accepted for compatibility");
        }
        if let Some(path) = &self.storage_agent_path {
            info!(
                path = %path.display(),
                "--storage.agent.path is ignored: no local storage/WAL"
            );
        }
        if let Some(path) = &self.web_config_file {
            warn!(
                path = %path.display(),
                "--web.config.file is ignored: probe endpoint is plain HTTP without auth"
            );
        }
        if self.web_route_prefix != "/" {
            warn!(
                prefix = self.web_route_prefix,
                "--web.route-prefix is ignored: endpoints are served under /"
            );
        }
    }
}

fn main() -> anyhow::Result<()> {
    prometheus_scrape_rs::auth::ensure_crypto_provider();
    let args = Args::parse();
    if args.pgo_training {
        return prometheus_scrape_rs::pgo::run_training_workload(args.pgo_corpus.as_deref());
    }
    METRICS.mark_started();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .parse_lossy(&args.log_level),
        )
        .init();
    args.warn_ignored();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?
        .block_on(run(&args))
}

fn load_config(path: &std::path::Path) -> anyhow::Result<Arc<config::Config>> {
    let config =
        config::load(path).with_context(|| format!("loading config {}", path.display()))?;
    if config.remote_write.is_empty() {
        anyhow::bail!("no remote_write endpoints configured; scraped data would be discarded");
    }
    info!(
        config = %path.display(),
        jobs = config.scrape_configs.len(),
        remote_writes = config.remote_write.len(),
        "configuration loaded"
    );
    Ok(Arc::new(config))
}

enum StopReason {
    Shutdown,
    Reload,
}

async fn run(args: &Args) -> anyhow::Result<()> {
    let state = Arc::new(WebState::default());
    let (lifecycle_tx, mut lifecycle_rx) = mpsc::channel::<LifecycleRequest>(4);
    let (_addr, _web_task) = web::serve(
        &args.web_listen_address,
        Arc::clone(&state),
        args.web_enable_lifecycle.then_some(lifecycle_tx),
    )
    .await?;

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;

    let mut config = load_config(&args.config_file)?;
    loop {
        let (remote_handle, sender_tasks) =
            remote_write::spawn(&config.remote_write).context("starting remote-write senders")?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let scrape_tasks = scrape::spawn_jobs(&config, &remote_handle, &shutdown_rx);
        let self_monitor = tokio::spawn(self_monitor_loop(
            Arc::clone(&config),
            remote_handle.clone(),
            shutdown_rx,
        ));
        state.ready.store(true, Ordering::Relaxed);

        let reason = wait_for_stop(
            args,
            &mut config,
            &mut lifecycle_rx,
            &mut sigterm,
            &mut sighup,
        )
        .await;

        if matches!(reason, StopReason::Shutdown) {
            state.ready.store(false, Ordering::Relaxed);
        }
        let _ = shutdown_tx.send(true);
        for task in scrape_tasks {
            let _ = task.await;
        }
        let _ = self_monitor.await;
        // All scrape loops are gone; dropping the last handle closes the
        // queues so the senders flush pending batches and exit.
        let dropped = remote_handle.total_dropped();
        drop(remote_handle);
        for task in sender_tasks {
            let _ = task.await;
        }
        if dropped > 0 {
            info!(dropped, "series dropped due to full remote-write queues");
        }

        match reason {
            StopReason::Shutdown => break,
            StopReason::Reload => info!("restarting scrape pipeline with reloaded configuration"),
        }
    }
    info!("shutdown complete");
    Ok(())
}

/// Push the agent's own metrics through the remote-write pipeline every
/// scrape interval, labeled job="prometheus-scrape-rs" plus external
/// labels — self-monitoring works without any discovery finding this pod.
/// The same registry is also served on GET /metrics for normal scraping.
async fn self_monitor_loop(
    config: Arc<config::Config>,
    remote_write: RemoteWriteHandle,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_owned());
    let mut labels = vec![
        Label::new("job", "prometheus-scrape-rs"),
        Label::new("instance", hostname),
    ];
    for (name, value) in &config.global.external_labels {
        if !labels.iter().any(|label| label.name == name) {
            labels.push(Label::new(name.clone(), value.clone()));
        }
    }
    let mut ticker = tokio::time::interval(config.global.scrape_interval.as_duration());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.wait_for(|stop| *stop) => return,
        }
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
            });
        remote_write.send(METRICS.series(&labels, timestamp));
    }
}

/// Wait for a signal or lifecycle request; on reload, the new configuration
/// is validated first — a broken config keeps the current one running,
/// matching Prometheus.
async fn wait_for_stop(
    args: &Args,
    config: &mut Arc<config::Config>,
    lifecycle_rx: &mut mpsc::Receiver<LifecycleRequest>,
    sigterm: &mut tokio::signal::unix::Signal,
    sighup: &mut tokio::signal::unix::Signal,
) -> StopReason {
    // With lifecycle endpoints disabled the sender side is dropped at
    // startup and `recv()` resolves `None` immediately; the arm must stop
    // being polled or this select loop spins at 100% CPU.
    let mut lifecycle_open = true;
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(err) = result {
                    error!(%err, "SIGINT handler failed; shutting down");
                }
                info!("SIGINT received; stopping scrapes and flushing");
                return StopReason::Shutdown;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received; stopping scrapes and flushing");
                return StopReason::Shutdown;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received; reloading configuration");
                match load_config(&args.config_file) {
                    Ok(new_config) => {
                        *config = new_config;
                        return StopReason::Reload;
                    }
                    Err(err) => error!(%err, "config reload failed; keeping current configuration"),
                }
            }
            request = lifecycle_rx.recv(), if lifecycle_open => {
                let Some(request) = request else {
                    lifecycle_open = false;
                    continue;
                };
                match request.command {
                    LifecycleCommand::Quit => {
                        info!("termination requested via /-/quit");
                        let _ = request.respond.send(Ok(()));
                        return StopReason::Shutdown;
                    }
                    LifecycleCommand::Reload => match load_config(&args.config_file) {
                        Ok(new_config) => {
                            info!("configuration reloaded via /-/reload");
                            *config = new_config;
                            let _ = request.respond.send(Ok(()));
                            return StopReason::Reload;
                        }
                        Err(err) => {
                            error!(%err, "config reload failed; keeping current configuration");
                            let _ = request.respond.send(Err(format!("{err:#}")));
                        }
                    },
                }
            }
        }
    }
}
