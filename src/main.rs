use std::{
    path::PathBuf,
    sync::Arc,
};

use anyhow::Context as _;
use clap::Parser as _;
use tracing::info;

use prometheus_scrape_rs::{
    config,
    remote_write,
    scrape,
};

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
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .parse_lossy(&args.log_level),
        )
        .init();

    let config = Arc::new(
        config::load(&args.config_file)
            .with_context(|| format!("loading config {}", args.config_file.display()))?,
    );
    info!(
        config = %args.config_file.display(),
        jobs = config.scrape_configs.len(),
        remote_writes = config.remote_write.len(),
        "configuration loaded"
    );
    if config.remote_write.is_empty() {
        anyhow::bail!("no remote_write endpoints configured; scraped data would be discarded");
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?
        .block_on(run(config))
}

async fn run(config: Arc<config::Config>) -> anyhow::Result<()> {
    let (remote_handle, sender_tasks) =
        remote_write::spawn(&config.remote_write).context("starting remote-write senders")?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let scrape_tasks = scrape::spawn_jobs(&config, &remote_handle, &shutdown_rx);
    drop(shutdown_rx);

    tokio::signal::ctrl_c()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received; stopping scrapes and flushing");

    let _ = shutdown_tx.send(true);
    for task in scrape_tasks {
        let _ = task.await;
    }
    // All scrape loops are gone; dropping the last handle closes the queues
    // so the senders flush pending batches and exit.
    let dropped = remote_handle.total_dropped();
    drop(remote_handle);
    for task in sender_tasks {
        let _ = task.await;
    }
    if dropped > 0 {
        info!(dropped, "series dropped due to full remote-write queues");
    }
    info!("shutdown complete");
    Ok(())
}
