//! Scrape pool: builds targets from discovery via target relabeling and runs
//! one jittered scrape loop per target.

use std::{
    sync::Arc,
    time::{
        Duration,
        SystemTime,
        UNIX_EPOCH,
    },
};

use tokio::{
    sync::watch,
    task::JoinHandle,
};
use tracing::{
    debug,
    info,
    warn,
};

use crate::{
    auth::Credentials,
    config::{
        Config,
        GlobalConfig,
        ScrapeConfig,
    },
    model::{
        Label,
        METRIC_NAME_LABEL,
        Sample,
        TimeSeries,
        sort_labels,
    },
    relabel::{
        self,
        RelabelConfig,
    },
    remote_write::RemoteWriteHandle,
    sd::TargetGroup,
};

const EXPORTED_LABEL_PREFIX: &str = "exported_";

/// Spawn one manager task per scrape job. Tasks stop when `shutdown` flips
/// to true.
#[must_use]
pub fn spawn_jobs(
    config: &Arc<Config>,
    remote_write: &RemoteWriteHandle,
    shutdown: &watch::Receiver<bool>,
) -> Vec<JoinHandle<()>> {
    let external_labels: Arc<[Label]> = config
        .global
        .external_labels
        .iter()
        .map(|(name, value)| Label::new(name.clone(), value.clone()))
        .collect();

    config
        .scrape_configs
        .iter()
        .map(|job| {
            let job = Arc::new(job.clone());
            let global = config.global.clone();
            let remote_write = remote_write.clone();
            let shutdown = shutdown.clone();
            let external_labels = Arc::clone(&external_labels);
            tokio::spawn(run_job(
                job,
                global,
                external_labels,
                remote_write,
                shutdown,
            ))
        })
        .collect()
}

async fn run_job(
    job: Arc<ScrapeConfig>,
    global: GlobalConfig,
    external_labels: Arc<[Label]>,
    remote_write: RemoteWriteHandle,
    mut shutdown: watch::Receiver<bool>,
) {
    let client = match crate::auth::build_client(job.timeout(&global), &job.tls_config) {
        Ok(client) => client,
        Err(err) => {
            warn!(job = job.job_name, %err, "cannot build HTTP client; job disabled");
            return;
        }
    };
    let credentials = match Credentials::resolve(
        job.basic_auth.as_ref(),
        job.authorization.as_ref(),
        job.bearer_token.as_deref(),
        job.bearer_token_file.as_deref(),
    ) {
        Ok(credentials) => Arc::new(credentials),
        Err(err) => {
            warn!(job = job.job_name, %err, "cannot resolve credentials; job disabled");
            return;
        }
    };

    let (mut groups_rx, _sd_tasks) = crate::sd::watch(&job);
    let mut target_tasks: Vec<JoinHandle<()>> = Vec::new();
    loop {
        let groups = groups_rx.borrow_and_update().clone();
        for task in target_tasks.drain(..) {
            task.abort();
        }
        let targets = build_targets(&job, &global, &groups, &external_labels);
        info!(
            job = job.job_name,
            targets = targets.len(),
            "scrape targets updated"
        );
        target_tasks = targets
            .into_iter()
            .map(|target| {
                tokio::spawn(scrape_loop(
                    Arc::new(target),
                    client.clone(),
                    Arc::clone(&credentials),
                    remote_write.clone(),
                    shutdown.clone(),
                ))
            })
            .collect();

        let discovery_closed = tokio::select! {
            changed = groups_rx.changed() => changed.is_err(),
            _ = shutdown.wait_for(|stop| *stop) => break,
        };
        if discovery_closed {
            // Static-only job: discovery never changes again.
            let _ = shutdown.wait_for(|stop| *stop).await;
            break;
        }
    }
    for task in target_tasks {
        task.abort();
    }
}

/// A fully resolved scrape target.
#[derive(Debug)]
struct Target {
    url: String,
    params: Vec<(String, String)>,
    /// Sorted, `__`-prefixed labels stripped, includes `job` and `instance`.
    labels: Vec<Label>,
    interval: Duration,
    timeout: Duration,
    honor_labels: bool,
    honor_timestamps: bool,
    sample_limit: u64,
    metric_relabel_configs: Vec<RelabelConfig>,
    external_labels: Arc<[Label]>,
}

/// Prometheus `populateLabels`: seed target labels, run target relabeling,
/// derive URL parts from the resulting `__`-meta labels.
fn build_targets(
    job: &ScrapeConfig,
    global: &GlobalConfig,
    groups: &[TargetGroup],
    external_labels: &Arc<[Label]>,
) -> Vec<Target> {
    let mut targets = Vec::new();
    for group in groups {
        for address in &group.targets {
            let mut labels: Vec<Label> = Vec::with_capacity(group.labels.len() + 8);
            labels.push(Label::new("__address__", address.clone()));
            for (name, value) in &group.labels {
                if name != "__address__" {
                    set_label(&mut labels, name, value.clone());
                }
            }
            // Scrape-config defaults only where discovery did not set them.
            add_if_absent(&mut labels, "job", &job.job_name);
            add_if_absent(&mut labels, "__scheme__", &job.scheme);
            add_if_absent(&mut labels, "__metrics_path__", &job.metrics_path);
            for (param, values) in &job.params {
                if let Some(first) = values.first() {
                    add_if_absent(&mut labels, &format!("__param_{param}"), first);
                }
            }

            let Some(mut labels) = relabel::process(labels, &job.relabel_configs) else {
                debug!(job = job.job_name, address, "target dropped by relabeling");
                continue;
            };

            let address = get_label(&labels, "__address__").to_owned();
            if address.is_empty() {
                warn!(
                    job = job.job_name,
                    "target has empty __address__ after relabeling; skipped"
                );
                continue;
            }
            let scheme = get_label(&labels, "__scheme__").to_owned();
            let mut path = get_label(&labels, "__metrics_path__").to_owned();
            if !path.is_empty() && !path.starts_with('/') {
                path.insert(0, '/');
            }
            let mut params: Vec<(String, String)> = Vec::new();
            for label in &labels {
                if let Some(param) = label.name.strip_prefix("__param_") {
                    params.push((param.to_owned(), label.value.clone()));
                }
            }
            add_if_absent(&mut labels, "instance", &address);

            labels.retain(|label| !label.name.starts_with("__"));
            sort_labels(&mut labels);

            targets.push(Target {
                url: format!("{scheme}://{address}{path}"),
                params,
                labels,
                interval: job.interval(global),
                timeout: job.timeout(global),
                honor_labels: job.honor_labels,
                honor_timestamps: job.honor_timestamps,
                sample_limit: job.sample_limit,
                metric_relabel_configs: job.metric_relabel_configs.clone(),
                external_labels: Arc::clone(external_labels),
            });
        }
    }
    targets
}

async fn scrape_loop(
    target: Arc<Target>,
    client: reqwest::Client,
    credentials: Arc<Credentials>,
    remote_write: RemoteWriteHandle,
    mut shutdown: watch::Receiver<bool>,
) {
    // Deterministic per-target offset spreads scrapes over the interval,
    // like Prometheus' scrapeloop offset.
    let offset_nanos = fnv1a(target.url.as_bytes())
        % u64::try_from(target.interval.as_nanos()).unwrap_or(u64::MAX);
    tokio::select! {
        () = tokio::time::sleep(Duration::from_nanos(offset_nanos)) => {}
        _ = shutdown.wait_for(|stop| *stop) => return,
    }

    let mut ticker = tokio::time::interval(target.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    debug!(url = target.url, "scrape loop started");
    // Log failures on state transitions only: one warning when a target
    // goes down (and one when it recovers), not one per interval.
    let mut last_error: Option<String> = None;
    let mut failures = 0u64;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.wait_for(|stop| *stop) => return,
        }
        let (batch, error) = scrape_once(&target, &client, &credentials).await;
        match (&last_error, &error) {
            (None, Some(message)) => {
                failures = 1;
                warn!(url = target.url, error = message, "target scrape failing");
            }
            (Some(previous), Some(message)) => {
                failures += 1;
                if previous == message {
                    debug!(url = target.url, error = message, failures, "target still failing");
                } else {
                    warn!(
                        url = target.url,
                        error = message,
                        failures,
                        "target scrape still failing, error changed"
                    );
                }
            }
            (Some(_), None) => {
                info!(url = target.url, failures, "target scrape recovered");
                failures = 0;
            }
            (None, None) => {}
        }
        last_error = error;
        remote_write.send(batch);
    }
}

/// Perform one scrape. Returns the batch to forward (always including the
/// synthetic report series) and the failure reason, if the scrape failed.
async fn scrape_once(
    target: &Target,
    client: &reqwest::Client,
    credentials: &Credentials,
) -> (Vec<TimeSeries>, Option<String>) {
    let start_ms = now_ms();
    let started = std::time::Instant::now();
    let result = fetch(target, client, credentials).await;
    let duration = started.elapsed();

    let mut up = 0.0;
    let mut scraped = 0usize;
    let mut kept = 0usize;
    let mut error = None;
    let mut batch: Vec<TimeSeries> = Vec::new();

    match result {
        Ok(body) => match crate::parser::parse(&body, start_ms, target.honor_timestamps) {
            Ok(series) => {
                scraped = series.len();
                if target.sample_limit > 0 && scraped as u64 > target.sample_limit {
                    error = Some(format!(
                        "sample_limit exceeded ({scraped} > {}); scrape discarded",
                        target.sample_limit
                    ));
                } else {
                    up = 1.0;
                    batch.reserve(series.len() + 5);
                    for mut single in series {
                        let labels = merge_target_labels(
                            std::mem::take(&mut single.labels),
                            &target.labels,
                            target.honor_labels,
                        );
                        let Some(mut labels) =
                            relabel::process(labels, &target.metric_relabel_configs)
                        else {
                            continue;
                        };
                        for external in target.external_labels.iter() {
                            add_if_absent(&mut labels, &external.name, &external.value);
                        }
                        sort_labels(&mut labels);
                        single.labels = labels;
                        batch.push(single);
                    }
                    kept = batch.len();
                }
            }
            Err(err) => {
                error = Some(format!("scrape body failed to parse: {err}"));
            }
        },
        Err(err) => {
            error = Some(format!("{err:#}"));
        }
    }

    // Synthetic report series, always emitted (target labels + external).
    let mut report_labels = target.labels.clone();
    for external in target.external_labels.iter() {
        add_if_absent(&mut report_labels, &external.name, &external.value);
    }
    sort_labels(&mut report_labels);
    for (name, value) in [
        ("up", up),
        ("scrape_duration_seconds", duration.as_secs_f64()),
        ("scrape_samples_scraped", to_f64(scraped)),
        ("scrape_samples_post_metric_relabeling", to_f64(kept)),
        ("scrape_series_added", to_f64(kept)),
    ] {
        let mut labels = Vec::with_capacity(report_labels.len() + 1);
        labels.push(Label::new(METRIC_NAME_LABEL, name));
        labels.extend_from_slice(&report_labels);
        sort_labels(&mut labels);
        batch.push(TimeSeries {
            labels,
            samples: vec![Sample {
                value,
                timestamp: start_ms,
            }],
        });
    }
    (batch, error)
}

async fn fetch(
    target: &Target,
    client: &reqwest::Client,
    credentials: &Credentials,
) -> anyhow::Result<String> {
    let mut builder = client
        .get(&target.url)
        .header(
            reqwest::header::ACCEPT,
            "text/plain;version=0.0.4;q=0.5,*/*;q=0.1",
        )
        .header(
            "X-Prometheus-Scrape-Timeout-Seconds",
            format!("{}", target.timeout.as_secs_f64()),
        )
        .timeout(target.timeout);
    if !target.params.is_empty() {
        builder = builder.query(&target.params);
    }
    let response = credentials.apply(builder).send().await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("server returned HTTP {status}");
    }
    Ok(response.text().await?)
}

/// Attach target labels to a scraped series.
///
/// `honor_labels: true` keeps the scraped label on conflict; `false` moves
/// the scraped value to `exported_<name>` and the target label wins.
fn merge_target_labels(
    mut labels: Vec<Label>,
    target_labels: &[Label],
    honor_labels: bool,
) -> Vec<Label> {
    for target_label in target_labels {
        if honor_labels {
            add_if_absent(&mut labels, &target_label.name, &target_label.value);
        } else if let Some(existing) = labels
            .iter_mut()
            .find(|label| label.name == target_label.name)
        {
            let exported_name = format!("{EXPORTED_LABEL_PREFIX}{}", target_label.name);
            let exported_value = std::mem::replace(&mut existing.value, target_label.value.clone());
            set_label(&mut labels, &exported_name, exported_value);
        } else {
            labels.push(target_label.clone());
        }
    }
    labels
}

fn get_label<'a>(labels: &'a [Label], name: &str) -> &'a str {
    labels
        .iter()
        .find(|label| label.name == name)
        .map_or("", |label| label.value.as_str())
}

fn set_label(labels: &mut Vec<Label>, name: &str, value: String) {
    if let Some(existing) = labels.iter_mut().find(|label| label.name == name) {
        existing.value = value;
    } else {
        labels.push(Label::new(name, value));
    }
}

fn add_if_absent(labels: &mut Vec<Label>, name: &str, value: &str) {
    if !labels.iter().any(|label| label.name == name) {
        labels.push(Label::new(name, value));
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "sample counts are far below 2^52"
)]
fn to_f64(count: usize) -> f64 {
    count as f64
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label_vec(pairs: &[(&str, &str)]) -> Vec<Label> {
        pairs
            .iter()
            .map(|(name, value)| Label::new(*name, *value))
            .collect()
    }

    #[test]
    fn merge_honor_labels_keeps_scraped_value() {
        let scraped = label_vec(&[(METRIC_NAME_LABEL, "m"), ("job", "custom")]);
        let target = label_vec(&[("job", "node"), ("instance", "a:9100")]);
        let merged = merge_target_labels(scraped, &target, true);
        assert_eq!(get_label(&merged, "job"), "custom");
        assert_eq!(get_label(&merged, "instance"), "a:9100");
    }

    #[test]
    fn merge_without_honor_labels_exports_conflicts() {
        let scraped = label_vec(&[(METRIC_NAME_LABEL, "m"), ("job", "custom")]);
        let target = label_vec(&[("job", "node"), ("instance", "a:9100")]);
        let merged = merge_target_labels(scraped, &target, false);
        assert_eq!(get_label(&merged, "job"), "node");
        assert_eq!(get_label(&merged, "exported_job"), "custom");
        assert_eq!(get_label(&merged, "instance"), "a:9100");
    }

    #[test]
    fn fnv1a_matches_reference_vector() {
        // FNV-1a 64-bit of "a" is 0xaf63dc4c8601ec8c.
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn build_targets_applies_relabeling() -> anyhow::Result<()> {
        let yaml = r#"
job_name: test
metrics_path: /custom
params:
  module: [http_2xx]
relabel_configs:
  - source_labels: [__address__]
    regex: "drop-me.*"
    action: drop
  - source_labels: [env]
    target_label: environment
"#;
        let job: ScrapeConfig = serde_saphyr::from_str(yaml)?;
        let global: GlobalConfig = serde_saphyr::from_str("{}")?;
        let external: Arc<[Label]> = Arc::new([]);
        let groups = [TargetGroup {
            targets: vec!["a:8080".into(), "drop-me:8080".into()],
            labels: [("env".to_owned(), "prod".to_owned())].into(),
        }];
        let targets = build_targets(&job, &global, &groups, &external);
        assert_eq!(targets.len(), 1);
        let target = &targets[0];
        assert_eq!(target.url, "http://a:8080/custom");
        assert_eq!(
            target.params,
            vec![("module".to_owned(), "http_2xx".to_owned())]
        );
        assert_eq!(get_label(&target.labels, "job"), "test");
        assert_eq!(get_label(&target.labels, "instance"), "a:8080");
        assert_eq!(get_label(&target.labels, "environment"), "prod");
        assert!(!target.labels.iter().any(|l| l.name.starts_with("__")));
        Ok(())
    }
}
