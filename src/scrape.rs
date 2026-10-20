//! Scrape pool: builds targets from discovery via target relabeling and runs
//! one jittered scrape loop per target.

use std::{
    fmt::Write as _,
    hash::Hasher as _,
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
        ScrapeProtocol,
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
///
/// `track_staleness` enables staleness markers for series that stop being
/// exposed (`--staleness.enable-tracking`); with it off no scrape body is
/// retained and no per-series state is kept.
#[must_use]
pub fn spawn_jobs(
    config: &Arc<Config>,
    remote_write: &RemoteWriteHandle,
    shutdown: &watch::Receiver<bool>,
    track_staleness: bool,
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
                track_staleness,
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
    track_staleness: bool,
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
    // Running scrape loops keyed by target identity. On discovery change,
    // only removed targets are stopped (emitting staleness markers when
    // tracking is on) and only new ones started; unchanged targets keep
    // their series intact.
    let mut running: std::collections::HashMap<u64, RunningTarget> =
        std::collections::HashMap::new();
    loop {
        let groups = groups_rx.borrow_and_update().clone();
        let targets = build_targets(&job, &global, &groups, &external_labels, track_staleness);
        let desired: std::collections::HashMap<u64, Target> = targets
            .into_iter()
            .map(|target| (target.identity(), target))
            .collect();

        let removed: Vec<u64> = running
            .keys()
            .filter(|key| !desired.contains_key(key))
            .copied()
            .collect();
        for key in removed {
            if let Some(target) = running.remove(&key) {
                let _ = target.removed_tx.send(true);
                let _ = target.handle.await;
            }
        }
        for (key, target) in desired {
            running.entry(key).or_insert_with(|| {
                let (removed_tx, removed_rx) = watch::channel(false);
                let handle = tokio::spawn(scrape_loop(
                    Arc::new(target),
                    client.clone(),
                    Arc::clone(&credentials),
                    remote_write.clone(),
                    shutdown.clone(),
                    removed_rx,
                ));
                RunningTarget { removed_tx, handle }
            });
        }
        info!(
            job = job.job_name,
            targets = running.len(),
            "scrape targets updated"
        );

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
    // Process shutdown: loops exit via the shutdown signal WITHOUT staleness
    // markers — a replacement instance continues these series and markers
    // would punch holes into them during rollouts.
    for (_, target) in running {
        let _ = target.handle.await;
    }
}

struct RunningTarget {
    /// Signals "this target left the target set": the loop emits staleness
    /// markers for everything it wrote (when tracking is on), then exits.
    removed_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

/// Initial body buffer for a response that announces no `Content-Length`
/// (every gzipped one).
const DEFAULT_BODY_CAPACITY: u64 = 64 * 1024;

/// Upper bound on what a single announced `Content-Length` may pre-allocate;
/// beyond it the buffer grows as the body actually arrives.
const MAX_PREALLOCATED_BODY: u64 = 8 * 1024 * 1024;

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
    /// Maximum decoded response body accepted from the target, in bytes.
    /// `0` disables the limit.
    body_size_limit: u64,
    /// `Accept` header offering the job's `scrape_protocols`.
    accept: String,
    /// Conversion settings for protobuf bodies (native histograms).
    protobuf: crate::protobuf::Options,
    /// Keep per-series state so vanished series get staleness markers.
    /// Off unless `--staleness.enable-tracking` was given.
    track_staleness: bool,
    metric_relabel_configs: Vec<RelabelConfig>,
    external_labels: Arc<[Label]>,
}

impl Target {
    /// Stable identity across discovery updates: URL, params and final
    /// label set. Targets with equal identity are the same series source.
    fn identity(&self) -> u64 {
        let mut hasher = crate::hash::FxHasher::default();
        hasher.write(self.url.as_bytes());
        for (name, value) in &self.params {
            hasher.write(name.as_bytes());
            hasher.write(value.as_bytes());
        }
        hash_labels_into(&mut hasher, &self.labels);
        hasher.finish()
    }
}

/// Prometheus `populateLabels`: seed target labels, run target relabeling,
/// derive URL parts from the resulting `__`-meta labels.
fn build_targets(
    job: &ScrapeConfig,
    global: &GlobalConfig,
    groups: &[TargetGroup],
    external_labels: &Arc<[Label]>,
    track_staleness: bool,
) -> Vec<Target> {
    let mut targets = Vec::new();
    let accept = accept_header(&job.protocols(global));
    let protobuf = crate::protobuf::Options {
        honor_timestamps: job.honor_timestamps,
        native_histograms: job.native_histograms(global),
        classic_histograms: job.classic_histograms(global),
        bucket_limit: job.native_histogram_bucket_limit,
    };
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
                    params.push((param.to_owned(), label.value.to_string()));
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
                body_size_limit: job.body_size_limit.as_bytes(),
                accept: accept.clone(),
                protobuf,
                track_staleness,
                metric_relabel_configs: job.metric_relabel_configs.clone(),
                external_labels: Arc::clone(external_labels),
            });
        }
    }
    targets
}

/// Prometheus' `acceptHeader`: the protocols in preference order with
/// descending q-values, then a catch-all below them.
fn accept_header(protocols: &[ScrapeProtocol]) -> String {
    // Prometheus starts at one above its number of known protocols (5), so
    // the values match its header for the same list.
    let mut weight = 6usize;
    let mut header = String::new();
    for protocol in protocols {
        header.push_str(protocol.media_type());
        let _ = write!(header, ";q=0.{weight},");
        weight = weight.saturating_sub(1);
    }
    let _ = write!(header, "*/*;q=0.{weight}");
    header
}

/// Wire format of a scrape body, from the response's `Content-Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFormat {
    /// Text exposition format; also assumed when the type is missing or
    /// unknown, as before protobuf support.
    Text,
    /// Delimited `io.prometheus.client.MetricFamily` messages.
    Protobuf,
}

impl BodyFormat {
    fn from_content_type(content_type: Option<&str>) -> anyhow::Result<Self> {
        let Some(content_type) = content_type else {
            return Ok(Self::Text);
        };
        let mut parts = content_type.split(';');
        let media_type = parts.next().unwrap_or_default().trim();
        if media_type.to_lowercase() != crate::protobuf::MEDIA_TYPE {
            return Ok(Self::Text);
        }
        let mut proto = "";
        let mut encoding = "";
        for parameter in parts {
            if let Some((key, value)) = parameter.split_once('=') {
                let value = value.trim().trim_matches('"');
                match key.trim().to_lowercase().as_str() {
                    "proto" => proto = value,
                    "encoding" => encoding = value,
                    _ => {}
                }
            }
        }
        if proto != crate::protobuf::MESSAGE_TYPE {
            anyhow::bail!("unsupported protobuf message type {proto:?} in {content_type:?}");
        }
        if encoding != "delimited" {
            anyhow::bail!("unsupported protobuf encoding {encoding:?} in {content_type:?}");
        }
        Ok(Self::Protobuf)
    }
}

/// A fetched scrape body and the format it is in.
#[derive(Debug, Clone)]
struct ScrapeBody {
    bytes: bytes::Bytes,
    format: BodyFormat,
}

/// Parse a scrape body with the parser for its format. Shared by live
/// scrapes and staleness re-derivation, which must produce the same series.
fn parse_body(
    target: &Target,
    body: &[u8],
    format: BodyFormat,
    default_timestamp_ms: i64,
) -> Result<Vec<TimeSeries>, String> {
    match format {
        BodyFormat::Text => {
            // Validation instead of a lossy conversion: no full-body copy
            // per scrape, and a body Prometheus could not have parsed
            // anyway becomes a scrape error, not mojibake.
            let text = std::str::from_utf8(body)
                .map_err(|err| format!("scrape body is not valid UTF-8: {err}"))?;
            crate::parser::parse(text, default_timestamp_ms, target.honor_timestamps)
                .map_err(|err| format!("scrape body failed to parse: {err}"))
        }
        BodyFormat::Protobuf => crate::protobuf::parse(body, default_timestamp_ms, target.protobuf)
            .map_err(|err| format!("protobuf scrape body failed to parse: {err}")),
    }
}

async fn scrape_loop(
    target: Arc<Target>,
    client: reqwest::Client,
    credentials: Arc<Credentials>,
    remote_write: RemoteWriteHandle,
    mut shutdown: watch::Receiver<bool>,
    mut removed: watch::Receiver<bool>,
) {
    // Deterministic per-target offset spreads scrapes over the interval,
    // like Prometheus' scrapeloop offset.
    let offset_nanos = hash_bytes(target.url.as_bytes())
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
    // Series written by the previous scrape, for staleness markers. Series
    // carrying explicit exposition timestamps are excluded, matching
    // Prometheus (staleness only applies to scrape-timestamped samples).
    // `None` when tracking is off: no retained body, no hashes, no markers.
    let mut tracker = target.track_staleness.then(SeriesTracker::default);
    let mut report_series: Vec<Vec<Label>> = Vec::new();
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.wait_for(|stop| *stop) => return,
            _ = removed.wait_for(|gone| *gone) => {
                // Target left the target set: everything it wrote ends now.
                let Some(tracker) = &mut tracker else { return };
                let timestamp = now_ms();
                let mut markers = tracker.drain_all(&target, timestamp);
                markers.extend(report_series.drain(..).map(|labels| stale_series(labels, timestamp)));
                debug!(url = target.url, series = markers.len(), "target removed; staleness markers sent");
                remote_write.send(markers);
                return;
            }
        }
        let outcome = scrape_once(&target, &client, &credentials).await;
        crate::telemetry::METRICS.scrapes_total.inc();
        if outcome.error.is_some() {
            crate::telemetry::METRICS.scrape_failures_total.inc();
        }
        match (&last_error, &outcome.error) {
            (None, Some(message)) => {
                failures = 1;
                warn!(url = target.url, error = message, "target scrape failing");
            }
            (Some(previous), Some(message)) => {
                failures += 1;
                if previous == message {
                    debug!(
                        url = target.url,
                        error = message,
                        failures,
                        "target still failing"
                    );
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
        last_error = outcome.error;

        let mut batch = outcome.series;
        if let Some(tracker) = &mut tracker {
            let markers = tracker.advance(&target, &batch, outcome.retained_body, outcome.start_ms);
            crate::telemetry::METRICS
                .staleness_markers_total
                .add(markers.len() as u64);
            batch.extend(markers);
            if report_series.is_empty() {
                report_series = outcome.report.iter().map(|s| s.labels.clone()).collect();
            }
        }
        batch.extend(outcome.report);
        remote_write.send(batch);
    }
}

/// Staleness tracking state for one target, vmagent-style.
///
/// Instead of one stored label set per active series (~500B each at 300k
/// series), retain the previous scrape's raw body — one allocation with no
/// per-series overhead — plus a sorted vector of series hashes (8 bytes per
/// series). When series vanish (pod churn, an exporter dropping a series,
/// a failed scrape), their label sets are re-derived by re-parsing the
/// retained body through the same deterministic pipeline that produced
/// them. Steady state costs hashing plus a sorted diff per scrape; the
/// re-parse runs only on vanish events. A u64 hash collision (odds ~1e-9
/// at 300k series) costs at most one wrong or missing marker, never wrong
/// sample data.
struct SeriesTracker {
    /// Compressed body and scrape timestamp of the last emitted scrape.
    retained: Option<RetainedScrape>,
    /// Sorted hashes of the scrape-timestamped series last emitted.
    hashes: Vec<u64>,
    /// Last size reported into the global `tracked_series` gauge.
    tracked_reported: u64,
    /// Reused snappy encoder for compressing retained bodies.
    encoder: snap::raw::Encoder,
}

impl Default for SeriesTracker {
    fn default() -> Self {
        Self {
            retained: None,
            hashes: Vec::new(),
            tracked_reported: 0,
            encoder: snap::raw::Encoder::new(),
        }
    }
}

struct RetainedScrape {
    /// Snappy-compressed exposition body. Measured ~7x smaller than the
    /// raw text on the pgo-corpus bodies at ~2.2 GB/s compression (~23 µs
    /// per 50 KiB scrape); decompressed only on vanish events. snappy beat
    /// lz4 on compression speed at near-equal ratio and needs no new
    /// dependency; zstd's better ratio (11.5x) was not worth a C dependency
    /// in the static musl build.
    compressed: Vec<u8>,
    format: BodyFormat,
    start_ms: i64,
}

impl SeriesTracker {
    /// Advance by one scrape: remember which series `batch` emitted (only
    /// those carrying the scrape timestamp — explicitly timestamped samples
    /// are exempt from staleness, like in Prometheus) and return one marker
    /// for every series present before but gone now. After a failed scrape
    /// (`batch` empty) that is everything.
    fn advance(
        &mut self,
        target: &Target,
        batch: &[TimeSeries],
        retained_body: Option<ScrapeBody>,
        start_ms: i64,
    ) -> Vec<TimeSeries> {
        let mut current: Vec<u64> = batch
            .iter()
            .filter(|series| series.sample.timestamp == start_ms)
            .map(|series| series.identity_hash)
            .collect();
        current.sort_unstable();
        current.dedup();

        let vanished: Vec<u64> = self
            .hashes
            .iter()
            .copied()
            .filter(|hash| current.binary_search(hash).is_err())
            .collect();
        let markers = self.rederive_markers(target, &vanished, start_ms);

        // The retained body exists only to re-derive label sets of vanished
        // series. While the series set is unchanged — the steady state — the
        // body already retained answers every re-derivation the new one
        // could (label sets per identity are deterministic; values and
        // timestamps are irrelevant to markers), so skip the per-scrape
        // recompression. `RetainedScrape.start_ms` stays the retained
        // body's own scrape time: the re-parse filter depends on it.
        match retained_body {
            None => self.retained = None,
            Some(body) => {
                if self.retained.is_none() || self.hashes != current {
                    self.retained = match self.encoder.compress_vec(&body.bytes) {
                        Ok(compressed) => Some(RetainedScrape {
                            compressed,
                            format: body.format,
                            start_ms,
                        }),
                        Err(err) => {
                            warn!(
                                url = target.url,
                                %err,
                                "compressing retained scrape body failed; staleness markers unavailable until the next scrape"
                            );
                            None
                        }
                    };
                }
            }
        }
        self.hashes = current;
        self.update_gauge();
        markers
    }

    /// Emit markers for everything currently tracked (target removal).
    fn drain_all(&mut self, target: &Target, timestamp: i64) -> Vec<TimeSeries> {
        let vanished = std::mem::take(&mut self.hashes);
        let markers = self.rederive_markers(target, &vanished, timestamp);
        crate::telemetry::METRICS
            .staleness_markers_total
            .add(markers.len() as u64);
        self.retained = None;
        self.update_gauge();
        markers
    }

    /// Re-parse the retained body and rebuild the final label sets of the
    /// `vanished` hashes (must be sorted). The pipeline is deterministic,
    /// so re-derived label sets are identical to what was originally sent.
    fn rederive_markers(
        &self,
        target: &Target,
        vanished: &[u64],
        timestamp: i64,
    ) -> Vec<TimeSeries> {
        if vanished.is_empty() {
            return Vec::new();
        }
        let Some(retained) = &self.retained else {
            return Vec::new();
        };
        // The body compressed cleanly when it was retained; failures from
        // here on would be determinism bugs.
        let Ok(body) = snap::raw::Decoder::new().decompress_vec(&retained.compressed) else {
            warn!(
                url = target.url,
                "retained scrape body failed to decompress; staleness markers skipped"
            );
            return Vec::new();
        };
        let series = match parse_body(target, &body, retained.format, retained.start_ms) {
            Ok(series) => series,
            Err(err) => {
                warn!(
                    url = target.url,
                    err, "retained scrape body failed to re-parse; staleness markers skipped"
                );
                return Vec::new();
            }
        };
        let mut consumed = vec![false; vanished.len()];
        let mut markers = Vec::with_capacity(vanished.len());
        for mut single in series {
            if single.sample.timestamp != retained.start_ms {
                continue;
            }
            // Identity is the parser's raw-line hash, so matching happens
            // before label finalization — only vanished series pay for the
            // merge/relabel/sort pipeline here.
            let Ok(index) = vanished.binary_search(&single.identity_hash) else {
                continue;
            };
            if consumed[index] {
                continue;
            }
            let Some(labels) = finalize_series_labels(std::mem::take(&mut single.labels), target)
            else {
                continue;
            };
            consumed[index] = true;
            markers.push(stale_series(labels, timestamp));
        }
        markers
    }

    fn update_gauge(&mut self) {
        let now = self.hashes.len() as u64;
        if now >= self.tracked_reported {
            crate::telemetry::METRICS
                .tracked_series
                .add(now - self.tracked_reported);
        } else {
            crate::telemetry::METRICS
                .tracked_series
                .sub(self.tracked_reported - now);
        }
        self.tracked_reported = now;
    }
}

/// Every exit path — target removal, config reload, shutdown, panic — must
/// return this tracker's contribution to the global gauge, or reloads leak
/// it upward (observed: gauge at 564k with 306k live series after reloads).
impl Drop for SeriesTracker {
    fn drop(&mut self) {
        crate::telemetry::METRICS
            .tracked_series
            .sub(self.tracked_reported);
        self.tracked_reported = 0;
    }
}

/// A single-sample series carrying the staleness marker. Markers are
/// appended to the batch after the tracker advanced, so they are never
/// tracked themselves and carry no identity.
fn stale_series(labels: Vec<Label>, timestamp: i64) -> TimeSeries {
    TimeSeries {
        labels,
        sample: Sample {
            value: crate::model::stale_nan(),
            timestamp,
        },
        identity_hash: 0,
        histogram: None,
    }
}

/// One scrape's output, kept apart so staleness tracking can tell scraped
/// data from the synthetic report series.
struct ScrapeOutcome {
    series: Vec<TimeSeries>,
    report: Vec<TimeSeries>,
    /// Raw exposition body, present only when staleness tracking is on and
    /// `series` was actually emitted — tracking must reflect what was sent.
    retained_body: Option<ScrapeBody>,
    start_ms: i64,
    error: Option<String>,
}

async fn scrape_once(
    target: &Target,
    client: &reqwest::Client,
    credentials: &Credentials,
) -> ScrapeOutcome {
    let start_ms = now_ms();
    let started = std::time::Instant::now();
    let result = fetch(target, client, credentials).await;
    let duration = started.elapsed();

    let mut up = 0.0;
    let mut scraped = 0usize;
    let mut kept = 0usize;
    let mut error = None;
    let mut retained_body = None;
    let mut batch: Vec<TimeSeries> = Vec::new();

    match result {
        Ok(body) => match parse_body(target, &body.bytes, body.format, start_ms) {
            Ok(series) => {
                scraped = series.len();
                crate::telemetry::METRICS
                    .samples_scraped_total
                    .add(scraped as u64);
                if target.sample_limit > 0 && scraped as u64 > target.sample_limit {
                    error = Some(format!(
                        "sample_limit exceeded ({scraped} > {}); scrape discarded",
                        target.sample_limit
                    ));
                } else {
                    up = 1.0;
                    batch.reserve(series.len() + 5);
                    for mut single in series {
                        // identity_hash stays as the parser set it.
                        let Some(labels) =
                            finalize_series_labels(std::mem::take(&mut single.labels), target)
                        else {
                            continue;
                        };
                        single.labels = labels;
                        batch.push(single);
                    }
                    kept = batch.len();
                    if target.track_staleness {
                        retained_body = Some(body);
                    }
                }
            }
            Err(message) => error = Some(message),
        },
        Err(err) => {
            error = Some(format!("{err:#}"));
        }
    }

    // Synthetic report series, always emitted (target labels + external).
    let mut report: Vec<TimeSeries> = Vec::with_capacity(5);
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
        report.push(TimeSeries {
            labels,
            sample: Sample {
                value,
                timestamp: start_ms,
            },
            identity_hash: 0,
            histogram: None,
        });
    }
    ScrapeOutcome {
        series: batch,
        report,
        retained_body,
        start_ms,
        error,
    }
}

async fn fetch(
    target: &Target,
    client: &reqwest::Client,
    credentials: &Credentials,
) -> anyhow::Result<ScrapeBody> {
    let mut builder = client
        .get(&target.url)
        .header(reqwest::header::ACCEPT, &target.accept)
        .header(
            "X-Prometheus-Scrape-Timeout-Seconds",
            format!("{}", target.timeout.as_secs_f64()),
        )
        .timeout(target.timeout);
    if !target.params.is_empty() {
        builder = builder.query(&target.params);
    }
    let mut response = credentials.apply(builder).send().await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("server returned HTTP {status}");
    }
    let format = BodyFormat::from_content_type(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
    )?;
    let bytes = read_body(&mut response, target.body_size_limit).await?;
    Ok(ScrapeBody { bytes, format })
}

/// Read the response body, refusing to buffer more than `limit` decoded bytes
/// (`0` disables the limit).
///
/// The body is streamed rather than taken with `Response::bytes()`: an
/// announced `Content-Length` covers neither chunked nor gzipped responses, so
/// only a running count of the decoded bytes bounds what a hostile or broken
/// target can make the agent allocate.
async fn read_body(response: &mut reqwest::Response, limit: u64) -> anyhow::Result<bytes::Bytes> {
    let announced = response.content_length();
    if limit > 0
        && let Some(length) = announced
        && length > limit
    {
        anyhow::bail!("response body is {length} bytes, over body_size_limit of {limit}");
    }

    // Size to what the target announced (bounded by the limit, since the
    // announcement is unverified); gzipped responses announce nothing, so
    // those grow from a modest start.
    let capacity = announced
        .unwrap_or(DEFAULT_BODY_CAPACITY)
        .min(if limit == 0 { u64::MAX } else { limit })
        .min(MAX_PREALLOCATED_BODY);
    let mut body = bytes::BytesMut::with_capacity(usize::try_from(capacity).unwrap_or(usize::MAX));
    while let Some(chunk) = response.chunk().await? {
        if limit > 0 && body.len() as u64 + chunk.len() as u64 > limit {
            anyhow::bail!("response body exceeds body_size_limit of {limit} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// The deterministic series-building pipeline: merge target labels, apply
/// metric relabeling, attach external labels, sort. Shared by live scrapes
/// and staleness re-derivation, which must reproduce identical label sets.
///
/// The staleness identity is *not* derived here: the parser hashes the raw
/// exposition bytes while the line is in cache (re-hashing the finalized
/// labels per series per scrape was 11% of live CPU, bound on the `FxHash`
/// multiply chain).
fn finalize_series_labels(raw: Vec<Label>, target: &Target) -> Option<Vec<Label>> {
    let labels = merge_target_labels(raw, &target.labels, target.honor_labels);
    let mut labels = relabel::process(labels, &target.metric_relabel_configs)?;
    for external in target.external_labels.iter() {
        add_if_absent(&mut labels, &external.name, &external.value);
    }
    sort_labels(&mut labels);
    Some(labels)
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
    labels.reserve(target_labels.len());
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

fn set_label(labels: &mut Vec<Label>, name: &str, value: impl Into<compact_str::CompactString>) {
    let value = value.into();
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

fn hash_bytes(data: &[u8]) -> u64 {
    let mut hasher = crate::hash::FxHasher::default();
    hasher.write(data);
    hasher.finish()
}

/// Hash a label set into `hasher`. [`crate::hash::FxHasher`] folds each
/// part's length into the state, which keeps `("ab","c")` distinct from
/// `("a","bc")` without separator bytes. Used for target identities; the
/// staleness tracker's *series* identities are the parser's raw-line
/// hashes. Never leaves the process.
fn hash_labels_into(hasher: &mut crate::hash::FxHasher, labels: &[Label]) {
    for label in labels {
        hasher.write(label.name.as_bytes());
        hasher.write(label.value.as_bytes());
    }
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
    fn hash_bytes_is_deterministic() {
        // The hash is process-internal: only self-consistency matters,
        // there is no external reference vector to pin.
        assert_eq!(hash_bytes(b"a"), hash_bytes(b"a"));
        assert_ne!(hash_bytes(b"a"), hash_bytes(b"b"));
    }

    /// Minimal target for tracker tests: no relabeling, one external label.
    fn test_target() -> Target {
        Target {
            url: "http://t:1/metrics".to_owned(),
            params: Vec::new(),
            labels: label_vec(&[("instance", "t:1"), ("job", "test")]),
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            honor_labels: false,
            honor_timestamps: true,
            sample_limit: 0,
            body_size_limit: 0,
            accept: accept_header(&[ScrapeProtocol::PrometheusText0_0_4]),
            protobuf: crate::protobuf::Options {
                honor_timestamps: true,
                native_histograms: true,
                ..crate::protobuf::Options::default()
            },
            track_staleness: true,
            metric_relabel_configs: Vec::new(),
            external_labels: Arc::new([Label::new("origin", "tracker-test")]),
        }
    }

    /// A scrape body as the tracker receives it from `fetch`.
    fn retained(body: &str) -> ScrapeBody {
        ScrapeBody {
            bytes: bytes::Bytes::copy_from_slice(body.as_bytes()),
            format: BodyFormat::Text,
        }
    }

    /// Reproduce the live pipeline for a raw body: parse + finalize labels
    /// (the identity hash stays as the parser computed it).
    fn simulate_scrape(target: &Target, body: &str, start_ms: i64) -> Vec<TimeSeries> {
        let parsed =
            crate::parser::parse(body, start_ms, target.honor_timestamps).expect("body parses");
        parsed
            .into_iter()
            .filter_map(|mut single| {
                let labels = finalize_series_labels(std::mem::take(&mut single.labels), target)?;
                single.labels = labels;
                Some(single)
            })
            .collect()
    }

    #[test]
    fn staleness_markers_for_vanished_series() {
        let target = test_target();
        let mut tracker = SeriesTracker::default();

        // First scrape: metric_a, metric_b, and one explicitly timestamped
        // series (exempt from staleness tracking).
        let body1 = "metric_a{case=\"x\"} 1\nmetric_b 2\nexplicit 3 500\n";
        let ts1 = 1_000;
        let batch1 = simulate_scrape(&target, body1, ts1);
        assert_eq!(
            tracker.advance(&target, &batch1, Some(retained(body1)), ts1),
            Vec::<TimeSeries>::new()
        );
        assert_eq!(tracker.hashes.len(), 2);

        // metric_b vanishes: its marker is re-derived from the retained
        // body with the full final label set (target + external labels).
        let body2 = "metric_a{case=\"x\"} 1\nexplicit 3 500\n";
        let ts2 = 2_000;
        let batch2 = simulate_scrape(&target, body2, ts2);
        let markers = tracker.advance(&target, &batch2, Some(retained(body2)), ts2);
        assert_eq!(markers.len(), 1);
        assert_eq!(get_label(&markers[0].labels, METRIC_NAME_LABEL), "metric_b");
        assert_eq!(get_label(&markers[0].labels, "job"), "test");
        assert_eq!(get_label(&markers[0].labels, "origin"), "tracker-test");
        assert!(
            markers[0].labels.windows(2).all(|w| w[0].name < w[1].name),
            "marker labels must be sorted"
        );
        assert!(crate::model::is_stale_nan(markers[0].sample.value));
        assert_eq!(markers[0].sample.timestamp, ts2);

        // Failed scrape (nothing emitted, no body): everything left goes
        // stale, re-derived from the retained body of scrape 2.
        let ts3 = 3_000;
        let markers = tracker.advance(&target, &[], None, ts3);
        assert_eq!(markers.len(), 1);
        assert_eq!(get_label(&markers[0].labels, METRIC_NAME_LABEL), "metric_a");
        assert_eq!(get_label(&markers[0].labels, "case"), "x");
        assert_eq!(tracker.hashes, Vec::<u64>::new());
        assert!(tracker.retained.is_none());

        // Recovery: series returns, no markers.
        let ts4 = 4_000;
        let batch4 = simulate_scrape(&target, body2, ts4);
        assert_eq!(
            tracker.advance(&target, &batch4, Some(retained(body2)), ts4),
            Vec::<TimeSeries>::new()
        );

        // Target removal drains everything tracked.
        let markers = tracker.drain_all(&target, 5_000);
        assert_eq!(markers.len(), 1);
        assert_eq!(get_label(&markers[0].labels, METRIC_NAME_LABEL), "metric_a");
        assert_eq!(tracker.hashes, Vec::<u64>::new());
        assert!(tracker.retained.is_none());
    }

    #[test]
    fn stable_series_set_keeps_the_retained_body() {
        let target = test_target();
        let mut tracker = SeriesTracker::default();

        // Three scrapes of the same series set with changing values: the
        // body retained after scrape 1 must survive untouched (no
        // recompression), because it can re-derive the same identities.
        for (timestamp, body) in [
            (1_000, "metric_a 1\nmetric_b 2\n"),
            (2_000, "metric_a 5\nmetric_b 6\n"),
            (3_000, "metric_a 9\nmetric_b 10\n"),
        ] {
            let batch = simulate_scrape(&target, body, timestamp);
            assert_eq!(
                tracker.advance(&target, &batch, Some(retained(body)), timestamp),
                Vec::<TimeSeries>::new()
            );
        }
        let retained_scrape = tracker.retained.as_ref().expect("body retained");
        assert_eq!(
            retained_scrape.start_ms, 1_000,
            "unchanged series set must not replace the retained body"
        );

        // metric_b vanishes: the marker is re-derived from the scrape-1
        // body, with the full final label set.
        let body4 = "metric_a 12\n";
        let batch4 = simulate_scrape(&target, body4, 4_000);
        let markers = tracker.advance(&target, &batch4, Some(retained(body4)), 4_000);
        assert_eq!(markers.len(), 1);
        assert_eq!(get_label(&markers[0].labels, METRIC_NAME_LABEL), "metric_b");
        assert_eq!(get_label(&markers[0].labels, "job"), "test");
        assert_eq!(markers[0].sample.timestamp, 4_000);
        // The set changed, so the scrape-4 body replaced the retained one.
        assert_eq!(
            tracker.retained.as_ref().expect("body retained").start_ms,
            4_000
        );
    }

    #[test]
    fn staleness_rederivation_respects_metric_relabeling() {
        // Series dropped by metric relabeling never entered the sent batch;
        // re-derivation applies the same rules, so they get no markers.
        let mut target = test_target();
        target.metric_relabel_configs = serde_saphyr::from_str(
            "- source_labels: [__name__]\n  regex: \"kept_.*\"\n  action: keep\n",
        )
        .expect("valid config");
        let mut tracker = SeriesTracker::default();

        let body1 = "kept_a 1\ndropped_b 2\n";
        let batch1 = simulate_scrape(&target, body1, 1_000);
        assert_eq!(batch1.len(), 1);
        tracker.advance(&target, &batch1, Some(retained(body1)), 1_000);
        assert_eq!(tracker.hashes.len(), 1);

        // Everything vanishes; only kept_a may produce a marker.
        let markers = tracker.advance(&target, &[], None, 2_000);
        assert_eq!(markers.len(), 1);
        assert_eq!(get_label(&markers[0].labels, METRIC_NAME_LABEL), "kept_a");
    }

    #[test]
    fn stale_series_carries_the_marker_bits() {
        // Wire round-tripping of the stale NaN is covered by the model
        // parity tests; here only the construction is checked.
        let series = stale_series(label_vec(&[(METRIC_NAME_LABEL, "x")]), 1);
        assert!(crate::model::is_stale_nan(series.sample.value));
        assert_eq!(series.sample.timestamp, 1);
        assert_eq!(series.identity_hash, 0, "markers are never tracked");
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
        let targets = build_targets(&job, &global, &groups, &external, false);
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
        assert!(
            !target.track_staleness,
            "staleness tracking is opt-in per --staleness.enable-tracking"
        );
        Ok(())
    }

    #[test]
    fn accept_header_matches_prometheus() {
        assert_eq!(
            accept_header(&[ScrapeProtocol::PrometheusText0_0_4]),
            "text/plain;version=0.0.4;q=0.6,*/*;q=0.5"
        );
        assert_eq!(
            accept_header(&[
                ScrapeProtocol::PrometheusProto,
                ScrapeProtocol::PrometheusText0_0_4,
            ]),
            "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;\
             encoding=delimited;q=0.6,text/plain;version=0.0.4;q=0.5,*/*;q=0.4"
        );
    }

    #[test]
    fn body_format_follows_content_type() {
        for (content_type, expected) in [
            (None, BodyFormat::Text),
            (
                Some("text/plain; version=0.0.4; charset=utf-8"),
                BodyFormat::Text,
            ),
            (Some("application/openmetrics-text"), BodyFormat::Text),
            (
                Some(
                    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; \
                     encoding=delimited",
                ),
                BodyFormat::Protobuf,
            ),
            (
                Some(
                    "Application/Vnd.Google.Protobuf;Encoding=delimited;proto=\"io.prometheus.\
                     client.MetricFamily\"",
                ),
                BodyFormat::Protobuf,
            ),
        ] {
            assert_eq!(
                BodyFormat::from_content_type(content_type).expect("supported"),
                expected,
                "{content_type:?}"
            );
        }
        for unsupported in [
            "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; \
             encoding=text",
            "application/vnd.google.protobuf; proto=other.Message; encoding=delimited",
            "application/vnd.google.protobuf",
        ] {
            assert!(
                BodyFormat::from_content_type(Some(unsupported)).is_err(),
                "{unsupported}"
            );
        }
    }

    /// A protobuf body: one counter and one native histogram per entry of
    /// `histograms`.
    fn protobuf_body(histograms: &[&str]) -> ScrapeBody {
        use prost::Message as _;

        use crate::protobuf::dto;

        let native = |name: &str| dto::MetricFamily {
            name: Some(name.to_owned()),
            r#type: Some(dto::MetricType::Histogram as i32),
            metric: vec![dto::Metric {
                histogram: Some(dto::Histogram {
                    sample_count: Some(1),
                    schema: Some(0),
                    positive_span: vec![dto::BucketSpan {
                        offset: Some(0),
                        length: Some(1),
                    }],
                    positive_delta: vec![1],
                    ..dto::Histogram::default()
                }),
                ..dto::Metric::default()
            }],
        };
        let mut families = vec![dto::MetricFamily {
            name: Some("requests_total".to_owned()),
            r#type: Some(dto::MetricType::Counter as i32),
            metric: vec![dto::Metric {
                counter: Some(dto::Counter { value: Some(1.0) }),
                ..dto::Metric::default()
            }],
        }];
        families.extend(histograms.iter().map(|name| native(name)));
        let mut bytes = Vec::new();
        for family in families {
            family
                .encode_length_delimited(&mut bytes)
                .expect("Vec grows as needed");
        }
        ScrapeBody {
            bytes: bytes.into(),
            format: BodyFormat::Protobuf,
        }
    }

    fn simulate_body(target: &Target, body: &ScrapeBody, start_ms: i64) -> Vec<TimeSeries> {
        parse_body(target, &body.bytes, body.format, start_ms)
            .expect("body parses")
            .into_iter()
            .filter_map(|mut single| {
                single.labels = finalize_series_labels(std::mem::take(&mut single.labels), target)?;
                Some(single)
            })
            .collect()
    }

    /// A vanished native histogram gets a (float) staleness marker, like in
    /// Prometheus, re-derived from the retained protobuf body.
    #[test]
    fn native_histogram_staleness_from_protobuf_body() {
        let target = test_target();
        let mut tracker = SeriesTracker::default();

        let body1 = protobuf_body(&["latency_seconds", "size_bytes"]);
        let batch1 = simulate_body(&target, &body1, 1_000);
        assert_eq!(batch1.iter().filter(|s| s.histogram.is_some()).count(), 2);
        assert_eq!(
            tracker.advance(&target, &batch1, Some(body1), 1_000),
            Vec::<TimeSeries>::new()
        );
        assert_eq!(tracker.hashes.len(), 3);

        let body2 = protobuf_body(&["latency_seconds"]);
        let batch2 = simulate_body(&target, &body2, 2_000);
        let markers = tracker.advance(&target, &batch2, Some(body2), 2_000);
        assert_eq!(markers.len(), 1);
        assert_eq!(
            get_label(&markers[0].labels, METRIC_NAME_LABEL),
            "size_bytes"
        );
        assert_eq!(get_label(&markers[0].labels, "job"), "test");
        assert!(crate::model::is_stale_nan(markers[0].sample.value));
        assert!(markers[0].histogram.is_none());
    }
}
