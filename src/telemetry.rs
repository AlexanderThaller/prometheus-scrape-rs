//! Self-monitoring: an allocation-free metrics registry, rendered either as
//! a text exposition body (`GET /metrics`) or as wire-ready series pushed
//! through the normal remote-write pipeline.
//!
//! Deliberately dependency-free: the agent's own metrics are a fixed set of
//! counters and gauges, not worth a client-library dependency.

use std::{
    sync::atomic::{
        AtomicU64,
        Ordering,
    },
    time::{
        SystemTime,
        UNIX_EPOCH,
    },
};

use crate::model::{
    Label,
    METRIC_NAME_LABEL,
    Sample,
    TimeSeries,
    sort_labels,
};

/// Global registry; incremented from the scrape and remote-write paths.
pub static METRICS: Metrics = Metrics::new();

#[derive(Debug)]
pub struct Metrics {
    /// Scrapes attempted, including failed ones.
    pub scrapes_total: Value,
    /// Scrapes that failed (fetch, parse or `sample_limit`).
    pub scrape_failures_total: Value,
    /// Samples parsed from scrape bodies (before metric relabeling).
    pub samples_scraped_total: Value,
    /// Staleness markers emitted.
    pub staleness_markers_total: Value,
    /// Series currently tracked for staleness (gauge).
    pub tracked_series: Value,
    /// Remote-write batches accepted by an endpoint.
    pub remote_write_batches_total: Value,
    /// Compressed bytes accepted by remote-write endpoints.
    pub remote_write_sent_bytes_total: Value,
    /// Send attempts that will be retried (5xx/429/transport).
    pub remote_write_retries_total: Value,
    /// Batches dropped after an unrecoverable (4xx) response.
    pub remote_write_failed_batches_total: Value,
    /// Series dropped because an endpoint queue was full.
    pub remote_write_dropped_series_total: Value,
    /// Unix time the process started, set once at startup.
    start_time_seconds: Value,
}

/// A metric value backed by one atomic; counter or gauge is a matter of the
/// exposition TYPE line.
#[derive(Debug)]
pub struct Value(AtomicU64);

impl Value {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn add(&self, delta: u64) {
        self.0.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn sub(&self, delta: u64) {
        self.0.fetch_sub(delta, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.add(1);
    }

    pub fn set(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }

    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

enum Kind {
    Counter,
    Gauge,
}

impl Metrics {
    const fn new() -> Self {
        Self {
            scrapes_total: Value::new(),
            scrape_failures_total: Value::new(),
            samples_scraped_total: Value::new(),
            staleness_markers_total: Value::new(),
            tracked_series: Value::new(),
            remote_write_batches_total: Value::new(),
            remote_write_sent_bytes_total: Value::new(),
            remote_write_retries_total: Value::new(),
            remote_write_failed_batches_total: Value::new(),
            remote_write_dropped_series_total: Value::new(),
            start_time_seconds: Value::new(),
        }
    }

    /// Record the process start time; call once at startup.
    pub fn mark_started(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        self.start_time_seconds.set(now);
    }

    /// Snapshot all metrics as (name, help, kind, value).
    fn snapshot(&self) -> Vec<(&'static str, &'static str, Kind, f64)> {
        let process = ProcessStats::read();
        #[expect(clippy::cast_precision_loss, reason = "counters stay far below 2^52")]
        let mut values = vec![
            (
                "prometheus_scrape_rs_scrapes_total",
                "Scrapes attempted, including failures.",
                Kind::Counter,
                self.scrapes_total.get() as f64,
            ),
            (
                "prometheus_scrape_rs_scrape_failures_total",
                "Scrapes that failed (fetch, parse or sample_limit).",
                Kind::Counter,
                self.scrape_failures_total.get() as f64,
            ),
            (
                "prometheus_scrape_rs_samples_scraped_total",
                "Samples parsed from scrape bodies.",
                Kind::Counter,
                self.samples_scraped_total.get() as f64,
            ),
            (
                "prometheus_scrape_rs_staleness_markers_total",
                "Staleness markers emitted.",
                Kind::Counter,
                self.staleness_markers_total.get() as f64,
            ),
            (
                "prometheus_scrape_rs_tracked_series",
                "Series currently tracked for staleness.",
                Kind::Gauge,
                self.tracked_series.get() as f64,
            ),
            (
                "prometheus_scrape_rs_remote_write_batches_total",
                "Remote-write batches accepted by an endpoint.",
                Kind::Counter,
                self.remote_write_batches_total.get() as f64,
            ),
            (
                "prometheus_scrape_rs_remote_write_sent_bytes_total",
                "Compressed bytes accepted by remote-write endpoints.",
                Kind::Counter,
                self.remote_write_sent_bytes_total.get() as f64,
            ),
            (
                "prometheus_scrape_rs_remote_write_retries_total",
                "Remote-write attempts that will be retried.",
                Kind::Counter,
                self.remote_write_retries_total.get() as f64,
            ),
            (
                "prometheus_scrape_rs_remote_write_failed_batches_total",
                "Batches dropped after an unrecoverable response.",
                Kind::Counter,
                self.remote_write_failed_batches_total.get() as f64,
            ),
            (
                "prometheus_scrape_rs_remote_write_dropped_series_total",
                "Series dropped because an endpoint queue was full.",
                Kind::Counter,
                self.remote_write_dropped_series_total.get() as f64,
            ),
            (
                "process_start_time_seconds",
                "Unix time the process started.",
                Kind::Gauge,
                self.start_time_seconds.get() as f64,
            ),
        ];
        if let Some(process) = process {
            values.push((
                "process_cpu_seconds_total",
                "Total user and system CPU time.",
                Kind::Counter,
                process.cpu_seconds,
            ));
            values.push((
                "process_resident_memory_bytes",
                "Resident set size.",
                Kind::Gauge,
                process.resident_bytes,
            ));
        }
        values
    }

    /// Render the registry as a text exposition body for `GET /metrics`.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut body = String::with_capacity(2048);
        for (name, help, kind, value) in self.snapshot() {
            let kind = match kind {
                Kind::Counter => "counter",
                Kind::Gauge => "gauge",
            };
            let _ = writeln!(body, "# HELP {name} {help}");
            let _ = writeln!(body, "# TYPE {name} {kind}");
            let _ = writeln!(body, "{name} {value}");
        }
        let _ = writeln!(
            body,
            "# HELP prometheus_scrape_rs_build_info Build information.\n# TYPE \
             prometheus_scrape_rs_build_info \
             gauge\nprometheus_scrape_rs_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        body
    }

    /// Snapshot as remote-write series carrying `extra_labels`.
    #[must_use]
    pub fn series(&self, extra_labels: &[Label], timestamp: i64) -> Vec<TimeSeries> {
        let mut out: Vec<TimeSeries> = self
            .snapshot()
            .into_iter()
            .map(|(name, _, _, value)| (name.to_owned(), Vec::new(), value))
            .chain(std::iter::once((
                "prometheus_scrape_rs_build_info".to_owned(),
                vec![Label::new("version", env!("CARGO_PKG_VERSION"))],
                1.0,
            )))
            .map(|(name, mut labels, value)| {
                labels.push(Label::new(METRIC_NAME_LABEL, name));
                labels.extend(extra_labels.iter().cloned());
                sort_labels(&mut labels);
                TimeSeries {
                    labels,
                    sample: Sample { value, timestamp },
                    identity_hash: 0,
                }
            })
            .collect();
        out.sort_by(|a, b| a.labels.cmp(&b.labels));
        out
    }
}

struct ProcessStats {
    cpu_seconds: f64,
    resident_bytes: f64,
}

impl ProcessStats {
    /// Read CPU and RSS from procfs; `None` off-Linux or on parse issues.
    fn read() -> Option<Self> {
        // /proc/self/stat: fields 14/15 are utime/stime in clock ticks
        // (USER_HZ, 100 on Linux for glibc and musl alike). The comm field
        // may contain spaces but is parenthesized: split after ')'.
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let after_comm = stat.rsplit_once(')')?.1;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        let utime: f64 = fields.get(11)?.parse().ok()?;
        let stime: f64 = fields.get(12)?.parse().ok()?;

        // /proc/self/statm: second field is resident pages.
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let resident_pages: f64 = statm.split_whitespace().nth(1)?.parse().ok()?;

        Some(Self {
            cpu_seconds: (utime + stime) / 100.0,
            resident_bytes: resident_pages * 4096.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_exposition_format_that_parses() {
        METRICS.scrapes_total.inc();
        METRICS.tracked_series.set(42);
        let body = METRICS.render();
        let series = crate::parser::parse(&body, 1_000, true).expect("must parse");
        assert!(
            series
                .iter()
                .any(|s| s.labels[0].value == "prometheus_scrape_rs_tracked_series")
        );
        assert!(
            series
                .iter()
                .any(|s| s.labels[0].value == "prometheus_scrape_rs_build_info")
        );
    }

    #[test]
    fn series_snapshot_is_sorted_and_labeled() {
        let extra = [Label::new("job", "self"), Label::new("instance", "here")];
        let series = METRICS.series(&extra, 5_000);
        assert!(!series.is_empty());
        for s in &series {
            assert!(s.labels.windows(2).all(|w| w[0].name < w[1].name));
            assert!(
                s.labels
                    .iter()
                    .any(|l| l.name == "job" && l.value == "self")
            );
            assert_eq!(s.sample.timestamp, 5_000);
        }
    }

    #[test]
    fn process_stats_read_on_linux() {
        let stats = ProcessStats::read().expect("procfs must be readable on linux");
        assert!(stats.resident_bytes > 0.0);
        assert!(stats.cpu_seconds >= 0.0);
    }
}
