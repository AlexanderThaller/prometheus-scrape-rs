//! PGO training workload (`--pgo-training`, hidden).
//!
//! Deterministically exercises the CPU-hot paths — exposition parsing,
//! relabeling, label sorting, protobuf encoding, snappy compression and
//! config parsing — so an instrumented build can collect a representative
//! profile without network access. Used by the two-phase container build.

use std::{
    fmt::Write as _,
    hash::Hasher as _,
    io::Write as _,
    path::Path,
};

use prost::Message as _;

use crate::{
    model::{
        Label,
        WriteRequest,
        sort_labels,
    },
    relabel::RelabelConfig,
};

/// Total bytes of exposition text to push through the pipeline; roughly ten
/// seconds of training on one core.
const TARGET_BYTES: usize = 750_000_000;

/// Print without panicking when stdout is a closed pipe — with
/// `panic = "abort"` that would kill the process before the PGO runtime
/// flushes its .profraw files at exit.
fn note(message: &str) {
    let _ = writeln!(std::io::stdout(), "{message}");
}

pub fn run_training_workload(corpus_dir: Option<&Path>) -> anyhow::Result<()> {
    // Production-shaped relabel chain: a rarely-matching drop, capture-group
    // replaces, and a labeldrop — without discarding the bulk of the series,
    // so the encode path trains on realistic batch sizes.
    let relabel_configs: Vec<RelabelConfig> = serde_saphyr::from_str(
        r#"
- source_labels: [__name__]
  regex: "go_gc_duration_seconds.*"
  action: drop
- source_labels: [__name__, le]
  separator: "@"
  target_label: __tmp_bucket
- source_labels: [instance]
  regex: "([^:]+):.*"
  target_label: host
  replacement: "${1}"
- regex: "__tmp_.*"
  action: labeldrop
"#,
    )?;
    let target_labels = [
        Label::new("instance", "node-1.example.com:9100"),
        Label::new("job", "training"),
        Label::new("cluster", "pgo"),
    ];

    let bodies = corpus_dir.map_or_else(Vec::new, load_corpus);
    let bodies = if bodies.is_empty() {
        note("pgo training on synthetic data (no corpus)");
        vec![training_scrape_body(10_000)]
    } else {
        note(&format!("pgo training on {} corpus bodies", bodies.len()));
        bodies
    };
    let bytes_per_round: usize = bodies.iter().map(String::len).sum();
    let rounds = (TARGET_BYTES / bytes_per_round.max(1)).clamp(3, 100_000);

    let mut checksum = FnvChecksum::default();
    let mut proto_buf = Vec::new();
    let mut encoder = snap::raw::Encoder::new();

    for round in 0..rounds {
        for body in &bodies {
            #[expect(clippy::cast_possible_wrap, reason = "round count is tiny")]
            let series = crate::parser::parse(body, 1_700_000_000_000 + round as i64, true)?;
            let mut batch = Vec::with_capacity(series.len());
            for mut single in series {
                let mut labels = std::mem::take(&mut single.labels);
                labels.extend(target_labels.iter().cloned());
                let Some(mut labels) = crate::relabel::process(labels, &relabel_configs) else {
                    continue;
                };
                sort_labels(&mut labels);
                single.labels = labels;
                batch.push(single);
            }
            let request = WriteRequest { timeseries: batch };
            proto_buf.clear();
            request.encode(&mut proto_buf)?;
            let compressed = encoder.compress_vec(&proto_buf)?;
            checksum.0.write(&compressed);
        }
    }

    // Config parsing is startup-only but cheap to include.
    for _ in 0..50 {
        let _: crate::config::GlobalConfig =
            serde_saphyr::from_str("scrape_interval: 15s\nscrape_timeout: 10s\n")?;
    }

    // Print the checksum so the whole workload is observably used and the
    // optimizer cannot discard it.
    note(&format!(
        "pgo training done, checksum {:x}",
        checksum.0.finish()
    ));
    Ok(())
}

/// Load `*.prom` exposition bodies from the corpus directory. Unreadable
/// files and parse failures are skipped with a note — training must not
/// fail because one collected sample is stale or malformed.
fn load_corpus(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        note(&format!(
            "pgo corpus directory {} not readable",
            dir.display()
        ));
        return Vec::new();
    };
    let mut bodies = Vec::new();
    let mut paths: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "prom"))
        .collect();
    paths.sort();
    for path in paths {
        match std::fs::read_to_string(&path) {
            Ok(body) if !body.trim().is_empty() => {
                if crate::parser::parse(&body, 0, true).is_ok() {
                    bodies.push(body);
                } else {
                    note(&format!(
                        "pgo corpus {} does not parse; skipped",
                        path.display()
                    ));
                }
            }
            Ok(_) => note(&format!("pgo corpus {} is empty; skipped", path.display())),
            Err(err) => note(&format!("pgo corpus {}: {err}; skipped", path.display())),
        }
    }
    bodies
}

/// Realistic scrape body: counters with varied label values plus histogram
/// buckets, matching what exporters produce.
fn training_scrape_body(series: usize) -> String {
    let mut body = String::with_capacity(series * 96);
    body.push_str("# HELP http_requests_total Total HTTP requests.\n");
    body.push_str("# TYPE http_requests_total counter\n");
    for i in 0..series / 2 {
        let _ = writeln!(
            body,
            "http_requests_total{{method=\"GET\",code=\"200\",path=\"/api/v1/resource/{i}\",\
             handler=\"h{}\"}} {}",
            i % 97,
            i * 3 + 1
        );
    }
    body.push_str("# TYPE request_duration_seconds histogram\n");
    let buckets = ["0.005", "0.01", "0.05", "0.1", "0.5", "1", "+Inf"];
    let mut emitted = body.matches('\n').count();
    let mut handler = 0usize;
    while emitted < series {
        for le in &buckets {
            let _ = writeln!(
                body,
                "request_duration_seconds_bucket{{handler=\"h{handler}\",le=\"{le}\"}} {emitted}.5"
            );
            emitted += 1;
        }
        handler += 1;
    }
    body
}

struct FnvChecksum(FnvHasher);

impl Default for FnvChecksum {
    fn default() -> Self {
        Self(FnvHasher {
            hash: 0xcbf2_9ce4_8422_2325,
        })
    }
}

struct FnvHasher {
    hash: u64,
}

impl std::hash::Hasher for FnvHasher {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.hash ^= u64::from(*byte);
            self.hash = self.hash.wrapping_mul(0x100_0000_01b3);
        }
    }

    fn finish(&self) -> u64 {
        self.hash
    }
}
