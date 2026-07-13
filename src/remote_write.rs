//! Prometheus remote-write 1.0 sender.
//!
//! One sender task per configured endpoint. Samples arrive as batches of
//! [`TimeSeries`] over a bounded channel (backpressure: the scrape side drops
//! and counts when an endpoint's queue is full), are accumulated until
//! `max_samples_per_send` or `batch_send_deadline`, then encoded as a snappy
//! compressed protobuf `WriteRequest`.
//!
//! Retry semantics follow the remote-write 1.0 spec: retry forever with
//! exponential backoff on 429/5xx and transport errors, never retry other
//! 4xx (the batch is dropped and logged).

use std::{
    sync::{
        Arc,
        atomic::{
            AtomicU64,
            Ordering,
        },
    },
    time::Duration,
};

use anyhow::Context as _;
use tokio::{
    sync::mpsc,
    task::JoinHandle,
};
use tracing::{
    debug,
    error,
    info,
    warn,
};

use crate::{
    auth::Credentials,
    config::{
        ProtobufMessage,
        RemoteWriteConfig,
    },
    model::{
        TimeSeries,
        WriteRequest,
        sort_labels,
    },
    relabel::{
        self,
        RelabelConfig,
    },
};

/// Cheap-to-clone handle used by scrape loops to fan samples out to all
/// configured remote-write endpoints.
#[derive(Debug, Clone)]
pub struct RemoteWriteHandle {
    senders: Vec<mpsc::Sender<Vec<TimeSeries>>>,
    /// Total series dropped because an endpoint queue was full.
    dropped: Arc<AtomicU64>,
}

impl RemoteWriteHandle {
    /// Fan a batch out to every endpoint. Non-blocking: a full endpoint
    /// queue drops the batch for that endpoint (logged and counted).
    pub fn send(&self, mut batch: Vec<TimeSeries>) {
        if batch.is_empty() || self.senders.is_empty() {
            return;
        }
        let last = self.senders.len() - 1;
        for (i, sender) in self.senders.iter().enumerate() {
            let payload = if i == last {
                std::mem::take(&mut batch)
            } else {
                batch.clone()
            };
            if let Err(
                mpsc::error::TrySendError::Full(payload)
                | mpsc::error::TrySendError::Closed(payload),
            ) = sender.try_send(payload)
            {
                let count = payload.len() as u64;
                crate::telemetry::METRICS
                    .remote_write_dropped_series_total
                    .add(count);
                let total = self.dropped.fetch_add(count, Ordering::Relaxed) + count;
                warn!(
                    endpoint = i,
                    dropped = payload.len(),
                    total_dropped = total,
                    "remote-write queue full or closed; dropping series"
                );
            }
        }
    }

    #[must_use]
    pub fn total_dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Spawn one sender task per remote-write endpoint.
///
/// Dropping all clones of the returned handle closes the queues; the tasks
/// flush what they hold and exit — await the join handles for a clean
/// shutdown.
pub fn spawn(
    configs: &[RemoteWriteConfig],
) -> anyhow::Result<(RemoteWriteHandle, Vec<JoinHandle<()>>)> {
    let mut senders = Vec::with_capacity(configs.len());
    let mut tasks = Vec::with_capacity(configs.len());
    for config in configs {
        let endpoint = Endpoint::new(config)?;
        let (tx, rx) = mpsc::channel(queue_slots(config));
        senders.push(tx);
        tasks.push(tokio::spawn(endpoint.run(rx)));
    }
    Ok((
        RemoteWriteHandle {
            senders,
            dropped: Arc::new(AtomicU64::new(0)),
        },
        tasks,
    ))
}

/// The queue is bounded in batches, but `queue_config.capacity` is in
/// samples; scrape batches are typically hundreds of samples, so dividing by
/// a nominal batch size keeps memory in the same ballpark as Prometheus.
fn queue_slots(config: &RemoteWriteConfig) -> usize {
    (config.queue_config.capacity / 100).max(16)
}

struct Endpoint {
    name: String,
    url: String,
    protocol: ProtobufMessage,
    client: reqwest::Client,
    credentials: Credentials,
    extra_headers: Vec<(String, String)>,
    write_relabel_configs: Vec<RelabelConfig>,
    max_samples_per_send: usize,
    batch_send_deadline: Duration,
    min_backoff: Duration,
    max_backoff: Duration,
}

/// Reserved headers must not be overridden per the spec.
const RESERVED_HEADERS: &[&str] = &[
    "content-encoding",
    "content-type",
    "x-prometheus-remote-write-version",
];

impl Endpoint {
    fn new(config: &RemoteWriteConfig) -> anyhow::Result<Self> {
        let name = config.name.clone().unwrap_or_else(|| config.url.clone());
        let client =
            crate::auth::build_client(config.remote_timeout.as_duration(), &config.tls_config)
                .with_context(|| format!("remote_write {name}: building client"))?;
        let credentials = Credentials::resolve(
            config.basic_auth.as_ref(),
            config.authorization.as_ref(),
            config.bearer_token.as_deref(),
            None,
        )
        .with_context(|| format!("remote_write {name}: resolving credentials"))?;

        let mut extra_headers = Vec::new();
        for (key, value) in &config.headers {
            if RESERVED_HEADERS.contains(&key.to_lowercase().as_str()) {
                warn!(
                    endpoint = name,
                    header = key,
                    "ignoring reserved remote-write header"
                );
                continue;
            }
            extra_headers.push((key.clone(), value.clone()));
        }

        Ok(Self {
            name,
            url: config.url.clone(),
            protocol: config.protobuf_message,
            client,
            credentials,
            extra_headers,
            write_relabel_configs: config.write_relabel_configs.clone(),
            max_samples_per_send: config.queue_config.max_samples_per_send,
            batch_send_deadline: config.queue_config.batch_send_deadline.as_duration(),
            min_backoff: config.queue_config.min_backoff.as_duration(),
            max_backoff: config.queue_config.max_backoff.as_duration(),
        })
    }

    async fn run(self, mut rx: mpsc::Receiver<Vec<TimeSeries>>) {
        info!(endpoint = self.name, "remote-write sender started");
        let mut pending: Vec<TimeSeries> = Vec::new();
        let mut pending_samples = 0usize;
        // Reused encode buffers; snappy output is allocated per request.
        let mut proto_buf = Vec::new();
        let mut scratch = V2Scratch::default();
        let mut encoder = snap::raw::Encoder::new();
        let mut deadline = tokio::time::interval(self.batch_send_deadline);
        deadline.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                received = rx.recv() => match received {
                    Some(batch) => {
                        pending_samples += batch.len();
                        pending.extend(batch);
                        while pending_samples >= self.max_samples_per_send {
                            let (chunk, samples) = split_batch(&mut pending, self.max_samples_per_send);
                            pending_samples -= samples;
                            self.flush(chunk, &mut proto_buf, &mut scratch, &mut encoder).await;
                            deadline.reset();
                        }
                    }
                    None => break,
                },
                _ = deadline.tick() => {
                    if !pending.is_empty() {
                        let batch = std::mem::take(&mut pending);
                        pending_samples = 0;
                        self.flush(batch, &mut proto_buf, &mut scratch, &mut encoder).await;
                    }
                }
            }
        }
        if !pending.is_empty() {
            self.flush(
                std::mem::take(&mut pending),
                &mut proto_buf,
                &mut scratch,
                &mut encoder,
            )
            .await;
        }
        info!(endpoint = self.name, "remote-write sender stopped");
    }

    async fn flush(
        &self,
        mut batch: Vec<TimeSeries>,
        proto_buf: &mut Vec<u8>,
        scratch: &mut V2Scratch,
        encoder: &mut snap::raw::Encoder,
    ) {
        if !self.write_relabel_configs.is_empty() {
            batch = batch
                .into_iter()
                .filter_map(|mut series| {
                    let labels = relabel::process(
                        std::mem::take(&mut series.labels),
                        &self.write_relabel_configs,
                    )?;
                    series.labels = labels;
                    sort_labels(&mut series.labels);
                    Some(series)
                })
                .collect();
        }
        if batch.is_empty() {
            return;
        }

        let series_count = batch.len();
        let sample_count = batch.len() as u64;
        proto_buf.clear();
        match self.protocol {
            ProtobufMessage::WriteRequestV1 => {
                WriteRequest { timeseries: batch }.encode_into(proto_buf);
            }
            ProtobufMessage::WriteRequestV2 => {
                encode_v2_into(&batch, proto_buf, scratch);
            }
        }
        // `Bytes` so the per-attempt body handoff below is a refcount
        // bump instead of a full copy of the compressed payload.
        let compressed: bytes::Bytes = match encoder.compress_vec(proto_buf) {
            Ok(compressed) => compressed.into(),
            Err(err) => {
                error!(endpoint = self.name, %err, "snappy compression failed; dropping batch");
                return;
            }
        };

        let mut backoff = self.min_backoff;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.send_once(compressed.clone(), sample_count).await {
                Ok(()) => {
                    crate::telemetry::METRICS.remote_write_batches_total.inc();
                    crate::telemetry::METRICS
                        .remote_write_sent_bytes_total
                        .add(compressed.len() as u64);
                    debug!(
                        endpoint = self.name,
                        series = series_count,
                        attempt,
                        "batch sent"
                    );
                    return;
                }
                Err(SendError::Unrecoverable(message)) => {
                    crate::telemetry::METRICS
                        .remote_write_failed_batches_total
                        .inc();
                    error!(
                        endpoint = self.name,
                        series = series_count,
                        error = message,
                        "unrecoverable remote-write error; dropping batch"
                    );
                    return;
                }
                Err(SendError::Recoverable(message)) => {
                    crate::telemetry::METRICS.remote_write_retries_total.inc();
                    warn!(
                        endpoint = self.name,
                        attempt,
                        backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
                        error = message,
                        "remote-write failed; retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(self.max_backoff);
                }
            }
        }
    }

    async fn send_once(&self, body: bytes::Bytes, sample_count: u64) -> Result<(), SendError> {
        let (content_type, version) = match self.protocol {
            ProtobufMessage::WriteRequestV1 => ("application/x-protobuf", "0.1.0"),
            ProtobufMessage::WriteRequestV2 => (
                "application/x-protobuf;proto=io.prometheus.write.v2.Request",
                "2.0.0",
            ),
        };
        let mut builder = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .header(reqwest::header::CONTENT_ENCODING, "snappy")
            .header("X-Prometheus-Remote-Write-Version", version)
            .body(body);
        for (key, value) in &self.extra_headers {
            builder = builder.header(key, value);
        }
        builder = self.credentials.apply(builder);

        let response = builder
            .send()
            .await
            .map_err(|err| SendError::Recoverable(err.to_string()))?;
        let status = response.status();
        if status.is_success() {
            // Remote-write 2.0 receivers report what they actually wrote;
            // a 2xx with fewer samples written than sent is a partial write
            // that would otherwise be silent (the failure mode of
            // grafana/mimir#12622/#13576).
            if self.protocol == ProtobufMessage::WriteRequestV2 {
                let written = response
                    .headers()
                    .get("X-Prometheus-Remote-Write-Samples-Written")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok());
                if let Some(written) = written
                    && written < sample_count
                {
                    warn!(
                        endpoint = self.name,
                        sent = sample_count,
                        written,
                        "receiver accepted the request but wrote fewer samples than sent"
                    );
                }
            }
            return Ok(());
        }
        let detail = response.text().await.unwrap_or_default();
        let message = format!("HTTP {status}: {}", detail.trim());
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(SendError::Recoverable(message))
        } else {
            Err(SendError::Unrecoverable(message))
        }
    }
}

enum SendError {
    Recoverable(String),
    Unrecoverable(String),
}

type FxMap<'a> =
    std::collections::HashMap<&'a str, u32, std::hash::BuildHasherDefault<crate::hash::FxHasher>>;

/// Reusable buffers for the v2 encoder, held across batches by the sender
/// task so steady state allocates nothing per series.
#[derive(Debug, Default)]
struct V2Scratch {
    /// Flat stream of symbol refs for the whole batch, in series order —
    /// replaces the former per-series `labels_refs: Vec<u32>`.
    refs: Vec<u32>,
    /// Per-series encoded size of the packed `labels_refs` field,
    /// accumulated while pass 1 touches each ref anyway — the write loop
    /// would otherwise re-walk every ref just to sum `varint_len`s.
    packed_lens: Vec<u32>,
}

/// Single-pass remote-write 2.0 encoder: every distinct label name and
/// value is written once into the symbols table and series carry pairs of
/// symbol indices. Byte-identical to prost-encoding the `WriteRequestV2`
/// the previous implementation built (verified by test), without the
/// intermediate struct: no owned symbol `String`s, no per-series ref
/// `Vec`s — those were 18% of all live allocations.
fn encode_v2_into(batch: &[TimeSeries], buf: &mut Vec<u8>, scratch: &mut V2Scratch) {
    use crate::model::{
        put_varint,
        varint_len,
    };

    fn intern<'a>(symbols: &mut Vec<&'a str>, index: &mut FxMap<'a>, text: &'a str) -> u32 {
        if text.is_empty() {
            // symbols[0] MUST be the empty string per the 2.0 spec.
            return 0;
        }
        if let Some(reference) = index.get(text) {
            return *reference;
        }
        let reference = u32::try_from(symbols.len()).unwrap_or(0);
        symbols.push(text);
        index.insert(text, reference);
        reference
    }

    scratch.refs.clear();
    scratch.packed_lens.clear();
    let mut symbols: Vec<&str> = Vec::with_capacity(1024);
    symbols.push("");
    let mut index = FxMap::with_capacity_and_hasher(1024, std::hash::BuildHasherDefault::default());

    // Pass 1: intern all strings and collect the flat ref stream.
    // Consecutive series overwhelmingly share label names (same exposition
    // order) and target-level values (job/instance/...), so each label is
    // first compared against the previous series' label at the same
    // position — an equal string reuses the ref without touching the map,
    // which the profile showed dominated this pass. Reuse cannot change
    // interning order: it only fires for strings already interned.
    let mut prev: Option<&TimeSeries> = None;
    for series in batch {
        let base = scratch.refs.len();
        let mut packed = 0usize;
        let prev_matches = prev.is_some_and(|p| p.labels.len() == series.labels.len());
        for (position, label) in series.labels.iter().enumerate() {
            let mut name_ref = None;
            let mut value_ref = None;
            if prev_matches {
                #[expect(clippy::unwrap_used, reason = "prev_matches implies prev exists")]
                let previous = &prev.unwrap().labels[position];
                let prev_base = base - 2 * series.labels.len() + 2 * position;
                if previous.name == label.name {
                    name_ref = Some(scratch.refs[prev_base]);
                }
                if previous.value == label.value {
                    value_ref = Some(scratch.refs[prev_base + 1]);
                }
            }
            let name_ref =
                name_ref.unwrap_or_else(|| intern(&mut symbols, &mut index, &label.name));
            let value_ref =
                value_ref.unwrap_or_else(|| intern(&mut symbols, &mut index, &label.value));
            scratch.refs.push(name_ref);
            scratch.refs.push(value_ref);
            packed += varint_len(u64::from(name_ref)) + varint_len(u64::from(value_ref));
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "packed length of one series' refs is far below 4 GiB"
        )]
        scratch.packed_lens.push(packed as u32);
        prev = Some(series);
    }

    // Field 4: repeated string symbols, in interning order. Repeated
    // fields encode every element, including the empty string at index 0.
    for symbol in &symbols {
        buf.push(0x22);
        put_varint(symbol.len() as u64, buf);
        buf.extend_from_slice(symbol.as_bytes());
    }

    // Field 5: repeated TimeSeriesV2.
    let mut offset = 0usize;
    for (series, &packed) in batch.iter().zip(&scratch.packed_lens) {
        let packed = packed as usize;
        let refs = &scratch.refs[offset..offset + series.labels.len() * 2];
        offset += refs.len();
        let mut series_len = 0usize;
        if !refs.is_empty() {
            series_len += 1 + varint_len(packed as u64) + packed;
        }
        let sample_len = series.sample.wire_len();
        series_len += 1 + varint_len(sample_len as u64) + sample_len;
        buf.push(0x2a);
        put_varint(series_len as u64, buf);
        // Field 1: packed uint32 labels_refs (omitted when empty, matching
        // prost's packed-repeated encoding).
        if !refs.is_empty() {
            buf.push(0x0a);
            put_varint(packed as u64, buf);
            for &reference in refs {
                put_varint(u64::from(reference), buf);
            }
        }
        // Field 2: the single sample, as a repeated field of one.
        buf.push(0x12);
        put_varint(sample_len as u64, buf);
        series.sample.put_fields(buf);
    }
}

/// Split off up to `max_samples` worth of leading series from `pending`.
/// Returns the chunk and the number of samples it holds (one per series).
fn split_batch(pending: &mut Vec<TimeSeries>, max_samples: usize) -> (Vec<TimeSeries>, usize) {
    let cut = max_samples.min(pending.len());
    let rest = pending.split_off(cut);
    let chunk = std::mem::replace(pending, rest);
    let samples = chunk.len();
    (chunk, samples)
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::*;
    use crate::model::{
        Label,
        Sample,
        TimeSeriesV2,
        WriteRequestV2,
    };

    /// Reference v2 encoder via the prost-derived types — the previous
    /// production implementation, kept to pin the wire format of
    /// [`encode_v2_into`].
    fn encode_v2(batch: Vec<TimeSeries>) -> WriteRequestV2 {
        let mut symbols: Vec<String> = vec![String::new()];
        let mut index: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut intern = |symbols: &mut Vec<String>, text: &str| -> u32 {
            if text.is_empty() {
                return 0;
            }
            if let Some(reference) = index.get(text) {
                return *reference;
            }
            let reference = u32::try_from(symbols.len()).unwrap_or(0);
            symbols.push(text.to_owned());
            index.insert(text.to_owned(), reference);
            reference
        };

        let timeseries = batch
            .into_iter()
            .map(|series| {
                let mut labels_refs = Vec::with_capacity(series.labels.len() * 2);
                for label in &series.labels {
                    labels_refs.push(intern(&mut symbols, &label.name));
                    labels_refs.push(intern(&mut symbols, &label.value));
                }
                TimeSeriesV2 {
                    labels_refs,
                    samples: vec![series.sample],
                }
            })
            .collect();
        WriteRequestV2 {
            symbols,
            timeseries,
        }
    }

    /// The single-pass encoder must be byte-identical to prost-encoding
    /// the reference `WriteRequestV2`, across interning order, shared
    /// symbols, the reserved empty-string ref, packed ref fields, empty
    /// series and skipped default sample fields.
    #[test]
    fn encode_v2_into_matches_reference() {
        let batches: Vec<Vec<TimeSeries>> = vec![
            Vec::new(),
            vec![TimeSeries::default()],
            vec![
                TimeSeries {
                    labels: vec![
                        Label::new("__name__", "http_requests_total"),
                        Label::new("job", "node"),
                        Label::new("empty", ""),
                        Label::new("long", "x".repeat(300)),
                    ],
                    sample: Sample {
                        value: 1027.0,
                        timestamp: 1_395_066_363_000,
                    },
                    identity_hash: 0,
                },
                TimeSeries {
                    labels: vec![
                        Label::new("__name__", "http_requests_total"),
                        Label::new("job", "other"),
                    ],
                    sample: Sample {
                        value: crate::model::stale_nan(),
                        timestamp: -1,
                    },
                    identity_hash: 0,
                },
            ],
        ];
        for batch in batches {
            let mut buf = Vec::new();
            let mut scratch = V2Scratch::default();
            encode_v2_into(&batch, &mut buf, &mut scratch);
            let reference = encode_v2(batch).encode_to_vec();
            assert_eq!(buf, reference);
        }
    }

    /// A corpus-scale batch exercises multi-byte varint symbol refs and
    /// length delimiters.
    ///
    /// The corpus is committed (pseudonymized from real scrapes), so this must
    /// run everywhere. It previously skipped when the file was absent, which
    /// meant it only ever ran on the machine holding the private capture.
    #[test]
    fn encode_v2_into_matches_reference_on_large_batch() {
        let body = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("pgo-corpus/cilium-agent.prom"),
        )
        .expect("committed corpus is readable");
        let batch = crate::parser::parse(&body, 1_700_000_000_000, true).expect("corpus parses");
        let mut buf = Vec::new();
        let mut scratch = V2Scratch::default();
        encode_v2_into(&batch, &mut buf, &mut scratch);
        let reference = encode_v2(batch).encode_to_vec();
        assert_eq!(buf, reference);
    }

    fn series(name: &str, timestamp: i64) -> TimeSeries {
        TimeSeries {
            labels: vec![Label::new("__name__", name)],
            sample: Sample {
                value: 1.0,
                timestamp,
            },
            identity_hash: 0,
        }
    }

    #[test]
    fn split_batch_respects_sample_budget() {
        let mut pending = vec![series("a", 3), series("b", 3), series("c", 3)];
        let (chunk, samples) = split_batch(&mut pending, 2);
        assert_eq!(chunk.len(), 2);
        assert_eq!(samples, 2);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].labels[0].value, "c");
    }

    #[test]
    fn split_batch_takes_all_when_under_budget() {
        let mut pending = vec![series("a", 1), series("b", 1)];
        let (chunk, samples) = split_batch(&mut pending, 100);
        assert_eq!(chunk.len(), 2);
        assert_eq!(samples, 2);
        assert!(pending.is_empty());
    }

    #[test]
    fn v2_encoding_interns_symbols() {
        let batch = vec![
            TimeSeries {
                labels: vec![Label::new("__name__", "up"), Label::new("job", "node")],
                sample: Sample {
                    value: 1.0,
                    timestamp: 10,
                },
                identity_hash: 0,
            },
            TimeSeries {
                labels: vec![Label::new("__name__", "up"), Label::new("job", "other")],
                sample: Sample {
                    value: 0.0,
                    timestamp: 10,
                },
                identity_hash: 0,
            },
        ];
        let request = encode_v2(batch);
        // spec: symbols[0] is the empty string
        assert_eq!(request.symbols[0], "");
        // shared strings appear exactly once
        assert_eq!(
            request.symbols.iter().filter(|s| *s == "__name__").count(),
            1
        );
        assert_eq!(request.symbols.iter().filter(|s| *s == "up").count(), 1);
        assert_eq!(request.symbols.iter().filter(|s| *s == "job").count(), 1);
        // refs resolve back to the original label pairs
        let resolve = |refs: &[u32]| -> Vec<(String, String)> {
            refs.chunks(2)
                .map(|pair| {
                    (
                        request.symbols[pair[0] as usize].clone(),
                        request.symbols[pair[1] as usize].clone(),
                    )
                })
                .collect()
        };
        assert_eq!(
            resolve(&request.timeseries[0].labels_refs),
            vec![
                ("__name__".to_owned(), "up".to_owned()),
                ("job".to_owned(), "node".to_owned())
            ]
        );
        assert_eq!(resolve(&request.timeseries[1].labels_refs)[1].1, "other");
        // samples move through untouched
        assert!((request.timeseries[1].samples[0].value - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn v2_empty_label_value_uses_reserved_zero_ref() {
        let batch = vec![TimeSeries {
            labels: vec![Label::new("empty", "")],
            ..TimeSeries::default()
        }];
        let request = encode_v2(batch);
        assert_eq!(request.timeseries[0].labels_refs[1], 0);
    }

    #[test]
    fn v2_roundtrips_protobuf() -> anyhow::Result<()> {
        let request = encode_v2(vec![series("metric_a", 2), series("metric_b", 1)]);
        let decoded = WriteRequestV2::decode(request.encode_to_vec().as_slice())?;
        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn write_request_roundtrips_protobuf_snappy() -> anyhow::Result<()> {
        // Round-trip through the single-pass encoder and snappy; decoding
        // uses the same prost shadow types as the model parity tests.
        let request = WriteRequest {
            timeseries: vec![series("up", 1)],
        };
        let mut encoded = Vec::new();
        request.encode_into(&mut encoded);
        let compressed = snap::raw::Encoder::new().compress_vec(&encoded)?;
        let decompressed = snap::raw::Decoder::new().decompress_vec(&compressed)?;
        let decoded = crate::model::tests::PbWriteRequest::decode(decompressed.as_slice())?;
        assert_eq!(decoded.timeseries[0].samples[0].timestamp, 1);
        assert_eq!(decoded.timeseries[0].labels[0].value, "up");
        Ok(())
    }
}
