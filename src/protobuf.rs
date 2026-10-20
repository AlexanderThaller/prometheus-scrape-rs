//! Parser for the Prometheus protobuf exposition format: a stream of
//! varint-length-delimited `io.prometheus.client.MetricFamily` messages,
//! served as `application/vnd.google.protobuf;
//! proto=io.prometheus.client.MetricFamily; encoding=delimited`.
//!
//! It is the only exposition format that carries native histograms. The
//! conversion to series follows Prometheus' `textparse.ProtobufParser`:
//! counters, gauges and untyped metrics become one series each; summaries
//! become `_count`, `_sum` and one series per quantile; histograms become a
//! native histogram series (when enabled and the histogram is native), the
//! classic `_count`, `_sum` and `_bucket` series, or both.
//!
//! Like the text parser, any malformed message fails the whole scrape.

use std::{
    collections::HashSet,
    hash::Hasher as _,
};

use compact_str::CompactString;

use crate::{
    model::{
        BucketSpan,
        Histogram,
        HistogramCount,
        Label,
        METRIC_NAME_LABEL,
        ResetHint,
        Sample,
        TimeSeries,
    },
    parser::{
        MAX_LABELS_PER_SERIES,
        is_valid_name,
    },
};

/// Media type of the protobuf exposition format (without parameters).
pub const MEDIA_TYPE: &str = "application/vnd.google.protobuf";

/// The `proto` media-type parameter value naming the message type.
pub const MESSAGE_TYPE: &str = "io.prometheus.client.MetricFamily";

/// Finest exponential schema; finer histograms are reduced to it, like
/// Prometheus does on ingestion.
const SCHEMA_MAX: i32 = 8;

/// Coarsest exponential schema.
const SCHEMA_MIN: i32 = -4;

/// Hand-written `prost` messages matching `io/prometheus/client/metrics.proto`
/// (proto2, hence the `Option` scalars). Only the fields the conversion
/// reads are declared; prost skips the rest (help, unit, exemplars, created
/// timestamps) without allocating.
pub mod dto {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct MetricFamily {
        #[prost(string, optional, tag = "1")]
        pub name: Option<String>,
        /// Raw [`MetricType`] value, kept as `i32` so an unknown type is an
        /// error rather than prost's silent fallback to the default.
        #[prost(enumeration = "MetricType", optional, tag = "3")]
        pub r#type: Option<i32>,
        #[prost(message, repeated, tag = "4")]
        pub metric: Vec<Metric>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
    #[repr(i32)]
    pub enum MetricType {
        Counter = 0,
        Gauge = 1,
        Summary = 2,
        Untyped = 3,
        Histogram = 4,
        GaugeHistogram = 5,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Metric {
        #[prost(message, repeated, tag = "1")]
        pub label: Vec<LabelPair>,
        #[prost(message, optional, tag = "2")]
        pub gauge: Option<Gauge>,
        #[prost(message, optional, tag = "3")]
        pub counter: Option<Counter>,
        #[prost(message, optional, tag = "4")]
        pub summary: Option<Summary>,
        #[prost(message, optional, tag = "5")]
        pub untyped: Option<Untyped>,
        #[prost(message, optional, tag = "7")]
        pub histogram: Option<Histogram>,
        #[prost(int64, optional, tag = "6")]
        pub timestamp_ms: Option<i64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct LabelPair {
        #[prost(string, optional, tag = "1")]
        pub name: Option<String>,
        #[prost(string, optional, tag = "2")]
        pub value: Option<String>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Gauge {
        #[prost(double, optional, tag = "1")]
        pub value: Option<f64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Counter {
        #[prost(double, optional, tag = "1")]
        pub value: Option<f64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Untyped {
        #[prost(double, optional, tag = "1")]
        pub value: Option<f64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Quantile {
        #[prost(double, optional, tag = "1")]
        pub quantile: Option<f64>,
        #[prost(double, optional, tag = "2")]
        pub value: Option<f64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Summary {
        #[prost(uint64, optional, tag = "1")]
        pub sample_count: Option<u64>,
        #[prost(double, optional, tag = "2")]
        pub sample_sum: Option<f64>,
        #[prost(message, repeated, tag = "3")]
        pub quantile: Vec<Quantile>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Histogram {
        #[prost(uint64, optional, tag = "1")]
        pub sample_count: Option<u64>,
        #[prost(double, optional, tag = "4")]
        pub sample_count_float: Option<f64>,
        #[prost(double, optional, tag = "2")]
        pub sample_sum: Option<f64>,
        /// Classic buckets, cumulative and ordered by upper bound.
        #[prost(message, repeated, tag = "3")]
        pub bucket: Vec<Bucket>,
        #[prost(sint32, optional, tag = "5")]
        pub schema: Option<i32>,
        #[prost(double, optional, tag = "6")]
        pub zero_threshold: Option<f64>,
        #[prost(uint64, optional, tag = "7")]
        pub zero_count: Option<u64>,
        #[prost(double, optional, tag = "8")]
        pub zero_count_float: Option<f64>,
        #[prost(message, repeated, tag = "9")]
        pub negative_span: Vec<BucketSpan>,
        #[prost(sint64, repeated, packed = "false", tag = "10")]
        pub negative_delta: Vec<i64>,
        #[prost(double, repeated, packed = "false", tag = "11")]
        pub negative_count: Vec<f64>,
        #[prost(message, repeated, tag = "12")]
        pub positive_span: Vec<BucketSpan>,
        #[prost(sint64, repeated, packed = "false", tag = "13")]
        pub positive_delta: Vec<i64>,
        #[prost(double, repeated, packed = "false", tag = "14")]
        pub positive_count: Vec<f64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Bucket {
        #[prost(uint64, optional, tag = "1")]
        pub cumulative_count: Option<u64>,
        #[prost(double, optional, tag = "4")]
        pub cumulative_count_float: Option<f64>,
        #[prost(double, optional, tag = "2")]
        pub upper_bound: Option<f64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct BucketSpan {
        #[prost(sint32, optional, tag = "1")]
        pub offset: Option<i32>,
        #[prost(uint32, optional, tag = "2")]
        pub length: Option<u32>,
    }
}

/// Per-job conversion settings. Part of the deterministic pipeline: the
/// staleness tracker re-parses retained bodies with the same options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Use exposed timestamps; otherwise every series gets the scrape time.
    pub honor_timestamps: bool,
    /// Emit native histograms. Off, every histogram is converted to its
    /// classic series.
    pub native_histograms: bool,
    /// With native histograms on, also emit the classic series of native
    /// histograms that expose classic buckets.
    pub classic_histograms: bool,
    /// Maximum buckets per native histogram; `0` disables the limit.
    pub bucket_limit: u32,
}

/// Error produced when a protobuf scrape body cannot be converted.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ParseError(String);

/// Parse a delimited `MetricFamily` stream into remote-write-ready series.
///
/// `default_timestamp_ms` is the scrape start time, used for metrics without
/// a timestamp and for all of them unless `options.honor_timestamps`. Labels
/// are ordered `__name__` first, then as exposed — sorted later by the scrape
/// pipeline, like the text parser's output.
pub fn parse(
    body: &[u8],
    default_timestamp_ms: i64,
    options: Options,
) -> Result<Vec<TimeSeries>, ParseError> {
    let mut out = Vec::new();
    let mut rest = body;
    let mut index = 0usize;
    while !rest.is_empty() {
        index += 1;
        let family = <dto::MetricFamily as prost::Message>::decode_length_delimited(&mut rest)
            .map_err(|err| ParseError(format!("metric family #{index}: {err}")))?;
        convert_family(&family, default_timestamp_ms, options, &mut out).map_err(|message| {
            ParseError(format!(
                "metric family {:?}: {message}",
                family.name.as_deref().unwrap_or_default()
            ))
        })?;
    }
    Ok(out)
}

fn convert_family(
    family: &dto::MetricFamily,
    default_timestamp_ms: i64,
    options: Options,
    out: &mut Vec<TimeSeries>,
) -> Result<(), String> {
    use dto::MetricType;

    let name = family.name.as_deref().unwrap_or_default();
    if name.is_empty() {
        return Err("metric family without a name".to_owned());
    }
    if !is_valid_name(name, true) {
        return Err(format!("invalid metric name {name:?}"));
    }
    let raw_type = family.r#type.unwrap_or_default();
    let kind =
        MetricType::try_from(raw_type).map_err(|_| format!("unknown metric type {raw_type}"))?;

    for metric in &family.metric {
        let labels = base_labels(name, &metric.label)?;
        let timestamp = match metric.timestamp_ms {
            // Like Prometheus, an exposed timestamp of 0 means "none".
            Some(timestamp) if options.honor_timestamps && timestamp != 0 => timestamp,
            _ => default_timestamp_ms,
        };
        let series = SeriesBuilder {
            name,
            labels: &labels,
            timestamp,
        };
        match kind {
            MetricType::Counter => {
                let value = metric.counter.as_ref().and_then(|c| c.value);
                out.push(series.float("", None, value.unwrap_or_default())?);
            }
            MetricType::Gauge => {
                let value = metric.gauge.as_ref().and_then(|g| g.value);
                out.push(series.float("", None, value.unwrap_or_default())?);
            }
            MetricType::Untyped => {
                let value = metric.untyped.as_ref().and_then(|u| u.value);
                out.push(series.float("", None, value.unwrap_or_default())?);
            }
            MetricType::Summary => {
                let empty = dto::Summary::default();
                series.summary(metric.summary.as_ref().unwrap_or(&empty), out)?;
            }
            MetricType::Histogram | MetricType::GaugeHistogram => {
                let empty = dto::Histogram::default();
                let histogram = metric.histogram.as_ref().unwrap_or(&empty);
                let native = options.native_histograms && is_native(histogram);
                if native {
                    let converted = native_histogram(
                        histogram,
                        kind == MetricType::GaugeHistogram,
                        options.bucket_limit,
                    )?;
                    out.push(series.histogram(converted));
                }
                if !native || (options.classic_histograms && !histogram.bucket.is_empty()) {
                    series.classic_histogram(histogram, out)?;
                }
            }
        }
    }
    Ok(())
}

/// `__name__` plus the exposed labels, checked for empty, reserved and
/// duplicate names and the per-series label cap.
fn base_labels(name: &str, pairs: &[dto::LabelPair]) -> Result<Vec<Label>, String> {
    if pairs.len() + 1 > MAX_LABELS_PER_SERIES {
        return Err(format!(
            "series has more than {MAX_LABELS_PER_SERIES} labels"
        ));
    }
    // Headroom for target, external and derived (`le`/`quantile`) labels,
    // as in the text parser.
    let mut labels = Vec::with_capacity(pairs.len() + 12);
    labels.push(Label::new(METRIC_NAME_LABEL, name));
    for pair in pairs {
        let label_name = pair.name.as_deref().unwrap_or_default();
        if !is_valid_name(label_name, false) {
            return Err(format!("invalid label name {label_name:?}"));
        }
        labels.push(Label::new(
            label_name,
            pair.value.as_deref().unwrap_or_default(),
        ));
    }
    // Small sets (the norm) are scanned; large ones would go quadratic.
    if labels.len() <= 32 {
        for (i, label) in labels.iter().enumerate() {
            if labels[..i].iter().any(|seen| seen.name == label.name) {
                return Err(format!("duplicate label name {:?}", label.name));
            }
        }
    } else {
        let mut seen: HashSet<&CompactString> = HashSet::with_capacity(labels.len());
        for label in &labels {
            if !seen.insert(&label.name) {
                return Err(format!("duplicate label name {:?}", label.name));
            }
        }
    }
    Ok(labels)
}

/// Builds the series of one exposed metric.
struct SeriesBuilder<'a> {
    name: &'a str,
    labels: &'a [Label],
    timestamp: i64,
}

impl SeriesBuilder<'_> {
    /// The metric's labels with `__name__` set to the family name plus
    /// `suffix`, and `extra` (`le`/`quantile`) appended.
    fn labels(&self, suffix: &str, extra: Option<(&str, &str)>) -> Result<Vec<Label>, String> {
        let mut labels = self.labels.to_vec();
        if !suffix.is_empty() {
            let mut name = CompactString::from(self.name);
            name.push_str(suffix);
            labels[0].value = name;
        }
        if let Some((name, value)) = extra {
            if labels.iter().any(|label| label.name == name) {
                return Err(format!(
                    "label {name:?} collides with the {name:?} the series derives"
                ));
            }
            labels.push(Label::new(name, value));
        }
        Ok(labels)
    }

    /// A float series named after the family plus `suffix`, with an
    /// optional derived label.
    fn float(
        &self,
        suffix: &str,
        extra: Option<(&str, &str)>,
        value: f64,
    ) -> Result<TimeSeries, String> {
        Ok(self.series(self.labels(suffix, extra)?, value, None))
    }

    fn histogram(&self, histogram: Histogram) -> TimeSeries {
        self.series(self.labels.to_vec(), 0.0, Some(Box::new(histogram)))
    }

    fn series(
        &self,
        labels: Vec<Label>,
        value: f64,
        histogram: Option<Box<Histogram>>,
    ) -> TimeSeries {
        // The staleness identity: deterministic across re-parses of the
        // same body, distinct between a native histogram and a float
        // series with the same labels.
        let mut hasher = crate::hash::FxHasher::default();
        for label in &labels {
            hasher.write(label.name.as_bytes());
            hasher.write(label.value.as_bytes());
        }
        hasher.write_u8(u8::from(histogram.is_some()));
        TimeSeries {
            labels,
            sample: Sample {
                value,
                timestamp: self.timestamp,
            },
            identity_hash: hasher.finish(),
            histogram,
        }
    }

    fn summary(&self, summary: &dto::Summary, out: &mut Vec<TimeSeries>) -> Result<(), String> {
        out.push(self.float(
            "_count",
            None,
            to_f64(summary.sample_count.unwrap_or_default()),
        )?);
        out.push(self.float("_sum", None, summary.sample_sum.unwrap_or_default())?);
        for quantile in &summary.quantile {
            let label = format_float(quantile.quantile.unwrap_or_default());
            out.push(self.float(
                "",
                Some(("quantile", &label)),
                quantile.value.unwrap_or_default(),
            )?);
        }
        Ok(())
    }

    /// The classic `_count`, `_sum` and cumulative `_bucket` series, plus
    /// the `+Inf` bucket when the exposition leaves it implicit.
    fn classic_histogram(
        &self,
        histogram: &dto::Histogram,
        out: &mut Vec<TimeSeries>,
    ) -> Result<(), String> {
        let count = match histogram.sample_count_float {
            Some(count) if count > 0.0 => count,
            _ => to_f64(histogram.sample_count.unwrap_or_default()),
        };
        out.push(self.float("_count", None, count)?);
        out.push(self.float("_sum", None, histogram.sample_sum.unwrap_or_default())?);
        for bucket in &histogram.bucket {
            let value = match bucket.cumulative_count_float {
                Some(count) if count > 0.0 => count,
                _ => to_f64(bucket.cumulative_count.unwrap_or_default()),
            };
            let le = format_float(bucket.upper_bound.unwrap_or_default());
            out.push(self.float("_bucket", Some(("le", &le)), value)?);
        }
        let explicit_inf = histogram
            .bucket
            .last()
            .is_some_and(|bucket| bucket.upper_bound == Some(f64::INFINITY));
        if !explicit_inf {
            out.push(self.float("_bucket", Some(("le", "+Inf")), count)?);
        }
        Ok(())
    }
}

/// Prometheus' `isNativeHistogram`: anything with spans, a zero bucket or
/// zero observations in it. A native histogram without observations must
/// expose a no-op span to be recognized, as instrumentation libraries do.
fn is_native(histogram: &dto::Histogram) -> bool {
    !histogram.positive_span.is_empty()
        || !histogram.negative_span.is_empty()
        || histogram.zero_threshold.unwrap_or_default() > 0.0
        || histogram.zero_count.unwrap_or_default() > 0
        || histogram.zero_count_float.unwrap_or_default() > 0.0
}

fn native_histogram(
    exposed: &dto::Histogram,
    gauge: bool,
    bucket_limit: u32,
) -> Result<Histogram, String> {
    let schema = exposed.schema.unwrap_or_default();
    if schema < SCHEMA_MIN {
        return Err(format!(
            "native histogram schema {schema} is below the minimum of {SCHEMA_MIN}"
        ));
    }
    let spans = |spans: &[dto::BucketSpan]| -> Vec<BucketSpan> {
        spans
            .iter()
            .map(|span| BucketSpan {
                offset: span.offset.unwrap_or_default(),
                length: span.length.unwrap_or_default(),
            })
            .collect()
    };
    // Prometheus' rule: any float count makes it a float histogram, whose
    // buckets are absolute counts instead of deltas.
    let float = exposed.sample_count_float.unwrap_or_default() > 0.0
        || exposed.zero_count_float.unwrap_or_default() > 0.0;
    let mut histogram = Histogram {
        sum: exposed.sample_sum.unwrap_or_default(),
        schema,
        zero_threshold: exposed.zero_threshold.unwrap_or_default(),
        negative_spans: spans(&exposed.negative_span),
        positive_spans: spans(&exposed.positive_span),
        reset_hint: if gauge {
            ResetHint::Gauge
        } else {
            ResetHint::Unknown
        },
        ..Histogram::default()
    };
    if float {
        histogram.count = HistogramCount::Float(exposed.sample_count_float.unwrap_or_default());
        histogram.zero_count = HistogramCount::Float(exposed.zero_count_float.unwrap_or_default());
        histogram
            .negative_counts
            .clone_from(&exposed.negative_count);
        histogram
            .positive_counts
            .clone_from(&exposed.positive_count);
    } else {
        histogram.count = HistogramCount::Int(exposed.sample_count.unwrap_or_default());
        histogram.zero_count = HistogramCount::Int(exposed.zero_count.unwrap_or_default());
        histogram
            .negative_deltas
            .clone_from(&exposed.negative_delta);
        histogram
            .positive_deltas
            .clone_from(&exposed.positive_delta);
    }
    validate_side(
        "negative",
        &histogram.negative_spans,
        bucket_len(&histogram, Side::Negative),
        &histogram.negative_deltas,
    )?;
    validate_side(
        "positive",
        &histogram.positive_spans,
        bucket_len(&histogram, Side::Positive),
        &histogram.positive_deltas,
    )?;

    if histogram.schema > SCHEMA_MAX {
        reduce_resolution(&mut histogram, SCHEMA_MAX)?;
    }
    if bucket_limit > 0 {
        let limit = usize::try_from(bucket_limit).unwrap_or(usize::MAX);
        while bucket_len(&histogram, Side::Negative) + bucket_len(&histogram, Side::Positive)
            > limit
        {
            if histogram.schema <= SCHEMA_MIN {
                return Err(format!(
                    "native histogram has more than native_histogram_bucket_limit of {limit} \
                     buckets even at the coarsest schema"
                ));
            }
            let coarser = histogram.schema - 1;
            reduce_resolution(&mut histogram, coarser)?;
        }
    }
    Ok(histogram)
}

#[derive(Debug, Clone, Copy)]
enum Side {
    Negative,
    Positive,
}

/// Populated buckets on one side, whichever representation is in use.
fn bucket_len(histogram: &Histogram, side: Side) -> usize {
    match side {
        Side::Negative => histogram.negative_deltas.len() + histogram.negative_counts.len(),
        Side::Positive => histogram.positive_deltas.len() + histogram.positive_counts.len(),
    }
}

/// Structural checks a receiver would otherwise reject the whole request
/// for: span lengths must add up to the bucket count, spans after the first
/// must not go backwards, bucket indices must fit `i32`, and integer deltas
/// must describe non-negative counts.
fn validate_side(
    side: &str,
    spans: &[BucketSpan],
    buckets: usize,
    deltas: &[i64],
) -> Result<(), String> {
    let mut covered = 0u64;
    // Index of the bucket right after the previous span.
    let mut next = 0i64;
    for (i, span) in spans.iter().enumerate() {
        if i > 0 && span.offset < 0 {
            return Err(format!(
                "{side} span {i} has negative offset {}",
                span.offset
            ));
        }
        let first = next + i64::from(span.offset);
        let last = first + i64::from(span.length.max(1)) - 1;
        if i32::try_from(first).is_err() || i32::try_from(last).is_err() {
            return Err(format!("{side} bucket index {last} out of range"));
        }
        covered += u64::from(span.length);
        next = first + i64::from(span.length);
    }
    if covered != buckets as u64 {
        return Err(format!(
            "{side} spans cover {covered} buckets but {buckets} are exposed"
        ));
    }
    let mut count = 0i64;
    for delta in deltas {
        count = count
            .checked_add(*delta)
            .ok_or_else(|| format!("{side} bucket count overflows"))?;
        if count < 0 {
            return Err(format!("{side} bucket count {count} is negative"));
        }
    }
    Ok(())
}

/// Merge buckets down to `target` (coarser than the current schema). Each
/// step down merges pairs of neighbouring buckets; the zero bucket, sum and
/// count are unaffected.
fn reduce_resolution(histogram: &mut Histogram, target: i32) -> Result<(), String> {
    let shift = histogram.schema - target;
    for side in [Side::Negative, Side::Positive] {
        let (spans, deltas, counts) = match side {
            Side::Negative => (
                &mut histogram.negative_spans,
                &mut histogram.negative_deltas,
                &mut histogram.negative_counts,
            ),
            Side::Positive => (
                &mut histogram.positive_spans,
                &mut histogram.positive_deltas,
                &mut histogram.positive_counts,
            ),
        };
        if counts.is_empty() {
            // Integer histogram (or an empty side): merge absolute counts,
            // then re-encode as deltas.
            let mut absolute = Vec::with_capacity(deltas.len());
            let mut count = 0i64;
            for delta in deltas.iter() {
                count += delta;
                absolute.push(count);
            }
            let (merged_spans, merged) = merge_buckets(spans, &absolute, shift)?;
            *spans = merged_spans;
            deltas.clear();
            let mut previous = 0;
            for count in merged {
                deltas.push(count - previous);
                previous = count;
            }
        } else {
            let (merged_spans, merged) = merge_buckets(spans, counts, shift)?;
            *spans = merged_spans;
            *counts = merged;
        }
    }
    histogram.schema = target;
    Ok(())
}

/// Re-bucket `counts` (absolute, laid out by `spans`) `shift` schemas
/// coarser: bucket `i` lands in `((i - 1) >> shift) + 1`, Prometheus'
/// `targetIdx`. Indices only ever move towards 1, so the output stays in
/// `i32` when the input does (checked by [`validate_side`]).
fn merge_buckets<T>(
    spans: &[BucketSpan],
    counts: &[T],
    shift: i32,
) -> Result<(Vec<BucketSpan>, Vec<T>), String>
where
    T: Copy + std::ops::AddAssign,
{
    let mut out_spans: Vec<BucketSpan> = Vec::new();
    let mut out_counts: Vec<T> = Vec::with_capacity(counts.len());
    let mut counts = counts.iter();
    let mut index = 0i64;
    let mut last: Option<i64> = None;
    let to_i32 =
        |value: i64| i32::try_from(value).map_err(|_| format!("bucket index {value} out of range"));
    for span in spans {
        index += i64::from(span.offset);
        for _ in 0..span.length {
            let Some(&count) = counts.next() else {
                return Err("spans cover more buckets than exposed".to_owned());
            };
            let target = ((index - 1) >> shift) + 1;
            match last {
                Some(previous) if previous == target => {
                    if let Some(merged) = out_counts.last_mut() {
                        *merged += count;
                    }
                }
                Some(previous) if previous + 1 == target => {
                    if let Some(span) = out_spans.last_mut() {
                        span.length += 1;
                    }
                    out_counts.push(count);
                }
                Some(previous) => {
                    out_spans.push(BucketSpan {
                        offset: to_i32(target - previous - 1)?,
                        length: 1,
                    });
                    out_counts.push(count);
                }
                None => {
                    out_spans.push(BucketSpan {
                        offset: to_i32(target)?,
                        length: 1,
                    });
                    out_counts.push(count);
                }
            }
            last = Some(target);
            index += 1;
        }
    }
    Ok((out_spans, out_counts))
}

/// Prometheus' `formatOpenMetricsFloat`, used for `le` and `quantile`
/// values: Go's shortest `%g` (exponent form below 1e-4 and from 1e6 on,
/// with a sign and at least two exponent digits), plus `.0` on integers.
fn format_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "+Inf" } else { "-Inf" }.to_owned();
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or_default();
    let mut text = if (-4..6).contains(&exponent) {
        // Rust's `Display` is the shortest round-trip form, never in
        // exponent notation — Go's `%f` branch of `%g`.
        value.to_string()
    } else {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exponent.unsigned_abs())
    };
    if !text.contains(['.', 'e', 'E']) {
        text.push_str(".0");
    }
    text
}

#[expect(
    clippy::cast_precision_loss,
    reason = "Prometheus converts uint64 counts to float64 the same way"
)]
fn to_f64(count: u64) -> f64 {
    count as f64
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::*;

    const TS: i64 = 1_700_000_000_000;

    fn options() -> Options {
        Options {
            honor_timestamps: true,
            native_histograms: true,
            classic_histograms: false,
            bucket_limit: 0,
        }
    }

    fn body(families: &[dto::MetricFamily]) -> Vec<u8> {
        let mut buf = Vec::new();
        for family in families {
            family
                .encode_length_delimited(&mut buf)
                .expect("Vec grows as needed");
        }
        buf
    }

    fn family(name: &str, kind: dto::MetricType, metric: Vec<dto::Metric>) -> dto::MetricFamily {
        dto::MetricFamily {
            name: Some(name.to_owned()),
            r#type: Some(kind as i32),
            metric,
        }
    }

    fn label_pairs(pairs: &[(&str, &str)]) -> Vec<dto::LabelPair> {
        pairs
            .iter()
            .map(|(name, value)| dto::LabelPair {
                name: Some((*name).to_owned()),
                value: Some((*value).to_owned()),
            })
            .collect()
    }

    fn label<'a>(series: &'a TimeSeries, name: &str) -> Option<&'a str> {
        series
            .labels
            .iter()
            .find(|label| label.name == name)
            .map(|label| label.value.as_str())
    }

    fn names(series: &[TimeSeries]) -> Vec<String> {
        series
            .iter()
            .map(|s| {
                let mut name = label(s, METRIC_NAME_LABEL).unwrap_or_default().to_owned();
                for extra in ["le", "quantile"] {
                    if let Some(value) = label(s, extra) {
                        name = format!("{name}{{{extra}={value}}}");
                    }
                }
                name
            })
            .collect()
    }

    fn span(offset: i32, length: u32) -> dto::BucketSpan {
        dto::BucketSpan {
            offset: Some(offset),
            length: Some(length),
        }
    }

    /// A histogram as `client_golang` exposes one with both native and
    /// classic buckets: observations 0.5, 1.5, 1.5, 3 at schema 0.
    fn mixed_histogram() -> dto::Histogram {
        dto::Histogram {
            sample_count: Some(4),
            sample_sum: Some(6.5),
            bucket: vec![
                dto::Bucket {
                    cumulative_count: Some(1),
                    upper_bound: Some(1.0),
                    ..dto::Bucket::default()
                },
                dto::Bucket {
                    cumulative_count: Some(3),
                    upper_bound: Some(2.0),
                    ..dto::Bucket::default()
                },
            ],
            schema: Some(0),
            zero_threshold: Some(2.938_735_877_055_719e-39),
            zero_count: Some(0),
            // Buckets (0.5,1], (1,2], (2,4] are indices 0, 1, 2.
            positive_span: vec![span(0, 3)],
            positive_delta: vec![1, 1, -1],
            ..dto::Histogram::default()
        }
    }

    #[test]
    fn scalar_types() -> Result<(), ParseError> {
        let families = [
            family(
                "requests_total",
                dto::MetricType::Counter,
                vec![dto::Metric {
                    label: label_pairs(&[("code", "200")]),
                    counter: Some(dto::Counter { value: Some(7.0) }),
                    ..dto::Metric::default()
                }],
            ),
            family(
                "temperature",
                dto::MetricType::Gauge,
                vec![dto::Metric {
                    gauge: Some(dto::Gauge { value: Some(-3.5) }),
                    timestamp_ms: Some(1_234),
                    ..dto::Metric::default()
                }],
            ),
            family(
                "mystery",
                dto::MetricType::Untyped,
                vec![dto::Metric {
                    untyped: Some(dto::Untyped { value: Some(1.0) }),
                    ..dto::Metric::default()
                }],
            ),
        ];
        let series = parse(&body(&families), TS, options())?;
        assert_eq!(names(&series), ["requests_total", "temperature", "mystery"]);
        assert_eq!(label(&series[0], "code"), Some("200"));
        assert!((series[0].sample.value - 7.0).abs() < f64::EPSILON);
        assert_eq!(series[0].sample.timestamp, TS);
        assert!((series[1].sample.value + 3.5).abs() < f64::EPSILON);
        assert_eq!(
            series[1].sample.timestamp, 1_234,
            "exposed timestamp honored"
        );
        assert!(series.iter().all(|s| s.histogram.is_none()));

        let ignored = parse(
            &body(&families),
            TS,
            Options {
                honor_timestamps: false,
                ..options()
            },
        )?;
        assert_eq!(ignored[1].sample.timestamp, TS);
        Ok(())
    }

    #[test]
    fn summary_expands_like_prometheus() -> Result<(), ParseError> {
        let families = [family(
            "rpc_seconds",
            dto::MetricType::Summary,
            vec![dto::Metric {
                summary: Some(dto::Summary {
                    sample_count: Some(10),
                    sample_sum: Some(2.5),
                    quantile: vec![
                        dto::Quantile {
                            quantile: Some(0.5),
                            value: Some(0.2),
                        },
                        dto::Quantile {
                            quantile: Some(1.0),
                            value: Some(0.9),
                        },
                    ],
                }),
                ..dto::Metric::default()
            }],
        )];
        let series = parse(&body(&families), TS, options())?;
        assert_eq!(
            names(&series),
            [
                "rpc_seconds_count",
                "rpc_seconds_sum",
                "rpc_seconds{quantile=0.5}",
                "rpc_seconds{quantile=1.0}",
            ]
        );
        assert!((series[0].sample.value - 10.0).abs() < f64::EPSILON);
        Ok(())
    }

    #[test]
    fn native_histogram_when_enabled() -> Result<(), ParseError> {
        let families = [family(
            "latency_seconds",
            dto::MetricType::Histogram,
            vec![dto::Metric {
                label: label_pairs(&[("path", "/")]),
                histogram: Some(mixed_histogram()),
                ..dto::Metric::default()
            }],
        )];
        let series = parse(&body(&families), TS, options())?;
        assert_eq!(names(&series), ["latency_seconds"]);
        let histogram = series[0].histogram.as_deref().expect("native histogram");
        assert_eq!(histogram.count, HistogramCount::Int(4));
        assert!((histogram.sum - 6.5).abs() < f64::EPSILON);
        assert_eq!(histogram.schema, 0);
        assert_eq!(histogram.zero_count, HistogramCount::Int(0));
        assert_eq!(
            histogram.positive_spans,
            [BucketSpan {
                offset: 0,
                length: 3
            }]
        );
        assert_eq!(histogram.positive_deltas, [1, 1, -1]);
        assert_eq!(histogram.positive_counts, Vec::<f64>::new());
        assert_eq!(histogram.reset_hint, ResetHint::Unknown);
        assert_eq!(series[0].sample.timestamp, TS);
        assert_eq!(label(&series[0], "path"), Some("/"));
        Ok(())
    }

    #[test]
    fn classic_series_without_native_histograms() -> Result<(), ParseError> {
        let families = [family(
            "latency_seconds",
            dto::MetricType::Histogram,
            vec![dto::Metric {
                histogram: Some(mixed_histogram()),
                ..dto::Metric::default()
            }],
        )];
        let series = parse(
            &body(&families),
            TS,
            Options {
                native_histograms: false,
                ..options()
            },
        )?;
        assert_eq!(
            names(&series),
            [
                "latency_seconds_count",
                "latency_seconds_sum",
                "latency_seconds_bucket{le=1.0}",
                "latency_seconds_bucket{le=2.0}",
                "latency_seconds_bucket{le=+Inf}",
            ]
        );
        let values: Vec<f64> = series.iter().map(|s| s.sample.value).collect();
        assert_eq!(values, [4.0, 6.5, 1.0, 3.0, 4.0]);
        assert!(series.iter().all(|s| s.histogram.is_none()));
        Ok(())
    }

    #[test]
    fn always_scrape_classic_histograms_emits_both() -> Result<(), ParseError> {
        let families = [family(
            "latency_seconds",
            dto::MetricType::Histogram,
            vec![dto::Metric {
                histogram: Some(mixed_histogram()),
                ..dto::Metric::default()
            }],
        )];
        let both = Options {
            classic_histograms: true,
            ..options()
        };
        let series = parse(&body(&families), TS, both)?;
        assert_eq!(series.len(), 6);
        assert!(series[0].histogram.is_some());
        assert_eq!(
            names(&series[1..]),
            [
                "latency_seconds_count",
                "latency_seconds_sum",
                "latency_seconds_bucket{le=1.0}",
                "latency_seconds_bucket{le=2.0}",
                "latency_seconds_bucket{le=+Inf}",
            ]
        );
        // Identities of the native and classic series differ.
        let mut hashes: Vec<u64> = series.iter().map(|s| s.identity_hash).collect();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), 6);

        // A native-only histogram has no classic buckets to add.
        let mut native_only = mixed_histogram();
        native_only.bucket.clear();
        let families = [family(
            "native_only",
            dto::MetricType::Histogram,
            vec![dto::Metric {
                histogram: Some(native_only),
                ..dto::Metric::default()
            }],
        )];
        assert_eq!(names(&parse(&body(&families), TS, both)?), ["native_only"]);
        Ok(())
    }

    #[test]
    fn classic_only_histogram_stays_classic_with_native_enabled() -> Result<(), ParseError> {
        let mut classic = mixed_histogram();
        classic.positive_span.clear();
        classic.positive_delta.clear();
        classic.zero_threshold = None;
        let families = [family(
            "classic",
            dto::MetricType::Histogram,
            vec![dto::Metric {
                histogram: Some(classic),
                ..dto::Metric::default()
            }],
        )];
        let series = parse(&body(&families), TS, options())?;
        assert_eq!(series.len(), 5);
        assert!(series.iter().all(|s| s.histogram.is_none()));
        Ok(())
    }

    #[test]
    fn float_gauge_histogram() -> Result<(), ParseError> {
        let families = [family(
            "queue_size",
            dto::MetricType::GaugeHistogram,
            vec![dto::Metric {
                histogram: Some(dto::Histogram {
                    sample_count_float: Some(2.5),
                    sample_sum: Some(10.0),
                    schema: Some(1),
                    zero_threshold: Some(0.001),
                    zero_count_float: Some(0.5),
                    negative_span: vec![span(-1, 1)],
                    negative_count: vec![1.0],
                    positive_span: vec![span(2, 1)],
                    positive_count: vec![1.0],
                    ..dto::Histogram::default()
                }),
                ..dto::Metric::default()
            }],
        )];
        let series = parse(&body(&families), TS, options())?;
        let histogram = series[0].histogram.as_deref().expect("native histogram");
        assert_eq!(histogram.count, HistogramCount::Float(2.5));
        assert_eq!(histogram.zero_count, HistogramCount::Float(0.5));
        assert_eq!(histogram.negative_counts, [1.0]);
        assert_eq!(histogram.positive_counts, [1.0]);
        assert_eq!(histogram.positive_deltas, Vec::<i64>::new());
        assert_eq!(histogram.reset_hint, ResetHint::Gauge);
        Ok(())
    }

    /// An observation-free native histogram is recognized by its no-op
    /// span, as `client_golang` exposes it.
    #[test]
    fn empty_native_histogram_with_noop_span() -> Result<(), ParseError> {
        let families = [family(
            "idle",
            dto::MetricType::Histogram,
            vec![dto::Metric {
                histogram: Some(dto::Histogram {
                    schema: Some(3),
                    positive_span: vec![span(0, 0)],
                    ..dto::Histogram::default()
                }),
                ..dto::Metric::default()
            }],
        )];
        let series = parse(&body(&families), TS, options())?;
        let histogram = series[0].histogram.as_deref().expect("native histogram");
        assert_eq!(histogram.count, HistogramCount::Int(0));
        assert_eq!(histogram.schema, 3);
        Ok(())
    }

    fn histogram_family(histogram: dto::Histogram) -> Vec<u8> {
        body(&[family(
            "h",
            dto::MetricType::Histogram,
            vec![dto::Metric {
                histogram: Some(histogram),
                ..dto::Metric::default()
            }],
        )])
    }

    /// Absolute bucket counts by bucket index, decoded from spans + deltas.
    fn absolute(spans: &[BucketSpan], deltas: &[i64]) -> Vec<(i64, i64)> {
        let mut out = Vec::new();
        let mut index = 0i64;
        let mut count = 0i64;
        let mut deltas = deltas.iter();
        for span in spans {
            index += i64::from(span.offset);
            for _ in 0..span.length {
                count += deltas.next().expect("enough deltas");
                out.push((index, count));
                index += 1;
            }
        }
        out
    }

    #[test]
    fn schema_above_eight_is_reduced() -> Result<(), ParseError> {
        // Schema 9 indices 1..=4 and 7 merge pairwise into schema 8:
        // ((i - 1) >> 1) + 1 → 1, 1, 2, 2, 4.
        let series = parse(
            &histogram_family(dto::Histogram {
                sample_count: Some(15),
                schema: Some(9),
                positive_span: vec![span(1, 4), span(2, 1)],
                positive_delta: vec![1, 1, 1, 1, 1],
                ..dto::Histogram::default()
            }),
            TS,
            options(),
        )?;
        let histogram = series[0].histogram.as_deref().expect("native histogram");
        assert_eq!(histogram.schema, 8);
        assert_eq!(
            absolute(&histogram.positive_spans, &histogram.positive_deltas),
            [(1, 3), (2, 7), (4, 5)]
        );
        Ok(())
    }

    #[test]
    fn bucket_limit_reduces_resolution() -> Result<(), ParseError> {
        // Negative indices exercise the arithmetic shift: at schema 2,
        // -3..=0 and 1..=4 each fold into two buckets per step.
        let exposed = dto::Histogram {
            sample_count: Some(8),
            schema: Some(2),
            negative_span: vec![span(-3, 4)],
            negative_delta: vec![1, 0, 0, 0],
            positive_span: vec![span(1, 4)],
            positive_delta: vec![1, 0, 0, 0],
            ..dto::Histogram::default()
        };
        let limited = |limit| Options {
            bucket_limit: limit,
            ..options()
        };
        let series = parse(&histogram_family(exposed.clone()), TS, limited(4))?;
        let histogram = series[0].histogram.as_deref().expect("native histogram");
        assert_eq!(histogram.schema, 1);
        assert_eq!(
            absolute(&histogram.negative_spans, &histogram.negative_deltas),
            [(-1, 2), (0, 2)]
        );
        assert_eq!(
            absolute(&histogram.positive_spans, &histogram.positive_deltas),
            [(1, 2), (2, 2)]
        );

        // Every bucket count is 1, so no schema fits a limit of 1 per side
        // plus the other side: the scrape fails.
        let err = parse(&histogram_family(exposed), TS, limited(1)).expect_err("over limit");
        assert!(
            err.to_string().contains("native_histogram_bucket_limit"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn float_histogram_reduction_sums_counts() -> Result<(), ParseError> {
        let series = parse(
            &histogram_family(dto::Histogram {
                sample_count_float: Some(3.0),
                schema: Some(9),
                positive_span: vec![span(1, 2)],
                positive_count: vec![1.5, 1.5],
                ..dto::Histogram::default()
            }),
            TS,
            options(),
        )?;
        let histogram = series[0].histogram.as_deref().expect("native histogram");
        assert_eq!(histogram.schema, 8);
        assert_eq!(
            histogram.positive_spans,
            [BucketSpan {
                offset: 1,
                length: 1
            }]
        );
        assert_eq!(histogram.positive_counts, [3.0]);
        Ok(())
    }

    #[test]
    fn malformed_native_histograms_fail_the_scrape() {
        let cases = [
            (
                dto::Histogram {
                    positive_span: vec![span(0, 2)],
                    positive_delta: vec![1],
                    ..dto::Histogram::default()
                },
                "cover 2 buckets but 1",
            ),
            (
                dto::Histogram {
                    positive_span: vec![span(0, 1), span(-2, 1)],
                    positive_delta: vec![1, 0],
                    ..dto::Histogram::default()
                },
                "negative offset",
            ),
            (
                dto::Histogram {
                    positive_span: vec![span(0, 2)],
                    positive_delta: vec![1, -2],
                    ..dto::Histogram::default()
                },
                "is negative",
            ),
            (
                dto::Histogram {
                    schema: Some(-5),
                    positive_span: vec![span(0, 0)],
                    ..dto::Histogram::default()
                },
                "below the minimum",
            ),
            (
                dto::Histogram {
                    positive_span: vec![span(i32::MAX, 1), span(i32::MAX, 1)],
                    positive_delta: vec![1, 0],
                    ..dto::Histogram::default()
                },
                "out of range",
            ),
        ];
        for (histogram, expected) in cases {
            let err = parse(&histogram_family(histogram), TS, options()).expect_err(expected);
            assert!(err.to_string().contains(expected), "{err} vs {expected}");
        }
    }

    #[test]
    fn malformed_families_fail_the_scrape() {
        let counter = |labels: &[(&str, &str)]| dto::Metric {
            label: label_pairs(labels),
            counter: Some(dto::Counter { value: Some(1.0) }),
            ..dto::Metric::default()
        };
        let cases = [
            (
                family("", dto::MetricType::Counter, vec![counter(&[])]),
                "without a name",
            ),
            (
                dto::MetricFamily {
                    name: Some("m".to_owned()),
                    r#type: Some(42),
                    metric: vec![counter(&[])],
                },
                "unknown metric type 42",
            ),
            (
                family(
                    "m",
                    dto::MetricType::Counter,
                    vec![counter(&[("a", "1"), ("a", "2")])],
                ),
                "duplicate label name",
            ),
            (
                family(
                    "m",
                    dto::MetricType::Counter,
                    vec![counter(&[("__name__", "x")])],
                ),
                "duplicate label name",
            ),
            (
                family("m", dto::MetricType::Counter, vec![counter(&[("", "x")])]),
                "invalid label name \"\"",
            ),
            (
                family(
                    "m",
                    dto::MetricType::Histogram,
                    vec![dto::Metric {
                        label: label_pairs(&[("le", "x")]),
                        histogram: Some(dto::Histogram::default()),
                        ..dto::Metric::default()
                    }],
                ),
                "collides",
            ),
        ];
        for (family, expected) in cases {
            let err = parse(&body(&[family]), TS, options()).expect_err(expected);
            assert!(err.to_string().contains(expected), "{err} vs {expected}");
        }

        let too_many: Vec<(String, String)> = (0..MAX_LABELS_PER_SERIES)
            .map(|i| (format!("l{i}"), String::new()))
            .collect();
        let pairs: Vec<(&str, &str)> = too_many
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let err = parse(
            &body(&[family("m", dto::MetricType::Counter, vec![counter(&pairs)])]),
            TS,
            options(),
        )
        .expect_err("too many labels");
        assert!(err.to_string().contains("more than"), "{err}");

        // Duplicates past the linear-scan size are still caught.
        let mut pairs: Vec<(&str, &str)> = pairs[..40].to_vec();
        pairs.push(("l3", "again"));
        let err = parse(
            &body(&[family("m", dto::MetricType::Counter, vec![counter(&pairs)])]),
            TS,
            options(),
        )
        .expect_err("duplicate");
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    /// Names follow the text format's character rules, so a target cannot
    /// get names past the agent that a remote-write receiver would reject.
    #[test]
    fn names_follow_the_text_format_rules() {
        let series = |name: &str, label: &str| {
            let metric = dto::Metric {
                label: label_pairs(&[(label, "x")]),
                counter: Some(dto::Counter { value: Some(1.0) }),
                ..dto::Metric::default()
            };
            parse(
                &body(&[family(name, dto::MetricType::Counter, vec![metric])]),
                TS,
                options(),
            )
            .map(|series| series.len())
            .map_err(|err| err.to_string())
        };

        for (name, label, expected) in [
            ("m", "a-b", "invalid label name \"a-b\""),
            ("m", "a:b", "invalid label name \"a:b\""),
            ("m", "1a", "invalid label name \"1a\""),
            ("my.metric", "a", "invalid metric name \"my.metric\""),
            ("1m", "a", "invalid metric name \"1m\""),
            ("métric", "a", "invalid metric name \"métric\""),
        ] {
            let err = series(name, label).expect_err(expected);
            assert!(err.contains(expected), "{err} vs {expected}");
        }
        // Colons stay valid in metric names (recording-rule style).
        assert_eq!(series("job:requests:rate5m", "_a1"), Ok(1));
    }

    #[test]
    fn truncated_body_is_an_error() {
        let families = [family(
            "m",
            dto::MetricType::Gauge,
            vec![dto::Metric {
                gauge: Some(dto::Gauge { value: Some(1.0) }),
                ..dto::Metric::default()
            }],
        )];
        let full = body(&families);
        assert!(parse(&full[..full.len() - 1], TS, options()).is_err());
        assert_eq!(
            parse(&[], TS, options()).expect("empty body"),
            Vec::<TimeSeries>::new()
        );
    }

    #[test]
    fn identity_is_deterministic() -> Result<(), ParseError> {
        let families = [family(
            "latency_seconds",
            dto::MetricType::Histogram,
            vec![dto::Metric {
                histogram: Some(mixed_histogram()),
                ..dto::Metric::default()
            }],
        )];
        let first = parse(&body(&families), TS, options())?;
        let second = parse(&body(&families), TS + 1, options())?;
        assert_eq!(first[0].identity_hash, second[0].identity_hash);
        assert_ne!(first[0].identity_hash, 0);
        Ok(())
    }

    /// Matches Go's `strconv.FormatFloat(v, 'g', -1, 64)` plus the `.0`
    /// Prometheus appends.
    #[test]
    fn format_float_matches_prometheus() {
        for (value, expected) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (0.25, "0.25"),
            (0.005, "0.005"),
            (0.0001, "0.0001"),
            (0.000_01, "1e-05"),
            (100_000.0, "100000.0"),
            (1e6, "1e+06"),
            (1_234_567.0, "1.234567e+06"),
            (2.5e-300, "2.5e-300"),
            (1e21, "1e+21"),
            (-7.5, "-7.5"),
            (f64::INFINITY, "+Inf"),
            (f64::NEG_INFINITY, "-Inf"),
            (f64::NAN, "NaN"),
        ] {
            assert_eq!(format_float(value), expected, "{value}");
        }
    }
}
