//! Prometheus remote-write wire types.
//!
//! Hand-written `prost` messages matching `prompb/remote.proto` and
//! `prompb/types.proto` from the Prometheus repository (remote-write 1.0
//! protocol). Only the fields required for writing samples and native
//! histograms are included; metadata and exemplars are intentionally omitted
//! to keep payloads small.

use compact_str::CompactString;

/// Reserved label name carrying the metric name.
pub const METRIC_NAME_LABEL: &str = "__name__";

/// Prometheus staleness marker: a NaN with this exact bit pattern tells the
/// receiver "this series ended here" instead of applying query lookback.
/// Must be compared/constructed via bits — `==` on NaN is always false.
pub const STALE_NAN_BITS: u64 = 0x7ff0_0000_0000_0002;

#[must_use]
pub const fn stale_nan() -> f64 {
    f64::from_bits(STALE_NAN_BITS)
}

#[must_use]
pub const fn is_stale_nan(value: f64) -> bool {
    value.to_bits() == STALE_NAN_BITS
}

/// A label pair backed by [`CompactString`]: strings up to 24 bytes live
/// inline (no allocation, no refcount), longer ones on the heap like a
/// `String`. Clones are plain memcpys — unlike the reverted shared-`Bytes`
/// labels there is no atomic refcount to contend on across scrape tasks.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Label {
    pub name: CompactString,
    pub value: CompactString,
}

impl Label {
    pub fn new(name: impl Into<CompactString>, value: impl Into<CompactString>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Hand-written `prost::Message` so `TimeSeries`/`WriteRequest` can keep
/// their derives on top of the `CompactString` fields. Wire-compatible with
/// the former `#[prost(string, tag = "1"/"2")]` definition; only the decode
/// path allocates a transient `String`.
impl prost::Message for Label {
    fn encode_raw(&self, buf: &mut impl bytes::BufMut) {
        use prost::encoding::{
            WireType,
            encode_key,
            encode_varint,
        };
        if !self.name.is_empty() {
            encode_key(1, WireType::LengthDelimited, buf);
            encode_varint(self.name.len() as u64, buf);
            buf.put_slice(self.name.as_bytes());
        }
        if !self.value.is_empty() {
            encode_key(2, WireType::LengthDelimited, buf);
            encode_varint(self.value.len() as u64, buf);
            buf.put_slice(self.value.as_bytes());
        }
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: prost::encoding::WireType,
        buf: &mut impl bytes::Buf,
        ctx: prost::encoding::DecodeContext,
    ) -> Result<(), prost::DecodeError> {
        match tag {
            1 | 2 => {
                let mut text = String::new();
                prost::encoding::string::merge(wire_type, &mut text, buf, ctx)?;
                if tag == 1 {
                    self.name = text.into();
                } else {
                    self.value = text.into();
                }
                Ok(())
            }
            _ => prost::encoding::skip_field(wire_type, tag, buf, ctx),
        }
    }

    fn encoded_len(&self) -> usize {
        string_field_len(&self.name) + string_field_len(&self.value)
    }

    fn clear(&mut self) {
        self.name.clear();
        self.value.clear();
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Sample {
    #[prost(double, tag = "1")]
    pub value: f64,
    /// Milliseconds since Unix epoch.
    #[prost(int64, tag = "2")]
    pub timestamp: i64,
}

/// One series carrying one sample — the pipeline's unit of work.
///
/// This is the *internal* series type, not a prost message: every series
/// in this agent holds exactly one sample by construction (the parser
/// emits one series per sample line, staleness markers are single-sample),
/// so the wire protocols' `repeated samples` is a repeated-of-one written
/// by the hand-rolled encoders. Dropping the per-series `Vec<Sample>`
/// removed one heap allocation per series per scrape (~20% of live
/// allocation calls).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TimeSeries {
    /// Must be sorted by label name and contain no duplicates when sent.
    pub labels: Vec<Label>,
    pub sample: Sample,
    /// Staleness identity: `FxHash` of the series' raw exposition bytes
    /// (metric name through the closing label brace), computed by the
    /// parser while the line is cache-hot and consumed by the staleness
    /// tracker. Deterministic across re-parses of the same body; keyed on
    /// the textual form like Prometheus' scrape cache, so a formatting
    /// change is a new identity. Zero for synthetic series (report series,
    /// staleness markers — never tracked); never on the wire.
    pub identity_hash: u64,
    /// A native histogram sample. When set, the series carries this
    /// histogram *instead of* `sample.value`; `sample.timestamp` still holds
    /// its timestamp, so timestamp-based logic (staleness tracking) treats
    /// both kinds alike. Boxed: histograms are rare next to float samples
    /// and this keeps the float path's series 8 bytes wider, not ~250.
    pub histogram: Option<Box<Histogram>>,
}

/// A native histogram count: integer histograms carry integer counts, float
/// histograms float ones. A `oneof` on the wire — receivers tell the two
/// kinds apart by which variant is set, so it is written even when zero.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HistogramCount {
    Int(u64),
    Float(f64),
}

impl Default for HistogramCount {
    fn default() -> Self {
        Self::Int(0)
    }
}

/// A run of `length` consecutive populated buckets, starting `offset`
/// buckets after the end of the previous span (the first span's offset is
/// the absolute index of its first bucket).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BucketSpan {
    pub offset: i32,
    pub length: u32,
}

/// Counter-reset hint of a native histogram (`prompb.Histogram.ResetHint`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResetHint {
    /// Receiver must detect counter resets itself (scraped counters).
    #[default]
    Unknown = 0,
    Yes = 1,
    No = 2,
    /// Gauge histogram: no counter semantics at all.
    Gauge = 3,
}

/// A native (sparse, exponential-bucket) histogram, in the shape of
/// `prompb.Histogram` — identical in remote-write 1.0 and 2.0.
///
/// Integer histograms ([`HistogramCount::Int`]) store their buckets as
/// `*_deltas` (each the difference to the previous bucket's count), float
/// histograms as absolute `*_counts`; the other list stays empty.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Histogram {
    pub count: HistogramCount,
    pub sum: f64,
    /// Bucket resolution: bucket boundaries grow by `2^(2^-schema)`.
    pub schema: i32,
    pub zero_threshold: f64,
    pub zero_count: HistogramCount,
    pub negative_spans: Vec<BucketSpan>,
    pub negative_deltas: Vec<i64>,
    pub negative_counts: Vec<f64>,
    pub positive_spans: Vec<BucketSpan>,
    pub positive_deltas: Vec<i64>,
    pub positive_counts: Vec<f64>,
    pub reset_hint: ResetHint,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WriteRequest {
    pub timeseries: Vec<TimeSeries>,
}

/// Remote-write 2.0 request (`io.prometheus.write.v2.Request`).
///
/// Every label name and value is written once into `symbols`; series
/// reference them by index — the protocol-level fix for per-series label
/// duplication (measured 40-60% smaller payloads upstream). `symbols[0]`
/// MUST be the empty string per spec. Exemplars and metadata are
/// intentionally omitted (we forward samples and histograms only).
///
/// Production encoding is hand-rolled (`remote_write::encode_v2_into`);
/// this prost view pins that wire format and decodes it in tests.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WriteRequestV2 {
    #[prost(string, repeated, tag = "4")]
    pub symbols: Vec<String>,
    #[prost(message, repeated, tag = "5")]
    pub timeseries: Vec<TimeSeriesV2>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct TimeSeriesV2 {
    /// Pairs of symbol indices: even positions are label names, odd
    /// positions the corresponding values.
    #[prost(uint32, repeated, tag = "1")]
    pub labels_refs: Vec<u32>,
    #[prost(message, repeated, tag = "2")]
    pub samples: Vec<Sample>,
    #[prost(message, repeated, tag = "3")]
    pub histograms: Vec<WireHistogram>,
}

/// Prost-derived view of `prompb.Histogram` (wire-identical in remote-write
/// 1.0 and 2.0). Production encoding goes through [`Histogram`] and the
/// hand-rolled encoder; this type pins that wire format and lets tests and
/// receivers decode it.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WireHistogram {
    #[prost(oneof = "WireCount", tags = "1, 2")]
    pub count: Option<WireCount>,
    #[prost(double, tag = "3")]
    pub sum: f64,
    #[prost(sint32, tag = "4")]
    pub schema: i32,
    #[prost(double, tag = "5")]
    pub zero_threshold: f64,
    #[prost(oneof = "WireZeroCount", tags = "6, 7")]
    pub zero_count: Option<WireZeroCount>,
    #[prost(message, repeated, tag = "8")]
    pub negative_spans: Vec<WireBucketSpan>,
    #[prost(sint64, repeated, tag = "9")]
    pub negative_deltas: Vec<i64>,
    #[prost(double, repeated, tag = "10")]
    pub negative_counts: Vec<f64>,
    #[prost(message, repeated, tag = "11")]
    pub positive_spans: Vec<WireBucketSpan>,
    #[prost(sint64, repeated, tag = "12")]
    pub positive_deltas: Vec<i64>,
    #[prost(double, repeated, tag = "13")]
    pub positive_counts: Vec<f64>,
    /// [`ResetHint`] discriminant.
    #[prost(int32, tag = "14")]
    pub reset_hint: i32,
    #[prost(int64, tag = "15")]
    pub timestamp: i64,
}

#[derive(Clone, Copy, PartialEq, prost::Oneof)]
pub enum WireCount {
    #[prost(uint64, tag = "1")]
    CountInt(u64),
    #[prost(double, tag = "2")]
    CountFloat(f64),
}

#[derive(Clone, Copy, PartialEq, prost::Oneof)]
pub enum WireZeroCount {
    #[prost(uint64, tag = "6")]
    ZeroCountInt(u64),
    #[prost(double, tag = "7")]
    ZeroCountFloat(f64),
}

#[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
pub struct WireBucketSpan {
    #[prost(sint32, tag = "1")]
    pub offset: i32,
    #[prost(uint32, tag = "2")]
    pub length: u32,
}

impl WireHistogram {
    /// The wire view of `histogram` sampled at `timestamp`.
    #[must_use]
    pub fn from_histogram(histogram: &Histogram, timestamp: i64) -> Self {
        let spans = |spans: &[BucketSpan]| {
            spans
                .iter()
                .map(|span| WireBucketSpan {
                    offset: span.offset,
                    length: span.length,
                })
                .collect()
        };
        Self {
            count: Some(match histogram.count {
                HistogramCount::Int(count) => WireCount::CountInt(count),
                HistogramCount::Float(count) => WireCount::CountFloat(count),
            }),
            sum: histogram.sum,
            schema: histogram.schema,
            zero_threshold: histogram.zero_threshold,
            zero_count: Some(match histogram.zero_count {
                HistogramCount::Int(count) => WireZeroCount::ZeroCountInt(count),
                HistogramCount::Float(count) => WireZeroCount::ZeroCountFloat(count),
            }),
            negative_spans: spans(&histogram.negative_spans),
            negative_deltas: histogram.negative_deltas.clone(),
            negative_counts: histogram.negative_counts.clone(),
            positive_spans: spans(&histogram.positive_spans),
            positive_deltas: histogram.positive_deltas.clone(),
            positive_counts: histogram.positive_counts.clone(),
            reset_hint: histogram.reset_hint as i32,
            timestamp,
        }
    }
}

/// Sort labels by name as required by the remote-write spec.
pub fn sort_labels(labels: &mut [Label]) {
    labels.sort_unstable_by(|a, b| a.name.cmp(&b.name));
}

// --- hand-rolled remote-write 1.0 encoder ---
//
// The derived `prost::Message::encode` computes every nested message length
// twice: once inside the parent's `encoded_len` and again when writing the
// length delimiter. On this three-level schema that doubles the tree walk;
// the encoder below computes each length once, bottom-up, and is
// byte-identical to the derived implementation (verified by test).

/// Wire tag for a length-delimited field 1 (`labels`, `name`, `timeseries`).
const TAG1_LEN: u8 = 0x0a;
/// Wire tag for a length-delimited field 2 (`samples`, `value`).
const TAG2_LEN: u8 = 0x12;
/// Wire tag for the `double` field 1 of `Sample`.
const TAG1_DOUBLE: u8 = 0x09;
/// Wire tag for the `int64` field 2 of `Sample`.
const TAG2_VARINT: u8 = 0x10;

/// Encoded size of `value` as a protobuf varint (prost's branch-free form).
pub(crate) fn varint_len(value: u64) -> usize {
    (((value | 1).leading_zeros() as usize ^ 63) * 9 + 73) / 64
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "bytes are masked to 7 bits before the cast"
)]
pub(crate) fn put_varint(mut value: u64, buf: &mut Vec<u8>) {
    while value >= 0x80 {
        buf.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Encoded size of a string field, 0 when empty — protobuf proto3 semantics
/// (matched by prost) skip fields holding their default value.
fn string_field_len(value: &str) -> usize {
    if value.is_empty() {
        0
    } else {
        1 + varint_len(value.len() as u64) + value.len()
    }
}

fn put_string_field(tag: u8, value: &str, buf: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    buf.push(tag);
    put_varint(value.len() as u64, buf);
    buf.extend_from_slice(value.as_bytes());
}

/// Reinterpret an `int64` as the `u64` protobuf varints are built from
/// (two's complement; negative values encode as 10 bytes).
fn int64_bits(value: i64) -> u64 {
    u64::from_le_bytes(value.to_le_bytes())
}

impl Label {
    fn wire_len(&self) -> usize {
        string_field_len(&self.name) + string_field_len(&self.value)
    }
}

impl Sample {
    pub(crate) fn wire_len(&self) -> usize {
        let mut len = 0;
        if self.value != 0.0 {
            len += 9;
        }
        if self.timestamp != 0 {
            len += 1 + varint_len(int64_bits(self.timestamp));
        }
        len
    }

    /// Write the sample's fields (without the message header) — shared by
    /// the v1 and v2 encoders; the wire layout of `Sample` is identical in
    /// both protocols.
    pub(crate) fn put_fields(&self, buf: &mut Vec<u8>) {
        if self.value != 0.0 {
            buf.push(TAG1_DOUBLE);
            buf.extend_from_slice(&self.value.to_le_bytes());
        }
        if self.timestamp != 0 {
            buf.push(TAG2_VARINT);
            put_varint(int64_bits(self.timestamp), buf);
        }
    }
}

/// Zigzag encoding of `sint32`/`sint64` fields.
fn zigzag(value: i64) -> u64 {
    int64_bits((value << 1) ^ (value >> 63))
}

/// Encoded size of a packed repeated field's payload, 0 when empty.
fn packed_field_len(payload: usize) -> usize {
    if payload == 0 {
        0
    } else {
        1 + varint_len(payload as u64) + payload
    }
}

impl HistogramCount {
    /// The oneof is written whichever variant is set, zero included.
    fn wire_len(self) -> usize {
        match self {
            Self::Int(count) => 1 + varint_len(count),
            Self::Float(_) => 9,
        }
    }

    /// `int_tag`/`float_tag` are the full key bytes of the two variants.
    fn put(self, int_tag: u8, float_tag: u8, buf: &mut Vec<u8>) {
        match self {
            Self::Int(count) => {
                buf.push(int_tag);
                put_varint(count, buf);
            }
            Self::Float(count) => {
                buf.push(float_tag);
                buf.extend_from_slice(&count.to_le_bytes());
            }
        }
    }
}

impl BucketSpan {
    fn wire_len(self) -> usize {
        let mut len = 0;
        if self.offset != 0 {
            len += 1 + varint_len(zigzag(i64::from(self.offset)));
        }
        if self.length != 0 {
            len += 1 + varint_len(u64::from(self.length));
        }
        len
    }

    fn put_fields(self, buf: &mut Vec<u8>) {
        if self.offset != 0 {
            buf.push(0x08);
            put_varint(zigzag(i64::from(self.offset)), buf);
        }
        if self.length != 0 {
            buf.push(0x10);
            put_varint(u64::from(self.length), buf);
        }
    }
}

fn spans_len(spans: &[BucketSpan]) -> usize {
    spans
        .iter()
        .map(|span| {
            let len = span.wire_len();
            1 + varint_len(len as u64) + len
        })
        .sum()
}

fn put_spans(tag: u8, spans: &[BucketSpan], buf: &mut Vec<u8>) {
    for span in spans {
        buf.push(tag);
        put_varint(span.wire_len() as u64, buf);
        span.put_fields(buf);
    }
}

fn deltas_payload_len(deltas: &[i64]) -> usize {
    deltas.iter().map(|&delta| varint_len(zigzag(delta))).sum()
}

fn put_deltas(tag: u8, deltas: &[i64], buf: &mut Vec<u8>) {
    if deltas.is_empty() {
        return;
    }
    buf.push(tag);
    put_varint(deltas_payload_len(deltas) as u64, buf);
    for &delta in deltas {
        put_varint(zigzag(delta), buf);
    }
}

fn put_counts(tag: u8, counts: &[f64], buf: &mut Vec<u8>) {
    if counts.is_empty() {
        return;
    }
    buf.push(tag);
    put_varint(counts.len() as u64 * 8, buf);
    for count in counts {
        buf.extend_from_slice(&count.to_le_bytes());
    }
}

impl Histogram {
    /// Encoded size of the `prompb.Histogram` message body carrying
    /// `timestamp` (field 15). Proto3 skips default scalars and empty
    /// packed fields; the two count oneofs are always present.
    pub(crate) fn wire_len(&self, timestamp: i64) -> usize {
        let mut len = self.count.wire_len() + self.zero_count.wire_len();
        if self.sum != 0.0 {
            len += 9;
        }
        if self.schema != 0 {
            len += 1 + varint_len(zigzag(i64::from(self.schema)));
        }
        if self.zero_threshold != 0.0 {
            len += 9;
        }
        len += spans_len(&self.negative_spans) + spans_len(&self.positive_spans);
        len += packed_field_len(deltas_payload_len(&self.negative_deltas))
            + packed_field_len(deltas_payload_len(&self.positive_deltas));
        len += packed_field_len(self.negative_counts.len() * 8)
            + packed_field_len(self.positive_counts.len() * 8);
        if self.reset_hint != ResetHint::Unknown {
            len += 2;
        }
        if timestamp != 0 {
            len += 1 + varint_len(int64_bits(timestamp));
        }
        len
    }

    /// Write the message body (without its header), fields in tag order —
    /// shared by the v1 and v2 encoders, whose `Histogram` messages are
    /// wire-identical.
    pub(crate) fn put_fields(&self, timestamp: i64, buf: &mut Vec<u8>) {
        self.count.put(0x08, 0x11, buf);
        if self.sum != 0.0 {
            buf.push(0x19);
            buf.extend_from_slice(&self.sum.to_le_bytes());
        }
        if self.schema != 0 {
            buf.push(0x20);
            put_varint(zigzag(i64::from(self.schema)), buf);
        }
        if self.zero_threshold != 0.0 {
            buf.push(0x29);
            buf.extend_from_slice(&self.zero_threshold.to_le_bytes());
        }
        self.zero_count.put(0x30, 0x39, buf);
        put_spans(0x42, &self.negative_spans, buf);
        put_deltas(0x4a, &self.negative_deltas, buf);
        put_counts(0x52, &self.negative_counts, buf);
        put_spans(0x5a, &self.positive_spans, buf);
        put_deltas(0x62, &self.positive_deltas, buf);
        put_counts(0x6a, &self.positive_counts, buf);
        if self.reset_hint != ResetHint::Unknown {
            buf.push(0x70);
            buf.push(self.reset_hint as u8);
        }
        if timestamp != 0 {
            buf.push(0x78);
            put_varint(int64_bits(timestamp), buf);
        }
    }
}

/// Wire tag of `prompb.TimeSeries.histograms` (field 4, length-delimited).
const TAG4_LEN: u8 = 0x22;

impl TimeSeries {
    fn wire_len(&self) -> usize {
        let labels: usize = self
            .labels
            .iter()
            .map(|label| {
                let len = label.wire_len();
                1 + varint_len(len as u64) + len
            })
            .sum();
        let value_len = self.value_wire_len();
        labels + 1 + varint_len(value_len as u64) + value_len
    }

    /// Encoded size of the series' one value message: its `Sample`, or its
    /// `Histogram` when it carries one.
    pub(crate) fn value_wire_len(&self) -> usize {
        match &self.histogram {
            Some(histogram) => histogram.wire_len(self.sample.timestamp),
            None => self.sample.wire_len(),
        }
    }

    /// Write the series' one value as a repeated field of one: tag
    /// `sample_tag` for a float sample, `histogram_tag` for a histogram.
    pub(crate) fn put_value(&self, sample_tag: u8, histogram_tag: u8, buf: &mut Vec<u8>) {
        if let Some(histogram) = &self.histogram {
            buf.push(histogram_tag);
            put_varint(histogram.wire_len(self.sample.timestamp) as u64, buf);
            histogram.put_fields(self.sample.timestamp, buf);
        } else {
            buf.push(sample_tag);
            put_varint(self.sample.wire_len() as u64, buf);
            self.sample.put_fields(buf);
        }
    }
}

impl WriteRequest {
    /// Encode into `buf` (appending) in a single pass.
    ///
    /// Produces exactly the bytes prost's derive would emit for the
    /// equivalent `prompb` message (each series' single sample or histogram
    /// as a repeated field of one).
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        for series in &self.timeseries {
            let series_len = series.wire_len();
            buf.push(TAG1_LEN);
            put_varint(series_len as u64, buf);
            for label in &series.labels {
                buf.push(TAG1_LEN);
                put_varint(label.wire_len() as u64, buf);
                put_string_field(TAG1_LEN, &label.name, buf);
                put_string_field(TAG2_LEN, &label.value, buf);
            }
            series.put_value(TAG2_LEN, TAG4_LEN, buf);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use prost::Message as _;

    use super::*;

    /// Prost-derived shadow of the `prompb` wire format, used to pin the
    /// hand-rolled encoders now that the internal [`TimeSeries`] is not a
    /// prost message. Also used by the remote-write round-trip test.
    #[derive(Clone, PartialEq, prost::Message)]
    pub(crate) struct PbTimeSeries {
        #[prost(message, repeated, tag = "1")]
        pub(crate) labels: Vec<Label>,
        #[prost(message, repeated, tag = "2")]
        pub(crate) samples: Vec<Sample>,
        #[prost(message, repeated, tag = "4")]
        pub(crate) histograms: Vec<WireHistogram>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(crate) struct PbWriteRequest {
        #[prost(message, repeated, tag = "1")]
        pub(crate) timeseries: Vec<PbTimeSeries>,
    }

    /// The wire view of an internal series: its single sample (or
    /// histogram) becomes a repeated field of one.
    fn shadow(request: &WriteRequest) -> PbWriteRequest {
        PbWriteRequest {
            timeseries: request
                .timeseries
                .iter()
                .map(|series| match &series.histogram {
                    Some(histogram) => PbTimeSeries {
                        labels: series.labels.clone(),
                        samples: Vec::new(),
                        histograms: vec![WireHistogram::from_histogram(
                            histogram,
                            series.sample.timestamp,
                        )],
                    },
                    None => PbTimeSeries {
                        labels: series.labels.clone(),
                        samples: vec![series.sample.clone()],
                        histograms: Vec::new(),
                    },
                })
                .collect(),
        }
    }

    /// The hand-rolled encoder must be byte-identical to the prost derive
    /// across the edge cases prost handles specially: default (skipped)
    /// fields, -0.0, negative and huge varints, empty messages, multi-byte
    /// length delimiters and non-ASCII strings.
    #[test]
    fn encode_into_matches_prost_derive() {
        let request = WriteRequest {
            timeseries: vec![
                TimeSeries {
                    labels: vec![
                        Label::new(METRIC_NAME_LABEL, "http_requests_total"),
                        Label::new("code", "200"),
                        Label::new("empty_value", ""),
                        Label::new("", "empty_name"),
                        Label::new("unicode", "héllo→世界"),
                        Label::new("long", "x".repeat(300)),
                    ],
                    sample: Sample {
                        value: 1027.0,
                        timestamp: 1_395_066_363_000,
                    },
                    identity_hash: 0,
                    histogram: None,
                },
                TimeSeries {
                    labels: Vec::new(),
                    sample: Sample {
                        value: 0.0,
                        timestamp: 0,
                    },
                    identity_hash: 0,
                    histogram: None,
                },
                TimeSeries {
                    labels: vec![Label::new("edge", "cases")],
                    sample: Sample {
                        value: -0.0,
                        timestamp: -1,
                    },
                    identity_hash: 0,
                    histogram: None,
                },
                TimeSeries {
                    labels: vec![Label::new("edge", "stale")],
                    sample: Sample {
                        value: stale_nan(),
                        timestamp: i64::MAX,
                    },
                    identity_hash: 0,
                    histogram: None,
                },
                TimeSeries {
                    labels: vec![Label::new("edge", "min")],
                    sample: Sample {
                        value: f64::MIN_POSITIVE,
                        timestamp: i64::MIN,
                    },
                    identity_hash: 0,
                    histogram: None,
                },
            ],
        };
        let mut buf = Vec::new();
        request.encode_into(&mut buf);
        assert_eq!(buf, shadow(&request).encode_to_vec());

        // The stale-NaN bit pattern survives a decode round-trip.
        let decoded = PbWriteRequest::decode(buf.as_slice()).expect("decode");
        assert!(is_stale_nan(decoded.timeseries[3].samples[0].value));
    }

    /// Native histograms covering what prost treats specially: the count
    /// oneofs at zero (must still be written), negative schemas and
    /// offsets (zigzag), zero-offset spans, empty and float bucket lists,
    /// and the reset-hint/timestamp defaults.
    pub(crate) fn sample_histograms() -> Vec<Histogram> {
        vec![
            Histogram::default(),
            Histogram {
                count: HistogramCount::Int(12),
                sum: 18.4,
                schema: 3,
                zero_threshold: 1e-128,
                zero_count: HistogramCount::Int(2),
                negative_spans: vec![BucketSpan {
                    offset: -2,
                    length: 2,
                }],
                negative_deltas: vec![1, -1],
                positive_spans: vec![
                    BucketSpan {
                        offset: 0,
                        length: 2,
                    },
                    BucketSpan {
                        offset: 1,
                        length: 0,
                    },
                    BucketSpan {
                        offset: 300,
                        length: 1,
                    },
                ],
                positive_deltas: vec![2, 1, -3],
                ..Histogram::default()
            },
            Histogram {
                count: HistogramCount::Float(0.0),
                sum: -0.0,
                schema: -4,
                zero_count: HistogramCount::Float(0.5),
                positive_spans: vec![BucketSpan {
                    offset: i32::MIN,
                    length: u32::MAX,
                }],
                positive_counts: vec![0.25, f64::INFINITY, 0.0],
                negative_counts: vec![f64::MIN_POSITIVE],
                reset_hint: ResetHint::Gauge,
                ..Histogram::default()
            },
        ]
    }

    #[test]
    fn histogram_encoding_matches_prost_derive() {
        let mut timeseries = Vec::new();
        for (i, histogram) in sample_histograms().into_iter().enumerate() {
            for timestamp in [0, -1, 1_700_000_000_000] {
                timeseries.push(TimeSeries {
                    labels: vec![Label::new(METRIC_NAME_LABEL, format!("h{i}"))],
                    sample: Sample {
                        value: 0.0,
                        timestamp,
                    },
                    identity_hash: 0,
                    histogram: Some(Box::new(histogram.clone())),
                });
            }
        }
        let request = WriteRequest { timeseries };
        let mut buf = Vec::new();
        request.encode_into(&mut buf);
        assert_eq!(buf, shadow(&request).encode_to_vec());

        // A float histogram whose counts are all zero still decodes as a
        // float histogram: the oneof is present.
        let decoded = PbWriteRequest::decode(buf.as_slice()).expect("decode");
        let float = &decoded.timeseries[6].histograms[0];
        assert_eq!(float.count, Some(WireCount::CountFloat(0.0)));
        assert_eq!(decoded.timeseries[6].samples, Vec::<Sample>::new());
    }

    /// The bytes-labels experiment showed `Label` size directly moves the
    /// hot paths (48 → 64 bytes was part of its regression). `CompactString`
    /// keeps parity with the two former `String`s.
    #[test]
    fn label_stays_48_bytes() {
        assert_eq!(std::mem::size_of::<Label>(), 48);
    }

    #[test]
    fn varint_len_matches_encoding() {
        for value in [
            0u64,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            put_varint(value, &mut buf);
            assert_eq!(varint_len(value), buf.len(), "value {value:#x}");
        }
    }
}
