//! Prometheus remote-write wire types.
//!
//! Hand-written `prost` messages matching `prompb/remote.proto` and
//! `prompb/types.proto` from the Prometheus repository (remote-write 1.0
//! protocol). Only the fields required for writing samples are included;
//! metadata and exemplars are intentionally omitted to keep payloads small.

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

#[derive(Clone, PartialEq, prost::Message)]
pub struct TimeSeries {
    /// Must be sorted by label name and contain no duplicates when sent.
    #[prost(message, repeated, tag = "1")]
    pub labels: Vec<Label>,
    #[prost(message, repeated, tag = "2")]
    pub samples: Vec<Sample>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct WriteRequest {
    #[prost(message, repeated, tag = "1")]
    pub timeseries: Vec<TimeSeries>,
}

/// Remote-write 2.0 request (`io.prometheus.write.v2.Request`).
///
/// Every label name and value is written once into `symbols`; series
/// reference them by index — the protocol-level fix for per-series label
/// duplication (measured 40-60% smaller payloads upstream). `symbols[0]`
/// MUST be the empty string per spec. Histograms, exemplars and metadata
/// are intentionally omitted (we forward samples only).
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
        let samples: usize = self
            .samples
            .iter()
            .map(|sample| {
                let len = sample.wire_len();
                1 + varint_len(len as u64) + len
            })
            .sum();
        labels + samples
    }
}

impl WriteRequest {
    /// Encode into `buf` (appending) in a single pass.
    ///
    /// Produces exactly the bytes of the derived `prost::Message::encode`.
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
            for sample in &series.samples {
                buf.push(TAG2_LEN);
                put_varint(sample.wire_len() as u64, buf);
                sample.put_fields(buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::*;

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
                    samples: vec![
                        Sample {
                            value: 1027.0,
                            timestamp: 1_395_066_363_000,
                        },
                        Sample {
                            value: 0.0,
                            timestamp: 0,
                        },
                        Sample {
                            value: -0.0,
                            timestamp: -1,
                        },
                        Sample {
                            value: stale_nan(),
                            timestamp: i64::MAX,
                        },
                        Sample {
                            value: f64::MIN_POSITIVE,
                            timestamp: i64::MIN,
                        },
                    ],
                },
                TimeSeries {
                    labels: Vec::new(),
                    samples: Vec::new(),
                },
            ],
        };
        let mut buf = Vec::new();
        request.encode_into(&mut buf);
        assert_eq!(buf, request.encode_to_vec());
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
