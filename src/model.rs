//! Prometheus remote-write wire types.
//!
//! Hand-written `prost` messages matching `prompb/remote.proto` and
//! `prompb/types.proto` from the Prometheus repository (remote-write 1.0
//! protocol). Only the fields required for writing samples are included;
//! metadata and exemplars are intentionally omitted to keep payloads small.

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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, prost::Message)]
pub struct Label {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

impl Label {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
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
