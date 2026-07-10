//! Prometheus remote-write wire types.
//!
//! Hand-written `prost` messages matching `prompb/remote.proto` and
//! `prompb/types.proto` from the Prometheus repository (remote-write 1.0
//! protocol). Only the fields required for writing samples are included;
//! metadata and exemplars are intentionally omitted to keep payloads small.

/// Reserved label name carrying the metric name.
pub const METRIC_NAME_LABEL: &str = "__name__";

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

/// Sort labels by name as required by the remote-write spec.
pub fn sort_labels(labels: &mut [Label]) {
    labels.sort_unstable_by(|a, b| a.name.cmp(&b.name));
}
