//! Criterion benchmarks for the hot paths: exposition parsing, relabeling,
//! and remote-write encoding (protobuf + snappy).

use std::{
    fmt::Write as _,
    hint::black_box,
};

use criterion::{
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
use prometheus_scrape_rs::{
    model::{
        Label,
        Sample,
        TimeSeries,
        WriteRequest,
    },
    parser,
    relabel::{
        self,
        RelabelConfig,
    },
};

/// Same allocator as the shipped binary so numbers reflect production.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// A realistic scrape body: counters, gauges, and histograms with HELP/TYPE
/// comments, roughly what a `node_exporter` or app endpoint produces.
fn scrape_body(series: usize) -> String {
    let mut body = String::with_capacity(series * 96);
    body.push_str("# HELP http_requests_total Total HTTP requests.\n");
    body.push_str("# TYPE http_requests_total counter\n");
    for i in 0..series / 2 {
        let _ = writeln!(
            body,
            "http_requests_total{{method=\"GET\",code=\"200\",path=\"/api/v1/resource/{i}\"}} {}",
            i * 3 + 1
        );
    }
    body.push_str("# HELP request_duration_seconds Request latency.\n");
    body.push_str("# TYPE request_duration_seconds histogram\n");
    let buckets = ["0.005", "0.01", "0.05", "0.1", "0.5", "1", "+Inf"];
    let mut emitted = body.matches('\n').count();
    let mut handler = 0usize;
    while emitted < series {
        for le in &buckets {
            let _ = writeln!(
                body,
                "request_duration_seconds_bucket{{handler=\"h{handler}\",le=\"{le}\"}} {emitted}"
            );
            emitted += 1;
        }
        handler += 1;
    }
    body
}

fn bench_parser(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser");
    for series in [100usize, 1_000, 10_000] {
        let body = scrape_body(series);
        group.throughput(Throughput::Bytes(body.len() as u64));
        group.bench_function(format!("parse_{series}_series"), |b| {
            b.iter(|| parser::parse(black_box(&body), 1_700_000_000_000, true));
        });
    }
    group.finish();
}

fn relabel_configs() -> Vec<RelabelConfig> {
    let yaml = r#"
- source_labels: [__name__]
  regex: "http_.*"
  action: keep
- source_labels: [method, code]
  separator: "_"
  target_label: method_code
- regex: "path"
  action: labeldrop
"#;
    serde_saphyr::from_str(yaml).expect("static relabel config is valid")
}

fn bench_relabel(c: &mut Criterion) {
    let configs = relabel_configs();
    let labels: Vec<Label> = vec![
        Label::new("__name__", "http_requests_total"),
        Label::new("method", "GET"),
        Label::new("code", "200"),
        Label::new("path", "/api/v1/resource/42"),
        Label::new("instance", "app-1:8080"),
        Label::new("job", "app"),
    ];
    c.bench_function("relabel/6_labels_3_rules", |b| {
        b.iter_batched(
            || labels.clone(),
            |labels| relabel::process(black_box(labels), black_box(&configs)),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn write_request(series: usize) -> WriteRequest {
    WriteRequest {
        timeseries: (0..series)
            .map(|i| TimeSeries {
                labels: vec![
                    Label::new("__name__", "http_requests_total"),
                    Label::new("code", "200"),
                    Label::new("instance", "app-1:8080"),
                    Label::new("job", "app"),
                    Label::new("path", format!("/api/v1/resource/{i}")),
                ],
                sample: Sample {
                    value: 42.0,
                    timestamp: 1_700_000_000_000 + i64::try_from(i).unwrap_or(0),
                },
                identity_hash: 0,
            })
            .collect(),
    }
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("remote_write_encode");
    for series in [500usize, 2_000] {
        let request = write_request(series);
        group.throughput(Throughput::Elements(series as u64));
        group.bench_function(format!("protobuf_snappy_{series}_series"), |b| {
            let mut proto_buf = Vec::new();
            let mut encoder = snap::raw::Encoder::new();
            b.iter(|| {
                proto_buf.clear();
                black_box(&request).encode_into(&mut proto_buf);
                black_box(
                    encoder
                        .compress_vec(&proto_buf)
                        .expect("snappy compress cannot fail"),
                );
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parser, bench_relabel, bench_encode);
criterion_main!(benches);
