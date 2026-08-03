# prometheus-scrape-rs

A lightweight Prometheus scraping agent in Rust: scrapes Prometheus
exposition endpoints and forwards all samples to durable remote storage via
the [remote-write 1.0 protocol](https://prometheus.io/docs/specs/prw/remote_write_spec/).
It reads a standard `prometheus.yml` and aims to be a cheap drop-in
replacement for Prometheus in agent mode.

## Usage

```sh
prometheus-scrape-rs --config.file prometheus.yml [--log.level info]
```

See [`example/prometheus.yml`](example/prometheus.yml) for a full example.

## Web endpoint

A minimal HTTP endpoint (default `0.0.0.0:9090`, `--web.listen-address`)
serves Kubernetes-style probes — there is deliberately no web UI:

- `GET /-/healthy` — liveness
- `GET /-/ready` — readiness (200 once scraping runs)
- `POST /-/reload`, `POST /-/quit` — lifecycle API, enabled with
  `--web.enable-lifecycle`; a failed reload keeps the current config
  running and returns 500, like Prometheus. SIGHUP also reloads.

For drop-in use in existing Prometheus deployments (e.g. via
prometheus-operator), the server-only flags `--agent`,
`--storage.agent.path`, `--web.config.file` and `--web.route-prefix` are
accepted and ignored (hidden from `--help`).

## Supported configuration

The agent-mode subset of the Prometheus configuration format:

- `global`: `scrape_interval`, `scrape_timeout`, `external_labels`
- `scrape_configs`: `job_name`, `metrics_path`, `scheme`, `params`,
  `scrape_interval`/`scrape_timeout` overrides, `honor_labels`,
  `honor_timestamps`, `sample_limit`, `basic_auth`, `authorization`,
  `bearer_token(_file)`, `tls_config` (`insecure_skip_verify`, `ca_file`),
  `static_configs`, `file_sd_configs`, `kubernetes_sd_configs`,
  `relabel_configs`, `metric_relabel_configs`
- `remote_write`: `url`, `name`, `remote_timeout`, `headers`, auth as above,
  `write_relabel_configs`, `queue_config` (`capacity`,
  `max_samples_per_send`, `batch_send_deadline`, `min_backoff`,
  `max_backoff`), `protobuf_message` (`prometheus.WriteRequest` default,
  or `io.prometheus.write.v2.Request` for remote-write 2.0 with its
  symbol table — ~40-60% smaller payloads, supported by Mimir >= 2.17)

Relabeling implements the full Prometheus action set: `replace`, `keep`,
`drop`, `keepequal`, `dropequal`, `hashmod` (MD5, bit-compatible with
Prometheus), `labelmap`, `labeldrop`, `labelkeep`, `lowercase`, `uppercase`.
Unknown configuration fields are rejected at startup so unsupported setups
(e.g. `kubernetes_sd_configs`) fail loudly instead of silently not scraping.

Per-target synthetic series (`up`, `scrape_duration_seconds`,
`scrape_samples_scraped`, `scrape_samples_post_metric_relabeling`,
`scrape_series_added`) are emitted like Prometheus does.

Staleness markers are **off by default** and enabled with
`--staleness.enable-tracking`. Tracking costs one retained (snappy
compressed) scrape body plus one hash per active series and per target, and
for most backends the markers only duplicate what missing samples already
imply. With the flag unset no body is retained, no per-series state is kept,
and `prometheus_scrape_rs_tracked_series` stays at zero.

The agent also
exposes its own self-monitoring metrics on `GET /metrics` and pushes them
via remote-write; see [docs/metrics.md](docs/metrics.md) for the full list.

### Kubernetes service discovery

`kubernetes_sd_configs` supports the `pod` and `endpointslice` roles — the
two prometheus-operator generates for podMonitors and serviceMonitors —
with `namespaces` (`names`, `own_namespace`) and `attach_metadata.node`.
Targets carry the standard `__meta_kubernetes_*` labels so operator
generated relabel rules work unchanged. Client configuration comes from
the environment (in-cluster service account or `KUBECONFIG`); `api_server`,
`kubeconfig_file` and `selectors` are not supported.

Required RBAC: `get`/`list`/`watch` on `pods`, `services`,
`endpointslices` (API group `discovery.k8s.io`), and `nodes` when
`attach_metadata.node` is used — the same rules the prometheus-operator
ships for Prometheus itself.

## Design notes

- **Wire format without middlemen**: the four remote-write protobuf messages
  are hand-written `prost` structs (`src/model.rs`); the exposition parser
  emits them directly, so a sample goes scrape body → `TimeSeries` → snappy
  compressed `WriteRequest` with no intermediate metric model.
- **Parser** (`src/parser.rs`): single-pass, byte-level, regex-free parser
  for the text exposition format 0.0.4 with pragmatic OpenMetrics tolerance
  (`# EOF`, exemplars ignored, float-second timestamps converted).
- **Scraping** (`src/scrape.rs`): one tokio task per target with a
  deterministic FNV-1a jitter offset spreading scrapes over the interval.
- **Sending** (`src/remote_write.rs`): per-endpoint batching queues honoring
  `queue_config`; retries forever with exponential backoff on 429/5xx and
  transport errors, drops the batch on other 4xx (per spec). Backpressure is
  a bounded queue; when an endpoint is down long enough that the queue
  fills, new samples for it are dropped and counted.
- **YAML** via [`serde_saphyr`](https://docs.rs/serde_saphyr) (`serde_yaml`
  is unmaintained).
- **musl + mimalloc, deliberately**: musl's two real performance penalties
  are its allocator under multithreaded load (solved by mimalloc; measured
  within ~2% of glibc) and the static-build default of 2003-era x86-64
  codegen without runtime SIMD dispatch (solved by pinning
  `-C target-cpu=x86-64-v3` in the container build). ring's crypto is
  libc-independent assembly and tokio threads use Rust-managed stacks, so
  no residual musl penalty applies to this workload — a glibc base image
  would buy nothing measurable and cost the scratch image.

## Known gaps vs. Prometheus agent mode

- No WAL: samples buffered in memory only; a long remote-storage outage
  drops data that Prometheus agent would have kept on disk.
- Service discovery: `static_configs`, `file_sd_configs` and
  `kubernetes_sd_configs` (`pod`/`endpointslice` roles); other roles and
  SD mechanisms are rejected at startup.
- No client TLS certificates (`cert_file`/`key_file`) yet.

## Container image

```sh
docker build -f Containerfile -t prometheus-scrape-rs .
```

Multi-stage build: `rust:1-alpine` compiles a fully static musl binary
(mimalloc allocator, ring-only TLS — no aws-lc/cmake involved) with the
LTO `deploy` profile; the runtime stage is `FROM scratch` containing only
the binary and a CA bundle, running as UID 65534. Resulting image is
~6 MB. Kubernetes probes are served on `:9090` (see the web endpoint
section); no shell, no UI, no writable filesystem needed.

The build is profile-guided: an instrumented binary runs a deterministic
training workload (parse → relabel → encode → compress) and the final
binary is rebuilt with the collected profile — measured 1.08x faster on
the hot path. Drop real scrape bodies into `pgo-corpus/*.prom` (see
[`pgo-corpus/README.md`](pgo-corpus/README.md)) to train on production
data; without them a synthetic body is used.

## Development

```sh
cargo test           # unit tests + end-to-end pipeline test
cargo bench          # criterion benchmarks: parser, relabel, encoding
cargo clippy --all-targets
```
