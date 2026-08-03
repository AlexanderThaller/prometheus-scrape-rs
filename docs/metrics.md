# Metrics

prometheus-scrape-rs produces two families of metrics:

1. **Self-monitoring metrics** — the agent's own counters and gauges,
   describing scrape and remote-write activity plus process resource use.
2. **Per-target synthetic series** — the standard Prometheus `up` /
   `scrape_*` report series, emitted once per scraped target.

## Self-monitoring metrics

These describe the agent itself. They are exposed two ways, from a single
in-process registry (`src/telemetry.rs`):

- **Pull:** `GET /metrics` on the web endpoint (default `0.0.0.0:9090`),
  in Prometheus text exposition format.
- **Push:** sent through the normal remote-write pipeline every
  `scrape_interval`, labeled `job="prometheus-scrape-rs"` and
  `instance=$HOSTNAME` (falling back to `localhost`), plus any
  `external_labels`. This means self-monitoring works even when no service
  discovery targets the agent's own pod.

All values come from a fixed set of atomics — there is no client-library
dependency, so cardinality is constant and none of these metrics carry
per-target labels.

### Scrape activity

| Metric | Type | Description |
| --- | --- | --- |
| `prometheus_scrape_rs_scrapes_total` | counter | Scrapes attempted, including failures. |
| `prometheus_scrape_rs_scrape_failures_total` | counter | Scrapes that failed (fetch, parse, or `sample_limit`). |
| `prometheus_scrape_rs_samples_scraped_total` | counter | Samples parsed from scrape bodies, before metric relabeling. |
| `prometheus_scrape_rs_staleness_markers_total` | counter | Staleness markers emitted (stale NaN samples for series that disappeared). |
| `prometheus_scrape_rs_tracked_series` | gauge | Series currently tracked for staleness detection. |

Both staleness metrics stay at zero unless the agent runs with
`--staleness.enable-tracking`; staleness tracking is off by default.

### Remote-write activity

| Metric | Type | Description |
| --- | --- | --- |
| `prometheus_scrape_rs_remote_write_batches_total` | counter | Batches accepted by an endpoint. |
| `prometheus_scrape_rs_remote_write_sent_bytes_total` | counter | Compressed bytes accepted by remote-write endpoints. |
| `prometheus_scrape_rs_remote_write_retries_total` | counter | Send attempts that will be retried (5xx / 429 / transport errors). |
| `prometheus_scrape_rs_remote_write_failed_batches_total` | counter | Batches dropped after an unrecoverable (4xx) response. |
| `prometheus_scrape_rs_remote_write_dropped_series_total` | counter | Series dropped because an endpoint queue was full. |

### Process and build info

| Metric | Type | Description |
| --- | --- | --- |
| `prometheus_scrape_rs_build_info` | gauge | Always `1`; carries a `version` label with the crate version. |
| `process_start_time_seconds` | gauge | Unix time the process started (set once at startup). |
| `process_cpu_seconds_total` | counter | Total user + system CPU time. Linux only (read from `/proc/self/stat`). |
| `process_resident_memory_bytes` | gauge | Resident set size. Linux only (read from `/proc/self/statm`). |

The two `process_*` metrics are only present on Linux; on other platforms,
or if procfs cannot be read, they are omitted from the output.

## Per-target synthetic series

For every scrape of every target, the agent emits the same report series
Prometheus does (`src/scrape.rs`). They carry the target's labels plus
`external_labels`, and are always emitted — including on failure, so `up`
can go to `0`.

| Series | Description |
| --- | --- |
| `up` | `1` if the scrape succeeded, `0` if it failed. |
| `scrape_duration_seconds` | Wall-clock duration of the scrape. |
| `scrape_samples_scraped` | Number of samples parsed from the scrape body. |
| `scrape_samples_post_metric_relabeling` | Samples remaining after `metric_relabel_configs`. |
| `scrape_series_added` | Series retained from this scrape. |

These are the per-target counterparts to the aggregate
`prometheus_scrape_rs_samples_scraped_total` self-metric above.
