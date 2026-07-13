# PGO training corpus

Real exposition bodies from a production cluster (Cilium, Mimir, Grafana,
cert-manager, node-exporter, plus two IoT exporters), pseudonymized so they can
be committed. The container build feeds them to `--pgo-training`, and the
`remote_write` encoder tests parse them, so a CI build trains on
production-shaped data instead of falling back to a synthetic body.

## These are not raw scrapes

Every label value is pseudonymized except a short allowlist of enum labels whose
values come from the exporters' own source code (`le`, `quantile`, `method`,
`status_code`, `collector`, `fstype`, …). Metric names, `# HELP`/`# TYPE`
comments, sample values and timestamps are untouched — they are exporter
vocabulary, not environment data.

The substitution preserves **byte length, cardinality, and character class**, so
a UUID stays UUID-shaped and a mount path stays path-shaped. Bytes, series
counts, metric-family counts and distinct-value counts are all identical to the
raw capture, which is what the profile and the benchmarks actually depend on:
value *lengths* drive the word-at-a-time hasher, and distinct-value *counts*
drive the v2 encoder's memoized interning hit rate.

Do not hand-edit these files.

## Regenerating

Put raw captures in `corpus-raw/` (gitignored) and run:

```sh
cargo run --example sanitize_corpus -- --input corpus-raw --output pgo-corpus
```

The tool writes nothing if its leak scan finds a hostname, MAC, IP, tenant name
or hardware serial surviving into the output.

## Adding a new exporter

Expect the leak scan to fail the first time, and read what it says rather than
working around it. The audit behind the allowlist found environment identifiers
in labels that look entirely innocuous: `serial` held hardware serial numbers,
`key` held per-tenant keys, and `datasource_type`, `dialer_name` and `cluster`
all held internal project names. If a new label is genuinely enum vocabulary, add
it to `KEEP` in the tool; otherwise leave it to be redacted. Over-redacting costs
readability, never profile accuracy.
