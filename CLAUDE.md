# CLAUDE

## Rust

Run all three of these before committing, and fix anything they report. They are
the exact commands CI runs, so a green local run is the only way to know the
push will pass:

```sh
cargo clippy --all-targets --all-features -- -D warnings
cargo +nightly fmt --all
cargo nextest run --all-targets --all-features
```

Notes:

* Clippy runs with `-D warnings` in CI — a warning fails the build, so there is
  no such thing as an acceptable leftover warning. Fix the cause; reach for
  `#[expect(..., reason = "...")]` only when the lint is genuinely wrong, never
  `#[allow]`.
* Formatting is checked with the **nightly** toolchain (`cargo fmt --all --
  --check`). Stable `cargo fmt` can format differently, so use `+nightly`.
* Use `--all-targets --all-features`, not `--all`. `--all` means all *packages*
  and misses benches, examples and integration tests — which is where several
  real failures have hidden.

## Scrape corpus

`pgo-corpus/*.prom` are committed, pseudonymized scrape bodies. They feed PGO
training in the container build and are parsed by the remote-write tests. Do not
hand-edit them and do not commit raw captures — see `pgo-corpus/README.md`.
