# PGO training corpus

Drop real exposition-format scrape bodies here as `*.prom` files; the
container build feeds them to `--pgo-training` so the profile reflects
production data. Without any `*.prom` files the training falls back to a
synthetic body. The samples themselves are deliberately not committed.
