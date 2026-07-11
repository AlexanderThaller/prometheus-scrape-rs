# Fully static musl build (mimalloc allocator, ring TLS) in a scratch image.
# Build: docker build -f Containerfile -t prometheus-scrape-rs .
#
# rust:1-alpine targets musl natively (crt-static is the default), so no
# cross toolchain or RUSTFLAGS are needed. The TLS stack is ring-only —
# aws-lc-sys and its cmake/linux-headers requirements never enter the build.

FROM docker.io/library/rust:1-alpine AS builder
RUN apk add --no-cache musl-dev build-base ca-certificates
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --profile deploy --bin prometheus-scrape-rs \
    && cp target/deploy/prometheus-scrape-rs /prometheus-scrape-rs

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /prometheus-scrape-rs /prometheus-scrape-rs
USER 65534:65534
EXPOSE 9090
ENTRYPOINT ["/prometheus-scrape-rs"]
