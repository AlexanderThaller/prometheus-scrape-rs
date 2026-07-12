//! A lightweight Prometheus scraping agent: scrapes Prometheus exposition
//! endpoints and forwards samples via the remote-write 1.0 protocol, driven
//! by a standard `prometheus.yml` (agent-mode subset).

pub mod auth;
pub mod config;
mod hash;
pub mod model;
pub mod parser;
#[doc(hidden)]
pub mod pgo;
pub mod relabel;
pub mod remote_write;
pub mod scrape;
pub mod sd;
pub mod sd_k8s;
pub mod telemetry;
pub mod web;
