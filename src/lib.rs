//! A lightweight Prometheus scraping agent: scrapes Prometheus exposition
//! endpoints and forwards samples via the remote-write 1.0 protocol, driven
//! by a standard `prometheus.yml` (agent-mode subset).

pub mod auth;
pub mod config;
pub mod model;
pub mod parser;
pub mod relabel;
pub mod sd;
