//! Prometheus configuration file (`prometheus.yml`) parsing.
//!
//! Supports the subset of the upstream Prometheus configuration schema
//! relevant to agent-mode operation: global settings, scrape configs
//! (static and file service discovery), relabeling and remote-write.

use std::{
    collections::{
        BTreeMap,
        HashMap,
    },
    path::{
        Path,
        PathBuf,
    },
    time::Duration,
};

use serde::{
    Deserialize,
    Deserializer,
};

use crate::relabel::RelabelConfig;

/// Load and validate a Prometheus configuration file from `path`.
pub fn load(path: &Path) -> anyhow::Result<Config> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("reading config file {}: {err}", path.display()))?;
    let config: Config = serde_saphyr::from_str(&raw)
        .map_err(|err| anyhow::anyhow!("parsing config file {}: {err}", path.display()))?;
    config.validate()?;
    Ok(config)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub global: GlobalConfig,
    pub scrape_configs: Vec<ScrapeConfig>,
    pub remote_write: Vec<RemoteWriteConfig>,
    // Server-only sections. Parsed so a server config is diagnosed with a
    // clear "not supported in agent mode" error instead of a generic
    // unknown-field failure, mirroring Prometheus --agent.
    rule_files: Option<serde::de::IgnoredAny>,
    alerting: Option<serde::de::IgnoredAny>,
    remote_read: Option<serde::de::IgnoredAny>,
}

impl Config {
    fn validate(&self) -> anyhow::Result<()> {
        for (section, value) in [
            ("rule_files", &self.rule_files),
            ("alerting", &self.alerting),
            ("remote_read", &self.remote_read),
        ] {
            if value.is_some() {
                anyhow::bail!(
                    "field {section} is not supported: this is a scraping agent \
                     (like Prometheus agent mode); remove the section from the config"
                );
            }
        }
        let mut seen_job_names = std::collections::HashSet::new();
        for scrape_config in &self.scrape_configs {
            scrape_config.validate()?;
            if !seen_job_names.insert(scrape_config.job_name.as_str()) {
                anyhow::bail!(
                    "duplicate job_name {:?} in scrape_configs",
                    scrape_config.job_name
                );
            }
        }
        for remote_write in &self.remote_write {
            remote_write.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GlobalConfig {
    pub scrape_interval: PromDuration,
    pub scrape_timeout: PromDuration,
    pub external_labels: BTreeMap<String, String>,
    // Accepted but unused, like Prometheus agent mode: rule evaluation and
    // query logging do not exist in a scraping agent.
    evaluation_interval: Option<PromDuration>,
    query_log_file: Option<String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            scrape_interval: PromDuration::from_secs(60),
            scrape_timeout: PromDuration::from_secs(10),
            external_labels: BTreeMap::new(),
            evaluation_interval: None,
            query_log_file: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScrapeConfig {
    pub job_name: String,
    pub scrape_interval: Option<PromDuration>,
    pub scrape_timeout: Option<PromDuration>,
    pub metrics_path: String,
    pub scheme: String,
    pub params: HashMap<String, Vec<String>>,
    pub honor_labels: bool,
    pub honor_timestamps: bool,
    pub basic_auth: Option<BasicAuth>,
    pub authorization: Option<Authorization>,
    pub bearer_token: Option<String>,
    pub bearer_token_file: Option<PathBuf>,
    pub tls_config: TlsConfig,
    pub sample_limit: u64,
    pub static_configs: Vec<StaticConfig>,
    pub file_sd_configs: Vec<FileSdConfig>,
    pub relabel_configs: Vec<RelabelConfig>,
    pub metric_relabel_configs: Vec<RelabelConfig>,
}

impl Default for ScrapeConfig {
    fn default() -> Self {
        Self {
            job_name: String::new(),
            scrape_interval: None,
            scrape_timeout: None,
            metrics_path: "/metrics".to_owned(),
            scheme: "http".to_owned(),
            params: HashMap::new(),
            honor_labels: false,
            honor_timestamps: true,
            basic_auth: None,
            authorization: None,
            bearer_token: None,
            bearer_token_file: None,
            tls_config: TlsConfig::default(),
            sample_limit: 0,
            static_configs: Vec::new(),
            file_sd_configs: Vec::new(),
            relabel_configs: Vec::new(),
            metric_relabel_configs: Vec::new(),
        }
    }
}

impl ScrapeConfig {
    /// Effective scrape interval, falling back to the global default when
    /// unset.
    #[must_use]
    pub fn interval(&self, global: &GlobalConfig) -> Duration {
        self.scrape_interval
            .unwrap_or(global.scrape_interval)
            .as_duration()
    }

    /// Effective scrape timeout, falling back to the global default when unset.
    #[must_use]
    pub fn timeout(&self, global: &GlobalConfig) -> Duration {
        self.scrape_timeout
            .unwrap_or(global.scrape_timeout)
            .as_duration()
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.job_name.is_empty() {
            anyhow::bail!("job_name must not be empty");
        }
        if self.scheme != "http" && self.scheme != "https" {
            anyhow::bail!(
                "scrape config {:?}: scheme must be \"http\" or \"https\", got {:?}",
                self.job_name,
                self.scheme
            );
        }
        validate_basic_auth(self.basic_auth.as_ref())
            .map_err(|err| anyhow::anyhow!("scrape config {:?}: {err}", self.job_name))?;
        validate_authorization(self.authorization.as_ref())
            .map_err(|err| anyhow::anyhow!("scrape config {:?}: {err}", self.job_name))?;
        validate_exclusive_auth(
            self.basic_auth.as_ref(),
            self.authorization.as_ref(),
            self.bearer_token.as_ref(),
        )
        .map_err(|err| anyhow::anyhow!("scrape config {:?}: {err}", self.job_name))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StaticConfig {
    pub targets: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileSdConfig {
    pub files: Vec<String>,
    pub refresh_interval: PromDuration,
}

impl Default for FileSdConfig {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            refresh_interval: PromDuration::from_secs(5 * 60),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BasicAuth {
    pub username: String,
    pub password: Option<String>,
    pub password_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Authorization {
    pub r#type: String,
    pub credentials: Option<String>,
    pub credentials_file: Option<PathBuf>,
}

impl Default for Authorization {
    fn default() -> Self {
        Self {
            r#type: "Bearer".to_owned(),
            credentials: None,
            credentials_file: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    pub insecure_skip_verify: bool,
    pub ca_file: Option<PathBuf>,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RemoteWriteConfig {
    pub url: String,
    pub name: Option<String>,
    pub remote_timeout: PromDuration,
    pub headers: HashMap<String, String>,
    pub basic_auth: Option<BasicAuth>,
    pub authorization: Option<Authorization>,
    pub bearer_token: Option<String>,
    pub tls_config: TlsConfig,
    pub write_relabel_configs: Vec<RelabelConfig>,
    pub queue_config: QueueConfig,
}

impl Default for RemoteWriteConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            name: None,
            remote_timeout: PromDuration::from_secs(30),
            headers: HashMap::new(),
            basic_auth: None,
            authorization: None,
            bearer_token: None,
            tls_config: TlsConfig::default(),
            write_relabel_configs: Vec::new(),
            queue_config: QueueConfig::default(),
        }
    }
}

impl RemoteWriteConfig {
    fn validate(&self) -> anyhow::Result<()> {
        validate_url(&self.url)
            .map_err(|err| anyhow::anyhow!("remote_write {:?}: {err}", self.url))?;
        validate_basic_auth(self.basic_auth.as_ref())
            .map_err(|err| anyhow::anyhow!("remote_write {:?}: {err}", self.url))?;
        validate_authorization(self.authorization.as_ref())
            .map_err(|err| anyhow::anyhow!("remote_write {:?}: {err}", self.url))?;
        validate_exclusive_auth(
            self.basic_auth.as_ref(),
            self.authorization.as_ref(),
            self.bearer_token.as_ref(),
        )
        .map_err(|err| anyhow::anyhow!("remote_write {:?}: {err}", self.url))?;
        self.queue_config
            .validate()
            .map_err(|err| anyhow::anyhow!("remote_write {:?}: {err}", self.url))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct QueueConfig {
    pub capacity: usize,
    pub max_shards: usize,
    pub min_shards: usize,
    pub max_samples_per_send: usize,
    pub batch_send_deadline: PromDuration,
    pub min_backoff: PromDuration,
    pub max_backoff: PromDuration,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            capacity: 10_000,
            max_shards: 50,
            min_shards: 1,
            max_samples_per_send: 2_000,
            batch_send_deadline: PromDuration::from_secs(5),
            min_backoff: PromDuration(Duration::from_millis(30)),
            max_backoff: PromDuration::from_secs(5),
        }
    }
}

impl QueueConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.capacity == 0 {
            anyhow::bail!("queue_config.capacity must be non-zero");
        }
        if self.max_samples_per_send == 0 {
            anyhow::bail!("queue_config.max_samples_per_send must be non-zero");
        }
        if self.min_shards == 0 {
            anyhow::bail!("queue_config.min_shards must be non-zero");
        }
        if self.max_shards == 0 {
            anyhow::bail!("queue_config.max_shards must be non-zero");
        }
        if self.max_shards < self.min_shards {
            anyhow::bail!("queue_config.max_shards must be >= min_shards");
        }
        Ok(())
    }
}

fn validate_basic_auth(basic_auth: Option<&BasicAuth>) -> anyhow::Result<()> {
    if let Some(basic_auth) = basic_auth
        && basic_auth.password.is_some()
        && basic_auth.password_file.is_some()
    {
        anyhow::bail!("basic_auth: password and password_file are mutually exclusive");
    }
    Ok(())
}

fn validate_authorization(authorization: Option<&Authorization>) -> anyhow::Result<()> {
    if let Some(authorization) = authorization
        && authorization.credentials.is_some()
        && authorization.credentials_file.is_some()
    {
        anyhow::bail!("authorization: credentials and credentials_file are mutually exclusive");
    }
    Ok(())
}

fn validate_exclusive_auth(
    basic_auth: Option<&BasicAuth>,
    authorization: Option<&Authorization>,
    bearer_token: Option<&String>,
) -> anyhow::Result<()> {
    let set_count = usize::from(basic_auth.is_some())
        + usize::from(authorization.is_some())
        + usize::from(bearer_token.is_some());
    if set_count > 1 {
        anyhow::bail!("at most one of basic_auth, authorization, or bearer_token may be set");
    }
    Ok(())
}

/// Minimal http(s) URL validation: checks the scheme prefix and a non-empty
/// host.
fn validate_url(url: &str) -> anyhow::Result<()> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| anyhow::anyhow!("url must start with http:// or https://"))?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        anyhow::bail!("url is missing a host");
    }
    Ok(())
}

/// A Prometheus-style duration, e.g. `15s`, `1h30m`, `5m`, `30ms`, `1d`, `1w`,
/// `1y`, `0`.
///
/// Mirrors the parsing rules of Prometheus's `model.ParseDuration`: one or
/// more `<number><unit>` groups in strictly descending unit order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromDuration(Duration);

impl PromDuration {
    #[must_use]
    pub const fn as_duration(&self) -> Duration {
        self.0
    }

    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    /// Parse a Prometheus duration string.
    pub fn parse(input: &str) -> Result<Self, PromDurationError> {
        // Units in strictly descending order, with their length in
        // milliseconds. Checked in order so that e.g. "m" is not matched
        // before "ms".
        const UNITS: &[(&str, u64)] = &[
            ("y", 365 * 24 * 60 * 60 * 1000),
            ("w", 7 * 24 * 60 * 60 * 1000),
            ("d", 24 * 60 * 60 * 1000),
            ("h", 60 * 60 * 1000),
            ("m", 60 * 1000),
            ("s", 1000),
            ("ms", 1),
        ];

        if input.is_empty() {
            return Err(PromDurationError::Empty);
        }
        if input == "0" {
            return Ok(Self(Duration::ZERO));
        }

        let mut remaining = input;
        let mut last_unit_index: Option<usize> = None;
        let mut total_ms: u128 = 0;

        while !remaining.is_empty() {
            let digits_len = remaining
                .as_bytes()
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digits_len == 0 {
                return Err(PromDurationError::InvalidFormat(input.to_owned()));
            }
            let (digits, rest) = remaining.split_at(digits_len);
            let number: u64 = digits
                .parse()
                .map_err(|_err| PromDurationError::NumberOverflow(input.to_owned()))?;

            // Match the longest unit prefix first (needed to distinguish "m" from "ms").
            let unit_match = UNITS
                .iter()
                .enumerate()
                .filter(|(_, (unit, _))| rest.starts_with(unit))
                .max_by_key(|(_, (unit, _))| unit.len());

            let Some((unit_index, &(unit, ms_per_unit))) = unit_match else {
                return Err(PromDurationError::UnknownUnit(input.to_owned()));
            };

            if let Some(last_index) = last_unit_index
                && unit_index <= last_index
            {
                return Err(PromDurationError::UnitOrder(input.to_owned()));
            }
            last_unit_index = Some(unit_index);

            let contribution = u128::from(number)
                .checked_mul(u128::from(ms_per_unit))
                .ok_or_else(|| PromDurationError::NumberOverflow(input.to_owned()))?;
            total_ms = total_ms
                .checked_add(contribution)
                .ok_or_else(|| PromDurationError::NumberOverflow(input.to_owned()))?;

            remaining = &rest[unit.len()..];
        }

        let total_ms: u64 = total_ms
            .try_into()
            .map_err(|_err| PromDurationError::NumberOverflow(input.to_owned()))?;
        Ok(Self(Duration::from_millis(total_ms)))
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum PromDurationError {
    #[error("duration string must not be empty")]
    Empty,
    #[error("invalid duration format: {0:?}")]
    InvalidFormat(String),
    #[error("unknown or misplaced unit in duration: {0:?}")]
    UnknownUnit(String),
    #[error("duration units must appear in descending order without repeats: {0:?}")]
    UnitOrder(String),
    #[error("duration number overflow: {0:?}")]
    NumberOverflow(String),
}

impl<'de> Deserialize<'de> for PromDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_server_only_global_fields() {
        let yaml = r"
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  query_log_file: /var/log/queries.log
";
        let config: Config = serde_saphyr::from_str(yaml).expect("must parse");
        assert_eq!(
            config.global.scrape_interval.as_duration(),
            Duration::from_secs(15)
        );
    }

    #[test]
    fn rejects_server_only_sections_with_agent_hint() {
        for section in ["rule_files: ['alerts.yml']", "alerting: {}", "remote_read: []"] {
            let yaml = format!("{section}\nscrape_configs: []\n");
            let config: Config = serde_saphyr::from_str(&yaml).expect("must parse");
            let err = config.validate().expect_err("must be rejected").to_string();
            assert!(
                err.contains("agent mode"),
                "error should mention agent mode: {err}"
            );
        }
    }

    #[test]
    fn parses_realistic_agent_config() {
        let yaml = r#"
global:
  scrape_interval: 30s
  scrape_timeout: 15s
  external_labels:
    region: eu-central
    cluster: prod-1

scrape_configs:
  - job_name: node
    metrics_path: /metrics
    scheme: http
    params:
      collect[]: ["cpu", "meminfo"]
    basic_auth:
      username: scraper
      password: hunter2
    static_configs:
      - targets: ["10.0.0.1:9100", "10.0.0.2:9100"]
        labels:
          env: prod
    file_sd_configs:
      - files: ["/etc/prometheus/sd/*.json"]
        refresh_interval: 1m
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: "go_.*"
        action: drop

remote_write:
  - url: "https://remote.example.com/api/v1/write"
    name: primary
    headers:
      X-Scope-OrgID: tenant-a
    queue_config:
      capacity: 20000
      max_samples_per_send: 5000
    write_relabel_configs:
      - source_labels: [__name__]
        regex: "expensive_.*"
        action: drop
"#;
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        config.validate().unwrap();

        assert_eq!(config.global.scrape_interval, PromDuration::from_secs(30));
        assert_eq!(config.global.scrape_timeout, PromDuration::from_secs(15));
        assert_eq!(
            config
                .global
                .external_labels
                .get("region")
                .map(String::as_str),
            Some("eu-central")
        );
        assert_eq!(
            config
                .global
                .external_labels
                .get("cluster")
                .map(String::as_str),
            Some("prod-1")
        );

        assert_eq!(config.scrape_configs.len(), 1);
        let scrape = &config.scrape_configs[0];
        assert_eq!(scrape.job_name, "node");
        assert_eq!(scrape.metrics_path, "/metrics");
        assert_eq!(scrape.scheme, "http");
        assert_eq!(
            scrape.params.get("collect[]"),
            Some(&vec!["cpu".to_owned(), "meminfo".to_owned()])
        );
        assert!(!scrape.honor_labels);
        assert!(scrape.honor_timestamps);

        let basic_auth = scrape.basic_auth.as_ref().unwrap();
        assert_eq!(basic_auth.username, "scraper");
        assert_eq!(basic_auth.password.as_deref(), Some("hunter2"));
        assert!(basic_auth.password_file.is_none());

        assert_eq!(scrape.static_configs.len(), 1);
        assert_eq!(
            scrape.static_configs[0].targets,
            vec!["10.0.0.1:9100".to_owned(), "10.0.0.2:9100".to_owned()]
        );
        assert_eq!(
            scrape.static_configs[0]
                .labels
                .get("env")
                .map(String::as_str),
            Some("prod")
        );

        assert_eq!(scrape.file_sd_configs.len(), 1);
        assert_eq!(
            scrape.file_sd_configs[0].files,
            vec!["/etc/prometheus/sd/*.json".to_owned()]
        );
        assert_eq!(
            scrape.file_sd_configs[0].refresh_interval,
            PromDuration::from_secs(60)
        );

        assert_eq!(scrape.relabel_configs.len(), 1);
        assert_eq!(scrape.relabel_configs[0].target_label, "instance");

        assert_eq!(scrape.metric_relabel_configs.len(), 1);
        assert_eq!(scrape.metric_relabel_configs[0].regex.source, "go_.*");

        assert_eq!(config.remote_write.len(), 1);
        let remote_write = &config.remote_write[0];
        assert_eq!(remote_write.url, "https://remote.example.com/api/v1/write");
        assert_eq!(remote_write.name.as_deref(), Some("primary"));
        assert_eq!(
            remote_write
                .headers
                .get("X-Scope-OrgID")
                .map(String::as_str),
            Some("tenant-a")
        );
        assert_eq!(remote_write.queue_config.capacity, 20_000);
        assert_eq!(remote_write.queue_config.max_samples_per_send, 5_000);
        assert_eq!(remote_write.write_relabel_configs.len(), 1);
    }

    #[test]
    fn defaults_applied_when_absent() {
        let yaml = r"
scrape_configs:
  - job_name: minimal
";
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        config.validate().unwrap();

        assert_eq!(config.global.scrape_interval, PromDuration::from_secs(60));
        assert_eq!(config.global.scrape_timeout, PromDuration::from_secs(10));
        assert!(config.global.external_labels.is_empty());

        let scrape = &config.scrape_configs[0];
        assert_eq!(scrape.metrics_path, "/metrics");
        assert_eq!(scrape.scheme, "http");
        assert!(scrape.params.is_empty());
        assert!(!scrape.honor_labels);
        assert!(scrape.honor_timestamps);
        assert!(scrape.basic_auth.is_none());
        assert!(scrape.authorization.is_none());
        assert!(scrape.bearer_token.is_none());
        assert_eq!(scrape.sample_limit, 0);
        assert!(scrape.static_configs.is_empty());
        assert!(scrape.file_sd_configs.is_empty());
        assert!(scrape.relabel_configs.is_empty());
        assert!(scrape.metric_relabel_configs.is_empty());
        assert!(!scrape.tls_config.insecure_skip_verify);

        assert_eq!(scrape.interval(&config.global), Duration::from_secs(60));
        assert_eq!(scrape.timeout(&config.global), Duration::from_secs(10));

        assert!(config.remote_write.is_empty());
    }

    #[test]
    fn per_job_interval_overrides_global() {
        let yaml = r"
global:
  scrape_interval: 60s
  scrape_timeout: 10s
scrape_configs:
  - job_name: fast
    scrape_interval: 5s
    scrape_timeout: 2s
";
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let scrape = &config.scrape_configs[0];
        assert_eq!(scrape.interval(&config.global), Duration::from_secs(5));
        assert_eq!(scrape.timeout(&config.global), Duration::from_secs(2));
    }

    #[test]
    fn queue_config_defaults() {
        let queue_config = QueueConfig::default();
        assert_eq!(queue_config.capacity, 10_000);
        assert_eq!(queue_config.max_shards, 50);
        assert_eq!(queue_config.min_shards, 1);
        assert_eq!(queue_config.max_samples_per_send, 2_000);
        assert_eq!(queue_config.batch_send_deadline, PromDuration::from_secs(5));
        assert_eq!(
            queue_config.min_backoff.as_duration(),
            Duration::from_millis(30)
        );
        assert_eq!(queue_config.max_backoff, PromDuration::from_secs(5));
    }

    #[test]
    fn tls_config_default() {
        let tls_config = TlsConfig::default();
        assert!(!tls_config.insecure_skip_verify);
        assert!(tls_config.ca_file.is_none());
        assert!(tls_config.cert_file.is_none());
        assert!(tls_config.key_file.is_none());
    }

    #[test]
    fn duration_parsing_table() {
        let valid = [
            ("0", Duration::ZERO),
            ("0s", Duration::ZERO),
            ("30ms", Duration::from_millis(30)),
            ("15s", Duration::from_secs(15)),
            ("5m", Duration::from_mins(5)),
            ("1h", Duration::from_hours(1)),
            ("1d", Duration::from_hours(24)),
            ("1w", Duration::from_hours(7 * 24)),
            ("1y", Duration::from_hours(365 * 24)),
            ("1h30m", Duration::from_hours(1) + Duration::from_mins(30)),
            (
                "1h30m15s",
                Duration::from_hours(1) + Duration::from_mins(30) + Duration::from_secs(15),
            ),
            (
                "1d2h3m4s5ms",
                Duration::from_hours(26)
                    + Duration::from_mins(3)
                    + Duration::from_secs(4)
                    + Duration::from_millis(5),
            ),
        ];
        for (input, expected) in valid {
            let parsed = PromDuration::parse(input)
                .unwrap_or_else(|err| panic!("expected {input:?} to parse, got error {err}"));
            assert_eq!(parsed.as_duration(), expected, "input was {input:?}");
        }

        let invalid = [
            "", "5", "s", "5x", "5s5s", "5m5h", "-5s", "5.5s", " 5s", "5s ", "5ms5s",
        ];
        for input in invalid {
            assert!(
                PromDuration::parse(input).is_err(),
                "expected {input:?} to fail to parse"
            );
        }
    }

    #[test]
    fn rejects_duplicate_job_names() {
        let yaml = r#"
scrape_configs:
  - job_name: dup
    static_configs:
      - targets: ["a:9100"]
  - job_name: dup
    static_configs:
      - targets: ["b:9100"]
"#;
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate job_name"), "{err}");
    }

    #[test]
    fn rejects_empty_job_name() {
        let yaml = r#"
scrape_configs:
  - job_name: ""
"#;
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("job_name must not be empty"),
            "{err}"
        );
    }

    #[test]
    fn rejects_bad_scheme() {
        let yaml = r"
scrape_configs:
  - job_name: bad
    scheme: ftp
";
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("scheme"), "{err}");
    }

    #[test]
    fn rejects_bad_duration_in_yaml() {
        let yaml = r#"
global:
  scrape_interval: "not-a-duration"
"#;
        let result: Result<Config, _> = serde_saphyr::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let yaml = r"
scrape_configs:
  - job_name: node
    not_a_real_field: true
";
        let result: Result<Config, _> = serde_saphyr::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let yaml = r"
totally_unknown_section: {}
";
        let result: Result<Config, _> = serde_saphyr::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_conflicting_basic_auth_password_fields() {
        let yaml = r"
scrape_configs:
  - job_name: node
    basic_auth:
      username: u
      password: p
      password_file: /etc/secret
";
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn rejects_conflicting_authorization_credentials_fields() {
        let yaml = r"
scrape_configs:
  - job_name: node
    authorization:
      credentials: abc
      credentials_file: /etc/secret
";
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn rejects_basic_auth_and_bearer_token_together() {
        let yaml = r"
scrape_configs:
  - job_name: node
    basic_auth:
      username: u
      password: p
    bearer_token: xyz
";
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("at most one of basic_auth, authorization, or bearer_token"),
            "{err}"
        );
    }

    #[test]
    fn rejects_bad_remote_write_url() {
        let yaml = r"
remote_write:
  - url: not-a-url
";
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("http"), "{err}");
    }

    #[test]
    fn rejects_zero_queue_capacity() {
        let yaml = r"
remote_write:
  - url: http://localhost:9090/write
    queue_config:
      capacity: 0
";
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("capacity"), "{err}");
    }

    #[test]
    fn rejects_zero_max_samples_per_send() {
        let yaml = r"
remote_write:
  - url: http://localhost:9090/write
    queue_config:
      max_samples_per_send: 0
";
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("max_samples_per_send"), "{err}");
    }
}
