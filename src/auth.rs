//! Shared HTTP client construction and authentication.

use std::{
    path::Path,
    time::Duration,
};

use anyhow::Context as _;

use crate::config::{
    Authorization,
    BasicAuth,
    TlsConfig,
};

/// Build an HTTP client honoring the given TLS settings.
pub fn build_client(timeout: Duration, tls: &TlsConfig) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("prometheus-scrape-rs/", env!("CARGO_PKG_VERSION")))
        .gzip(true);

    if tls.insecure_skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(ca_file) = &tls.ca_file {
        let pem = std::fs::read(ca_file)
            .with_context(|| format!("reading ca_file {}", ca_file.display()))?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("parsing ca_file {}", ca_file.display()))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    if tls.cert_file.is_some() || tls.key_file.is_some() {
        anyhow::bail!("tls_config cert_file/key_file (client certificates) are not supported yet");
    }

    builder.build().context("building HTTP client")
}

/// Pre-resolved request credentials.
///
/// Credential files are read once at startup, matching how often Prometheus
/// effectively re-reads them per scrape; hot-reload of credential files is not
/// supported.
#[derive(Debug, Clone, Default)]
pub enum Credentials {
    #[default]
    None,
    Basic {
        username: String,
        password: String,
    },
    /// Pre-formatted `Authorization` header value, e.g. `Bearer <token>`.
    Header(String),
}

impl Credentials {
    pub fn resolve(
        basic_auth: Option<&BasicAuth>,
        authorization: Option<&Authorization>,
        bearer_token: Option<&str>,
        bearer_token_file: Option<&Path>,
    ) -> anyhow::Result<Self> {
        if let Some(basic) = basic_auth {
            let password = match (&basic.password, &basic.password_file) {
                (Some(password), None) => password.clone(),
                (None, Some(file)) => read_secret_file(file)?,
                (None, None) => String::new(),
                (Some(_), Some(_)) => {
                    anyhow::bail!("basic_auth: password and password_file are mutually exclusive")
                }
            };
            return Ok(Self::Basic {
                username: basic.username.clone(),
                password,
            });
        }
        if let Some(authorization) = authorization {
            let credentials = match (&authorization.credentials, &authorization.credentials_file) {
                (Some(credentials), None) => credentials.clone(),
                (None, Some(file)) => read_secret_file(file)?,
                (None, None) => String::new(),
                (Some(_), Some(_)) => anyhow::bail!(
                    "authorization: credentials and credentials_file are mutually exclusive"
                ),
            };
            return Ok(Self::Header(format!(
                "{} {credentials}",
                authorization.r#type
            )));
        }
        if let Some(token) = bearer_token {
            return Ok(Self::Header(format!("Bearer {token}")));
        }
        if let Some(file) = bearer_token_file {
            return Ok(Self::Header(format!("Bearer {}", read_secret_file(file)?)));
        }
        Ok(Self::None)
    }

    pub fn apply(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Self::None => builder,
            Self::Basic { username, password } => builder.basic_auth(username, Some(password)),
            Self::Header(value) => builder.header(reqwest::header::AUTHORIZATION, value.clone()),
        }
    }
}

fn read_secret_file(path: &Path) -> anyhow::Result<String> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading credentials file {}", path.display()))?;
    Ok(contents.trim_end_matches(['\n', '\r']).to_owned())
}
