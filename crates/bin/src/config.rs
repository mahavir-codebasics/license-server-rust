//! Application configuration.
//!
//! Loaded from (later source wins):
//!   1. built-in defaults
//!   2. `config.toml` in the working dir (optional)
//!   3. environment variables, prefixed `LICENSE_SERVER__`, `__` = nesting
//!
//! Secrets (master key, DB password embedded in URL) live only in env, never
//! in defaults or the toml file.

use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Which process role(s) this binary runs. Lets one binary act as api, worker,
/// scheduler, or all — enabling horizontal scaling by running more `api`/
/// `worker` replicas while keeping `scheduler` singleton via Redis leader lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Role {
    Api,
    Worker,
    Scheduler,
    #[default]
    All,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpConfig {
    pub host: String,
    pub port: u16,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 8080,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GrpcConfig {
    pub host: String,
    pub port: u16,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 9090,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    /// Optional read-replica DSN (Postgres only).
    #[serde(default)]
    pub replica_url: Option<String>,
    #[serde(default = "default_pool")]
    pub max_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            replica_url: None,
            max_connections: default_pool(),
        }
    }
}

fn default_pool() -> u32 {
    16
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CryptoConfig {
    /// 32-byte master key (hex) used to encrypt signing-key material at rest.
    pub master_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_filter")]
    pub filter: String,
}

fn default_log_format() -> String {
    "compact".into()
}
fn default_log_filter() -> String {
    "info,license_server=debug".into()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
            filter: default_log_filter(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// OTLP gRPC endpoint, e.g. `http://localhost:4317`. Empty = off.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
}

/// CORS origins, XFF trust, bootstrap secret, and webhook egress policy.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// Comma-separated CORS origins allowed to call the API. Empty = same-origin only.
    #[serde(default)]
    pub allowed_origins: String,
    /// How many reverse-proxy hops sit directly in front of us (XFF trust).
    #[serde(default)]
    pub trusted_proxies: usize,
    /// When set, `POST /v1/accounts` (which mints the first admin token)
    /// requires a matching `X-Bootstrap-Secret` header. Strongly recommended
    /// for any deployment reachable by untrusted clients.
    #[serde(default)]
    pub bootstrap_secret: Option<String>,
    /// Explicit opt-out of the webhook SSRF guard, for deployments whose
    /// receivers live on the private network. Default: block loopback/private/
    /// link-local webhook targets.
    #[serde(default)]
    pub webhooks_allow_private: bool,
}

/// Top-level config.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub role: Role,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub grpc: GrpcConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

impl Config {
    /// Load config from defaults → toml → env. Env keys look like
    /// `LICENSE_SERVER__DATABASE__URL` (`__` = nesting).
    #[allow(clippy::result_large_err)] // figment::Error is a third-party type we can't shrink
    pub fn load() -> Result<Self, figment::Error> {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));

        let toml_path = Path::new("config.toml");
        if toml_path.exists() {
            fig = fig.merge(Toml::file(toml_path));
        }

        fig = fig.merge(Env::prefixed("LICENSE_SERVER__").split("__"));

        fig.extract()
    }

    /// Pretty-ish debug of the public fields (master key redacted).
    pub fn display_safe(&self) -> String {
        let mk = self.crypto.master_key.as_str();
        let redacted = if mk.is_empty() || mk.chars().all(|c| c == '0') {
            "(unset/zero)".to_string()
        } else {
            format!("{}…", &mk[..mk.len().min(6)])
        };
        format!(
            "role={:?} http={}:{} grpc={}:{} db={} redis={} master_key={} log={}",
            self.role,
            self.http.host,
            self.http.port,
            self.grpc.host,
            self.grpc.port,
            redact_url_userinfo(&self.database.url),
            self.redis.url,
            redacted,
            self.log.format,
        )
    }
}

/// Mask the `user:pass@` segment of a DSN so it never reaches a log.
fn redact_url_userinfo(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        if let Some(at) = rest.find('@') {
            let after = &rest[at + 1..];
            return format!("{}://***@{}", &url[..scheme_end], after);
        }
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_userinfo_hides_password() {
        let r = redact_url_userinfo("postgresql://user:s3cret@host:5432/db");
        assert!(!r.contains("s3cret"));
        assert!(r.contains("***@host"));
    }

    #[test]
    fn redact_url_userinfo_passthrough_when_no_creds() {
        let r = redact_url_userinfo("sqlite:///data/app.db");
        assert_eq!(r, "sqlite:///data/app.db");
    }
}
