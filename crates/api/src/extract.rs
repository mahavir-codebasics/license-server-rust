//! Extractors: shared app state, pagination query.

use axum::extract::Query;
use license_domain::repository::{PageQuery, Repository};
use redis::aio::ConnectionManager;
use serde::Deserialize;
use std::sync::Arc;

/// Shared state injected into every handler.
///
/// `repo` is a trait object so the API works with ANY backend (SQLite,
/// Postgres, MySQL) — the concrete impl is chosen at startup via
/// [`license_db::Pool::connect`] and erased here. `redis` is optional: when
/// present it backs rate limiting + idempotency; when absent those degrade to
/// no-ops (the API still works).
#[derive(Clone)]
pub struct AppState {
    pub repo: Arc<dyn Repository>,
    /// Master secret used for AES-key derivation + token hashing.
    /// (In production this comes from the KMS-backed KeyStore.)
    pub master_secret: Arc<[u8; 32]>,
    /// Multiplexed async Redis connection (rate limiting + idempotency).
    pub redis: Option<ConnectionManager>,
    /// How many reverse-proxy hops sit directly in front of us; controls
    /// X-Forwarded-For trust when keying anonymous rate-limit buckets.
    pub trusted_proxies: usize,
}

impl AppState {
    pub fn new(repo: Arc<dyn Repository>, master_secret: [u8; 32]) -> Self {
        Self {
            repo,
            master_secret: Arc::new(master_secret),
            redis: None,
            trusted_proxies: 0,
        }
    }

    pub fn with_redis(mut self, redis: ConnectionManager) -> Self {
        self.redis = Some(redis);
        self
    }

    pub fn with_trusted_proxies(mut self, n: usize) -> Self {
        self.trusted_proxies = n;
        self
    }
}

/// Pagination query: `?page[limit]=25&page[after]=<cursor>`.
#[derive(Debug, Deserialize, Default)]
pub struct PageParams {
    #[serde(rename = "page[limit]", default)]
    pub limit: Option<u32>,
    #[serde(rename = "page[after]", default)]
    pub after: Option<String>,
}

impl PageParams {
    pub fn into_query(self) -> PageQuery {
        PageQuery {
            // clamp to [1, 100]
            limit: self.limit.unwrap_or(25).clamp(1, 100),
            after: self.after,
        }
    }
}

/// Extract pagination from the query string.
pub async fn extract_page(query: Option<Query<PageParams>>) -> PageQuery {
    query.map(|q| q.0.into_query()).unwrap_or_default()
}
