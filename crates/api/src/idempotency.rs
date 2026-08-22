//! Idempotency-Key support — Redis-backed replay cache for safe retries.
//!
//! Clients send `Idempotency-Key: <client-chosen-uuid>` on a mutation. We
//! record the (account, key) -> stored-response mapping for 24h. A retry with
//! the same key returns the CACHED response instead of re-executing the
//! mutation, so flaky-network retries don't double-create licenses/tokens/etc.
//!
//! When Redis is absent, the layer is a no-op (mutations just aren't
//! idempotent-safe — acceptable for local dev).

use redis::{aio::ConnectionManager, AsyncCommands};
use std::time::Duration;

const TTL: Duration = Duration::from_secs(24 * 3600);

/// Has this (account, key) been seen before? Returns the cached response body
/// + status if so. No-op (None) when Redis isn't configured.
pub async fn get_cached(
    redis: Option<&ConnectionManager>,
    account_id: &str,
    key: &str,
) -> Option<(u16, String)> {
    let mut conn = redis?.clone();
    let val: Option<String> = conn.get(redis_key(account_id, key)).await.ok()?;
    val.and_then(|s| {
        // Format: "<status>\n<body>"
        let (status, body) = s.split_once('\n')?;
        Some((status.parse().ok()?, body.to_string()))
    })
}

/// Store a response for future replays. No-op when Redis isn't configured.
pub async fn store(
    redis: Option<&ConnectionManager>,
    account_id: &str,
    key: &str,
    status: u16,
    body: &str,
) {
    let Some(mut conn) = redis.cloned() else {
        return;
    };
    let _: Result<(), _> = conn
        .set_ex(
            redis_key(account_id, key),
            format!("{status}\n{body}"),
            TTL.as_secs(),
        )
        .await;
}

/// Is the presented key well-formed? (non-empty, reasonable length)
pub fn is_well_formed(key: &str) -> bool {
    !key.is_empty() && key.len() <= 256
}

fn redis_key(account_id: &str, key: &str) -> String {
    format!("idempotency:{account_id}:{key}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_check() {
        assert!(is_well_formed("abc-123"));
        assert!(!is_well_formed(""));
        assert!(!is_well_formed(&"x".repeat(300)));
    }

    #[tokio::test]
    async fn get_cached_returns_none_without_redis() {
        assert!(get_cached(None, "acc", "key").await.is_none());
    }

    #[tokio::test]
    async fn store_is_noop_without_redis() {
        store(None, "acc", "key", 200, "{}").await;
    }
}
