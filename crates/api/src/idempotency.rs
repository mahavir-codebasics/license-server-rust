//! Idempotency-Key support — Redis-backed replay cache for safe retries.
//!
//! Clients send `Idempotency-Key: <client-chosen-uuid>` on a mutation. We
//! record the (account, key) -> stored-response mapping for 24h. A retry with
//! the same key returns the CACHED response instead of re-executing the
//! mutation, so flaky-network retries don't double-create licenses/tokens/etc.
//!
//! When Redis is absent, the layer is a no-op (mutations just aren't
//! idempotent-safe — acceptable for local dev).

use redis::Commands;
use std::sync::Arc;
use std::time::Duration;

const TTL: Duration = Duration::from_secs(24 * 3600);

/// Has this (account, key) been seen before? Returns the cached response body
/// + status if so. No-op (None) when Redis isn't configured.
pub fn get_cached(
    redis: Option<&Arc<redis::Client>>,
    account_id: &str,
    key: &str,
) -> Option<(u16, String)> {
    let client = redis?;
    let Ok(mut conn) = client.get_connection() else {
        return None;
    };
    let redis_key = redis_key(account_id, key);
    let val: Option<String> = conn.get(&redis_key).ok();
    val.and_then(|s| {
        // Format: "<status>\n<body>"
        let (status, body) = s.split_once('\n')?;
        Some((status.parse().ok()?, body.to_string()))
    })
}

/// Store a response for future replays. No-op when Redis isn't configured.
pub fn store(
    redis: Option<&Arc<redis::Client>>,
    account_id: &str,
    key: &str,
    status: u16,
    body: &str,
) {
    let Some(client) = redis else {
        return;
    };
    let Ok(mut conn) = client.get_connection() else {
        return;
    };
    let redis_key = redis_key(account_id, key);
    let payload = format!("{status}\n{body}");
    let _: () = conn
        .set_ex(&redis_key, payload, TTL.as_secs())
        .unwrap_or(());
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

    #[test]
    fn get_cached_returns_none_without_redis() {
        assert!(get_cached(None, "acc", "key").is_none());
    }

    #[test]
    fn store_is_noop_without_redis() {
        // Just shouldn't panic.
        store(None, "acc", "key", 200, "{}");
    }
}
