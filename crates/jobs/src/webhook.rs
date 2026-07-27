//! Webhook delivery worker.
//!
//! Picks up due `WebhookEvent` rows, POSTs them to the endpoint URL with an
//! HMAC-SHA256 signature, and records the attempt. Failed deliveries are
//! retried with exponential backoff (the next_retry_at column drives the
//! schedule; the `due()` query only returns rows whose retry time has passed).
//!
//! The signing scheme mirrors GitHub/Stripe: `X-License-Signature:
//! t=<unix_ts>,v1=<hex_hmac_sha256(t.body)>`. Receivers verify by recomputing
//! the HMAC over `<ts>.<body>` with the shared secret + checking the timestamp
//! is recent (replay protection).

use apalis::prelude::{BoxDynError, Data, Error};
use apalis_redis::{Config, RedisStorage};
use hmac::{Hmac, Mac};
use license_domain::repository::Repository;
use license_domain::WebhookEventId;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

/// A serializable webhook-delivery job pushed onto the Redis queue. We don't
/// ship the full `WebhookEvent` row (it lives in the DB); we ship just enough
/// to let the worker reload + attempt it. This keeps jobs small and means the
/// DB is the source of truth for state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDeliveryJob {
    pub event_id: String,
    pub account_id: String,
    pub endpoint_id: String,
}

/// Run a single delivery attempt. Returns `Err` only for transient failures
/// (5xx, timeouts, connection errors) so apalis's retry layer re-queues;
/// permanent failures (4xx, missing endpoint) are logged + marked done so we
/// don't retry forever.
pub async fn deliver_webhook(
    job: WebhookDeliveryJob,
    repo: Data<Arc<dyn Repository>>,
    http: Data<reqwest::Client>,
) -> Result<(), Error> {
    let event_id = parse_id(&job.event_id)?;
    let account_id = parse_account_id(&job.account_id)?;

    // Reload the event + endpoint fresh each attempt (the secret may have
    // rotated; the URL may have changed).
    let endpoint_id = parse_endpoint_id(&job.endpoint_id)?;
    let endpoint = repo
        .webhooks()
        .get_endpoint(account_id, endpoint_id)
        .await
        .map_err(|e| io_err(format!("reload endpoint: {e}")))?;
    if endpoint.status != license_domain::WebhookStatus::Active {
        // Endpoint disabled since the job was enqueued — drop it.
        repo.webhooks()
            .mark_attempt(event_id, true, None, Some("endpoint disabled".into()), None)
            .await
            .ok();
        return Ok(());
    }

    let event = match repo
        .webhooks()
        .due(OffsetDateTime::now_utc(), 1)
        .await
        .map_err(|e| io_err(format!("load due: {e}")))?
        .into_iter()
        .find(|e| e.id == event_id)
    {
        Some(e) => e,
        None => return Ok(()), // already delivered by another worker / pruned
    };

    let body = serde_json::to_vec(&event.payload).unwrap_or_default();
    let (sig_header, _ts) = sign_webhook(&endpoint.secret, &body);

    let result = http
        .post(&endpoint.url)
        .header("content-type", "application/json")
        .header("x-license-signature", &sig_header)
        .header("x-license-event", &event.event_type)
        .header("x-license-delivery", event.id.to_string())
        .timeout(Duration::from_secs(15))
        .body(body)
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => {
            repo.webhooks()
                .mark_attempt(event_id, true, Some(resp.status().as_u16()), None, None)
                .await
                .ok();
            tracing::info!(
                event_id = %event_id,
                status = resp.status().as_u16(),
                "webhook delivered"
            );
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            // 4xx (except 408/429) are permanent — don't retry forever.
            let permanent = (400..500).contains(&status) && status != 408 && status != 429;
            let next_retry = if permanent {
                None
            } else {
                Some(OffsetDateTime::now_utc() + backoff(event.attempts + 1))
            };
            repo.webhooks()
                .mark_attempt(
                    event_id,
                    permanent,
                    Some(status),
                    Some(format!("HTTP {status}: {text}")[..512].to_string()),
                    next_retry,
                )
                .await
                .ok();
            if permanent {
                Ok(())
            } else {
                Err(io_err(format!("transient HTTP {status}")))
            }
        }
        Err(e) => {
            // Network error — retryable.
            let next_retry = Some(OffsetDateTime::now_utc() + backoff(event.attempts + 1));
            repo.webhooks()
                .mark_attempt(event_id, false, None, Some(e.to_string()), next_retry)
                .await
                .ok();
            Err(io_err(format!("network: {e}")))
        }
    }
}

/// Sign `(timestamp).(body)` with HMAC-SHA256 and return the header value +
/// the timestamp used. Receivers verify by recomputing.
pub fn sign_webhook(secret: &str, body: &[u8]) -> (String, i64) {
    let ts = OffsetDateTime::now_utc().unix_timestamp();
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let sig = hex::encode(mac.finalize().into_bytes());
    (format!("t={ts},v1={sig}"), ts)
}

/// Exponential backoff with jitter-ish capping. attempt = 1 → ~10s, 2 → ~20s,
/// ... capped at 1h.
fn backoff(attempts: u32) -> Duration {
    let secs = 10u64.saturating_mul(1u64 << attempts.min(8));
    Duration::from_secs(secs.min(3600))
}

fn parse_id(s: &str) -> Result<WebhookEventId, Error> {
    uuid::Uuid::parse_str(s)
        .map(WebhookEventId)
        .map_err(|_| io_err(format!("bad event id `{s}`")))
}
fn parse_account_id(s: &str) -> Result<license_domain::AccountId, Error> {
    uuid::Uuid::parse_str(s)
        .map(license_domain::AccountId)
        .map_err(|_| io_err(format!("bad account id `{s}`")))
}
fn parse_endpoint_id(s: &str) -> Result<license_domain::WebhookEndpointId, Error> {
    uuid::Uuid::parse_str(s)
        .map(license_domain::WebhookEndpointId)
        .map_err(|_| io_err(format!("bad endpoint id `{s}`")))
}

fn io_err(msg: String) -> Error {
    // `apalis::prelude::Error` only implements `From<BoxDynError>` (Box<dyn
    // StdError + Send + Sync>); there is no direct `From<std::io::Error>`. Box
    // the io::Error first, then convert via the blanket impl.
    let boxed: BoxDynError = Box::new(std::io::Error::other(msg));
    boxed.into()
}

/// Build a Redis storage handle for the webhook-delivery queue, suitable for
/// both producing (`.push`) and consuming (worker).
pub async fn webhook_storage(redis_url: &str) -> Result<RedisStorage<WebhookDeliveryJob>, String> {
    let conn = apalis_redis::connect(redis_url)
        .await
        .map_err(|e| format!("redis connect: {e}"))?;
    // apalis-redis 0.7.4 `Config` has no `Config::new` constructor; start from
    // the default and set the queue namespace (apalis-redis itself does the
    // same internally — see `RedisStorage::new`).
    Ok(RedisStorage::new_with_config(
        conn,
        Config::default().set_namespace("webhook-delivery"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let secret = "s3cret";
        let body = br#"{"event":"license.created"}"#;
        let (header, ts) = sign_webhook(secret, body);

        // header shape
        assert!(header.starts_with(&format!("t={ts},")));
        let v1 = header.split("v1=").nth(1).unwrap();
        assert_eq!(v1.len(), 64); // hex sha256

        // recompute and compare
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        assert_eq!(hex::encode(mac.finalize().into_bytes()), v1);
    }

    #[test]
    fn sign_is_time_dependent() {
        let (a, _) = sign_webhook("k", b"body");
        std::thread::sleep(Duration::from_millis(1100));
        let (b, _) = sign_webhook("k", b"body");
        // timestamps differ across a second boundary
        assert_ne!(a, b);
    }

    #[test]
    fn backoff_is_monotonic_and_capped() {
        let b1 = backoff(1);
        let b2 = backoff(2);
        let b3 = backoff(3);
        assert!(b2 > b1);
        assert!(b3 > b2);
        // capped at 1h regardless of attempt count
        assert!(backoff(100) <= Duration::from_secs(3600));
    }

    #[test]
    fn bad_id_is_rejected() {
        assert!(parse_id("not-a-uuid").is_err());
        assert!(parse_id("019fa1b2-3c4d-7e8f-9012-3456789abcde").is_ok());
    }
}
