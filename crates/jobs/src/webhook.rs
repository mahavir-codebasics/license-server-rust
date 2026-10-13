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
//!
//! SSRF guard: endpoint URLs are admin-supplied, so delivery is blocked unless
//! the URL is http(s) AND its host is public. [`validate_public_url`] resolves
//! the host and rejects loopback/private/link-local/reserved targets (including
//! cloud-metadata endpoints such as 169.254.169.254) right before every
//! request; redirects are disabled on the delivery client so a public URL can't
//! bounce to a private one. [`validate_endpoint_url`] applies the cheap scheme/
//! literal checks at endpoint-creation time for fast operator feedback.
//! `allow_private` (config `LICENSE_SERVER__SECURITY__WEBHOOKS_ALLOW_PRIVATE`)
//! is the explicit opt-out for deployments whose receivers live on the
//! internal network. Residual risk: a DNS-rebinding race between our check
//! and reqwest's own resolution — mitigate at the network layer if you accept
//! org-admin-supplied URLs in hostile environments.

use apalis::prelude::{BoxDynError, Data, Error};
use apalis_redis::{Config, RedisStorage};
use hmac::{Hmac, Mac};
use license_domain::repository::Repository;
use license_domain::WebhookEventId;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::IpAddr;
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
    allow_private: Data<bool>,
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

    // SSRF guard, immediately before the request: an admin-supplied URL must
    // point at a public host on every attempt (DNS can change between the
    // create call and this delivery). Blocked deliveries are permanent — the
    // operator has to fix the endpoint.
    if let Err(reason) = validate_public_url(&endpoint.url, *allow_private).await {
        let host = url::Url::parse(&endpoint.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default();
        tracing::warn!(event_id = %event_id, host = %host, "webhook blocked by SSRF guard: {reason}");
        repo.webhooks()
            .mark_attempt(
                event_id,
                true,
                None,
                Some(format!("blocked by SSRF guard: {reason}")),
                None,
            )
            .await
            .ok();
        return Ok(());
    }

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

// ── SSRF guard ────────────────────────────────────────────────────────────

/// Full pre-delivery check: the URL must be http(s) and its host must resolve
/// to public addresses only. `allow_private` is the explicit operator opt-out.
/// See the module docs for the (documented) DNS-rebinding residual risk.
pub async fn validate_public_url(raw: &str, allow_private: bool) -> Result<(), String> {
    let url = url::Url::parse(raw).map_err(|e| format!("invalid url: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme {:?} not allowed (http/https only)",
            url.scheme()
        ));
    }
    if allow_private {
        return Ok(());
    }
    let Some(host) = url.host_str().map(str::to_owned) else {
        return Err("url has no host".into());
    };
    let port = url.port_or_known_default().unwrap_or(80);

    // IP literals bypass DNS entirely. (url keeps brackets on v6 literals.)
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return ip_is_public(ip)
            .then_some(())
            .ok_or_else(|| format!("{ip} is not a public address"));
    }
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return Err("localhost is not allowed".into());
    }

    let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| format!("cannot resolve host `{host}`: {e}"))?
        .collect();
    if let Some(bad) = addrs.iter().map(|a| a.ip()).find(|ip| !ip_is_public(*ip)) {
        return Err(format!("`{host}` resolves to a non-public address ({bad})"));
    }
    Ok(())
}

/// Cheap, DNS-free checks for endpoint creation: valid URL, http(s) scheme,
/// and no loopback/private/reserved IP literal or localhost name. Full DNS
/// validation happens at delivery time (see [`validate_public_url`]).
pub fn validate_endpoint_url(raw: &str) -> Result<(), String> {
    let url = url::Url::parse(raw).map_err(|e| format!("invalid url: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme {:?} not allowed (http/https only)",
            url.scheme()
        ));
    }
    let Some(host) = url.host_str().map(str::to_owned) else {
        return Err("url has no host".into());
    };
    if let Ok(ip) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        return ip_is_public(ip).then_some(()).ok_or_else(|| {
            format!("{ip} is not a public address — point the endpoint at a public host")
        });
    }
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return Err("localhost is not allowed".into());
    }
    Ok(())
}

/// True only for globally-routable addresses. Rejects loopback, RFC1918
/// private, link-local (includes the cloud-metadata endpoint 169.254.169.254),
/// unspecified/broadcast/reserved, CGNAT 100.64/10, benchmarking 198.18/15,
/// documentation ranges, IPv6 unique-local/link-local/documentation, and
/// v4-mapped v6 (checked as their embedded v4).
fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // 240.0.0.0/4 reserved (broadcast 255.255.255.255 included)
                || (v4.octets()[0] & 0xf0) == 0xf0
                // 100.64/10 — carrier-grade NAT / shared address space
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                // 198.18/15 — benchmarking
                || (o[0] == 198 && (18..=19).contains(&o[1])))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_is_public(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                // fe80::/10 link-local
                || (seg[0] & 0xffc0) == 0xfe80
                // fc00::/7 unique-local
                || (seg[0] & 0xfe00) == 0xfc00
                // 2001:db8::/32 documentation
                || (seg[0] == 0x2001 && seg[1] == 0x0db8))
        }
    }
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

    #[test]
    fn endpoint_url_rejects_private_targets() {
        assert!(validate_endpoint_url("ftp://hooks.example.com/x").is_err());
        assert!(validate_endpoint_url("file:///etc/passwd").is_err());
        assert!(validate_endpoint_url("http://localhost/hook").is_err());
        assert!(validate_endpoint_url("http://api.localhost/hook").is_err());
        assert!(validate_endpoint_url("http://127.0.0.1/hook").is_err());
        assert!(validate_endpoint_url("http://[::1]/hook").is_err());
        assert!(validate_endpoint_url("http://10.1.2.3/hook").is_err());
        assert!(validate_endpoint_url("http://172.16.0.9/hook").is_err());
        assert!(validate_endpoint_url("http://192.168.1.4/hook").is_err());
        // cloud metadata endpoint — link-local
        assert!(validate_endpoint_url("http://169.254.169.254/latest/meta-data").is_err());
        // v4-mapped v6 wrapping a private v4
        assert!(validate_endpoint_url("http://[::ffff:10.0.0.5]/hook").is_err());
        assert!(validate_endpoint_url("not a url").is_err());
    }

    #[test]
    fn endpoint_url_allows_public_targets() {
        assert!(validate_endpoint_url("https://hooks.example.com/x").is_ok());
        assert!(validate_endpoint_url("https://8.8.8.8/hook").is_ok());
        assert!(validate_endpoint_url("http://93.184.216.34/hook").is_ok());
    }

    #[tokio::test]
    async fn public_url_check_passes_ip_literals() {
        assert!(validate_public_url("https://8.8.8.8/hook", false)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn public_url_check_blocks_metadata_even_with_dns() {
        assert!(validate_public_url("http://169.254.169.254/", false)
            .await
            .is_err());
        assert!(validate_public_url("http://localhost:9090/", false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn allow_private_opt_out_bypasses_host_checks_but_not_scheme() {
        assert!(validate_public_url("http://127.0.0.1:8080/hook", true)
            .await
            .is_ok());
        assert!(validate_public_url("ftp://127.0.0.1/hook", true)
            .await
            .is_err());
    }

    #[test]
    fn ip_classifier_matches_rfc_ranges() {
        assert!(ip_is_public("93.184.216.34".parse().unwrap()));
        assert!(!ip_is_public("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(!ip_is_public("198.18.0.1".parse().unwrap())); // benchmarking
        assert!(!ip_is_public("198.19.255.255".parse().unwrap()));
        assert!(!ip_is_public("192.0.2.1".parse().unwrap())); // documentation
        assert!(!ip_is_public("240.0.0.1".parse().unwrap())); // reserved
        assert!(!ip_is_public("0.0.0.0".parse().unwrap()));
        assert!(ip_is_public("2001:4860:4860::8888".parse().unwrap())); // public v6
        assert!(!ip_is_public("fd00::1".parse().unwrap())); // unique-local
        assert!(!ip_is_public("fe80::1".parse().unwrap())); // link-local
        assert!(!ip_is_public("2001:db8::1".parse().unwrap())); // documentation
        assert!(!ip_is_public("::ffff:192.168.0.1".parse().unwrap())); // mapped
    }
}
