//! Client-IP resolution for rate limiting. XFF is trusted under the classic
//! hop-count rule: honor it only when the chain is at least as long as the
//! configured trusted-proxy count (spec F8).
//!
//! Residual risk: a client connecting DIRECTLY (bypassing every declared
//! proxy) can forge its bucket identity with an XFF header longer than
//! `trusted_proxies`. Count-based trust assumes the service is reachable only
//! through the declared proxy chain; upgrade path is peer-address allowlisting.

/// Resolve the rate-limit bucket id for an anonymous request.
///
/// With `trusted_proxies == N > 0`, the immediate TCP peer is assumed to be
/// proxy hop #1; walk `X-Forwarded-For` from RIGHT to LEFT taking the value
/// N hops back (the first client-controlled address). A chain SHORTER than
/// the trusted-hop count never traversed every configured proxy and falls
/// back to the TCP peer, as does anything malformed. Never trusts XFF by
/// default.
pub fn client_bucket_key(
    trusted_proxies: usize,
    xff: Option<&str>,
    peer: Option<std::net::IpAddr>,
) -> String {
    let fallback = || {
        format!(
            "ip:{}",
            peer.map(|p| p.to_string())
                .unwrap_or_else(|| "local".into())
        )
    };
    let Some(xff) = xff else { return fallback() };
    if trusted_proxies == 0 {
        return fallback();
    }
    let hops: Vec<&str> = xff.split(',').map(str::trim).rev().collect();
    if hops.len() < trusted_proxies {
        return fallback();
    }
    match hops[trusted_proxies.saturating_sub(1)].parse::<std::net::IpAddr>() {
        Ok(ip) => format!("ip:{ip}"),
        Err(_) => fallback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const PEER: Option<IpAddr> = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    #[test]
    fn no_xff_uses_peer() {
        assert_eq!(client_bucket_key(0, None, PEER), "ip:10.0.0.1");
    }

    #[test]
    fn untrusted_xff_is_ignored() {
        assert_eq!(client_bucket_key(0, Some("1.2.3.4"), PEER), "ip:10.0.0.1");
    }

    #[test]
    fn trusted_proxy_walks_chain_from_right() {
        // peer=proxy; chain "victim, attacker-spoofed" -> take rightmost non-peer hop.
        assert_eq!(
            client_bucket_key(1, Some("203.0.113.9, 198.51.100.7"), PEER),
            "ip:198.51.100.7"
        );
    }

    #[test]
    fn short_chain_falls_back_to_peer() {
        assert_eq!(
            client_bucket_key(2, Some("203.0.113.9"), PEER),
            "ip:10.0.0.1"
        );
    }

    #[test]
    fn legit_single_proxy_chain_is_honored() {
        assert_eq!(
            client_bucket_key(1, Some("203.0.113.9"), PEER),
            "ip:203.0.113.9"
        );
    }

    #[test]
    fn garbage_xff_falls_back_to_peer() {
        assert_eq!(client_bucket_key(1, Some("not-an-ip"), PEER), "ip:10.0.0.1");
    }
}
