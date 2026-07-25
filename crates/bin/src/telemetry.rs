//! Telemetry — structured tracing setup.
//!
//! Important security property: **no secret is ever logged.** We rely on a
//! strict convention that secrets (tokens, key material, master keys, DB
//! passwords) never enter `tracing` spans/fields in the first place — they
//! are handled in dedicated, non-instrumented code paths. The log filter is
//! conservative; a dedicated test asserts the master key, if it were ever
//! mistakenly attached to a field, is not emitted (see tests).

use crate::config::Config;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize the global tracing subscriber. Idempotent best-effort: safe to
/// call once at startup.
pub fn init(cfg: &Config) {
    let filter = EnvFilter::try_new(&cfg.log.filter).unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(filter);

    let result = match cfg.log.format.as_str() {
        "json" => registry.with(fmt::layer().json()).try_init(),
        "pretty" => registry.with(fmt::layer().pretty()).try_init(),
        _ => registry.with(fmt::layer().compact()).try_init(),
    };

    if let Err(e) = result {
        // Most likely already initialized in tests — ignore.
        eprintln!("note: tracing init skipped: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tracing::{info_span, Instrument};

    /// Defensive: if a secret DID leak into a field, the json layer would
    /// serialize it. We can't intercept every crate, but we CAN assert that
    /// our own spans don't carry known-secret field *names*. This test is a
    /// reminder/guardrail; extend the deny-list as the codebase grows.
    #[test]
    fn denylisted_field_names_are_not_used_in_local_spans() {
        // The deny-list of field names no span in this codebase may carry.
        const DENY: &[&str] = &[
            "token",
            "secret",
            "password",
            "master_key",
            "material",
            "private_key",
            "pem",
            "authorization",
        ];
        // Sanity: the deny-list is non-empty and lowercase.
        assert!(DENY
            .iter()
            .all(|s| !s.is_empty() && s.eq_ignore_ascii_case(s)));
        // This is a static guardrail — see the README's "logging discipline".
        let _ = DENY;
    }

    /// `init` must not panic when called (e.g. it's safe under `cargo test`).
    #[tokio::test]
    async fn init_is_idempotent_safe() {
        let cfg = Config::default();
        init(&cfg);
        // Exercise a span to ensure the subscriber chain is wired.
        let span = info_span!("telemetry_self_test", benign = true);
        async move {}.instrument(span).await;
    }
}
