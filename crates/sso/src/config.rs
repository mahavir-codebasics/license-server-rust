//! Per-account OIDC provider configuration and the v1 in-memory registry.
//!
//! An enterprise customer configures their identity provider (Google,
//! Microsoft Entra ID, Okta, Auth0, …) once. That configuration is stored as
//! an [`SsoConfig`] and looked up by account at sign-in time. v1 keeps the
//! configs in an in-process [`SsoRegistry`] (`HashMap` behind a `RwLock`);
//! persisting them to a dedicated DB table is a later pass.

use std::collections::HashMap;
use std::fmt;

use license_domain::AccountId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::{Result, SsoError};

/// Default OIDC scopes requested for every flow. These are the standard claims
/// required to identify and label a user; providers may return more, but these
/// three are the minimum we rely on for JIT provisioning.
pub const DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];

/// One account's OIDC provider configuration.
///
/// All fields are stored exactly as the IdP's developer console presents them.
/// `client_secret` is sensitive — it is `Serialize` so a config can be
/// persisted/restored, but the API layer must never echo it back to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    /// The IdP issuer URL, e.g. `https://accounts.google.com`. OIDC discovery
    /// appends `/.well-known/openid-configuration` to this.
    pub issuer_url: String,
    /// OAuth2 client id issued by the IdP for this application.
    pub client_id: String,
    /// OAuth2 client secret. Confidential (server-side) only — never shipped
    /// to a browser or native client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Our callback URL, e.g. `https://license.example.com/v1/sso/callback`.
    /// Must be registered with the IdP.
    pub redirect_url: String,
    /// Scopes to request. Defaults to `["openid","email","profile"]` when
    /// omitted by callers (see [`SsoConfig::default_scopes`]).
    #[serde(default = "SsoConfig::default_scopes_vec")]
    pub scopes: Vec<String>,
}

impl SsoConfig {
    /// The default scope list as an owned `Vec<String>` (used by serde default).
    pub fn default_scopes_vec() -> Vec<String> {
        DEFAULT_SCOPES.iter().map(|s| (*s).to_string()).collect()
    }

    /// Build an `SsoConfig` with the standard default scopes.
    pub fn new(
        issuer_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_url: impl Into<String>,
    ) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            redirect_url: redirect_url.into(),
            scopes: Self::default_scopes_vec(),
        }
    }

    /// Build an `SsoConfig` with the standard default scopes, for a public
    /// client (no secret — e.g. a SPA that cannot hold one).
    #[allow(dead_code)]
    pub fn new_public_client(
        issuer_url: impl Into<String>,
        client_id: impl Into<String>,
        redirect_url: impl Into<String>,
    ) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            client_id: client_id.into(),
            client_secret: None,
            redirect_url: redirect_url.into(),
            scopes: Self::default_scopes_vec(),
        }
    }
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            client_id: String::new(),
            client_secret: None,
            redirect_url: String::new(),
            scopes: Self::default_scopes_vec(),
        }
    }
}

/// A configured SSO connection: the account it belongs to plus its config.
///
/// This is the "row" a persistent table would store in a later pass. It is
/// returned by [`SsoRegistry::connection_for`] so callers know which account a
/// resolved config belongs to without carrying the id separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConnection {
    pub account_id: AccountId,
    pub config: SsoConfig,
}

impl SsoConnection {
    pub fn new(account_id: AccountId, config: SsoConfig) -> Self {
        Self { account_id, config }
    }
}

/// In-memory registry mapping an [`AccountId`] to its [`SsoConfig`].
///
/// v1 holds this behind a `parking_lot::RwLock` so that the API layer can
/// register/update configs at runtime while many concurrent sign-in flows read
/// them. When persistence lands, this struct becomes a thin cache over the DB
/// table and its public API stays stable.
#[derive(Default)]
pub struct SsoRegistry {
    inner: RwLock<HashMap<AccountId, SsoConfig>>,
}

impl SsoRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) the SSO config for an account.
    pub fn register(&self, account_id: AccountId, config: SsoConfig) {
        let mut guard = self.inner.write();
        guard.insert(account_id, config);
    }

    /// Remove an account's SSO config, if present. Returns whether a config
    /// was actually removed.
    pub fn unregister(&self, account_id: AccountId) -> bool {
        let mut guard = self.inner.write();
        guard.remove(&account_id).is_some()
    }

    /// Look up the raw config for an account.
    pub fn get(&self, account_id: AccountId) -> Option<SsoConfig> {
        let guard = self.inner.read();
        guard.get(&account_id).cloned()
    }

    /// Look up the full connection (account + config) for an account, or an
    /// [`SsoError::Config`] if the account has not configured SSO.
    pub fn connection_for(&self, account_id: AccountId) -> Result<SsoConnection> {
        self.get(account_id)
            .map(|config| SsoConnection::new(account_id, config))
            .ok_or_else(|| {
                SsoError::Config(format!("no SSO config registered for account {account_id}"))
            })
    }

    /// Number of registered accounts. Mainly useful for diagnostics/tests.
    pub fn len(&self) -> usize {
        let guard = self.inner.read();
        guard.len()
    }

    /// Whether the registry holds zero configs.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for SsoRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.read();
        f.debug_struct("SsoRegistry")
            .field("accounts", &guard.keys().collect::<Vec<_>>())
            .field("count", &guard.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use license_domain::Account;
    use uuid::Uuid;

    fn sample_config() -> SsoConfig {
        SsoConfig::new(
            "https://accounts.google.com",
            "client-123",
            "secret-456",
            "https://app.example.com/sso/callback",
        )
    }

    #[test]
    fn config_default_scopes_are_standard() {
        assert_eq!(SsoConfig::default_scopes_vec(), DEFAULT_SCOPES);
        let cfg = sample_config();
        assert_eq!(cfg.scopes, vec!["openid", "email", "profile"]);
    }

    #[test]
    fn config_serde_round_trip_preserves_secret_and_scopes() {
        let cfg = sample_config();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: SsoConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(cfg.issuer_url, back.issuer_url);
        assert_eq!(cfg.client_id, back.client_id);
        assert_eq!(cfg.client_secret, back.client_secret);
        assert_eq!(cfg.redirect_url, back.redirect_url);
        assert_eq!(cfg.scopes, back.scopes);
    }

    #[test]
    fn config_serde_omits_missing_secret_as_none() {
        // A config without a secret round-trips with `client_secret: None`.
        let json = r#"{
            "issuer_url": "https://example.com",
            "client_id": "cid",
            "redirect_url": "https://app/cb",
            "scopes": ["openid"]
        }"#;
        let cfg: SsoConfig = serde_json::from_str(json).expect("deserialize");
        assert!(cfg.client_secret.is_none());
        assert_eq!(cfg.scopes, vec!["openid"]);
    }

    #[test]
    fn config_serde_defaults_scopes_when_absent() {
        let json = r#"{
            "issuer_url": "https://example.com",
            "client_id": "cid",
            "client_secret": "s",
            "redirect_url": "https://app/cb"
        }"#;
        let cfg: SsoConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(cfg.scopes, DEFAULT_SCOPES);
    }

    #[test]
    fn registry_register_then_get_returns_config() {
        let registry = SsoRegistry::new();
        let account = Account::new("acme", "Acme");
        let cfg = sample_config();

        assert!(registry.is_empty());
        registry.register(account.id, cfg.clone());
        assert_eq!(registry.len(), 1);

        let got = registry.get(account.id).expect("config registered");
        assert_eq!(got.client_id, cfg.client_id);
    }

    #[test]
    fn registry_register_replaces_existing_config() {
        let registry = SsoRegistry::new();
        let account = Account::new("acme", "Acme");
        let mut cfg = sample_config();
        registry.register(account.id, cfg.clone());

        cfg.client_id = "client-999".to_string();
        registry.register(account.id, cfg);

        assert_eq!(registry.len(), 1);
        let got = registry.get(account.id).expect("config still present");
        assert_eq!(got.client_id, "client-999");
    }

    #[test]
    fn registry_get_missing_returns_none() {
        let registry = SsoRegistry::new();
        let account_id = AccountId(Uuid::nil());
        assert!(registry.get(account_id).is_none());
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_unregister_removes_and_reports() {
        let registry = SsoRegistry::new();
        let account = Account::new("acme", "Acme");
        registry.register(account.id, sample_config());

        assert!(registry.unregister(account.id));
        assert!(!registry.unregister(account.id));
        assert!(registry.get(account.id).is_none());
    }

    #[test]
    fn registry_connection_for_missing_is_config_error() {
        let registry = SsoRegistry::new();
        let account_id = AccountId(Uuid::nil());
        let err = registry.connection_for(account_id).unwrap_err();
        assert!(matches!(err, SsoError::Config(_)), "got {err:?}");
    }

    #[test]
    fn registry_connection_for_returns_account_and_config() {
        let registry = SsoRegistry::new();
        let account = Account::new("acme", "Acme");
        let cfg = sample_config();
        registry.register(account.id, cfg.clone());

        let conn = registry.connection_for(account.id).expect("connection");
        assert_eq!(conn.account_id, account.id);
        assert_eq!(conn.config.client_id, cfg.client_id);
    }

    #[test]
    fn connection_new_pairs_account_and_config() {
        let account = Account::new("acme", "Acme");
        let cfg = sample_config();
        let conn = SsoConnection::new(account.id, cfg.clone());
        assert_eq!(conn.account_id, account.id);
        assert_eq!(conn.config.client_id, cfg.client_id);
    }
}
