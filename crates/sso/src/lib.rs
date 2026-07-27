//! `license-sso` — OIDC client + just-in-time (JIT) user provisioning.
//!
//! Enterprise customers configure an OIDC identity provider (Google, Microsoft
//! Entra ID, Okta, Auth0, …) for their account. A user clicks "Sign in with
//! SSO", is redirected to the IdP, returns to our callback, and we
//! JIT-provision them: create a [`license_domain::User`] if they don't exist,
//! link them to the configured [`license_domain::Account`] with a role, and
//! hand control back to the API layer to issue an admin token.
//!
//! # Flow
//!
//! ```text
//!  begin(config, state)  ──►  redirect browser to IdP auth URL
//!         │                        (user authenticates at the IdP)
//!         ▼
//!  IdP redirects to our callback with ?code=…&state=…
//!         │
//!         ▼
//!  exchange(config, code, pkce_verifier)  ──►  OidcUserInfo { email, subject, name }
//!         │
//!         ▼
//!  provision_or_login(repo, account_id, info, role)  ──►  User
//!         │
//!         ▼
//!  (caller issues an admin token — lives in the API layer)
//! ```
//!
//! # Crate layout
//!
//! - [`config`] — per-account [`SsoConfig`] and the in-memory [`SsoRegistry`].
//! - [`flow`] — the OIDC authorization-code flow ([`begin`], [`exchange`]).
//! - [`jit`] — JIT provisioning ([`provision_or_login`]).
//! - [`error`] — the [`SsoError`] type and `From` conversions.
//!
//! [`begin`]: flow::begin
//! [`exchange`]: flow::exchange
//! [`provision_or_login`]: jit::provision_or_login

pub mod config;
pub mod error;
pub mod flow;
pub mod jit;

// Ergonomic re-exports so callers can write `use license_sso::{begin, SsoConfig}`.
pub use config::{SsoConfig, SsoConnection, SsoRegistry, DEFAULT_SCOPES};
pub use error::{Result, SsoError};
pub use flow::{begin, exchange, AuthorizationRequest, OidcUserInfo};
pub use jit::{provision_or_login, SSO_PASSWORD_MARKER};
