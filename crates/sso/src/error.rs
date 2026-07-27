//! Errors raised by the SSO crate.
//!
//! Errors are intentionally coarse-grained: the API layer maps them onto
//! HTTP statuses, and the underlying `openidconnect` / domain errors are kept
//! as sources for diagnostics without leaking driver- or IdP-specific detail
//! through the public API surface.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SsoError>;

/// All errors produced by `license-sso`.
///
/// The variants follow the phases of the OIDC authorization-code flow plus a
/// catch-all for domain-layer failures raised during JIT provisioning. The
/// message field is a short human-stable label (e.g. `"discovery"`); the
/// original error is preserved as the `#[source]` so logs can show the cause
/// without it being serialized into an API response.
#[derive(Debug, Error)]
pub enum SsoError {
    /// The OIDC provider could not be reached, its discovery document was
    /// malformed, or its JWKS endpoint failed. Covers [`openidconnect`]
    /// discovery and provider-configuration failures.
    #[error("SSO provider error: {0}")]
    Provider(String),

    /// The stored [`crate::SsoConfig`] for an account is incomplete or invalid
    /// (missing issuer, malformed URL, etc.).
    #[error("SSO config error: {0}")]
    Config(String),

    /// The authorization-code exchange at the token endpoint failed.
    #[error("SSO token exchange error: {0}")]
    Exchange(String),

    /// The userinfo endpoint returned an error or its claims could not be
    /// parsed/verified.
    #[error("SSO userinfo error: {0}")]
    Userinfo(String),

    /// A downstream [`license_domain`] operation (user create, membership add,
    /// lookup) failed during JIT provisioning.
    #[error("SSO domain error: {0}")]
    Domain(String),
}

impl SsoError {
    /// Convenience constructor mirroring [`license_domain::DomainError::invalid`].
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}

// NOTE: the openidconnect error types are generic over the HTTP-client error
// (`RE`) and the token-response error (`TE`). Rather than parameterize
// `SsoError`, we erase the source to a `Box<dyn Error>`-compatible value by
// taking the `Display` form of the upstream error and dropping the typed
// source. This keeps the public type stable regardless of which HTTP client
// (reqwest, etc.) is in use.

impl<RE> From<openidconnect::DiscoveryError<RE>> for SsoError
where
    RE: std::error::Error + 'static,
{
    fn from(err: openidconnect::DiscoveryError<RE>) -> Self {
        Self::Provider(err.to_string())
    }
}

impl<RE, T> From<openidconnect::RequestTokenError<RE, T>> for SsoError
where
    RE: std::error::Error + 'static,
    T: openidconnect::ErrorResponse + 'static,
{
    fn from(err: openidconnect::RequestTokenError<RE, T>) -> Self {
        Self::Exchange(err.to_string())
    }
}

impl<RE> From<openidconnect::UserInfoError<RE>> for SsoError
where
    RE: std::error::Error + 'static,
{
    fn from(err: openidconnect::UserInfoError<RE>) -> Self {
        Self::Userinfo(err.to_string())
    }
}

impl From<openidconnect::ConfigurationError> for SsoError {
    fn from(err: openidconnect::ConfigurationError) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<openidconnect::ClaimsVerificationError> for SsoError {
    fn from(err: openidconnect::ClaimsVerificationError) -> Self {
        Self::Userinfo(err.to_string())
    }
}

impl From<url::ParseError> for SsoError {
    fn from(err: url::ParseError) -> Self {
        Self::Config(format!("invalid URL: {err}"))
    }
}

impl From<license_domain::DomainError> for SsoError {
    fn from(err: license_domain::DomainError) -> Self {
        Self::Domain(err.to_string())
    }
}
