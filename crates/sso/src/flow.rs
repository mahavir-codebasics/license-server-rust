//! The OIDC authorization-code flow.
//!
//! Two phases:
//!  1. [`begin`] — builds the authorization URL + a PKCE challenge. The caller
//!     redirects the user's browser to the URL and **stashes the returned
//!     PKCE verifier** (in a short-lived cookie / cache) keyed by the state
//!     token.
//!  2. [`exchange`] — the browser comes back with `?code=…&state=…`. The
//!     caller looks up the stashed PKCE verifier by `state`, then calls this
//!     with the code + verifier. It exchanges the code for tokens at the IdP's
//!     token endpoint and fetches the userinfo, returning a normalized
//!     [`OidcUserInfo`].
//!
//! The HTTP transport is `reqwest` via `openidconnect`'s built-in async client.
//! All network errors are mapped to [`crate::SsoError`].

use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreUserInfoClaims,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::SsoConfig;
use crate::error::{Result, SsoError};

/// Normalized user identity extracted from the IdP's userinfo response.
///
/// We deliberately collapse the full OIDC claim set down to the three fields
/// the licensing server actually consumes for JIT provisioning. The raw `sub`
/// is retained so a future "link existing SSO identity" feature can key on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcUserInfo {
    /// `sub` claim — the stable, IdP-local subject identifier.
    pub subject: String,
    /// `email` claim, lowercased. Required for JIT (we look users up by it).
    pub email: String,
    /// `name` claim if the IdP returned one.
    pub name: Option<String>,
}

impl OidcUserInfo {
    /// Build normalized user info from a parsed set of OIDC userinfo claims.
    ///
    /// `email` is required: a sign-in without an email cannot be JIT-provisioned
    /// (we key users by email). Returns [`SsoError::Userinfo`] otherwise.
    pub fn from_claims(claims: &CoreUserInfoClaims) -> Result<Self> {
        let email = claims
            .email()
            .map(|e| e.as_str().to_lowercase())
            .ok_or_else(|| {
                SsoError::Userinfo(
                    "OIDC userinfo response is missing the `email` claim".to_string(),
                )
            })?;

        if email.trim().is_empty() {
            return Err(SsoError::Userinfo(
                "OIDC userinfo `email` claim is empty".to_string(),
            ));
        }

        // `name` may be localized; prefer the non-localized entry, then fall
        // back to the first localized variant if that's all the IdP sent.
        let name = claims.name().and_then(|localized| {
            localized
                .get(None)
                .or_else(|| localized.iter().next().map(|(_, v)| v))
                .map(|n| n.as_str().to_string())
                .filter(|s| !s.trim().is_empty())
        });

        Ok(Self {
            subject: claims.subject().as_str().to_string(),
            email,
            name,
        })
    }
}

/// The result of [`begin`]: the URL to send the user to, plus the PKCE verifier
/// the caller must persist (alongside the state token) to complete the callback.
#[derive(Debug)]
pub struct AuthorizationRequest {
    /// The fully-formed authorization URL the browser should be redirected to.
    pub url: Url,
    /// The opaque `state` token embedded in `url`. The caller echoes this back
    /// on the callback to correlate request ↔ response.
    pub state: CsrfToken,
    /// The PKCE code verifier. **Must** be passed to [`exchange`]. Treat as a
    /// secret: keep it only as long as the in-flight authorization.
    pub pkce_verifier: PkceCodeVerifier,
}

/// Begin the authorization-code flow.
///
/// Performs OIDC discovery against `config.issuer_url` (so the IdP must be
/// reachable), builds a PKCE-protected authorization URL with the configured
/// scopes, and returns everything the caller needs to redirect the user and
/// later complete the callback.
///
/// `state_token` is supplied by the caller (typically a random opaque value
/// tied to a browser cookie) so the caller controls CSRF correlation. It is
/// embedded in the returned URL's `state` query param.
pub async fn begin(config: &SsoConfig, state_token: String) -> Result<AuthorizationRequest> {
    let client = build_client(config).await?;

    // PKCE: S256 challenge + verifier. The verifier is returned to the caller
    // and must be supplied verbatim to `exchange`.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // We use the caller-supplied state token for CSRF correlation; the nonce
    // is generated freshly here (we don't strictly need it for the userinfo
    // flow, but `authorize_url` requires a nonce producer and including one is
    // best practice).
    let (url, state, _nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            // `move` because the closure must be `'static`.
            move || CsrfToken::new(state_token.clone()),
            Nonce::new_random,
        )
        // Scopes from config (always includes `openid` via the client default).
        .add_scopes(config.scopes.iter().map(|s| Scope::new(s.clone())))
        .set_pkce_challenge(pkce_challenge)
        .url();

    Ok(AuthorizationRequest {
        url,
        state,
        pkce_verifier,
    })
}

/// Complete the authorization-code flow: exchange the code for tokens and
/// fetch the userinfo.
///
/// `pkce_verifier` is the value returned by [`begin`] (looked up by `state` on
/// the callback). `code` is the `code` query param from the IdP's redirect.
pub async fn exchange(
    config: &SsoConfig,
    code: String,
    pkce_verifier: PkceCodeVerifier,
) -> Result<OidcUserInfo> {
    let client = build_client(config).await?;

    // 1) Exchange the auth code for a token set.
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    // 2) Fetch userinfo using the access token. We do not constrain the
    //    expected subject here (None) — the userinfo endpoint's own `sub` is
    //    authoritative for our normalization purposes.
    let user_info: CoreUserInfoClaims = client
        .user_info(token_response.access_token().clone(), None)?
        .request_async(async_http_client)
        .await?;

    OidcUserInfo::from_claims(&user_info)
}

/// Build and configure a `CoreClient` from an [`SsoConfig`].
///
/// Performs OIDC discovery (`GET {issuer}/.well-known/openid-configuration`)
/// so the client knows the authorization, token, userinfo, and JWKS endpoints.
/// This is the only network call in `build_client`; it is invoked once per
/// `begin` and once per `exchange`. A future optimization may cache the
/// discovered metadata per (issuer, client_id) pair.
async fn build_client(config: &SsoConfig) -> Result<CoreClient> {
    if config.issuer_url.trim().is_empty() {
        return Err(SsoError::config("issuer_url is required"));
    }
    if config.client_id.trim().is_empty() {
        return Err(SsoError::config("client_id is required"));
    }
    if config.redirect_url.trim().is_empty() {
        return Err(SsoError::config("redirect_url is required"));
    }

    let issuer = IssuerUrl::new(config.issuer_url.clone())?;
    let client_id = ClientId::new(config.client_id.clone());
    let client_secret = config
        .client_secret
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| ClientSecret::new(s.clone()));
    let redirect_url = RedirectUrl::new(config.redirect_url.clone())?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client)
        // We cannot `?` here because the discovery error is generic over
        // the reqwest error type; the `From` impl in `error.rs` handles it.
        .await?;

    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, client_secret)
        .set_redirect_uri(redirect_url);

    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openidconnect::core::CoreGenderClaim;
    use openidconnect::{AdditionalClaims, UserInfoClaims};

    /// Parse a raw userinfo JSON blob into [`CoreUserInfoClaims`], the same
    /// shape `exchange` produces from a real IdP response.
    fn parse_userinfo(json: &[u8]) -> CoreUserInfoClaims {
        UserInfoClaims::<openidconnect::EmptyAdditionalClaims, CoreGenderClaim>::from_json::<
            std::convert::Infallible,
        >(json, None)
        .expect("valid userinfo JSON")
    }

    #[test]
    fn userinfo_from_claims_normalizes_email_and_subject() {
        let json = br#"{
            "sub": "google-oauth2|1234567890",
            "email": "Alice@Example.COM",
            "name": "Alice Liddell"
        }"#;
        let claims = parse_userinfo(json);
        let info = OidcUserInfo::from_claims(&claims).expect("ok");

        assert_eq!(info.subject, "google-oauth2|1234567890");
        // Email is lowercased for stable lookup.
        assert_eq!(info.email, "alice@example.com");
        assert_eq!(info.name.as_deref(), Some("Alice Liddell"));
    }

    #[test]
    fn userinfo_from_claims_without_name_is_ok() {
        let json = br#"{ "sub": "sub-1", "email": "bob@example.com" }"#;
        let claims = parse_userinfo(json);
        let info = OidcUserInfo::from_claims(&claims).expect("ok");
        assert_eq!(info.email, "bob@example.com");
        assert!(info.name.is_none());
    }

    #[test]
    fn userinfo_from_claims_missing_email_is_error() {
        let json = br#"{ "sub": "sub-1", "name": "No Email" }"#;
        let claims = parse_userinfo(json);
        let err = OidcUserInfo::from_claims(&claims).unwrap_err();
        assert!(matches!(err, SsoError::Userinfo(_)), "got {err:?}");
    }

    #[test]
    fn userinfo_from_claims_empty_email_is_error() {
        let json = br#"{ "sub": "sub-1", "email": "   " }"#;
        let claims = parse_userinfo(json);
        let err = OidcUserInfo::from_claims(&claims).unwrap_err();
        assert!(matches!(err, SsoError::Userinfo(_)), "got {err:?}");
    }

    #[test]
    fn userinfo_from_claims_treats_whitespace_only_name_as_absent() {
        let json = br#"{ "sub": "s", "email": "d@example.com", "name": "   " }"#;
        let claims = parse_userinfo(json);
        let info = OidcUserInfo::from_claims(&claims).expect("ok");
        assert!(info.name.is_none());
    }

    #[test]
    fn userinfo_serde_round_trip() {
        let info = OidcUserInfo {
            subject: "sub-1".to_string(),
            email: "alice@example.com".to_string(),
            name: Some("Alice".to_string()),
        };
        let json = serde_json::to_string(&info).expect("serialize");
        let back: OidcUserInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(info, back);
    }

    // We deliberately do NOT unit-test `begin`/`exchange` here: they require a
    // live OIDC provider (network + discovery). Those are covered by the
    // integration suite that runs against a mock IdP in staging.

    #[test]
    fn additional_claims_trait_object_compiles() {
        // Sanity guard: ensure the EmptyAdditionalClaims type we rely on still
        // implements AdditionalClaims (a breaking upstream change to the trait
        // would surface as a compile error here).
        fn _accepts<C: AdditionalClaims>() {}
        _accepts::<openidconnect::EmptyAdditionalClaims>();
    }
}
