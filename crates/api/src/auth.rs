//! Bearer-token authentication.
//!
//! Design:
//!   - The `AuthorizationMiddleware` runs on every request, extracts the
//!     `Authorization: Bearer <token>` header, hashes it, looks the token up,
//!     and stashes an [`AuthPrincipal`] in request extensions.
//!   - Handlers declare [`RequiresAuth`] to get the resolved principal; routes
//!     can require a specific kind (`Admin`/`Product`/...) via [`Auth::require`].
//!   - Account bootstrap is special: `POST /v1/accounts` is the ONLY
//!     unauthenticated write (it creates an org + its first admin token),
//!     guarded by a setup secret in config. After bootstrap, every other
//!     tenant-scoped write requires an admin/product token.
//!
//! Tokens are stored as SHA-256 hashes (see `license_crypto::token`); the
//! plaintext is never persisted. Expired tokens are rejected. Last-used is
//! updated best-effort (non-blocking).

use crate::error::ApiError;
use crate::extract::AppState;
use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use license_crypto::{hash_token, TokenPrefix};
use license_domain::{AccountId, Token, TokenKind};
use std::sync::Arc;
use time::OffsetDateTime;

/// The resolved identity behind a request. `None` for unauthenticated calls
/// (allowed only on unprotected accounts for client-side validate/activate).
#[derive(Debug, Clone)]
pub struct AuthPrincipal {
    pub token: Arc<Token>,
}

impl AuthPrincipal {
    pub fn account_id(&self) -> AccountId {
        self.token.account_id
    }
    pub fn kind(&self) -> TokenKind {
        self.token.kind
    }
    /// True if this principal can do account-admin work (admin/personal).
    pub fn is_admin(&self) -> bool {
        matches!(self.token.kind, TokenKind::Admin | TokenKind::Personal)
    }
}

/// Extractor: handlers that need the authenticated principal. Returns 401 if
/// absent (use [`OptionalAuth`] for endpoints that allow anonymous calls).
#[derive(Debug, Clone)]
pub struct RequiresAuth(pub AuthPrincipal);

#[axum::async_trait]
impl axum::extract::FromRequestParts<AppState> for RequiresAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthPrincipal>() {
            Some(p) => Ok(Self(p.clone())),
            None => {
                // Maybe there was a bearer that failed to resolve — surface a
                // more specific error if so.
                let hdr = parts
                    .headers
                    .get(AUTHORIZATION)
                    .and_then(|h| h.to_str().ok());
                if hdr.is_some() {
                    Err(ApiError::new(
                        axum::http::StatusCode::UNAUTHORIZED,
                        "token_invalid",
                        "Invalid token",
                        "the provided bearer token is invalid or expired",
                    ))
                } else {
                    Err(ApiError::unauthorized())
                }
            }
        }
    }
}

/// Extractor for endpoints that MAY be anonymous (validate/activate on
/// unprotected accounts). Use [`OptionalAuth::require_admin`] to gate writes.
#[derive(Debug, Clone, Default)]
pub struct OptionalAuth(pub Option<AuthPrincipal>);

impl OptionalAuth {
    /// Require an admin-or-better principal; 403 otherwise.
    pub fn require_admin(&self) -> Result<&AuthPrincipal, ApiError> {
        match &self.0 {
            Some(p) if p.is_admin() => Ok(p),
            Some(_) => Err(ApiError::forbidden("this action requires an admin token")),
            None => Err(ApiError::unauthorized()),
        }
    }

    /// Require any authenticated principal; 401 otherwise.
    pub fn require_any(&self) -> Result<&AuthPrincipal, ApiError> {
        self.0.as_ref().ok_or_else(ApiError::unauthorized)
    }
}

#[axum::async_trait]
impl axum::extract::FromRequestParts<AppState> for OptionalAuth {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(OptionalAuth(
            parts.extensions.get::<AuthPrincipal>().cloned(),
        ))
    }
}

/// Axum middleware: resolve the bearer (if any) to an AuthPrincipal.
///
/// Soft-fail: missing/invalid token → request proceeds anonymous. Handlers
/// enforce via `RequiresAuth` / `OptionalAuth::require_*`.
pub async fn middleware(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    // Extract the bearer token from headers BEFORE any .await: `Body` is
    // `Send` but not `Sync`, so `&Request<Body>` is not `Send` and cannot be
    // held across an await point. Pulling the owned `Option<String>` out first
    // keeps the resolver's future `Send`.
    let bearer = extract_bearer(&req);
    if let Some(principal) = resolve(&state, bearer).await {
        req.extensions_mut().insert(principal);
    }
    next.run(req).await
}

/// Synchronously pull the bearer string out of `Authorization: Bearer <tok>`.
/// Returns `None` for missing/malformed headers (caller proceeds anonymous).
fn extract_bearer(req: &Request) -> Option<String> {
    let auth = req.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let bearer = auth.strip_prefix("Bearer ")?.trim();
    // Reject malformed tokens early (propagate None via `?`).
    let _ = license_crypto::token::is_well_formed(bearer)?;
    Some(bearer.to_owned())
}

/// Resolve a bearer token (already extracted from the request) to a principal.
/// `bearer` is `None` when no well-formed `Authorization: Bearer ...` header
/// was present; the caller then proceeds anonymous. Note this takes an owned
/// `Option<String>` (not `&Request`) so the returned future stays `Send` —
/// `Body` is `Send` but not `Sync`, so `&Request<Body>` is not `Send` and
/// cannot be captured across the `.await` below.
async fn resolve(state: &AppState, bearer: Option<String>) -> Option<AuthPrincipal> {
    let bearer = bearer?;
    let h = hash_token(&bearer);
    let token = state.repo.tokens().get_by_hash(&h).await.ok()?;
    // Reject expired tokens.
    if let Some(exp) = token.expiry {
        if OffsetDateTime::now_utc() >= exp {
            return None;
        }
    }
    // Best-effort touch of last_used_at — don't block on it.
    let tok_id = token.id;
    let repo = state.repo.clone();
    tokio::spawn(async move {
        let _ = repo
            .tokens()
            .touch_last_used(tok_id, OffsetDateTime::now_utc())
            .await;
    });

    Some(AuthPrincipal {
        token: Arc::new(token),
    })
}

/// Convenience: the kind prefix to emit when generating a token of `kind`.
pub fn prefix_for(kind: TokenKind) -> TokenPrefix {
    match kind {
        TokenKind::Admin => TokenPrefix::Admin,
        TokenKind::Product => TokenPrefix::Product,
        TokenKind::License => TokenPrefix::License,
        TokenKind::User => TokenPrefix::User,
        TokenKind::Personal => TokenPrefix::Personal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_mapping_is_bijective() {
        for k in [
            TokenKind::Admin,
            TokenKind::Product,
            TokenKind::License,
            TokenKind::User,
            TokenKind::Personal,
        ] {
            let p = prefix_for(k);
            // round-trip via the crypto module's well_formed check
            let t = license_crypto::generate_token(p);
            assert_eq!(license_crypto::token::is_well_formed(&t.plaintext), Some(p));
        }
    }
}
