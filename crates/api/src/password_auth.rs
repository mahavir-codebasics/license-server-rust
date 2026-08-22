//! Email/password signup + login for the admin console.
//!
//! Self-service flow: a signup creates the **user**, their own **account**
//! (org), an Owner membership, and mints a personal bearer token — so any
//! individual can bootstrap their own tenant and manage products/licenses
//! without an operator. Login verifies the argon2id hash and mints a fresh
//! personal token for the user's first membership.
//!
//! Passwords are hashed with argon2id (OWASP defaults); the hash never leaves
//! the users table (`User::password_hash` is `serde(skip)`). Login failures
//! return a generic 401 so the response can't be used to enumerate emails.
//! The shared rate-limit middleware (IP-keyed for anonymous calls) throttles
//! brute force on both endpoints.

use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::extract::AppState;
use crate::response::Envelope;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, Json};
use license_crypto::generate_token;
use license_domain::error::DomainError;
use license_domain::user::{AccountMembership, MembershipId, MembershipRole, User, UserStatus};
use license_domain::{Account, AccountId, Token, TokenKind};
use rand::Rng;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const MIN_PASSWORD_LEN: usize = 8;

async fn hash_password(password: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| ApiError::internal(format!("password hashing failed: {e}")))
    })
    .await
    .map_err(|e| ApiError::internal(format!("hash task panicked: {e}")))?
}

async fn verify_password(hash: String, password: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|parsed| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            })
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

fn invalid_credentials() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::UNAUTHORIZED,
        "invalid_credentials",
        "Invalid email or password",
        "check the email and password and try again",
    )
}

/// Derive a unique account slug from an email's local part. Sanitized to
/// `[a-z0-9-]`; a short random suffix is appended on collision. (The suffix
/// only disambiguates display slugs — no secret ever derives from it.)
async fn unique_slug(state: &AppState, email: &str) -> String {
    let base: String = email
        .split('@')
        .next()
        .unwrap_or("org")
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let base = base.trim_matches('-').to_string();
    let base = if base.is_empty() {
        "org".to_string()
    } else {
        base
    };

    async fn is_free(state: &AppState, slug: &str) -> bool {
        matches!(
            state.repo.accounts().get_by_slug(slug).await,
            Err(DomainError::NotFound(_))
        )
    }
    if is_free(state, &base).await {
        return base;
    }
    for _ in 0..5 {
        let candidate = format!("{}-{:04x}", base, rand::thread_rng().gen::<u16>());
        if is_free(state, &candidate).await {
            return candidate;
        }
    }
    // Vanishingly unlikely; fall back to a full random slug.
    format!("org-{:08x}", rand::thread_rng().gen::<u32>())
}

// ── Signup ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SignupBody {
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
    /// Org display name; defaults to the user's name or email local part.
    pub org_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthSession {
    pub user: User,
    pub account: Account,
    /// Plaintext personal token (admin-capable). Shown ONCE.
    pub token: String,
}

/// `POST /v1/auth/signup` — self-service tenant bootstrap: user + org +
/// Owner membership + a personal bearer token, all in one call.
pub async fn signup(
    State(state): State<AppState>,
    Json(body): Json<SignupBody>,
) -> ApiResult<Envelope<AuthSession>> {
    let email = body.email.trim().to_ascii_lowercase();
    if !email.contains('@') || email.len() < 5 {
        return Err(ApiError::bad_request("a valid email is required"));
    }
    if body.password.len() < MIN_PASSWORD_LEN {
        return Err(ApiError::bad_request(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }

    if !matches!(
        state.repo.users().get_by_email(&email).await,
        Err(DomainError::NotFound(_))
    ) {
        return Err(ApiError::conflict(
            "an account with this email already exists",
        ));
    }

    let mut user = User::new(&email, hash_password(body.password.clone()).await?);
    user.full_name = body
        .full_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let user = state.repo.users().create(&user).await?;

    let org_name = body
        .org_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| {
            user.full_name
                .clone()
                .unwrap_or_else(|| email.split('@').next().unwrap_or("My Org").to_string())
        });
    let slug = unique_slug(&state, &email).await;
    let account = state
        .repo
        .accounts()
        .create(&Account::new(slug, org_name))
        .await?;

    state
        .repo
        .users()
        .add_membership(&AccountMembership {
            id: MembershipId::now(),
            user_id: user.id,
            account_id: account.id,
            role: MembershipRole::Owner,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        })
        .await?;

    let token = mint_token(&state, account.id, "signup").await?;

    license_jobs::record(
        state.repo.clone(),
        account.id,
        "user.signed_up",
        serde_json::json!({"email": user.email, "slug": account.slug}),
    );

    Ok(Envelope::ok(AuthSession {
        user,
        account,
        token,
    }))
}

// ── Login ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginBody {
    pub email: String,
    pub password: String,
}

/// `POST /v1/auth/login` — verify the password, mint a fresh personal token
/// for the user's first membership. The plaintext token is shown ONCE.
pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> ApiResult<Envelope<AuthSession>> {
    let email = body.email.trim().to_ascii_lowercase();
    let user = match state.repo.users().get_by_email(&email).await {
        Ok(u) => u,
        Err(DomainError::NotFound(_)) => return Err(invalid_credentials()),
        Err(e) => return Err(e.into()),
    };
    if !verify_password(user.password_hash.clone(), body.password.clone()).await {
        return Err(invalid_credentials());
    }
    if user.status != UserStatus::Active {
        return Err(ApiError::forbidden("this user is suspended"));
    }

    let memberships = state.repo.users().memberships(user.id).await?;
    let account_id: AccountId = memberships
        .first()
        .ok_or_else(|| {
            ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "no_organization",
                "User has no organization",
                "this login has no organization attached; contact support",
            )
        })?
        .account_id;
    let account = state.repo.accounts().get(account_id).await?;

    let token = mint_token(&state, account.id, "login").await?;

    // Record last login (best-effort shape: reuse the entity update).
    let mut logged_in = user.clone();
    logged_in.last_login_at = Some(OffsetDateTime::now_utc());
    logged_in.updated_at = OffsetDateTime::now_utc();
    let _ = state.repo.users().update(&logged_in).await;

    license_jobs::record(
        state.repo.clone(),
        account.id,
        "user.logged_in",
        serde_json::json!({"email": user.email}),
    );

    Ok(Envelope::ok(AuthSession {
        user: logged_in,
        account,
        token,
    }))
}

/// Mint + persist a personal (admin-capable) bearer token for an account.
async fn mint_token(
    state: &AppState,
    account_id: AccountId,
    name: &str,
) -> Result<String, ApiError> {
    let gen = generate_token(auth::prefix_for(TokenKind::Personal));
    let mut token = Token::new(account_id, TokenKind::Personal, gen.hash.clone());
    token.name = Some(name.into());
    state.repo.tokens().create(&token).await?;
    Ok(gen.plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashing_does_not_block_the_runtime() {
        // 8 concurrent hashes must complete; before spawn_blocking each pinned a
        // worker for ~100ms+. Functional gate: correctness under concurrency.
        let jobs: Vec<_> = (0..8)
            .map(|i| tokio::spawn(hash_password(format!("password-{i}-long-enough"))))
            .collect();
        for j in jobs {
            assert!(j.await.unwrap().is_ok());
        }
    }
}
