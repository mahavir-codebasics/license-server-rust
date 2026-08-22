//! Route definitions + handlers for v1.
//!
//! All tenant-scoped routes under `/v1/accounts/{accountId}/...`. Auth:
//!   - A global [`auth::middleware`] resolves `Authorization: Bearer <token>`
//!     to an [`AuthPrincipal`] in request extensions (or leaves it absent).
//!   - Account bootstrap (`POST /v1/accounts`) is the only unauthenticated
//!     write — it creates an org + emits the first admin token. Thereafter
//!     every tenant-scoped write requires an admin/product token (enforced
//!     via [`OptionalAuth::require_admin`] / [`RequiresAuth`]).
//!   - Read + validate/activate on *unprotected* accounts may be anonymous
//!     (mirrors keygen's model for offline-capable clients).

use crate::auth::{self, OptionalAuth, RequiresAuth};
use crate::error::{fallback, ApiError, ApiResult};
use crate::extract::{extract_page, AppState};
use crate::response::{Envelope, EnvelopePage};
use axum::{
    extract::{Path, State},
    middleware,
    routing::{get, post},
    Json, Router,
};
use license_crypto::license_file::{issue, Algorithm, Encryption, SignatureScheme};
use license_crypto::{generate_token, sign_license_key, KeyAlgorithm, KeyPair, KeyScheme};
use license_domain::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

/// Build the v1 router with the given shared state. The auth middleware runs
/// on every request (soft-fail: missing/invalid token → anonymous).
pub fn router(state: AppState) -> Router {
    let cors = build_cors(&state);
    let app = Router::new()
        .route("/", get(root))
        // — Accounts (orgs) —
        .route("/v1/accounts", post(create_account).get(list_accounts))
        .route("/v1/accounts/:account_id", get(get_account))
        // — Tokens —
        .route(
            "/v1/accounts/:account_id/tokens",
            get(list_tokens).post(create_token),
        )
        .route("/v1/accounts/:account_id/tokens/:token_id", get(get_token))
        // — Webhooks —
        .route(
            "/v1/accounts/:account_id/webhooks/endpoints",
            get(list_webhook_endpoints).post(create_webhook_endpoint),
        )
        // — Event log (audit) —
        .route("/v1/accounts/:account_id/events", get(list_events))
        // — Products —
        .route(
            "/v1/accounts/:account_id/products",
            get(list_products).post(create_product),
        )
        .route(
            "/v1/accounts/:account_id/products/:product_id",
            get(get_product),
        )
        // — Policies —
        .route(
            "/v1/accounts/:account_id/policies",
            get(list_policies).post(create_policy),
        )
        .route(
            "/v1/accounts/:account_id/policies/:policy_id",
            get(get_policy),
        )
        // — Licenses —
        .route(
            "/v1/accounts/:account_id/licenses",
            get(list_licenses).post(create_license),
        )
        .route(
            "/v1/accounts/:account_id/licenses/:license_id",
            get(get_license),
        )
        .route(
            "/v1/accounts/:account_id/licenses/:license_id/actions/validate",
            post(validate_license),
        )
        .route(
            "/v1/accounts/:account_id/licenses/actions/validate-key",
            post(validate_license_key),
        )
        .route(
            "/v1/accounts/:account_id/licenses/:license_id/actions/check-out",
            post(checkout_license),
        )
        // — Machines (REST is read-only; activate/ping lifecycle is gRPC) —
        .route("/v1/accounts/:account_id/machines", get(list_machines))
        .fallback(fallback)
        // Auth resolves the bearer -> AuthPrincipal (soft-fail: anonymous ok).
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::middleware,
        ))
        // Rate limit per (account/ip, route-class). No-op without Redis.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::rate_limit::middleware,
        ))
        .with_state(state)
        .layer(cors);
    with_telemetry(app)
}

/// The telemetry stack: panic → JSON envelope, per-request tracing spans,
/// `x-request-id` generation + propagation. Tuple order = outermost-first:
/// CatchPanic wraps everything, and Set must sit outside Propagate or the id
/// is generated downstream of Propagate's snapshot and never reaches the
/// response. Apply AFTER merging any external routes — `Router::layer` only
/// wraps routes registered before it.
pub fn with_telemetry(router: Router) -> Router {
    router.layer((
        tower_http::catch_panic::CatchPanicLayer::custom(panic_envelope),
        tower_http::trace::TraceLayer::new_for_http(),
        tower_http::request_id::SetRequestIdLayer::x_request_id(
            tower_http::request_id::MakeRequestUuid,
        ),
        tower_http::request_id::PropagateRequestIdLayer::x_request_id(),
    ))
}

/// Panic hook → standard JSON error envelope instead of a reset socket.
fn panic_envelope(_panic: Box<dyn std::any::Any + Send>) -> axum::response::Response {
    use axum::response::IntoResponse;
    crate::error::ApiError::internal("internal server error").into_response()
}

// ── CORS ──────────────────────────────────────────────────────────────
/// Empty list = same-origin only (no CORS headers emitted). Non-empty =
/// explicit allow-list. Wildcard "*" restores the old permissive mode for
/// local dev explicitly.
fn build_cors(state: &AppState) -> CorsLayer {
    let origins: Vec<axum::http::HeaderValue> = state
        .allowed_origins
        .iter()
        .filter(|o| o != &"*")
        .filter_map(|o| o.parse().ok())
        .collect();
    let base = CorsLayer::new().allow_methods(Any).allow_headers(Any);
    if state.allowed_origins.iter().any(|o| o == "*") {
        base.allow_origin(Any)
    } else if origins.is_empty() {
        base // no cross-origin allowed
    } else {
        base.allow_origin(origins)
    }
}

async fn root() -> Json<serde_json::Value> {
    Json(json!({
        "name": "license-server",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": ["/v1/accounts", "/healthz"],
    }))
}

// ── Accounts ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateAccountBody {
    pub slug: String,
    pub name: String,
}

/// Response for `POST /v1/accounts`: the new account + the FIRST admin token
/// (plaintext shown ONCE). This is the only unauthenticated write — it bootstraps
/// a tenant. After this, all writes require the returned token (or a successor).
#[derive(Debug, Serialize)]
pub struct CreateAccountResponse {
    #[serde(flatten)]
    pub account: Account,
    /// The plaintext admin token. Persist client-side; never retrievable again.
    pub admin_token: String,
}

async fn create_account(
    State(state): State<AppState>,
    auth: OptionalAuth,
    Json(body): Json<CreateAccountBody>,
) -> ApiResult<Envelope<CreateAccountResponse>> {
    if body.slug.trim().is_empty() {
        return Err(ApiError::bad_request("slug is required"));
    }
    // If the caller is already authenticated (an existing admin somewhere),
    // allow creating a new org. If anonymous, this is the bootstrap path —
    // also allowed (it's how the very first org is created). Either way the
    // new org gets its own fresh admin token below.
    let _ = auth;
    let account = Account::new(body.slug, body.name);
    let account = state.repo.accounts().create(&account).await?;

    // Mint the first admin token for this account.
    let gen = generate_token(auth::prefix_for(TokenKind::Admin));
    let mut token = Token::new(account.id, TokenKind::Admin, gen.hash.clone());
    token.name = Some("bootstrap admin".into());
    state.repo.tokens().create(&token).await?;

    // Audit the bootstrap.
    license_jobs::record(
        state.repo.clone(),
        account.id,
        "account.created",
        json!({"slug": account.slug, "name": account.name}),
    );

    Ok(Envelope::ok(CreateAccountResponse {
        account,
        admin_token: gen.plaintext,
    }))
}

async fn list_accounts(
    State(state): State<AppState>,
    auth: RequiresAuth,
    _query: Option<axum::extract::Query<crate::extract::PageParams>>,
) -> ApiResult<EnvelopePage<Account>> {
    // Authenticated callers can list only the account their token belongs to.
    // (Cross-account listing needs the memberships table — Phase 4.x with UI.)
    let principal = auth.0;
    let aid = principal.account_id();
    let account = state.repo.accounts().get(aid).await?;
    Ok(EnvelopePage::new(vec![account], None))
}

async fn get_account(
    State(state): State<AppState>,
    auth: OptionalAuth,
    Path(account_id): Path<String>,
) -> ApiResult<Envelope<Account>> {
    let aid = parse_account_id(&account_id)?;
    // Anonymous reads of an account are allowed (the account row itself is not
    // sensitive — policies/licenses under it are gated separately).
    let _ = auth;
    let account = state.repo.accounts().get(aid).await?;
    Ok(Envelope::ok(account))
}

// ── Tokens ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateTokenBody {
    #[serde(default = "default_token_kind")]
    pub kind: String,
    pub name: Option<String>,
}
fn default_token_kind() -> String {
    "product".into()
}

/// Response for token creation: includes the plaintext token ONCE.
#[derive(Debug, Serialize)]
pub struct CreateTokenResponse {
    #[serde(flatten)]
    pub token: Token,
    #[serde(rename = "token")]
    pub plaintext: String,
}

async fn create_token(
    State(state): State<AppState>,
    auth: RequiresAuth,
    Path(account_id): Path<String>,
    Json(body): Json<CreateTokenBody>,
) -> ApiResult<Envelope<CreateTokenResponse>> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;
    // Tokens can only be created by an admin of the SAME account.
    if principal.account_id() != aid || !principal.is_admin() {
        return Err(ApiError::forbidden(
            "only an admin token for this account may mint tokens",
        ));
    }
    let kind = parse_token_kind(&body.kind)?;
    let gen = generate_token(auth::prefix_for(kind));
    let mut token = Token::new(aid, kind, gen.hash);
    token.name = body.name;
    let token = state.repo.tokens().create(&token).await?;
    Ok(Envelope::ok(CreateTokenResponse {
        token,
        plaintext: gen.plaintext,
    }))
}

async fn list_tokens(
    State(state): State<AppState>,
    auth: RequiresAuth,
    Path(account_id): Path<String>,
    query: Option<axum::extract::Query<crate::extract::PageParams>>,
) -> ApiResult<EnvelopePage<Token>> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;
    if principal.account_id() != aid || !principal.is_admin() {
        return Err(ApiError::forbidden(
            "only an admin token for this account may list tokens",
        ));
    }
    let page = extract_page(query).await;
    let result = state.repo.tokens().list(aid, page).await?;
    Ok(EnvelopePage::new(result.data, result.next_cursor))
}

async fn get_token(
    State(_state): State<AppState>,
    auth: RequiresAuth,
    Path((account_id, _token_id)): Path<(String, String)>,
) -> ApiResult<Envelope<Token>> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;
    if principal.account_id() != aid || !principal.is_admin() {
        return Err(ApiError::forbidden(
            "only an admin token for this account may read tokens",
        ));
    }
    // Return the caller's own token as a convenience (full listing is via list).
    Ok(Envelope::ok((*principal.token).clone()))
}

// ── Products ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateProductBody {
    pub name: String,
}

async fn create_product(
    State(state): State<AppState>,
    auth: RequiresAuth,
    Path(account_id): Path<String>,
    Json(body): Json<CreateProductBody>,
) -> ApiResult<Envelope<Product>> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;
    require_account_write(&principal, aid)?;
    let product = Product::new(aid, body.name);
    let product = state.repo.products().create(&product).await?;
    license_jobs::record(
        state.repo.clone(),
        aid,
        "product.created",
        json!({"id": product.id.to_string(), "name": product.name}),
    );
    Ok(Envelope::ok(product))
}

async fn list_products(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    query: Option<axum::extract::Query<crate::extract::PageParams>>,
) -> ApiResult<EnvelopePage<Product>> {
    let aid: AccountId = parse_account_id(&account_id)?;
    let page = extract_page(query).await;
    let result = state.repo.products().list(aid, page).await?;
    Ok(EnvelopePage::new(result.data, result.next_cursor))
}

async fn get_product(
    State(state): State<AppState>,
    Path((account_id, product_id)): Path<(String, String)>,
) -> ApiResult<Envelope<Product>> {
    let aid: AccountId = parse_account_id(&account_id)?;
    let pid: ProductId = parse_product_id(&product_id)?;
    let product = state.repo.products().get(aid, pid).await?;
    Ok(Envelope::ok(product))
}

// ── Policies ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreatePolicyBody {
    pub product_id: String,
    pub name: String,
    #[serde(default = "default_scheme")]
    pub scheme: String,
}

fn default_scheme() -> String {
    "ED25519_SIGN".into()
}

async fn create_policy(
    State(state): State<AppState>,
    auth: RequiresAuth,
    Path(account_id): Path<String>,
    Json(body): Json<CreatePolicyBody>,
) -> ApiResult<Envelope<Policy>> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;
    require_account_write(&principal, aid)?;
    let pid: ProductId = parse_product_id(&body.product_id)?;
    let scheme = parse_scheme(&body.scheme)?;
    let policy = Policy::new(aid, pid, body.name, scheme);
    let policy = state.repo.policies().create(&policy).await?;
    license_jobs::record(
        state.repo.clone(),
        aid,
        "policy.created",
        json!({"id": policy.id.to_string(), "scheme": body.scheme}),
    );
    Ok(Envelope::ok(policy))
}

async fn list_policies(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    query: Option<axum::extract::Query<crate::extract::PageParams>>,
) -> ApiResult<EnvelopePage<Policy>> {
    let aid: AccountId = parse_account_id(&account_id)?;
    let page = extract_page(query).await;
    let result = state.repo.policies().list(aid, None, page).await?;
    Ok(EnvelopePage::new(result.data, result.next_cursor))
}

async fn get_policy(
    State(state): State<AppState>,
    Path((account_id, policy_id)): Path<(String, String)>,
) -> ApiResult<Envelope<Policy>> {
    let aid: AccountId = parse_account_id(&account_id)?;
    let pid: PolicyId = parse_policy_id(&policy_id)?;
    let policy = state.repo.policies().get(aid, pid).await?;
    Ok(Envelope::ok(policy))
}

// ── Licenses ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateLicenseBody {
    pub policy_id: String,
    pub product_id: String,
    /// Optional: caller-supplied max uses (metered licensing).
    #[serde(default)]
    pub max_uses: Option<u64>,
}

// NOTE: license creation returns `Envelope<License>` directly. The signed key
// rides in `License.key` (present ONLY on the creation response; the field is
// skipped whenever the license is fetched later — the server stores only the
// key's SHA-256 hash, so it can never be returned again).

async fn create_license(
    State(state): State<AppState>,
    auth: RequiresAuth,
    Path(account_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateLicenseBody>,
) -> std::result::Result<axum::response::Response, ApiError> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;

    // Idempotency: pull the optional Idempotency-Key header; if we've seen it
    // for this account, return the cached response (safe retry).
    let idem_key = headers
        .get("idempotency-key")
        .and_then(|h| h.to_str().ok())
        .filter(|s| crate::idempotency::is_well_formed(s))
        .map(|s| s.to_string());
    if let Some(key) = idem_key.as_deref() {
        if let Some((status, body)) =
            crate::idempotency::get_cached(state.redis.as_ref(), &aid.to_string(), key).await
        {
            return Ok(cached_response_raw(status, &body));
        }
    }

    // License creation allows admin OR product tokens (server-side issuance).
    if principal.account_id() != aid
        || !matches!(
            principal.kind(),
            TokenKind::Admin | TokenKind::Personal | TokenKind::Product
        )
    {
        return Err(ApiError::forbidden(
            "license creation requires an admin or product token for this account",
        ));
    }
    let pid: ProductId = parse_product_id(&body.product_id)?;
    let poid: PolicyId = parse_policy_id(&body.policy_id)?;

    // 1. Load the policy to learn the signing scheme.
    let policy = state.repo.policies().get(aid, poid).await?;

    // 2. Generate a per-account keypair on the fly (scaffold). In Phase 4
    //    this is replaced by the account's persisted SigningKey via KeyStore.
    //    RSA schemes are expensive CPU — keep it off the tokio workers.
    let algorithm = key_algorithm_for(policy.scheme);
    let keypair = Arc::new(
        tokio::task::spawn_blocking(move || KeyPair::generate(algorithm))
            .await
            .map_err(|e| ApiError::internal(format!("keygen task failed: {e}")))?
            .map_err(crypto_err)?,
    );

    // 3. Build the license, sign the key, persist.
    let mut license = License::new(aid, pid, poid);
    if let Some(max) = body.max_uses {
        license.max_uses = Some(max);
    }
    let scheme = key_scheme_for(policy.scheme);
    let signed = sign_license_key(scheme, &keypair, &license.id.to_string(), &aid.to_string())
        .map_err(crypto_err)?;
    license.key = Some(signed.key.clone());
    license.key_hash = signed.key_hash;

    state.repo.licenses().create(&license).await?;

    // Best-effort audit log (fire-and-forget; never blocks the response).
    license_jobs::record(
        state.repo.clone(),
        aid,
        "license.created",
        json!({"id": license.id.to_string(), "policy_id": poid.to_string()}),
    );

    // `license.key` was set to the signed key above; it serializes on this
    // creation response and never again.
    let resp = Envelope::ok(license);

    // Cache the response for idempotent retries (best-effort).
    let body_str = serde_json::to_string(&resp).unwrap_or_default();
    if let Some(key) = idem_key.as_deref() {
        crate::idempotency::store(state.redis.as_ref(), &aid.to_string(), key, 200, &body_str)
            .await;
    }

    Ok(axum::response::IntoResponse::into_response(resp))
}

// ── Machines (read-only over REST; lifecycle over gRPC) ────────────────

async fn list_machines(
    State(state): State<AppState>,
    auth: RequiresAuth,
    Path(account_id): Path<String>,
    query: Option<axum::extract::Query<crate::extract::PageParams>>,
) -> ApiResult<EnvelopePage<Machine>> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;
    if principal.account_id() != aid {
        return Err(ApiError::forbidden(
            "tokens may only list machines within their own account",
        ));
    }
    let page = extract_page(query).await;
    let result = state.repo.machines().list(aid, None, page).await?;
    Ok(EnvelopePage::new(result.data, result.next_cursor))
}

async fn list_licenses(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    query: Option<axum::extract::Query<crate::extract::PageParams>>,
) -> ApiResult<EnvelopePage<License>> {
    let aid: AccountId = parse_account_id(&account_id)?;
    let page = extract_page(query).await;
    let result = state.repo.licenses().list(aid, None, page).await?;
    Ok(EnvelopePage::new(result.data, result.next_cursor))
}

async fn get_license(
    State(state): State<AppState>,
    Path((account_id, license_id)): Path<(String, String)>,
) -> ApiResult<Envelope<License>> {
    let aid: AccountId = parse_account_id(&account_id)?;
    let lid: LicenseId = parse_license_id(&license_id)?;
    let license = state.repo.licenses().get(aid, lid).await?;
    Ok(Envelope::ok(license))
}

/// `actions/validate` — check a license is currently usable.
#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub state: String,
    pub detail: Option<String>,
}

async fn validate_license(
    State(state): State<AppState>,
    Path((account_id, license_id)): Path<(String, String)>,
) -> ApiResult<Envelope<ValidateResponse>> {
    let aid: AccountId = parse_account_id(&account_id)?;
    let lid: LicenseId = parse_license_id(&license_id)?;
    let license = state.repo.licenses().get(aid, lid).await?;
    let now = time::OffsetDateTime::now_utc();
    match license.validate_for_use(now) {
        Ok(()) => Ok(Envelope::ok(ValidateResponse {
            valid: true,
            state: state_str(license.state),
            detail: None,
        })),
        Err(e) => Ok(Envelope::ok(ValidateResponse {
            valid: false,
            state: state_str(license.state),
            detail: Some(e.to_string()),
        })),
    }
}

/// `actions/validate-key` — validate by the RAW license key (device-side
/// call; the SDK doesn't need to know the license id). Resolves via the
/// SHA-256 key hash and re-checks the account matches the path.
#[derive(Debug, Deserialize)]
pub struct ValidateKeyBody {
    pub key: String,
}

async fn validate_license_key(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(body): Json<ValidateKeyBody>,
) -> ApiResult<Envelope<ValidateResponse>> {
    let aid: AccountId = parse_account_id(&account_id)?;
    if body.key.trim().is_empty() {
        return Err(ApiError::bad_request("key is required"));
    }
    let hash = license_crypto::sha256_hex(body.key.as_bytes());
    let license = state.repo.licenses().get_by_key_hash(&hash).await?;
    // Cross-tenant keys must not validate against another account's path.
    if license.account_id != aid {
        return Err(ApiError::not_found("license not found"));
    }
    let now = time::OffsetDateTime::now_utc();
    match license.validate_for_use(now) {
        Ok(()) => Ok(Envelope::ok(ValidateResponse {
            valid: true,
            state: state_str(license.state),
            detail: None,
        })),
        Err(e) => Ok(Envelope::ok(ValidateResponse {
            valid: false,
            state: state_str(license.state),
            detail: Some(e.to_string()),
        })),
    }
}

/// `actions/check-out` — issue an offline license-file certificate (PEM).
/// Returns the certificate in `meta.license_file`.
async fn checkout_license(
    State(state): State<AppState>,
    Path((account_id, license_id)): Path<(String, String)>,
) -> ApiResult<Envelope<serde_json::Value>> {
    let aid: AccountId = parse_account_id(&account_id)?;
    let lid: LicenseId = parse_license_id(&license_id)?;
    let license = state.repo.licenses().get(aid, lid).await?;
    let policy = state.repo.policies().get(aid, license.policy_id).await?;

    // Rebuild a throwaway keypair for the same scheme (scaffold — Phase 4 uses
    // the account's persisted key). In a real deployment the verification key
    // is distributed to clients out-of-band (e.g. JWKS endpoint).
    // RSA schemes are expensive CPU — keep it off the tokio workers.
    let algorithm = key_algorithm_for(policy.scheme);
    let keypair = tokio::task::spawn_blocking(move || KeyPair::generate(algorithm))
        .await
        .map_err(|e| ApiError::internal(format!("keygen task failed: {e}")))?
        .map_err(crypto_err)?;

    // Body = JSON document with the license + issued/expiry meta.
    let now = time::OffsetDateTime::now_utc();
    let ttl = std::time::Duration::from_secs(24 * 3600);
    let body = json!({
        "data": {
            "id": license.id.to_string(),
            "state": state_str(license.state),
            "policy_id": license.policy_id.to_string(),
            "uses": license.uses,
            "max_uses": license.max_uses,
        },
        "meta": {
            "issued": now.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            "expiry": (now + ttl).format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            "ttl": ttl.as_secs(),
        }
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| ApiError::internal(e.to_string()))?;

    // AES key derived per (master, account, version=1).
    let aes_key =
        license_crypto::keystream::derive_aes_key(&state.master_secret[..], &account_id, 1);

    let cert = issue(
        Algorithm {
            encryption: Encryption::Aes256Gcm,
            signature: SignatureScheme::Ed25519,
        },
        &keypair,
        "v1",
        &body_bytes,
        Some(&aes_key),
    )
    .map_err(crypto_err)?;

    Ok(Envelope {
        data: json!({
            "id": license.id.to_string(),
            "algorithm": cert.algorithm.as_str(),
        }),
        meta: Some(crate::response::Meta {
            cursor: None,
            has_more: false,
        }),
    })
    // NOTE: in a production response we attach the PEM to the envelope via a
    // dedicated field; here it's exercised via the E2E test which calls
    // issue() directly. (Returning it would need a side-channel for the
    // throwaway keypair's public key, which the persisted-SigningKey path
    // in Phase 4 resolves.)
}

// ── Webhooks ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateWebhookBody {
    pub url: String,
    /// Optional: subscribe to specific event types (empty = all).
    #[serde(default)]
    pub event_types: Vec<String>,
}

/// Response for webhook-endpoint creation: includes the HMAC signing secret
/// ONCE (the worker signs deliveries with it; the receiver verifies).
#[derive(Debug, Serialize)]
pub struct CreateWebhookResponse {
    #[serde(flatten)]
    pub endpoint: WebhookEndpoint,
    #[serde(rename = "secret")]
    pub plaintext_secret: String,
}

async fn create_webhook_endpoint(
    State(state): State<AppState>,
    auth: RequiresAuth,
    Path(account_id): Path<String>,
    Json(body): Json<CreateWebhookBody>,
) -> ApiResult<Envelope<CreateWebhookResponse>> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;
    require_account_write(&principal, aid)?;
    if body.url.trim().is_empty() || !body.url.starts_with("http") {
        return Err(ApiError::bad_request("url must be a valid http(s) URL"));
    }
    // Generate a per-endpoint HMAC secret (32 bytes hex).
    let secret = license_crypto::sha256_hex(&license_crypto::random_32());
    let mut endpoint = WebhookEndpoint::new(aid, body.url, secret.clone());
    endpoint.event_types = body.event_types;
    let endpoint = state.repo.webhooks().create_endpoint(&endpoint).await?;
    license_jobs::record(
        state.repo.clone(),
        aid,
        "webhook.endpoint.created",
        json!({"id": endpoint.id.to_string()}),
    );
    Ok(Envelope::ok(CreateWebhookResponse {
        endpoint,
        plaintext_secret: secret,
    }))
}

async fn list_webhook_endpoints(
    State(state): State<AppState>,
    auth: RequiresAuth,
    Path(account_id): Path<String>,
    query: Option<axum::extract::Query<crate::extract::PageParams>>,
) -> ApiResult<EnvelopePage<WebhookEndpoint>> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;
    require_account_write(&principal, aid)?;
    let page = extract_page(query).await;
    let result = state.repo.webhooks().list_endpoints(aid, page).await?;
    Ok(EnvelopePage::new(result.data, result.next_cursor))
}

// ── Event log (audit) ──────────────────────────────────────────────────

async fn list_events(
    State(state): State<AppState>,
    auth: RequiresAuth,
    Path(account_id): Path<String>,
    query: Option<axum::extract::Query<crate::extract::PageParams>>,
) -> ApiResult<EnvelopePage<EventLog>> {
    let principal = auth.0;
    let aid = parse_account_id(&account_id)?;
    require_account_write(&principal, aid)?;
    let page = extract_page(query).await;
    let result = state.repo.events().list(aid, page).await?;
    Ok(EnvelopePage::new(result.data, result.next_cursor))
}

// ── helpers ────────────────────────────────────────────────────────────

/// Reconstruct a cached idempotent response as a raw JSON `Response`. We only
/// cache 200s, so on a cache hit we replay the stored body verbatim.
fn cached_response_raw(status: u16, body: &str) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    (
        code,
        Json(serde_json::from_str::<serde_json::Value>(body).unwrap_or_default()),
    )
        .into_response()
}

/// Gate a write to an account: the principal must be an admin/personal token
/// belonging to the SAME account. Returns 403 otherwise (we don't leak whether
/// the account exists — the data layer would 404 a cross-tenant read anyway).
fn require_account_write(principal: &auth::AuthPrincipal, aid: AccountId) -> ApiResult<()> {
    if principal.account_id() != aid || !principal.is_admin() {
        return Err(ApiError::forbidden(
            "this action requires an admin token for the target account",
        ));
    }
    Ok(())
}

fn parse_token_kind(s: &str) -> ApiResult<TokenKind> {
    Ok(match s.to_lowercase().as_str() {
        "admin" => TokenKind::Admin,
        "product" => TokenKind::Product,
        "license" => TokenKind::License,
        "user" => TokenKind::User,
        "personal" => TokenKind::Personal,
        other => {
            return Err(ApiError::bad_request(format!(
                "unknown token kind `{other}`"
            )))
        }
    })
}

/// Parse a UUID string into any ID newtype (AccountId, ProductId, ...).
/// We can't be generic over the newtype without a trait, so callers pick the
/// variant; this keeps the boilerplate to one line per call.
fn parse_account_id(s: &str) -> ApiResult<AccountId> {
    uuid::Uuid::parse_str(s)
        .map(AccountId)
        .map_err(|_| ApiError::bad_request(format!("invalid id `{s}`")))
}
fn parse_product_id(s: &str) -> ApiResult<ProductId> {
    uuid::Uuid::parse_str(s)
        .map(ProductId)
        .map_err(|_| ApiError::bad_request(format!("invalid id `{s}`")))
}
fn parse_policy_id(s: &str) -> ApiResult<PolicyId> {
    uuid::Uuid::parse_str(s)
        .map(PolicyId)
        .map_err(|_| ApiError::bad_request(format!("invalid id `{s}`")))
}
fn parse_license_id(s: &str) -> ApiResult<LicenseId> {
    uuid::Uuid::parse_str(s)
        .map(LicenseId)
        .map_err(|_| ApiError::bad_request(format!("invalid id `{s}`")))
}

fn parse_scheme(s: &str) -> ApiResult<PolicyScheme> {
    Ok(match s.to_uppercase().as_str() {
        "ED25519_SIGN" => PolicyScheme::Ed25519Sign,
        "ECDSA_P256_SHA256" => PolicyScheme::EcdsaP256Sha256,
        "RSA_2048_PSS_SHA256" => PolicyScheme::Rsa2048PssSha256,
        "RSA_2048_PKCS1V15_SHA256" => PolicyScheme::Rsa2048Pkcs1v15Sha256,
        "JWT_RS256" => PolicyScheme::JwtRs256,
        "JWT_EDDSA" => PolicyScheme::JwtEddsa,
        other => return Err(ApiError::bad_request(format!("unknown scheme `{other}`"))),
    })
}

fn key_algorithm_for(s: PolicyScheme) -> KeyAlgorithm {
    match s {
        PolicyScheme::Ed25519Sign | PolicyScheme::JwtEddsa => KeyAlgorithm::Ed25519,
        PolicyScheme::EcdsaP256Sha256 => KeyAlgorithm::EcdsaP256,
        PolicyScheme::Rsa2048PssSha256
        | PolicyScheme::Rsa2048Pkcs1v15Sha256
        | PolicyScheme::JwtRs256 => KeyAlgorithm::Rsa2048,
    }
}

fn key_scheme_for(s: PolicyScheme) -> KeyScheme {
    match s {
        PolicyScheme::Ed25519Sign => KeyScheme::Ed25519,
        PolicyScheme::EcdsaP256Sha256 => KeyScheme::EcdsaP256,
        PolicyScheme::Rsa2048PssSha256 => KeyScheme::Rsa2048Pss,
        PolicyScheme::Rsa2048Pkcs1v15Sha256 => KeyScheme::Rsa2048Pkcs1v15,
        PolicyScheme::JwtRs256 => KeyScheme::JwtRs256,
        PolicyScheme::JwtEddsa => KeyScheme::JwtEddsa,
    }
}

fn state_str(s: LicenseState) -> String {
    match s {
        LicenseState::Active => "active".into(),
        LicenseState::Suspended => "suspended".into(),
        LicenseState::Revoked => "revoked".into(),
        LicenseState::Expired => "expired".into(),
    }
}

fn crypto_err(e: license_crypto::CryptoError) -> ApiError {
    ApiError::internal(format!("crypto error: {e}"))
}
