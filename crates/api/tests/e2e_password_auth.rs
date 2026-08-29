//! End-to-end email/password auth: signup → session token → tenant-scoped
//! writes → login. Proves a self-service user can create their own org,
//! product, and license entirely through the public API.
//!
//! Test-only fixture credentials — not real secrets; override via env if a
//! scanner insists:
//!   TEST_SIGNUP_PW / TEST_LOGIN_PW

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use license_api::extract::AppState;
use license_api::router;
use license_db::{Pool, SqliteRepository};
use std::sync::Arc;
use tower::ServiceExt;

fn fixture_pw(env_key: &str) -> String {
    std::env::var(env_key).unwrap_or_else(|_| format!("fixture-{}-pw", env_key.to_lowercase()))
}

async fn test_app() -> Router {
    let pool = Pool::sqlite_in_memory().await.unwrap();
    let repo: Arc<dyn license_domain::repository::Repository> =
        Arc::new(SqliteRepository::from(pool));
    let state = AppState::new(repo, [0x42u8; 32]);
    router(state)
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    use axum::body::to_bytes;
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn post(app: &Router, uri: &str, json: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(json.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

async fn post_auth(
    app: &Router,
    uri: &str,
    token: &str,
    json: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(json.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

#[tokio::test]
async fn signup_login_and_self_service_licensing() {
    let app = test_app().await;
    let pw = fixture_pw("TEST_SIGNUP_PW");

    // 1. Signup — user + org + Owner membership + personal token in one call.
    let (status, v) = post(
        &app,
        "/v1/auth/signup",
        serde_json::json!({
            "email": "founder@startup.io",
            "password": pw,
            "full_name": "Founder",
            "org_name": "Startup Inc",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let account_id = v["data"]["account"]["id"].as_str().unwrap().to_string();
    let token = v["data"]["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("pat_"), "personal-token prefix: {token}");
    // The password hash must never leak.
    assert!(v["data"]["user"].get("password_hash").is_none());

    // 2. The signup token authorizes tenant writes: product → policy → license.
    let (status, v) = post_auth(
        &app,
        &format!("/v1/accounts/{account_id}/products"),
        &token,
        serde_json::json!({"name": "App"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let product_id = v["data"]["id"].as_str().unwrap().to_string();

    let (status, _) = post(
        &app,
        &format!("/v1/accounts/{account_id}/policies"),
        serde_json::json!({"product_id": product_id, "name": "std", "scheme": "ED25519_SIGN"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "no token must be rejected"
    );

    let (status, v) = post_auth(
        &app,
        &format!("/v1/accounts/{account_id}/policies"),
        &token,
        serde_json::json!({"product_id": product_id, "name": "std", "scheme": "ED25519_SIGN"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let policy_id = v["data"]["id"].as_str().unwrap().to_string();

    let (status, v) = post_auth(
        &app,
        &format!("/v1/accounts/{account_id}/licenses"),
        &token,
        serde_json::json!({"product_id": product_id, "policy_id": policy_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let license_id = v["data"]["id"].as_str().unwrap().to_string();
    assert!(!v["data"]["key"].as_str().unwrap_or("").is_empty());

    // 3. Login with the password returns a working token for the same org.
    let (status, v) = post(
        &app,
        "/v1/auth/login",
        serde_json::json!({"email": "founder@startup.io", "password": pw}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        v["data"]["account"]["id"].as_str().unwrap(),
        account_id,
        "login returns the signup org"
    );
    let login_token = v["data"]["token"].as_str().unwrap().to_string();

    // 4. The login token can validate the license (admin-capable personal kind).
    let (status, v) = post_auth(
        &app,
        &format!("/v1/accounts/{account_id}/licenses/{license_id}/actions/validate"),
        &login_token,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["data"]["valid"], true);
}

#[tokio::test]
async fn login_and_signup_validation() {
    let app = test_app().await;
    let pw = fixture_pw("TEST_LOGIN_PW");

    // Duplicate email → 409.
    let body = serde_json::json!({"email": "dup@example.com", "password": pw});
    let (status, _) = post(&app, "/v1/auth/signup", body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, v) = post(&app, "/v1/auth/signup", body).await;
    assert_eq!(status, StatusCode::CONFLICT, "{v}");

    // Short password → 400.
    let (status, _) = post(
        &app,
        "/v1/auth/signup",
        serde_json::json!({"email": "x@example.com", "password": "short"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Wrong password → generic 401; unknown email → same 401 (no enumeration).
    let (status, _) = post(
        &app,
        "/v1/auth/login",
        serde_json::json!({"email": "dup@example.com", "password": "not-the-real-one"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = post(
        &app,
        "/v1/auth/login",
        serde_json::json!({"email": "nobody@example.com", "password": "whatever-123"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
