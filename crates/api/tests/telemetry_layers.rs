//! Request telemetry layers on the REST router: panic → standard JSON error
//! envelope (500) instead of a reset socket, tracing spans per request, and
//! `x-request-id` generation + propagation on every response.

use axum::{body::Body, http::Request, routing::get, Router};
use license_api::{extract::AppState, router, with_telemetry};
use license_db::{Pool, SqliteRepository};
use std::sync::Arc;
use tower::ServiceExt;

async fn test_app() -> Router {
    let pool = Pool::sqlite_in_memory().await.unwrap();
    let repo: Arc<dyn license_domain::repository::Repository> =
        Arc::new(SqliteRepository::from(pool));
    let state = AppState::new(repo, [0x42u8; 32]);
    router(state)
}

async fn boom_app() -> Router {
    with_telemetry(Router::new().route("/boom", get(boom)))
}

async fn boom() {
    panic!("boom");
}

#[tokio::test]
async fn panic_returns_json_envelope_not_reset() {
    let res = boom_app()
        .await
        .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
        .await
        .expect("response, not connection reset");
    assert_eq!(res.status(), 500);
    let body = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("\"code\":\"internal\""),
        "{body:?}"
    );
}

#[tokio::test]
async fn responses_carry_request_id() {
    let res = test_app()
        .await
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(res.headers().contains_key("x-request-id"));
}
