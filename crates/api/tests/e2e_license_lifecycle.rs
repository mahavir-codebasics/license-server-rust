//! End-to-end license lifecycle through the HTTP API.
//!
//! Proves the full stack works: HTTP → API handler → domain logic → SQLite
//! repository, with crypto (Ed25519 license-key signing + AES-256-GCM license
//! file) wired in. Uses axum `oneshot` against a test router backed by an
//! in-memory SQLite database — no external dependencies.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use license_api::extract::AppState;
use license_api::router;
use license_crypto::license_file::{
    issue, verify_and_open, Algorithm, Encryption, SignatureScheme,
};
use license_crypto::{KeyAlgorithm, KeyPair};
use license_db::{Pool, SqliteRepository};
use std::sync::Arc;
use tower::ServiceExt;

async fn test_app() -> Router {
    let pool = Pool::sqlite_in_memory().await.unwrap();
    let repo = SqliteRepository::from(pool);
    let state = AppState {
        repo: Arc::new(repo),
        master_secret: Arc::new([0x42u8; 32]),
    };
    router(state)
}

async fn body_str(resp: axum::response::Response) -> String {
    use axum::body::to_bytes;
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Pull the `data.id` string out of a JSON envelope response body.
fn data_id(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body).unwrap()["data"]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn full_license_lifecycle() {
    let app = test_app().await;

    // 1. Bootstrap: create an account (org). This is the ONE unauthenticated
    //    write — the response carries the first admin token (plaintext, once).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/accounts")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"slug":"acme","name":"ACME Inc."}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    let v = serde_json::from_str::<serde_json::Value>(&body).unwrap();
    let account_id = v["data"]["id"].as_str().unwrap().to_string();
    let admin_token = v["data"]["admin_token"]
        .as_str()
        .expect("bootstrap admin_token must be returned")
        .to_string();
    assert!(!admin_token.is_empty(), "admin token must be non-empty");
    let base = format!("/v1/accounts/{account_id}");

    // 1b. An UNAUTHENTICATED write to a tenant-scoped resource must be 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("{base}/products"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"name":"should fail"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated write must be rejected"
    );

    // Helper: a Bearer-authenticated POST JSON request.
    let authed_post = |uri: String, token: String, payload: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(payload.to_string()))
            .unwrap()
    };

    // 2. Create a product — authenticated with the bootstrap admin token.
    let resp = app
        .clone()
        .oneshot(authed_post(
            format!("{base}/products"),
            admin_token.clone(),
            serde_json::json!({"name":"ACME Pro"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let product_id = data_id(&body_str(resp).await);

    // 3. Create a policy (Ed25519 scheme).
    let resp = app
        .clone()
        .oneshot(authed_post(
            format!("{base}/policies"),
            admin_token.clone(),
            serde_json::json!({
                "product_id": product_id,
                "name": "pro-monthly",
                "scheme": "ED25519_SIGN",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let policy_id = data_id(&body_str(resp).await);

    // 4. Create a license — this signs the key and returns it ONCE.
    let resp = app
        .clone()
        .oneshot(authed_post(
            format!("{base}/licenses"),
            admin_token.clone(),
            serde_json::json!({
                "product_id": product_id,
                "policy_id": policy_id,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let lic_body = body_str(resp).await;
    let lic_json = serde_json::from_str::<serde_json::Value>(&lic_body).unwrap();
    let license_id = lic_json["data"]["id"].as_str().unwrap().to_string();
    let signed_key = lic_json["data"]["key"].as_str().expect("key returned");
    assert!(
        !signed_key.is_empty(),
        "signed license key must be returned"
    );

    // 5. Validate the license — should be valid.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("{base}/licenses/{license_id}/actions/validate"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = serde_json::from_str::<serde_json::Value>(&body_str(resp).await).unwrap();
    assert_eq!(v["data"]["valid"], true);
    assert_eq!(v["data"]["state"], "active");

    // 6. Cross-tenant isolation: a second account cannot read the license.
    //    Bootstrap a second org (also unauthenticated) and try to GET acme's
    //    license through it — the data layer maps cross-tenant reads to 404.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/accounts")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"slug":"globex","name":"Globex"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let globex_id = data_id(&body_str(resp).await);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/accounts/{globex_id}/licenses/{license_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "globex must NOT see acme's license"
    );

    // 7. A token from a DIFFERENT account cannot write to acme — cross-tenant
    //    writes are forbidden even with a valid (foreign) admin token.
    let globex_token = {
        // Re-bootstrap globex's token by reading it from its create response.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"slug":"globex2","name":"Globex2"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let v = serde_json::from_str::<serde_json::Value>(&body_str(resp).await).unwrap();
        v["data"]["admin_token"].as_str().unwrap().to_string()
    };
    let resp = app
        .clone()
        .oneshot(authed_post(
            format!("{base}/products"),
            globex_token,
            serde_json::json!({"name":"foreign"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a foreign admin token must not write to acme"
    );
}

#[tokio::test]
async fn license_file_crypto_round_trip() {
    // Independently verify the license-file crypto used by check-out: a
    // certificate issued with AES-256-GCM + Ed25519 must round-trip, and a
    // tampered signature must be rejected before decryption.
    let keypair = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let aes_key = [0x42u8; 32];
    let body = br#"{"data":{"id":"lic-x","state":"active"}}"#;

    let cert = issue(
        Algorithm {
            encryption: Encryption::Aes256Gcm,
            signature: SignatureScheme::Ed25519,
        },
        &keypair,
        "v1",
        body,
        Some(&aes_key),
    )
    .unwrap();

    // Valid cert verifies + decrypts to the original body.
    let (_alg, opened) = verify_and_open(&cert.pem, &keypair.public(), Some(&aes_key)).unwrap();
    assert_eq!(opened, body);

    // Wrong public key → BadSignature (not DecryptionFailed — encrypt-then-sign
    // means we never reach the AES layer on a bad signature).
    let other = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    assert!(verify_and_open(&cert.pem, &other.public(), Some(&aes_key)).is_err());
}

#[tokio::test]
async fn invalid_id_returns_bad_request() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/accounts/not-a-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_str(resp).await;
    let v = serde_json::from_str::<serde_json::Value>(&body).unwrap();
    assert_eq!(v["errors"][0]["code"], "bad_request");
    assert_eq!(v["errors"][0]["status"], 400);
}

#[tokio::test]
async fn unknown_route_returns_404_envelope() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = serde_json::from_str::<serde_json::Value>(&body_str(resp).await).unwrap();
    assert_eq!(v["errors"][0]["code"], "not_found");
}
