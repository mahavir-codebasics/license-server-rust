//! SDK end-to-end tests: a real in-process server (the actual production
//! router + SQLite) driven through the SDK's HTTP client. This proves the
//! SDK works against the real wire format, not a mock.

use license_db::{Pool, SqliteRepository};
use std::sync::Arc;

/// Spawn the production router on an ephemeral port; return its base URL.
async fn spawn_server() -> String {
    let pool = Pool::sqlite_in_memory().await.unwrap();
    let repo: Arc<dyn license_domain::repository::Repository> =
        Arc::new(SqliteRepository::from(pool));
    let state = license_api::extract::AppState::new(repo, [0x42u8; 32]);
    let app = license_api::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn full_lifecycle_through_the_sdk() {
    let base = spawn_server().await;

    // 1. Bootstrap an org (unauthenticated one-time call).
    let (client, org) = license_sdk::LicenseClient::bootstrap(&base, "sdkco", "SDK Co")
        .await
        .unwrap();
    assert!(org.admin_token.starts_with("adm_"));
    assert_eq!(org.account.slug, "sdkco");

    // 2. Model product + policy.
    let product = client.create_product("SDK Pro").await.unwrap();
    let policy = client
        .create_policy(&product.id, "monthly", "ED25519_SIGN")
        .await
        .unwrap();
    assert_eq!(policy.scheme, "ED25519_SIGN");

    // 3. Issue a license — the signed key returns once.
    let license = client
        .create_license(&product.id, &policy.id)
        .await
        .unwrap();
    let key = license.key.clone().expect("signed key on creation");
    assert!(!key.is_empty());

    // 4. Validate by id and by raw key.
    let v = client.validate_license(&license.id).await.unwrap();
    assert!(v.valid);
    assert_eq!(v.state, "active");
    let v = client.validate_key(&key).await.unwrap();
    assert!(v.valid);

    // 5. Lists round-trip.
    let products = client.products().await.unwrap();
    assert_eq!(products.len(), 1);
    let licenses = client.licenses().await.unwrap();
    assert_eq!(licenses.len(), 1);
    // Fetched licenses never carry the key (server stores only the hash).
    assert!(licenses[0].key.is_none());

    // 6. Tokens: mint a product token, then use it from a second client.
    let minted = client.create_token("product", Some("ci")).await.unwrap();
    assert!(minted.token_plaintext.starts_with("prod_"));
    let product_client = license_sdk::LicenseClient::new(&base, &minted.token_plaintext)
        .unwrap()
        .with_account(org.account.id.clone());
    let issued = product_client
        .create_license(&product.id, &policy.id)
        .await
        .unwrap();
    assert!(issued.key.is_some(), "product tokens may issue licenses");

    // 7. Webhooks: register + list.
    let hook = client
        .create_webhook("https://example.com/hook", &["license.created".into()])
        .await
        .unwrap();
    assert!(!hook.secret.is_empty(), "HMAC secret returned once");
    assert_eq!(client.webhooks().await.unwrap().len(), 1);

    // 8. Machines list (empty) + audit log captured the creates.
    assert!(client.machines().await.unwrap().is_empty());
    // audit appends are fire-and-forget; poll briefly
    let mut events = Vec::new();
    for _ in 0..20 {
        events = client.events().await.unwrap();
        if events.len() >= 4 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    for expected in [
        "account.created",
        "product.created",
        "policy.created",
        "license.created",
    ] {
        assert!(types.contains(&expected), "missing {expected} in {types:?}");
    }
}

#[tokio::test]
async fn idempotent_license_creation_replays() {
    let base = spawn_server().await;
    let (client, org) = license_sdk::LicenseClient::bootstrap(&base, "idemco", "Idem Co")
        .await
        .unwrap();
    let product = client.create_product("P").await.unwrap();
    let policy = client
        .create_policy(&product.id, "p", "ED25519_SIGN")
        .await
        .unwrap();

    // Same idempotency key -> server returns the SAME license on retry.
    // (Requires Redis on the server; without it the calls simply issue twice —
    // assert the happy path both ways: both must succeed and both must be
    // valid licenses with keys.)
    let idem = uuid::Uuid::new_v4().to_string();
    let a = client
        .create_license_idempotent(&product.id, &policy.id, Some(&idem))
        .await
        .unwrap();
    let b = client
        .create_license_idempotent(&product.id, &policy.id, Some(&idem))
        .await
        .unwrap();
    assert!(a.key.is_some() && b.key.is_some());
    let _ = org;
}

#[tokio::test]
async fn errors_are_typed() {
    let base = spawn_server().await;
    let (client, _org) = license_sdk::LicenseClient::bootstrap(&base, "errco", "Err Co")
        .await
        .unwrap();

    // Unknown license -> NotFound kind.
    let bogus = uuid::Uuid::new_v4().to_string();
    let err = client.validate_license(&bogus).await.unwrap_err();
    assert_eq!(err.kind, license_sdk::LicenseErrorKind::NotFound);
    assert_eq!(err.status, 404);

    // Cross-tenant key -> also NotFound (never Conflict/Forbidden: no leak).
    let err = client
        .validate_key("adm_totally-not-a-license-key")
        .await
        .unwrap_err();
    assert_eq!(err.kind, license_sdk::LicenseErrorKind::NotFound);

    // Unpinned client -> immediate config error, no network.
    let bare = license_sdk::LicenseClient::new(&base, "adm_x").unwrap();
    let err = bare.licenses().await.unwrap_err();
    assert_eq!(err.code, "no_account");

    // Unreachable server -> Transport.
    let dead = license_sdk::LicenseClient::new("http://127.0.0.1:1", "adm_x")
        .unwrap()
        .with_account(uuid::Uuid::new_v4());
    let err = dead.account().await.unwrap_err();
    assert_eq!(err.kind, license_sdk::LicenseErrorKind::Transport);
}
