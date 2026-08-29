//! gRPC E2E: spin up the LicenseService on an ephemeral port, exercise the
//! hot-path RPCs (Validate, ValidateKey, Activate, Ping, CheckIn, CheckOut).
//! Machine-lifecycle RPCs require `authorization: Bearer <token>` metadata
//! (SEC-002); validate/validate-key stay callable anonymously.

use license_db::{Pool, SqliteRepository};
use license_domain::repository::Repository;
use license_domain::{Policy, PolicyScheme};
use license_grpc::proto::license_service_client::LicenseServiceClient;
use license_grpc::proto::{
    ActivateRequest, CheckInRequest, CheckOutRequest, PingRequest, ValidateKeyRequest,
    ValidateRequest,
};
use license_grpc::LicenseService;
use std::sync::Arc;
use tonic::transport::Server;

async fn fresh_repo() -> Arc<dyn Repository> {
    let pool = Pool::sqlite_in_memory().await.unwrap();
    Arc::new(SqliteRepository::from(pool))
}

/// Bind an ephemeral port, serve the LicenseService on it, return a connected
/// client + the server task handle.
async fn start_server_clean(
    repo: Arc<dyn Repository>,
) -> (
    LicenseServiceClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = LicenseService::new(repo, Arc::new([0x42u8; 32]));
    let server = Server::builder()
        .add_service(license_grpc::proto::license_service_server::LicenseServiceServer::new(svc));
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        let _ = server.serve_with_incoming(incoming).await;
    });
    let client = LicenseServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    (client, handle)
}

/// Wrap a request message with `authorization: Bearer <token>` metadata.
fn authed<T>(msg: T, token: &str) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

async fn seed(
    repo: &Arc<dyn Repository>,
) -> (
    license_domain::AccountId,
    license_domain::LicenseId,
    String,
    String,
) {
    let account = license_domain::Account::new("grpc-co", "gRPCCo");
    repo.accounts().create(&account).await.unwrap();
    let product = license_domain::Product::new(account.id, "P");
    repo.products().create(&product).await.unwrap();
    let policy = Policy::new(account.id, product.id, "pol", PolicyScheme::Ed25519Sign);
    repo.policies().create(&policy).await.unwrap();
    // Sign a key so we can validate-by-key.
    let keypair = license_crypto::KeyPair::generate(license_crypto::KeyAlgorithm::Ed25519).unwrap();
    let signed = license_crypto::sign_license_key(
        license_crypto::KeyScheme::Ed25519,
        &keypair,
        "seed-lic",
        &account.id.to_string(),
    )
    .unwrap();
    let mut license = license_domain::License::new(account.id, product.id, policy.id);
    license.key_hash = signed.key_hash.clone();
    license.key = Some(signed.key.clone());
    repo.licenses().create(&license).await.unwrap();

    // Mint an admin token — machine-lifecycle RPCs require it (SEC-002).
    let gen = license_crypto::generate_token(license_crypto::TokenPrefix::Admin);
    let mut token = license_domain::Token::new(
        account.id,
        license_domain::TokenKind::Admin,
        gen.hash.clone(),
    );
    token.name = Some("e2e admin".into());
    repo.tokens().create(&token).await.unwrap();

    (account.id, license.id, signed.key, gen.plaintext)
}

#[tokio::test]
async fn validate_returns_valid() {
    let repo = fresh_repo().await;
    let (aid, lid, _key, _tok) = seed(&repo).await;
    let (mut client, _h) = start_server_clean(repo).await;

    let resp = client
        .validate(ValidateRequest {
            account_id: aid.to_string(),
            license_id: lid.to_string(),
            fingerprint: String::new(),
        })
        .await
        .expect("validate rpc");
    let v = resp.into_inner();
    assert!(v.valid, "should be valid: {}", v.detail);
    assert_eq!(v.state, "active");
    assert!(v.license.is_some());
    assert_eq!(v.license.unwrap().id, lid.to_string());
}

#[tokio::test]
async fn validate_key_resolves_by_raw_key() {
    let repo = fresh_repo().await;
    let (_aid, _lid, key, _tok) = seed(&repo).await;
    let (mut client, _h) = start_server_clean(repo).await;

    let resp = client
        .validate_key(ValidateKeyRequest { key })
        .await
        .expect("validate_key rpc");
    let v = resp.into_inner();
    assert!(v.valid);
}

#[tokio::test]
async fn validate_unknown_license_is_not_found() {
    let repo = fresh_repo().await;
    let (mut client, _h) = start_server_clean(repo).await;
    let bogus = uuid::Uuid::now_v7().to_string();
    let res = client
        .validate(ValidateRequest {
            account_id: bogus.clone(),
            license_id: bogus,
            fingerprint: String::new(),
        })
        .await;
    assert!(res.is_err(), "unknown license must error");
    let status = res.err().unwrap();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn activate_without_token_is_unauthenticated() {
    let repo = fresh_repo().await;
    let (aid, lid, _key, _tok) = seed(&repo).await;
    let (mut client, _h) = start_server_clean(repo).await;

    let res = client
        .activate(ActivateRequest {
            account_id: aid.to_string(),
            license_id: lid.to_string(),
            fingerprint: "fp-grpc-1".into(),
            name: "mbp".into(),
            platform: "macos".into(),
            core_count: 8,
        })
        .await;
    let status = res.expect_err("unauthenticated activate must error");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn activate_and_ping_round_trip() {
    let repo = fresh_repo().await;
    let (aid, lid, _key, tok) = seed(&repo).await;
    let (mut client, _h) = start_server_clean(repo).await;

    // Activate
    let resp = client
        .activate(authed(
            ActivateRequest {
                account_id: aid.to_string(),
                license_id: lid.to_string(),
                fingerprint: "fp-grpc-1".into(),
                name: "mbp".into(),
                platform: "macos".into(),
                core_count: 8,
            },
            &tok,
        ))
        .await
        .expect("activate rpc");
    let machine = resp.into_inner();
    assert_eq!(machine.fingerprint, "fp-grpc-1");
    assert_eq!(machine.state, "active");
    let mid = machine.id.clone();

    // Ping (refresh heartbeat)
    let resp = client
        .ping(authed(
            PingRequest {
                account_id: aid.to_string(),
                machine_id: mid,
            },
            &tok,
        ))
        .await
        .expect("ping rpc");
    let p = resp.into_inner();
    assert!(p.alive);
}

#[tokio::test]
async fn check_in_advances_window() {
    let repo = fresh_repo().await;
    let (aid, lid, _key, tok) = seed(&repo).await;
    let (mut client, _h) = start_server_clean(repo).await;

    let resp = client
        .check_in(authed(
            CheckInRequest {
                account_id: aid.to_string(),
                license_id: lid.to_string(),
            },
            &tok,
        ))
        .await
        .expect("check_in rpc");
    let c = resp.into_inner();
    assert!(c.ok);
    assert!(!c.next_check_in.is_empty(), "next_check_in should be set");
}

#[tokio::test]
async fn check_out_streams_a_certificate() {
    let repo = fresh_repo().await;
    let (aid, lid, _key, tok) = seed(&repo).await;
    let (mut client, _h) = start_server_clean(repo).await;

    let mut stream = client
        .check_out(authed(
            CheckOutRequest {
                account_id: aid.to_string(),
                license_id: lid.to_string(),
                algorithm: "aes-256-gcm+ed25519".into(),
            },
            &tok,
        ))
        .await
        .expect("check_out rpc")
        .into_inner();

    let mut got_alg = false;
    let mut total = 0usize;
    while let Some(chunk) = stream.message().await.expect("stream ok") {
        if !chunk.algorithm.is_empty() {
            got_alg = true;
            assert_eq!(chunk.algorithm, "aes-256-gcm+ed25519");
        }
        total += chunk.data.len();
    }
    assert!(got_alg, "first chunk must carry the algorithm");
    assert!(total > 100, "expected a PEM body, got {total} bytes");
}
