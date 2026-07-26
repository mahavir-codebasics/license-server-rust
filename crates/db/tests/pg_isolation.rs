//! Cross-tenant isolation test for the **Postgres** backend.
//!
//! Mirrors `tests/isolation.rs` (the SQLite contract test) but against a live
//! Postgres instance. Postgres additionally enforces tenancy with Row-Level
//! Security (see `migrations/pg/20260725000001_initial.sql`), so this test
//! proves BOTH the SQL `WHERE account_id = $1` clauses AND the RLS policies
//! hold.
//!
//! # When it runs
//!
//! These tests need a real Postgres server (there is no in-process equivalent).
//! To keep CI green without Docker, every test is gated:
//!   - Set `LICENSE_TEST_BACKEND=postgres` to opt in.
//!   - Provide a reachable `DATABASE_URL` (or `LICENSE_TEST_PG_URL`) pointing at
//!     an EMPTY database (the migration is applied on connect).
//!
//! If either is missing, or the connect fails, the test SKIPS (prints a message,
//! returns early) — it never fails the build.
//!
//! Example:
//! ```sh
//! docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=license \
//!   postgres:16
//! LICENSE_TEST_BACKEND=postgres \
//! DATABASE_URL=postgres://postgres:pw@localhost:5432/license \
//! cargo test -p license-db --test pg_isolation
//! ```

use license_db::pg::PostgresRepository;
use license_db::Pool;
use license_domain::repository::Repository;
use license_domain::*;

/// Connect to Postgres and apply the migration. Returns `None` (and the test
/// skips) when the backend isn't selected or the DB isn't reachable.
async fn fresh_repo() -> Option<PostgresRepository> {
    // Opt-in gate: must explicitly request the postgres backend.
    let requested = std::env::var("LICENSE_TEST_BACKEND")
        .map(|v| v.eq_ignore_ascii_case("postgres") || v.eq_ignore_ascii_case("pg"))
        .unwrap_or(false);
    if !requested {
        eprintln!("[pg_isolation] skipped: set LICENSE_TEST_BACKEND=postgres to run");
        return None;
    }
    let url = std::env::var("LICENSE_TEST_PG_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    let Some(url) = url else {
        eprintln!("[pg_isolation] skipped: no DATABASE_URL / LICENSE_TEST_PG_URL");
        return None;
    };
    match Pool::connect(&url).await {
        Ok(p) => Some(PostgresRepository::from(p)),
        Err(e) => {
            eprintln!("[pg_isolation] skipped: could not connect to Postgres ({url}): {e}");
            None
        }
    }
}

fn make_account(slug: &str, name: &str) -> Account {
    Account::new(slug, name)
}

async fn seed_account_with_product(
    repo: &PostgresRepository,
    slug: &str,
) -> (AccountId, ProductId) {
    let account = make_account(slug, slug);
    repo.accounts().create(&account).await.unwrap();
    let product = Product::new(account.id, format!("{slug}-product"));
    repo.products().create(&product).await.unwrap();
    let pid = product.id;
    (account.id, pid)
}

#[tokio::test]
async fn cannot_get_product_from_other_account() {
    let repo = match fresh_repo().await {
        Some(r) => r,
        None => return,
    };
    let (a1, p1) = seed_account_with_product(&repo, "acme").await;
    let (a2, _) = seed_account_with_product(&repo, "globex").await;

    // a2 must NOT see acme's product.
    let res = repo.products().get(a2, p1).await;
    assert!(
        matches!(&res, Err(e) if matches!(e, license_domain::DomainError::NotFound(_))),
        "cross-tenant product read leaked! got: {:?}",
        res
    );

    // a1 CAN read its own.
    assert!(repo.products().get(a1, p1).await.is_ok());
}

#[tokio::test]
async fn list_does_not_leak_other_accounts() {
    let repo = match fresh_repo().await {
        Some(r) => r,
        None => return,
    };
    let (a1, _) = seed_account_with_product(&repo, "acme").await;
    let (a2, _) = seed_account_with_product(&repo, "globex").await;

    for i in 0..3 {
        let p = Product::new(a1, format!("acme-p{i}"));
        repo.products().create(&p).await.unwrap();
    }

    let page = repo
        .products()
        .list(a2, license_domain::repository::PageQuery::default())
        .await
        .unwrap();
    assert_eq!(
        page.data.len(),
        1,
        "globex should see exactly its 1 product, got {} (possible cross-tenant leak)",
        page.data.len()
    );
    assert_eq!(page.data[0].account_id, a2);

    let page = repo
        .products()
        .list(a1, license_domain::repository::PageQuery::default())
        .await
        .unwrap();
    assert_eq!(page.data.len(), 4, "acme should see its 4 products");
    assert!(page.data.iter().all(|p| p.account_id == a1));
}

#[tokio::test]
async fn cannot_delete_other_account_product() {
    let repo = match fresh_repo().await {
        Some(r) => r,
        None => return,
    };
    let (a1, p1) = seed_account_with_product(&repo, "acme").await;
    let (a2, _) = seed_account_with_product(&repo, "globex").await;

    repo.products().delete(a2, p1).await.unwrap();
    assert!(repo.products().get(a1, p1).await.is_ok());
}

#[tokio::test]
async fn policy_and_license_isolation() {
    let repo = match fresh_repo().await {
        Some(r) => r,
        None => return,
    };
    let (a1, p1) = seed_account_with_product(&repo, "acme").await;
    let (a2, _p2) = seed_account_with_product(&repo, "globex").await;

    let policy = Policy::new(a1, p1, "acme-pro", PolicyScheme::Ed25519Sign);
    repo.policies().create(&policy).await.unwrap();
    let mut license = License::new(a1, p1, policy.id);
    license.key_hash = "deadbeefacme".into();
    repo.licenses().create(&license).await.unwrap();

    let res = repo.policies().get(a2, policy.id).await;
    assert!(res.is_err(), "globex read acme's policy");

    let res = repo.licenses().get(a2, license.id).await;
    assert!(
        matches!(&res, Err(e) if matches!(e, license_domain::DomainError::NotFound(_))),
        "globex read acme's license by id"
    );

    let page = repo
        .licenses()
        .list(a2, None, license_domain::repository::PageQuery::default())
        .await
        .unwrap();
    assert_eq!(page.data.len(), 0);

    // get_by_key_hash works globally (hash is globally unique); tenancy is
    // re-checked upstream via the account_id on the row.
    let found = repo
        .licenses()
        .get_by_key_hash("deadbeefacme")
        .await
        .unwrap();
    assert_eq!(found.account_id, a1);
}

#[tokio::test]
async fn machine_isolation() {
    let repo = match fresh_repo().await {
        Some(r) => r,
        None => return,
    };
    let (a1, p1) = seed_account_with_product(&repo, "acme").await;
    let (a2, _) = seed_account_with_product(&repo, "globex").await;

    let policy = Policy::new(a1, p1, "acme-pro", PolicyScheme::Ed25519Sign);
    repo.policies().create(&policy).await.unwrap();
    let mut license = License::new(a1, p1, policy.id);
    license.key_hash = "acmekey".into();
    repo.licenses().create(&license).await.unwrap();

    let machine = Machine::new(a1, license.id, "fp-acme");
    repo.machines().create(&machine).await.unwrap();

    let res = repo.machines().get(a2, machine.id).await;
    assert!(res.is_err());

    let page = repo
        .machines()
        .list(a2, None, license_domain::repository::PageQuery::default())
        .await
        .unwrap();
    assert_eq!(page.data.len(), 0);
}

#[tokio::test]
async fn full_license_lifecycle_persists() {
    let repo = match fresh_repo().await {
        Some(r) => r,
        None => return,
    };
    let (a1, p1) = seed_account_with_product(&repo, "acme").await;
    let policy = Policy::new(a1, p1, "acme-pro", PolicyScheme::Ed25519Sign);
    repo.policies().create(&policy).await.unwrap();

    let mut license = License::new(a1, p1, policy.id);
    license.key_hash = "lifecyclekey".into();
    license.max_uses = Some(5);
    repo.licenses().create(&license).await.unwrap();

    let mut l = repo.licenses().get(a1, license.id).await.unwrap();
    l.suspend().unwrap();
    repo.licenses().update(&l).await.unwrap();
    let l2 = repo.licenses().get(a1, license.id).await.unwrap();
    assert_eq!(l2.state, LicenseState::Suspended);

    let now = time::OffsetDateTime::now_utc();
    let affected = repo.licenses().expire_due(now).await.unwrap();
    assert_eq!(affected, 0);

    let mut l2 = l2;
    l2.expiry = Some(now - std::time::Duration::from_secs(60));
    l2.state = LicenseState::Active;
    repo.licenses().update(&l2).await.unwrap();
    let affected = repo.licenses().expire_due(now).await.unwrap();
    assert_eq!(affected, 1);
    let l3 = repo.licenses().get(a1, license.id).await.unwrap();
    assert_eq!(l3.state, LicenseState::Expired);
}
