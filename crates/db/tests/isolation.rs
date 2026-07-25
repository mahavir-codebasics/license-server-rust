//! Cross-tenant isolation test — the most important safety property of the
//! multi-tenant data layer.
//!
//! Creates two accounts and verifies NO repository method can read or list
//! another account's resources, even when the correct id is supplied. This is
//! the contract test that must pass for every backend (Postgres, MySQL,
//! SQLite). Backend-specific versions run via the CI matrix; this one uses
//! in-memory SQLite so it runs anywhere without Docker.

use license_db::Pool;
use license_domain::repository::Repository;
use license_domain::*;

async fn fresh_repo() -> SqliteRepository {
    let pool = Pool::sqlite_in_memory().await.expect("pool");
    SqliteRepository::from(pool)
}

// Re-exported convenience — SqliteRepository is the only impl today.
use license_db::sqlite::SqliteRepository;

fn make_account(slug: &str, name: &str) -> Account {
    Account::new(slug, name)
}

async fn seed_account_with_product(repo: &SqliteRepository, slug: &str) -> (AccountId, ProductId) {
    let account = make_account(slug, slug);
    repo.accounts().create(&account).await.unwrap();
    let product = Product::new(account.id, format!("{slug}-product"));
    repo.products().create(&product).await.unwrap();
    let pid = product.id;
    (account.id, pid)
}

#[tokio::test]
async fn cannot_get_product_from_other_account() {
    let repo = fresh_repo().await;
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
    let repo = fresh_repo().await;
    let (a1, _) = seed_account_with_product(&repo, "acme").await;
    let (a2, _) = seed_account_with_product(&repo, "globex").await;

    // add 3 more products to a1 (a1 already has 1 from seed)
    for i in 0..3 {
        let p = Product::new(a1, format!("acme-p{i}"));
        repo.products().create(&p).await.unwrap();
    }

    // globex sees ONLY its own 1 seed product — never acme's 4.
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

    // acme sees its 4 products.
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
    let repo = fresh_repo().await;
    let (a1, p1) = seed_account_with_product(&repo, "acme").await;
    let (a2, _) = seed_account_with_product(&repo, "globex").await;

    // a2 tries to delete acme's product — should be a no-op (0 rows affected),
    // and acme's product must still be readable.
    repo.products().delete(a2, p1).await.unwrap();
    assert!(repo.products().get(a1, p1).await.is_ok());
}

#[tokio::test]
async fn policy_and_license_isolation() {
    let repo = fresh_repo().await;
    let (a1, p1) = seed_account_with_product(&repo, "acme").await;
    let (a2, _p2) = seed_account_with_product(&repo, "globex").await;

    // acme policy + license
    let policy = Policy::new(a1, p1, "acme-pro", PolicyScheme::Ed25519Sign);
    repo.policies().create(&policy).await.unwrap();
    let mut license = License::new(a1, p1, policy.id);
    license.key_hash = "deadbeefacme".into();
    repo.licenses().create(&license).await.unwrap();

    // globex cannot see acme's policy
    let res = repo.policies().get(a2, policy.id).await;
    assert!(res.is_err(), "globex read acme's policy");

    // globex cannot see acme's license by id
    let res = repo.licenses().get(a2, license.id).await;
    assert!(
        matches!(&res, Err(e) if matches!(e, license_domain::DomainError::NotFound(_))),
        "globex read acme's license by id"
    );

    // license list scoped to globex returns nothing
    let page = repo
        .licenses()
        .list(a2, None, license_domain::repository::PageQuery::default())
        .await
        .unwrap();
    assert_eq!(page.data.len(), 0);

    // But get_by_key_hash works globally (the hash is globally unique; this
    // is intentional for validate-key flows, which then re-check the account).
    let found = repo
        .licenses()
        .get_by_key_hash("deadbeefacme")
        .await
        .unwrap();
    assert_eq!(found.account_id, a1);
}

#[tokio::test]
async fn machine_isolation() {
    let repo = fresh_repo().await;
    let (a1, p1) = seed_account_with_product(&repo, "acme").await;
    let (a2, _) = seed_account_with_product(&repo, "globex").await;

    let policy = Policy::new(a1, p1, "acme-pro", PolicyScheme::Ed25519Sign);
    repo.policies().create(&policy).await.unwrap();
    let mut license = License::new(a1, p1, policy.id);
    license.key_hash = "acmekey".into();
    repo.licenses().create(&license).await.unwrap();

    let machine = Machine::new(a1, license.id, "fp-acme");
    repo.machines().create(&machine).await.unwrap();

    // globex cannot read acme's machine by id
    let res = repo.machines().get(a2, machine.id).await;
    assert!(res.is_err());

    // globex cannot list acme's machines
    let page = repo
        .machines()
        .list(a2, None, license_domain::repository::PageQuery::default())
        .await
        .unwrap();
    assert_eq!(page.data.len(), 0);
}

#[tokio::test]
async fn full_license_lifecycle_persists() {
    let repo = fresh_repo().await;
    let (a1, p1) = seed_account_with_product(&repo, "acme").await;
    let policy = Policy::new(a1, p1, "acme-pro", PolicyScheme::Ed25519Sign);
    repo.policies().create(&policy).await.unwrap();

    let mut license = License::new(a1, p1, policy.id);
    license.key_hash = "lifecyclekey".into();
    license.max_uses = Some(5);
    repo.licenses().create(&license).await.unwrap();

    // reload, mutate state, persist
    let mut l = repo.licenses().get(a1, license.id).await.unwrap();
    l.suspend().unwrap();
    repo.licenses().update(&l).await.unwrap();
    let l2 = repo.licenses().get(a1, license.id).await.unwrap();
    assert_eq!(l2.state, LicenseState::Suspended);

    // expire-due sweep affects only due rows
    let now = time::OffsetDateTime::now_utc();
    let affected = repo.licenses().expire_due(now).await.unwrap();
    // nothing expired yet (no expiry set)
    assert_eq!(affected, 0);

    // set an expiry in the past, then sweep
    let mut l2 = l2;
    l2.expiry = Some(now - std::time::Duration::from_secs(60));
    l2.state = LicenseState::Active;
    repo.licenses().update(&l2).await.unwrap();
    let affected = repo.licenses().expire_due(now).await.unwrap();
    assert_eq!(affected, 1);
    let l3 = repo.licenses().get(a1, license.id).await.unwrap();
    assert_eq!(l3.state, LicenseState::Expired);
}
