//! PostgreSQL implementation of the [`Repository`] trait.
//!
//! Uses native types throughout: `UUID` ↔ `uuid::Uuid`, `TIMESTAMPTZ` ↔
//! `time::OffsetDateTime`, `JSONB` ↔ `serde_json::Value`, `BOOL` ↔ `bool`.
//! This is simpler than the SQLite impl — no string conversion needed.
//!
//! **Row-Level Security (RLS):** every tenant-scoped table carries an RLS policy
//! `tenant_isolation` (see `migrations/pg/20260725000001_initial.sql`). The
//! policy compares `account_id::text` to `current_setting('app.account_id', true)`,
//! which is NULL/empty unless the connection set it — fail-closed. Each repo
//! method that touches a tenant-scoped table runs inside a transaction and calls
//! [`set_account_id`] first so the RLS policy sees the right tenant. This is
//! defense-in-depth on top of the `WHERE account_id = $1` clauses every query
//! already carries. `accounts` and `users` are exempt (cross-tenant identity).

use crate::error::{map_err, not_found, Pool, PostgresConnPool};
use license_domain::error::{DomainError, Result};
use license_domain::repository::{
    AccountRepo, EntitlementRepo, EventLogRepo, LicenseRepo, MachineRepo, Page, PageQuery,
    PolicyRepo, ProductRepo, Repository, SigningKeyRepo, TokenRepo, UserRepo, WebhookRepo,
};
use license_domain::*;
use sqlx::{query::Query, Database, Row};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

// ── small shared helpers ───────────────────────────────────────────────

/// Type-anchored `sqlx::query` for Postgres.
///
/// With multiple sqlx backends enabled in one build, `query(...)` is
/// generic over `DB` and the bind chain can infer the wrong backend (the
/// `OffsetDateTime`/`Uuid`/`serde_json::Value`/`bool` binds are valid for more
/// than one backend). Anchoring `DB = Postgres` here at construction lets every
/// bind inherit the right type. The `$N` placeholders are PG-specific but
/// placeholders alone don't drive inference — the bound values do.
pub(super) fn query(
    sql: &str,
) -> Query<'_, sqlx::Postgres, <sqlx::Postgres as Database>::Arguments<'_>> {
    sqlx::query::<sqlx::Postgres>(sql)
}

/// Type-anchored `sqlx::query_as` for Postgres (same rationale as [`query`]).
pub(super) fn query_as<'q, T>(
    sql: &'q str,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, T, <sqlx::Postgres as Database>::Arguments<'q>>
where
    T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send,
{
    sqlx::query_as::<sqlx::Postgres, _>(sql)
}

/// The SQL string used to set the RLS session variable per-transaction.
/// Exposed as a constant so a unit test can assert its exact shape without a
/// live Postgres.
pub(crate) const SET_ACCOUNT_ID_SQL: &str = "SELECT set_config('app.account_id', $1, true)";

/// Set the RLS session variable for the current transaction. MUST be called
/// before any query on a tenant-scoped table. The `true` arg makes the setting
/// transaction-local (rolled back with the tx).
pub(crate) async fn set_account_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: AccountId,
) -> Result<()> {
    query(SET_ACCOUNT_ID_SQL)
        .bind(account_id.0.to_string())
        .execute(&mut **tx)
        .await
        .map_err(map_err)?;
    Ok(())
}

pub(super) fn dur_to_secs(d: Option<Duration>) -> Option<i64> {
    d.map(|x| x.as_secs() as i64)
}

pub(super) fn secs_to_dur(s: Option<i64>) -> Option<Duration> {
    s.filter(|&v| v > 0).map(|v| Duration::from_secs(v as u64))
}

pub(super) fn meta(v: serde_json::Value) -> Metadata {
    serde_json::from_value(v).unwrap_or_default()
}

pub(super) fn meta_json(m: &Metadata) -> serde_json::Value {
    serde_json::to_value(m).unwrap_or(serde_json::Value::Object(Default::default()))
}

pub(super) fn dbtype<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Internal(format!("column decode error: {e}"))
}

/// Parse the keyset cursor. The cursor is the canonical UUID string of the last
/// row on the previous page (UUIDv7 is time-ordered, so `id < cursor` walks
/// backwards chronologically).
pub(super) fn cursor_after(page: &PageQuery) -> Option<Uuid> {
    page.after.as_deref().and_then(|c| Uuid::parse_str(c).ok())
}

pub(super) fn next_cursor<T: IdStr>(data: &[T], limit: u32) -> Option<String> {
    if data.len() as u32 >= limit {
        data.last().map(|x| x.id_str())
    } else {
        None
    }
}

pub(super) trait IdStr {
    fn id_str(&self) -> String;
}

// ── the repo ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PostgresRepository {
    pub(super) pool: PostgresConnPool,
}

impl PostgresRepository {
    pub fn new(pool: PostgresConnPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PostgresConnPool {
        &self.pool
    }
}

impl From<Pool> for PostgresRepository {
    fn from(p: Pool) -> Self {
        match p {
            Pool::Postgres(p) => Self::new(p),
            Pool::Sqlite(_) | Pool::Mysql(_) => {
                panic!("PostgresRepository::from(Pool) called with a non-Postgres pool")
            }
        }
    }
}

// ── Accounts (NOT tenant-scoped — no RLS) ──────────────────────────────

#[async_trait::async_trait]
impl AccountRepo for PostgresRepository {
    async fn create(&self, account: &Account) -> Result<Account> {
        let settings = serde_json::to_value(&account.settings).unwrap_or_default();
        let md = meta_json(&account.metadata);
        query(
            "INSERT INTO accounts (id, slug, name, status, protection_mode, settings, metadata, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(account.id.0)
        .bind(&account.slug)
        .bind(&account.name)
        .bind(status_str(account.status))
        .bind(protection_str(account.protection_mode))
        .bind(&settings)
        .bind(&md)
        .bind(account.created_at)
        .bind(account.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as AccountRepo>::get(self, account.id).await
    }

    async fn get(&self, id: AccountId) -> Result<Account> {
        let row = query("SELECT * FROM accounts WHERE id = $1")
            .bind(id.0)
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
        row_to_account(&row)
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Account> {
        let row = query("SELECT * FROM accounts WHERE slug = $1")
            .bind(slug)
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
        row_to_account(&row)
    }

    async fn update(&self, account: &Account) -> Result<Account> {
        let settings = serde_json::to_value(&account.settings).unwrap_or_default();
        let md = meta_json(&account.metadata);
        query(
            "UPDATE accounts SET slug=$2, name=$3, status=$4, protection_mode=$5, settings=$6, metadata=$7, updated_at=$8 \
             WHERE id=$1",
        )
        .bind(account.id.0)
        .bind(&account.slug)
        .bind(&account.name)
        .bind(status_str(account.status))
        .bind(protection_str(account.protection_mode))
        .bind(&settings)
        .bind(&md)
        .bind(account.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as AccountRepo>::get(self, account.id).await
    }

    async fn list_for_user(&self, user_id: UserId, page: PageQuery) -> Result<Page<Account>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        // accounts are not RLS-protected; account_memberships IS tenant-scoped
        // in the sense it has account_id, but RLS isn't enabled on it (it's the
        // bridge table). We read it directly.
        let rows = query(
            "SELECT a.* FROM accounts a \
             JOIN account_memberships m ON m.account_id = a.id \
             WHERE m.user_id = $1 AND ($2 IS NULL OR a.id < $2) \
             ORDER BY a.created_at DESC, a.id DESC LIMIT $3",
        )
        .bind(user_id.0)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;

        let data: Vec<Account> = rows.iter().map(row_to_account).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        Ok(Page { data, next_cursor })
    }
}

pub(super) fn status_str(s: AccountStatus) -> &'static str {
    match s {
        AccountStatus::Active => "active",
        AccountStatus::Suspended => "suspended",
        AccountStatus::Canceled => "canceled",
    }
}

pub(super) fn protection_str(p: ProtectionMode) -> &'static str {
    match p {
        ProtectionMode::Protected => "protected",
        ProtectionMode::Unprotected => "unprotected",
    }
}

fn row_to_account(row: &sqlx::postgres::PgRow) -> Result<Account> {
    let id: Uuid = row.try_get("id").map_err(dbtype)?;
    let slug: String = row.try_get("slug").map_err(dbtype)?;
    let name: String = row.try_get("name").map_err(dbtype)?;
    let status: String = row.try_get("status").map_err(dbtype)?;
    let pm: String = row.try_get("protection_mode").map_err(dbtype)?;
    let settings: serde_json::Value = row.try_get("settings").map_err(dbtype)?;
    let md: serde_json::Value = row.try_get("metadata").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Account {
        id: AccountId(id),
        slug,
        name,
        status: match status.as_str() {
            "suspended" => AccountStatus::Suspended,
            "canceled" => AccountStatus::Canceled,
            _ => AccountStatus::Active,
        },
        protection_mode: match pm.as_str() {
            "unprotected" => ProtectionMode::Unprotected,
            _ => ProtectionMode::Protected,
        },
        settings: serde_json::from_value(settings).unwrap_or_default(),
        metadata: meta(md),
        created_at,
        updated_at,
    })
}

// ── Products (tenant-scoped — RLS) ─────────────────────────────────────

#[async_trait::async_trait]
impl ProductRepo for PostgresRepository {
    async fn create(&self, product: &Product) -> Result<Product> {
        let md = meta_json(&product.metadata);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, product.account_id).await?;
        query(
            "INSERT INTO products (id, account_id, name, url, metadata, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(product.id.0)
        .bind(product.account_id.0)
        .bind(&product.name)
        .bind(&product.url)
        .bind(&md)
        .bind(product.created_at)
        .bind(product.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as ProductRepo>::get(self, product.account_id, product.id).await
    }

    async fn get(&self, account_id: AccountId, id: ProductId) -> Result<Product> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let row = query("SELECT * FROM products WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        let res = not_found(row.map(|r| row_to_product(&r)));
        tx.commit().await.map_err(map_err)?;
        res
    }

    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<Product>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let rows = query(
            "SELECT * FROM products WHERE account_id=$1 AND ($2 IS NULL OR id < $2) \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(account_id.0)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        let data: Vec<Product> = rows.iter().map(row_to_product).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        tx.commit().await.map_err(map_err)?;
        Ok(Page { data, next_cursor })
    }

    async fn update(&self, product: &Product) -> Result<Product> {
        let md = meta_json(&product.metadata);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, product.account_id).await?;
        query(
            "UPDATE products SET name=$3, url=$4, metadata=$5, updated_at=$6 \
             WHERE account_id=$1 AND id=$2",
        )
        .bind(product.account_id.0)
        .bind(product.id.0)
        .bind(&product.name)
        .bind(&product.url)
        .bind(&md)
        .bind(product.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as ProductRepo>::get(self, product.account_id, product.id).await
    }

    async fn delete(&self, account_id: AccountId, id: ProductId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        query("DELETE FROM products WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(())
    }
}

fn row_to_product(row: &sqlx::postgres::PgRow) -> Result<Product> {
    let id: Uuid = row.try_get("id").map_err(dbtype)?;
    let aid: Uuid = row.try_get("account_id").map_err(dbtype)?;
    let name: String = row.try_get("name").map_err(dbtype)?;
    let url: Option<String> = row.try_get("url").map_err(dbtype)?;
    let md: serde_json::Value = row.try_get("metadata").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Product {
        id: ProductId(id),
        account_id: AccountId(aid),
        name,
        url,
        metadata: meta(md),
        created_at,
        updated_at,
    })
}

impl IdStr for Product {
    fn id_str(&self) -> String {
        self.id.0.to_string()
    }
}
impl IdStr for Account {
    fn id_str(&self) -> String {
        self.id.0.to_string()
    }
}
impl IdStr for Policy {
    fn id_str(&self) -> String {
        self.id.0.to_string()
    }
}

// ── Policies (tenant-scoped — RLS) ─────────────────────────────────────

#[async_trait::async_trait]
impl PolicyRepo for PostgresRepository {
    async fn create(&self, policy: &Policy) -> Result<Policy> {
        let md = meta_json(&policy.metadata);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, policy.account_id).await?;
        query(
            "INSERT INTO policies (\
               id, account_id, product_id, name, key, scheme, max_machines, floating_strategy, \
               max_components, max_processes, max_uses, max_users, max_cores, max_memory, max_disk, \
               duration_secs, heartbeat_duration_secs, require_check_in, max_overdue_check_ins, \
               require_product_scope, require_user, require_fingerprint, protected, renewable, \
               metadata, created_at, updated_at\
             ) VALUES (\
               $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27\
             )",
        )
        .bind(policy.id.0)
        .bind(policy.account_id.0)
        .bind(policy.product_id.0)
        .bind(&policy.name)
        .bind(&policy.key)
        .bind(scheme_str(policy.scheme))
        .bind(policy.max_machines.map(|v| v as i32))
        .bind(float_str(policy.floating_strategy))
        .bind(policy.max_components.map(|v| v as i32))
        .bind(policy.max_processes.map(|v| v as i32))
        .bind(policy.max_uses.map(|v| v as i64))
        .bind(policy.max_users.map(|v| v as i32))
        .bind(policy.max_cores.map(|v| v as i32))
        .bind(policy.max_memory.map(|v| v as i64))
        .bind(policy.max_disk.map(|v| v as i64))
        .bind(dur_to_secs(policy.duration))
        .bind(dur_to_secs(policy.heartbeat_duration))
        .bind(policy.require_check_in)
        .bind(policy.max_overdue_check_ins.map(|v| v as i32))
        .bind(policy.require_product_scope)
        .bind(policy.require_user)
        .bind(policy.require_fingerprint)
        .bind(policy.protected)
        .bind(policy.renewable)
        .bind(&md)
        .bind(policy.created_at)
        .bind(policy.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as PolicyRepo>::get(self, policy.account_id, policy.id).await
    }

    async fn get(&self, account_id: AccountId, id: PolicyId) -> Result<Policy> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let row = query("SELECT * FROM policies WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        let res = not_found(row.map(|r| row_to_policy(&r)));
        tx.commit().await.map_err(map_err)?;
        res
    }

    async fn list(
        &self,
        account_id: AccountId,
        product_id: Option<ProductId>,
        page: PageQuery,
    ) -> Result<Page<Policy>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let product_id = product_id.map(|p| p.0);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let rows = query(
            "SELECT * FROM policies WHERE account_id=$1 \
             AND ($2 IS NULL OR product_id=$2) \
             AND ($3 IS NULL OR id < $3) \
             ORDER BY created_at DESC LIMIT $4",
        )
        .bind(account_id.0)
        .bind(product_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        let data: Vec<Policy> = rows.iter().map(row_to_policy).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        tx.commit().await.map_err(map_err)?;
        Ok(Page { data, next_cursor })
    }

    async fn update(&self, policy: &Policy) -> Result<Policy> {
        let md = meta_json(&policy.metadata);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, policy.account_id).await?;
        query(
            "UPDATE policies SET name=$3, scheme=$4, max_machines=$5, floating_strategy=$6, \
             max_components=$7, max_processes=$8, max_uses=$9, max_users=$10, max_cores=$11, \
             max_memory=$12, max_disk=$13, duration_secs=$14, heartbeat_duration_secs=$15, \
             require_check_in=$16, max_overdue_check_ins=$17, require_product_scope=$18, \
             require_user=$19, require_fingerprint=$20, protected=$21, renewable=$22, \
             metadata=$23, updated_at=$24 WHERE account_id=$1 AND id=$2",
        )
        .bind(policy.account_id.0)
        .bind(policy.id.0)
        .bind(&policy.name)
        .bind(scheme_str(policy.scheme))
        .bind(policy.max_machines.map(|v| v as i32))
        .bind(float_str(policy.floating_strategy))
        .bind(policy.max_components.map(|v| v as i32))
        .bind(policy.max_processes.map(|v| v as i32))
        .bind(policy.max_uses.map(|v| v as i64))
        .bind(policy.max_users.map(|v| v as i32))
        .bind(policy.max_cores.map(|v| v as i32))
        .bind(policy.max_memory.map(|v| v as i64))
        .bind(policy.max_disk.map(|v| v as i64))
        .bind(dur_to_secs(policy.duration))
        .bind(dur_to_secs(policy.heartbeat_duration))
        .bind(policy.require_check_in)
        .bind(policy.max_overdue_check_ins.map(|v| v as i32))
        .bind(policy.require_product_scope)
        .bind(policy.require_user)
        .bind(policy.require_fingerprint)
        .bind(policy.protected)
        .bind(policy.renewable)
        .bind(&md)
        .bind(policy.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as PolicyRepo>::get(self, policy.account_id, policy.id).await
    }

    async fn delete(&self, account_id: AccountId, id: PolicyId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        query("DELETE FROM policies WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(())
    }
}

pub(super) fn scheme_str(s: PolicyScheme) -> &'static str {
    match s {
        PolicyScheme::Ed25519Sign => "ED25519_SIGN",
        PolicyScheme::EcdsaP256Sha256 => "ECDSA_P256_SHA256",
        PolicyScheme::Rsa2048PssSha256 => "RSA_2048_PSS_SHA256",
        PolicyScheme::Rsa2048Pkcs1v15Sha256 => "RSA_2048_PKCS1V15_SHA256",
        PolicyScheme::JwtRs256 => "JWT_RS256",
        PolicyScheme::JwtEddsa => "JWT_EDDSA",
    }
}

pub(super) fn scheme_from_str(s: &str) -> PolicyScheme {
    match s {
        "ECDSA_P256_SHA256" => PolicyScheme::EcdsaP256Sha256,
        "RSA_2048_PSS_SHA256" => PolicyScheme::Rsa2048PssSha256,
        "RSA_2048_PKCS1V15_SHA256" => PolicyScheme::Rsa2048Pkcs1v15Sha256,
        "JWT_RS256" => PolicyScheme::JwtRs256,
        "JWT_EDDSA" => PolicyScheme::JwtEddsa,
        _ => PolicyScheme::Ed25519Sign,
    }
}

fn float_str(s: FloatingStrategy) -> &'static str {
    match s {
        FloatingStrategy::Strict => "strict",
        FloatingStrategy::Allow125xOverage => "allow_125x_overage",
        FloatingStrategy::Allow15xOverage => "allow_15x_overage",
    }
}

fn float_from_str(s: &str) -> FloatingStrategy {
    match s {
        "allow_125x_overage" => FloatingStrategy::Allow125xOverage,
        "allow_15x_overage" => FloatingStrategy::Allow15xOverage,
        _ => FloatingStrategy::Strict,
    }
}

fn row_to_policy(row: &sqlx::postgres::PgRow) -> Result<Policy> {
    let id: Uuid = row.try_get("id").map_err(dbtype)?;
    let aid: Uuid = row.try_get("account_id").map_err(dbtype)?;
    let pid: Uuid = row.try_get("product_id").map_err(dbtype)?;
    let name: String = row.try_get("name").map_err(dbtype)?;
    let key: Option<String> = row.try_get("key").map_err(dbtype)?;
    let scheme: String = row.try_get("scheme").map_err(dbtype)?;
    let md: serde_json::Value = row.try_get("metadata").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Policy {
        id: PolicyId(id),
        account_id: AccountId(aid),
        product_id: ProductId(pid),
        name,
        key,
        scheme: scheme_from_str(&scheme),
        max_machines: row
            .try_get::<Option<i32>, _>("max_machines")
            .map_err(dbtype)?
            .map(|v| v as u32),
        floating_strategy: float_from_str(
            &row.try_get::<String, _>("floating_strategy")
                .map_err(dbtype)?,
        ),
        max_components: row
            .try_get::<Option<i32>, _>("max_components")
            .map_err(dbtype)?
            .map(|v| v as u32),
        max_processes: row
            .try_get::<Option<i32>, _>("max_processes")
            .map_err(dbtype)?
            .map(|v| v as u32),
        max_uses: row
            .try_get::<Option<i64>, _>("max_uses")
            .map_err(dbtype)?
            .map(|v| v as u64),
        max_users: row
            .try_get::<Option<i32>, _>("max_users")
            .map_err(dbtype)?
            .map(|v| v as u32),
        max_cores: row
            .try_get::<Option<i32>, _>("max_cores")
            .map_err(dbtype)?
            .map(|v| v as u32),
        max_memory: row
            .try_get::<Option<i64>, _>("max_memory")
            .map_err(dbtype)?
            .map(|v| v as u64),
        max_disk: row
            .try_get::<Option<i64>, _>("max_disk")
            .map_err(dbtype)?
            .map(|v| v as u64),
        duration: secs_to_dur(
            row.try_get::<Option<i64>, _>("duration_secs")
                .map_err(dbtype)?,
        ),
        heartbeat_duration: secs_to_dur(
            row.try_get::<Option<i64>, _>("heartbeat_duration_secs")
                .map_err(dbtype)?,
        ),
        require_check_in: row.try_get("require_check_in").map_err(dbtype)?,
        max_overdue_check_ins: row
            .try_get::<Option<i32>, _>("max_overdue_check_ins")
            .map_err(dbtype)?
            .map(|v| v as u32),
        require_product_scope: row.try_get("require_product_scope").map_err(dbtype)?,
        require_user: row.try_get("require_user").map_err(dbtype)?,
        require_fingerprint: row.try_get("require_fingerprint").map_err(dbtype)?,
        protected: row.try_get("protected").map_err(dbtype)?,
        renewable: row.try_get("renewable").map_err(dbtype)?,
        metadata: meta(md),
        created_at,
        updated_at,
    })
}

// ── Repository facade ──────────────────────────────────────────────────

#[async_trait::async_trait]
impl Repository for PostgresRepository {
    fn accounts(&self) -> &dyn AccountRepo {
        self
    }
    fn products(&self) -> &dyn ProductRepo {
        self
    }
    fn policies(&self) -> &dyn PolicyRepo {
        self
    }
    fn licenses(&self) -> &dyn LicenseRepo {
        self
    }
    fn machines(&self) -> &dyn MachineRepo {
        self
    }
    fn entitlements(&self) -> &dyn EntitlementRepo {
        self
    }
    fn tokens(&self) -> &dyn TokenRepo {
        self
    }
    fn users(&self) -> &dyn UserRepo {
        self
    }
    fn signing_keys(&self) -> &dyn SigningKeyRepo {
        self
    }
    fn webhooks(&self) -> &dyn WebhookRepo {
        self
    }
    fn events(&self) -> &dyn EventLogRepo {
        self
    }
}

// The remaining entity repos are implemented in sibling modules that each
// `impl ...Repo for PostgresRepository`. They reuse the helpers above via
// `pub(crate)` / `pub(super)`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_account_id_uses_local_config() {
        // The SQL must set a LOCAL (transaction-scoped) config var so the RLS
        // policy sees it only within the tx, and so it can't leak across
        // pooled connections. The `true` second arg to set_config = local.
        assert_eq!(
            SET_ACCOUNT_ID_SQL,
            "SELECT set_config('app.account_id', $1, true)"
        );
    }
}
