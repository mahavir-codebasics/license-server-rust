//! SQLite implementation of the [`Repository`] trait.
//!
//! Stores UUIDs as TEXT (canonical 36-char form), timestamps as RFC3339
//! text, and JSON/metadata as TEXT. Tenancy is enforced by SQL
//! (`WHERE account_id = ?`) — no RLS — and a contract test (see `tests/`)
//! asserts no method returns cross-account rows.

use crate::error::{map_err, not_found, Pool, SqliteConnPool};
use license_domain::error::{DomainError, Result};
use license_domain::repository::{
    AccountRepo, EntitlementRepo, EventLogRepo, LicenseRepo, MachineRepo, Page, PageQuery,
    PolicyRepo, ProductRepo, Repository, SigningKeyRepo, TokenRepo, UserRepo, WebhookRepo,
};
use license_domain::*;
use sqlx::Row;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

// ── small shared helpers ───────────────────────────────────────────────

pub(super) fn parse_ts(v: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(v, &time::format_description::well_known::Rfc3339)
        .map_err(|e| DomainError::Internal(format!("bad timestamp: {e}")))
}

pub(super) fn ts(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

pub(super) fn opt_ts(t: Option<OffsetDateTime>) -> Option<String> {
    t.map(ts)
}

pub(super) fn dur_to_secs(d: Option<Duration>) -> Option<i64> {
    d.map(|x| x.as_secs() as i64)
}

pub(super) fn secs_to_dur(s: Option<i64>) -> Option<Duration> {
    s.filter(|&v| v > 0).map(|v| Duration::from_secs(v as u64))
}

pub(super) fn opt_ts_to_dur(s: Option<i64>) -> Option<Duration> {
    secs_to_dur(s)
}

pub(super) fn meta(v: &str) -> Metadata {
    serde_json::from_str(v).unwrap_or_default()
}

pub(super) fn meta_json(m: &Metadata) -> String {
    serde_json::to_string(m).unwrap_or_else(|_| "{}".into())
}

pub(super) fn badid<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Internal(format!("bad id: {e}"))
}

pub(super) fn dbtype<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Internal(format!("column decode error: {e}"))
}

pub(super) fn cursor_after(page: &PageQuery) -> Option<String> {
    page.after
        .as_deref()
        .and_then(|c| Uuid::parse_str(c).ok())
        .map(|u| u.to_string())
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
pub struct SqliteRepository {
    pub(super) pool: SqliteConnPool,
}

impl SqliteRepository {
    pub fn new(pool: SqliteConnPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqliteConnPool {
        &self.pool
    }
}

impl From<Pool> for SqliteRepository {
    fn from(p: Pool) -> Self {
        match p {
            Pool::Sqlite(p) => Self::new(p),
            // Programming error: a SqliteRepository can only be built from a
            // Sqlite pool. Callers pick the backend at connect time.
            Pool::Postgres(_) | Pool::Mysql(_) => {
                panic!("SqliteRepository::from(Pool) called with a non-SQLite pool")
            }
        }
    }
}

// ── Accounts ───────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl AccountRepo for SqliteRepository {
    async fn create(&self, account: &Account) -> Result<Account> {
        let settings = serde_json::to_string(&account.settings).unwrap_or_default();
        let md = meta_json(&account.metadata);
        let status = status_str(account.status);
        let pm = protection_str(account.protection_mode);
        sqlx::query(
            "INSERT INTO accounts (id, slug, name, status, protection_mode, settings, metadata, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(account.id.to_string())
        .bind(&account.slug)
        .bind(&account.name)
        .bind(status)
        .bind(pm)
        .bind(&settings)
        .bind(&md)
        .bind(ts(account.created_at))
        .bind(ts(account.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as AccountRepo>::get(self, account.id).await
    }

    async fn get(&self, id: AccountId) -> Result<Account> {
        let row = sqlx::query("SELECT * FROM accounts WHERE id = ?1")
            .bind(id.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
        row_to_account(&row)
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Account> {
        let row = sqlx::query("SELECT * FROM accounts WHERE slug = ?1")
            .bind(slug)
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
        row_to_account(&row)
    }

    async fn update(&self, account: &Account) -> Result<Account> {
        let settings = serde_json::to_string(&account.settings).unwrap_or_default();
        let md = meta_json(&account.metadata);
        sqlx::query(
            "UPDATE accounts SET slug=?2, name=?3, status=?4, protection_mode=?5, settings=?6, metadata=?7, updated_at=?8 \
             WHERE id=?1",
        )
        .bind(account.id.to_string())
        .bind(&account.slug)
        .bind(&account.name)
        .bind(status_str(account.status))
        .bind(protection_str(account.protection_mode))
        .bind(&settings)
        .bind(&md)
        .bind(ts(account.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as AccountRepo>::get(self, account.id).await
    }

    async fn list_for_user(&self, user_id: UserId, page: PageQuery) -> Result<Page<Account>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let rows = sqlx::query(
            "SELECT a.* FROM accounts a \
             JOIN account_memberships m ON m.account_id = a.id \
             WHERE m.user_id = ?1 AND (?2 IS NULL OR a.id < ?2) \
             ORDER BY a.created_at DESC, a.id DESC LIMIT ?3",
        )
        .bind(user_id.to_string())
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

fn row_to_account(row: &sqlx::sqlite::SqliteRow) -> Result<Account> {
    let id: String = row.try_get("id").map_err(dbtype)?;
    let slug: String = row.try_get("slug").map_err(dbtype)?;
    let name: String = row.try_get("name").map_err(dbtype)?;
    let status: String = row.try_get("status").map_err(dbtype)?;
    let pm: String = row.try_get("protection_mode").map_err(dbtype)?;
    let settings_json: String = row.try_get("settings").map_err(dbtype)?;
    let md_json: String = row.try_get("metadata").map_err(dbtype)?;
    let ca: String = row.try_get("created_at").map_err(dbtype)?;
    let ua: String = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Account {
        id: AccountId(Uuid::parse_str(&id).map_err(badid)?),
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
        settings: serde_json::from_str(&settings_json).unwrap_or_default(),
        metadata: meta(&md_json),
        created_at: parse_ts(&ca)?,
        updated_at: parse_ts(&ua)?,
    })
}

// ── Products ───────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl ProductRepo for SqliteRepository {
    async fn create(&self, product: &Product) -> Result<Product> {
        let md = meta_json(&product.metadata);
        sqlx::query(
            "INSERT INTO products (id, account_id, name, url, metadata, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(product.id.to_string())
        .bind(product.account_id.to_string())
        .bind(&product.name)
        .bind(&product.url)
        .bind(&md)
        .bind(ts(product.created_at))
        .bind(ts(product.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as ProductRepo>::get(self, product.account_id, product.id).await
    }

    async fn get(&self, account_id: AccountId, id: ProductId) -> Result<Product> {
        let row = sqlx::query("SELECT * FROM products WHERE account_id=?1 AND id=?2")
            .bind(account_id.to_string())
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        not_found(row.map(|r| row_to_product(&r)))
    }

    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<Product>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let rows = sqlx::query(
            "SELECT * FROM products WHERE account_id=?1 AND (?2 IS NULL OR id < ?2) \
             ORDER BY created_at DESC LIMIT ?3",
        )
        .bind(account_id.to_string())
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let data: Vec<Product> = rows.iter().map(row_to_product).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        Ok(Page { data, next_cursor })
    }

    async fn update(&self, product: &Product) -> Result<Product> {
        let md = meta_json(&product.metadata);
        sqlx::query(
            "UPDATE products SET name=?3, url=?4, metadata=?5, updated_at=?6 \
             WHERE account_id=?1 AND id=?2",
        )
        .bind(product.account_id.to_string())
        .bind(product.id.to_string())
        .bind(&product.name)
        .bind(&product.url)
        .bind(&md)
        .bind(ts(product.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as ProductRepo>::get(self, product.account_id, product.id).await
    }

    async fn delete(&self, account_id: AccountId, id: ProductId) -> Result<()> {
        sqlx::query("DELETE FROM products WHERE account_id=?1 AND id=?2")
            .bind(account_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

fn row_to_product(row: &sqlx::sqlite::SqliteRow) -> Result<Product> {
    let id: String = row.try_get("id").map_err(dbtype)?;
    let aid: String = row.try_get("account_id").map_err(dbtype)?;
    let name: String = row.try_get("name").map_err(dbtype)?;
    let url: Option<String> = row.try_get("url").map_err(dbtype)?;
    let md: String = row.try_get("metadata").map_err(dbtype)?;
    let ca: String = row.try_get("created_at").map_err(dbtype)?;
    let ua: String = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Product {
        id: ProductId(Uuid::parse_str(&id).map_err(badid)?),
        account_id: AccountId(Uuid::parse_str(&aid).map_err(badid)?),
        name,
        url,
        metadata: meta(&md),
        created_at: parse_ts(&ca)?,
        updated_at: parse_ts(&ua)?,
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

// ── Policies ───────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl PolicyRepo for SqliteRepository {
    async fn create(&self, policy: &Policy) -> Result<Policy> {
        let md = meta_json(&policy.metadata);
        sqlx::query(
            "INSERT INTO policies (\
               id, account_id, product_id, name, key, scheme, max_machines, floating_strategy, \
               max_components, max_processes, max_uses, max_users, max_cores, max_memory, max_disk, \
               duration_secs, heartbeat_duration_secs, require_check_in, max_overdue_check_ins, \
               require_product_scope, require_user, require_fingerprint, protected, renewable, \
               metadata, created_at, updated_at\
             ) VALUES (\
               ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27\
             )",
        )
        .bind(policy.id.to_string())
        .bind(policy.account_id.to_string())
        .bind(policy.product_id.to_string())
        .bind(&policy.name)
        .bind(&policy.key)
        .bind(scheme_str(policy.scheme))
        .bind(policy.max_machines.map(|v| v as i64))
        .bind(float_str(policy.floating_strategy))
        .bind(policy.max_components.map(|v| v as i64))
        .bind(policy.max_processes.map(|v| v as i64))
        .bind(policy.max_uses.map(|v| v as i64))
        .bind(policy.max_users.map(|v| v as i64))
        .bind(policy.max_cores.map(|v| v as i64))
        .bind(policy.max_memory.map(|v| v as i64))
        .bind(policy.max_disk.map(|v| v as i64))
        .bind(dur_to_secs(policy.duration))
        .bind(dur_to_secs(policy.heartbeat_duration))
        .bind(policy.require_check_in)
        .bind(policy.max_overdue_check_ins.map(|v| v as i64))
        .bind(policy.require_product_scope)
        .bind(policy.require_user)
        .bind(policy.require_fingerprint)
        .bind(policy.protected)
        .bind(policy.renewable)
        .bind(&md)
        .bind(ts(policy.created_at))
        .bind(ts(policy.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as PolicyRepo>::get(self, policy.account_id, policy.id).await
    }

    async fn get(&self, account_id: AccountId, id: PolicyId) -> Result<Policy> {
        let row = sqlx::query("SELECT * FROM policies WHERE account_id=?1 AND id=?2")
            .bind(account_id.to_string())
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        not_found(row.map(|r| row_to_policy(&r)))
    }

    async fn list(
        &self,
        account_id: AccountId,
        product_id: Option<ProductId>,
        page: PageQuery,
    ) -> Result<Page<Policy>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let product_id = product_id.map(|p| p.to_string());
        let rows = sqlx::query(
            "SELECT * FROM policies WHERE account_id=?1 \
             AND (?2 IS NULL OR product_id=?2) \
             AND (?3 IS NULL OR id < ?3) \
             ORDER BY created_at DESC LIMIT ?4",
        )
        .bind(account_id.to_string())
        .bind(product_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let data: Vec<Policy> = rows.iter().map(row_to_policy).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        Ok(Page { data, next_cursor })
    }

    async fn update(&self, policy: &Policy) -> Result<Policy> {
        let md = meta_json(&policy.metadata);
        sqlx::query(
            "UPDATE policies SET name=?3, scheme=?4, max_machines=?5, floating_strategy=?6, \
             max_components=?7, max_processes=?8, max_uses=?9, max_users=?10, max_cores=?11, \
             max_memory=?12, max_disk=?13, duration_secs=?14, heartbeat_duration_secs=?15, \
             require_check_in=?16, max_overdue_check_ins=?17, require_product_scope=?18, \
             require_user=?19, require_fingerprint=?20, protected=?21, renewable=?22, \
             metadata=?23, updated_at=?24 WHERE account_id=?1 AND id=?2",
        )
        .bind(policy.account_id.to_string())
        .bind(policy.id.to_string())
        .bind(&policy.name)
        .bind(scheme_str(policy.scheme))
        .bind(policy.max_machines.map(|v| v as i64))
        .bind(float_str(policy.floating_strategy))
        .bind(policy.max_components.map(|v| v as i64))
        .bind(policy.max_processes.map(|v| v as i64))
        .bind(policy.max_uses.map(|v| v as i64))
        .bind(policy.max_users.map(|v| v as i64))
        .bind(policy.max_cores.map(|v| v as i64))
        .bind(policy.max_memory.map(|v| v as i64))
        .bind(policy.max_disk.map(|v| v as i64))
        .bind(dur_to_secs(policy.duration))
        .bind(dur_to_secs(policy.heartbeat_duration))
        .bind(policy.require_check_in)
        .bind(policy.max_overdue_check_ins.map(|v| v as i64))
        .bind(policy.require_product_scope)
        .bind(policy.require_user)
        .bind(policy.require_fingerprint)
        .bind(policy.protected)
        .bind(policy.renewable)
        .bind(&md)
        .bind(ts(policy.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as PolicyRepo>::get(self, policy.account_id, policy.id).await
    }

    async fn delete(&self, account_id: AccountId, id: PolicyId) -> Result<()> {
        sqlx::query("DELETE FROM policies WHERE account_id=?1 AND id=?2")
            .bind(account_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
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

fn row_to_policy(row: &sqlx::sqlite::SqliteRow) -> Result<Policy> {
    let id: String = row.try_get("id").map_err(dbtype)?;
    let aid: String = row.try_get("account_id").map_err(dbtype)?;
    let pid: String = row.try_get("product_id").map_err(dbtype)?;
    let name: String = row.try_get("name").map_err(dbtype)?;
    let key: Option<String> = row.try_get("key").map_err(dbtype)?;
    let scheme: String = row.try_get("scheme").map_err(dbtype)?;
    let md: String = row.try_get("metadata").map_err(dbtype)?;
    let ca: String = row.try_get("created_at").map_err(dbtype)?;
    let ua: String = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Policy {
        id: PolicyId(Uuid::parse_str(&id).map_err(badid)?),
        account_id: AccountId(Uuid::parse_str(&aid).map_err(badid)?),
        product_id: ProductId(Uuid::parse_str(&pid).map_err(badid)?),
        name,
        key,
        scheme: scheme_from_str(&scheme),
        max_machines: row
            .try_get::<Option<i64>, _>("max_machines")
            .map_err(dbtype)?
            .map(|v| v as u32),
        floating_strategy: float_from_str(
            &row.try_get::<String, _>("floating_strategy")
                .map_err(dbtype)?,
        ),
        max_components: row
            .try_get::<Option<i64>, _>("max_components")
            .map_err(dbtype)?
            .map(|v| v as u32),
        max_processes: row
            .try_get::<Option<i64>, _>("max_processes")
            .map_err(dbtype)?
            .map(|v| v as u32),
        max_uses: row
            .try_get::<Option<i64>, _>("max_uses")
            .map_err(dbtype)?
            .map(|v| v as u64),
        max_users: row
            .try_get::<Option<i64>, _>("max_users")
            .map_err(dbtype)?
            .map(|v| v as u32),
        max_cores: row
            .try_get::<Option<i64>, _>("max_cores")
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
        duration: opt_ts_to_dur(
            row.try_get::<Option<i64>, _>("duration_secs")
                .map_err(dbtype)?,
        ),
        heartbeat_duration: opt_ts_to_dur(
            row.try_get::<Option<i64>, _>("heartbeat_duration_secs")
                .map_err(dbtype)?,
        ),
        require_check_in: row.try_get("require_check_in").map_err(dbtype)?,
        max_overdue_check_ins: row
            .try_get::<Option<i64>, _>("max_overdue_check_ins")
            .map_err(dbtype)?
            .map(|v| v as u32),
        require_product_scope: row.try_get("require_product_scope").map_err(dbtype)?,
        require_user: row.try_get("require_user").map_err(dbtype)?,
        require_fingerprint: row.try_get("require_fingerprint").map_err(dbtype)?,
        protected: row.try_get("protected").map_err(dbtype)?,
        renewable: row.try_get("renewable").map_err(dbtype)?,
        metadata: meta(&md),
        created_at: parse_ts(&ca)?,
        updated_at: parse_ts(&ua)?,
    })
}

// ── Repository facade ──────────────────────────────────────────────────

#[async_trait::async_trait]
impl Repository for SqliteRepository {
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
// `impl ...Repo for SqliteRepository`. They reuse the helpers above via
// `pub(crate)`.
