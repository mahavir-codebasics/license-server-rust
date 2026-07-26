//! MySQL implementation of the [`Repository`] trait.
//!
//! UUIDs are stored as `BINARY(16)`. We bind `uuid.as_bytes()` (16 bytes, big
//! endian — for UUIDv7 this is already time-ordered, so we do NOT need MySQL's
//! `UUID_TO_BIN(id, true)` swap) on write and reconstruct on read via
//! [`uuid::Uuid::from_slice`] from the 16-byte `Vec<u8>`. The migration column
//! is plain `BINARY(16)` (no generated swap), so the raw bytes round-trip
//! verbatim. See [`uuid_to_bin`] / [`bin_to_uuid`] for the (de)serialization
//! and the `binary16_uuid_round_trip` unit test for proof.
//!
//! Timestamps are `DATETIME(6)` — sqlx maps `OffsetDateTime` directly (the
//! `time` feature is on). JSON columns are `JSON` — sqlx maps
//! `serde_json::Value`. Booleans are `TINYINT(1)` — bind as `bool`, reads
//! decode as `bool`. The `ON UPDATE CURRENT_TIMESTAMP(6)` clause keeps
//! `updated_at` fresh on UPDATE, but we still bind `updated_at` explicitly for
//! consistency (the trigger overrides it server-side).
//!
//! No RLS in MySQL — tenancy is enforced by `WHERE account_id = ?` on every
//! tenant-scoped query, exactly like SQLite.

use crate::error::{map_err, not_found, MysqlConnPool, Pool};
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

/// Type-anchored `sqlx::query` for MySQL.
///
/// With multiple sqlx backends enabled in one build, `query(...)` is
/// generic over `DB` and the bind chain can infer the wrong backend (the `?`
/// placeholder and `OffsetDateTime`/`Vec<u8>`/`bool` binds are all valid for
/// more than one backend). Anchoring `DB = MySql` here at construction time
/// lets every bind inherit the right type. Call sites use `query(...)` exactly
/// as they would `query(...)`.
pub(super) fn query(sql: &str) -> Query<'_, sqlx::MySql, <sqlx::MySql as Database>::Arguments<'_>> {
    sqlx::query::<sqlx::MySql>(sql)
}

/// Type-anchored `sqlx::query_as` for MySQL (same rationale as [`query`]).
pub(super) fn query_as<'q, T>(
    sql: &'q str,
) -> sqlx::query::QueryAs<'q, sqlx::MySql, T, <sqlx::MySql as Database>::Arguments<'q>>
where
    T: for<'r> sqlx::FromRow<'r, sqlx::mysql::MySqlRow> + Send,
{
    sqlx::query_as::<sqlx::MySql, _>(sql)
}

/// Serialize a UUID to the 16 bytes MySQL stores in a `BINARY(16)` column.
/// For UUIDv7 the big-endian byte layout (`as_bytes()`) is already
/// time-ordered, so this is what we bind directly — no `UUID_TO_BIN` swap.
///
/// Returns a `Vec<u8>` (not `[u8; 16]`) because sqlx implements `Encode`/
/// `Type` for `Vec<u8>`/`&[u8]` but not for the fixed-size array. The 16-byte
/// allocation per DB call is negligible next to the round-trip.
pub(super) fn uuid_to_bin(u: Uuid) -> Vec<u8> {
    u.as_bytes().to_vec()
}

/// Deserialize a UUID from the 16 bytes read out of a `BINARY(16)` column.
/// Inverse of [`uuid_to_bin`].
pub(super) fn bin_to_uuid(bytes: &[u8]) -> Result<Uuid> {
    Uuid::from_slice(bytes).map_err(|e| DomainError::Internal(format!("bad id: {e}")))
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

/// Read a `BINARY(16)` column into a `Uuid`, mapping a NULL/short value to a
/// decode error.
pub(super) fn get_uuid(row: &sqlx::mysql::MySqlRow, col: &str) -> Result<Uuid> {
    let bytes: Vec<u8> = row.try_get(col).map_err(dbtype)?;
    bin_to_uuid(&bytes)
}

/// Read a nullable `BINARY(16)` column into an `Option<Uuid>`.
pub(super) fn get_opt_uuid(row: &sqlx::mysql::MySqlRow, col: &str) -> Result<Option<Uuid>> {
    match row.try_get::<Option<Vec<u8>>, _>(col).map_err(dbtype)? {
        Some(bytes) => Ok(Some(bin_to_uuid(&bytes)?)),
        None => Ok(None),
    }
}

/// Parse the keyset cursor (canonical UUID string of the last row).
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
pub struct MysqlRepository {
    pub(super) pool: MysqlConnPool,
}

impl MysqlRepository {
    pub fn new(pool: MysqlConnPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &MysqlConnPool {
        &self.pool
    }
}

impl From<Pool> for MysqlRepository {
    fn from(p: Pool) -> Self {
        match p {
            Pool::Mysql(p) => Self::new(p),
            Pool::Sqlite(_) | Pool::Postgres(_) => {
                panic!("MysqlRepository::from(Pool) called with a non-MySQL pool")
            }
        }
    }
}

// ── Accounts (NOT tenant-scoped) ───────────────────────────────────────

#[async_trait::async_trait]
impl AccountRepo for MysqlRepository {
    async fn create(&self, account: &Account) -> Result<Account> {
        let settings = serde_json::to_value(&account.settings).unwrap_or_default();
        let md = meta_json(&account.metadata);
        query(
            "INSERT INTO accounts (id, slug, name, status, protection_mode, settings, metadata, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid_to_bin(account.id.0))
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
        let row = query("SELECT * FROM accounts WHERE id = ?")
            .bind(uuid_to_bin(id.0))
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
        row_to_account(&row)
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Account> {
        let row = query("SELECT * FROM accounts WHERE slug = ?")
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
            "UPDATE accounts SET slug=?, name=?, status=?, protection_mode=?, settings=?, metadata=?, updated_at=? \
             WHERE id=?",
        )
        .bind(&account.slug)
        .bind(&account.name)
        .bind(status_str(account.status))
        .bind(protection_str(account.protection_mode))
        .bind(&settings)
        .bind(&md)
        .bind(account.updated_at)
        .bind(uuid_to_bin(account.id.0))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as AccountRepo>::get(self, account.id).await
    }

    async fn list_for_user(&self, user_id: UserId, page: PageQuery) -> Result<Page<Account>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let rows = query(
            "SELECT a.* FROM accounts a \
             JOIN account_memberships m ON m.account_id = a.id \
             WHERE m.user_id = ? AND (? IS NULL OR a.id < ?) \
             ORDER BY a.created_at DESC, a.id DESC LIMIT ?",
        )
        .bind(uuid_to_bin(user_id.0))
        .bind(after_id.map(uuid_to_bin))
        .bind(after_id.map(uuid_to_bin))
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

fn row_to_account(row: &sqlx::mysql::MySqlRow) -> Result<Account> {
    let id = get_uuid(row, "id")?;
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

// ── Products (tenant-scoped) ───────────────────────────────────────────

#[async_trait::async_trait]
impl ProductRepo for MysqlRepository {
    async fn create(&self, product: &Product) -> Result<Product> {
        let md = meta_json(&product.metadata);
        query(
            "INSERT INTO products (id, account_id, name, url, metadata, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid_to_bin(product.id.0))
        .bind(uuid_to_bin(product.account_id.0))
        .bind(&product.name)
        .bind(&product.url)
        .bind(&md)
        .bind(product.created_at)
        .bind(product.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as ProductRepo>::get(self, product.account_id, product.id).await
    }

    async fn get(&self, account_id: AccountId, id: ProductId) -> Result<Product> {
        let row = query("SELECT * FROM products WHERE account_id=? AND id=?")
            .bind(uuid_to_bin(account_id.0))
            .bind(uuid_to_bin(id.0))
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        not_found(row.map(|r| row_to_product(&r)))
    }

    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<Product>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let rows = query(
            "SELECT * FROM products WHERE account_id=? AND (? IS NULL OR id < ?) \
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(uuid_to_bin(account_id.0))
        .bind(after_id.map(uuid_to_bin))
        .bind(after_id.map(uuid_to_bin))
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
        query(
            "UPDATE products SET name=?, url=?, metadata=?, updated_at=? \
             WHERE account_id=? AND id=?",
        )
        .bind(&product.name)
        .bind(&product.url)
        .bind(&md)
        .bind(product.updated_at)
        .bind(uuid_to_bin(product.account_id.0))
        .bind(uuid_to_bin(product.id.0))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as ProductRepo>::get(self, product.account_id, product.id).await
    }

    async fn delete(&self, account_id: AccountId, id: ProductId) -> Result<()> {
        query("DELETE FROM products WHERE account_id=? AND id=?")
            .bind(uuid_to_bin(account_id.0))
            .bind(uuid_to_bin(id.0))
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

fn row_to_product(row: &sqlx::mysql::MySqlRow) -> Result<Product> {
    let id = get_uuid(row, "id")?;
    let aid = get_uuid(row, "account_id")?;
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

// ── Policies (tenant-scoped) ───────────────────────────────────────────

#[async_trait::async_trait]
impl PolicyRepo for MysqlRepository {
    async fn create(&self, policy: &Policy) -> Result<Policy> {
        let md = meta_json(&policy.metadata);
        query(
            "INSERT INTO policies (\
               id, account_id, product_id, name, `key`, scheme, max_machines, floating_strategy, \
               max_components, max_processes, max_uses, max_users, max_cores, max_memory, max_disk, \
               duration_secs, heartbeat_duration_secs, require_check_in, max_overdue_check_ins, \
               require_product_scope, require_user, require_fingerprint, protected, renewable, \
               metadata, created_at, updated_at\
             ) VALUES (\
               ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?\
             )",
        )
        .bind(uuid_to_bin(policy.id.0))
        .bind(uuid_to_bin(policy.account_id.0))
        .bind(uuid_to_bin(policy.product_id.0))
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
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as PolicyRepo>::get(self, policy.account_id, policy.id).await
    }

    async fn get(&self, account_id: AccountId, id: PolicyId) -> Result<Policy> {
        let row = query("SELECT * FROM policies WHERE account_id=? AND id=?")
            .bind(uuid_to_bin(account_id.0))
            .bind(uuid_to_bin(id.0))
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
        let product_id = product_id.map(|p| uuid_to_bin(p.0));
        let rows = query(
            "SELECT * FROM policies WHERE account_id=? \
             AND (? IS NULL OR product_id=?) \
             AND (? IS NULL OR id < ?) \
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(uuid_to_bin(account_id.0))
        .bind(product_id.clone())
        .bind(product_id)
        .bind(after_id.map(uuid_to_bin))
        .bind(after_id.map(uuid_to_bin))
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
        query(
            "UPDATE policies SET name=?, scheme=?, max_machines=?, floating_strategy=?, \
             max_components=?, max_processes=?, max_uses=?, max_users=?, max_cores=?, \
             max_memory=?, max_disk=?, duration_secs=?, heartbeat_duration_secs=?, \
             require_check_in=?, max_overdue_check_ins=?, require_product_scope=?, \
             require_user=?, require_fingerprint=?, protected=?, renewable=?, \
             metadata=?, updated_at=? WHERE account_id=? AND id=?",
        )
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
        .bind(uuid_to_bin(policy.account_id.0))
        .bind(uuid_to_bin(policy.id.0))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as PolicyRepo>::get(self, policy.account_id, policy.id).await
    }

    async fn delete(&self, account_id: AccountId, id: PolicyId) -> Result<()> {
        query("DELETE FROM policies WHERE account_id=? AND id=?")
            .bind(uuid_to_bin(account_id.0))
            .bind(uuid_to_bin(id.0))
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

fn row_to_policy(row: &sqlx::mysql::MySqlRow) -> Result<Policy> {
    let id = get_uuid(row, "id")?;
    let aid = get_uuid(row, "account_id")?;
    let pid = get_uuid(row, "product_id")?;
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
impl Repository for MysqlRepository {
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
// `impl ...Repo for MysqlRepository`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary16_uuid_round_trip() {
        // A BINARY(16) UUID round-trips: the 16 bytes we bind on write decode
        // back to the same Uuid on read. Verifies both v4 and v7 layouts
        // (v7 is what the app generates; v4 is the fallback).
        for original in [
            Uuid::now_v7(),
            Uuid::new_v4(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
            Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap(),
        ] {
            let bytes = uuid_to_bin(original);
            assert_eq!(bytes.len(), 16, "BINARY(16) must be exactly 16 bytes");
            let decoded = bin_to_uuid(&bytes).expect("round-trip decode");
            assert_eq!(
                original, decoded,
                "UUID did not round-trip through BINARY(16)"
            );
            // The on-the-wire bytes equal the canonical big-endian layout.
            assert_eq!(bytes.as_slice(), original.as_bytes());
        }
    }

    #[test]
    fn bin_to_uuid_rejects_wrong_length() {
        assert!(bin_to_uuid(&[0u8; 15]).is_err(), "15 bytes must fail");
        assert!(bin_to_uuid(&[0u8; 17]).is_err(), "17 bytes must fail");
        assert!(bin_to_uuid(&[]).is_err(), "empty must fail");
    }
}
