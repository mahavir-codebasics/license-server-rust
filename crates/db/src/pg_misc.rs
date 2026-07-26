//! PostgreSQL impls for the remaining repos: entitlements, tokens, users,
//! signing_keys, webhooks, event_log.
//!
//! `users` and `accounts` are NOT RLS-protected (cross-tenant identity). All
//! other tables here ARE tenant-scoped and set `app.account_id` per-tx. The
//! cron-style sweeps (`retire_expired`, `due`) run as the owner role (bypass
//! RLS) since they span tenants — matching the SQLite/MySQL behavior.

use super::pg::{cursor_after, dbtype, meta, meta_json, next_cursor, query, set_account_id, IdStr};
use crate::error::{map_err, not_found};
use license_domain::error::Result;
use license_domain::repository::{
    EntitlementRepo, EventLogRepo, Page, PageQuery, SigningKeyRepo, TokenRepo, UserRepo,
    WebhookRepo,
};
use license_domain::*;
use sqlx::Row;
use time::OffsetDateTime;

// ── Entitlements (tenant-scoped — RLS) ─────────────────────────────────

#[async_trait::async_trait]
impl EntitlementRepo for super::pg::PostgresRepository {
    async fn create(&self, e: &Entitlement) -> Result<Entitlement> {
        let md = meta_json(&e.metadata);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, e.account_id).await?;
        query(
            "INSERT INTO entitlements (id, account_id, code, name, metadata, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(e.id.0)
        .bind(e.account_id.0)
        .bind(&e.code.0)
        .bind(&e.name)
        .bind(&md)
        .bind(e.created_at)
        .bind(e.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as EntitlementRepo>::get(self, e.account_id, e.id).await
    }

    async fn get(&self, account_id: AccountId, id: EntitlementId) -> Result<Entitlement> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let row = query("SELECT * FROM entitlements WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        let res = not_found(row.map(|r| row_to_entitlement(&r)));
        tx.commit().await.map_err(map_err)?;
        res
    }

    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<Entitlement>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let rows = query(
            "SELECT * FROM entitlements WHERE account_id=$1 AND ($2 IS NULL OR id < $2) \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(account_id.0)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        let data: Vec<Entitlement> = rows.iter().map(row_to_entitlement).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        tx.commit().await.map_err(map_err)?;
        Ok(Page { data, next_cursor })
    }

    async fn update(&self, e: &Entitlement) -> Result<Entitlement> {
        let md = meta_json(&e.metadata);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, e.account_id).await?;
        query(
            "UPDATE entitlements SET name=$3, metadata=$4, updated_at=$5 \
             WHERE account_id=$1 AND id=$2",
        )
        .bind(e.account_id.0)
        .bind(e.id.0)
        .bind(&e.name)
        .bind(&md)
        .bind(e.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as EntitlementRepo>::get(self, e.account_id, e.id).await
    }

    async fn delete(&self, account_id: AccountId, id: EntitlementId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        query("DELETE FROM entitlements WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(())
    }
}

fn row_to_entitlement(row: &sqlx::postgres::PgRow) -> Result<Entitlement> {
    let id: uuid::Uuid = row.try_get("id").map_err(dbtype)?;
    let aid: uuid::Uuid = row.try_get("account_id").map_err(dbtype)?;
    let code: String = row.try_get("code").map_err(dbtype)?;
    let name: String = row.try_get("name").map_err(dbtype)?;
    let md: serde_json::Value = row.try_get("metadata").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Entitlement {
        id: EntitlementId(id),
        account_id: AccountId(aid),
        code: EntitlementCode(code),
        name,
        metadata: meta(md),
        created_at,
        updated_at,
    })
}

impl IdStr for Entitlement {
    fn id_str(&self) -> String {
        self.id.to_string()
    }
}

// ── Tokens (tenant-scoped — RLS) ───────────────────────────────────────
//
// `get_by_hash` is a global lookup (the token hash is 256-bit globally unique)
// and bypasses RLS via the table-owner exemption (our migration does not set
// FORCE ROW LEVEL SECURITY). `touch_last_used` similarly updates by id alone.

#[async_trait::async_trait]
impl TokenRepo for super::pg::PostgresRepository {
    async fn create(&self, t: &Token) -> Result<Token> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, t.account_id).await?;
        query(
            "INSERT INTO tokens (id, account_id, kind, name, token_hash, expiry, last_used_at, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(t.id.0)
        .bind(t.account_id.0)
        .bind(token_kind_str(t.kind))
        .bind(&t.name)
        .bind(&t.token_hash)
        .bind(t.expiry)
        .bind(t.last_used_at)
        .bind(t.created_at)
        .bind(t.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as TokenRepo>::get(self, t.account_id, t.id).await
    }

    async fn get(&self, account_id: AccountId, id: TokenId) -> Result<Token> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let row = query("SELECT * FROM tokens WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        let res = not_found(row.map(|r| row_to_token(&r)));
        tx.commit().await.map_err(map_err)?;
        res
    }

    async fn get_by_hash(&self, token_hash: &str) -> Result<Token> {
        // Global lookup by SHA-256 hash (256 bits of entropy, globally unique).
        // Runs as the table owner (bypasses RLS). See module doc.
        let row = query("SELECT * FROM tokens WHERE token_hash=$1")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        not_found(row.map(|r| row_to_token(&r)))
    }

    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<Token>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let rows = query(
            "SELECT * FROM tokens WHERE account_id=$1 AND ($2 IS NULL OR id < $2) \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(account_id.0)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        let data: Vec<Token> = rows.iter().map(row_to_token).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        tx.commit().await.map_err(map_err)?;
        Ok(Page { data, next_cursor })
    }

    async fn revoke(&self, account_id: AccountId, id: TokenId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        query("DELETE FROM tokens WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(())
    }

    async fn touch_last_used(&self, id: TokenId, at: OffsetDateTime) -> Result<()> {
        query("UPDATE tokens SET last_used_at=$2 WHERE id=$1")
            .bind(id.0)
            .bind(at)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

fn token_kind_str(k: TokenKind) -> &'static str {
    match k {
        TokenKind::Admin => "admin",
        TokenKind::Product => "product",
        TokenKind::License => "license",
        TokenKind::User => "user",
        TokenKind::Personal => "personal",
    }
}
fn token_kind_from_str(s: &str) -> TokenKind {
    match s {
        "product" => TokenKind::Product,
        "license" => TokenKind::License,
        "user" => TokenKind::User,
        "personal" => TokenKind::Personal,
        _ => TokenKind::Admin,
    }
}

fn row_to_token(row: &sqlx::postgres::PgRow) -> Result<Token> {
    let id: uuid::Uuid = row.try_get("id").map_err(dbtype)?;
    let aid: uuid::Uuid = row.try_get("account_id").map_err(dbtype)?;
    let kind: String = row.try_get("kind").map_err(dbtype)?;
    let name: Option<String> = row.try_get("name").map_err(dbtype)?;
    let token_hash: String = row.try_get("token_hash").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Token {
        id: TokenId(id),
        account_id: AccountId(aid),
        kind: token_kind_from_str(&kind),
        name,
        token_hash,
        expiry: row.try_get("expiry").map_err(dbtype)?,
        last_used_at: row.try_get("last_used_at").map_err(dbtype)?,
        created_at,
        updated_at,
    })
}

impl IdStr for Token {
    fn id_str(&self) -> String {
        self.id.to_string()
    }
}

// ── Users (NOT tenant-scoped — no RLS) ─────────────────────────────────

#[async_trait::async_trait]
impl UserRepo for super::pg::PostgresRepository {
    async fn create(&self, u: &User) -> Result<User> {
        query(
            "INSERT INTO users (id, email, full_name, password_hash, totp_secret, totp_enabled, status, avatar_url, last_login_at, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(u.id.0)
        .bind(&u.email)
        .bind(&u.full_name)
        .bind(&u.password_hash)
        .bind(&u.totp_secret)
        .bind(u.totp_enabled)
        .bind(user_status_str(u.status))
        .bind(&u.avatar_url)
        .bind(u.last_login_at)
        .bind(u.created_at)
        .bind(u.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as UserRepo>::get(self, u.id).await
    }

    async fn get(&self, id: UserId) -> Result<User> {
        let row = query("SELECT * FROM users WHERE id=$1")
            .bind(id.0)
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
        row_to_user(&row)
    }

    async fn get_by_email(&self, email: &str) -> Result<User> {
        let row = query("SELECT * FROM users WHERE email=$1")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;
        row_to_user(&row)
    }

    async fn update(&self, u: &User) -> Result<User> {
        query(
            "UPDATE users SET email=$2, full_name=$3, password_hash=$4, totp_secret=$5, totp_enabled=$6, status=$7, avatar_url=$8, last_login_at=$9, updated_at=$10 \
             WHERE id=$1",
        )
        .bind(u.id.0)
        .bind(&u.email)
        .bind(&u.full_name)
        .bind(&u.password_hash)
        .bind(&u.totp_secret)
        .bind(u.totp_enabled)
        .bind(user_status_str(u.status))
        .bind(&u.avatar_url)
        .bind(u.last_login_at)
        .bind(u.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as UserRepo>::get(self, u.id).await
    }

    async fn add_membership(&self, m: &AccountMembership) -> Result<()> {
        query(
            "INSERT INTO account_memberships (id, user_id, account_id, role, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(m.id.0)
        .bind(m.user_id.0)
        .bind(m.account_id.0)
        .bind(role_str(m.role))
        .bind(m.created_at)
        .bind(m.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn memberships(&self, user_id: UserId) -> Result<Vec<AccountMembership>> {
        let rows = query("SELECT * FROM account_memberships WHERE user_id=$1")
            .bind(user_id.0)
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?;
        rows.iter().map(row_to_membership).collect()
    }
}

fn user_status_str(s: UserStatus) -> &'static str {
    match s {
        UserStatus::Active => "active",
        UserStatus::Suspended => "suspended",
    }
}
fn user_status_from_str(s: &str) -> UserStatus {
    match s {
        "suspended" => UserStatus::Suspended,
        _ => UserStatus::Active,
    }
}
fn role_str(r: MembershipRole) -> &'static str {
    match r {
        MembershipRole::Owner => "owner",
        MembershipRole::Admin => "admin",
        MembershipRole::Developer => "developer",
        MembershipRole::Viewer => "viewer",
    }
}
fn role_from_str(s: &str) -> MembershipRole {
    match s {
        "owner" => MembershipRole::Owner,
        "developer" => MembershipRole::Developer,
        "viewer" => MembershipRole::Viewer,
        _ => MembershipRole::Admin,
    }
}

fn row_to_user(row: &sqlx::postgres::PgRow) -> Result<User> {
    let id: uuid::Uuid = row.try_get("id").map_err(dbtype)?;
    let email: String = row.try_get("email").map_err(dbtype)?;
    let full_name: Option<String> = row.try_get("full_name").map_err(dbtype)?;
    let password_hash: String = row.try_get("password_hash").map_err(dbtype)?;
    let totp_secret: Option<String> = row.try_get("totp_secret").map_err(dbtype)?;
    let totp_enabled: bool = row.try_get("totp_enabled").map_err(dbtype)?;
    let status: String = row.try_get("status").map_err(dbtype)?;
    let avatar_url: Option<String> = row.try_get("avatar_url").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(User {
        id: UserId(id),
        email,
        full_name,
        password_hash,
        totp_secret,
        totp_enabled,
        status: user_status_from_str(&status),
        avatar_url,
        last_login_at: row.try_get("last_login_at").map_err(dbtype)?,
        created_at,
        updated_at,
    })
}

fn row_to_membership(row: &sqlx::postgres::PgRow) -> Result<AccountMembership> {
    let id: uuid::Uuid = row.try_get("id").map_err(dbtype)?;
    let uid: uuid::Uuid = row.try_get("user_id").map_err(dbtype)?;
    let aid: uuid::Uuid = row.try_get("account_id").map_err(dbtype)?;
    let role: String = row.try_get("role").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(AccountMembership {
        id: MembershipId(id),
        user_id: UserId(uid),
        account_id: AccountId(aid),
        role: role_from_str(&role),
        created_at,
        updated_at,
    })
}

// ── SigningKeys (tenant-scoped — RLS) ──────────────────────────────────

#[async_trait::async_trait]
impl SigningKeyRepo for super::pg::PostgresRepository {
    async fn create(&self, k: &SigningKey) -> Result<SigningKey> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, k.account_id).await?;
        query(
            "INSERT INTO signing_keys (id, account_id, algorithm, usage, status, version, material, public_pem, retired_at, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(k.id.0)
        .bind(k.account_id.0)
        .bind(algo_str(k.algorithm))
        .bind(usage_str(k.usage))
        .bind(key_status_str(k.status))
        .bind(k.version as i32)
        .bind(&k.material)
        .bind(&k.public_pem)
        .bind(k.retired_at)
        .bind(k.created_at)
        .bind(k.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as SigningKeyRepo>::get(self, k.account_id, k.id).await
    }

    async fn get(&self, account_id: AccountId, id: SigningKeyId) -> Result<SigningKey> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let row = query("SELECT * FROM signing_keys WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        let res = not_found(row.map(|r| row_to_signing_key(&r)));
        tx.commit().await.map_err(map_err)?;
        res
    }

    async fn active(&self, account_id: AccountId) -> Result<SigningKey> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let row = query("SELECT * FROM signing_keys WHERE account_id=$1 AND status='active'")
            .bind(account_id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        let res = not_found(row.map(|r| row_to_signing_key(&r)));
        tx.commit().await.map_err(map_err)?;
        res
    }

    async fn verifiable(&self, account_id: AccountId) -> Result<Vec<SigningKey>> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let rows = query(
            "SELECT * FROM signing_keys WHERE account_id=$1 AND status IN ('active','rotating') ORDER BY version DESC",
        )
        .bind(account_id.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        let data: Vec<SigningKey> = rows.iter().map(row_to_signing_key).collect::<Result<_>>()?;
        tx.commit().await.map_err(map_err)?;
        Ok(data)
    }

    async fn rotate(&self, account_id: AccountId, new_key: &SigningKey) -> Result<SigningKey> {
        // Demote current active → rotating, then insert the new active key.
        // Wrap in a transaction so a partial failure leaves keys consistent.
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        query(
            "UPDATE signing_keys SET status='rotating', retired_at=NULL, updated_at=$2 \
             WHERE account_id=$1 AND status='active'",
        )
        .bind(account_id.0)
        .bind(new_key.created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        query(
            "INSERT INTO signing_keys (id, account_id, algorithm, usage, status, version, material, public_pem, retired_at, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,'active',$5,$6,$7,NULL,$8,$9)",
        )
        .bind(new_key.id.0)
        .bind(new_key.account_id.0)
        .bind(algo_str(new_key.algorithm))
        .bind(usage_str(new_key.usage))
        .bind(new_key.version as i32)
        .bind(&new_key.material)
        .bind(&new_key.public_pem)
        .bind(new_key.created_at)
        .bind(new_key.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        self.active(account_id).await
    }

    async fn retire_expired(&self, now: OffsetDateTime) -> Result<u64> {
        // Cross-tenant sweep — runs as the owner role (bypasses RLS).
        let res = query(
            "UPDATE signing_keys SET status='retired' \
             WHERE status='rotating' AND retired_at IS NOT NULL AND retired_at < $1",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(res.rows_affected())
    }
}

fn algo_str(a: KeyAlgorithm) -> &'static str {
    match a {
        KeyAlgorithm::Ed25519 => "ed25519",
        KeyAlgorithm::EcdsaP256 => "ecdsa_p256",
        KeyAlgorithm::Rsa2048 => "rsa_2048",
    }
}
fn usage_str(u: KeyUsage) -> &'static str {
    match u {
        KeyUsage::License => "license",
        KeyUsage::Webhook => "webhook",
    }
}
fn key_status_str(s: KeyStatus) -> &'static str {
    match s {
        KeyStatus::Active => "active",
        KeyStatus::Rotating => "rotating",
        KeyStatus::Retired => "retired",
    }
}
fn algo_from_str(s: &str) -> KeyAlgorithm {
    match s {
        "ecdsa_p256" => KeyAlgorithm::EcdsaP256,
        "rsa_2048" => KeyAlgorithm::Rsa2048,
        _ => KeyAlgorithm::Ed25519,
    }
}
fn usage_from_str(s: &str) -> KeyUsage {
    match s {
        "webhook" => KeyUsage::Webhook,
        _ => KeyUsage::License,
    }
}
fn key_status_from_str(s: &str) -> KeyStatus {
    match s {
        "rotating" => KeyStatus::Rotating,
        "retired" => KeyStatus::Retired,
        _ => KeyStatus::Active,
    }
}

fn row_to_signing_key(row: &sqlx::postgres::PgRow) -> Result<SigningKey> {
    let id: uuid::Uuid = row.try_get("id").map_err(dbtype)?;
    let aid: uuid::Uuid = row.try_get("account_id").map_err(dbtype)?;
    let algorithm: String = row.try_get("algorithm").map_err(dbtype)?;
    let usage: String = row.try_get("usage").map_err(dbtype)?;
    let status: String = row.try_get("status").map_err(dbtype)?;
    let version: i32 = row.try_get("version").map_err(dbtype)?;
    let material: Vec<u8> = row.try_get("material").map_err(dbtype)?;
    let public_pem: String = row.try_get("public_pem").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(SigningKey {
        id: SigningKeyId(id),
        account_id: AccountId(aid),
        algorithm: algo_from_str(&algorithm),
        usage: usage_from_str(&usage),
        status: key_status_from_str(&status),
        version: version as u32,
        material,
        public_pem,
        retired_at: row.try_get("retired_at").map_err(dbtype)?,
        created_at,
        updated_at,
    })
}

// ── Webhooks (tenant-scoped — RLS; `due` is an owner-role sweep) ────────

#[async_trait::async_trait]
impl WebhookRepo for super::pg::PostgresRepository {
    async fn create_endpoint(&self, e: &WebhookEndpoint) -> Result<WebhookEndpoint> {
        let ets = serde_json::to_value(&e.event_types)
            .unwrap_or_else(|_| serde_json::Value::Array(vec![]));
        let md = meta_json(&e.metadata);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, e.account_id).await?;
        query(
            "INSERT INTO webhook_endpoints (id, account_id, url, event_types, secret, status, metadata, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(e.id.0)
        .bind(e.account_id.0)
        .bind(&e.url)
        .bind(&ets)
        .bind(&e.secret)
        .bind(webhook_status_str(e.status))
        .bind(&md)
        .bind(e.created_at)
        .bind(e.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        self.get_endpoint(e.account_id, e.id).await
    }

    async fn get_endpoint(
        &self,
        account_id: AccountId,
        id: WebhookEndpointId,
    ) -> Result<WebhookEndpoint> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let row = query("SELECT * FROM webhook_endpoints WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        let res = not_found(row.map(|r| row_to_webhook_endpoint(&r)));
        tx.commit().await.map_err(map_err)?;
        res
    }

    async fn list_endpoints(
        &self,
        account_id: AccountId,
        page: PageQuery,
    ) -> Result<Page<WebhookEndpoint>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let rows = query(
            "SELECT * FROM webhook_endpoints WHERE account_id=$1 AND ($2 IS NULL OR id < $2) \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(account_id.0)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        let data: Vec<WebhookEndpoint> = rows
            .iter()
            .map(row_to_webhook_endpoint)
            .collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        tx.commit().await.map_err(map_err)?;
        Ok(Page { data, next_cursor })
    }

    async fn enqueue(&self, e: &WebhookEvent) -> Result<WebhookEvent> {
        let payload = serde_json::to_value(&e.payload)
            .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, e.account_id).await?;
        query(
            "INSERT INTO webhook_events (id, account_id, endpoint_id, event_type, payload, attempts, delivered, last_response_status, last_error, next_retry_at, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(e.id.0)
        .bind(e.account_id.0)
        .bind(e.endpoint_id.0)
        .bind(&e.event_type)
        .bind(&payload)
        .bind(e.attempts as i32)
        .bind(e.delivered)
        .bind(e.last_response_status.map(|v| v as i32))
        .bind(&e.last_error)
        .bind(e.next_retry_at)
        .bind(e.created_at)
        .bind(e.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(e.clone())
    }

    async fn due(&self, now: OffsetDateTime, limit: u32) -> Result<Vec<WebhookEvent>> {
        // Cross-tenant sweep — runs as the owner role (bypasses RLS).
        let rows = query(
            "SELECT * FROM webhook_events WHERE delivered=false AND (next_retry_at IS NULL OR next_retry_at <= $1) \
             ORDER BY created_at LIMIT $2",
        )
        .bind(now)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        rows.iter().map(row_to_webhook_event).collect()
    }

    async fn mark_attempt(
        &self,
        id: WebhookEventId,
        delivered: bool,
        status: Option<u16>,
        error: Option<String>,
        next_retry_at: Option<OffsetDateTime>,
    ) -> Result<()> {
        query(
            "UPDATE webhook_events SET attempts = attempts + 1, delivered=$2, last_response_status=$3, last_error=$4, next_retry_at=$5, updated_at=$6 \
             WHERE id=$1",
        )
        .bind(id.0)
        .bind(delivered)
        .bind(status.map(|v| v as i32))
        .bind(&error)
        .bind(next_retry_at)
        .bind(OffsetDateTime::now_utc())
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }
}

fn webhook_status_str(s: WebhookStatus) -> &'static str {
    match s {
        WebhookStatus::Active => "active",
        WebhookStatus::Disabled => "disabled",
    }
}
fn webhook_status_from_str(s: &str) -> WebhookStatus {
    match s {
        "disabled" => WebhookStatus::Disabled,
        _ => WebhookStatus::Active,
    }
}

fn row_to_webhook_endpoint(row: &sqlx::postgres::PgRow) -> Result<WebhookEndpoint> {
    let id: uuid::Uuid = row.try_get("id").map_err(dbtype)?;
    let aid: uuid::Uuid = row.try_get("account_id").map_err(dbtype)?;
    let url: String = row.try_get("url").map_err(dbtype)?;
    let ets: serde_json::Value = row.try_get("event_types").map_err(dbtype)?;
    let secret: String = row.try_get("secret").map_err(dbtype)?;
    let status: String = row.try_get("status").map_err(dbtype)?;
    let md: serde_json::Value = row.try_get("metadata").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(WebhookEndpoint {
        id: WebhookEndpointId(id),
        account_id: AccountId(aid),
        url,
        event_types: serde_json::from_value(ets).unwrap_or_default(),
        secret,
        status: webhook_status_from_str(&status),
        metadata: meta(md),
        created_at,
        updated_at,
    })
}

fn row_to_webhook_event(row: &sqlx::postgres::PgRow) -> Result<WebhookEvent> {
    let id: uuid::Uuid = row.try_get("id").map_err(dbtype)?;
    let aid: uuid::Uuid = row.try_get("account_id").map_err(dbtype)?;
    let eid: uuid::Uuid = row.try_get("endpoint_id").map_err(dbtype)?;
    let event_type: String = row.try_get("event_type").map_err(dbtype)?;
    let payload: serde_json::Value = row.try_get("payload").map_err(dbtype)?;
    let attempts: i32 = row.try_get("attempts").map_err(dbtype)?;
    let delivered: bool = row.try_get("delivered").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(WebhookEvent {
        id: WebhookEventId(id),
        account_id: AccountId(aid),
        endpoint_id: WebhookEndpointId(eid),
        event_type,
        payload: serde_json::from_value(payload).unwrap_or_default(),
        attempts: attempts as u32,
        delivered,
        last_response_status: row
            .try_get::<Option<i32>, _>("last_response_status")
            .map_err(dbtype)?
            .map(|v| v as u16),
        last_error: row.try_get("last_error").map_err(dbtype)?,
        next_retry_at: row.try_get("next_retry_at").map_err(dbtype)?,
        created_at,
        updated_at,
    })
}

// ── EventLog (tenant-scoped — RLS) ─────────────────────────────────────

#[async_trait::async_trait]
impl EventLogRepo for super::pg::PostgresRepository {
    async fn append(&self, e: &EventLog) -> Result<EventLogId> {
        let payload = serde_json::to_value(&e.payload)
            .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, e.account_id).await?;
        query(
            "INSERT INTO event_log (id, account_id, event_type, severity, actor_id, resource_type, resource_id, payload, request_id, ip, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(e.id.0)
        .bind(e.account_id.0)
        .bind(&e.event_type)
        .bind(severity_str(e.severity))
        .bind(&e.actor_id)
        .bind(&e.resource_type)
        .bind(&e.resource_id)
        .bind(&payload)
        .bind(&e.request_id)
        .bind(&e.ip)
        .bind(e.created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(e.id)
    }

    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<EventLog>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let rows = query(
            "SELECT * FROM event_log WHERE account_id=$1 AND ($2 IS NULL OR id < $2) \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(account_id.0)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        let data: Vec<EventLog> = rows.iter().map(row_to_event_log).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        tx.commit().await.map_err(map_err)?;
        Ok(Page { data, next_cursor })
    }
}

fn severity_str(s: EventSeverity) -> &'static str {
    match s {
        EventSeverity::Info => "info",
        EventSeverity::Warning => "warning",
        EventSeverity::Critical => "critical",
    }
}
fn severity_from_str(s: &str) -> EventSeverity {
    match s {
        "warning" => EventSeverity::Warning,
        "critical" => EventSeverity::Critical,
        _ => EventSeverity::Info,
    }
}

fn row_to_event_log(row: &sqlx::postgres::PgRow) -> Result<EventLog> {
    let id: uuid::Uuid = row.try_get("id").map_err(dbtype)?;
    let aid: uuid::Uuid = row.try_get("account_id").map_err(dbtype)?;
    let event_type: String = row.try_get("event_type").map_err(dbtype)?;
    let severity: String = row.try_get("severity").map_err(dbtype)?;
    let payload: serde_json::Value = row.try_get("payload").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    Ok(EventLog {
        id: EventLogId(id),
        account_id: AccountId(aid),
        event_type,
        severity: severity_from_str(&severity),
        actor_id: row.try_get("actor_id").map_err(dbtype)?,
        resource_type: row.try_get("resource_type").map_err(dbtype)?,
        resource_id: row.try_get("resource_id").map_err(dbtype)?,
        payload: serde_json::from_value(payload).unwrap_or_default(),
        request_id: row.try_get("request_id").map_err(dbtype)?,
        ip: row.try_get("ip").map_err(dbtype)?,
        created_at,
    })
}

impl IdStr for WebhookEndpoint {
    fn id_str(&self) -> String {
        self.id.0.to_string()
    }
}
impl IdStr for EventLog {
    fn id_str(&self) -> String {
        self.id.0.to_string()
    }
}
