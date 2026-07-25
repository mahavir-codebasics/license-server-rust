//! SQLite impl of [`LicenseRepo`] for [`SqliteRepository`].

use super::sqlite::{
    badid, cursor_after, dbtype, meta, meta_json, next_cursor, parse_ts, ts, IdStr,
};
use crate::error::{map_err, not_found};
use license_domain::error::Result;
use license_domain::repository::{LicenseRepo, Page, PageQuery};
use license_domain::*;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

#[async_trait::async_trait]
impl LicenseRepo for super::sqlite::SqliteRepository {
    async fn create(&self, license: &License) -> Result<License> {
        let md = meta_json(&license.metadata);
        sqlx::query(
            "INSERT INTO licenses (\
               id, account_id, product_id, policy_id, key_hash, state, license_type, \
               uses, max_uses, expiry_basis, expiry_strategy, expiry, last_check_in, \
               next_check_in, overdue_check_ins, metadata, created_at, updated_at\
             ) VALUES (\
               ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18\
             )",
        )
        .bind(license.id.to_string())
        .bind(license.account_id.to_string())
        .bind(license.product_id.to_string())
        .bind(license.policy_id.to_string())
        .bind(&license.key_hash)
        .bind(license_state_str(license.state))
        .bind(license_type_str(license.license_type))
        .bind(license.uses as i64)
        .bind(license.max_uses.map(|v| v as i64))
        .bind(expiry_basis_str(license.expiry_basis))
        .bind(expiry_strategy_str(license.expiry_strategy))
        .bind(super::sqlite::opt_ts(license.expiry))
        .bind(super::sqlite::opt_ts(license.last_check_in))
        .bind(super::sqlite::opt_ts(license.next_check_in))
        .bind(license.overdue_check_ins as i64)
        .bind(&md)
        .bind(ts(license.created_at))
        .bind(ts(license.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as LicenseRepo>::get(self, license.account_id, license.id).await
    }

    async fn get(&self, account_id: AccountId, id: LicenseId) -> Result<License> {
        let row = sqlx::query("SELECT * FROM licenses WHERE account_id=?1 AND id=?2")
            .bind(account_id.to_string())
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        not_found(row.map(|r| row_to_license(&r)))
    }

    async fn get_by_key_hash(&self, key_hash: &str) -> Result<License> {
        // Global lookup by key hash (the hash has 256 bits of entropy and is
        // globally unique). Tenancy is enforced because subsequent reads on
        // related resources take the account_id from the license row.
        let row = sqlx::query("SELECT * FROM licenses WHERE key_hash=?1")
            .bind(key_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        not_found(row.map(|r| row_to_license(&r)))
    }

    async fn list(
        &self,
        account_id: AccountId,
        policy_id: Option<PolicyId>,
        page: PageQuery,
    ) -> Result<Page<License>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let policy_id = policy_id.map(|p| p.to_string());
        let rows = sqlx::query(
            "SELECT * FROM licenses WHERE account_id=?1 \
             AND (?2 IS NULL OR policy_id=?2) \
             AND (?3 IS NULL OR id < ?3) \
             ORDER BY created_at DESC LIMIT ?4",
        )
        .bind(account_id.to_string())
        .bind(policy_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let data: Vec<License> = rows.iter().map(row_to_license).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        Ok(Page { data, next_cursor })
    }

    async fn update(&self, license: &License) -> Result<License> {
        let md = meta_json(&license.metadata);
        sqlx::query(
            "UPDATE licenses SET state=?3, license_type=?4, uses=?5, max_uses=?6, \
             expiry_basis=?7, expiry_strategy=?8, expiry=?9, last_check_in=?10, \
             next_check_in=?11, overdue_check_ins=?12, metadata=?13, updated_at=?14 \
             WHERE account_id=?1 AND id=?2",
        )
        .bind(license.account_id.to_string())
        .bind(license.id.to_string())
        .bind(license_state_str(license.state))
        .bind(license_type_str(license.license_type))
        .bind(license.uses as i64)
        .bind(license.max_uses.map(|v| v as i64))
        .bind(expiry_basis_str(license.expiry_basis))
        .bind(expiry_strategy_str(license.expiry_strategy))
        .bind(super::sqlite::opt_ts(license.expiry))
        .bind(super::sqlite::opt_ts(license.last_check_in))
        .bind(super::sqlite::opt_ts(license.next_check_in))
        .bind(license.overdue_check_ins as i64)
        .bind(&md)
        .bind(ts(license.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as LicenseRepo>::get(self, license.account_id, license.id).await
    }

    async fn expire_due(&self, now: OffsetDateTime) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE licenses SET state='expired' \
             WHERE state='active' AND expiry IS NOT NULL AND expiry < ?1",
        )
        .bind(ts(now))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(res.rows_affected())
    }

    async fn mark_overdue_check_ins(&self, now: OffsetDateTime) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE licenses SET overdue_check_ins = overdue_check_ins + 1 \
             WHERE state='active' AND next_check_in IS NOT NULL AND next_check_in < ?1",
        )
        .bind(ts(now))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(res.rows_affected())
    }
}

fn license_state_str(s: LicenseState) -> &'static str {
    match s {
        LicenseState::Active => "active",
        LicenseState::Suspended => "suspended",
        LicenseState::Revoked => "revoked",
        LicenseState::Expired => "expired",
    }
}
fn license_state_from_str(s: &str) -> LicenseState {
    match s {
        "suspended" => LicenseState::Suspended,
        "revoked" => LicenseState::Revoked,
        "expired" => LicenseState::Expired,
        _ => LicenseState::Active,
    }
}
fn license_type_str(t: LicenseType) -> &'static str {
    match t {
        LicenseType::NodeLocked => "node_locked",
        LicenseType::Floating => "floating",
    }
}
fn license_type_from_str(s: &str) -> LicenseType {
    match s {
        "floating" => LicenseType::Floating,
        _ => LicenseType::NodeLocked,
    }
}
fn expiry_basis_str(b: ExpiryBasis) -> &'static str {
    match b {
        ExpiryBasis::FromCreation => "from_creation",
        ExpiryBasis::FromFirstActivation => "from_first_activation",
        ExpiryBasis::FromFirstValidation => "from_first_validation",
        ExpiryBasis::FromFirstUse => "from_first_use",
    }
}
fn expiry_basis_from_str(s: &str) -> ExpiryBasis {
    match s {
        "from_first_activation" => ExpiryBasis::FromFirstActivation,
        "from_first_validation" => ExpiryBasis::FromFirstValidation,
        "from_first_use" => ExpiryBasis::FromFirstUse,
        _ => ExpiryBasis::FromCreation,
    }
}
fn expiry_strategy_str(s: ExpiryStrategy) -> &'static str {
    match s {
        ExpiryStrategy::RestrictAccess => "restrict_access",
    }
}
fn expiry_strategy_from_str(_s: &str) -> ExpiryStrategy {
    ExpiryStrategy::RestrictAccess
}

fn row_to_license(row: &sqlx::sqlite::SqliteRow) -> Result<License> {
    let id: String = row.try_get("id").map_err(dbtype)?;
    let aid: String = row.try_get("account_id").map_err(dbtype)?;
    let pid: String = row.try_get("product_id").map_err(dbtype)?;
    let poid: String = row.try_get("policy_id").map_err(dbtype)?;
    let key_hash: String = row.try_get("key_hash").map_err(dbtype)?;
    let state: String = row.try_get("state").map_err(dbtype)?;
    let ltype: String = row.try_get("license_type").map_err(dbtype)?;
    let md: String = row.try_get("metadata").map_err(dbtype)?;
    let ca: String = row.try_get("created_at").map_err(dbtype)?;
    let ua: String = row.try_get("updated_at").map_err(dbtype)?;
    Ok(License {
        id: LicenseId(Uuid::parse_str(&id).map_err(badid)?),
        account_id: AccountId(Uuid::parse_str(&aid).map_err(badid)?),
        product_id: ProductId(Uuid::parse_str(&pid).map_err(badid)?),
        policy_id: PolicyId(Uuid::parse_str(&poid).map_err(badid)?),
        key: None, // never persisted; only set on create/checkout responses
        key_hash,
        state: license_state_from_str(&state),
        license_type: license_type_from_str(&ltype),
        uses: row.try_get::<i64, _>("uses").map_err(dbtype)? as u64,
        max_uses: row
            .try_get::<Option<i64>, _>("max_uses")
            .map_err(dbtype)?
            .map(|v| v as u64),
        expiry_basis: expiry_basis_from_str(
            &row.try_get::<String, _>("expiry_basis").map_err(dbtype)?,
        ),
        expiry_strategy: expiry_strategy_from_str(
            &row.try_get::<String, _>("expiry_strategy")
                .map_err(dbtype)?,
        ),
        expiry: opt_ts(
            row.try_get::<Option<String>, _>("expiry")
                .map_err(dbtype)?
                .as_deref(),
        )?,
        last_check_in: opt_ts(
            row.try_get::<Option<String>, _>("last_check_in")
                .map_err(dbtype)?
                .as_deref(),
        )?,
        next_check_in: opt_ts(
            row.try_get::<Option<String>, _>("next_check_in")
                .map_err(dbtype)?
                .as_deref(),
        )?,
        overdue_check_ins: row.try_get::<i64, _>("overdue_check_ins").map_err(dbtype)? as u32,
        metadata: meta(&md),
        created_at: parse_ts(&ca)?,
        updated_at: parse_ts(&ua)?,
    })
}

fn opt_ts(v: Option<&str>) -> Result<Option<OffsetDateTime>> {
    match v {
        Some(s) => parse_ts(s).map(Some),
        None => Ok(None),
    }
}

impl IdStr for License {
    fn id_str(&self) -> String {
        self.id.to_string()
    }
}
