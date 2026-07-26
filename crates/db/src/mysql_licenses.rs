//! MySQL impl of [`LicenseRepo`] for [`MysqlRepository`].

use super::mysql::{
    cursor_after, dbtype, get_uuid, meta, meta_json, next_cursor, query, uuid_to_bin, IdStr,
};
use crate::error::{map_err, not_found};
use license_domain::error::Result;
use license_domain::repository::{LicenseRepo, Page, PageQuery};
use license_domain::*;
use sqlx::Row;
use time::OffsetDateTime;

#[async_trait::async_trait]
impl LicenseRepo for super::mysql::MysqlRepository {
    async fn create(&self, license: &License) -> Result<License> {
        let md = meta_json(&license.metadata);
        query(
            "INSERT INTO licenses (\
               id, account_id, product_id, policy_id, key_hash, state, license_type, \
               uses, max_uses, expiry_basis, expiry_strategy, expiry, last_check_in, \
               next_check_in, overdue_check_ins, metadata, created_at, updated_at\
             ) VALUES (\
               ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?\
             )",
        )
        .bind(uuid_to_bin(license.id.0))
        .bind(uuid_to_bin(license.account_id.0))
        .bind(uuid_to_bin(license.product_id.0))
        .bind(uuid_to_bin(license.policy_id.0))
        .bind(&license.key_hash)
        .bind(license_state_str(license.state))
        .bind(license_type_str(license.license_type))
        .bind(license.uses as i64)
        .bind(license.max_uses.map(|v| v as i64))
        .bind(expiry_basis_str(license.expiry_basis))
        .bind(expiry_strategy_str(license.expiry_strategy))
        .bind(license.expiry)
        .bind(license.last_check_in)
        .bind(license.next_check_in)
        .bind(license.overdue_check_ins as i32)
        .bind(&md)
        .bind(license.created_at)
        .bind(license.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as LicenseRepo>::get(self, license.account_id, license.id).await
    }

    async fn get(&self, account_id: AccountId, id: LicenseId) -> Result<License> {
        let row = query("SELECT * FROM licenses WHERE account_id=? AND id=?")
            .bind(uuid_to_bin(account_id.0))
            .bind(uuid_to_bin(id.0))
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        not_found(row.map(|r| row_to_license(&r)))
    }

    async fn get_by_key_hash(&self, key_hash: &str) -> Result<License> {
        // Global lookup by key hash (the hash has 256 bits of entropy and is
        // globally unique). Tenancy is enforced because subsequent reads on
        // related resources take the account_id from the license row.
        let row = query("SELECT * FROM licenses WHERE key_hash=?")
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
        let policy_id = policy_id.map(|p| uuid_to_bin(p.0));
        let rows = query(
            "SELECT * FROM licenses WHERE account_id=? \
             AND (? IS NULL OR policy_id=?) \
             AND (? IS NULL OR id < ?) \
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(uuid_to_bin(account_id.0))
        .bind(policy_id.clone())
        .bind(policy_id)
        .bind(after_id.map(uuid_to_bin))
        .bind(after_id.map(uuid_to_bin))
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
        query(
            "UPDATE licenses SET state=?, license_type=?, uses=?, max_uses=?, \
             expiry_basis=?, expiry_strategy=?, expiry=?, last_check_in=?, \
             next_check_in=?, overdue_check_ins=?, metadata=?, updated_at=? \
             WHERE account_id=? AND id=?",
        )
        .bind(license_state_str(license.state))
        .bind(license_type_str(license.license_type))
        .bind(license.uses as i64)
        .bind(license.max_uses.map(|v| v as i64))
        .bind(expiry_basis_str(license.expiry_basis))
        .bind(expiry_strategy_str(license.expiry_strategy))
        .bind(license.expiry)
        .bind(license.last_check_in)
        .bind(license.next_check_in)
        .bind(license.overdue_check_ins as i32)
        .bind(&md)
        .bind(license.updated_at)
        .bind(uuid_to_bin(license.account_id.0))
        .bind(uuid_to_bin(license.id.0))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as LicenseRepo>::get(self, license.account_id, license.id).await
    }

    async fn expire_due(&self, now: OffsetDateTime) -> Result<u64> {
        let res = query(
            "UPDATE licenses SET state='expired' \
             WHERE state='active' AND expiry IS NOT NULL AND expiry < ?",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(res.rows_affected())
    }

    async fn mark_overdue_check_ins(&self, now: OffsetDateTime) -> Result<u64> {
        let res = query(
            "UPDATE licenses SET overdue_check_ins = overdue_check_ins + 1 \
             WHERE state='active' AND next_check_in IS NOT NULL AND next_check_in < ?",
        )
        .bind(now)
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

fn row_to_license(row: &sqlx::mysql::MySqlRow) -> Result<License> {
    let id = get_uuid(row, "id")?;
    let aid = get_uuid(row, "account_id")?;
    let pid = get_uuid(row, "product_id")?;
    let poid = get_uuid(row, "policy_id")?;
    let key_hash: String = row.try_get("key_hash").map_err(dbtype)?;
    let state: String = row.try_get("state").map_err(dbtype)?;
    let ltype: String = row.try_get("license_type").map_err(dbtype)?;
    let md: serde_json::Value = row.try_get("metadata").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(License {
        id: LicenseId(id),
        account_id: AccountId(aid),
        product_id: ProductId(pid),
        policy_id: PolicyId(poid),
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
        expiry: row.try_get("expiry").map_err(dbtype)?,
        last_check_in: row.try_get("last_check_in").map_err(dbtype)?,
        next_check_in: row.try_get("next_check_in").map_err(dbtype)?,
        overdue_check_ins: row.try_get::<i32, _>("overdue_check_ins").map_err(dbtype)? as u32,
        metadata: meta(md),
        created_at,
        updated_at,
    })
}

impl IdStr for License {
    fn id_str(&self) -> String {
        self.id.to_string()
    }
}
