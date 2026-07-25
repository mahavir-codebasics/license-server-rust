//! SQLite impl of [`MachineRepo`] for [`SqliteRepository`].

use super::sqlite::{
    badid, cursor_after, dbtype, meta, meta_json, next_cursor, parse_ts, ts, IdStr,
};
use crate::error::{map_err, not_found};
use license_domain::error::Result;
use license_domain::repository::{MachineRepo, Page, PageQuery};
use license_domain::*;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

#[async_trait::async_trait]
impl MachineRepo for super::sqlite::SqliteRepository {
    async fn create(&self, machine: &Machine) -> Result<Machine> {
        let md = meta_json(&machine.metadata);
        sqlx::query(
            "INSERT INTO machines (\
               id, account_id, license_id, fingerprint, name, platform, core_count, metadata, \
               state, cull_strategy, resurrection_strategy, last_heartbeat, next_heartbeat, \
               created_at, updated_at\
             ) VALUES (\
               ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15\
             )",
        )
        .bind(machine.id.to_string())
        .bind(machine.account_id.to_string())
        .bind(machine.license_id.to_string())
        .bind(&machine.fingerprint)
        .bind(&machine.name)
        .bind(&machine.platform)
        .bind(machine.core_count.map(|v| v as i64))
        .bind(&md)
        .bind(machine_state_str(machine.state))
        .bind(cull_str(machine.cull_strategy))
        .bind(resurrect_str(machine.resurrection_strategy))
        .bind(super::sqlite::opt_ts(machine.last_heartbeat))
        .bind(super::sqlite::opt_ts(machine.next_heartbeat))
        .bind(ts(machine.created_at))
        .bind(ts(machine.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as MachineRepo>::get(self, machine.account_id, machine.id).await
    }

    async fn get(&self, account_id: AccountId, id: MachineId) -> Result<Machine> {
        let row = sqlx::query("SELECT * FROM machines WHERE account_id=?1 AND id=?2")
            .bind(account_id.to_string())
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;
        not_found(row.map(|r| row_to_machine(&r)))
    }

    async fn get_by_fingerprint(
        &self,
        account_id: AccountId,
        license_id: LicenseId,
        fingerprint: &str,
    ) -> Result<Machine> {
        let row = sqlx::query(
            "SELECT * FROM machines WHERE account_id=?1 AND license_id=?2 AND fingerprint=?3",
        )
        .bind(account_id.to_string())
        .bind(license_id.to_string())
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        not_found(row.map(|r| row_to_machine(&r)))
    }

    async fn list(
        &self,
        account_id: AccountId,
        license_id: Option<LicenseId>,
        page: PageQuery,
    ) -> Result<Page<Machine>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let license_id = license_id.map(|l| l.to_string());
        let rows = sqlx::query(
            "SELECT * FROM machines WHERE account_id=?1 \
             AND (?2 IS NULL OR license_id=?2) \
             AND (?3 IS NULL OR id < ?3) \
             ORDER BY created_at DESC LIMIT ?4",
        )
        .bind(account_id.to_string())
        .bind(license_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let data: Vec<Machine> = rows.iter().map(row_to_machine).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        Ok(Page { data, next_cursor })
    }

    async fn update(&self, machine: &Machine) -> Result<Machine> {
        let md = meta_json(&machine.metadata);
        sqlx::query(
            "UPDATE machines SET fingerprint=?3, name=?4, platform=?5, core_count=?6, \
             metadata=?7, state=?8, cull_strategy=?9, resurrection_strategy=?10, \
             last_heartbeat=?11, next_heartbeat=?12, updated_at=?13 \
             WHERE account_id=?1 AND id=?2",
        )
        .bind(machine.account_id.to_string())
        .bind(machine.id.to_string())
        .bind(&machine.fingerprint)
        .bind(&machine.name)
        .bind(&machine.platform)
        .bind(machine.core_count.map(|v| v as i64))
        .bind(&md)
        .bind(machine_state_str(machine.state))
        .bind(cull_str(machine.cull_strategy))
        .bind(resurrect_str(machine.resurrection_strategy))
        .bind(super::sqlite::opt_ts(machine.last_heartbeat))
        .bind(super::sqlite::opt_ts(machine.next_heartbeat))
        .bind(ts(machine.updated_at))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        <Self as MachineRepo>::get(self, machine.account_id, machine.id).await
    }

    async fn delete(&self, account_id: AccountId, id: MachineId) -> Result<()> {
        sqlx::query("DELETE FROM machines WHERE account_id=?1 AND id=?2")
            .bind(account_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn count_active(&self, account_id: AccountId, license_id: LicenseId) -> Result<u64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM machines WHERE account_id=?1 AND license_id=?2 AND state='active'",
        )
        .bind(account_id.to_string())
        .bind(license_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(count as u64)
    }

    async fn cull_dead(&self, now: OffsetDateTime) -> Result<u64> {
        // Per the policy's cull strategy: deactivate_dead machines whose
        // heartbeat window has elapsed. keep_dead is a no-op.
        let res = sqlx::query(
            "UPDATE machines SET state='dead' \
             WHERE state='active' AND cull_strategy='deactivate_dead' \
             AND next_heartbeat IS NOT NULL AND next_heartbeat < ?1",
        )
        .bind(ts(now))
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(res.rows_affected())
    }
}

fn machine_state_str(s: MachineState) -> &'static str {
    match s {
        MachineState::Active => "active",
        MachineState::Dead => "dead",
        MachineState::Deactivated => "deactivated",
    }
}
fn machine_state_from_str(s: &str) -> MachineState {
    match s {
        "dead" => MachineState::Dead,
        "deactivated" => MachineState::Deactivated,
        _ => MachineState::Active,
    }
}
fn cull_str(c: CullStrategy) -> &'static str {
    match c {
        CullStrategy::DeactivateDead => "deactivate_dead",
        CullStrategy::KeepDead => "keep_dead",
    }
}
fn resurrect_str(r: ResurrectionStrategy) -> &'static str {
    match r {
        ResurrectionStrategy::NoRevive => "no_revive",
        ResurrectionStrategy::AlwaysRevive => "always_revive",
    }
}
fn resurrect_from_str(s: &str) -> ResurrectionStrategy {
    match s {
        "always_revive" => ResurrectionStrategy::AlwaysRevive,
        _ => ResurrectionStrategy::NoRevive,
    }
}
fn cull_from_str(s: &str) -> CullStrategy {
    match s {
        "keep_dead" => CullStrategy::KeepDead,
        _ => CullStrategy::DeactivateDead,
    }
}

fn opt_ts(v: Option<String>) -> Result<Option<time::OffsetDateTime>> {
    match v {
        Some(s) => parse_ts(&s).map(Some),
        None => Ok(None),
    }
}

fn row_to_machine(row: &sqlx::sqlite::SqliteRow) -> Result<Machine> {
    let id: String = row.try_get("id").map_err(dbtype)?;
    let aid: String = row.try_get("account_id").map_err(dbtype)?;
    let lid: String = row.try_get("license_id").map_err(dbtype)?;
    let fp: String = row.try_get("fingerprint").map_err(dbtype)?;
    let name: Option<String> = row.try_get("name").map_err(dbtype)?;
    let platform: Option<String> = row.try_get("platform").map_err(dbtype)?;
    let md: String = row.try_get("metadata").map_err(dbtype)?;
    let state: String = row.try_get("state").map_err(dbtype)?;
    let cull: String = row.try_get("cull_strategy").map_err(dbtype)?;
    let res: String = row.try_get("resurrection_strategy").map_err(dbtype)?;
    let ca: String = row.try_get("created_at").map_err(dbtype)?;
    let ua: String = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Machine {
        id: MachineId(Uuid::parse_str(&id).map_err(badid)?),
        account_id: AccountId(Uuid::parse_str(&aid).map_err(badid)?),
        license_id: LicenseId(Uuid::parse_str(&lid).map_err(badid)?),
        fingerprint: fp,
        name,
        platform,
        core_count: row
            .try_get::<Option<i64>, _>("core_count")
            .map_err(dbtype)?
            .map(|v| v as u32),
        metadata: meta(&md),
        state: machine_state_from_str(&state),
        cull_strategy: cull_from_str(&cull),
        resurrection_strategy: resurrect_from_str(&res),
        last_heartbeat: opt_ts(
            row.try_get::<Option<String>, _>("last_heartbeat")
                .map_err(dbtype)?,
        )?,
        next_heartbeat: opt_ts(
            row.try_get::<Option<String>, _>("next_heartbeat")
                .map_err(dbtype)?,
        )?,
        created_at: parse_ts(&ca)?,
        updated_at: parse_ts(&ua)?,
    })
}

impl IdStr for Machine {
    fn id_str(&self) -> String {
        self.id.to_string()
    }
}
