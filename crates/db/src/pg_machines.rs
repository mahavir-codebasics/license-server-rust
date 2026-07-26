//! PostgreSQL impl of [`MachineRepo`] for [`PostgresRepository`].
//!
//! `machines` is RLS-protected; every method sets `app.account_id` first.

use super::pg::{
    cursor_after, dbtype, meta, meta_json, next_cursor, query, query_as, set_account_id, IdStr,
};
use crate::error::{map_err, not_found};
use license_domain::error::Result;
use license_domain::repository::{MachineRepo, Page, PageQuery};
use license_domain::*;
use sqlx::Row;
use time::OffsetDateTime;

#[async_trait::async_trait]
impl MachineRepo for super::pg::PostgresRepository {
    async fn create(&self, machine: &Machine) -> Result<Machine> {
        let md = meta_json(&machine.metadata);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, machine.account_id).await?;
        query(
            "INSERT INTO machines (\
               id, account_id, license_id, fingerprint, name, platform, core_count, metadata, \
               state, cull_strategy, resurrection_strategy, last_heartbeat, next_heartbeat, \
               created_at, updated_at\
             ) VALUES (\
               $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15\
             )",
        )
        .bind(machine.id.0)
        .bind(machine.account_id.0)
        .bind(machine.license_id.0)
        .bind(&machine.fingerprint)
        .bind(&machine.name)
        .bind(&machine.platform)
        .bind(machine.core_count.map(|v| v as i32))
        .bind(&md)
        .bind(machine_state_str(machine.state))
        .bind(cull_str(machine.cull_strategy))
        .bind(resurrect_str(machine.resurrection_strategy))
        .bind(machine.last_heartbeat)
        .bind(machine.next_heartbeat)
        .bind(machine.created_at)
        .bind(machine.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as MachineRepo>::get(self, machine.account_id, machine.id).await
    }

    async fn get(&self, account_id: AccountId, id: MachineId) -> Result<Machine> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let row = query("SELECT * FROM machines WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_err)?;
        let res = not_found(row.map(|r| row_to_machine(&r)));
        tx.commit().await.map_err(map_err)?;
        res
    }

    async fn get_by_fingerprint(
        &self,
        account_id: AccountId,
        license_id: LicenseId,
        fingerprint: &str,
    ) -> Result<Machine> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let row = query(
            "SELECT * FROM machines WHERE account_id=$1 AND license_id=$2 AND fingerprint=$3",
        )
        .bind(account_id.0)
        .bind(license_id.0)
        .bind(fingerprint)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        let res = not_found(row.map(|r| row_to_machine(&r)));
        tx.commit().await.map_err(map_err)?;
        res
    }

    async fn list(
        &self,
        account_id: AccountId,
        license_id: Option<LicenseId>,
        page: PageQuery,
    ) -> Result<Page<Machine>> {
        let limit = page.limit as i64;
        let after_id = cursor_after(&page);
        let license_id = license_id.map(|l| l.0);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let rows = query(
            "SELECT * FROM machines WHERE account_id=$1 \
             AND ($2 IS NULL OR license_id=$2) \
             AND ($3 IS NULL OR id < $3) \
             ORDER BY created_at DESC LIMIT $4",
        )
        .bind(account_id.0)
        .bind(license_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        let data: Vec<Machine> = rows.iter().map(row_to_machine).collect::<Result<_>>()?;
        let next_cursor = next_cursor(&data, page.limit);
        tx.commit().await.map_err(map_err)?;
        Ok(Page { data, next_cursor })
    }

    async fn update(&self, machine: &Machine) -> Result<Machine> {
        let md = meta_json(&machine.metadata);
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, machine.account_id).await?;
        query(
            "UPDATE machines SET fingerprint=$3, name=$4, platform=$5, core_count=$6, \
             metadata=$7, state=$8, cull_strategy=$9, resurrection_strategy=$10, \
             last_heartbeat=$11, next_heartbeat=$12, updated_at=$13 \
             WHERE account_id=$1 AND id=$2",
        )
        .bind(machine.account_id.0)
        .bind(machine.id.0)
        .bind(&machine.fingerprint)
        .bind(&machine.name)
        .bind(&machine.platform)
        .bind(machine.core_count.map(|v| v as i32))
        .bind(&md)
        .bind(machine_state_str(machine.state))
        .bind(cull_str(machine.cull_strategy))
        .bind(resurrect_str(machine.resurrection_strategy))
        .bind(machine.last_heartbeat)
        .bind(machine.next_heartbeat)
        .bind(machine.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        <Self as MachineRepo>::get(self, machine.account_id, machine.id).await
    }

    async fn delete(&self, account_id: AccountId, id: MachineId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        query("DELETE FROM machines WHERE account_id=$1 AND id=$2")
            .bind(account_id.0)
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(())
    }

    async fn count_active(&self, account_id: AccountId, license_id: LicenseId) -> Result<u64> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        set_account_id(&mut tx, account_id).await?;
        let (count,): (i64,) = query_as(
            "SELECT COUNT(*) FROM machines WHERE account_id=$1 AND license_id=$2 AND state='active'",
        )
        .bind(account_id.0)
        .bind(license_id.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(count as u64)
    }

    async fn cull_dead(&self, now: OffsetDateTime) -> Result<u64> {
        // Cross-tenant sweep — runs as the owner role (bypasses RLS), mirrors
        // the SQLite/MySQL behavior.
        let res = query(
            "UPDATE machines SET state='dead' \
             WHERE state='active' AND cull_strategy='deactivate_dead' \
             AND next_heartbeat IS NOT NULL AND next_heartbeat < $1",
        )
        .bind(now)
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

fn row_to_machine(row: &sqlx::postgres::PgRow) -> Result<Machine> {
    let id: uuid::Uuid = row.try_get("id").map_err(dbtype)?;
    let aid: uuid::Uuid = row.try_get("account_id").map_err(dbtype)?;
    let lid: uuid::Uuid = row.try_get("license_id").map_err(dbtype)?;
    let fp: String = row.try_get("fingerprint").map_err(dbtype)?;
    let name: Option<String> = row.try_get("name").map_err(dbtype)?;
    let platform: Option<String> = row.try_get("platform").map_err(dbtype)?;
    let md: serde_json::Value = row.try_get("metadata").map_err(dbtype)?;
    let state: String = row.try_get("state").map_err(dbtype)?;
    let cull: String = row.try_get("cull_strategy").map_err(dbtype)?;
    let res: String = row.try_get("resurrection_strategy").map_err(dbtype)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(dbtype)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(dbtype)?;
    Ok(Machine {
        id: MachineId(id),
        account_id: AccountId(aid),
        license_id: LicenseId(lid),
        fingerprint: fp,
        name,
        platform,
        core_count: row
            .try_get::<Option<i32>, _>("core_count")
            .map_err(dbtype)?
            .map(|v| v as u32),
        metadata: meta(md),
        state: machine_state_from_str(&state),
        cull_strategy: cull_from_str(&cull),
        resurrection_strategy: resurrect_from_str(&res),
        last_heartbeat: row.try_get("last_heartbeat").map_err(dbtype)?,
        next_heartbeat: row.try_get("next_heartbeat").map_err(dbtype)?,
        created_at,
        updated_at,
    })
}

impl IdStr for Machine {
    fn id_str(&self) -> String {
        self.id.to_string()
    }
}
