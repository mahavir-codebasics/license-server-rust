//! Machine — a device a license is activated on (node-locking / floating).

use crate::account::AccountId;
use crate::license::LicenseId;
use crate::value::Metadata;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

declare_id!(MachineId, "Identifier of a [`Machine`].");

/// Lifecycle state of a machine binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MachineState {
    #[default]
    Active,
    /// Heartbeat lapsed; will be culled by the sweeper job per [`CullStrategy`].
    Dead,
    Deactivated,
}

/// What the cull-dead-machines job does with machines whose heartbeat expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CullStrategy {
    /// Deactivate dead machines, freeing a floating slot.
    #[default]
    DeactivateDead,
    /// Leave dead machines bound (counts against max_machines).
    KeepDead,
}

/// Whether a dead machine can come back to life on the next heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResurrectionStrategy {
    #[default]
    NoRevive,
    AlwaysRevive,
}

/// Heartbeat evaluation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatStatus {
    /// Heartbeat current; machine is alive.
    Alive,
    /// Heartbeat overdue; machine is now dead.
    Dead,
}

/// A device bound to a license, addressed by `fingerprint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    pub id: MachineId,
    pub account_id: AccountId,
    pub license_id: LicenseId,

    /// Client-supplied unique device id (e.g. MAC hash, hardware UUID).
    pub fingerprint: String,
    /// Optional friendly name.
    pub name: Option<String>,
    /// Optional IP / platform metadata.
    pub platform: Option<String>,
    pub core_count: Option<u32>,
    pub metadata: Metadata,

    pub state: MachineState,
    pub cull_strategy: CullStrategy,
    pub resurrection_strategy: ResurrectionStrategy,

    pub last_heartbeat: Option<OffsetDateTime>,
    pub next_heartbeat: Option<OffsetDateTime>,

    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Machine {
    pub fn new(
        account_id: AccountId,
        license_id: LicenseId,
        fingerprint: impl Into<String>,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: MachineId::now(),
            account_id,
            license_id,
            fingerprint: fingerprint.into(),
            name: None,
            platform: None,
            core_count: None,
            metadata: Metadata::new(),
            state: MachineState::Active,
            cull_strategy: CullStrategy::default(),
            resurrection_strategy: ResurrectionStrategy::default(),
            last_heartbeat: Some(now),
            next_heartbeat: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Record a heartbeat; resets state to Active if revival is allowed.
    pub fn ping(&mut self, heartbeat: Duration) {
        let now = OffsetDateTime::now_utc();
        self.last_heartbeat = Some(now);
        self.next_heartbeat = Some(now + heartbeat);
        if self.state == MachineState::Dead
            && self.resurrection_strategy == ResurrectionStrategy::AlwaysRevive
        {
            self.state = MachineState::Active;
        }
        self.updated_at = now;
    }

    /// Returns `Dead` if the heartbeat window has elapsed and the machine
    /// is still marked Active (caller transitions per cull strategy).
    pub fn evaluate_heartbeat(&self, now: OffsetDateTime) -> HeartbeatStatus {
        match self.next_heartbeat {
            Some(due) if now >= due && self.state == MachineState::Active => HeartbeatStatus::Dead,
            _ => HeartbeatStatus::Alive,
        }
    }

    pub fn deactivate(&mut self) {
        self.state = MachineState::Deactivated;
        self.updated_at = OffsetDateTime::now_utc();
    }
}

use std::time::Duration;
