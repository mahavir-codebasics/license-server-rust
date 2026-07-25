//! License — an issued instance of a [`crate::Policy`].
//!
//! Contains the license lifecycle state machine, metering counters, and
//! expiry math. The signed key string and license-file certificate are
//! produced by the `license-crypto` crate; this module is pure domain.

use crate::account::AccountId;
use crate::policy::PolicyId;
use crate::product::ProductId;
use crate::value::Metadata;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use time::OffsetDateTime;

declare_id!(LicenseId, "Identifier of a [`License`].");

/// Lifecycle state of a license.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LicenseState {
    /// Active and usable.
    #[default]
    Active,
    /// Temporarily suspended (administrative); can be reinstated.
    Suspended,
    /// Permanently revoked; cannot be reactivated.
    Revoked,
    /// Time-based expiry has passed.
    Expired,
}

impl LicenseState {
    /// A license in this state is considered valid for validation calls.
    #[inline]
    pub fn is_valid(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the state permits resurrection (suspend→active) but not
    /// creation of a brand-new active state from terminal ones.
    #[inline]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

/// Whether a license is node-locked (one-time activation) or floating
/// (revoked when heartbeat stops).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LicenseType {
    /// Node-locked: persistent activation.
    #[default]
    NodeLocked,
    /// Floating: requires periodic heartbeat.
    Floating,
}

/// When the duration clock starts ticking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryBasis {
    /// From license creation.
    #[default]
    FromCreation,
    /// From the first machine activation.
    FromFirstActivation,
    /// From the first successful validation.
    FromFirstValidation,
    /// From the first metered use.
    FromFirstUse,
}

/// What happens when a license expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryStrategy {
    /// License simply becomes invalid (returns EXPIRED on validate).
    #[default]
    RestrictAccess,
}

/// Metering counters for a license. `uses` is incremented/decremented via
/// the `increment-usage`/`decrement-usage` actions.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct UsageCounter {
    pub uses: u64,
    pub max_uses: Option<u64>,
}

impl UsageCounter {
    #[inline]
    pub fn is_at_capacity(self) -> bool {
        self.max_uses.is_some_and(|max| self.uses >= max)
    }
}

/// A license. The signed key string is held in `key` only at creation/response
/// time — persistence stores only `key_hash` (SHA-256) for lookup, never the
/// raw signed key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub id: LicenseId,
    pub account_id: AccountId,
    pub product_id: ProductId,
    pub policy_id: PolicyId,

    /// The signed key string (Ed25519/JWT/etc). Populated on create and
    /// checkout responses; **never persisted** in the clear.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// SHA-256 of the key, hex-encoded. This is what we persist + index.
    pub key_hash: String,

    pub state: LicenseState,
    pub license_type: LicenseType,

    /// Metering.
    pub uses: u64,
    pub max_uses: Option<u64>,

    /// Expiry.
    pub expiry_basis: ExpiryBasis,
    pub expiry_strategy: ExpiryStrategy,
    pub expiry: Option<OffsetDateTime>,

    /// Check-in tracking.
    pub last_check_in: Option<OffsetDateTime>,
    pub next_check_in: Option<OffsetDateTime>,
    pub overdue_check_ins: u32,

    pub metadata: Metadata,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl License {
    /// Construct a fresh active license. Caller fills in `key`/`key_hash`
    /// via the crypto layer after this.
    pub fn new(account_id: AccountId, product_id: ProductId, policy_id: PolicyId) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: LicenseId::now(),
            account_id,
            product_id,
            policy_id,
            key: None,
            key_hash: String::new(),
            state: LicenseState::Active,
            license_type: LicenseType::NodeLocked,
            uses: 0,
            max_uses: None,
            expiry_basis: ExpiryBasis::FromCreation,
            expiry_strategy: ExpiryStrategy::default(),
            expiry: None,
            last_check_in: None,
            next_check_in: None,
            overdue_check_ins: 0,
            metadata: Metadata::new(),
            created_at: now,
            updated_at: now,
        }
    }

    // — State machine —
    //
    // These are pure functions that return a Result; the repository persists
    // the resulting state. Centralizing transitions here makes them auditable.

    pub fn suspend(&mut self) -> Result<(), crate::error::DomainError> {
        match self.state {
            LicenseState::Active => {
                self.state = LicenseState::Suspended;
                self.touch();
                Ok(())
            }
            _ => Err(crate::error::DomainError::InvalidState(format!(
                "cannot suspend license in {:?} state",
                self.state
            ))),
        }
    }

    pub fn reinstate(&mut self) -> Result<(), crate::error::DomainError> {
        match self.state {
            LicenseState::Suspended => {
                self.state = LicenseState::Active;
                self.touch();
                Ok(())
            }
            _ => Err(crate::error::DomainError::InvalidState(format!(
                "cannot reinstate license in {:?} state",
                self.state
            ))),
        }
    }

    pub fn revoke(&mut self) -> Result<(), crate::error::DomainError> {
        if matches!(self.state, LicenseState::Revoked) {
            return Err(crate::error::DomainError::InvalidState(
                "license already revoked".into(),
            ));
        }
        self.state = LicenseState::Revoked;
        self.touch();
        Ok(())
    }

    pub fn renew(&mut self, duration: Duration) -> Result<(), crate::error::DomainError> {
        if self.state.is_terminal() {
            return Err(crate::error::DomainError::InvalidState(
                "cannot renew a revoked license".into(),
            ));
        }
        let now = OffsetDateTime::now_utc();
        let base = self.expiry.map(|e| e.max(now)).unwrap_or(now);
        self.expiry = Some(base + duration);
        if self.state == LicenseState::Expired {
            self.state = LicenseState::Active;
        }
        self.touch();
        Ok(())
    }

    pub fn expire(&mut self) {
        if self.state == LicenseState::Active || self.state == LicenseState::Suspended {
            self.state = LicenseState::Expired;
            self.touch();
        }
    }

    /// Increment metered usage, respecting `max_uses`.
    pub fn increment_usage(&mut self, n: u64) -> Result<(), crate::error::DomainError> {
        if let Some(max) = self.max_uses {
            if self.uses + n > max {
                return Err(crate::error::DomainError::PolicyViolated(
                    "usage would exceed max_uses".into(),
                ));
            }
        }
        self.uses = self.uses.saturating_add(n);
        self.touch();
        Ok(())
    }

    pub fn decrement_usage(&mut self, n: u64) {
        self.uses = self.uses.saturating_sub(n);
        self.touch();
    }

    pub fn reset_usage(&mut self) {
        self.uses = 0;
        self.touch();
    }

    pub fn check_in(&mut self, heartbeat: Duration) {
        let now = OffsetDateTime::now_utc();
        self.last_check_in = Some(now);
        self.next_check_in = Some(now + heartbeat);
        self.overdue_check_ins = 0;
        self.touch();
    }

    /// Mark one missed check-in window; returns true if the license should
    /// now be revoked (caller decides based on policy `max_overdue_check_ins`).
    pub fn mark_overdue(&mut self) -> bool {
        self.overdue_check_ins = self.overdue_check_ins.saturating_add(1);
        self.touch();
        true
    }

    /// Has this license's expiry passed?
    pub fn is_expired_at(&self, now: OffsetDateTime) -> bool {
        self.expiry.is_some_and(|e| now >= e)
    }

    /// Returns `Ok(())` if the license is currently valid for validation.
    pub fn validate_for_use(&self, now: OffsetDateTime) -> Result<(), crate::error::DomainError> {
        if !self.state.is_valid() {
            return Err(crate::error::DomainError::PolicyViolated(format!(
                "license is in {:?} state",
                self.state
            )));
        }
        if self.is_expired_at(now) {
            return Err(crate::error::DomainError::PolicyViolated(
                "license has expired".into(),
            ));
        }
        Ok(())
    }

    fn touch(&mut self) {
        self.updated_at = OffsetDateTime::now_utc();
    }
}
