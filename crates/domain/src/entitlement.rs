//! Entitlement — a feature flag attachable to policies (defaults) and
//! licenses (overrides). Used to gate functionality in client software.

use crate::account::AccountId;
use crate::value::Metadata;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

declare_id!(EntitlementId, "Identifier of an [`Entitlement`].");

/// Stable, machine-readable entitlement code, e.g. `pro.export.4k`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntitlementCode(pub String);

impl EntitlementCode {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// A feature flag definition scoped to an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub id: EntitlementId,
    pub account_id: AccountId,
    pub code: EntitlementCode,
    pub name: String,
    pub metadata: Metadata,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Entitlement {
    pub fn new(account_id: AccountId, code: impl Into<String>, name: impl Into<String>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: EntitlementId::now(),
            account_id,
            code: EntitlementCode(code.into()),
            name: name.into(),
            metadata: Metadata::new(),
            created_at: now,
            updated_at: now,
        }
    }
}
