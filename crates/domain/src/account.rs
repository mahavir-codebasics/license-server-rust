//! Account — the tenant boundary.
//!
//! Every resource lives under exactly one account. The account owns its
//! signing keypair (rotated via [`crate::SigningKey`]) and controls whether
//! client-side (license/user) tokens can call the API without an admin token
//! (the `protection_mode` field).

use crate::value::Metadata;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

declare_id!(AccountId, "Identifier of an [`Account`] (tenant).");

/// Whether client-side calls (license/user tokens) may hit the API directly,
/// or whether every call must carry an admin/product token.
///
/// `Protected` is the secure default: only server-side tokens work.
/// `Unprotected` allows offline-capable clients to validate/activate using
/// just their license key — useful for desktop apps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ProtectionMode {
    #[default]
    Protected,
    Unprotected,
}

/// Lifecycle status of an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// Active and billable.
    #[default]
    Active,
    /// Suspended: API calls rejected (except read of the account itself).
    Suspended,
    /// Marked for deletion; data retained for a grace period then purged.
    Canceled,
}

/// Per-account tunable settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountSettings {
    /// Optional read-replica DSN, per-account (Cloud-style). `None` uses primary.
    pub replica_database_url: Option<String>,
    /// Default region for presigned URLs, webhooks source IP allowlist, etc.
    pub region: Option<String>,
}

/// The tenant. URLs are scoped `/v1/accounts/{id}/...`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    /// Human-friendly unique slug, e.g. `acme`. Used in SSO URLs and URLs.
    pub slug: String,
    pub name: String,
    pub status: AccountStatus,
    pub protection_mode: ProtectionMode,
    pub settings: AccountSettings,
    pub metadata: Metadata,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Account {
    /// Construct a new account with sensible defaults and a fresh id.
    pub fn new(slug: impl Into<String>, name: impl Into<String>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: AccountId::now(),
            slug: slug.into(),
            name: name.into(),
            status: AccountStatus::Active,
            protection_mode: ProtectionMode::default(),
            settings: AccountSettings::default(),
            metadata: Metadata::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// The raw UUID — convenience for DB layers.
    #[inline]
    pub fn uuid(&self) -> Uuid {
        self.id.0
    }
}
