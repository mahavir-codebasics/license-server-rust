//! User — an admin who logs into the UI. Linked to accounts via
//! [`AccountMembership`]. Authentication (password hash, TOTP) lives here;
//! the API layer applies argon2id and TOTP verification.

use crate::account::AccountId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

declare_id!(UserId, "Identifier of a [`User`].");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    #[default]
    Active,
    Suspended,
}

/// RBAC role within an account. v1 ships a coarse set; fine-grained
/// permissions are a deferred (EE-style) phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    /// Full control, including billing and deletion.
    Owner,
    /// Manage resources but not billing.
    #[default]
    Admin,
    /// Create/manage policies, licenses, machines.
    Developer,
    /// Read-only.
    Viewer,
}

impl MembershipRole {
    /// Whether this role may perform destructive/admin actions.
    pub fn is_admin(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub full_name: Option<String>,
    /// Argon2id hash. **Never** serialized to API responses (skip attribute).
    #[serde(skip)]
    pub password_hash: String,
    /// TOTP secret (base32) if 2FA is enabled.
    #[serde(skip)]
    pub totp_secret: Option<String>,
    /// Whether 2FA has been verified at least once.
    pub totp_enabled: bool,
    pub status: UserStatus,
    /// URL of avatar (derived from email by the UI usually).
    pub avatar_url: Option<String>,
    pub last_login_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl User {
    pub fn new(email: impl Into<String>, password_hash: impl Into<String>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: UserId::now(),
            email: email.into(),
            full_name: None,
            password_hash: password_hash.into(),
            totp_secret: None,
            totp_enabled: false,
            status: UserStatus::Active,
            avatar_url: None,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Binds a user to an account with a role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMembership {
    pub id: MembershipId,
    pub user_id: UserId,
    pub account_id: AccountId,
    pub role: MembershipRole,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

declare_id!(MembershipId, "Identifier of an [`AccountMembership`].");
