//! Policy — the licensing rule template.
//!
//! A policy is the heart of the system: it dictates how licenses created from
//! it behave. Licenses inherit the policy's scheme, duration, machine limits,
//! heartbeat cadence, and expiry/overage strategies. Mirrors keygen's policy
//! model but with a leaner, typed Rust surface.

use crate::account::AccountId;
use crate::product::ProductId;
use crate::value::Metadata;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use time::OffsetDateTime;

declare_id!(PolicyId, "Identifier of a [`Policy`].");

/// The cryptographic scheme used to sign license keys created from this policy.
///
/// See `license-crypto` for implementations. Ed25519 is the recommended
/// default: smallest signatures, fastest verify, no parameters to misuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyScheme {
    #[default]
    /// Ed25519 over the key bytes. ~64B signature. **Recommended.**
    Ed25519Sign,
    /// ECDSA over NIST P-256 with SHA-256. FIPS-friendly.
    EcdsaP256Sha256,
    /// RSA-2048 with RSASSA-PSS and SHA-256. Probabilistic, modern padding.
    Rsa2048PssSha256,
    /// RSA-2048 with PKCS#1 v1.5 and SHA-256. Deterministic, legacy compat.
    Rsa2048Pkcs1v15Sha256,
    /// Key is a JWT signed with RS256 (RSA-2048). The "key string" is a JWT.
    JwtRs256,
    /// Key is a JWT signed with EdDSA (Ed25519). Compact JWT variant.
    JwtEddsa,
}

/// Strategy for how floating licenses deal with machines whose heartbeat
/// has expired. `AllowOverage` lets a few dead machines linger so a flaky
/// network doesn't lock users out; `Strict` deactivates immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FloatingStrategy {
    #[default]
    Strict,
    /// Allow 1.25× the max before culling.
    Allow125xOverage,
    /// Allow 1.5× the max before culling.
    Allow15xOverage,
}

/// The full licensing rule template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: PolicyId,
    pub account_id: AccountId,
    pub product_id: ProductId,

    pub name: String,
    /// Optional machine-friendly key (unique within account).
    pub key: Option<String>,

    /// Cryptographic scheme for license keys.
    pub scheme: PolicyScheme,

    // — Machine limits —
    /// Max concurrent machine activations. `None` = unlimited.
    pub max_machines: Option<u32>,
    /// Floating license behavior when activations exceed max.
    pub floating_strategy: FloatingStrategy,
    /// Max machine components (sub-parts) per machine.
    pub max_components: Option<u32>,
    /// Max processes per machine (heartbeat-tracked).
    pub max_processes: Option<u32>,

    // — Usage / metering —
    /// Max uses for metered licenses (`max_uses`).
    pub max_uses: Option<u64>,
    /// Max users bound to licenses created from this policy.
    pub max_users: Option<u32>,
    /// Hardware caps (informational; enforced by client optionally).
    pub max_cores: Option<u32>,
    pub max_memory: Option<u64>,
    pub max_disk: Option<u64>,

    // — Time / expiry —
    /// License lifetime after creation/activation/validation. `None` = perpetual.
    pub duration: Option<Duration>,
    /// How often machines must heartbeat before being culled.
    pub heartbeat_duration: Option<Duration>,
    /// Whether check-in (license-level heartbeat) is required.
    pub require_check_in: bool,
    /// Max overdue check-ins before license is revoked.
    pub max_overdue_check_ins: Option<u32>,

    // — Requirements —
    /// Whether activation requires a product token (server-side).
    pub require_product_scope: bool,
    /// Whether the license must be associated with a user.
    pub require_user: bool,
    /// Whether machine activation requires a fingerprint.
    pub require_fingerprint: bool,
    /// Whether the policy is protected (read-only after creation).
    pub protected: bool,
    /// Whether licenses can be re-activated after expiry (renewable).
    pub renewable: bool,

    pub metadata: Metadata,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Policy {
    /// Construct a policy with sensible secure defaults for `scheme`.
    pub fn new(
        account_id: AccountId,
        product_id: ProductId,
        name: impl Into<String>,
        scheme: PolicyScheme,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: PolicyId::now(),
            account_id,
            product_id,
            name: name.into(),
            key: None,
            scheme,
            max_machines: Some(1),
            floating_strategy: FloatingStrategy::default(),
            max_components: None,
            max_processes: None,
            max_uses: None,
            max_users: None,
            max_cores: None,
            max_memory: None,
            max_disk: None,
            duration: None,
            heartbeat_duration: None,
            require_check_in: false,
            max_overdue_check_ins: None,
            require_product_scope: false,
            require_user: false,
            require_fingerprint: true,
            protected: false,
            renewable: true,
            metadata: Metadata::new(),
            created_at: now,
            updated_at: now,
        }
    }
}
