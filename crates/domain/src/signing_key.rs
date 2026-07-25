//! SigningKey — per-account cryptographic key material with rotation support.
//!
//! An account has one *active* [`SigningKey`] used to sign new artifacts, and
//! zero or more *prior* keys still accepted for verification during a rotation
//! grace period. This makes key rotation safe: old clients keep validating
//! until they fetch a license file signed by the new key.

use crate::account::AccountId;
use crate::id::SigningKeyId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// The algorithm family a key implements. Must align with the policy scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa2048,
}

/// Lifecycle of a key. Only `Active` is used to sign; `Rotating` and `Retired`
/// remain verifiable for grace periods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    /// Used to sign new artifacts.
    #[default]
    Active,
    /// Formerly active; still accepted for verification during rotation.
    Rotating,
    /// Grace period elapsed; verification will be refused.
    Retired,
}

/// What this key is used to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsage {
    #[default]
    /// Sign license keys + license files.
    License,
    /// Sign webhooks (HMAC variant — uses symmetric material instead).
    Webhook,
}

/// Versioned signing key. `material` is the serialized keypair (PKCS#8 PEM
/// or JWK) — encrypted at rest by the `KeyStore` in the crypto crate, never
/// logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKey {
    pub id: SigningKeyId,
    pub account_id: AccountId,
    pub algorithm: KeyAlgorithm,
    pub usage: KeyUsage,
    pub status: KeyStatus,
    /// Monotonic version number; bumped on rotation.
    pub version: u32,
    /// Encrypted/encoded key material (opaque to domain).
    #[serde(skip)]
    pub material: Vec<u8>,
    /// Public key in a shareable encoding (e.g. PEM) — safe to expose.
    pub public_pem: String,
    /// When this key was retired (for grace-period accounting).
    pub retired_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl SigningKey {
    pub fn new(
        account_id: AccountId,
        algorithm: KeyAlgorithm,
        material: Vec<u8>,
        public_pem: impl Into<String>,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: SigningKeyId::now(),
            account_id,
            algorithm,
            usage: KeyUsage::License,
            status: KeyStatus::Active,
            version: 1,
            material,
            public_pem: public_pem.into(),
            retired_at: None,
            created_at: now,
            updated_at: now,
        }
    }
}
