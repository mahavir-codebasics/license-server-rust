//! `license-crypto` — license-key signing + license-file certificates.
//!
//! Two distinct subsystems (the same separation keygen gets right):
//!
//! 1. **License-key signing** ([`key`]) — the algorithm that produces and
//!    verifies the license *key string* itself (Ed25519, ECDSA-P256,
//!    RSA-2048 PSS/PKCS1v15, JWT-RS256/EdDSA).
//! 2. **License-file certificates** ([`license_file`]) — a PEM-wrapped,
//!    optionally AES-256-GCM-encrypted JSON document carrying the license +
//!    included resources, signed with Ed25519 / ECDSA-P256 / RSA-PSS /
//!    RSA-PKCS1v15. **Encrypt-then-sign** ordering throughout.
//!
//! ### Security properties enforced here
//!
//! - Plaintext license keys are **never persisted** — only their SHA-256 hash.
//! - License files use **encrypt-then-sign**: the signature covers the
//!   ciphertext, so tampering is detectable before decryption.
//! - AES-256-GCM uses a **fresh random 96-bit IV per encryption** (never
//!   reused) — enforced by the API, not left to the caller.
//! - All signature comparisons are **constant-time** (`subtle`).
//! - Key material is held in `zeroize`-clearing types and **never logged**.
//! - The `KeyStore` trait isolates local vs KMS/HSM backends so signing can
//!   happen inside an HSM with the private key never leaving it.

pub mod error;
pub mod key;
pub mod keystream;
pub mod license_file;
pub mod store;
pub mod token;

pub use error::{CryptoError, Result};
pub use key::{
    sign_license_key, verify_license_key, EcdsaP256Keypair, Ed25519Keypair, KeyAlgorithm,
    KeyEncoding, KeyPair, KeyScheme, PublicKey, RsaKeypair, SecretKey, SignedKey,
};
pub use license_file::{Algorithm, Certificate, Encryption, LicenseFileError, SignatureScheme};
pub use store::{KeyStore, LocalKeyStore};
pub use token::{generate as generate_token, hash as hash_token, GeneratedToken, TokenPrefix};

/// SHA-256 of `data`, hex-encoded. Used for license-key and token hashing
/// (the only thing we persist for lookup; the plaintext is never stored).
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Generate 32 cryptographically-random bytes.
pub fn random_32() -> [u8; 32] {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}
