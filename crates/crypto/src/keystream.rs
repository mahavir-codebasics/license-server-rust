//! Per-account AES key derivation for license-file encryption.
//!
//! When a license file uses `aes-256-gcm`, the symmetric key is derived
//! deterministically from the account's signing key id + a master secret,
//! so the same key can be recomputed to decrypt any file that account issued.
//! Rotating the signing key bumps `kid`, which also rolls the AES key.

use sha2::{Digest, Sha256};

/// Derive a 32-byte AES key from `(master_secret, account_id, key_version)`.
/// HKDF-style: SHA-256 over the inputs. Deterministic so any node can decrypt.
pub fn derive_aes_key(master_secret: &[u8], account_id: &str, key_version: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"license-server/license-file/v1");
    h.update(master_secret);
    h.update(account_id.as_bytes());
    h.update(key_version.to_be_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Convenience: derive and return as owned bytes.
pub fn derive_aes_key_vec(master_secret: &[u8], account_id: &str, key_version: u32) -> Vec<u8> {
    derive_aes_key(master_secret, account_id, key_version).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_aes_key(b"master", "acc-1", 1);
        let b = derive_aes_key(b"master", "acc-1", 1);
        assert_eq!(a, b);
    }

    #[test]
    fn different_accounts_different_keys() {
        let a = derive_aes_key(b"master", "acc-1", 1);
        let b = derive_aes_key(b"master", "acc-2", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn different_versions_different_keys() {
        let a = derive_aes_key(b"master", "acc-1", 1);
        let b = derive_aes_key(b"master", "acc-1", 2);
        assert_ne!(a, b);
    }
}
