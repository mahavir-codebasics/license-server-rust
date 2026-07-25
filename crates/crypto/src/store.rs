//! KeyStore — abstraction over where signing keys live.
//!
//! Two production-grade impls:
//!   - [`LocalKeyStore`]: keys encrypted at rest with AES-256-GCM under a
//!     master key from config/env. Suitable for self-hosted single-node and
//!     most cloud deployments.
//!   - `KmsKeyStore` (planned): keys live in AWS KMS / GCP KMS / Vault
//!     Transit; signing happens inside the HSM and the private key never
//!     leaves. The trait here is the seam.
//!
//! Both impls satisfy [`KeyStore`], so the rest of the codebase is agnostic
//! to which is configured.

use crate::error::{CryptoError, Result};
use crate::key::{KeyAlgorithm, KeyPair};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::RngCore;
use zeroize::Zeroize;

/// Where signing keys are stored + how signing is performed.
#[async_trait::async_trait]
pub trait KeyStore: Send + Sync {
    /// Encrypt `keypair` to opaque bytes for at-rest storage.
    fn seal(&self, keypair: &KeyPair) -> Result<Vec<u8>>;

    /// Decrypt opaque bytes back into a keypair.
    fn open(&self, algorithm: KeyAlgorithm, material: &[u8]) -> Result<KeyPair>;

    /// The PEM encoding of the public half (safe to store in the clear, used
    /// for license-file signature headers and JWKS).
    fn public_pem(&self, keypair: &KeyPair) -> Result<String>;
}

/// Local at-rest key storage: encrypts PKCS#8 PEM with AES-256-GCM under a
/// 32-byte master key.
pub struct LocalKeyStore {
    master_key: [u8; 32],
}

impl LocalKeyStore {
    /// Build from a hex-encoded 32-byte master key (64 hex chars).
    pub fn from_hex(hex_key: &str) -> Result<Self> {
        let bytes = hex::decode(hex_key)
            .map_err(|e| CryptoError::KeyStore(format!("bad master key hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(CryptoError::KeyStore(format!(
                "master key must be 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            )));
        }
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&bytes);
        Ok(Self { master_key })
    }

    fn cipher(&self) -> Aes256Gcm {
        let key = Key::<Aes256Gcm>::from(self.master_key);
        Aes256Gcm::new(&key)
    }
}

#[async_trait::async_trait]
impl KeyStore for LocalKeyStore {
    fn seal(&self, keypair: &KeyPair) -> Result<Vec<u8>> {
        let pem = keypair.to_pkcs8_pem()?;
        // Fresh random 96-bit nonce per sealing — NEVER reused.
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let cipher = self.cipher();
        let ciphertext = cipher
            .encrypt(&nonce, pem.as_bytes())
            .map_err(|_| CryptoError::KeyStore("aes-gcm encryption failed".into()))?;

        // Layout: [12-byte nonce][ciphertext]. The nonce is not secret.
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open(&self, algorithm: KeyAlgorithm, material: &[u8]) -> Result<KeyPair> {
        if material.len() < 12 {
            return Err(CryptoError::KeyStore("sealed material too short".into()));
        }
        let (nonce_bytes, ciphertext) = material.split_at(12);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce = Nonce::from(nonce_arr);
        let cipher = self.cipher();
        let pem_bytes = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let pem = String::from_utf8(pem_bytes)
            .map_err(|e| CryptoError::KeyStore(format!("sealed pem not utf8: {e}")))?;
        KeyPair::from_pkcs8_pem(algorithm, &pem)
    }

    fn public_pem(&self, keypair: &KeyPair) -> Result<String> {
        keypair.public_pem()
    }
}

impl Drop for LocalKeyStore {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_store_seal_open_round_trip() {
        let master = "abababababababababababababababababababababababababababababababab";
        let store = LocalKeyStore::from_hex(master).unwrap();
        let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let sealed = store.seal(&kp).unwrap();
        let kp2 = store.open(KeyAlgorithm::Ed25519, &sealed).unwrap();
        assert_eq!(kp.public_pem().unwrap(), kp2.public_pem().unwrap());
    }

    #[test]
    fn sealed_material_differs_each_time_due_to_nonce() {
        let master = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        let store = LocalKeyStore::from_hex(master).unwrap();
        let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let a = store.seal(&kp).unwrap();
        let b = store.seal(&kp).unwrap();
        assert_ne!(a, b, "fresh nonce should make ciphertexts differ");
        // both still decrypt to the same key
        assert_eq!(
            store
                .open(KeyAlgorithm::Ed25519, &a)
                .unwrap()
                .public_pem()
                .unwrap(),
            store
                .open(KeyAlgorithm::Ed25519, &b)
                .unwrap()
                .public_pem()
                .unwrap(),
        );
    }

    #[test]
    fn wrong_master_key_fails_to_open() {
        let store1 = LocalKeyStore::from_hex(
            "abababababababababababababababababababababababababababababababab",
        )
        .unwrap();
        let store2 = LocalKeyStore::from_hex(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        )
        .unwrap();
        let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let sealed = store1.seal(&kp).unwrap();
        assert!(matches!(
            store2.open(KeyAlgorithm::Ed25519, &sealed),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn bad_master_key_length_rejected() {
        assert!(LocalKeyStore::from_hex("tooshort").is_err());
    }
}
