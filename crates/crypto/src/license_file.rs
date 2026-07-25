//! License-file (certificate) signing.
//!
//! A license file is a PEM-wrapped document:
//!
//! ```text
//! -----BEGIN LICENSE FILE-----
//! {base64 or aes-256-gcm ciphertext of the JSON body}
//! -----END LICENSE FILE-----
//! Signature: alg=<ALG>, kid=<KEY_ID>, sig=<base64>
//! ```
//!
//! The JSON body has the shape `{ data, included, meta }` (caller-defined).
//! **Encrypt-then-sign** ordering: we sign the ciphertext, so tampering is
//! detected before decryption. AES-256-GCM uses a fresh random 96-bit IV per
//! encryption.

use crate::error::{CryptoError, Result};
use crate::key::{KeyPair, PublicKey};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// How the body is wrapped before signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encryption {
    /// Plain base64 (no confidentiality — the body is public, only signed).
    Base64,
    /// AES-256-GCM with a per-file random 96-bit IV; the symmetric key is
    /// derived per-account (rotate alongside the signing key).
    Aes256Gcm,
}

/// Which signature algorithm protects the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    Ed25519,
    EcdsaP256,
    RsaPssSha256,
    RsaSha256,
}

/// Full algorithm tuple, e.g. `aes-256-gcm+ed25519` or `base64+rsa-sha256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Algorithm {
    pub encryption: Encryption,
    pub signature: SignatureScheme,
}

impl Algorithm {
    /// Parse a keygen-style algorithm string like `aes-256-gcm+ed25519`.
    pub fn parse(s: &str) -> Result<Self> {
        let (enc, sig) = s
            .split_once('+')
            .ok_or_else(|| CryptoError::Unsupported(format!("bad algorithm `{s}`")))?;
        let encryption = match enc {
            "aes-256-gcm" => Encryption::Aes256Gcm,
            "base64" => Encryption::Base64,
            other => return Err(CryptoError::Unsupported(other.into())),
        };
        let signature = match sig {
            "ed25519" => SignatureScheme::Ed25519,
            "ecdsa-p256" => SignatureScheme::EcdsaP256,
            "rsa-pss-sha256" => SignatureScheme::RsaPssSha256,
            "rsa-sha256" => SignatureScheme::RsaSha256,
            other => return Err(CryptoError::Unsupported(other.into())),
        };
        Ok(Self { encryption, signature })
    }

    pub fn as_str(self) -> &'static str {
        match (self.encryption, self.signature) {
            (Encryption::Aes256Gcm, SignatureScheme::Ed25519) => "aes-256-gcm+ed25519",
            (Encryption::Aes256Gcm, SignatureScheme::EcdsaP256) => "aes-256-gcm+ecdsa-p256",
            (Encryption::Aes256Gcm, SignatureScheme::RsaPssSha256) => "aes-256-gcm+rsa-pss-sha256",
            (Encryption::Aes256Gcm, SignatureScheme::RsaSha256) => "aes-256-gcm+rsa-sha256",
            (Encryption::Base64, SignatureScheme::Ed25519) => "base64+ed25519",
            (Encryption::Base64, SignatureScheme::EcdsaP256) => "base64+ecdsa-p256",
            (Encryption::Base64, SignatureScheme::RsaPssSha256) => "base64+rsa-pss-sha256",
            (Encryption::Base64, SignatureScheme::RsaSha256) => "base64+rsa-sha256",
        }
    }
}

/// A serialized license file ready to hand to a client.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The full PEM block including the signature trailer line.
    pub pem: String,
    pub algorithm: Algorithm,
}

/// Errors specific to license-file parsing.
#[derive(Debug, thiserror::Error)]
pub enum LicenseFileError {
    #[error("malformed license file: {0}")]
    Malformed(String),
    #[error("signature missing or invalid")]
    BadSignature,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

const BEGIN: &str = "-----BEGIN LICENSE FILE-----";
const END: &str = "-----END LICENSE FILE-----";

/// Issue a license file. `body` is the JSON document to embed.
/// `aes_key` is required for `Aes256Gcm` encryption (32 bytes).
pub fn issue(
    algorithm: Algorithm,
    keypair: &KeyPair,
    key_id: &str,
    body: &[u8],
    aes_key: Option<&[u8; 32]>,
) -> Result<Certificate> {
    // 1. Wrap the body: encrypt (if requested) then base64.
    let (blob, iv_b64) = match algorithm.encryption {
        Encryption::Base64 => {
            let b64 = b64_standard(body);
            (b64, None)
        }
        Encryption::Aes256Gcm => {
            let key = aes_key.ok_or_else(|| {
                CryptoError::Unsupported("aes-256-gcm requires an aes key".into())
            })?;
            let key_arr = Key::<Aes256Gcm>::from(*key);
            let cipher = Aes256Gcm::new(&key_arr);
            // Fresh random 96-bit IV — NEVER reused.
            let mut iv = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut iv);
            let nonce = Nonce::from(iv);
            let ct = cipher
                .encrypt(&nonce, body)
                .map_err(|_| CryptoError::KeyStore("aes-gcm encrypt failed".into()))?;
            // Prepend the IV to the ciphertext so the verifier can find it.
            let mut combined = Vec::with_capacity(12 + ct.len());
            combined.extend_from_slice(&iv);
            combined.extend_from_slice(&ct);
            (b64_standard(&combined), Some(b64_standard(&iv)))
        }
    };

    // 2. Sign the *wrapped* bytes (encrypt-then-sign). The signature covers
    //    the ciphertext/base64 blob, so any tampering is detected before
    //    decryption is attempted.
    let sig = sign_blob(algorithm.signature, keypair, blob.as_bytes())?;
    let sig_b64 = b64_standard(&sig);

    // 3. Assemble the PEM block.
    let mut pem = String::new();
    pem.push_str(BEGIN);
    pem.push('\n');
    pem.push_str(&blob);
    pem.push('\n');
    pem.push_str(END);
    pem.push('\n');
    pem.push_str(&format!(
        "Signature: alg={}, kid={}, sig={}\n",
        algorithm.as_str(),
        key_id,
        sig_b64
    ));
    if let Some(iv) = iv_b64 {
        pem.push_str(&format!("Iv: {iv}\n"));
    }

    Ok(Certificate { pem, algorithm })
}

/// Verify a license file's signature and return the embedded body bytes
/// (decrypting if needed). Constant-time at the signature layer.
pub fn verify_and_open(
    pem: &str,
    public: &PublicKey,
    aes_key: Option<&[u8; 32]>,
) -> std::result::Result<(Algorithm, Vec<u8>), LicenseFileError> {
    let (blob, sig_line) = parse_pem(pem)?;
    let (alg_str, _kid, sig_b64) = parse_signature(&sig_line)?;
    let algorithm = Algorithm::parse(&alg_str)?;
    let sig = b64_decode(&sig_b64)?;

    // Verify the signature over the wrapped blob FIRST.
    if !verify_blob(algorithm.signature, public, blob.as_bytes(), &sig)? {
        return Err(LicenseFileError::BadSignature);
    }

    // Only then unwrap.
    let body = match algorithm.encryption {
        Encryption::Base64 => b64_decode(&blob)?,
        Encryption::Aes256Gcm => {
            let key = aes_key.ok_or_else(|| {
                CryptoError::Unsupported("aes-256-gcm requires an aes key".into())
            })?;
            let combined = b64_decode(&blob)?;
            if combined.len() < 12 {
                return Err(LicenseFileError::Malformed("ciphertext too short".into()));
            }
            let (iv, ct) = combined.split_at(12);
            let key_arr = Key::<Aes256Gcm>::from(*key);
            let cipher = Aes256Gcm::new(&key_arr);
            let mut iv_arr = [0u8; 12];
            iv_arr.copy_from_slice(iv);
            let nonce = Nonce::from(iv_arr);
            cipher
                .decrypt(&nonce, ct)
                .map_err(|_| CryptoError::DecryptionFailed)?
        }
    };
    Ok((algorithm, body))
}

fn parse_pem(pem: &str) -> std::result::Result<(String, String), LicenseFileError> {
    let mut lines = pem.lines();
    let begin = lines.next().ok_or_else(|| LicenseFileError::Malformed("empty".into()))?;
    if !begin.starts_with("-----BEGIN LICENSE FILE") {
        return Err(LicenseFileError::Malformed("missing begin fence".into()));
    }
    let blob = lines
        .next()
        .ok_or_else(|| LicenseFileError::Malformed("missing body".into()))?
        .trim()
        .to_string();
    let end = lines
        .next()
        .ok_or_else(|| LicenseFileError::Malformed("missing end fence".into()))?;
    if !end.starts_with("-----END LICENSE FILE") {
        return Err(LicenseFileError::Malformed("missing end fence".into()));
    }
    let sig_line = lines
        .next()
        .ok_or_else(|| LicenseFileError::Malformed("missing signature".into()))?
        .to_string();
    Ok((blob, sig_line))
}

fn parse_signature(s: &str) -> std::result::Result<(String, String, String), LicenseFileError> {
    // "Signature: alg=..., kid=..., sig=..."
    let inner = s
        .trim()
        .strip_prefix("Signature:")
        .ok_or_else(|| LicenseFileError::Malformed("bad signature line".into()))?
        .trim();
    let mut alg = None;
    let mut kid = None;
    let mut sig = None;
    for part in inner.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("alg=") {
            alg = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("kid=") {
            kid = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("sig=") {
            sig = Some(v.to_string());
        }
    }
    match (alg, kid, sig) {
        (Some(a), Some(k), Some(s)) => Ok((a, k, s)),
        _ => Err(LicenseFileError::Malformed("incomplete signature".into())),
    }
}

fn sign_blob(scheme: SignatureScheme, keypair: &KeyPair, blob: &[u8]) -> Result<Vec<u8>> {
    match scheme {
        SignatureScheme::Ed25519 => {
            let KeyPair::Ed25519(k) = keypair else {
                return Err(CryptoError::InvalidKey("expected ed25519".into()));
            };
            use ed25519_dalek::Signer;
            let sig: ed25519_dalek::Signature = k.signing.sign(blob);
            Ok(sig.to_bytes().to_vec())
        }
        SignatureScheme::EcdsaP256 => {
            let KeyPair::EcdsaP256(k) = keypair else {
                return Err(CryptoError::InvalidKey("expected ecdsa".into()));
            };
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = k.signing.sign(blob);
            Ok(sig.to_bytes().to_vec())
        }
        SignatureScheme::RsaPssSha256 => rsa_sign(keypair, blob, true),
        SignatureScheme::RsaSha256 => rsa_sign(keypair, blob, false),
    }
}

fn rsa_sign(keypair: &KeyPair, blob: &[u8], pss: bool) -> Result<Vec<u8>> {
    use rand::rngs::OsRng;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    let KeyPair::Rsa(k) = keypair else {
        return Err(CryptoError::InvalidKey("expected rsa".into()));
    };
    Ok(if pss {
        let signing = rsa::pss::SigningKey::<sha2::Sha256>::new(k.signing.clone());
        let sig = signing.sign_with_rng(&mut OsRng, blob);
        sig.to_bytes().to_vec()
    } else {
        let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(k.signing.clone());
        let sig = signing.sign_with_rng(&mut OsRng, blob);
        sig.to_bytes().to_vec()
    })
}

fn verify_blob(
    scheme: SignatureScheme,
    public: &PublicKey,
    blob: &[u8],
    sig: &[u8],
) -> Result<bool> {
    match scheme {
        SignatureScheme::Ed25519 => {
            use ed25519_dalek::Verifier;
            let PublicKey::Ed25519(vk) = public else {
                return Err(CryptoError::InvalidKey("expected ed25519".into()));
            };
            if sig.len() != 64 {
                return Ok(false);
            }
            let sig_bytes: [u8; 64] = sig
                .try_into()
                .map_err(|_| CryptoError::SignatureInvalid)?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            // ed25519-dalek's verify is already constant-time; both branches
            // return a plain bool so callers can't distinguish paths by timing.
            match vk.verify(blob, &sig) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        SignatureScheme::EcdsaP256 => {
            use p256::ecdsa::signature::Verifier;
            let PublicKey::EcdsaP256(vk) = public else {
                return Err(CryptoError::InvalidKey("expected ecdsa".into()));
            };
            let sig = match p256::ecdsa::Signature::from_slice(sig) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            Ok(vk.verify(blob, &sig).is_ok())
        }
        SignatureScheme::RsaPssSha256 => {
            use rsa::signature::Verifier;
            let PublicKey::Rsa(vk) = public else {
                return Err(CryptoError::InvalidKey("expected rsa".into()));
            };
            let verifying = rsa::pss::VerifyingKey::<sha2::Sha256>::new(vk.clone());
            let rsa_sig = match rsa::pss::Signature::try_from(sig) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            Ok(verifying.verify(blob, &rsa_sig).is_ok())
        }
        SignatureScheme::RsaSha256 => {
            use rsa::signature::Verifier;
            let PublicKey::Rsa(vk) = public else {
                return Err(CryptoError::InvalidKey("expected rsa".into()));
            };
            let verifying = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(vk.clone());
            let rsa_sig = match rsa::pkcs1v15::Signature::try_from(sig) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            Ok(verifying.verify(blob, &rsa_sig).is_ok())
        }
    }
}

fn b64_standard(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| CryptoError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyAlgorithm, KeyPair};

    fn kp(algo: KeyAlgorithm) -> KeyPair {
        KeyPair::generate(algo).unwrap()
    }

    #[test]
    fn round_trip_all_algorithms_base64() {
        let body = br#"{"data":{"id":"lic-1"}}"#;
        for (scheme, algo) in [
            (SignatureScheme::Ed25519, KeyAlgorithm::Ed25519),
            (SignatureScheme::EcdsaP256, KeyAlgorithm::EcdsaP256),
            (SignatureScheme::RsaPssSha256, KeyAlgorithm::Rsa2048),
            (SignatureScheme::RsaSha256, KeyAlgorithm::Rsa2048),
        ] {
            let kp = kp(algo);
            let cert = issue(
                Algorithm {
                    encryption: Encryption::Base64,
                    signature: scheme,
                },
                &kp,
                "kid-1",
                body,
                None,
            )
            .unwrap();
            let (alg, opened) = verify_and_open(&cert.pem, &kp.public(), None).unwrap();
            assert_eq!(alg.signature, scheme);
            assert_eq!(opened, body);
        }
    }

    #[test]
    fn round_trip_all_algorithms_aes_gcm() {
        let body = br#"{"data":{"id":"lic-2","secret":"hunter2"}}"#;
        let aes_key = [0x42u8; 32];
        for (scheme, algo) in [
            (SignatureScheme::Ed25519, KeyAlgorithm::Ed25519),
            (SignatureScheme::RsaPssSha256, KeyAlgorithm::Rsa2048),
        ] {
            let kp = kp(algo);
            let cert = issue(
                Algorithm {
                    encryption: Encryption::Aes256Gcm,
                    signature: scheme,
                },
                &kp,
                "kid-1",
                body,
                Some(&aes_key),
            )
            .unwrap();
            let (_alg, opened) =
                verify_and_open(&cert.pem, &kp.public(), Some(&aes_key)).unwrap();
            assert_eq!(opened, body);
        }
    }

    #[test]
    fn tampered_signature_rejected_before_decryption() {
        // Encrypt-then-sign means a bad signature is caught without ever
        // touching the AES layer (and without leaking whether the key is right).
        let body = br#"{"data":"x"}"#;
        let aes_key = [0x42u8; 32];
        let kp = kp(KeyAlgorithm::Ed25519);
        let cert = issue(
            Algorithm {
                encryption: Encryption::Aes256Gcm,
                signature: SignatureScheme::Ed25519,
            },
            &kp,
            "kid-1",
            body,
            Some(&aes_key),
        )
        .unwrap();

        // Flip a character in the blob.
        let mut tampered = cert.pem.clone();
        // mutate the base64 blob line (line index 1)
        let lines: Vec<&str> = tampered.lines().collect();
        let mut blob_line = lines[1].to_string();
        let b = blob_line.as_bytes();
        blob_line.replace_range(..1, if b[0] == b'A' { "B" } else { "A" });
        tampered = format!("{}\n{}\n{}", lines[0], blob_line, lines[2..].join("\n"));

        let res = verify_and_open(&tampered, &kp.public(), Some(&aes_key));
        assert!(matches!(res, Err(LicenseFileError::BadSignature)));
    }

    #[test]
    fn wrong_public_key_rejected() {
        let body = br#"{"data":"x"}"#;
        let kp1 = kp(KeyAlgorithm::Ed25519);
        let kp2 = kp(KeyAlgorithm::Ed25519);
        let cert = issue(
            Algorithm {
                encryption: Encryption::Base64,
                signature: SignatureScheme::Ed25519,
            },
            &kp1,
            "kid-1",
            body,
            None,
        )
        .unwrap();
        let res = verify_and_open(&cert.pem, &kp2.public(), None);
        assert!(matches!(res, Err(LicenseFileError::BadSignature)));
    }

    #[test]
    fn algorithm_string_round_trip() {
        for s in [
            "aes-256-gcm+ed25519",
            "aes-256-gcm+ecdsa-p256",
            "aes-256-gcm+rsa-pss-sha256",
            "aes-256-gcm+rsa-sha256",
            "base64+ed25519",
            "base64+ecdsa-p256",
            "base64+rsa-pss-sha256",
            "base64+rsa-sha256",
        ] {
            let alg = Algorithm::parse(s).unwrap();
            assert_eq!(alg.as_str(), s);
        }
        assert!(Algorithm::parse("nonsense").is_err());
    }

    #[test]
    fn iv_is_random_per_issuance() {
        let body = br#"{"data":"x"}"#;
        let aes_key = [0x42u8; 32];
        let kp = kp(KeyAlgorithm::Ed25519);
        let c1 = issue(
            Algorithm {
                encryption: Encryption::Aes256Gcm,
                signature: SignatureScheme::Ed25519,
            },
            &kp,
            "kid",
            body,
            Some(&aes_key),
        )
        .unwrap();
        let c2 = issue(
            Algorithm {
                encryption: Encryption::Aes256Gcm,
                signature: SignatureScheme::Ed25519,
            },
            &kp,
            "kid",
            body,
            Some(&aes_key),
        )
        .unwrap();
        // different IVs (in the Iv: trailer) → different ciphertexts
        assert_ne!(c1.pem, c2.pem);
    }
}
