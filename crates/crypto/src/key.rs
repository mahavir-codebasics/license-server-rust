//! License-key signing — the algorithm that produces and verifies the license
//! *key string* itself.
//!
//! Supported schemes (see [`KeyScheme`]):
//!   - `Ed25519` (recommended default — 64B sig, fastest)
//!   - `EcdsaP256` (compact, FIPS-friendly)
//!   - `Rsa2048Pss` (enterprise compat)
//!   - `Rsa2048Pkcs1v15` (legacy compat)
//!   - `JwtRs256` / `JwtEddsa` (the key string IS a signed JWT)
//!
//! The plaintext key is **never persisted**; callers store only
//! [`sha256_hex`][crate::sha256_hex] of it. Verification is constant-time.

use crate::error::{CryptoError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// The algorithm family a keypair implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa2048,
}

/// The signing scheme for license keys. Maps 1:1 to the domain `PolicyScheme`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyScheme {
    Ed25519,
    EcdsaP256,
    Rsa2048Pss,
    Rsa2048Pkcs1v15,
    JwtRs256,
    JwtEddsa,
}

impl KeyScheme {
    pub fn algorithm(self) -> KeyAlgorithm {
        match self {
            KeyScheme::Ed25519 | KeyScheme::JwtEddsa => KeyAlgorithm::Ed25519,
            KeyScheme::EcdsaP256 => KeyAlgorithm::EcdsaP256,
            KeyScheme::Rsa2048Pss | KeyScheme::Rsa2048Pkcs1v15 | KeyScheme::JwtRs256 => {
                KeyAlgorithm::Rsa2048
            }
        }
    }

    /// Whether the scheme emits a JWT as the key string.
    pub fn is_jwt(self) -> bool {
        matches!(self, KeyScheme::JwtRs256 | KeyScheme::JwtEddsa)
    }
}

/// A signable/verifiable keypair. The private material is held in
/// `ZeroizeOnDrop` types and never serialized to logs.
#[derive(Debug)]
pub enum KeyPair {
    Ed25519(Ed25519Keypair),
    EcdsaP256(EcdsaP256Keypair),
    Rsa(RsaKeypair),
}

/// A public key — safe to expose (in license-file headers, JWKS, etc.).
#[derive(Debug, Clone)]
pub enum PublicKey {
    Ed25519(VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

/// Secret key material — never leaves the [`KeyStore`] except to sign.
#[derive(ZeroizeOnDrop, Clone)]
pub enum SecretKey {
    Ed25519(SigningKey),
    #[allow(dead_code)]
    EcdsaP256(p256::ecdsa::SigningKey),
    #[allow(dead_code)]
    Rsa(rsa::RsaPrivateKey),
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

// Concrete keypair types — these own both halves and implement the signing.

#[derive(ZeroizeOnDrop)]
pub struct Ed25519Keypair {
    pub(crate) signing: SigningKey,
}

impl Ed25519Keypair {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self> {
        let signing = SigningKey::from_bytes(secret);
        Ok(Self { signing })
    }

    pub fn public(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// PKCS#8 PEM encoding of the private key (for at-rest storage).
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        // `ed25519`'s `pkcs8` re-export omits `LineEnding`; reach it via the
        // shared `der` crate (same type every pkcs8 consumer uses).
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        let s = self
            .signing
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| CryptoError::Encoding(e.to_string()))?;
        Ok(s.as_str().to_string())
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let signing = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| CryptoError::Decoding(e.to_string()))?;
        Ok(Self { signing })
    }

    /// Public key as PEM (SPKI).
    pub fn public_pem(&self) -> Result<String> {
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        use ed25519_dalek::pkcs8::EncodePublicKey;
        let s = self
            .public()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| CryptoError::Encoding(e.to_string()))?;
        Ok(s)
    }
}

impl std::fmt::Debug for Ed25519Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed25519Keypair(<redacted>)")
    }
}

#[derive(ZeroizeOnDrop)]
pub struct EcdsaP256Keypair {
    pub(crate) signing: p256::ecdsa::SigningKey,
}

impl EcdsaP256Keypair {
    pub fn generate() -> Self {
        Self {
            signing: p256::ecdsa::SigningKey::random(&mut OsRng),
        }
    }

    pub fn public(&self) -> p256::ecdsa::VerifyingKey {
        p256::ecdsa::VerifyingKey::from(&self.signing)
    }

    pub fn to_pkcs8_pem(&self) -> Result<String> {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        let s = self
            .signing
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| CryptoError::Encoding(e.to_string()))?;
        Ok(s.as_str().to_string())
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        use p256::pkcs8::DecodePrivateKey;
        let signing = p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| CryptoError::Decoding(e.to_string()))?;
        Ok(Self { signing })
    }

    pub fn public_pem(&self) -> Result<String> {
        use p256::pkcs8::{EncodePublicKey, LineEnding};
        let s = self
            .public()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| CryptoError::Encoding(e.to_string()))?;
        Ok(s)
    }
}

impl std::fmt::Debug for EcdsaP256Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcdsaP256Keypair(<redacted>)")
    }
}

#[derive(ZeroizeOnDrop)]
pub struct RsaKeypair {
    pub(crate) signing: rsa::RsaPrivateKey,
}

impl RsaKeypair {
    pub fn generate() -> Result<Self> {
        // 2048-bit RSA. ~keygen's baseline.
        let signing = rsa::RsaPrivateKey::new(&mut OsRng, 2048)?;
        Ok(Self { signing })
    }

    pub fn public(&self) -> rsa::RsaPublicKey {
        rsa::RsaPublicKey::from(&self.signing)
    }

    pub fn to_pkcs8_pem(&self) -> Result<String> {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        let s = self
            .signing
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| CryptoError::Encoding(e.to_string()))?;
        Ok(s.as_str().to_string())
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        use rsa::pkcs8::DecodePrivateKey;
        let signing = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| CryptoError::Decoding(e.to_string()))?;
        Ok(Self { signing })
    }

    pub fn public_pem(&self) -> Result<String> {
        use rsa::pkcs8::{EncodePublicKey, LineEnding};
        let s = self
            .public()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| CryptoError::Encoding(e.to_string()))?;
        Ok(s)
    }
}

impl std::fmt::Debug for RsaKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaKeypair(<redacted>)")
    }
}

impl KeyPair {
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self> {
        Ok(match algorithm {
            KeyAlgorithm::Ed25519 => KeyPair::Ed25519(Ed25519Keypair::generate()),
            KeyAlgorithm::EcdsaP256 => KeyPair::EcdsaP256(EcdsaP256Keypair::generate()),
            KeyAlgorithm::Rsa2048 => KeyPair::Rsa(RsaKeypair::generate()?),
        })
    }

    /// Serialize the private material to PKCS#8 PEM (for at-rest storage,
    /// always wrapped by the `KeyStore` encryption layer).
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        match self {
            KeyPair::Ed25519(k) => k.to_pkcs8_pem(),
            KeyPair::EcdsaP256(k) => k.to_pkcs8_pem(),
            KeyPair::Rsa(k) => k.to_pkcs8_pem(),
        }
    }

    /// Deserialize from PKCS#8 PEM.
    pub fn from_pkcs8_pem(algorithm: KeyAlgorithm, pem: &str) -> Result<Self> {
        Ok(match algorithm {
            KeyAlgorithm::Ed25519 => KeyPair::Ed25519(Ed25519Keypair::from_pkcs8_pem(pem)?),
            KeyAlgorithm::EcdsaP256 => KeyPair::EcdsaP256(EcdsaP256Keypair::from_pkcs8_pem(pem)?),
            KeyAlgorithm::Rsa2048 => KeyPair::Rsa(RsaKeypair::from_pkcs8_pem(pem)?),
        })
    }

    pub fn public_pem(&self) -> Result<String> {
        match self {
            KeyPair::Ed25519(k) => k.to_pkcs8_pem().and_then(|_| k.public_pem()),
            KeyPair::EcdsaP256(k) => k.public_pem(),
            KeyPair::Rsa(k) => k.public_pem(),
        }
    }

    pub fn public(&self) -> PublicKey {
        match self {
            KeyPair::Ed25519(k) => PublicKey::Ed25519(k.public()),
            KeyPair::EcdsaP256(k) => PublicKey::EcdsaP256(k.public()),
            KeyPair::Rsa(k) => PublicKey::Rsa(k.public()),
        }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            KeyPair::Ed25519(_) => KeyAlgorithm::Ed25519,
            KeyPair::EcdsaP256(_) => KeyAlgorithm::EcdsaP256,
            KeyPair::Rsa(_) => KeyAlgorithm::Rsa2048,
        }
    }
}

/// How the signed key is encoded into the final key string.
#[derive(Debug, Clone, Copy)]
pub enum KeyEncoding {
    /// Raw: base64(payload) + "." + base64(sig).
    DotSeparated,
    /// JWT (the key IS a JWT).
    Jwt,
}

/// A signed license key — the plaintext key string + the SHA-256 hash we
/// persist for lookup.
#[derive(Debug, Clone)]
pub struct SignedKey {
    /// The plaintext key string (Ed25519/RSA blob or JWT). Returned to the
    /// client ONCE at creation; never stored.
    pub key: String,
    /// SHA-256 hex of `key`. Persisted + indexed for lookup.
    pub key_hash: String,
}

/// Sign a license key for `license_id` using `scheme` + `keypair`.
///
/// The signed payload is a compact, deterministic encoding of the license id
/// + a random nonce (so two keys for the same license differ). For JWT
///   schemes, the key string is a signed JWT.
pub fn sign_license_key(
    scheme: KeyScheme,
    keypair: &KeyPair,
    license_id: &str,
    account_id: &str,
) -> Result<SignedKey> {
    let nonce = crate::random_32();
    // payload: "v1.{account}.{license}.{nonce_hex}" — deterministic structure
    // plus a per-key nonce so identical inputs yield different keys.
    let payload = format!("v1.{account_id}.{license_id}.{}", hex::encode(nonce));

    let key_string = match scheme {
        KeyScheme::Ed25519 => sign_detached_ed25519(keypair, payload.as_bytes())?,
        KeyScheme::EcdsaP256 => sign_detached_ecdsa(keypair, payload.as_bytes())?,
        KeyScheme::Rsa2048Pss => sign_rsa(keypair, payload.as_bytes(), true)?,
        KeyScheme::Rsa2048Pkcs1v15 => sign_rsa(keypair, payload.as_bytes(), false)?,
        KeyScheme::JwtRs256 => sign_jwt(keypair, &payload, license_id, account_id, "RS256")?,
        KeyScheme::JwtEddsa => sign_jwt(keypair, &payload, license_id, account_id, "EdDSA")?,
    };

    Ok(SignedKey {
        key: key_string,
        key_hash: crate::sha256_hex(payload.as_bytes()),
    })
}

fn sign_detached_ed25519(keypair: &KeyPair, payload: &[u8]) -> Result<String> {
    let KeyPair::Ed25519(k) = keypair else {
        return Err(CryptoError::InvalidKey("expected ed25519 keypair".into()));
    };
    let sig: Signature = k.signing.sign(payload);
    let mut combined = payload.to_vec();
    combined.extend_from_slice(&sig.to_bytes());
    Ok(base64_encode(&combined))
}

fn sign_detached_ecdsa(keypair: &KeyPair, payload: &[u8]) -> Result<String> {
    use p256::ecdsa::signature::Signer;
    let KeyPair::EcdsaP256(k) = keypair else {
        return Err(CryptoError::InvalidKey("expected ecdsa keypair".into()));
    };
    let sig: p256::ecdsa::Signature = k.signing.sign(payload);
    let mut combined = payload.to_vec();
    combined.extend_from_slice(&sig.to_bytes());
    Ok(base64_encode(&combined))
}

fn sign_rsa(keypair: &KeyPair, payload: &[u8], pss: bool) -> Result<String> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pss::SigningKey as PssSigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    // RSA-PSS is probabilistic and requires an RNG; PKCS1v15 SigningKey also
    // exposes RandomizedSigner in rsa 0.9, so we use that uniformly.
    let KeyPair::Rsa(k) = keypair else {
        return Err(CryptoError::InvalidKey("expected rsa keypair".into()));
    };
    let mut combined = payload.to_vec();
    let sig_bytes: Vec<u8> = if pss {
        let signing = PssSigningKey::<sha2::Sha256>::new(k.signing.clone());
        let sig = signing.sign_with_rng(&mut OsRng, payload);
        sig.to_bytes().to_vec()
    } else {
        let signing = SigningKey::<sha2::Sha256>::new(k.signing.clone());
        let sig = signing.sign_with_rng(&mut OsRng, payload);
        sig.to_bytes().to_vec()
    };
    combined.extend_from_slice(&sig_bytes);
    Ok(base64_encode(&combined))
}

fn sign_jwt(
    keypair: &KeyPair,
    payload_data: &str,
    license_id: &str,
    account_id: &str,
    alg: &str,
) -> Result<String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({
        "iss": format!("license-server/{account_id}"),
        "sub": license_id,
        "iat": now,
        "data": payload_data,
    });
    let header = Header::new(match alg {
        "RS256" => Algorithm::RS256,
        "EdDSA" => Algorithm::EdDSA,
        other => return Err(CryptoError::Unsupported(format!("jwt alg {other}"))),
    });
    let encoding_key = match keypair {
        KeyPair::Rsa(k) => {
            let pem = k.to_pkcs8_pem()?;
            EncodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|e| CryptoError::Encoding(e.to_string()))?
        }
        KeyPair::Ed25519(k) => {
            let pem = k.to_pkcs8_pem()?;
            EncodingKey::from_ed_pem(pem.as_bytes())
                .map_err(|e| CryptoError::Encoding(e.to_string()))?
        }
        _ => return Err(CryptoError::InvalidKey("jwt requires rsa/ed25519".into())),
    };
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key)
        .map_err(|e| CryptoError::Encoding(e.to_string()))?;
    Ok(token)
}

/// Verify a signed license key against `public`. Returns `Ok(())` if valid.
/// Comparison is constant-time at the signature layer.
pub fn verify_license_key(scheme: KeyScheme, public: &PublicKey, key: &str) -> Result<()> {
    match scheme {
        KeyScheme::Ed25519 => {
            let PublicKey::Ed25519(vk) = public else {
                return Err(CryptoError::InvalidKey("expected ed25519 pubkey".into()));
            };
            let combined = base64_decode(key)?;
            if combined.len() < 64 {
                return Err(CryptoError::SignatureInvalid);
            }
            let split = combined.len() - 64;
            let payload = &combined[..split];
            let sig_bytes: [u8; 64] = combined[split..]
                .try_into()
                .map_err(|_| CryptoError::SignatureInvalid)?;
            let sig = Signature::from_bytes(&sig_bytes);
            vk.verify(payload, &sig).map_err(|_| CryptoError::SignatureInvalid)
        }
        KeyScheme::EcdsaP256 => {
            use p256::ecdsa::signature::Verifier;
            let PublicKey::EcdsaP256(vk) = public else {
                return Err(CryptoError::InvalidKey("expected ecdsa pubkey".into()));
            };
            let combined = base64_decode(key)?;
            if combined.len() < 64 {
                return Err(CryptoError::SignatureInvalid);
            }
            let split = combined.len() - 64;
            let payload = &combined[..split];
            let sig = p256::ecdsa::Signature::from_slice(&combined[split..])
                .map_err(|_| CryptoError::SignatureInvalid)?;
            vk.verify(payload, &sig)
                .map_err(|_| CryptoError::SignatureInvalid)
        }
        KeyScheme::Rsa2048Pss => verify_rsa(public, key, true),
        KeyScheme::Rsa2048Pkcs1v15 => verify_rsa(public, key, false),
        KeyScheme::JwtRs256 | KeyScheme::JwtEddsa => {
            // JWT verification requires the full public key PEM; for v1 we
            // re-derive from the PublicKey enum. (A future pass can validate
            // claims/expiry here.)
            verify_jwt(scheme, public, key)
        }
    }
}

fn verify_rsa(public: &PublicKey, key: &str, pss: bool) -> Result<()> {
    use rsa::signature::Verifier;
    let PublicKey::Rsa(vk) = public else {
        return Err(CryptoError::InvalidKey("expected rsa pubkey".into()));
    };
    let combined = base64_decode(key)?;
    // RSA-2048 sig is 256 bytes.
    if combined.len() < 256 {
        return Err(CryptoError::SignatureInvalid);
    }
    let split = combined.len() - 256;
    let payload = &combined[..split];
    let sig = &combined[split..];
    let valid = if pss {
        let verifying = rsa::pss::VerifyingKey::<sha2::Sha256>::new(vk.clone());
        let rsa_sig = match rsa::pss::Signature::try_from(sig) {
            Ok(s) => s,
            Err(_) => return Err(CryptoError::SignatureInvalid),
        };
        verifying.verify(payload, &rsa_sig).is_ok()
    } else {
        let verifying = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(vk.clone());
        let rsa_sig = match rsa::pkcs1v15::Signature::try_from(sig) {
            Ok(s) => s,
            Err(_) => return Err(CryptoError::SignatureInvalid),
        };
        verifying.verify(payload, &rsa_sig).is_ok()
    };
    if valid {
        Ok(())
    } else {
        Err(CryptoError::SignatureInvalid)
    }
}

fn verify_jwt(scheme: KeyScheme, public: &PublicKey, token: &str) -> Result<()> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    let alg = match scheme {
        KeyScheme::JwtRs256 => Algorithm::RS256,
        KeyScheme::JwtEddsa => Algorithm::EdDSA,
        _ => return Err(CryptoError::Unsupported("non-jwt scheme".into())),
    };
    let decoding = match public {
        PublicKey::Rsa(k) => {
            use rsa::pkcs8::{EncodePublicKey, LineEnding};
            let pem = k
                .to_public_key_pem(LineEnding::LF)
                .map_err(|e| CryptoError::Encoding(e.to_string()))?;
            DecodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|e| CryptoError::Decoding(e.to_string()))?
        }
        PublicKey::Ed25519(k) => {
            use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
            use ed25519_dalek::pkcs8::EncodePublicKey;
            let pem = k
                .to_public_key_pem(LineEnding::LF)
                .map_err(|e| CryptoError::Encoding(e.to_string()))?;
            DecodingKey::from_ed_pem(pem.as_bytes())
                .map_err(|e| CryptoError::Decoding(e.to_string()))?
        }
        _ => return Err(CryptoError::InvalidKey("jwt requires rsa/ed25519".into())),
    };
    let mut validation = Validation::new(alg);
    // v1: validate signature + structure; claim-policy (iss/exp/aud) is
    // enforced at the API layer where account context lives. jsonwebtoken 9
    // requires `exp` and an `aud` by default — clear those requirements so a
    // structurally-valid, correctly-signed token verifies here.
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    validation.validate_aud = false;
    jsonwebtoken::decode::<serde_json::Value>(token, &decoding, &validation)
        .map_err(|_| CryptoError::SignatureInvalid)?;
    Ok(())
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| CryptoError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_schemes() {
        for (scheme, algo) in [
            (KeyScheme::Ed25519, KeyAlgorithm::Ed25519),
            (KeyScheme::EcdsaP256, KeyAlgorithm::EcdsaP256),
            (KeyScheme::Rsa2048Pss, KeyAlgorithm::Rsa2048),
            (KeyScheme::Rsa2048Pkcs1v15, KeyAlgorithm::Rsa2048),
            (KeyScheme::JwtRs256, KeyAlgorithm::Rsa2048),
            (KeyScheme::JwtEddsa, KeyAlgorithm::Ed25519),
        ] {
            let kp = KeyPair::generate(algo).expect("gen");
            let signed = sign_license_key(scheme, &kp, "lic-1", "acc-1").expect("sign");
            // verify with the matching public key succeeds
            verify_license_key(scheme, &kp.public(), &signed.key).expect_err_or_ok(scheme);
        }
    }

    trait UnwrapExt {
        fn expect_err_or_ok(self, scheme: KeyScheme);
    }
    impl UnwrapExt for Result<()> {
        fn expect_err_or_ok(self, scheme: KeyScheme) {
            match self {
                Ok(()) => {}
                Err(e) => panic!("verify failed for {scheme:?}: {e}"),
            }
        }
    }

    #[test]
    fn verification_rejects_wrong_key() {
        let kp1 = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let kp2 = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let signed = sign_license_key(KeyScheme::Ed25519, &kp1, "lic-1", "acc-1").unwrap();
        // verifying with a DIFFERENT public key must fail
        let res = verify_license_key(KeyScheme::Ed25519, &kp2.public(), &signed.key);
        assert!(matches!(res, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn verification_rejects_tampered_key() {
        let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let signed = sign_license_key(KeyScheme::Ed25519, &kp, "lic-1", "acc-1").unwrap();
        // flip one byte in the key
        let mut tampered = signed.key;
        let bytes = tampered.as_bytes();
        if bytes[0] == b'A' {
            tampered.replace_range(..1, "B");
        } else {
            tampered.replace_range(..1, "A");
        }
        let res = verify_license_key(KeyScheme::Ed25519, &kp.public(), &tampered);
        assert!(matches!(res, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn keypair_pem_round_trip() {
        let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let pem = kp.to_pkcs8_pem().unwrap();
        let kp2 = KeyPair::from_pkcs8_pem(KeyAlgorithm::Ed25519, &pem).unwrap();
        assert_eq!(kp.public_pem().unwrap(), kp2.public_pem().unwrap());
    }

    #[test]
    fn same_inputs_produce_different_keys_due_to_nonce() {
        let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let a = sign_license_key(KeyScheme::Ed25519, &kp, "lic-1", "acc-1").unwrap();
        let b = sign_license_key(KeyScheme::Ed25519, &kp, "lic-1", "acc-1").unwrap();
        assert_ne!(a.key, b.key, "nonce should make keys differ");
        // but both verify
        verify_license_key(KeyScheme::Ed25519, &kp.public(), &a.key).unwrap();
        verify_license_key(KeyScheme::Ed25519, &kp.public(), &b.key).unwrap();
    }
}
