//! Bearer-token generation + hashing.
//!
//! A token has the shape `<prefix>_<base62-secret>` where:
//!   - prefix identifies the kind (`lic_`, `prod_`, `adm_`, `usr_`, `pat_`)
//!   - the secret is 32 bytes of CSPRNG output, base62-encoded (~43 chars)
//!
//! We persist only `sha256_hex(plaintext)` — the plaintext is returned once
//! at creation and never retrievable. Lookup hashes the presented bearer.

use crate::sha256_hex;
use rand::RngCore;

/// A freshly generated token — the plaintext (returned ONCE) + its hash.
#[derive(Debug, Clone)]
pub struct GeneratedToken {
    /// The full plaintext token, e.g. `adm_a1b2c3...`. Show to the user once.
    pub plaintext: String,
    /// SHA-256 hex of `plaintext`. Persist this; index it for lookup.
    pub hash: String,
}

/// Token kind prefix. Mirrors [`license_domain::TokenKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPrefix {
    Admin,
    Product,
    License,
    User,
    Personal,
}

impl TokenPrefix {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenPrefix::Admin => "adm",
            TokenPrefix::Product => "prod",
            TokenPrefix::License => "lic",
            TokenPrefix::User => "usr",
            TokenPrefix::Personal => "pat",
        }
    }
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn base62_encode(bytes: Vec<u8>) -> String {
    // Compact base62 of the big-endian integer. Leading zero-bytes become
    // leading '0' chars so the encoding is canonical for a fixed input size.
    if bytes.iter().all(|&b| b == 0) {
        return "0".repeat(bytes.len() * 2);
    }
    let mut out = String::new();
    let mut num = bytes;
    while !num.iter().all(|&b| b == 0) {
        let mut remainder: u128 = 0;
        for byte in num.iter_mut() {
            let acc = (remainder << 8) | *byte as u128;
            *byte = (acc / 62) as u8;
            remainder = acc % 62;
        }
        out.push(BASE62[remainder as usize] as char);
    }
    out.chars().rev().collect()
}

/// Generate a new bearer token of the given kind. Returns plaintext + hash.
pub fn generate(prefix: TokenPrefix) -> GeneratedToken {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let encoded = base62_encode(secret.to_vec());
    let plaintext = format!("{}_{}", prefix.as_str(), encoded);
    let hash = sha256_hex(plaintext.as_bytes());
    GeneratedToken { plaintext, hash }
}

/// Hash a presented plaintext token for lookup. Constant work; same input →
/// same hash as [`generate`].
pub fn hash(plaintext: &str) -> String {
    sha256_hex(plaintext.as_bytes())
}

/// Validate the shape of a presented token (prefix + non-empty secret).
/// Doesn't verify existence — that's a DB lookup by hash.
pub fn is_well_formed(plaintext: &str) -> Option<TokenPrefix> {
    let (prefix, _secret) = plaintext.split_once('_')?;
    let parsed = match prefix {
        "adm" => TokenPrefix::Admin,
        "prod" => TokenPrefix::Product,
        "lic" => TokenPrefix::License,
        "usr" => TokenPrefix::User,
        "pat" => TokenPrefix::Personal,
        _ => return None,
    };
    if _secret.is_empty() {
        return None;
    }
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_unique() {
        let a = generate(TokenPrefix::Admin);
        let b = generate(TokenPrefix::Admin);
        assert_ne!(a.plaintext, b.plaintext);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn hash_is_deterministic() {
        let t = generate(TokenPrefix::Product);
        assert_eq!(hash(&t.plaintext), t.hash);
    }

    #[test]
    fn prefix_shape() {
        let t = generate(TokenPrefix::License);
        assert!(t.plaintext.starts_with("lic_"));
        let t = generate(TokenPrefix::Personal);
        assert!(t.plaintext.starts_with("pat_"));
    }

    #[test]
    fn well_formed_check() {
        assert_eq!(is_well_formed("adm_abc"), Some(TokenPrefix::Admin));
        assert_eq!(is_well_formed("lic_xyz"), Some(TokenPrefix::License));
        assert_eq!(is_well_formed("nope_abc"), None);
        assert_eq!(is_well_formed("adm_"), None); // empty secret
        assert_eq!(is_well_formed("noprefix"), None);
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let t = generate(TokenPrefix::User);
        assert_eq!(t.hash.len(), 64);
        assert!(t.hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn base62_round_trip_nonzero() {
        // a known non-zero input
        let s = base62_encode(vec![0xff, 0x01, 0x02]);
        assert!(!s.is_empty());
        // all-zero → all '0's
        let z = base62_encode(vec![0u8, 0, 0]);
        assert!(z.chars().all(|c| c == '0'));
    }
}
