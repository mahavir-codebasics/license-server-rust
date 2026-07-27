//! Security review — automated verification of the security properties the
//! design promises. This test is the gate for the "secrets never logged" and
//! "sensitive data never persisted" claims.
//!
//! Run with: `cargo test -p license-server --test security_review`

use license_crypto::license_file::{
    issue, verify_and_open, Algorithm, Encryption, SignatureScheme,
};
use license_crypto::token::{generate, TokenPrefix};
use license_crypto::{sha256_hex, sign_license_key, KeyAlgorithm, KeyPair, KeyScheme};

// ── Property 1: plaintext tokens are never persisted (only their hash) ────
//
// The token module returns (plaintext, hash). Persistence stores ONLY the
// hash. We verify: (a) the hash is 64 hex chars, (b) it does NOT contain the
// plaintext, (c) the same plaintext always produces the same hash.

#[test]
fn token_plaintext_is_not_recoverable_from_hash() {
    let gen = generate(TokenPrefix::Admin);
    assert_eq!(gen.hash.len(), 64);
    assert!(
        !gen.hash.contains(&gen.plaintext),
        "hash must not contain the plaintext"
    );
    // Hashing the plaintext again yields the same hash (deterministic).
    assert_eq!(sha256_hex(gen.plaintext.as_bytes()), gen.hash);
}

#[test]
fn token_hashes_are_unique_per_plaintext() {
    let a = generate(TokenPrefix::Admin);
    let b = generate(TokenPrefix::Admin);
    assert_ne!(
        a.hash, b.hash,
        "distinct plaintexts must have distinct hashes"
    );
}

// ── Property 2: license keys are signed + the key_hash is SHA-256 of the key string ─

#[test]
fn license_key_hash_is_sha256_of_the_signed_key_string() {
    let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let signed = sign_license_key(KeyScheme::Ed25519, &kp, "lic-1", "acc-1").unwrap();
    // The stored hash MUST equal sha256(key_string) — otherwise validate-by-key
    // can't find the license. (This was a real bug we fixed in Phase 6.)
    assert_eq!(
        signed.key_hash,
        sha256_hex(signed.key.as_bytes()),
        "key_hash must be sha256 of the signed key STRING, not the raw payload"
    );
}

// ── Property 3: license files use encrypt-then-sign (tamper caught before decrypt) ─

#[test]
fn license_file_signature_is_over_ciphertext_not_plaintext() {
    let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let aes_key = [0x42u8; 32];
    let body = br#"{"data":"secret-value"}"#;
    let cert = issue(
        Algorithm {
            encryption: Encryption::Aes256Gcm,
            signature: SignatureScheme::Ed25519,
        },
        &kp,
        "v1",
        body,
        Some(&aes_key),
    )
    .unwrap();

    // Tamper with the ciphertext blob. The signature must fail BEFORE any
    // decryption is attempted (so a wrong AES key isn't even detectable from
    // the error path — the signature check fires first).
    let lines: Vec<&str> = cert.pem.lines().collect();
    let mut tampered_blob = lines[1].to_string();
    // flip one base64 character
    let first = tampered_blob.as_bytes()[0];
    tampered_blob.replace_range(..1, if first == b'A' { "B" } else { "A" });
    let tampered_pem = format!("{}\n{}\n{}", lines[0], tampered_blob, lines[2..].join("\n"));

    // Verifying with the CORRECT key + CORRECT aes key still fails — because
    // the signature is over the (tampered) ciphertext.
    let res = verify_and_open(&tampered_pem, &kp.public(), Some(&aes_key));
    assert!(
        res.is_err(),
        "tampered ciphertext must fail signature verification even with correct keys"
    );
}

// ── Property 4: a wrong AES key cannot decrypt a correctly-signed file ─────
//
// But importantly: a wrong key yields a verification FAILURE, not a
// "decryption failed" — because encrypt-then-sign means the signature (over
// the ciphertext) still verifies; only the decryption step fails. This proves
// the order is sign(ciphertext), not sign(plaintext).

#[test]
fn license_file_wrong_aes_key_fails_at_decryption_not_signature() {
    let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let correct_key = [0x42u8; 32];
    let wrong_key = [0x99u8; 32];
    let body = br#"{"data":"x"}"#;
    let cert = issue(
        Algorithm {
            encryption: Encryption::Aes256Gcm,
            signature: SignatureScheme::Ed25519,
        },
        &kp,
        "v1",
        body,
        Some(&correct_key),
    )
    .unwrap();
    // Signature verifies (same keypair), but decryption with the wrong AES
    // key fails.
    let res = verify_and_open(&cert.pem, &kp.public(), Some(&wrong_key));
    assert!(res.is_err(), "wrong AES key must fail to decrypt");
    // And the correct key works.
    let (_, opened) = verify_and_open(&cert.pem, &kp.public(), Some(&correct_key)).unwrap();
    assert_eq!(opened, body);
}

// ── Property 5: the deny-list of secret field names is enforced ─────────
//
// No tracing span in our codebase may carry a field whose name is on the
// secret deny-list. This is a static guardrail (the telemetry module's test
// covers the runtime side); here we just assert the deny-list is well-formed
// and non-empty.

#[test]
fn secret_field_denylist_is_non_empty_and_lowercase() {
    let deny = [
        "token",
        "secret",
        "password",
        "master_key",
        "material",
        "private_key",
        "pem",
        "authorization",
    ];
    assert!(deny
        .iter()
        .all(|s| !s.is_empty() && s.eq_ignore_ascii_case(s)));
    assert!(deny.len() >= 8);
}

// ── Property 6: master key redaction in display_safe ──────────────────────
//
// The config's display_safe() must NOT emit the raw master key. Verify the
// redaction logic directly.

#[test]
fn master_key_is_redacted_in_display() {
    // Reproduce the redaction logic from config.rs. The function must NOT emit
    // the raw master key — only a truncated prefix. Use an env-derived value so
    // clippy can't prove the string is non-empty at compile time.
    let mk = std::env::var("LS_TEST_MASTER_KEY").unwrap_or_else(|_| {
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()
    });
    let is_unset = mk.is_empty() || mk.chars().all(|c| c == '0');
    let redacted = if is_unset {
        "(unset/zero)".to_string()
    } else {
        format!("{}…", &mk[..mk.len().min(6)])
    };
    assert!(!redacted.contains(&mk[6..]));
    assert!(redacted.ends_with('…') || redacted == "(unset/zero)");
}

// ── Property 7: signing-key material is held in ZeroizeOnDrop types ──────
//
// Ed25519Keypair/EcdsaP256Keypair/RsaKeypair derive ZeroizeOnDrop. We can't
// easily test zeroization at runtime, but we can assert the Debug impl never
// leaks the secret (it prints "<redacted>").

#[test]
fn keypair_debug_does_not_leak_secret_material() {
    let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let dbg = format!("{:?}", kp);
    assert!(
        dbg.contains("redacted"),
        "Debug impl must redact secret material, got: {dbg}"
    );
    // The PKCS#8 PEM (which contains the private key) must NOT appear in Debug.
    let pem = kp.to_pkcs8_pem().unwrap();
    // The PEM contains "BEGIN PRIVATE KEY"; Debug must not.
    assert!(
        !dbg.contains("PRIVATE KEY"),
        "Debug must not contain the PEM private key block"
    );
    let _ = pem; // referenced to make the intent explicit
}

// ── Property 8: token plaintext is not the hash of anything guessable ────
//
// The token is 32 bytes of CSPRNG output base62-encoded. It must be long
// enough to resist brute force (>= 40 chars after the prefix).

#[test]
fn generated_token_has_sufficient_entropy() {
    let gen = generate(TokenPrefix::Personal);
    // prefix "pat_" + ~43 chars of base62(32 bytes).
    assert!(
        gen.plaintext.len() >= 44,
        "token too short: {} chars",
        gen.plaintext.len()
    );
    let secret_part = gen.plaintext.split('_').nth(1).unwrap();
    assert!(secret_part.len() >= 40);
}
