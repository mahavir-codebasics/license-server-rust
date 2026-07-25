//! Crypto error type.

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("decryption failed (wrong key or tampered ciphertext)")]
    DecryptionFailed,

    #[error("unsupported scheme/algorithm: {0}")]
    Unsupported(String),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("decoding error: {0}")]
    Decoding(String),

    #[error("keystore error: {0}")]
    KeyStore(String),

    #[error("internal crypto error: {0}")]
    Internal(String),
}

impl From<rsa::errors::Error> for CryptoError {
    fn from(e: rsa::errors::Error) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<ed25519_dalek::ed25519::Error> for CryptoError {
    fn from(_: ed25519_dalek::ed25519::Error) -> Self {
        Self::SignatureInvalid
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Decoding(e.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        Self::Internal(e.to_string())
    }
}
