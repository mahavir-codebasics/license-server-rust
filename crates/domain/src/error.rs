//! Domain errors.
//!
//! Domain errors are intentionally coarse-grained and stable: the API layer
//! maps them to HTTP/gRPC statuses, and persistence backends map their
//! driver-specific errors into these. Keeping the set small and meaningful
//! avoids leaking DB internals through the API surface.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, DomainError>;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("resource not found: {0}")]
    NotFound(String),

    /// A write violated a uniqueness constraint (duplicate key, fingerprint, etc.).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Caller referenced a resource in a different account. Returned as
    /// `NotFound` to avoid leaking the existence of cross-tenant rows —
    /// callers should treat this identically to a genuine miss.
    #[error("resource not found: {0}")]
    CrossTenant(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    /// A state transition was illegal, e.g. revoking an already-revoked license.
    #[error("invalid state transition: {0}")]
    InvalidState(String),

    /// A policy/license/machine rule was violated, e.g. activating more
    /// machines than `max_machines` allows.
    #[error("policy violated: {0}")]
    PolicyViolated(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Anything the persistence layer couldn't classify. Carries the driver
    /// message for debugging but the API layer never surfaces it raw.
    #[error("internal error")]
    Internal(String),
}

impl DomainError {
    /// Convenience constructor.
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }
}
