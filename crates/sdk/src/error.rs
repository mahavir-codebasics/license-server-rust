//! SDK error type — maps the server's error envelope to a Rust error.

use std::fmt;

/// The error returned by every SDK call.
#[derive(Debug)]
pub struct LicenseError {
    /// HTTP status (0 for transport failures).
    pub status: u16,
    /// Machine-readable code from the envelope (`not_found`, `rate_limited`, …).
    pub code: String,
    /// Human-readable detail.
    pub message: String,
    /// Classification for programmatic handling.
    pub kind: LicenseErrorKind,
}

impl LicenseError {
    pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        let code = code.into();
        let kind = match (status, code.as_str()) {
            (0, _) => LicenseErrorKind::Transport,
            (401, _) | (403, _) => LicenseErrorKind::Auth,
            (404, _) => LicenseErrorKind::NotFound,
            (409, _) => LicenseErrorKind::Conflict,
            (422, _) => LicenseErrorKind::Policy,
            (429, _) => LicenseErrorKind::RateLimited,
            (s, _) if (400..500).contains(&s) => LicenseErrorKind::BadRequest,
            _ => LicenseErrorKind::Server,
        };
        Self {
            status,
            code,
            message: message.into(),
            kind,
        }
    }

    fn transport(e: reqwest::Error) -> Self {
        Self::new(0, "transport", e.to_string())
    }
}

/// Broad classification for `match`-friendly handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseErrorKind {
    /// Network/transport failure — retrying may help.
    Transport,
    /// 401/403 — token missing, invalid, or not permitted.
    Auth,
    /// 404 — resource missing OR cross-tenant (the server never leaks which).
    NotFound,
    /// 409 — duplicate or illegal state transition.
    Conflict,
    /// 422 — licensing policy violated (max machines, max uses, …).
    Policy,
    /// 429 — rate limited; back off and retry.
    RateLimited,
    /// Other 4xx — your request is malformed; do not blind-retry.
    BadRequest,
    /// 5xx — server-side; retrying later may help.
    Server,
}

impl fmt::Display for LicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.status == 0 {
            write!(f, "license-server unreachable: {}", self.message)
        } else {
            write!(
                f,
                "{} ({} {}): {}",
                self.code, self.status, self.kind, self.message
            )
        }
    }
}

impl fmt::Display for LicenseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transport => "transport",
            Self::Auth => "auth",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Policy => "policy",
            Self::RateLimited => "rate_limited",
            Self::BadRequest => "bad_request",
            Self::Server => "server",
        })
    }
}

impl std::error::Error for LicenseError {}

impl From<reqwest::Error> for LicenseError {
    fn from(e: reqwest::Error) -> Self {
        Self::transport(e)
    }
}
