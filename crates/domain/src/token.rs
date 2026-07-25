//! Token — bearer authentication credential.
//!
//! Security: tokens are stored only as their **SHA-256 hash**. The plaintext
//! token is returned exactly once at creation and never retrievable again.
//! Lookup at request time hashes the presented bearer and matches by hash.

use crate::account::AccountId;
use crate::id::TokenId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// What a token authenticates as / is scoped to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    /// Full account admin. Used by the UI / CI.
    Admin,
    /// Server-side product operations (creating licenses, etc).
    Product,
    /// Acts on behalf of a single license (client SDKs).
    License,
    /// Acts on behalf of an end-user.
    User,
    /// Personal access token for a user.
    Personal,
}

/// Capabilities granted by a token. v1 uses kind-based scoping; wildcard
/// permission strings are a deferred fine-grained feature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenScope {
    pub kind: Option<TokenKind>,
    /// Constrained resource id (e.g. product id for a product token).
    pub resource_id: Option<String>,
}

/// A bearer token record. `token_hash` holds SHA-256(plaintext) hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: TokenId,
    pub account_id: AccountId,
    pub kind: TokenKind,
    pub name: Option<String>,
    /// SHA-256 hex of the plaintext token. Indexed for lookup.
    #[serde(skip)]
    pub token_hash: String,
    /// Optional expiry.
    pub expiry: Option<OffsetDateTime>,
    /// Last time the token was used (best-effort).
    pub last_used_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Token {
    pub fn new(account_id: AccountId, kind: TokenKind, token_hash: impl Into<String>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: TokenId::now(),
            account_id,
            kind,
            name: None,
            token_hash: token_hash.into(),
            expiry: None,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        }
    }
}
