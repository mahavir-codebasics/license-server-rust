//! Wire models — self-contained so the SDK has no server-crate dependencies.
//! Field names match the JSON wire format exactly.

use serde::{Deserialize, Serialize};

/// Single-resource envelope: `{ "data": T }`.
#[derive(Debug, Deserialize)]
pub struct Envelope<T> {
    pub data: T,
}

/// Collection envelope with keyset-pagination cursor.
#[derive(Debug, Deserialize)]
pub struct EnvelopePage<T> {
    pub data: Vec<T>,
    pub meta: Option<PageMeta>,
}

#[derive(Debug, Deserialize)]
pub struct PageMeta {
    pub cursor: Option<String>,
    pub has_more: Option<bool>,
}

impl<T> EnvelopePage<T> {
    /// Cursor to pass to `*_after` methods for the next page (None on last page).
    pub fn next_cursor(&self) -> Option<&str> {
        self.meta.as_ref()?.cursor.as_deref()
    }
}

// ── Resources ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Account {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub protection_mode: String,
    pub created_at: String,
}

/// `POST /v1/accounts` response — carries the bootstrap admin token ONCE.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateAccountResponse {
    #[serde(flatten)]
    pub account: Account,
    pub admin_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Product {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub url: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    pub id: String,
    pub account_id: String,
    pub product_id: String,
    pub name: String,
    pub scheme: String,
    pub max_machines: Option<u32>,
    pub max_uses: Option<u64>,
    pub renewable: bool,
    pub protected: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct License {
    pub id: String,
    pub account_id: String,
    pub product_id: String,
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub state: String,
    pub license_type: String,
    pub uses: u64,
    pub max_uses: Option<u64>,
    pub expiry: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Machine {
    pub id: String,
    pub account_id: String,
    pub license_id: String,
    pub fingerprint: String,
    pub name: Option<String>,
    pub platform: Option<String>,
    pub state: String,
    pub next_heartbeat: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Token {
    pub id: String,
    pub account_id: String,
    pub kind: String,
    pub name: Option<String>,
    pub expiry: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

/// `POST /tokens` response — carries the plaintext token ONCE.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateTokenResponse {
    #[serde(flatten)]
    pub token: Token,
    /// The plaintext bearer (`prod_…`), present only on creation.
    #[serde(rename = "token")]
    pub token_plaintext: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookEndpoint {
    pub id: String,
    pub url: String,
    pub status: String,
    pub created_at: String,
}

/// `POST /webhooks/endpoints` response — carries the HMAC secret ONCE.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateWebhookResponse {
    #[serde(flatten)]
    pub endpoint: WebhookEndpoint,
    pub secret: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Event {
    pub id: String,
    pub event_type: String,
    pub severity: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub state: String,
    pub detail: Option<String>,
}

/// A checked-out license file (PEM certificate).
#[derive(Debug, Clone, Deserialize)]
pub struct LicenseFile {
    pub id: String,
    pub algorithm: String,
}

// ── Request bodies ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(crate) struct CreateAccountBody<'a> {
    pub slug: &'a str,
    pub name: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateProductBody<'a> {
    pub name: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreatePolicyBody<'a> {
    pub product_id: &'a str,
    pub name: &'a str,
    pub scheme: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateLicenseBody<'a> {
    pub product_id: &'a str,
    pub policy_id: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateTokenBody<'a> {
    pub kind: &'a str,
    pub name: Option<&'a str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateWebhookBody<'a> {
    pub url: &'a str,
    pub event_types: &'a [String],
}
