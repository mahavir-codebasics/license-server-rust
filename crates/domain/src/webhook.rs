//! Webhooks — outbound HTTP notifications with HMAC signing + retries.

use crate::account::AccountId;
use crate::value::Metadata;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

declare_id!(WebhookEndpointId, "Identifier of a [`WebhookEndpoint`].");
declare_id!(WebhookEventId, "Identifier of a [`WebhookEvent`].");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WebhookStatus {
    #[default]
    Active,
    Disabled,
}

/// A destination URL + secret for signed webhook delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub id: WebhookEndpointId,
    pub account_id: AccountId,
    pub url: String,
    /// Event types to subscribe to (empty = all).
    pub event_types: Vec<String>,
    /// HMAC-SHA256 secret (stored encrypted; never serialized to responses).
    #[serde(skip)]
    pub secret: String,
    pub status: WebhookStatus,
    pub metadata: Metadata,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl WebhookEndpoint {
    pub fn new(account_id: AccountId, url: impl Into<String>, secret: impl Into<String>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: WebhookEndpointId::now(),
            account_id,
            url: url.into(),
            event_types: Vec::new(),
            secret: secret.into(),
            status: WebhookStatus::Active,
            metadata: Metadata::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

/// A single delivery attempt record (queue item for the webhook worker).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub id: WebhookEventId,
    pub account_id: AccountId,
    pub endpoint_id: WebhookEndpointId,
    /// Event type, e.g. `license.validation.valid`.
    pub event_type: String,
    /// JSON payload to deliver.
    pub payload: serde_json::Value,
    /// Attempt count (0 = not yet sent).
    pub attempts: u32,
    /// Whether delivery has ultimately succeeded.
    pub delivered: bool,
    pub last_response_status: Option<u16>,
    pub last_error: Option<String>,
    pub next_retry_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
