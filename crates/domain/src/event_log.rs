//! EventLog — append-only audit trail of every meaningful action.
//!
//! Written asynchronously by the `event-log-writer` job. Source of truth for
//! the admin UI's activity feed and for compliance/forensics.

use crate::account::AccountId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

declare_id!(EventLogId, "Identifier of an [`EventLog`] entry.");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    #[default]
    Info,
    Warning,
    Critical,
}

/// A single audit event. `payload` is opaque JSON to keep this table stable
/// as the schema evolves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLog {
    pub id: EventLogId,
    pub account_id: AccountId,
    /// Dotted event name, e.g. `license.created`, `machine.activated`.
    pub event_type: String,
    pub severity: EventSeverity,
    /// Actor: a user id, token id, or "system" for background jobs.
    pub actor_id: Option<String>,
    /// Affected resource type/id (best-effort).
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub payload: serde_json::Value,
    /// Request id correlating with API logs.
    pub request_id: Option<String>,
    /// Originating IP, when known.
    pub ip: Option<String>,
    pub created_at: OffsetDateTime,
}

impl EventLog {
    pub fn new(
        account_id: AccountId,
        event_type: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: EventLogId::now(),
            account_id,
            event_type: event_type.into(),
            severity: EventSeverity::Info,
            actor_id: None,
            resource_type: None,
            resource_id: None,
            payload,
            request_id: None,
            ip: None,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}
