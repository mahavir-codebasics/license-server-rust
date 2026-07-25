//! Product — the software being licensed.

use crate::account::AccountId;
use crate::value::Metadata;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

declare_id!(ProductId, "Identifier of a [`Product`].");

/// A product groups policies and is mostly an organizational entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    pub id: ProductId,
    pub account_id: AccountId,
    pub name: String,
    /// Optional distribution/url metadata for the SDK / UI.
    pub url: Option<String>,
    pub metadata: Metadata,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Product {
    pub fn new(account_id: AccountId, name: impl Into<String>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: ProductId::now(),
            account_id,
            name: name.into(),
            url: None,
            metadata: Metadata::new(),
            created_at: now,
            updated_at: now,
        }
    }
}
