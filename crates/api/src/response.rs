//! Response envelope + error objects.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

/// A successful handler result. Wraps `Result<T, ApiError>` so any `T:
/// Serialize` works as a response via the `Envelope` envelope.
impl<T: Serialize> IntoResponse for Envelope<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl<T: Serialize> IntoResponse for EnvelopePage<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// Single-resource envelope: `{ "data": T, "meta": {...} }`.
#[derive(Debug, Serialize)]
pub struct Envelope<T> {
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
}

/// List envelope: `{ "data": [T], "meta": { cursor, has_more } }`.
#[derive(Debug, Serialize)]
pub struct EnvelopePage<T> {
    pub data: Vec<T>,
    pub meta: Meta,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Meta {
    /// Opaque cursor for the next page (`?page[after]=...`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub has_more: bool,
}

impl<T> Envelope<T> {
    pub fn ok(data: T) -> Self {
        Self { data, meta: None }
    }
}

impl<T> EnvelopePage<T> {
    pub fn new(data: Vec<T>, next_cursor: Option<String>) -> Self {
        let has_more = next_cursor.is_some();
        Self {
            data,
            meta: Meta {
                cursor: next_cursor,
                has_more,
            },
        }
    }
}

/// A single API error, JSON:API-style.
#[derive(Debug, Serialize)]
pub struct ErrorObject {
    pub code: String,
    pub title: String,
    pub detail: String,
    pub status: u16,
}

#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    pub errors: Vec<ErrorObject>,
}

impl IntoResponse for ErrorEnvelope {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.errors[0].status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}
