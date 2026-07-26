//! `license-api` — axum REST handlers.
//!
//! Performance-first, idiomatic REST/JSON (not JSON:API). Wire format:
//!
//! ```json
//! { "data": <T>, "meta": { "cursor": "...", "has_more": true } }
//! { "errors": [ { "code": "...", "title": "...", "detail": "...", "status": 404 } ] }
//! ```
//!
//! Keyset/cursor pagination everywhere (no OFFSET). All tenant-scoped routes
//! under `/v1/accounts/{accountId}/...`.

pub mod auth;
pub mod error;
pub mod extract;
pub mod response;
pub mod routes;

pub use error::{ApiError, ApiResult};
pub use response::{Envelope, EnvelopePage, ErrorObject, Meta};
pub use routes::router;
