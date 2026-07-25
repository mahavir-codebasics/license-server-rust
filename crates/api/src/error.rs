//! API error type + mapping from domain errors.
//!
//! Domain errors never leak DB internals: a cross-tenant access maps to 404
//! (not 403), so a caller can't distinguish "doesn't exist" from "not yours".

use crate::response::{ErrorEnvelope, ErrorObject};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use license_domain::DomainError;
use serde_json::json;

pub type ApiResult<T> = Result<T, ApiError>;

/// An error ready to become an HTTP response.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    title: &'static str,
    detail: String,
}

impl ApiError {
    pub fn new(
        status: StatusCode,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            title,
            detail: detail.into(),
        }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "Bad request",
            detail,
        )
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "Not found", detail)
    }

    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", "Conflict", detail)
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
            "a valid bearer token is required",
        )
    }

    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "Forbidden", detail)
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Internal server error",
            detail,
        )
    }
}

/// Map a domain error to an HTTP status. Cross-tenant → 404 (hide existence).
impl From<DomainError> for ApiError {
    fn from(e: DomainError) -> Self {
        match e {
            DomainError::NotFound(msg) | DomainError::CrossTenant(msg) => ApiError::not_found(msg),
            DomainError::Conflict(msg) => ApiError::conflict(msg),
            DomainError::Invalid(msg) => ApiError::bad_request(msg),
            DomainError::InvalidState(msg) => {
                ApiError::new(StatusCode::CONFLICT, "invalid_state", "Invalid state", msg)
            }
            DomainError::PolicyViolated(msg) => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "policy_violated",
                "Policy violated",
                msg,
            ),
            DomainError::Unauthorized(msg) => ApiError::forbidden(msg),
            DomainError::Crypto(msg) => ApiError::internal(format!("crypto: {msg}")),
            DomainError::Internal(msg) => {
                tracing::error!(error = %msg, "internal domain error");
                ApiError::internal("an internal error occurred")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let env = ErrorEnvelope {
            errors: vec![ErrorObject {
                code: self.code.into(),
                title: self.title.into(),
                detail: self.detail,
                status: self.status.as_u16(),
            }],
        };
        (self.status, Json(env)).into_response()
    }
}

/// A fallback 404 for unmatched routes — returns the standard error envelope
/// so clients always see the same shape.
pub async fn fallback() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "errors": [{
                "code": "not_found",
                "title": "Not found",
                "detail": "no route matches this request",
                "status": 404
            }]
        })),
    )
        .into_response()
}
