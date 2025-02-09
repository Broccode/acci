//! Error types for the API crate.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// API specific error types
#[derive(Debug, Error)]
pub enum ApiError {
    /// Internal server error
    #[error("Internal server error")]
    Internal(#[from] anyhow::Error),

    /// Not found error
    #[error("Resource not found")]
    NotFound,

    /// Bad request error
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Unauthorized error
    #[error("Unauthorized")]
    Unauthorized,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Internal(ref e) => {
                tracing::error!("Internal server error: {:#}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            },
            Self::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::BadRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
        };

        let body = Json(json!({
            "error": {
                "message": message,
                "code": status.as_u16()
            }
        }));

        (status, body).into_response()
    }
}

/// Result type for API operations
pub type ApiResult<T> = Result<T, ApiError>;
