//! Error types for the API crate.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;
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
                #[allow(clippy::large_stack_arrays)]
                {
                    tracing::error!(error.message = %e, error.display = %self);
                }
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            },
            Self::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::BadRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
        };

        let mut error_obj = serde_json::Map::new();
        let mut inner_obj = serde_json::Map::new();
        inner_obj.insert("message".to_string(), Value::String(message));
        inner_obj.insert("code".to_string(), Value::Number(status.as_u16().into()));
        error_obj.insert("error".to_string(), Value::Object(inner_obj));

        (status, Json(Value::Object(error_obj))).into_response()
    }
}

/// Result type for API operations
pub type ApiResult<T> = Result<T, ApiError>;
