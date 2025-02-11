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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_api_error_internal() {
        let error = ApiError::Internal(anyhow::anyhow!("test error"));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = response_to_json(response).await;
        assert_eq!(body["error"]["code"], 500);
        assert_eq!(body["error"]["message"], "Internal server error");
    }

    #[tokio::test]
    async fn test_api_error_not_found() {
        let error = ApiError::NotFound;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = response_to_json(response).await;
        assert_eq!(body["error"]["code"], 404);
        assert_eq!(body["error"]["message"], "Resource not found");
    }

    #[tokio::test]
    async fn test_api_error_bad_request() {
        let error = ApiError::BadRequest("Invalid input".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = response_to_json(response).await;
        assert_eq!(body["error"]["code"], 400);
        assert_eq!(body["error"]["message"], "Invalid input");
    }

    #[tokio::test]
    async fn test_api_error_unauthorized() {
        let error = ApiError::Unauthorized;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = response_to_json(response).await;
        assert_eq!(body["error"]["code"], 401);
        assert_eq!(body["error"]["message"], "Unauthorized");
    }

    // Helper function to convert response to JSON Value
    async fn response_to_json(response: Response) -> Value {
        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();
        serde_json::from_str(&body_str).unwrap()
    }
}
