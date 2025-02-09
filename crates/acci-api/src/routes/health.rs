//! Health check endpoint implementation.

use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::error::ApiResult;

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Status of the service
    pub status: String,
    /// Version of the service
    pub version: String,
}

/// Creates a router for health check endpoints
pub fn router() -> Router {
    Router::new().route("/health", get(health_check))
}

/// Health check handler
#[instrument(skip_all)]
async fn health_check() -> ApiResult<Json<HealthResponse>> {
    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check_response() {
        // Act
        let result = health_check().await.unwrap();
        let response = result.0;

        // Assert
        assert_eq!(response.status, "ok");
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_health_response_serialization() {
        // Arrange
        let response = HealthResponse {
            status: "ok".to_string(),
            version: "1.0.0".to_string(),
        };

        // Act
        let json = serde_json::to_string(&response).unwrap();

        // Assert
        assert_eq!(json, r#"{"status":"ok","version":"1.0.0"}"#);
    }

    #[test]
    fn test_health_response_deserialization() {
        // Arrange
        let json = r#"{"status":"ok","version":"1.0.0"}"#;

        // Act
        let response: HealthResponse = serde_json::from_str(json).unwrap();

        // Assert
        assert_eq!(response.status, "ok");
        assert_eq!(response.version, "1.0.0");
    }
}
