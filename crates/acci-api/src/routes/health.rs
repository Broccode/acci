//! Health check endpoint implementation.

use axum::http::StatusCode;
use axum::{routing::get, Router};
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Status of the service
    pub status: String,
    /// Version of the service
    pub version: String,
}

/// Creates the health routes
///
/// # Returns
///
/// The router with the health routes
pub fn create_health_routes() -> Router {
    Router::new().route("/health", get(health_check))
}

/// Health check handler
///
/// # Returns
///
/// 200 OK if the service is healthy
#[instrument(skip_all)]
pub async fn health_check() -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check_response() {
        // Act
        let result = health_check().await;

        // Assert
        assert_eq!(result, StatusCode::OK);
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
