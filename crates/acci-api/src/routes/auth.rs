//! Authentication endpoints implementation.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use acci_auth::BasicAuthProvider;
use acci_core::{
    auth::{AuthProvider, AuthResponse, Credentials},
    error::Error as CoreError,
};

use crate::error::{ApiError, ApiResult};

/// Login request payload
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Username or email
    pub username: String,
    /// Password
    pub password: String,
}

/// Creates a router for authentication endpoints
pub fn router() -> Router {
    Router::new().route("/auth/login", post(login))
}

/// Login handler
#[instrument(skip_all, fields(username = %credentials.username))]
async fn login(Json(credentials): Json<LoginRequest>) -> ApiResult<Json<AuthResponse>> {
    let auth_provider = BasicAuthProvider::new(Default::default());

    let credentials = Credentials {
        username: credentials.username,
        password: credentials.password,
    };

    match auth_provider.authenticate(credentials).await {
        Ok(response) => Ok(Json(response)),
        Err(CoreError::InvalidCredentials) => Err(ApiError::Unauthorized),
        Err(CoreError::AuthenticationFailed(msg)) => Err(ApiError::BadRequest(msg)),
        Err(e) => Err(ApiError::Internal(e.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let app = router();

        let request = Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "invalid@example.com",
                    "password": "wrongpassword"
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
