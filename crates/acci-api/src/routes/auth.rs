//! Authentication endpoints implementation.

#![allow(clippy::large_stack_arrays)]

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, instrument};
use validator::Validate;

use acci_auth::{AuthConfig, BasicAuthProvider};
use acci_core::{
    auth::{AuthProvider, AuthResponse, Credentials},
    error::Error as CoreError,
};
use acci_db::{
    repositories::{session::PgSessionRepository, user::PgUserRepository},
    sqlx::PgPool,
};

use crate::error::{ApiError, ApiResult};
use acci_db::repositories::session::SessionRepository;
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use rand::rngs::OsRng;

/// Login request payload
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    /// Username or email
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    /// Password
    #[validate(length(min = 8, max = 72))]
    pub password: String,
}

/// Login response payload
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// The authentication response containing the session and token
    pub auth: AuthResponse,
    /// The type of token (e.g., "Bearer")
    pub token_type: String,
}

/// Creates a router for authentication endpoints
pub fn router(pool: PgPool) -> Router {
    Router::new().route("/auth/login", post(login).with_state(pool))
}

/// Login handler
///
/// # Errors
///
/// Returns an error in the following cases:
/// - Invalid credentials (401 Unauthorized)
/// - Invalid input format (400 Bad Request)
/// - Internal server error (500 Internal Server Error)
///
/// # Example Request
///
/// ```json
/// {
///     "username": "admin@example.com",
///     "password": "your-password"
/// }
/// ```
///
/// # Example Response
///
/// ```json
/// {
///     "auth": {
///         "session": {
///             "session_id": "123e4567-e89b-12d3-a456-426614174000",
///             "user_id": "123e4567-e89b-12d3-a456-426614174000",
///             "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
///             "created_at": 1679825167,
///             "expires_at": 1679828767
///         },
///         "token_type": "Bearer"
///     }
/// }
/// ```
#[allow(clippy::large_stack_arrays)]
#[instrument(skip_all, fields(username = %credentials.username))]
async fn login(
    State(pool): State<PgPool>,
    Json(credentials): Json<LoginRequest>,
) -> ApiResult<Json<AuthResponse>> {
    debug!("Processing login request");

    // Validate request using validator
    if let Err(validation_errors) = credentials.validate() {
        error!("Validation failed: {:?}", validation_errors);
        return Err(ApiError::BadRequest(validation_errors.to_string()));
    }

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let auth_provider = BasicAuthProvider::new(user_repo, session_repo, AuthConfig::default());

    let credentials = Credentials {
        username: credentials.username.trim().to_string(),
        password: credentials.password,
    };

    match auth_provider.authenticate(credentials).await {
        Ok(response) => {
            info!("User successfully authenticated");
            Ok(Json(response))
        },
        Err(CoreError::InvalidCredentials) => {
            error!("Invalid credentials provided");
            Err(ApiError::Unauthorized)
        },
        Err(CoreError::AuthenticationFailed(msg)) => {
            error!("Authentication failed: {}", msg);
            Err(ApiError::BadRequest(msg))
        },
        Err(e) => {
            error!("Internal error during authentication: {}", e);
            Err(ApiError::Internal(e.into()))
        },
    }
}
