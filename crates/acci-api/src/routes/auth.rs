//! Authentication endpoints implementation.

#![allow(clippy::large_stack_arrays)]

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use acci_auth::BasicAuthProvider;
use acci_core::{
    auth::{AuthProvider, AuthResponse, Credentials},
    error::Error,
};
use tracing::{error, info, instrument};

/// Login request payload
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Username or email
    pub username: String,
    /// Password
    pub password: String,
}

/// Login response payload
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    /// The authentication response containing the session and token
    pub token: String,
}

/// Creates the authentication router with all routes.
///
/// # Arguments
///
/// * `auth_provider` - The authentication provider
///
/// # Returns
///
/// The router with the auth routes
pub fn create_auth_routes(auth_provider: Arc<BasicAuthProvider>) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/health", get(health_check))
        .with_state(auth_provider)
}

/// Login handler
///
/// # Arguments
///
/// * `auth_provider` - The authentication provider
/// * `credentials` - The login credentials
///
/// # Returns
///
/// The login response or an error
#[instrument(skip_all)]
pub async fn login(
    State(auth_provider): State<Arc<BasicAuthProvider>>,
    Json(credentials): Json<Credentials>,
) -> Result<Json<AuthResponse>, StatusCode> {
    match auth_provider.authenticate(credentials).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => match e {
            Error::NotFound(_) => Err(StatusCode::NOT_FOUND),
            Error::InvalidCredentials(_) => Err(StatusCode::UNAUTHORIZED),
            _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
        },
    }
}

/// Logout endpoint handler
///
/// # Errors
///
/// Returns an error if:
/// - The session is not found
/// - The session deletion fails
pub async fn logout(
    State(auth_provider): State<Arc<BasicAuthProvider>>,
    Path(session_id): Path<Uuid>,
) -> impl IntoResponse {
    match auth_provider.logout(session_id).await {
        Ok(()) => {
            info!(session_id = %session_id, "User logged out successfully");
            StatusCode::NO_CONTENT
        },
        Err(e) => {
            error!(error = %e, session_id = %session_id, "Logout failed");
            match e {
                Error::NotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
        },
    }
}

/// Token validation route handler
#[instrument(skip_all)]
pub async fn validate(
    State(auth_provider): State<Arc<BasicAuthProvider>>,
    Json(token): Json<String>,
) -> Result<Json<bool>, StatusCode> {
    match auth_provider.validate_token(token).await {
        Ok(_) => Ok(Json(true)),
        Err(e) => match e {
            Error::NotFound(_) => Err(StatusCode::NOT_FOUND),
            Error::InvalidToken(_) => Err(StatusCode::UNAUTHORIZED),
            _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
        },
    }
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
