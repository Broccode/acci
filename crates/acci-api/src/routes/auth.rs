//! Authentication endpoints implementation.

#![allow(clippy::large_stack_arrays)]

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use acci_auth::BasicAuthProvider;
use acci_core::auth::{AuthConfig, AuthProvider, Credentials};
use acci_db::{
    create_pool,
    repositories::{PgSessionRepository, PgUserRepository},
    sqlx::PgPool,
    DbConfig,
};

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
/// # Panics
/// Panics if the database connection pool cannot be created.
pub async fn create_auth_router(db_config: DbConfig) -> Router {
    let pool = create_pool(db_config)
        .await
        .expect("Failed to create database connection pool");
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let auth_config = AuthConfig::default();
    let auth_provider = Arc::new(BasicAuthProvider::new(user_repo, session_repo, auth_config));

    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/validate", get(validate))
        .with_state(auth_provider)
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
async fn login(
    State(auth_provider): State<Arc<BasicAuthProvider>>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, String> {
    let credentials = Credentials {
        username: request.username,
        password: request.password,
    };

    let auth_result = auth_provider
        .authenticate(credentials)
        .await
        .map_err(|e| e.to_string())?;

    Ok(Json(LoginResponse {
        token: auth_result.session.token,
    }))
}

/// Handles user registration.
///
/// # Errors
/// Returns an error if:
/// - User already exists
/// - Database operation fails
/// - Password hashing fails
async fn register(
    State(auth_provider): State<Arc<BasicAuthProvider>>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, String> {
    let credentials = Credentials {
        username: request.username,
        password: request.password,
    };

    let auth_result = auth_provider
        .authenticate(credentials)
        .await
        .map_err(|e| e.to_string())?;

    Ok(Json(LoginResponse {
        token: auth_result.session.token,
    }))
}

/// Handles user logout.
///
/// # Errors
/// Returns an error if:
/// - Session not found
/// - Database operation fails
async fn logout(
    State(auth_provider): State<Arc<BasicAuthProvider>>,
    Json(session_id): Json<String>,
) -> Result<(), String> {
    let session_id =
        Uuid::parse_str(&session_id).map_err(|e| format!("Invalid session ID: {e}"))?;

    auth_provider
        .logout(session_id)
        .await
        .map_err(|e| e.to_string())
}

/// Validates a JWT token.
///
/// # Errors
/// Returns an error if:
/// - Token is invalid
/// - Token is expired
/// - Signature verification fails
async fn validate(
    State(auth_provider): State<Arc<BasicAuthProvider>>,
    Json(token): Json<String>,
) -> Result<Json<bool>, String> {
    let _validation_result = auth_provider
        .validate_token(token)
        .await
        .map_err(|e| e.to_string())?;

    Ok(Json(true))
}

/// Creates the authentication router with all routes.
///
/// This function sets up all authentication-related routes including login,
/// logout, registration, and token validation.
pub fn router(pool: PgPool) -> Router {
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let auth_config = AuthConfig::default();
    let auth_provider = Arc::new(BasicAuthProvider::new(user_repo, session_repo, auth_config));

    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .with_state(auth_provider)
}
