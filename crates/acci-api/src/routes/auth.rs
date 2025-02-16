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
use acci_db::{repositories::user::PgUserRepository, sqlx::PgPool};

#[cfg(test)]
use {
    acci_db::repositories::user::{CreateUser, UpdateUser, User, UserRepository},
    uuid::Uuid,
};

use crate::error::{ApiError, ApiResult};

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

#[cfg(test)]
mod tests {
    use super::*;
    use acci_core::auth::AuthProvider;
    use acci_db::repositories::session::MockSessionRepository;
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;

    #[derive(Debug)]
    struct MockUserRepo {
        default_user: User,
    }

    impl MockUserRepo {
        fn new() -> Self {
            // Create password hash for "whiskey"
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2.hash_password(b"whiskey", &salt).unwrap().to_string();

            let default_user = User {
                id: Uuid::new_v4(),
                email: "admin".to_string(),
                password_hash,
                full_name: "Default Admin".to_string(),
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            };

            Self { default_user }
        }
    }

    #[async_trait::async_trait]
    impl UserRepository for MockUserRepo {
        async fn create(&self, _user: CreateUser) -> anyhow::Result<User> {
            unimplemented!()
        }

        async fn get_by_id(&self, _id: Uuid) -> anyhow::Result<Option<User>> {
            Ok(None)
        }

        async fn get_by_email(&self, email: &str) -> anyhow::Result<Option<User>> {
            if email == "admin" {
                Ok(Some(self.default_user.clone()))
            } else {
                Ok(None)
            }
        }

        async fn update(&self, _id: Uuid, _user: UpdateUser) -> anyhow::Result<Option<User>> {
            Ok(None)
        }

        async fn delete(&self, _id: Uuid) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn test_login_default_admin() {
        let user_repo = Arc::new(MockUserRepo::new());
        let session_repo = Arc::new(MockSessionRepository::new());
        let auth_provider = BasicAuthProvider::new(user_repo, session_repo, AuthConfig::default());

        let credentials = Credentials {
            username: "admin".to_string(),
            password: "whiskey".to_string(),
        };

        let result = auth_provider.authenticate(credentials).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let user_repo = Arc::new(MockUserRepo::new());
        let session_repo = Arc::new(MockSessionRepository::new());
        let auth_provider = BasicAuthProvider::new(user_repo, session_repo, AuthConfig::default());

        let credentials = Credentials {
            username: "invalid@example.com".to_string(),
            password: "wrongpassword".to_string(),
        };

        let result = auth_provider.authenticate(credentials).await;
        assert!(matches!(result, Err(CoreError::InvalidCredentials)));
    }
}
