//! Authentication endpoints implementation.

#![allow(clippy::large_stack_arrays)]

use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use std::sync::Arc;
use tracing::instrument;

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
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Username or email
    pub username: String,
    /// Password
    pub password: String,
}

/// Creates a router for authentication endpoints
pub fn router(pool: PgPool) -> Router {
    Router::new().route("/auth/login", post(login).with_state(pool))
}

/// Login handler
#[allow(clippy::large_stack_arrays)]
#[instrument(skip_all, fields(username = %credentials.username))]
async fn login(
    State(pool): State<PgPool>,
    Json(credentials): Json<LoginRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let user_repo = Arc::new(PgUserRepository::new(pool));
    let auth_provider = BasicAuthProvider::new(user_repo, AuthConfig::default());

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
    use acci_core::auth::AuthProvider;
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand_core::OsRng;

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
        let auth_provider = BasicAuthProvider::new(user_repo, AuthConfig::default());

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
        let auth_provider = BasicAuthProvider::new(user_repo, AuthConfig::default());

        let credentials = Credentials {
            username: "invalid@example.com".to_string(),
            password: "wrongpassword".to_string(),
        };

        let result = auth_provider.authenticate(credentials).await;
        assert!(matches!(result, Err(CoreError::InvalidCredentials)));
    }
}
