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

    #[derive(Debug)]
    struct MockUserRepo;

    #[async_trait::async_trait]
    impl UserRepository for MockUserRepo {
        async fn create(&self, _user: CreateUser) -> anyhow::Result<User> {
            unimplemented!()
        }

        async fn get_by_id(&self, _id: Uuid) -> anyhow::Result<Option<User>> {
            Ok(None)
        }

        async fn get_by_email(&self, _email: &str) -> anyhow::Result<Option<User>> {
            Ok(None)
        }

        async fn update(&self, _id: Uuid, _user: UpdateUser) -> anyhow::Result<Option<User>> {
            Ok(None)
        }

        async fn delete(&self, _id: Uuid) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let user_repo = Arc::new(MockUserRepo);
        let auth_provider = BasicAuthProvider::new(user_repo, AuthConfig::default());

        let credentials = Credentials {
            username: "invalid@example.com".to_string(),
            password: "wrongpassword".to_string(),
        };

        let result = auth_provider.authenticate(credentials).await;
        assert!(matches!(result, Err(CoreError::InvalidCredentials)));
    }
}
