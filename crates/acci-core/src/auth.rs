use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use uuid::Uuid;

/// Represents the credentials used for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// The username or email used for authentication
    pub username: String,
    /// The password used for authentication
    pub password: String,
}

/// Represents a user's authentication session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    /// The unique identifier of the session
    pub session_id: Uuid,
    /// The user ID associated with this session
    pub user_id: Uuid,
    /// The JWT token for this session
    pub token: String,
    /// When the session was created (Unix timestamp)
    pub created_at: i64,
    /// When the session expires (Unix timestamp)
    pub expires_at: i64,
}

/// The result of a successful authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// The authentication session details
    pub session: AuthSession,
    /// The type of token (e.g., "Bearer")
    pub token_type: String,
}

/// Defines the core authentication provider interface
#[async_trait]
pub trait AuthProvider: Send + Sync + Debug {
    /// Authenticates a user with the given credentials
    async fn authenticate(
        &self,
        credentials: Credentials,
    ) -> Result<AuthResponse, crate::error::Error>;

    /// Validates an authentication token
    async fn validate_token(&self, token: &str) -> Result<AuthSession, crate::error::Error>;

    /// Invalidates an authentication session
    async fn logout(&self, session_id: Uuid) -> Result<(), crate::error::Error>;
}

/// Configuration for the authentication provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// The secret key used for JWT token signing
    pub jwt_secret: String,
    /// The duration of the JWT token in seconds
    pub token_duration: i64,
    /// The issuer of the JWT token
    pub token_issuer: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: String::from("your-secret-key-here"),
            token_duration: 3600, // 1 hour
            token_issuer: String::from("acci"),
        }
    }
}
