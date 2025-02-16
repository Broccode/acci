use anyhow::Result;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use async_trait::async_trait;
use rand_core::OsRng;
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

/// Configuration for test users in development and test environments
#[derive(Debug, Clone)]
pub struct TestUserConfig {
    /// Whether test users are enabled
    pub enabled: bool,
    /// List of predefined test users
    pub users: Vec<TestUser>,
}

/// Represents a test user for development and testing
#[derive(Debug, Clone)]
pub struct TestUser {
    /// Email address of the test user
    pub email: String,
    /// Clear text password of the test user
    pub password: String,
    /// Full name of the test user
    pub full_name: String,
    /// Role of the test user (e.g., "admin", "user")
    pub role: String,
}

impl Default for TestUserConfig {
    fn default() -> Self {
        Self {
            #[cfg(debug_assertions)]
            enabled: true,
            #[cfg(not(debug_assertions))]
            enabled: false,
            users: vec![
                TestUser {
                    email: "test.admin@example.com".to_string(),
                    password: "test123!admin".to_string(),
                    full_name: "Test Administrator".to_string(),
                    role: "admin".to_string(),
                },
                TestUser {
                    email: "test.user@example.com".to_string(),
                    password: "test123!user".to_string(),
                    full_name: "Test User".to_string(),
                    role: "user".to_string(),
                },
            ],
        }
    }
}

/// Hash a password using Argon2
///
/// This function uses the Argon2 password hashing algorithm with default parameters
/// to securely hash the provided password.
///
/// # Arguments
///
/// * `password` - The password to hash
///
/// # Returns
///
/// * `Result<String>` - The hashed password if successful
///
/// # Errors
///
/// Returns an error if:
/// * Password hashing fails due to invalid input
/// * Memory allocation fails during hashing
/// * The system fails to generate secure random salt
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))
}
