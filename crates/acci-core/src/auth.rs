use crate::error::Error;
use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use async_trait::async_trait;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error as ThisError;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

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
#[derive(Debug, Clone, Deserialize)]
pub struct TestUser {
    /// Username of the test user
    pub username: String,
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
                    username: "test_admin".to_string(),
                    password: "test123!admin".to_string(),
                    full_name: "Test Administrator".to_string(),
                    role: "admin".to_string(),
                },
                TestUser {
                    username: "test_user".to_string(),
                    password: "test123!user".to_string(),
                    full_name: "Test User".to_string(),
                    role: "user".to_string(),
                },
            ],
        }
    }
}

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

/// Defines the core authentication service interface
#[async_trait]
pub trait AuthService {
    /// Registers a new user with the given credentials
    async fn register(&self, credentials: Credentials) -> Result<AuthResult, Error>;

    /// Authenticates a user with the given credentials
    async fn authenticate(&self, credentials: Credentials) -> Result<AuthResult, Error>;

    /// Validates an authentication token
    async fn validate_token(&self, token: String) -> Result<ValidationResult, Error>;

    /// Validates an authentication token with additional context
    async fn validate_token_with_context(
        &self,
        token: String,
        ip: String,
    ) -> Result<ValidationResult, Error>;

    /// Logs out a user by invalidating their session
    async fn logout(&self, session_id: Uuid) -> Result<(), Error>;

    /// Gets all active sessions for a user
    async fn get_active_sessions(&self, user_id: Uuid) -> Result<Vec<Uuid>, Error>;

    /// Invalidates a session as an admin
    async fn admin_invalidate_session(
        &self,
        admin_session_id: Uuid,
        target_session_id: Uuid,
    ) -> Result<(), Error>;
}

/// Defines the core authentication provider interface
#[async_trait]
pub trait AuthProvider: Send + Sync + Debug {
    /// Authenticates a user with the given credentials
    async fn authenticate(&self, credentials: Credentials) -> Result<AuthResponse, Error>;

    /// Validates an authentication token
    async fn validate_token(&self, token: String) -> Result<AuthSession, Error>;

    /// Logs out a user by invalidating their session
    async fn logout(&self, session_id: Uuid) -> Result<(), Error>;

    /// Invalidates all sessions for a specific user
    async fn invalidate_user_sessions(&self, user_id: Uuid) -> Result<u64, Error>;
}

/// The result of a successful authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// The JWT token
    pub token: String,
    /// The session ID
    pub session_id: Uuid,
    /// The user ID
    pub user_id: Uuid,
}

/// The result of validating an authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the token is valid
    pub is_valid: bool,
    /// The user ID associated with the token
    pub user_id: Option<Uuid>,
    /// The session ID associated with the token
    pub session_id: Option<Uuid>,
}

/// Errors that can occur during authentication
#[derive(Debug, ThisError)]
pub enum AuthError {
    /// The provided credentials are invalid
    #[error("Invalid credentials")]
    InvalidCredentials,
    /// Token validation failed
    #[error("Token validation failed: {0}")]
    TokenValidation(#[from] TokenValidationError),
    /// Session is invalid
    #[error("Session invalid: {0}")]
    SessionInvalid(String),
    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    /// Invalid operation
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    /// Token is invalid
    #[error("Token invalid: {0}")]
    TokenInvalid(String),
}

/// Errors that can occur during token validation
#[derive(Debug, ThisError)]
pub enum TokenValidationError {
    /// Token has expired
    #[error("Token expired")]
    Expired,
    /// Token signature is invalid
    #[error("Invalid signature")]
    InvalidSignature,
    /// Token algorithm is invalid
    #[error("Invalid algorithm")]
    InvalidAlgorithm,
    /// Token is malformed
    #[error("Token malformed")]
    Malformed,
}

/// Supported JWT algorithms
#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    /// HMAC with SHA-256
    HS256,
    /// HMAC with SHA-384
    HS384,
    /// HMAC with SHA-512
    HS512,
}

/// Default JWT secret key (should be overridden in production)
const JWT_SECRET: &[u8] = b"your-secret-key"; // TODO: Make configurable

/// Claims contained in a JWT token
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Session ID
    pub session_id: Uuid,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at time (Unix timestamp)
    pub iat: i64,
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
/// * `Result<String, Error>` - The hashed password if successful
///
/// # Errors
///
/// Returns an error if:
/// * Password hashing fails due to invalid input
/// * Memory allocation fails during hashing
/// * The system fails to generate secure random salt
pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| Error::Internal(format!("Password hashing failed: {e}")))
}

/// Verifies if a password matches a hash.
///
/// # Errors
/// Returns an error if the password verification process fails due to:
/// - Invalid hash format
/// - Memory allocation issues
/// - Algorithm version mismatch
pub fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| Error::Internal(format!("Failed to parse password hash: {e}")))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Creates a JWT token for a user.
///
/// # Errors
/// Returns an error if:
/// - Token creation fails
/// - Signing process fails
/// - Invalid key format
pub fn create_token(user_id: Uuid) -> Result<String, Error> {
    let session_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let exp = now + Duration::hours(24); // TODO: Make configurable

    let claims = Claims {
        sub: user_id.to_string(),
        session_id,
        exp: exp.unix_timestamp(),
        iat: now.unix_timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .map_err(|e| Error::Internal(format!("Failed to create token: {e}")))
}

/// Validates a JWT token and returns the claims.
///
/// # Errors
/// Returns an error if:
/// - Token is invalid
/// - Token is expired
/// - Signature verification fails
pub fn validate_token(token: &str) -> Result<Claims, Error> {
    let validation = Validation::default();
    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &validation)
        .map_err(|e| Error::InvalidToken(format!("Failed to validate token: {e}")))?;

    Ok(token_data.claims)
}
