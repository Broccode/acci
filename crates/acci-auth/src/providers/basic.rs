#![allow(clippy::large_stack_arrays)]

use acci_core::{
    auth::{AuthConfig, AuthProvider, AuthResponse, AuthSession, Credentials},
    error::Error,
};
use acci_db::repositories::{session::SessionRepository, user::UserRepository};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordVerifier},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, str::FromStr, sync::Arc};
use time::{Duration, OffsetDateTime};
use tracing::warn;
use uuid::Uuid;

/// Claims structure for JWT tokens
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Subject (user ID)
    sub: String,
    /// Issuer
    iss: String,
    /// Expiration time (as Unix timestamp)
    exp: i64,
    /// Issued at (as Unix timestamp)
    iat: i64,
    /// JWT ID (session ID)
    jti: String,
    /// IP address of the client
    ip: Option<String>,
    /// User agent of the client
    ua: Option<String>,
}

/// Session context for validation
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    /// IP address of the client
    pub ip_address: Option<IpAddr>,
    /// User agent string
    pub user_agent: Option<String>,
}

/// Basic authentication provider that uses JWT tokens for session management.
#[derive(Debug)]
pub struct BasicAuthProvider {
    /// User repository for database operations
    user_repo: Arc<dyn UserRepository + Send + Sync>,
    /// Session repository for session management
    session_repo: Arc<dyn SessionRepository + Send + Sync>,
    /// Authentication configuration
    config: AuthConfig,
}

impl BasicAuthProvider {
    /// Generates a cryptographically secure random token.
    ///
    /// This function uses the system's secure random number generator to create
    /// a URL-safe base64 encoded token of the specified length.
    ///
    /// # Arguments
    ///
    /// * `length` - The desired length of the random bytes before encoding
    ///
    /// # Returns
    ///
    /// A URL-safe base64 encoded string of random bytes
    fn generate_secure_token(length: usize) -> String {
        let mut buffer = vec![0u8; length];
        OsRng.fill_bytes(&mut buffer);
        URL_SAFE.encode(buffer)
    }

    /// Creates a new basic authentication provider instance.
    ///
    /// # Arguments
    ///
    /// * `user_repo` - The user repository implementation
    /// * `session_repo` - The session repository implementation
    /// * `config` - The authentication configuration
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository + Send + Sync>,
        session_repo: Arc<dyn SessionRepository + Send + Sync>,
        config: AuthConfig,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            config,
        }
    }

    /// Verifies a password against its hash.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Hash parsing fails
    /// - Password verification fails
    /// - Invalid hash format
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Error> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| Error::Internal(format!("Failed to parse password hash: {e}")))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Validates a JWT token.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Token is invalid
    /// - Token is expired
    /// - Signature verification fails
    fn validate_token(&self, token: &str) -> Result<Claims, Error> {
        let validation = Validation::default();
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|e| Error::InvalidToken(format!("Failed to validate token: {e}")))?;

        Ok(token_data.claims)
    }

    /// Authenticates a user with additional session context.
    ///
    /// # Arguments
    ///
    /// * `credentials` - The user credentials
    /// * `context` - Additional context for session validation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The credentials are invalid
    /// - The user is not found
    /// - The user account is disabled
    /// - Session creation fails
    pub async fn authenticate_with_context(
        &self,
        credentials: Credentials,
        context: SessionContext,
    ) -> Result<AuthResponse, Error> {
        // Get user
        let user = self
            .user_repo
            .get_user_by_username(&credentials.username)
            .await?
            .ok_or_else(|| Error::InvalidCredentials("User not found".to_string()))?;

        // Check if user is active
        if !user.is_active {
            return Err(Error::Forbidden("User account is disabled".to_string()));
        }

        // Verify password
        if !self.verify_password(&credentials.password, &user.password_hash)? {
            return Err(Error::InvalidCredentials("Invalid password".to_string()));
        }

        // Generate secure session token
        let token = Self::generate_secure_token(32);

        // Create session with initial token
        let now = OffsetDateTime::now_utc();
        let expires_at = now + Duration::seconds(self.config.token_duration);

        // Create initial session
        let session = self
            .session_repo
            .create_session(user.id, &token, expires_at)
            .await?;

        // Create JWT token with session ID and context
        let claims = Claims {
            sub: user.id.to_string(),
            iss: self.config.token_issuer.clone(),
            exp: expires_at.unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: session.id.to_string(),
            ip: context.ip_address.map(|ip| ip.to_string()),
            ua: context.user_agent,
        };

        let jwt_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| Error::Internal(format!("Failed to create token: {e}")))?;

        Ok(AuthResponse {
            session: AuthSession {
                session_id: session.id,
                user_id: user.id,
                token: jwt_token,
                created_at: session.created_at.unix_timestamp(),
                expires_at: session.expires_at.unix_timestamp(),
            },
            token_type: "Bearer".to_string(),
        })
    }

    /// Validates a token with additional session context.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to validate
    /// * `context` - Additional context for session validation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The token is invalid
    /// - The session is not found
    /// - The context validation fails
    pub async fn validate_token_with_context(
        &self,
        token: String,
        context: SessionContext,
    ) -> Result<AuthSession, Error> {
        // Validate token
        let claims = self.validate_token(&token)?;

        // Validate context if present in claims
        if let Some(token_ip) = claims.ip {
            if let Some(request_ip) = context.ip_address {
                if token_ip != request_ip.to_string() {
                    warn!(
                        token_ip = %token_ip,
                        request_ip = %request_ip,
                        "IP address mismatch"
                    );
                    return Err(Error::InvalidToken("IP address mismatch".to_string()));
                }
            }
        }

        if let Some(token_ua) = claims.ua {
            if let Some(request_ua) = context.user_agent {
                if token_ua != request_ua {
                    warn!(
                        "User agent mismatch: token={}, request={}",
                        token_ua, request_ua
                    );
                    return Err(Error::InvalidToken("User agent mismatch".to_string()));
                }
            }
        }

        // Get session
        let session = self
            .session_repo
            .get_session(Uuid::from_str(&claims.jti).map_err(|e| Error::Internal(e.to_string()))?)
            .await?
            .ok_or_else(|| Error::NotFound("Session not found".to_string()))?;

        Ok(AuthSession {
            session_id: session.id,
            user_id: session.user_id,
            token: token.to_string(),
            created_at: session.created_at.unix_timestamp(),
            expires_at: session.expires_at.unix_timestamp(),
        })
    }
}

#[async_trait::async_trait]
impl AuthProvider for BasicAuthProvider {
    async fn authenticate(&self, credentials: Credentials) -> Result<AuthResponse, Error> {
        self.authenticate_with_context(credentials, SessionContext::default())
            .await
    }

    async fn validate_token(&self, token: String) -> Result<AuthSession, Error> {
        self.validate_token_with_context(token, SessionContext::default())
            .await
    }

    async fn logout(&self, session_id: Uuid) -> Result<(), Error> {
        self.session_repo.delete_session(session_id).await
    }

    async fn invalidate_user_sessions(&self, user_id: Uuid) -> Result<u64, Error> {
        let sessions = self.session_repo.get_active_sessions(user_id).await?;

        let mut count = 0;
        for session in sessions {
            self.session_repo.delete_session(session.id).await?;
            count += 1;
        }

        Ok(count)
    }
}
