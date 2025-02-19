#![allow(clippy::large_stack_arrays)]

use acci_core::{
    auth::{AuthConfig, AuthProvider, AuthResponse, AuthSession, Credentials},
    error::Error,
};
use acci_db::repositories::{session::SessionRepository, user::UserRepository};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};
use time::{Duration, OffsetDateTime};
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
    /// JWT ID
    jti: String,
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

#[allow(dead_code, clippy::unused_self)]
impl BasicAuthProvider {
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

    /// Hashes a password using Argon2id.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Password hashing fails
    /// - Memory allocation fails
    /// - Algorithm parameters are invalid
    fn hash_password(&self, password: &str) -> Result<String, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| Error::Internal(format!("Failed to hash password: {e}")))?
            .to_string();
        Ok(password_hash)
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

    /// Creates a JWT token for a user.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Token creation fails
    /// - Signing process fails
    fn create_token(&self, user_id: Uuid) -> Result<String, Error> {
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(self.config.token_duration);

        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.config.token_issuer.clone(),
            exp: exp.unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| Error::Internal(format!("Failed to create token: {e}")))
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
}

#[async_trait::async_trait]
impl AuthProvider for BasicAuthProvider {
    async fn authenticate(&self, credentials: Credentials) -> Result<AuthResponse, Error> {
        // Get user
        let user = self
            .user_repo
            .get_user_by_username(&credentials.username)
            .await
            .map_err(|e| Error::Database(e.to_string()))?
            .ok_or(Error::InvalidCredentials)?;

        // Verify password
        if !self.verify_password(&credentials.password, &user.password_hash)? {
            return Err(Error::InvalidCredentials);
        }

        // Create session
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(self.config.token_duration);
        let session = self
            .session_repo
            .create_session(user.id, "", expires_at)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;

        // Create token with session ID as jti
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(self.config.token_duration);

        let claims = Claims {
            sub: user.id.to_string(),
            iss: self.config.token_issuer.clone(),
            exp: exp.unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: session.id.to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| Error::Internal(format!("Failed to create token: {e}")))?;

        // Update session with token
        self.session_repo
            .update_session_token(session.id, &token)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;

        Ok(AuthResponse {
            session: AuthSession {
                session_id: session.id,
                user_id: user.id,
                token: token.clone(),
                created_at: session.created_at.unix_timestamp(),
                expires_at: session.expires_at.unix_timestamp(),
            },
            token_type: "Bearer".to_string(),
        })
    }

    async fn validate_token(&self, token: String) -> Result<AuthSession, Error> {
        // Validate token
        let claims = self.validate_token(&token)?;

        // Get session
        let session = self
            .session_repo
            .get_session(Uuid::from_str(&claims.jti).map_err(|e| Error::Internal(e.to_string()))?)
            .await
            .map_err(|e| Error::Database(e.to_string()))?
            .ok_or_else(|| Error::NotFound("Session not found".to_string()))?;

        Ok(AuthSession {
            session_id: session.id,
            user_id: session.user_id,
            token: token.to_string(),
            created_at: session.created_at.unix_timestamp(),
            expires_at: session.expires_at.unix_timestamp(),
        })
    }

    async fn logout(&self, session_id: Uuid) -> Result<(), Error> {
        self.session_repo
            .delete_session(session_id)
            .await
            .map_err(|e| Error::Database(e.to_string()))
    }

    async fn invalidate_user_sessions(&self, user_id: Uuid) -> Result<u64, Error> {
        let sessions = self
            .session_repo
            .get_active_sessions(user_id)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;

        let mut count = 0;
        for session in sessions {
            self.session_repo
                .delete_session(session.id)
                .await
                .map_err(|e| Error::Database(e.to_string()))?;
            count += 1;
        }

        Ok(count)
    }
}
