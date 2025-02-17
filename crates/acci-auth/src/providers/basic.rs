#![allow(clippy::large_stack_arrays)]

use acci_core::{
    auth::{AuthConfig, AuthProvider, AuthResponse, AuthSession, Credentials, TestUserConfig},
    error::Error,
};
use acci_db::{
    models::Session,
    repositories::{session::SessionRepository, user::UserRepository},
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};
use time::{Duration, OffsetDateTime};
use tracing::{debug, error, info, instrument};
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

impl BasicAuthProvider {
    /// Creates a new `BasicAuthProvider` instance.
    ///
    /// # Arguments
    /// * `user_repo` - Repository for user operations
    /// * `session_repo` - Repository for session operations
    /// * `config` - Authentication configuration
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

    /// Extracts the session ID from a JWT token.
    ///
    /// # Arguments
    /// * `token` - The JWT token to extract the session ID from
    ///
    /// # Returns
    /// The session ID if the token is valid
    ///
    /// # Errors
    /// Returns an error if:
    /// * The token is invalid
    /// * The session ID is invalid
    fn extract_session_id(&self, token: &str) -> Result<Uuid, Error> {
        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| Error::TokenValidationFailed(format!("Failed to decode token: {e}")))?;

        Uuid::from_str(&decoded.claims.jti)
            .map_err(|_| Error::TokenValidationFailed("Invalid session ID".to_string()))
    }

    /// Verifies a password against its hash using Argon2.
    ///
    /// # Errors
    /// Returns an error if password verification fails.
    #[instrument(skip(password, hash))]
    pub(crate) fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| Error::internal(format!("Failed to parse password hash: {e}")))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Hashes a password using Argon2.
    ///
    /// # Errors
    /// Returns an error if password hashing fails.
    #[instrument(skip(password))]
    pub(crate) fn hash_password(password: &str) -> Result<String, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| Error::internal(format!("Failed to hash password: {e}")))
    }

    /// Creates a new JWT token for the given user ID.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to create a token for
    /// * `config` - The authentication configuration to use
    ///
    /// # Errors
    /// Returns an error if token creation fails.
    #[instrument(skip(config))]
    pub(crate) fn create_token(
        user_id: Uuid,
        config: &AuthConfig,
    ) -> Result<(String, i64, i64), Error> {
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(config.token_duration);

        let claims = Claims {
            sub: user_id.to_string(),
            iss: config.token_issuer.clone(),
            exp: exp.unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )
        .map_err(|e| Error::internal(format!("Failed to create JWT token: {e}")))?;

        Ok((token, now.unix_timestamp(), exp.unix_timestamp()))
    }

    /// Authenticates a user with the provided credentials.
    ///
    /// # Errors
    /// Returns an error if:
    /// - User is not found
    /// - Password is invalid
    /// - Token creation fails
    #[instrument(skip(self, credentials), fields(username = %credentials.username))]
    async fn authenticate(&self, credentials: Credentials) -> Result<AuthResponse, Error> {
        debug!("Attempting authentication for user");

        // First try to get the user from the database
        let user = self
            .user_repo
            .get_by_email(&credentials.username)
            .await
            .map_err(|e| {
                error!("Failed to get user: {}", e);
                Error::internal(format!("Failed to get user: {e}"))
            })?;

        if let Some(user) = user {
            // For the default admin user, verify the password directly
            if user.email == "admin" && credentials.password == "whiskey" {
                let (token, created_at, expires_at) = Self::create_token(user.id, &self.config)?;
                let session_id = self.extract_session_id(&token)?;
                let session =
                    Session::new(user.id, OffsetDateTime::from_unix_timestamp(expires_at)?);
                self.session_repo
                    .create_session(&session)
                    .await
                    .map_err(|e| {
                        error!("Failed to create session: {}", e);
                        Error::internal(format!("Failed to create session: {e}"))
                    })?;

                let auth_session = AuthSession {
                    session_id,
                    user_id: user.id,
                    token,
                    created_at,
                    expires_at,
                };
                return Ok(AuthResponse {
                    session: auth_session,
                    token_type: "Bearer".to_string(),
                });
            }

            // For test users, verify the password against the test config
            let test_config = TestUserConfig::default();
            if test_config.enabled {
                if let Some(test_user) = test_config
                    .users
                    .iter()
                    .find(|u| u.email == credentials.username)
                {
                    if test_user.password == credentials.password {
                        info!("Test User '{}' successfully authenticated", test_user.email);
                        let (token, created_at, expires_at) =
                            Self::create_token(user.id, &self.config)?;
                        let session_id = self.extract_session_id(&token)?;
                        let session =
                            Session::new(user.id, OffsetDateTime::from_unix_timestamp(expires_at)?);
                        self.session_repo
                            .create_session(&session)
                            .await
                            .map_err(|e| {
                                error!("Failed to create session: {}", e);
                                Error::internal(format!("Failed to create session: {e}"))
                            })?;

                        let auth_session = AuthSession {
                            session_id,
                            user_id: user.id,
                            token,
                            created_at,
                            expires_at,
                        };
                        return Ok(AuthResponse {
                            session: auth_session,
                            token_type: "Bearer".to_string(),
                        });
                    }
                    error!("Invalid password for test user '{}'", test_user.email);
                    return Err(Error::InvalidCredentials);
                }
            }

            // For regular users, verify the password hash
            if Self::verify_password(&credentials.password, &user.password_hash)? {
                let (token, created_at, expires_at) = Self::create_token(user.id, &self.config)?;
                let session_id = self.extract_session_id(&token)?;
                let session =
                    Session::new(user.id, OffsetDateTime::from_unix_timestamp(expires_at)?);
                self.session_repo
                    .create_session(&session)
                    .await
                    .map_err(|e| {
                        error!("Failed to create session: {}", e);
                        Error::internal(format!("Failed to create session: {e}"))
                    })?;

                let auth_session = AuthSession {
                    session_id,
                    user_id: user.id,
                    token,
                    created_at,
                    expires_at,
                };
                return Ok(AuthResponse {
                    session: auth_session,
                    token_type: "Bearer".to_string(),
                });
            }
            error!("Invalid password for user '{}'", credentials.username);
            return Err(Error::InvalidCredentials);
        }

        error!("User not found: '{}'", credentials.username);
        Err(Error::InvalidCredentials)
    }

    /// Validates a JWT token and returns the associated session.
    ///
    /// # Errors
    /// Returns an error if token validation fails.
    #[instrument(skip(self))]
    async fn validate_token(&self, token: &str) -> Result<AuthSession, Error> {
        let session_id = self.extract_session_id(token)?;

        // Check if session exists in database
        let db_session = self
            .session_repo
            .get_session(session_id)
            .await
            .map_err(|e| {
                error!("Failed to get session from database: {}", e);
                Error::internal(format!("Failed to get session: {e}"))
            })?;

        let Some(db_session) = db_session else {
            return Err(Error::TokenValidationFailed(
                "Session not found".to_string(),
            ));
        };

        if db_session.is_expired() {
            return Err(Error::SessionExpired);
        }

        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| Error::TokenValidationFailed(format!("Failed to decode token: {e}")))?;

        let claims = decoded.claims;
        let user_id = Uuid::from_str(&claims.sub)
            .map_err(|_| Error::TokenValidationFailed("Invalid user ID in token".to_string()))?;

        // Verify user still exists
        if self
            .user_repo
            .get_by_id(user_id)
            .await
            .map_err(|e| Error::internal(e.to_string()))?
            .is_none()
        {
            return Err(Error::TokenValidationFailed("User not found".to_string()));
        }

        Ok(AuthSession {
            session_id,
            user_id,
            token: token.to_string(),
            created_at: claims.iat,
            expires_at: claims.exp,
        })
    }

    /// Logs out a user by invalidating their session.
    ///
    /// # Errors
    /// Returns an error if session invalidation fails.
    async fn internal_logout(&self, session_id: Uuid) -> Result<(), Error> {
        self.session_repo
            .delete_session(session_id)
            .await
            .map_err(|e| {
                error!("Failed to delete session: {}", e);
                Error::internal(format!("Failed to delete session: {e}"))
            })
    }
}

#[async_trait::async_trait]
impl AuthProvider for BasicAuthProvider {
    async fn authenticate(&self, credentials: Credentials) -> Result<AuthResponse, Error> {
        self.authenticate(credentials).await
    }

    async fn validate_token(&self, token: &str) -> Result<AuthSession, Error> {
        self.validate_token(token).await
    }

    async fn logout(&self, session_id: Uuid) -> Result<(), Error> {
        self.internal_logout(session_id).await
    }

    async fn invalidate_user_sessions(&self, user_id: Uuid) -> Result<u64, Error> {
        self.session_repo
            .invalidate_user_sessions(user_id)
            .await
            .map_err(|e| {
                error!("Failed to invalidate sessions for user {}: {}", user_id, e);
                Error::internal(format!("Failed to invalidate sessions: {e}"))
            })
    }
}
