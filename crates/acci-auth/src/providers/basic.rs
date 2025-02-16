#![allow(clippy::large_stack_arrays)]

use acci_core::{
    auth::{AuthConfig, AuthProvider, AuthResponse, AuthSession, Credentials},
    error::Error,
};
use acci_db::repositories::user::UserRepository;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{encode, EncodingKey, Header};
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
#[allow(dead_code)] // Fields will be used when implementing token validation and logout
pub struct BasicAuthProvider {
    /// User repository for database operations
    user_repo: Arc<dyn UserRepository>,
    /// Authentication configuration
    config: AuthConfig,
}

impl BasicAuthProvider {
    /// Creates a new `BasicAuthProvider` instance.
    ///
    /// # Arguments
    /// * `user_repo` - Repository for user operations
    /// * `config` - Authentication configuration
    #[must_use]
    pub fn new(user_repo: Arc<dyn UserRepository>, config: AuthConfig) -> Self {
        Self { user_repo, config }
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
    fn create_token(user_id: Uuid, config: &AuthConfig) -> Result<(String, i64, i64), Error> {
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

    /// Verifies a password against its hash using Argon2.
    ///
    /// # Errors
    /// Returns an error if password verification fails.
    #[instrument(skip(password, hash))]
    fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
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
    fn hash_password(password: &str) -> Result<String, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| Error::internal(format!("Failed to hash password: {e}")))
    }

    /// Authenticates a user with the provided credentials.
    ///
    /// # Errors
    /// Returns an error if:
    /// - User is not found
    /// - Password is invalid
    /// - Token creation fails
    #[instrument(skip(self, credentials), fields(username = %credentials.username))]
    async fn authenticate(&self, credentials: Credentials) -> Result<AuthSession, Error> {
        debug!("Attempting authentication for user");

        let user = match self.user_repo.get_by_email(&credentials.username).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                error!("User not found");
                return Err(Error::InvalidCredentials);
            },
            Err(e) => {
                error!("Failed to find user: {e}");
                return Err(Error::Internal {
                    message: "Failed to find user".to_string(),
                });
            },
        };

        if !Self::verify_password(&credentials.password, &user.password_hash)? {
            error!("Invalid password for user");
            return Err(Error::InvalidCredentials);
        }

        let (token, created_at, expires_at) = Self::create_token(user.id, &self.config)?;

        let session = AuthSession {
            session_id: Uuid::new_v4(),
            user_id: user.id,
            token,
            created_at,
            expires_at,
        };

        info!("Successfully authenticated user");
        Ok(session)
    }

    /// Validates a JWT token and returns the associated session.
    ///
    /// # Errors
    /// Returns an error if token validation fails.
    #[instrument(skip(self))]
    async fn validate_token(&self, token: &str) -> Result<AuthSession, Error> {
        use jsonwebtoken::{decode, DecodingKey, Validation};

        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| Error::TokenValidationFailed(format!("Failed to decode token: {e}")))?;

        let claims = decoded.claims;
        let now = OffsetDateTime::now_utc().unix_timestamp();

        if now >= claims.exp {
            return Err(Error::SessionExpired);
        }

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
            session_id: Uuid::from_str(&claims.jti)
                .map_err(|_| Error::TokenValidationFailed("Invalid session ID".to_string()))?,
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
    fn logout(&self, session_id: Uuid) -> Result<(), Error> {
        // For basic auth provider, we don't need to store session state
        // as we use stateless JWT tokens. The client should simply discard the token.
        // In a real-world scenario, you might want to maintain a blacklist of
        // invalidated tokens, but for this implementation we'll keep it simple.
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuthProvider for BasicAuthProvider {
    async fn authenticate(&self, credentials: Credentials) -> Result<AuthResponse, Error> {
        let session = self.authenticate(credentials).await?;
        Ok(AuthResponse {
            session,
            token_type: "Bearer".to_string(),
        })
    }

    async fn validate_token(&self, token: &str) -> Result<AuthSession, Error> {
        self.validate_token(token).await
    }

    async fn logout(&self, session_id: Uuid) -> Result<(), Error> {
        self.logout(session_id)
    }
}

// Unit tests for internal functions only
#[cfg(test)]
mod tests {
    use super::*;
    use acci_db::repositories::user::{CreateUser, UpdateUser, User};
    use std::str::FromStr;

    #[test]
    fn test_password_hash_and_verify() -> Result<(), Error> {
        let password = "test_password";
        let hash = BasicAuthProvider::hash_password(password)?;

        assert!(BasicAuthProvider::verify_password(password, &hash)?);
        assert!(!BasicAuthProvider::verify_password(
            "wrong_password",
            &hash
        )?);
        Ok(())
    }

    #[test]
    fn test_password_hash_different_salts() -> Result<(), Error> {
        let password = "test_password";
        let hash1 = BasicAuthProvider::hash_password(password)?;
        let hash2 = BasicAuthProvider::hash_password(password)?;

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(BasicAuthProvider::verify_password(password, &hash1)?);
        assert!(BasicAuthProvider::verify_password(password, &hash2)?);
        Ok(())
    }

    #[test]
    fn test_password_verify_invalid_hash() {
        let result = BasicAuthProvider::verify_password("test", "invalid_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_create_token() -> Result<(), Error> {
        let user_id = Uuid::new_v4();
        let config = AuthConfig {
            token_duration: 3600,
            token_issuer: "test_issuer".to_string(),
            jwt_secret: "test_secret".to_string(),
        };

        let (token, iat, exp) = BasicAuthProvider::create_token(user_id, &config)?;

        // Basic validation
        assert!(!token.is_empty());
        assert!(exp > iat);
        assert_eq!(exp - iat, config.token_duration);

        Ok(())
    }

    // Mock UserRepository for testing
    #[derive(Debug)]
    struct MockUserRepo {}

    #[async_trait::async_trait]
    impl UserRepository for MockUserRepo {
        async fn get_by_email(&self, _email: &str) -> Result<Option<User>, anyhow::Error> {
            unimplemented!()
        }

        async fn create(&self, _user: CreateUser) -> Result<User, anyhow::Error> {
            unimplemented!()
        }

        async fn update(
            &self,
            _id: Uuid,
            _user: UpdateUser,
        ) -> Result<Option<User>, anyhow::Error> {
            unimplemented!()
        }

        async fn delete(&self, _id: Uuid) -> Result<bool, anyhow::Error> {
            unimplemented!()
        }

        async fn get_by_id(&self, _id: Uuid) -> Result<Option<User>, anyhow::Error> {
            unimplemented!()
        }
    }
}
