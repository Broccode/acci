//! Authentication functionality for the ACCI system.
//!
//! This crate provides authentication and authorization functionality,
//! including user authentication, session management, and token validation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

use std::sync::Arc;

use acci_core::{
    auth::{AuthResult, AuthService as AuthServiceTrait, Credentials, ValidationResult},
    clock::{Clock, SystemClock},
    error::Error,
};
use acci_db::repositories::{session::SessionRepository, user::UserRepository};
use time::OffsetDateTime;
use uuid::Uuid;

pub mod providers;
/// Contains background tasks and scheduled jobs for authentication-related operations.
/// This includes tasks like session cleanup and token management.
pub mod tasks;

pub use providers::basic::BasicAuthProvider;

/// The main authentication service implementation.
#[derive(Debug)]
pub struct AuthService<C: Clock = SystemClock> {
    user_repo: Arc<dyn UserRepository + Send + Sync>,
    session_repo: Arc<dyn SessionRepository + Send + Sync>,
    clock: C,
}

impl<C: Clock> AuthService<C> {
    /// Creates a new authentication service instance.
    ///
    /// # Arguments
    ///
    /// * `user_repo` - The user repository implementation
    /// * `session_repo` - The session repository implementation
    /// * `clock` - The clock implementation to use
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository + Send + Sync>,
        session_repo: Arc<dyn SessionRepository + Send + Sync>,
        clock: C,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            clock,
        }
    }
}

impl AuthService<SystemClock> {
    /// Creates a new authentication service instance with the system clock.
    ///
    /// # Arguments
    ///
    /// * `user_repo` - The user repository implementation
    /// * `session_repo` - The session repository implementation
    #[must_use]
    pub fn with_system_clock(
        user_repo: Arc<dyn UserRepository + Send + Sync>,
        session_repo: Arc<dyn SessionRepository + Send + Sync>,
    ) -> Self {
        Self::new(user_repo, session_repo, SystemClock)
    }
}

#[async_trait::async_trait]
impl<C: Clock> AuthServiceTrait for AuthService<C> {
    async fn register(&self, credentials: Credentials) -> Result<AuthResult, Error> {
        // Check if user exists
        if self
            .user_repo
            .get_user_by_username(&credentials.username)
            .await?
            .is_some()
        {
            return Err(Error::AlreadyExists("User already exists".to_string()));
        }

        // Hash password
        let password_hash = acci_core::auth::hash_password(&credentials.password)
            .map_err(|e| Error::Internal(e.to_string()))?;

        // Create user
        let user = self
            .user_repo
            .create_user(&credentials.username, &password_hash)
            .await?;

        // Create session
        let token =
            acci_core::auth::create_token(user.id).map_err(|e| Error::Internal(e.to_string()))?;
        let now = OffsetDateTime::from(self.clock.now());
        let expires_at = now + time::Duration::hours(24); // TODO: Make configurable

        let session = self
            .session_repo
            .create_session(user.id, &token, expires_at)
            .await?;

        Ok(AuthResult {
            token,
            session_id: session.id,
            user_id: user.id,
        })
    }

    async fn authenticate(&self, credentials: Credentials) -> Result<AuthResult, Error> {
        // Get user
        let user = self
            .user_repo
            .get_user_by_username(&credentials.username)
            .await?
            .ok_or_else(|| Error::NotFound("User not found".to_string()))?;

        // Verify password
        if !acci_core::auth::verify_password(&credentials.password, &user.password_hash)
            .map_err(|e| Error::Internal(e.to_string()))?
        {
            return Err(Error::InvalidCredentials("Invalid password".to_string()));
        }

        // Create session
        let token =
            acci_core::auth::create_token(user.id).map_err(|e| Error::Internal(e.to_string()))?;
        let now = OffsetDateTime::from(self.clock.now());
        let expires_at = now + time::Duration::hours(24); // TODO: Make configurable

        let session = self
            .session_repo
            .create_session(user.id, &token, expires_at)
            .await?;

        Ok(AuthResult {
            token,
            session_id: session.id,
            user_id: user.id,
        })
    }

    async fn validate_token(&self, token: String) -> Result<ValidationResult, Error> {
        // Validate token
        let claims =
            acci_core::auth::validate_token(&token).map_err(|e| Error::Internal(e.to_string()))?;

        // Get session
        let session = self
            .session_repo
            .get_session(claims.session_id)
            .await?
            .ok_or_else(|| Error::NotFound("Session not found".to_string()))?;

        Ok(ValidationResult {
            is_valid: true,
            user_id: Some(session.user_id),
            session_id: Some(session.id),
        })
    }

    async fn validate_token_with_context(
        &self,
        token: String,
        _ip: String,
    ) -> Result<ValidationResult, Error> {
        // Validate token
        let claims =
            acci_core::auth::validate_token(&token).map_err(|e| Error::Internal(e.to_string()))?;

        // Get session
        let session = self
            .session_repo
            .get_session(claims.session_id)
            .await?
            .ok_or_else(|| Error::NotFound("Session not found".to_string()))?;

        // TODO: Validate IP context

        Ok(ValidationResult {
            is_valid: true,
            user_id: Some(session.user_id),
            session_id: Some(session.id),
        })
    }

    async fn logout(&self, session_id: Uuid) -> Result<(), Error> {
        self.session_repo.delete_session(session_id).await
    }

    async fn get_active_sessions(&self, user_id: Uuid) -> Result<Vec<Uuid>, Error> {
        let sessions = self.session_repo.get_active_sessions(user_id).await?;
        Ok(sessions.into_iter().map(|s| s.id).collect())
    }

    async fn admin_invalidate_session(
        &self,
        admin_session_id: Uuid,
        target_session_id: Uuid,
    ) -> Result<(), Error> {
        // Get admin session
        let admin_session = self
            .session_repo
            .get_session(admin_session_id)
            .await?
            .ok_or_else(|| Error::NotFound("Admin session not found".to_string()))?;

        // Verify admin
        let admin = self
            .user_repo
            .get_user_by_id(admin_session.user_id)
            .await?
            .ok_or_else(|| Error::NotFound("Admin user not found".to_string()))?;

        if !admin.is_admin {
            return Err(Error::PermissionDenied);
        }

        // Delete target session
        self.session_repo.delete_session(target_session_id).await
    }
}
