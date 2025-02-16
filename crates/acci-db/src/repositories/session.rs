use async_trait::async_trait;
use sqlx::PgPool;
use tracing::{error, info};
use uuid::Uuid;

use crate::models::session::Session;
use crate::Error;

/// Defines the interface for managing user sessions in the database.
///
/// This trait provides methods for creating, retrieving, and managing user sessions,
/// including cleanup of expired sessions.
#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Creates a new session in the database.
    ///
    /// # Arguments
    ///
    /// * `session` - The session to create
    ///
    /// # Returns
    ///
    /// The created session with its database-assigned ID
    async fn create_session(&self, session: &Session) -> Result<Session, Error>;

    /// Retrieves a session by its ID.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The unique identifier of the session to retrieve
    ///
    /// # Returns
    ///
    /// The session if found, None otherwise
    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session>, Error>;

    /// Retrieves all sessions for a specific user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user whose sessions to retrieve
    ///
    /// # Returns
    ///
    /// A vector of all sessions belonging to the user
    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error>;

    /// Deletes a specific session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The ID of the session to delete
    async fn delete_session(&self, session_id: Uuid) -> Result<(), Error>;

    /// Removes all expired sessions from the database.
    ///
    /// # Returns
    ///
    /// The number of sessions that were deleted
    async fn delete_expired_sessions(&self) -> Result<u64, Error>;
}

/// PostgreSQL implementation of the `SessionRepository` trait.
///
/// This implementation uses `SQLx` to interact with a PostgreSQL database
/// for session management.
#[derive(Debug)]
pub struct PgSessionRepository {
    pool: PgPool,
}

impl PgSessionRepository {
    /// Creates a new PostgreSQL session repository instance.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database connection pool to use
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for PgSessionRepository {
    async fn create_session(&self, session: &Session) -> Result<Session, Error> {
        sqlx::query!(
            r#"
            INSERT INTO acci.sessions (session_id, user_id, created_at, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
            session.session_id,
            session.user_id,
            session.created_at,
            session.expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!("Failed to create session: {}", e);
            Error::from(e)
        })?;

        info!("Created session for user {}", session.user_id);
        Ok(session.clone())
    }

    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session>, Error> {
        let record = sqlx::query_as!(
            Session,
            r#"
            SELECT session_id, user_id, created_at, expires_at
            FROM acci.sessions
            WHERE session_id = $1
            "#,
            session_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!("Failed to get session {}: {}", session_id, e);
            Error::from(e)
        })?;

        if record.is_some() {
            info!("Retrieved session {}", session_id);
        }
        Ok(record)
    }

    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error> {
        let records = sqlx::query_as!(
            Session,
            r#"
            SELECT session_id, user_id, created_at, expires_at
            FROM acci.sessions
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!("Failed to get sessions for user {}: {}", user_id, e);
            Error::from(e)
        })?;

        info!("Retrieved {} sessions for user {}", records.len(), user_id);
        Ok(records)
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<(), Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM acci.sessions
            WHERE session_id = $1
            "#,
            session_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!("Failed to delete session {}: {}", session_id, e);
            Error::from(e)
        })?;

        if result.rows_affected() > 0 {
            info!("Deleted session {}", session_id);
        }
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> Result<u64, Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM acci.sessions
            WHERE expires_at < NOW()
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!("Failed to delete expired sessions: {}", e);
            Error::from(e)
        })?;

        let affected = result.rows_affected();
        info!("Deleted {} expired sessions", affected);
        Ok(affected)
    }
}

impl std::fmt::Debug for dyn SessionRepository + Send + Sync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionRepository")
    }
}
