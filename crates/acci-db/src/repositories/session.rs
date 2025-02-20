use async_trait::async_trait;
use sqlx::PgPool;
use time::OffsetDateTime;
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
    /// * `user_id` - The ID of the user
    /// * `token` - The session token
    /// * `expires_at` - The expiration time of the session
    ///
    /// # Returns
    ///
    /// The created session
    async fn create_session(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Session, Error>;

    /// Retrieves a session by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The unique identifier of the session to retrieve
    ///
    /// # Returns
    ///
    /// The session if found, None otherwise
    async fn get_session(&self, id: Uuid) -> Result<Option<Session>, Error>;

    /// Retrieves all active sessions for a specific user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user whose sessions to retrieve
    ///
    /// # Returns
    ///
    /// A vector of all active sessions belonging to the user
    async fn get_active_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error>;

    /// Deletes a specific session.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the session to delete
    async fn delete_session(&self, id: Uuid) -> Result<(), Error>;

    /// Validates a session.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the session to validate
    ///
    /// # Returns
    ///
    /// `true` if the session is valid, `false` otherwise
    async fn validate_session(&self, id: Uuid) -> Result<bool, Error>;

    /// Updates the token of a specific session.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the session to update
    /// * `token` - The new token value
    async fn update_session_token(&self, id: Uuid, token: &str) -> Result<(), Error>;

    /// Removes all expired sessions from the database.
    ///
    /// This method deletes all sessions that have expired (expires_at <= current time).
    ///
    /// # Returns
    ///
    /// The number of sessions that were removed
    async fn cleanup_expired_sessions(&self) -> Result<i64, Error>;
}

/// PostgreSQL implementation of the `SessionRepository` trait.
///
/// This implementation uses `SQLx` to interact with a PostgreSQL database
/// for session management.
#[derive(Debug, Clone)]
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
    async fn create_session(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Session, Error> {
        let now = OffsetDateTime::now_utc();
        let session = sqlx::query_as!(
            Session,
            r#"
            INSERT INTO acci.sessions (user_id, token, created_at, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, token, created_at, expires_at
            "#,
            user_id,
            token,
            now,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(Error::Database)?;

        Ok(session)
    }

    async fn get_session(&self, id: Uuid) -> Result<Option<Session>, Error> {
        let session = sqlx::query_as!(
            Session,
            r#"
            SELECT id, user_id, token, created_at, expires_at
            FROM acci.sessions
            WHERE id = $1 AND expires_at > $2
            "#,
            id,
            OffsetDateTime::now_utc(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::Database)?;

        Ok(session)
    }

    async fn get_active_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error> {
        let sessions = sqlx::query_as!(
            Session,
            r#"
            SELECT id, user_id, token, created_at, expires_at
            FROM acci.sessions
            WHERE user_id = $1 AND expires_at > $2
            ORDER BY created_at DESC
            "#,
            user_id,
            OffsetDateTime::now_utc(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Error::Database)?;

        Ok(sessions)
    }

    async fn delete_session(&self, id: Uuid) -> Result<(), Error> {
        sqlx::query!(
            r#"
            DELETE FROM acci.sessions
            WHERE id = $1
            "#,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(Error::Database)?;

        Ok(())
    }

    async fn validate_session(&self, id: Uuid) -> Result<bool, Error> {
        let count = sqlx::query!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM acci.sessions
            WHERE user_id = $1 AND expires_at > $2
            "#,
            id,
            OffsetDateTime::now_utc(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(Error::Database)?;

        Ok(count.count > 0)
    }

    async fn update_session_token(&self, id: Uuid, token: &str) -> Result<(), Error> {
        sqlx::query!(
            r#"
            UPDATE acci.sessions
            SET token = $2
            WHERE id = $1
            "#,
            id,
            token
        )
        .execute(&self.pool)
        .await
        .map_err(Error::Database)?;

        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<i64, Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM acci.sessions
            WHERE expires_at <= $1
            "#,
            OffsetDateTime::now_utc()
        )
        .execute(&self.pool)
        .await
        .map_err(Error::Database)?;

        Ok(result.rows_affected() as i64)
    }
}

impl std::fmt::Debug for dyn SessionRepository + Send + Sync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionRepository")
    }
}
