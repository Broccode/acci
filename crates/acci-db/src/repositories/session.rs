use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::{error, info};
use uuid::Uuid;

use crate::models::session::Session;
use crate::Error;

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create_session(&self, session: &Session) -> Result<Session, Error>;
    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session>, Error>;
    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error>;
    async fn delete_session(&self, session_id: Uuid) -> Result<(), Error>;
    async fn delete_expired_sessions(&self) -> Result<u64, Error>;
}

pub struct PgSessionRepository {
    pool: PgPool,
}

impl PgSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for PgSessionRepository {
    async fn create_session(&self, session: &Session) -> Result<Session, Error> {
        sqlx::query!(
            r#"
            INSERT INTO sessions (session_id, user_id, created_at, expires_at)
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
            FROM sessions
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
            FROM sessions
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
            DELETE FROM sessions
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
            DELETE FROM sessions
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
