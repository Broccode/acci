use acci_db::{models::Session, repositories::session::SessionRepository, Error};
use async_trait::async_trait;
use mockall::automock;
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

/// Repository for managing session data in tests
pub struct RealSessionRepository {
    sessions: Mutex<Vec<Session>>,
    create_session_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    get_session_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    get_active_sessions_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    delete_session_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    validate_session_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    update_session_token_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    cleanup_expired_sessions_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
}

#[automock]
#[async_trait]
impl SessionRepository for RealSessionRepository {
    async fn create_session(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Session, Error> {
        if let Some(error_fn) = self
            .create_session_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            return Err(error_fn());
        }

        let session = Session {
            id: Uuid::new_v4(),
            user_id,
            token: token.to_string(),
            created_at: OffsetDateTime::now_utc(),
            expires_at,
        };

        self.sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .push(session.clone());

        Ok(session)
    }

    async fn cleanup_expired_sessions(&self) -> Result<i64, Error> {
        if let Some(error_fn) = self
            .cleanup_expired_sessions_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            return Err(error_fn());
        }

        let now = OffsetDateTime::now_utc();
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        let initial_len = sessions.len();
        sessions.retain(|s| s.expires_at > now);
        Ok((initial_len - sessions.len()) as i64)
    }

    async fn get_session(&self, id: Uuid) -> Result<Option<Session>, Error> {
        if let Some(error_fn) = self
            .get_session_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            return Err(error_fn());
        }

        Ok(self
            .sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .iter()
            .find(|s| s.id == id)
            .cloned())
    }

    async fn get_active_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error> {
        if let Some(error_fn) = self
            .get_active_sessions_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            return Err(error_fn());
        }

        let now = OffsetDateTime::now_utc();
        Ok(self
            .sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .iter()
            .filter(|s| s.user_id == user_id && s.expires_at > now)
            .cloned()
            .collect())
    }

    async fn delete_session(&self, id: Uuid) -> Result<(), Error> {
        if let Some(error_fn) = self
            .delete_session_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            return Err(error_fn());
        }

        self.sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .retain(|s| s.id != id);
        Ok(())
    }

    async fn validate_session(&self, id: Uuid) -> Result<bool, Error> {
        if let Some(error_fn) = self
            .validate_session_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            return Err(error_fn());
        }

        let now = OffsetDateTime::now_utc();
        Ok(self
            .sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .iter()
            .any(|s| s.id == id && s.expires_at > now))
    }

    async fn update_session_token(&self, id: Uuid, token: &str) -> Result<(), Error> {
        if let Some(error_fn) = self
            .update_session_token_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            return Err(error_fn());
        }

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if let Some(session) = sessions.iter_mut().find(|s| s.id == id) {
            session.token = token.to_string();
            Ok(())
        } else {
            Err(Error::NotFound(format!("Session with ID {} not found", id)))
        }
    }
}

impl Default for RealSessionRepository {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
            create_session_error: Mutex::new(None),
            get_session_error: Mutex::new(None),
            get_active_sessions_error: Mutex::new(None),
            delete_session_error: Mutex::new(None),
            validate_session_error: Mutex::new(None),
            update_session_token_error: Mutex::new(None),
            cleanup_expired_sessions_error: Mutex::new(None),
        }
    }
}

impl RealSessionRepository {
    /// Creates a new instance of the repository
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a session to the repository
    pub fn add_session(&self, session: Session) -> Result<(), Error> {
        self.sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .push(session);
        Ok(())
    }

    /// Clears all sessions from the repository
    pub fn clear_sessions(&self) -> Result<(), Error> {
        self.sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .clear();
        Ok(())
    }

    /// Gets all sessions from the repository
    pub fn get_all_sessions(&self) -> Result<Vec<Session>, Error> {
        Ok(self
            .sessions
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .clone())
    }

    /// Sets an error to be returned by create_session
    pub fn expect_create_session_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        *self
            .create_session_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by get_session
    pub fn expect_get_session_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        *self
            .get_session_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by get_active_sessions
    pub fn expect_get_active_sessions_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        *self
            .get_active_sessions_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by delete_session
    pub fn expect_delete_session_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        *self
            .delete_session_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by validate_session
    pub fn expect_validate_session_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        *self
            .validate_session_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by update_session_token
    pub fn expect_update_session_token_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        *self
            .update_session_token_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by cleanup_expired_sessions
    pub fn expect_cleanup_expired_sessions_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        *self
            .cleanup_expired_sessions_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }
}
