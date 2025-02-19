use acci_core::error::Error as CoreError;
use acci_db::{models::Session, repositories::session::SessionRepository, Error};
use async_trait::async_trait;
use mockall::automock;
use sqlx::error::Error as SqlxError;
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

#[automock]
#[async_trait]
impl SessionRepository for RealSessionRepository {
    async fn create_session(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Session, Error> {
        let session = Session {
            id: Uuid::new_v4(),
            user_id,
            token: token.to_string(),
            created_at: OffsetDateTime::now_utc(),
            expires_at,
        };
        self.sessions.lock().unwrap().push(session.clone());
        Ok(session)
    }

    async fn get_session(&self, id: Uuid) -> Result<Option<Session>, Error> {
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.id == id)
            .cloned())
    }

    async fn get_active_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error> {
        let now = OffsetDateTime::now_utc();
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.user_id == user_id && s.expires_at > now)
            .cloned()
            .collect())
    }

    async fn delete_session(&self, id: Uuid) -> Result<(), Error> {
        self.sessions.lock().unwrap().retain(|s| s.id != id);
        Ok(())
    }

    async fn validate_session(&self, id: Uuid) -> Result<bool, Error> {
        let now = OffsetDateTime::now_utc();
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.id == id && s.expires_at > now))
    }

    async fn update_session_token(&self, id: Uuid, token: &str) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.iter_mut().find(|s| s.id == id) {
            session.token = token.to_string();
            Ok(())
        } else {
            Err(Error::Database(SqlxError::RowNotFound))
        }
    }
}

pub struct RealSessionRepository {
    sessions: Mutex<Vec<Session>>,
}

impl Default for RealSessionRepository {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
        }
    }
}

impl RealSessionRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_session(&self, session: Session) {
        self.sessions.lock().unwrap().push(session);
    }

    pub fn clear_sessions(&self) {
        self.sessions.lock().unwrap().clear();
    }

    pub fn get_all_sessions(&self) -> Vec<Session> {
        self.sessions.lock().unwrap().clone()
    }
}
