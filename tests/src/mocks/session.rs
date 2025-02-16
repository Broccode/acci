use acci_db::{models::Session, repositories::session::SessionRepository, Error};
use async_trait::async_trait;
use std::sync::Mutex;
use uuid::Uuid;

/// Mock session repository for testing.
#[derive(Debug, Default)]
pub struct MockSessionRepository {
    sessions: Mutex<Vec<Session>>,
}

impl MockSessionRepository {
    /// Creates a new mock session repository.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl SessionRepository for MockSessionRepository {
    async fn create_session(&self, session: &Session) -> Result<Session, Error> {
        let mut sessions = self.sessions.lock().unwrap();
        let new_session = session.clone();
        sessions.push(new_session.clone());
        Ok(new_session)
    }

    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session>, Error> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions
            .iter()
            .find(|s| s.session_id == session_id)
            .cloned())
    }

    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions
            .iter()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|s| s.session_id != session_id);
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> Result<u64, Error> {
        let mut sessions = self.sessions.lock().unwrap();
        let initial_len = sessions.len();
        sessions.retain(|s| !s.is_expired());
        Ok((initial_len - sessions.len()) as u64)
    }
}
