use acci_db::{repositories::session::SessionRepository, Error, Session};
use anyhow::Result;
use async_trait::async_trait;
use mockall::automock;
use uuid::Uuid;

#[automock]
#[async_trait]
pub trait SessionRepositoryTrait: Send + Sync {
    async fn create_session(&self, session: &Session) -> Result<Session, Error>;
    async fn get_session(&self, id: Uuid) -> Result<Option<Session>, Error>;
    async fn delete_session(&self, id: Uuid) -> Result<(), Error>;
    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error>;
    async fn delete_expired_sessions(&self) -> Result<u64, Error>;
    async fn invalidate_user_sessions(&self, user_id: Uuid) -> Result<u64, Error>;
}

pub type MockSessionRepository = MockSessionRepositoryTrait;

#[async_trait]
impl SessionRepository for MockSessionRepositoryTrait {
    async fn create_session(&self, session: &Session) -> Result<Session, Error> {
        SessionRepositoryTrait::create_session(self, session).await
    }

    async fn get_session(&self, id: Uuid) -> Result<Option<Session>, Error> {
        SessionRepositoryTrait::get_session(self, id).await
    }

    async fn delete_session(&self, id: Uuid) -> Result<(), Error> {
        SessionRepositoryTrait::delete_session(self, id).await
    }

    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error> {
        SessionRepositoryTrait::get_user_sessions(self, user_id).await
    }

    async fn delete_expired_sessions(&self) -> Result<u64, Error> {
        SessionRepositoryTrait::delete_expired_sessions(self).await
    }

    async fn invalidate_user_sessions(&self, user_id: Uuid) -> Result<u64, Error> {
        SessionRepositoryTrait::invalidate_user_sessions(self, user_id).await
    }
}
