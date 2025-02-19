use acci_db::{models::Session, repositories::session::SessionRepository, Error};
use async_trait::async_trait;
use mockall::mock;
use time::OffsetDateTime;
use uuid::Uuid;

mock! {
    #[derive(Debug, Clone)]
    pub SessionRepository {}

    #[async_trait]
    impl SessionRepository for SessionRepository {
        async fn create_session(&self, user_id: Uuid, token: &str, expires_at: OffsetDateTime) -> Result<Session, Error> {
            todo!()
        }

        async fn get_session(&self, id: Uuid) -> Result<Option<Session>, Error> {
            todo!()
        }

        async fn get_active_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, Error> {
            todo!()
        }

        async fn delete_session(&self, id: Uuid) -> Result<(), Error> {
            todo!()
        }

        async fn validate_session(&self, id: Uuid) -> Result<bool, Error> {
            todo!()
        }

        async fn update_session_token(&self, id: Uuid, token: &str) -> Result<(), Error> {
            todo!()
        }
    }
}
