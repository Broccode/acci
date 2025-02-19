use acci_core::{error::Error, models::User};
use acci_db::repositories::user::UserRepository;
use async_trait::async_trait;
use mockall::mock;
use uuid::Uuid;

mock! {
    #[derive(Debug, Clone)]
    pub UserRepository {}

    #[async_trait]
    impl UserRepository for UserRepository {
        async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, Error> {
            todo!()
        }

        async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, Error> {
            todo!()
        }

        async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, Error> {
            todo!()
        }

        async fn set_admin(&self, id: Uuid, is_admin: bool) -> Result<(), Error> {
            todo!()
        }

        async fn delete_user(&self, id: Uuid) -> Result<(), Error> {
            todo!()
        }

        async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), Error> {
            todo!()
        }
    }
}
