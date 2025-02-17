use acci_core::error::Error;
use acci_db::{
    repositories::user::{CreateUser, UpdateUser, UserRepository},
    User,
};
use anyhow::Result;
use async_trait::async_trait;
use mockall::mock;
use uuid::Uuid;

mock! {
    #[derive(Debug)]
    pub UserRepository {}

    #[async_trait]
    impl UserRepository for UserRepository {
        async fn create(&self, user: CreateUser) -> Result<User>;
        async fn get_by_id(&self, id: Uuid) -> Result<Option<User>>;
        async fn get_by_email(&self, email: &str) -> Result<Option<User>>;
        async fn update(&self, id: Uuid, user: UpdateUser) -> Result<Option<User>>;
        async fn delete(&self, id: Uuid) -> Result<bool>;
    }
}
