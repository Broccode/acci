use acci_db::repositories::user::{CreateUser, UpdateUser, User, UserRepository};
use anyhow::Result;
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use time::OffsetDateTime;
use uuid::Uuid;

/// Mock implementation of the UserRepository trait for testing.
#[derive(Debug, Default, Clone)]
pub struct MockUserRepository {
    users: Arc<Mutex<HashMap<Uuid, User>>>,
    email_index: Arc<Mutex<HashMap<String, Uuid>>>,
}

impl MockUserRepository {
    /// Creates a new empty MockUserRepository.
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            email_index: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn create(&self, user: CreateUser) -> Result<User> {
        let id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let user = User {
            id,
            email: user.email.clone(),
            password_hash: user.password_hash,
            full_name: user.full_name,
            created_at: now,
            updated_at: now,
        };

        self.email_index
            .lock()
            .unwrap()
            .insert(user.email.clone(), id);
        self.users.lock().unwrap().insert(id, user.clone());

        Ok(user)
    }

    async fn get_by_id(&self, id: Uuid) -> Result<Option<User>> {
        Ok(self.users.lock().unwrap().get(&id).cloned())
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<User>> {
        let id = self.email_index.lock().unwrap().get(email).copied();
        Ok(id.and_then(|id| self.users.lock().unwrap().get(&id).cloned()))
    }

    async fn update(&self, id: Uuid, user: UpdateUser) -> Result<Option<User>> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();

        if let Some(existing_user) = users.get_mut(&id) {
            if let Some(email) = user.email {
                email_index.remove(&existing_user.email);
                email_index.insert(email.clone(), id);
                existing_user.email = email;
            }
            if let Some(password_hash) = user.password_hash {
                existing_user.password_hash = password_hash;
            }
            if let Some(full_name) = user.full_name {
                existing_user.full_name = full_name;
            }
            existing_user.updated_at = OffsetDateTime::now_utc();
            Ok(Some(existing_user.clone()))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, id: Uuid) -> Result<bool> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.remove(&id) {
            self.email_index.lock().unwrap().remove(&user.email);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
