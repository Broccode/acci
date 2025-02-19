use acci_core::{error::Error, models::User};
use acci_db::repositories::user::UserRepository;
use async_trait::async_trait;
use mockall::automock;
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

#[automock]
#[async_trait]
impl UserRepository for RealUserRepository {
    async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, Error> {
        // Check if username already exists
        if self
            .users
            .lock()
            .unwrap()
            .iter()
            .any(|u| u.username == username)
        {
            return Err(Error::validation("Username already exists"));
        }

        let user = User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            email: format!("{}@example.com", username),
            password_hash: password_hash.to_string(),
            full_name: username.to_string(),
            is_admin: false,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        self.users.lock().unwrap().push(user.clone());
        Ok(user)
    }

    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, Error> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.id == id)
            .cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, Error> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.username == username)
            .cloned())
    }

    async fn set_admin(&self, id: Uuid, is_admin: bool) -> Result<(), Error> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == id) {
            user.is_admin = is_admin;
            Ok(())
        } else {
            Err(Error::not_found("User not found"))
        }
    }

    async fn delete_user(&self, id: Uuid) -> Result<(), Error> {
        let mut users = self.users.lock().unwrap();
        if users.iter().any(|u| u.id == id) {
            users.retain(|u| u.id != id);
            Ok(())
        } else {
            Err(Error::not_found("User not found"))
        }
    }

    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), Error> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == id) {
            user.password_hash = password_hash.to_string();
            user.updated_at = OffsetDateTime::now_utc();
            Ok(())
        } else {
            Err(Error::not_found("User not found"))
        }
    }
}

pub struct RealUserRepository {
    users: Mutex<Vec<User>>,
}

impl Default for RealUserRepository {
    fn default() -> Self {
        Self {
            users: Mutex::new(Vec::new()),
        }
    }
}

impl RealUserRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_user(&self, user: User) {
        self.users.lock().unwrap().push(user);
    }

    pub fn clear_users(&self) {
        self.users.lock().unwrap().clear();
    }

    pub fn get_all_users(&self) -> Vec<User> {
        self.users.lock().unwrap().clone()
    }
}
