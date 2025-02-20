use acci_core::{error::Error, models::User};
use acci_db::repositories::user::UserRepository;
use async_trait::async_trait;
use mockall::automock;
use std::sync::Mutex;
use time::OffsetDateTime;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Repository for managing user data in tests
pub struct RealUserRepository {
    users: Mutex<Vec<User>>,
    create_user_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    get_user_by_id_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    get_user_by_username_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    set_admin_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    delete_user_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
    update_password_error: Mutex<Option<Box<dyn Fn() -> Error + Send + Sync>>>,
}

#[automock]
#[async_trait]
impl UserRepository for RealUserRepository {
    async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, Error> {
        debug!("Attempting to create user with username: {}", username);

        if let Some(error_fn) = self
            .create_user_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            warn!("Injecting error for create_user");
            return Err(error_fn());
        }

        // Check if username already exists
        if self
            .users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .iter()
            .any(|u| u.username == username)
        {
            warn!("Username '{}' already exists", username);
            return Err(Error::Validation(format!(
                "error.user.username_exists:{}",
                username
            )));
        }

        let user = User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            email: format!("{}@example.com", username),
            password_hash: password_hash.to_string(),
            full_name: username.to_string(),
            is_admin: false,
            is_active: true,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        self.users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .push(user.clone());

        info!("Successfully created user: {}", username);
        Ok(user)
    }

    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, Error> {
        debug!("Attempting to get user by ID: {}", id);

        if let Some(error_fn) = self
            .get_user_by_id_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            warn!("Injecting error for get_user_by_id");
            return Err(error_fn());
        }

        let result = self
            .users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .iter()
            .find(|u| u.id == id)
            .cloned();

        if result.is_none() {
            debug!("User with ID {} not found", id);
        }

        Ok(result)
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, Error> {
        debug!("Attempting to get user by username: {}", username);

        if let Some(error_fn) = self
            .get_user_by_username_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            warn!("Injecting error for get_user_by_username");
            return Err(error_fn());
        }

        let result = self
            .users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .iter()
            .find(|u| u.username == username)
            .cloned();

        if result.is_none() {
            debug!("User with username {} not found", username);
        }

        Ok(result)
    }

    async fn set_admin(&self, id: Uuid, is_admin: bool) -> Result<(), Error> {
        debug!(
            "Attempting to set admin status to {} for user ID: {}",
            is_admin, id
        );

        if let Some(error_fn) = self
            .set_admin_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            warn!("Injecting error for set_admin");
            return Err(error_fn());
        }

        let mut users = self
            .users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if let Some(user) = users.iter_mut().find(|u| u.id == id) {
            user.is_admin = is_admin;
            info!(
                "Successfully {} admin privileges for user: {}",
                if is_admin { "granted" } else { "revoked" },
                user.username
            );
            Ok(())
        } else {
            warn!("Failed to set admin status: user with ID {} not found", id);
            Err(Error::NotFound(format!("error.user.not_found:{}", id)))
        }
    }

    async fn delete_user(&self, id: Uuid) -> Result<(), Error> {
        debug!("Attempting to delete user with ID: {}", id);

        if let Some(error_fn) = self
            .delete_user_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            warn!("Injecting error for delete_user");
            return Err(error_fn());
        }

        let mut users = self
            .users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if users.iter().any(|u| u.id == id) {
            users.retain(|u| u.id != id);
            info!("Successfully deleted user with ID: {}", id);
            Ok(())
        } else {
            warn!("Failed to delete user: user with ID {} not found", id);
            Err(Error::NotFound(format!("error.user.not_found:{}", id)))
        }
    }

    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), Error> {
        debug!("Attempting to update password for user ID: {}", id);

        if let Some(error_fn) = self
            .update_password_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_ref()
        {
            warn!("Injecting error for update_password");
            return Err(error_fn());
        }

        let mut users = self
            .users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if let Some(user) = users.iter_mut().find(|u| u.id == id) {
            user.password_hash = password_hash.to_string();
            user.updated_at = OffsetDateTime::now_utc();
            info!("Successfully updated password for user: {}", user.username);
            Ok(())
        } else {
            warn!("Failed to update password: user with ID {} not found", id);
            Err(Error::NotFound(format!("error.user.not_found:{}", id)))
        }
    }
}

impl Default for RealUserRepository {
    fn default() -> Self {
        Self {
            users: Mutex::new(Vec::new()),
            create_user_error: Mutex::new(None),
            get_user_by_id_error: Mutex::new(None),
            get_user_by_username_error: Mutex::new(None),
            set_admin_error: Mutex::new(None),
            delete_user_error: Mutex::new(None),
            update_password_error: Mutex::new(None),
        }
    }
}

impl RealUserRepository {
    /// Creates a new instance of the repository
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a user to the repository
    pub fn add_user(&self, user: User) -> Result<(), Error> {
        debug!("Adding user to repository: {}", user.username);
        self.users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .push(user);
        Ok(())
    }

    /// Clears all users from the repository
    pub fn clear_users(&self) -> Result<(), Error> {
        debug!("Clearing all users from repository");
        self.users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .clear();
        Ok(())
    }

    /// Gets all users from the repository
    pub fn get_all_users(&self) -> Result<Vec<User>, Error> {
        debug!("Getting all users from repository");
        Ok(self
            .users
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .clone())
    }

    /// Sets an error to be returned by create_user
    pub fn expect_create_user_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        debug!("Setting error expectation for create_user");
        *self
            .create_user_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by get_user_by_id
    pub fn expect_get_user_by_id_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        debug!("Setting error expectation for get_user_by_id");
        *self
            .get_user_by_id_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by get_user_by_username
    pub fn expect_get_user_by_username_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        debug!("Setting error expectation for get_user_by_username");
        *self
            .get_user_by_username_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by set_admin
    pub fn expect_set_admin_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        debug!("Setting error expectation for set_admin");
        *self
            .set_admin_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by delete_user
    pub fn expect_delete_user_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        debug!("Setting error expectation for delete_user");
        *self
            .delete_user_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }

    /// Sets an error to be returned by update_password
    pub fn expect_update_password_error<F>(&self, error_fn: F) -> Result<(), Error>
    where
        F: Fn() -> Error + Send + Sync + 'static,
    {
        debug!("Setting error expectation for update_password");
        *self
            .update_password_error
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))? = Some(Box::new(error_fn));
        Ok(())
    }
}
