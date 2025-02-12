//! User repository implementation for database operations.

use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Represents a user in the system.
#[derive(Debug, Clone)]
#[allow(clippy::large_stack_arrays)]
pub struct User {
    /// The unique identifier of the user.
    pub id: Uuid,
    /// The email address of the user.
    pub email: String,
    /// The hashed password of the user.
    pub password_hash: String,
    /// The full name of the user.
    pub full_name: String,
    /// The timestamp when the user was created.
    pub created_at: OffsetDateTime,
    /// The timestamp when the user was last updated.
    pub updated_at: OffsetDateTime,
}

/// Data required to create a new user.
#[derive(Debug)]
pub struct CreateUser {
    /// The email address of the user.
    pub email: String,
    /// The hashed password of the user.
    pub password_hash: String,
    /// The full name of the user.
    pub full_name: String,
}

/// Data that can be updated for a user.
#[derive(Debug)]
pub struct UpdateUser {
    /// The new email address of the user, if it should be updated.
    pub email: Option<String>,
    /// The new hashed password of the user, if it should be updated.
    pub password_hash: Option<String>,
    /// The new full name of the user, if it should be updated.
    pub full_name: Option<String>,
}

/// Repository trait for user-related database operations.
#[async_trait]
pub trait UserRepository: Send + Sync + std::fmt::Debug {
    /// Creates a new user in the database.
    async fn create(&self, user: CreateUser) -> Result<User>;

    /// Retrieves a user by their ID.
    async fn get_by_id(&self, id: Uuid) -> Result<Option<User>>;

    /// Retrieves a user by their email address.
    async fn get_by_email(&self, email: &str) -> Result<Option<User>>;

    /// Updates a user's information.
    async fn update(&self, id: Uuid, user: UpdateUser) -> Result<Option<User>>;

    /// Deletes a user from the database.
    async fn delete(&self, id: Uuid) -> Result<bool>;
}

/// PostgreSQL implementation of the `UserRepository` trait.
#[derive(Debug, Clone)]
pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    /// Creates a new `PgUserRepository` instance.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    /// Creates a new user in the database.
    ///
    /// # Arguments
    ///
    /// * `user` - The user data to create.
    ///
    /// # Returns
    ///
    /// The created user with all fields populated.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The database operation fails
    /// * The email is already in use
    ///
    /// # Panics
    ///
    /// This function will panic if the user data contains invalid UTF-8 characters.
    async fn create(&self, user: CreateUser) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO acci.users (email, password_hash, full_name)
            VALUES ($1, $2, $3)
            RETURNING
                id as "id: Uuid",
                email,
                password_hash,
                full_name,
                created_at,
                updated_at
            "#,
            user.email,
            user.password_hash,
            user.full_name
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    /// Retrieves a user by their ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the user to retrieve.
    ///
    /// # Returns
    ///
    /// The user if found, None otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    ///
    /// # Panics
    ///
    /// This function will panic if the database returns invalid UTF-8 characters.
    async fn get_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id as "id: Uuid",
                email,
                password_hash,
                full_name,
                created_at,
                updated_at
            FROM acci.users
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Retrieves a user by their email address.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address of the user to retrieve.
    ///
    /// # Returns
    ///
    /// The user if found, None otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    ///
    /// # Panics
    ///
    /// This function will panic if the database returns invalid UTF-8 characters.
    async fn get_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id as "id: Uuid",
                email,
                password_hash,
                full_name,
                created_at,
                updated_at
            FROM acci.users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Updates a user's information.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the user to update.
    /// * `user` - The new user data.
    ///
    /// # Returns
    ///
    /// The updated user if found, None otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The database operation fails
    /// * The new email is already in use
    ///
    /// # Panics
    ///
    /// This function will panic if the user data contains invalid UTF-8 characters.
    async fn update(&self, id: Uuid, user: UpdateUser) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE acci.users
            SET
                email = COALESCE($1, email),
                password_hash = COALESCE($2, password_hash),
                full_name = COALESCE($3, full_name)
            WHERE id = $4
            RETURNING
                id as "id: Uuid",
                email,
                password_hash,
                full_name,
                created_at,
                updated_at
            "#,
            user.email,
            user.password_hash,
            user.full_name,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Deletes a user from the database.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the user to delete.
    ///
    /// # Returns
    ///
    /// `true` if the user was deleted, `false` if the user was not found.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    ///
    /// # Panics
    ///
    /// This function will panic if the database returns invalid UTF-8 characters.
    async fn delete(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            DELETE FROM acci.users
            WHERE id = $1
            "#,
            id
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
/// Mock implementations of the UserRepository trait for testing purposes.
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mock implementation of the UserRepository trait for testing.
    #[derive(Debug, Default)]
    pub struct MockUserRepository {
        users: Mutex<HashMap<Uuid, User>>,
        email_index: Mutex<HashMap<String, Uuid>>,
    }

    impl MockUserRepository {
        /// Creates a new empty MockUserRepository.
        pub fn new() -> Self {
            Self::default()
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
}
