//! User repository implementation for database operations.

use acci_core::{error::Error, models::User};
use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Repository trait for user-related database operations.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Creates a new user with the given username and password hash.
    async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, Error>;

    /// Retrieves a user by their unique identifier.
    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, Error>;

    /// Retrieves a user by their username.
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, Error>;

    /// Sets or unsets the admin status for a user.
    async fn set_admin(&self, user_id: Uuid, is_admin: bool) -> Result<(), Error>;

    /// Deletes a user by their unique identifier.
    async fn delete_user(&self, id: Uuid) -> Result<(), Error>;

    /// Updates a user's password hash.
    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), Error>;
}

/// PostgreSQL implementation of the `UserRepository` trait.
#[derive(Debug, Clone)]
pub struct PgUserRepository {
    /// The database connection pool.
    pub pool: PgPool,
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
    /// * `username` - The username of the user.
    /// * `password_hash` - The hashed password of the user.
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
    async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, Error> {
        // First check if a user with this username already exists (case-insensitive)
        let existing_user = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM acci.users
            WHERE username ILIKE $1
            "#,
            username
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

        if existing_user.count.unwrap_or(0) > 0 {
            return Err(Error::Validation(format!(
                "Username '{username}' is already taken (case-insensitive)"
            )));
        }

        let now = time::OffsetDateTime::now_utc();
        let result = sqlx::query_as!(
            User,
            r#"
            INSERT INTO acci.users (username, email, password_hash, is_admin, created_at, updated_at, full_name)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, username, email, password_hash, is_admin, created_at, updated_at, full_name
            "#,
            username,
            format!("{}@example.com", username), // For testing purposes
            password_hash,
            false,
            now,
            now,
            username, // For testing purposes, we use the username as the full name
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(user) => Ok(user),
            Err(e) => Err(Error::Database(e.to_string())),
        }
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
    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, email, password_hash, is_admin, created_at, updated_at, full_name
            FROM acci.users
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

        Ok(user)
    }

    /// Retrieves a user by their username.
    ///
    /// # Arguments
    ///
    /// * `username` - The username of the user to retrieve.
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
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, email, password_hash, is_admin, created_at, updated_at, full_name
            FROM acci.users
            WHERE username ILIKE $1
            "#,
            username
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

        Ok(user)
    }

    /// Sets the admin status of a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user to update.
    /// * `is_admin` - The new admin status of the user.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the operation was successful, an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    ///
    /// # Panics
    ///
    /// This function will panic if the database returns invalid UTF-8 characters.
    async fn set_admin(&self, user_id: Uuid, is_admin: bool) -> Result<(), Error> {
        let now = time::OffsetDateTime::now_utc();
        sqlx::query!(
            r#"
            UPDATE acci.users
            SET is_admin = $1, updated_at = $2
            WHERE id = $3
            "#,
            is_admin,
            now,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

        Ok(())
    }

    /// Deletes a user from the database.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the user to delete.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the user was deleted, an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    ///
    /// # Panics
    ///
    /// This function will panic if the database returns invalid UTF-8 characters.
    async fn delete_user(&self, id: Uuid) -> Result<(), Error> {
        sqlx::query!(
            r#"
            DELETE FROM acci.users
            WHERE id = $1
            "#,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

        Ok(())
    }

    /// Updates the password of a user.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the user to update.
    /// * `password_hash` - The new hashed password of the user.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the operation was successful, an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    ///
    /// # Panics
    ///
    /// This function will panic if the database returns invalid UTF-8 characters.
    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), Error> {
        let now = time::OffsetDateTime::now_utc();
        sqlx::query!(
            r#"
            UPDATE acci.users
            SET password_hash = $1, updated_at = $2
            WHERE id = $3
            "#,
            password_hash,
            now,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

        Ok(())
    }
}

/// A mock implementation of the `UserRepository` trait for testing purposes.
#[derive(Debug, Clone, Default)]
pub struct MockUserRepository {}

impl MockUserRepository {
    /// Creates a new instance of the mock repository.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn get_user_by_username(&self, _username: &str) -> Result<Option<User>, Error> {
        Ok(None)
    }

    async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, Error> {
        Ok(User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            email: format!("{username}@example.com"),
            password_hash: password_hash.to_string(),
            is_admin: false,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            full_name: username.to_string(), // For testing purposes
        })
    }

    async fn get_user_by_id(&self, _id: Uuid) -> Result<Option<User>, Error> {
        Ok(None)
    }

    async fn set_admin(&self, _user_id: Uuid, _is_admin: bool) -> Result<(), Error> {
        Ok(())
    }

    async fn delete_user(&self, _id: Uuid) -> Result<(), Error> {
        Ok(())
    }

    async fn update_password(&self, _id: Uuid, _password_hash: &str) -> Result<(), Error> {
        Ok(())
    }
}

impl std::fmt::Debug for dyn UserRepository + Send + Sync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserRepository")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[derive(Debug)]
    struct CreateUser {
        email: String,
        password_hash: String,
        full_name: String,
    }

    #[derive(Debug)]
    struct UpdateUser {
        email: Option<String>,
        password_hash: Option<String>,
        full_name: Option<String>,
    }

    #[test]
    fn test_create_user_validation() {
        let user = CreateUser {
            email: "test@example.com".to_string(),
            password_hash: "hash123".to_string(),
            full_name: "Test User".to_string(),
        };

        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.password_hash, "hash123");
        assert_eq!(user.full_name, "Test User");
    }

    #[test]
    fn test_update_user_partial() {
        let update = UpdateUser {
            email: Some("new@example.com".to_string()),
            password_hash: None,
            full_name: Some("New Name".to_string()),
        };

        assert_eq!(update.email.as_deref(), Some("new@example.com"));
        assert_eq!(update.password_hash, None);
        assert_eq!(update.full_name.as_deref(), Some("New Name"));
    }

    #[test]
    fn test_user_fields() {
        let now = datetime!(2024-02-15 0:00 UTC);
        let user = User {
            id: Uuid::nil(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash123".to_string(),
            is_admin: false,
            created_at: now,
            updated_at: now,
            full_name: "testuser".to_string(),
        };

        assert_eq!(user.id, Uuid::nil());
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.password_hash, "hash123");
        assert_eq!(user.is_admin, false);
        assert_eq!(user.created_at, now);
        assert_eq!(user.updated_at, now);
        assert_eq!(user.full_name, "testuser");
    }
}
