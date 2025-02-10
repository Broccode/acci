//! User repository implementation for database operations.

use anyhow::Result;
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

/// Repository for user-related database operations.
#[derive(Debug, Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    /// Creates a new `UserRepository` instance.
    ///
    /// # Arguments
    ///
    /// * `pool` - The database connection pool to use.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

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
    pub async fn create(&self, user: CreateUser) -> Result<User> {
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
    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<User>> {
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
    pub async fn get_by_email(&self, email: &str) -> Result<Option<User>> {
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
    pub async fn update(&self, id: Uuid, user: UpdateUser) -> Result<Option<User>> {
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
    pub async fn delete(&self, id: Uuid) -> Result<bool> {
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
mod tests {
    use super::*;
    use crate::DbConfig;

    async fn setup() -> (PgPool, UserRepository) {
        let config = DbConfig::default();
        let pool = crate::create_pool(config).await.unwrap();
        crate::run_migrations(&pool).await.unwrap();
        let repo = UserRepository::new(pool.clone());
        (pool, repo)
    }

    #[tokio::test]
    async fn test_create_user() {
        let (_pool, repo) = setup().await;

        let user = CreateUser {
            email: "test@example.com".to_string(),
            password_hash: "hash123".to_string(),
            full_name: "Test User".to_string(),
        };

        let created = repo.create(user).await.unwrap();
        assert_eq!(created.email, "test@example.com");
        assert_eq!(created.full_name, "Test User");
    }

    #[tokio::test]
    async fn test_get_user_by_email() {
        let (_pool, repo) = setup().await;

        let user = CreateUser {
            email: "find@example.com".to_string(),
            password_hash: "hash123".to_string(),
            full_name: "Find User".to_string(),
        };

        let created = repo.create(user).await.unwrap();
        let found = repo
            .get_by_email("find@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(created.id, found.id);
    }
}
