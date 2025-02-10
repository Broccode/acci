use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub full_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct CreateUser {
    pub email: String,
    pub password_hash: String,
    pub full_name: String,
}

#[derive(Debug)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub full_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, user: CreateUser) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (email, password_hash, full_name)
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
            FROM users
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

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
            FROM users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn update(&self, id: Uuid, user: UpdateUser) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
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

    pub async fn delete(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            DELETE FROM users
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
