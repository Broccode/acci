//! Database module for the ACCI application.

use anyhow::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

mod error;

pub use error::DbError;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Database connection URL
    pub url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout: u64,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: "postgres://acci:development_only@localhost:5432/acci".to_string(),
            max_connections: 5,
            connect_timeout: 30,
        }
    }
}

/// Creates a new database connection pool
pub async fn create_pool(config: DbConfig) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(Duration::from_secs(config.connect_timeout))
        .connect(&config.url)
        .await
        .map_err(Into::into)
}

/// Runs database migrations
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(Into::into)
}

/// Test the database connection by running a simple query
pub async fn test_connection(pool: &PgPool) -> Result<bool> {
    let result = sqlx::query!("SELECT 1 as test").fetch_one(pool).await?;

    Ok(result.test == Some(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_pool() {
        let config = DbConfig::default();
        let pool = create_pool(config).await.unwrap();
        assert!(pool.acquire().await.is_ok());
    }
}
