//! Database functionality for the ACCI system.
//!
//! This crate provides database access and management functionality,
//! including connection pooling, migrations, and repository implementations.

use anyhow::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

mod error;
pub mod repositories;

pub use error::DbError;
#[cfg(test)]
pub use repositories::user::mock;
pub use repositories::user::{CreateUser, PgUserRepository, UpdateUser, User, UserRepository};
pub use sqlx;

/// Configuration for database connections.
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// The database connection URL.
    pub url: String,
    /// The maximum number of connections in the pool.
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

/// Creates a new database connection pool.
///
/// # Arguments
///
/// * `config` - The database configuration to use.
///
/// # Returns
///
/// A new connection pool configured according to the provided settings.
///
/// # Errors
///
/// Returns an error if:
/// * The connection URL is invalid
/// * The database is not accessible
/// * The pool creation fails
#[allow(clippy::missing_const_for_fn)]
pub async fn create_pool(config: DbConfig) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(Duration::from_secs(config.connect_timeout))
        .connect(&config.url)
        .await
        .map_err(Into::into)
}

/// Runs all pending database migrations.
///
/// # Arguments
///
/// * `pool` - The database connection pool to use.
///
/// # Returns
///
/// `Ok(())` if all migrations were successful.
///
/// # Errors
///
/// Returns an error if:
/// * The migrations cannot be loaded
/// * A migration fails to execute
/// * The database is not accessible
#[allow(clippy::large_stack_arrays)]
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(Into::into)
}

/// Tests the database connection.
///
/// # Arguments
///
/// * `pool` - The database connection pool to test.
///
/// # Returns
///
/// `Ok(true)` if the connection is successful, `Ok(false)` otherwise.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn test_connection(pool: &PgPool) -> Result<bool> {
    let result = sqlx::query!("SELECT 1 as one").fetch_one(pool).await?;

    Ok(result.one == Some(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_config_default() {
        let config = DbConfig::default();
        assert_eq!(config.max_connections, 5);
        assert_eq!(config.connect_timeout, 30);
        assert!(config.url.contains("postgres://"));
    }

    #[test]
    fn test_db_config_custom() {
        let config = DbConfig {
            url: "postgres://custom:pass@localhost/db".to_string(),
            max_connections: 10,
            connect_timeout: 60,
        };
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.connect_timeout, 60);
        assert_eq!(config.url, "postgres://custom:pass@localhost/db");
    }
}
