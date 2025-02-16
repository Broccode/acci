#![allow(clippy::large_stack_arrays)]

//! Database functionality for the ACCI system.
//!
//! This crate provides database access and management functionality,
//! including connection pooling, migrations, and repository implementations.

use anyhow::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use thiserror::Error;

mod error;
pub mod models;
pub mod repositories;

pub use error::DbError;
pub use repositories::user::{CreateUser, PgUserRepository, UpdateUser, User, UserRepository};
pub use sqlx;

/// Configuration for database connections.
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// The database connection URL.
    pub url: String,
    /// The maximum number of connections in the pool.
    pub max_connections: u32,
    /// The minimum number of connections in the pool.
    pub min_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout_seconds: u64,
    /// Idle timeout in seconds
    pub idle_timeout_seconds: u64,
    /// Maximum lifetime in seconds
    pub max_lifetime_seconds: u64,
    /// The environment setting
    pub environment: Environment,
}

/// Represents the environment in which the application is running.
/// This affects various behaviors like logging, error handling, and feature availability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Environment {
    /// Development environment with additional debugging and development features.
    Development,
    /// Test environment for running automated tests.
    Test,
    /// Production environment with optimized settings and security restrictions.
    Production,
}

impl Default for Environment {
    fn default() -> Self {
        if cfg!(debug_assertions) {
            Self::Development
        } else {
            Self::Production
        }
    }
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: "postgres://postgres:postgres@localhost:5432/postgres".to_string(),
            max_connections: 5,
            min_connections: 1,
            connect_timeout_seconds: 10,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 1800,
            environment: Environment::default(),
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
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.connect_timeout_seconds))
        .idle_timeout(Duration::from_secs(config.idle_timeout_seconds))
        .max_lifetime(Duration::from_secs(config.max_lifetime_seconds))
        .connect(&config.url)
        .await?;

    // Set environment in database session
    let env_str = match config.environment {
        Environment::Development => "development",
        Environment::Test => "test",
        Environment::Production => "production",
    };
    sqlx::query("SELECT set_config('app.environment', $1, false)")
        .bind(env_str)
        .execute(&pool)
        .await?;

    Ok(pool)
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

pub use models::Session;
pub use repositories::SessionRepository;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_config_default() {
        let config = DbConfig::default();
        assert_eq!(config.max_connections, 5);
        assert_eq!(config.min_connections, 1);
        assert_eq!(config.connect_timeout_seconds, 10);
        assert_eq!(config.idle_timeout_seconds, 600);
        assert_eq!(config.max_lifetime_seconds, 1800);
        assert_eq!(config.environment, Environment::Development);
        assert!(config.url.contains("postgres://"));
    }

    #[test]
    fn test_db_config_custom() {
        let config = DbConfig {
            url: "postgres://custom:pass@localhost/db".to_string(),
            max_connections: 10,
            min_connections: 2,
            connect_timeout_seconds: 60,
            idle_timeout_seconds: 1200,
            max_lifetime_seconds: 3600,
            environment: Environment::Test,
        };
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.min_connections, 2);
        assert_eq!(config.connect_timeout_seconds, 60);
        assert_eq!(config.idle_timeout_seconds, 1200);
        assert_eq!(config.max_lifetime_seconds, 3600);
        assert_eq!(config.environment, Environment::Test);
        assert_eq!(config.url, "postgres://custom:pass@localhost/db");
    }
}
