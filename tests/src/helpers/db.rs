use acci_core::error::Result as CoreResult;
use acci_db::{
    create_pool, run_migrations,
    sqlx::{self, PgPool},
    DbConfig,
};
use anyhow::Result;
use std::time::Duration;
use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};
use tokio::time::timeout;

/// Sets up a test database with all migrations applied
///
/// # Returns
/// * `Result<(Box<dyn std::any::Any>, PgPool)>` - A tuple containing:
///   - The container handle (must be kept alive for the duration of the test)
///   - The database connection pool
pub async fn setup_database() -> Result<(Box<dyn std::any::Any>, PgPool)> {
    let container = postgres::Postgres::default().start().await?;
    let port = container.get_host_port_ipv4(5432).await?;

    let config = DbConfig {
        url: format!("postgres://postgres:postgres@localhost:{}/postgres", port),
        ..Default::default()
    };

    let pool = create_pool(config).await?;

    // Enable crypto extension in postgres database
    sqlx::query("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"")
        .execute(&pool)
        .await?;

    // Enable UUID extension in postgres database
    sqlx::query("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
        .execute(&pool)
        .await?;

    // Create schema and ensure extension is available
    sqlx::query("CREATE SCHEMA IF NOT EXISTS acci")
        .execute(&pool)
        .await?;

    run_migrations(&pool).await?;

    Ok((Box::new(container), pool))
}

/// Creates a test database configuration for a given port
///
/// # Arguments
/// * `port` - The port number to use for the database connection
///
/// # Returns
/// * `DbConfig` - The database configuration
pub fn create_test_config(port: u16) -> DbConfig {
    DbConfig {
        url: format!("postgres://postgres:postgres@localhost:{}/postgres", port),
        max_connections: 2,
        connect_timeout_seconds: 5,
        min_connections: 1,
        idle_timeout_seconds: 300,
        max_lifetime_seconds: 3600,
        environment: acci_db::Environment::Test,
    }
}

/// Wartet, bis die Datenbank bereit ist
pub async fn wait_for_db(pool: &PgPool) -> CoreResult<()> {
    let timeout_duration = Duration::from_secs(5);

    timeout(timeout_duration, async {
        loop {
            match sqlx::query("SELECT 1").execute(pool).await {
                Ok(_) => return Ok(()),
                Err(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .map_err(|_| acci_core::error::Error::internal("Database connection timeout"))?
}
