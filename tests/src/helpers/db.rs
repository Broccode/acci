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

// Default values for database configuration
const DEFAULT_SETUP_TIMEOUT_SECS: u64 = 30;
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MAX_CONNECTIONS: u32 = 10;

fn get_env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn get_env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Sets up a test database with all migrations applied
///
/// # Returns
/// * `Result<(Box<dyn std::any::Any>, PgPool)>` - A tuple containing:
///   - The container handle (must be kept alive for the duration of the test)
///   - The database connection pool
///
/// # Errors
/// Returns an error if:
/// - Container startup fails
/// - Database connection fails
/// - Extensions cannot be enabled
/// - Migrations fail to apply
pub async fn setup_database() -> Result<(Box<dyn std::any::Any>, PgPool)> {
    let setup_timeout = Duration::from_secs(get_env_u64(
        "DB_SETUP_TIMEOUT_SECS",
        DEFAULT_SETUP_TIMEOUT_SECS,
    ));

    // Start container with timeout
    let container_setup = timeout(setup_timeout, async {
        let container = postgres::Postgres::default().start().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        Ok::<_, anyhow::Error>((container, port))
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "Container startup timeout after {} seconds",
            setup_timeout.as_secs()
        )
    })??;

    let (container, port) = container_setup;

    let max_connections = get_env_u32("DB_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS);
    let config = DbConfig {
        url: format!("postgres://postgres:postgres@localhost:{}/postgres", port),
        max_connections,
        connect_timeout_seconds: 5,
        min_connections: 2,
        idle_timeout_seconds: 300,
        max_lifetime_seconds: 3600,
        environment: acci_db::Environment::Test,
    };

    let pool = create_pool(config).await?;

    // Enable extensions and create schema with proper error handling
    let setup_result = sqlx::query("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\";")
        .execute(&pool)
        .await;

    if let Err(e) = setup_result {
        return Err(anyhow::anyhow!("Failed to setup pgcrypto extension: {}", e));
    }

    let setup_result = sqlx::query("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")
        .execute(&pool)
        .await;

    if let Err(e) = setup_result {
        return Err(anyhow::anyhow!(
            "Failed to setup uuid-ossp extension: {}",
            e
        ));
    }

    let setup_result = sqlx::query("CREATE SCHEMA IF NOT EXISTS acci;")
        .execute(&pool)
        .await;

    if let Err(e) = setup_result {
        return Err(anyhow::anyhow!("Failed to create schema: {}", e));
    }

    // Run migrations with timeout
    let migration_timeout = Duration::from_secs(get_env_u64(
        "DB_SETUP_TIMEOUT_SECS",
        DEFAULT_SETUP_TIMEOUT_SECS,
    ));
    timeout(migration_timeout, run_migrations(&pool))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Migration timeout after {} seconds",
                migration_timeout.as_secs()
            )
        })??;

    // Wait for database to be fully ready
    wait_for_db(&pool).await?;

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
    let max_connections = get_env_u32("DB_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS);
    DbConfig {
        url: format!("postgres://postgres:postgres@localhost:{}/postgres", port),
        max_connections,
        connect_timeout_seconds: 5,
        min_connections: 2,
        idle_timeout_seconds: 300,
        max_lifetime_seconds: 3600,
        environment: acci_db::Environment::Test,
    }
}

/// Wartet, bis die Datenbank bereit ist
///
/// # Arguments
/// * `pool` - The database connection pool
///
/// # Returns
/// * `CoreResult<()>` - Ok if database is ready, Error if timeout or connection fails
pub async fn wait_for_db(pool: &PgPool) -> CoreResult<()> {
    let timeout_duration = Duration::from_secs(get_env_u64(
        "DB_WAIT_TIMEOUT_SECS",
        DEFAULT_WAIT_TIMEOUT_SECS,
    ));

    timeout(timeout_duration, async {
        loop {
            match sqlx::query("SELECT 1").execute(pool).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if e.to_string().contains("the database system is starting up") {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    } else {
                        return Err(acci_core::error::Error::internal(format!(
                            "Database connection error: {}",
                            e
                        )));
                    }
                },
            }
        }
    })
    .await
    .map_err(|_| {
        acci_core::error::Error::internal(format!(
            "Database connection timeout after {} seconds",
            timeout_duration.as_secs()
        ))
    })?
}

/// Bereinigt die Testdatenbank
///
/// # Arguments
/// * `pool` - The database connection pool
///
/// # Returns
/// * `Result<()>` - Ok if cleanup successful, Error if cleanup fails
pub async fn cleanup_database(pool: &PgPool) -> Result<()> {
    sqlx::query(
        r#"
        DO $$
        BEGIN
            -- Disable all triggers
            EXECUTE (
                SELECT 'ALTER TABLE ' || quote_ident(tablename) || ' DISABLE TRIGGER ALL;'
                FROM pg_tables
                WHERE schemaname = 'acci'
            );

            -- Truncate all tables
            EXECUTE (
                SELECT 'TRUNCATE TABLE ' || quote_ident(tablename) || ' CASCADE;'
                FROM pg_tables
                WHERE schemaname = 'acci'
            );

            -- Re-enable all triggers
            EXECUTE (
                SELECT 'ALTER TABLE ' || quote_ident(tablename) || ' ENABLE TRIGGER ALL;'
                FROM pg_tables
                WHERE schemaname = 'acci'
            );
        END $$;
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("Failed to cleanup database: {}", e))?;

    Ok(())
}
