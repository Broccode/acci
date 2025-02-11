use acci_db::{create_pool, run_migrations, sqlx, test_connection, DbConfig};
use anyhow::Result;
use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};

async fn setup() -> Result<(Box<dyn std::any::Any>, DbConfig, sqlx::PgPool)> {
    let container = postgres::Postgres::default().start().await?;
    let port = container.get_host_port_ipv4(5432).await?;

    let config = DbConfig {
        url: format!("postgres://postgres:postgres@localhost:{}/postgres", port),
        max_connections: 2,
        connect_timeout: 5,
    };

    let pool = create_pool(config.clone()).await?;

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

    Ok((Box::new(container), config, pool))
}

#[tokio::test]
async fn test_create_pool() {
    let (_container, _config, pool) = setup().await.unwrap();
    assert!(pool.acquire().await.is_ok());
}

#[tokio::test]
async fn test_connection_success() {
    let (_container, _config, pool) = setup().await.unwrap();
    let result = test_connection(&pool).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_invalid_connection_config() {
    let (_container, _config, _pool) = setup().await.unwrap();

    // Test with invalid config
    let invalid_config = DbConfig {
        url: "postgres://invalid:invalid@localhost:1234/nonexistent".to_string(),
        max_connections: 1,
        connect_timeout: 1,
    };

    let result = create_pool(invalid_config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_connection_pool_limits() {
    let (_container, config, _existing_pool) = setup().await.unwrap();

    // Create a new pool with limited connections
    let limited_config = DbConfig {
        max_connections: 1,
        connect_timeout: 1,
        ..config
    };

    let pool = create_pool(limited_config).await.unwrap();

    // Acquire first connection
    let conn1 = pool.acquire().await.unwrap();

    // Second connection should timeout
    let conn2_result =
        tokio::time::timeout(std::time::Duration::from_secs(2), pool.acquire()).await;

    assert!(conn2_result.is_err() || conn2_result.unwrap().is_err());

    // Release first connection
    drop(conn1);

    // Should be able to acquire a connection again
    assert!(pool.acquire().await.is_ok());
}
