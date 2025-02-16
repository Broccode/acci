use acci_auth::{AuthConfig, AuthProvider, BasicAuthProvider, Credentials};
use acci_db::{
    create_pool,
    repositories::session::PgSessionRepository,
    repositories::user::{PgUserRepository, UserRepository},
    run_migrations,
    sqlx::{self, PgPool},
    DbConfig,
};
use anyhow::Result;
use std::sync::Arc;
use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};

async fn setup() -> Result<(Box<dyn std::any::Any>, PgUserRepository, PgPool)> {
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
    let repo = PgUserRepository::new(pool.clone());
    Ok((Box::new(container), repo, pool))
}

#[tokio::test]
async fn test_default_admin_user_exists() -> Result<()> {
    let (_container, repo, _) = setup().await?;

    // Get the default admin user
    let user = repo.get_by_email("admin").await?;

    assert!(user.is_some(), "Default admin user should exist");
    let user = user.unwrap();
    assert_eq!(user.email, "admin");
    assert_eq!(user.full_name, "Default Admin");

    Ok(())
}

#[tokio::test]
async fn test_default_admin_authentication() -> Result<()> {
    let (_container, repo, pool) = setup().await?;

    // Add a small delay to ensure database is ready
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create auth provider and try to authenticate
    let user_repo = Arc::new(repo);
    let session_repo = Arc::new(PgSessionRepository::new(pool.clone()));
    let auth_provider = BasicAuthProvider::new(user_repo, session_repo, AuthConfig::default());

    let credentials = Credentials {
        username: "admin".to_string(),
        password: "whiskey".to_string(),
    };

    let result = auth_provider.authenticate(credentials).await;
    assert!(
        result.is_ok(),
        "Default admin authentication should succeed: {:?}",
        result.err()
    );

    Ok(())
}
