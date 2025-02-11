use acci_db::{create_pool, repositories::UserRepository, run_migrations, sqlx, DbConfig};
use anyhow::Result;
use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};

async fn setup() -> Result<(Box<dyn std::any::Any>, UserRepository)> {
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
    let repo = UserRepository::new(pool);
    Ok((Box::new(container), repo))
}

#[tokio::test]
async fn test_create_user() {
    let (_container, repo) = setup().await.unwrap();

    let user = acci_db::repositories::user::CreateUser {
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
    let (_container, repo) = setup().await.unwrap();

    let user = acci_db::repositories::user::CreateUser {
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
