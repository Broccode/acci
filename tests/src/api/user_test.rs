use acci_db::{
    create_pool,
    repositories::user::{PgUserRepository, UserRepository},
    run_migrations,
    sqlx::{self, types::uuid::Uuid},
    DbConfig,
};
use anyhow::Result;
use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};

async fn setup() -> Result<(Box<dyn std::any::Any>, PgUserRepository)> {
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
    let repo = PgUserRepository::new(pool);
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
    assert_eq!(created.password_hash, "hash123");
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

#[tokio::test]
async fn test_get_by_id() {
    let (_container, repo) = setup().await.unwrap();

    let create_user = acci_db::repositories::user::CreateUser {
        email: "test_get@example.com".to_string(),
        password_hash: "hashed_password".to_string(),
        full_name: "Test Get User".to_string(),
    };

    let created_user = repo.create(create_user).await.unwrap();
    let found_user = repo.get_by_id(created_user.id).await.unwrap().unwrap();

    assert_eq!(found_user.id, created_user.id);
    assert_eq!(found_user.email, "test_get@example.com");

    // Test non-existent user
    let non_existent = repo.get_by_id(Uuid::new_v4()).await.unwrap();
    assert!(non_existent.is_none());
}

#[tokio::test]
async fn test_update_user() {
    let (_container, repo) = setup().await.unwrap();

    let create_user = acci_db::repositories::user::CreateUser {
        email: "test_update@example.com".to_string(),
        password_hash: "hashed_password".to_string(),
        full_name: "Test Update User".to_string(),
    };

    let created_user = repo.create(create_user).await.unwrap();

    let update_user = acci_db::repositories::user::UpdateUser {
        email: Some("updated@example.com".to_string()),
        password_hash: Some("new_password_hash".to_string()),
        full_name: Some("Updated User".to_string()),
    };

    let updated_user = repo
        .update(created_user.id, update_user)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated_user.email, "updated@example.com");
    assert_eq!(updated_user.password_hash, "new_password_hash");
    assert_eq!(updated_user.full_name, "Updated User");

    // Test partial update
    let partial_update = acci_db::repositories::user::UpdateUser {
        email: None,
        password_hash: None,
        full_name: Some("Partially Updated User".to_string()),
    };

    let partially_updated_user = repo
        .update(updated_user.id, partial_update)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(partially_updated_user.email, "updated@example.com"); // Unchanged
    assert_eq!(partially_updated_user.password_hash, "new_password_hash"); // Unchanged
    assert_eq!(partially_updated_user.full_name, "Partially Updated User"); // Changed
}

#[tokio::test]
async fn test_delete_user() {
    let (_container, repo) = setup().await.unwrap();

    let create_user = acci_db::repositories::user::CreateUser {
        email: "test_delete@example.com".to_string(),
        password_hash: "hashed_password".to_string(),
        full_name: "Test Delete User".to_string(),
    };

    let created_user = repo.create(create_user).await.unwrap();

    // Verify user exists
    assert!(repo.get_by_id(created_user.id).await.unwrap().is_some());

    // Delete user
    let deleted = repo.delete(created_user.id).await.unwrap();
    assert!(deleted);

    // Verify user no longer exists
    assert!(repo.get_by_id(created_user.id).await.unwrap().is_none());

    // Try to delete non-existent user
    let deleted = repo.delete(Uuid::new_v4()).await.unwrap();
    assert!(!deleted);
}
