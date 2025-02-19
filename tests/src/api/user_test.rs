use acci_core::error::Error;
use acci_core::models::User;
use acci_db::{
    create_pool,
    repositories::user::{PgUserRepository, UserRepository},
    run_migrations,
    sqlx::{self, PgPool},
    DbConfig, Environment,
};
use anyhow::Result;
use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};
use uuid::Uuid;

async fn setup() -> Result<(Box<dyn std::any::Any>, PgUserRepository)> {
    let container = postgres::Postgres::default().start().await?;
    let port = container.get_host_port_ipv4(5432).await?;

    let config = DbConfig {
        url: format!("postgres://postgres:postgres@localhost:{}/postgres", port),
        max_connections: 20,
        min_connections: 5,
        connect_timeout_seconds: 30,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 3600,
        environment: Environment::Test,
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

async fn cleanup_database(pool: &PgPool) -> Result<(), Error> {
    sqlx::query("DELETE FROM acci.users")
        .execute(pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;
    Ok(())
}

#[tokio::test]
async fn test_create_user() {
    let (_container, repo) = setup().await.unwrap();
    cleanup_database(&repo.pool).await.unwrap();

    let username = "test_user";
    let password_hash = "hash123";

    let created = repo.create_user(username, password_hash).await.unwrap();
    assert_eq!(created.username, username, "Username should match");
    assert_eq!(
        created.password_hash, password_hash,
        "Password hash should match"
    );
    assert!(!created.is_admin, "New user should not be admin by default");
}

#[tokio::test]
async fn test_get_user_by_username() {
    let (_container, repo) = setup().await.unwrap();

    let username = "find_user";
    let password_hash = "hash123";

    let created = repo.create_user(username, password_hash).await.unwrap();
    let found = repo.get_user_by_username(username).await.unwrap().unwrap();
    assert_eq!(created.id, found.id, "User IDs should match");
}

#[tokio::test]
async fn test_get_by_id() {
    let (_container, repo) = setup().await.unwrap();

    let username = "test_get_user";
    let password_hash = "hashed_password";

    let created_user = repo.create_user(username, password_hash).await.unwrap();
    let found_user = repo.get_user_by_id(created_user.id).await.unwrap().unwrap();

    assert_eq!(found_user.id, created_user.id, "User IDs should match");
    assert_eq!(found_user.username, username, "Usernames should match");

    // Test non-existent user
    let non_existent = repo.get_user_by_id(Uuid::new_v4()).await.unwrap();
    assert!(
        non_existent.is_none(),
        "Non-existent user should return None"
    );
}

#[tokio::test]
async fn test_update_user() {
    let (_container, repo) = setup().await.unwrap();

    let username = "test_update_user";
    let password_hash = "hashed_password";

    let created_user = repo.create_user(username, password_hash).await.unwrap();

    let new_password_hash = "new_password_hash";
    repo.update_password(created_user.id, new_password_hash)
        .await
        .unwrap();

    // Verify the update
    let updated_user = repo.get_user_by_id(created_user.id).await.unwrap().unwrap();
    assert_eq!(
        updated_user.password_hash, new_password_hash,
        "Password hash should be updated"
    );

    assert_eq!(
        updated_user.username, username,
        "Username should remain unchanged"
    );
}

#[tokio::test]
async fn test_delete_user() {
    let (_container, repo) = setup().await.unwrap();

    let username = "test_delete_user";
    let password_hash = "hashed_password";

    let created_user = repo.create_user(username, password_hash).await.unwrap();

    // Verify user exists
    assert!(
        repo.get_user_by_id(created_user.id)
            .await
            .unwrap()
            .is_some(),
        "User should exist before deletion"
    );

    // Delete user
    repo.delete_user(created_user.id).await.unwrap();

    // Verify user no longer exists
    assert!(
        repo.get_user_by_id(created_user.id)
            .await
            .unwrap()
            .is_none(),
        "User should not exist after deletion"
    );

    // Try to delete non-existent user
    repo.delete_user(Uuid::new_v4()).await.unwrap();
}

#[tokio::test]
async fn test_duplicate_username() {
    let (_container, repo) = setup().await.unwrap();

    let username = "duplicate_user";
    let password_hash1 = "hash123";
    let password_hash2 = "hash456";

    // First user should be created successfully
    let _user1 = repo.create_user(username, password_hash1).await.unwrap();

    // Second user with same username should fail
    let result = repo.create_user(username, password_hash2).await;
    assert!(
        result.is_err(),
        "Creating user with duplicate username should fail"
    );
}

#[tokio::test]
async fn test_username_case_sensitivity() -> Result<()> {
    let (_container, repo) = setup().await?;

    let username = "Test_User";
    let password_hash = "hash123";

    // Create the user and handle potential errors
    repo.create_user(username, password_hash).await?;

    // Wait briefly to ensure the transaction is complete
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Test with different casings
    let test_cases = vec!["test_user", "TEST_USER", "Test_User"];

    for test_username in test_cases {
        let found = repo.get_user_by_username(test_username).await?;
        assert!(
            found.is_some(),
            "User not found for username: {}",
            test_username
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_concurrent_updates() {
    let (_container, repo) = setup().await.unwrap();

    // Create initial user
    let username = "concurrent_user";
    let password_hash = "hash123";
    let user = repo.create_user(username, password_hash).await.unwrap();

    // Perform two concurrent updates
    let new_hash1 = "new_hash1";
    let new_hash2 = "new_hash2";

    let (result1, result2) = tokio::join!(
        repo.update_password(user.id, new_hash1),
        repo.update_password(user.id, new_hash2)
    );

    // Both updates should succeed
    assert!(result1.is_ok(), "First update should succeed");
    assert!(result2.is_ok(), "Second update should succeed");

    // Get final state
    let final_user = repo.get_user_by_id(user.id).await.unwrap().unwrap();

    // One of the updates should have won
    assert!(
        final_user.password_hash == new_hash1 || final_user.password_hash == new_hash2,
        "Final password hash should match one of the updates"
    );
}
