use crate::helpers::auth;
use acci_core::error::Error;
use acci_db::{
    create_pool,
    repositories::user::{PgUserRepository, UserRepository},
    run_migrations,
    sqlx::{self, PgPool},
    DbConfig, Environment,
};
use anyhow::Result;
use testcontainers_modules::{
    postgres,
    testcontainers::{runners::AsyncRunner, ImageExt},
};
use uuid::Uuid;

async fn setup() -> Result<(Box<dyn std::any::Any>, PgUserRepository)> {
    let container = postgres::Postgres::default()
        .with_tag("16-alpine")
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_DB", "postgres")
        .start()
        .await?;
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

    // Enable required extensions in public schema first
    sqlx::query("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\" SCHEMA public")
        .execute(&pool)
        .await?;
    sqlx::query("CREATE EXTENSION IF NOT EXISTS \"citext\" SCHEMA public")
        .execute(&pool)
        .await?;

    // Verify that citext extension is enabled by trying to use it
    sqlx::query("SELECT 'TEST'::citext = 'test'::citext AS is_equal")
        .fetch_one(&pool)
        .await?;

    // Create schema if not exists
    sqlx::query("CREATE SCHEMA IF NOT EXISTS acci")
        .execute(&pool)
        .await?;

    // Set search path to include both schemas
    sqlx::query("SET search_path TO acci, public")
        .execute(&pool)
        .await?;

    // Set environment to test mode
    sqlx::query("SET app.environment = 'test'")
        .execute(&pool)
        .await?;

    // Run migrations
    run_migrations(&pool).await?;

    // Create repository
    let repo = PgUserRepository::new(pool);
    Ok((Box::new(container), repo))
}

async fn cleanup_database(pool: &PgPool) -> Result<(), Error> {
    sqlx::query("DELETE FROM acci.users")
        .execute(pool)
        .await
        .map_err(|e| Error::Database(e))?;
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
    assert!(created.is_active, "New user should be active by default");
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
    let password_hash =
        auth::hash_password("Test123!@#").expect("Password hashing should succeed in test setup");

    let created_user = repo.create_user(username, &password_hash).await.unwrap();

    let new_password_hash = auth::hash_password("NewTest123!@#")
        .expect("Password hashing should succeed in test setup");
    repo.update_password(created_user.id, &new_password_hash)
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
async fn test_username_case_sensitivity() {
    let (_container, repo) = setup().await.unwrap();

    // Clean up the database first
    cleanup_database(&repo.pool).await.unwrap();

    let username = "test_user";
    let password_hash =
        auth::hash_password("Test123!@#").expect("Password hashing should succeed in test setup");

    // Create initial user
    let created_user = repo.create_user(username, &password_hash).await.unwrap();

    // Try to create user with same username but different case
    let uppercase_username = username.to_uppercase();
    let result = repo.create_user(&uppercase_username, &password_hash).await;

    // Verify that the creation fails with the expected error message
    match result {
        Err(Error::Validation(msg)) => {
            assert!(
                msg.contains("already taken"),
                "Error message should indicate that the username is already taken"
            );
            assert!(
                msg.contains("case-insensitive"),
                "Error message should mention case-insensitivity"
            );
        },
        other => panic!(
            "Expected Validation error, got {:?}",
            other.map_err(|e| e.to_string())
        ),
    }

    // Verify that we can find the user with case-insensitive search
    let found_user = repo
        .get_user_by_username(&uppercase_username)
        .await
        .unwrap();

    // Add debug output
    println!("Created user: {:?}", created_user);
    println!("Found user: {:?}", found_user);
    println!("Uppercase username: {}", uppercase_username);

    assert!(
        found_user.is_some(),
        "Should find user with case-insensitive search"
    );
    assert_eq!(
        found_user.unwrap().id,
        created_user.id,
        "Should find the same user regardless of case"
    );

    // Clean up
    repo.delete_user(created_user.id).await.unwrap();
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
