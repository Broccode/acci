use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use sqlx::PgPool;
use tempfile::TempDir;

use crate::helpers::db::setup_database;

#[tokio::test]
async fn test_user_management_flow() -> anyhow::Result<()> {
    // Setup test database
    let (_container, pool) = setup_database().await?;
    let database_url = pool.connect_options().to_string();

    // Test user creation
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("add")
        .arg("--email")
        .arg("test@example.com")
        .arg("--password")
        .arg("test123!")
        .arg("--full-name")
        .arg("Test User")
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Successfully created user"));

    // Test user listing
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("list")
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("test@example.com"))
        .stdout(predicate::str::contains("Test User"));

    // Test password reset
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("reset")
        .arg("--email")
        .arg("test@example.com")
        .arg("--password")
        .arg("newpass123!")
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Successfully reset password"));

    // Test user deletion
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("delete")
        .arg("--email")
        .arg("test@example.com")
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Successfully deleted user"));

    // Verify user is deleted
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("list")
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("No users found"));

    Ok(())
}

#[tokio::test]
async fn test_user_management_errors() -> anyhow::Result<()> {
    // Setup test database
    let (_container, pool) = setup_database().await?;
    let database_url = pool.connect_options().to_string();

    // Test invalid database URL
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg("postgres://invalid:5432/nonexistent")
        .arg("list")
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("Database connection failed"));

    // Test duplicate user creation
    let create_user = |email: &str| {
        AssertCommand::cargo_bin("acci-users")
            .expect("Failed to create acci-users command")
            .arg("--database-url")
            .arg(&database_url)
            .arg("add")
            .arg("--email")
            .arg(email)
            .arg("--password")
            .arg("test123!")
            .arg("--full-name")
            .arg("Test User")
            .assert()
    };

    // First creation should succeed
    create_user("duplicate@example.com").success();

    // Second creation should fail with specific error
    create_user("duplicate@example.com")
        .failure()
        .stderr(predicate::str::contains(
            "user with this email already exists",
        ));

    // Test deleting non-existent user
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("delete")
        .arg("--email")
        .arg("nonexistent@example.com")
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("User not found"));

    // Test resetting password for non-existent user
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("reset")
        .arg("--email")
        .arg("nonexistent@example.com")
        .arg("--password")
        .arg("newpass123!")
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("User not found"));

    Ok(())
}

#[tokio::test]
async fn test_user_management_validation() -> anyhow::Result<()> {
    // Setup test database
    let (_container, pool) = setup_database().await?;
    let database_url = pool.connect_options().to_string();

    // Test invalid email format
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("add")
        .arg("--email")
        .arg("invalid-email")
        .arg("--password")
        .arg("test123!")
        .arg("--full-name")
        .arg("Test User")
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("Invalid email format"));

    // Test weak password
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("add")
        .arg("--email")
        .arg("test@example.com")
        .arg("--password")
        .arg("weak")
        .arg("--full-name")
        .arg("Test User")
        .assert();

    assert.failure().stderr(predicate::str::contains(
        "Password must be at least 8 characters",
    ));

    // Test empty full name
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("add")
        .arg("--email")
        .arg("test@example.com")
        .arg("--password")
        .arg("test123!")
        .arg("--full-name")
        .arg("")
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("Full name cannot be empty"));

    // Test password reset validation
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("reset")
        .arg("--email")
        .arg("test@example.com")
        .arg("--password")
        .arg("weak")
        .assert();

    assert.failure().stderr(predicate::str::contains(
        "Password must be at least 8 characters",
    ));

    Ok(())
}

#[tokio::test]
async fn test_user_management_concurrent() -> anyhow::Result<()> {
    // Setup test database
    let (_container, pool) = setup_database().await?;
    let database_url = pool.connect_options().to_string();

    // Create multiple users concurrently
    let mut handles = vec![];
    for i in 0..5 {
        let database_url = database_url.clone();
        let handle = tokio::spawn(async move {
            AssertCommand::cargo_bin("acci-users")
                .expect("Failed to create acci-users command")
                .arg("--database-url")
                .arg(&database_url)
                .arg("add")
                .arg("--email")
                .arg(format!("user{}@example.com", i))
                .arg("--password")
                .arg("test123!")
                .arg("--full-name")
                .arg(format!("Test User {}", i))
                .assert()
                .success()
        });
        handles.push(handle);
    }

    // Wait for all creations to complete
    for handle in handles {
        handle.await??;
    }

    // Verify all users were created
    let assert = AssertCommand::cargo_bin("acci-users")?
        .arg("--database-url")
        .arg(&database_url)
        .arg("list")
        .assert();

    let output = assert.success().get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    for i in 0..5 {
        assert!(
            stdout.contains(&format!("user{}@example.com", i)),
            "User {} should be in the list",
            i
        );
    }

    Ok(())
}
