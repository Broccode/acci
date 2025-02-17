use crate::helpers::db::setup_database;
use acci_core::error::Error;
use acci_db::repositories::user::UserRepository;
use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use regex::Regex;
use testcontainers::clients::Cli;

#[tokio::test]
async fn test_list_users_command() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // Run test_users list command
    let assert = AssertCommand::cargo_bin("test_users")?
        .arg("list")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Test Users:"))
        .stdout(predicate::str::contains("admin"))
        // Validate output format
        .stdout(predicate::str::is_match(r"Username: [a-zA-Z0-9_]+\n\s+Status: (Active|Inactive)\n\s+Email: [^\n]+\n").unwrap());

    Ok(())
}

#[tokio::test]
async fn test_reset_users_command() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // Run test_users reset command
    let assert = AssertCommand::cargo_bin("test_users")?
        .arg("reset")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Test users reset successfully"));

    // Verify all default test users exist
    let user_repo = pool.connect().await?;

    // Check admin user
    let admin_user = user_repo
        .find_by_username("admin")
        .await?
        .expect("Admin user should exist after reset");
    assert_eq!(admin_user.username, "admin");
    assert_eq!(admin_user.email, "admin@example.com");

    // Check test user
    let test_user = user_repo
        .find_by_username("test_user")
        .await?
        .expect("Test user should exist after reset");
    assert_eq!(test_user.username, "test_user");
    assert_eq!(test_user.email, "test@example.com");

    Ok(())
}

#[tokio::test]
async fn test_clean_users_command() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // First reset to ensure users exist
    AssertCommand::cargo_bin("test_users")?
        .arg("reset")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert()
        .success();

    // Then run clean command
    let assert = AssertCommand::cargo_bin("test_users")?
        .arg("clean")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Test users cleaned successfully"));

    // Verify no test users exist
    let user_repo = pool.connect().await?;

    let admin_user = user_repo.find_by_username("admin").await?;
    assert!(
        admin_user.is_none(),
        "Admin user should not exist after cleanup"
    );

    let test_user = user_repo.find_by_username("test_user").await?;
    assert!(
        test_user.is_none(),
        "Test user should not exist after cleanup"
    );

    Ok(())
}

#[tokio::test]
async fn test_reset_idempotency() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // Run reset command multiple times
    for _ in 0..3 {
        let assert = AssertCommand::cargo_bin("test_users")?
            .arg("reset")
            .env("DATABASE_URL", pool.connect_options().get_url())
            .assert();

        assert
            .success()
            .stdout(predicate::str::contains("Test users reset successfully"));
    }

    // Verify users are in correct state
    let user_repo = pool.connect().await?;
    let admin_user = user_repo
        .find_by_username("admin")
        .await?
        .expect("Admin user should exist after multiple resets");
    assert_eq!(admin_user.username, "admin");

    Ok(())
}

#[tokio::test]
async fn test_clean_idempotency() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // Run clean command multiple times
    for _ in 0..3 {
        let assert = AssertCommand::cargo_bin("test_users")?
            .arg("clean")
            .env("DATABASE_URL", pool.connect_options().get_url())
            .assert();

        assert
            .success()
            .stdout(predicate::str::contains("Test users cleaned successfully"));
    }

    // Verify no users exist
    let user_repo = pool.connect().await?;
    let admin_user = user_repo.find_by_username("admin").await?;
    assert!(
        admin_user.is_none(),
        "Admin user should not exist after multiple cleanups"
    );

    Ok(())
}

#[tokio::test]
async fn test_invalid_command() {
    AssertCommand::cargo_bin("test_users")
        .unwrap()
        .arg("invalid_command")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error: unrecognized subcommand"));
}

#[tokio::test]
async fn test_missing_database_url() {
    AssertCommand::cargo_bin("test_users")
        .unwrap()
        .arg("list")
        .env_remove("DATABASE_URL")
        .assert()
        .failure()
        .stderr(predicate::str::contains("DATABASE_URL not set"));
}

#[tokio::test]
async fn test_invalid_database_url() {
    AssertCommand::cargo_bin("test_users")
        .unwrap()
        .arg("list")
        .env("DATABASE_URL", "invalid-url")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid connection URL"));
}

#[tokio::test]
async fn test_list_output_format() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // First reset to ensure users exist
    AssertCommand::cargo_bin("test_users")?
        .arg("reset")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert()
        .success();

    // Run list command and capture output
    let output = AssertCommand::cargo_bin("test_users")?
        .arg("list")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Define expected format using regex
    let user_format = Regex::new(
        r"Username: [a-zA-Z0-9_]+\n\s+Status: (Active|Inactive)\n\s+Email: [a-zA-Z0-9.@]+\n\s+Created: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
    )?;

    // Find all user entries in output
    let user_entries: Vec<_> = user_format.find_iter(&stdout).collect();

    // Should have at least two users (admin and test_user)
    assert!(
        user_entries.len() >= 2,
        "Should list at least admin and test_user"
    );

    Ok(())
}
