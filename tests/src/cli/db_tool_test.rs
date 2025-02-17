use crate::helpers::db::setup_database;
use acci_core::error::Error;
use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use regex::Regex;
use std::process::Command;
use testcontainers::clients::Cli;

#[tokio::test]
async fn test_db_info_command() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // Run db info command with assert_cmd
    let assert = AssertCommand::cargo_bin("acci-db")?
        .arg("info")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Database Information:"))
        .stdout(predicate::str::contains("Version:"))
        .stdout(predicate::str::contains("Connection Pool:"))
        // Validate version format (e.g., PostgreSQL 14.x)
        .stdout(predicate::str::is_match(r"Version: PostgreSQL \d+\.\d+").unwrap());

    Ok(())
}

#[tokio::test]
async fn test_db_status_command() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // Run db status command with assert_cmd
    let assert = AssertCommand::cargo_bin("acci-db")?
        .arg("status")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Database Status:"))
        .stdout(predicate::str::contains("Connected: true"))
        // Validate active connections format (number)
        .stdout(predicate::str::is_match(r"Active Connections: \d+").unwrap());

    Ok(())
}

#[tokio::test]
async fn test_db_schema_command() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // Run db schema command with assert_cmd
    let assert = AssertCommand::cargo_bin("acci-db")?
        .arg("schema")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Schema Information:"))
        .stdout(predicate::str::contains("Tables:"))
        .stdout(predicate::str::contains("users"))
        .stdout(predicate::str::contains("sessions"))
        // Ensure output is properly formatted
        .stdout(predicate::str::is_match(r"Table: [a-z_]+\n(\s+Column: [a-z_]+ \([A-Z_]+\)\n)+").unwrap());

    Ok(())
}

#[tokio::test]
async fn test_db_migrations_command() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // Run db migrations command with assert_cmd
    let assert = AssertCommand::cargo_bin("acci-db")?
        .arg("migrations")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("Migration Status:"))
        .stdout(predicate::str::contains("Applied Migrations:"))
        .stdout(predicate::str::contains("Pending Migrations:"))
        // Validate migration format (timestamp_name)
        .stdout(predicate::str::is_match(r"\d{14}_[a-z_]+").unwrap());

    Ok(())
}

#[tokio::test]
async fn test_db_connection_errors() {
    // Test invalid database URL format
    AssertCommand::cargo_bin("acci-db")
        .unwrap()
        .arg("info")
        .env("DATABASE_URL", "not-a-url")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid connection URL"));

    // Test non-existent database
    AssertCommand::cargo_bin("acci-db")
        .unwrap()
        .arg("info")
        .env("DATABASE_URL", "postgres://localhost:5432/nonexistent")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "database \"nonexistent\" does not exist",
        ));

    // Test authentication failure
    AssertCommand::cargo_bin("acci-db")
        .unwrap()
        .arg("info")
        .env(
            "DATABASE_URL",
            "postgres://wrong:wrong@localhost:5432/postgres",
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("authentication failed"));

    // Test missing DATABASE_URL
    AssertCommand::cargo_bin("acci-db")
        .unwrap()
        .arg("info")
        .env_remove("DATABASE_URL")
        .assert()
        .failure()
        .stderr(predicate::str::contains("DATABASE_URL not set"));
}

#[tokio::test]
async fn test_db_invalid_commands() {
    // Test invalid subcommand
    AssertCommand::cargo_bin("acci-db")
        .unwrap()
        .arg("invalid_command")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error: unrecognized subcommand"));

    // Test missing subcommand
    AssertCommand::cargo_bin("acci-db")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("error: a subcommand is required"));

    // Test invalid arguments
    AssertCommand::cargo_bin("acci-db")
        .unwrap()
        .args(["info", "--invalid-flag"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error: unexpected argument"));
}

#[tokio::test]
async fn test_db_migration_errors() -> Result<(), Error> {
    // Setup test environment with invalid migration
    let (_container, pool) = setup_database().await?;

    // Create invalid migration file
    std::fs::write(
        "migrations/99999999999999_invalid.sql",
        "THIS IS NOT VALID SQL;",
    )?;

    // Run migrations command
    let assert = AssertCommand::cargo_bin("acci-db")?
        .arg("migrations")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .assert();

    assert
        .failure()
        .stderr(predicate::str::contains("migration error"))
        .stderr(predicate::str::contains("syntax error"));

    // Cleanup
    std::fs::remove_file("migrations/99999999999999_invalid.sql")?;

    Ok(())
}

#[tokio::test]
async fn test_db_output_format() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database().await?;

    // Run info command and capture output
    let output = AssertCommand::cargo_bin("acci-db")?
        .arg("info")
        .env("DATABASE_URL", pool.connect_options().get_url())
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Define expected format using regex
    let info_format = Regex::new(
        r"Database Information:
Version: PostgreSQL \d+\.\d+
Connection Pool:
  Max Size: \d+
  Idle Timeout: \d+s
  Connection Timeout: \d+s",
    )?;

    assert!(
        info_format.is_match(&stdout),
        "Output format does not match expected pattern"
    );

    Ok(())
}
