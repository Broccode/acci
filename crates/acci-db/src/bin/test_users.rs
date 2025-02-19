//! CLI tool for managing test users in the ACCI system.
//!
//! This tool provides commands to list, reset, and clean up test users in the database.
//! It supports development and test environments.

#![allow(clippy::large_stack_arrays)]

use acci_core::auth::TestUserConfig;
use acci_db::{create_pool, repositories::user::UserRepository, DbConfig, Environment};
use anyhow::{Error, Result};
use clap::{Parser, Subcommand};
use std::env;

/// Command line arguments for the test users binary.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Database URL (overrides `DATABASE_URL` environment variable)
    #[arg(short, long)]
    database_url: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all test users
    List,
    /// Reset test users to default configuration
    Reset,
    /// Delete all test users
    Clean,
}

#[allow(dead_code)]
#[derive(Debug)]
struct TestUser {
    username: String,
    password: String,
    password_hash: String,
    role: String,
}

#[allow(dead_code)]
impl TestUser {
    /// Creates a new test user.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Password hashing fails
    /// - Password validation fails
    fn new(username: String, password: &str, role: String) -> Result<Self, Error> {
        let password_hash = acci_core::auth::hash_password(password)?;
        Ok(Self {
            username,
            password: password.to_string(),
            password_hash,
            role,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config = DbConfig {
        url: args
            .database_url
            .or_else(|| env::var("DATABASE_URL").ok())
            .unwrap_or_else(|| "postgres://acci:development_only@localhost:5432/acci".to_string()),
        environment: Environment::Development,
        ..Default::default()
    };

    let pool = create_pool(config).await?;
    let repo = acci_db::repositories::user::PgUserRepository::new(pool);
    let test_config = TestUserConfig::default();

    match args.command {
        Commands::List => {
            println!("Configured test users:");
            for user in test_config.users {
                let exists = repo.get_user_by_username(&user.username).await?.is_some();
                let status = if exists { "exists" } else { "missing" };
                println!(
                    "- {username} ({role}) [{status}]",
                    username = user.username,
                    role = user.role,
                    status = status
                );
            }
        },
        Commands::Reset => {
            println!("Resetting test users...");
            // First clean up existing test users
            for user in &test_config.users {
                if let Some(existing) = repo.get_user_by_username(&user.username).await? {
                    repo.delete_user(existing.id).await?;
                }
            }
            // Then create fresh test users
            for user in test_config.users {
                repo.create_user(
                    &user.username,
                    &acci_core::auth::hash_password(&user.password)?,
                )
                .await?;
                println!("Created test user: {username}", username = user.username);
            }
            println!("Test users reset successfully!");
        },
        Commands::Clean => {
            println!("Cleaning up test users...");
            for user in test_config.users {
                if let Some(existing) = repo.get_user_by_username(&user.username).await? {
                    repo.delete_user(existing.id).await?;
                    println!("Deleted test user: {username}", username = user.username);
                }
            }
            println!("Test users cleaned up successfully!");
        },
    }

    Ok(())
}
