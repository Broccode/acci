//! CLI tool for managing test users in the ACCI system.
//!
//! This tool provides commands to list, reset, and clean up test users in the database.
//! It supports development and test environments.

use acci_core::auth::TestUserConfig;
use acci_db::{create_pool, repositories::user::UserRepository, DbConfig, Environment};
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Database URL
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut config = DbConfig::default();
    if let Some(url) = args.database_url {
        config.url = url;
    }
    config.environment = Environment::Development;

    let pool = create_pool(config).await?;
    let repo = acci_db::repositories::user::PgUserRepository::new(pool);
    let test_config = TestUserConfig::default();

    match args.command {
        Commands::List => {
            println!("Configured test users:");
            for user in test_config.users {
                let exists = repo.get_by_email(&user.email).await?.is_some();
                println!(
                    "- {} ({}) [{}]",
                    user.email,
                    user.role,
                    if exists { "exists" } else { "missing" }
                );
            }
        },
        Commands::Reset => {
            println!("Resetting test users...");
            // First clean up existing test users
            for user in &test_config.users {
                if let Some(existing) = repo.get_by_email(&user.email).await? {
                    repo.delete(existing.id).await?;
                }
            }
            // Then create fresh test users
            for user in test_config.users {
                repo.create(acci_db::repositories::user::CreateUser {
                    email: user.email.clone(),
                    password_hash: acci_core::auth::hash_password(&user.password)?,
                    full_name: user.full_name,
                })
                .await?;
                println!("Created test user: {}", user.email);
            }
            println!("Test users reset successfully!");
        },
        Commands::Clean => {
            println!("Cleaning up test users...");
            for user in test_config.users {
                if let Some(existing) = repo.get_by_email(&user.email).await? {
                    repo.delete(existing.id).await?;
                    println!("Deleted test user: {}", user.email);
                }
            }
            println!("Test users cleaned up successfully!");
        },
    }

    Ok(())
}
