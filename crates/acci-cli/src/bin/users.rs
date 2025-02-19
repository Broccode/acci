//! Command line interface for user management.
//!
//! This binary provides commands for creating, listing, and managing users
//! in the ACCI system.

use acci_core::{auth::hash_password, error::Error};
use acci_db::repositories::{
    session::PgSessionRepository,
    user::{PgUserRepository, UserRepository},
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::info;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Database URL
    #[arg(short, long, env = "DATABASE_URL")]
    database_url: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new user
    Add {
        /// User's username
        #[arg(short, long)]
        username: String,

        /// User's password
        #[arg(short, long)]
        password: String,
    },
    /// List all users
    List,
    /// Delete a user
    Delete {
        /// User's username
        #[arg(short, long)]
        username: String,
    },
    /// Reset a user's password
    Reset {
        /// User's username
        #[arg(short, long)]
        username: String,

        /// New password
        #[arg(short, long)]
        password: String,
    },
}

#[tokio::main]
#[allow(clippy::large_stack_arrays)]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Initialize database connection
    let pool = PgPool::connect(&cli.database_url).await?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let _session_repo = Arc::new(PgSessionRepository::new(pool));

    match cli.command {
        Commands::Add { username, password } => {
            let hash = hash_password(&password)?;
            let user = user_repo
                .create_user(&username, &hash)
                .await
                .map_err(|e| Error::internal(format!("Failed to create user: {e}")))?;

            info!("Created user: {}", user.username);
            Ok(())
        },
        Commands::List => {
            println!("Listing users is not implemented yet.");
            Ok(())
        },
        Commands::Delete { username } => {
            let user = user_repo
                .get_user_by_username(&username)
                .await?
                .ok_or_else(|| {
                    Error::not_found(format!("User with username {username} not found"))
                })?;

            user_repo.delete_user(user.id).await?;
            info!("Deleted user: {}", username);
            Ok(())
        },
        Commands::Reset { username, password } => {
            let user = user_repo
                .get_user_by_username(&username)
                .await?
                .ok_or_else(|| {
                    Error::not_found(format!("User with username {username} not found"))
                })?;
            let hash = hash_password(&password)?;
            user_repo.update_password(user.id, &hash).await?;
            info!("Reset password for user: {}", username);
            Ok(())
        },
    }
}
