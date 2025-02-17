use acci_core::{auth::hash_password, error::Error};
use acci_db::repositories::{
    session::PgSessionRepository,
    user::{CreateUser, PgUserRepository, UpdateUser, UserRepository},
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
        /// User's email address
        #[arg(short, long)]
        email: String,

        /// User's password
        #[arg(short, long)]
        password: String,

        /// User's full name
        #[arg(short, long)]
        full_name: String,
    },
    /// List all users
    List,
    /// Delete a user
    Delete {
        /// User's email address
        #[arg(short, long)]
        email: String,
    },
    /// Reset a user's password
    Reset {
        /// User's email address
        #[arg(short, long)]
        email: String,

        /// New password
        #[arg(short, long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Initialize database connection
    let pool = PgPool::connect(&cli.database_url).await?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));

    match cli.command {
        Commands::Add {
            email,
            password,
            full_name,
        } => {
            let hash = hash_password(&password)?;
            let user = user_repo
                .create(CreateUser {
                    email: email.clone(),
                    password_hash: hash,
                    full_name,
                })
                .await
                .map_err(|e| Error::internal(format!("Failed to create user: {e}")))?;

            info!("Created user: {}", user.email);
            Ok(())
        },
        Commands::List => {
            let users = user_repo.list().await?;
            for user in users {
                println!("Email: {}, Name: {}", user.email, user.full_name);
            }
            Ok(())
        },
        Commands::Delete { email } => {
            let user = user_repo
                .get_by_email(&email)
                .await?
                .ok_or_else(|| Error::not_found(format!("User with email {email} not found")))?;

            user_repo.delete(user.id).await?;
            info!("Deleted user: {}", email);
            Ok(())
        },
        Commands::Reset { email, password } => {
            let user = user_repo
                .get_by_email(&email)
                .await?
                .ok_or_else(|| Error::not_found(format!("User with email {email} not found")))?;
            let hash = hash_password(&password)?;
            user_repo
                .update(
                    user.id,
                    UpdateUser {
                        password_hash: Some(hash),
                        email: None,
                        full_name: None,
                    },
                )
                .await?;
            info!("Reset password for user: {}", email);
            Ok(())
        },
    }
}
