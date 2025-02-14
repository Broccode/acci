//! CLI tool for managing the ACCI database.
//! Provides commands for database migrations and maintenance.

use acci_db::{create_pool, run_migrations, DbConfig, Environment};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::env;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Reset the database (drop and recreate)
    Reset,
    /// Run database migrations
    Migrate,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Get database URL from environment variable or use default
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());

    let config = DbConfig {
        url: database_url,
        ..Default::default()
    };

    let pool = create_pool(config).await?;

    match cli.command {
        Commands::Reset => {
            println!("Reset command is not implemented.");
        },
        Commands::Migrate => {
            println!("Running migrations...");
            run_migrations(&pool).await?;
            println!("Migrations completed successfully.");
        },
    }

    Ok(())
}
