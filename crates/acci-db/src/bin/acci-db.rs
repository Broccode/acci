//! CLI tool for managing the ACCI database.
//! Provides commands for database migrations and maintenance.

use acci_db::{create_pool, run_migrations, DbConfig};
use anyhow::Result;
use clap::{Parser, Subcommand};

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
    let config = DbConfig::default();
    let pool = create_pool(config).await?;

    match cli.command {
        // Start of Selection
        Commands::Reset => {
            println!("Reset command is not implemented.");
        },
        Commands::Migrate => {
            run_migrations(&pool).await?;
        },
    }

    Ok(())
}
