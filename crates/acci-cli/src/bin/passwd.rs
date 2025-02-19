#![allow(clippy::large_stack_arrays, clippy::disallowed_methods)]

//! ACCI Password Hashing Tool
//!
//! A secure command-line tool for generating password hashes using the Argon2id algorithm.
//! Supports both direct password input and stdin for secure password handling.
use acci_core::auth::hash_password;
use anyhow::Result;
use clap::Parser;
use serde_json::json;
use std::io::{self, Read};
use tracing::error;
use validator::Validate;

#[derive(Debug, Validate)]
struct PasswordInput {
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    password: String,
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "ACCI Password Hashing Tool",
    long_about = "A secure password hashing tool that uses the Argon2id algorithm. \
    This tool is designed to generate cryptographically secure password hashes \
    that can be safely stored in a database. The tool never stores the original \
    password and uses a unique salt for each hash."
)]
struct Cli {
    /// Read password from stdin instead of argument.
    /// This is useful for scripts and prevents the password from appearing in shell history.
    #[arg(short, long)]
    stdin: bool,

    /// Output format (text/json).
    /// Use 'text' for simple hash output or 'json' for detailed information including the algorithm used.
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Password to hash (if not using stdin).
    /// Note: For security, prefer using --stdin in scripts to avoid the password appearing in shell history.
    #[arg(short, long)]
    password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Get password from stdin or argument
    let password = if cli.stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input).map_err(|e| {
            error!("Failed to read from stdin: {}", e);
            anyhow::anyhow!("Failed to read password from stdin: {}", e)
        })?;
        input.trim().to_string()
    } else {
        cli.password.ok_or_else(|| {
            error!("No password provided");
            anyhow::anyhow!("Password must be provided either via --password or --stdin")
        })?
    };

    // Validate password
    let input = PasswordInput {
        password: password.clone(),
    };
    if let Err(e) = input.validate() {
        error!("Password validation failed: {}", e);
        return Err(anyhow::anyhow!("Password validation error: {}", e));
    }

    // Generate hash
    let hash = match hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password: {}", e);
            return Err(anyhow::anyhow!("Failed to generate password hash: {}", e));
        },
    };

    // Output result in requested format
    match cli.format.as_str() {
        "json" => {
            println!(
                "{}",
                json!({
                    "hash": hash,
                    "algorithm": "argon2id",
                    "version": "19",
                    "parameters": {
                        "m_cost": 4096,  // Memory cost
                        "t_cost": 3,     // Time cost
                        "p_cost": 1,     // Parallelism
                        "output_len": 32, // Hash length in bytes
                    }
                })
            );
        },
        _ => {
            println!("{hash}");
        },
    }

    Ok(())
}
