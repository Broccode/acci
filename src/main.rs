//! Main entry point for the ACCI application.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    tracing::info!("Starting ACCI application...");
    
    Ok(())
} 