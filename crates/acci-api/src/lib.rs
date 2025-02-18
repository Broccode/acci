//! ACCI API crate provides the HTTP API implementation for the ACCI system.
//!
//! This crate implements the REST API endpoints, middleware, and error handling.

pub mod error;
pub mod middleware;
pub mod routes;

use acci_db::sqlx::PgPool;
use axum::Router;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// The address to bind the server to
    pub bind_address: SocketAddr,
    /// Database connection pool
    pub db_pool: PgPool,
}

/// Configuration for the API server
#[derive(Debug, Clone)]
pub struct Config {
    /// The address to bind to
    pub bind_addr: SocketAddr,
    /// The database configuration
    pub db_config: acci_db::DbConfig,
}

/// Starts the API server with the given configuration
///
/// # Errors
///
/// This function will return an error if:
/// - The server fails to bind to the specified address
/// - The server encounters an error while running
pub async fn serve(config: ApiConfig) -> anyhow::Result<()> {
    let app = Router::new()
        .merge(routes::health::router())
        .merge(routes::auth::router(config.db_pool))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::cors());

    // Use a more compact logging approach
    #[allow(clippy::large_stack_arrays)]
    {
        tracing::info!(server.address = %config.bind_address);
    }

    let listener = TcpListener::bind(config.bind_address).await?;
    axum::serve(listener, app).await.map_err(Into::into)
}

/// Start the API server
pub async fn start(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting API server on {}", config.bind_addr);

    let app = Router::new()
        .merge(routes::health::router())
        .merge(routes::auth::create_auth_router(config.db_config).await)
        .layer(CorsLayer::permissive());

    let listener = TcpListener::bind(&config.bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("Shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_api_config() {
        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8080);
        let pool = PgPool::connect_lazy("postgres://postgres:postgres@localhost:5432/test")
            .expect("Failed to create database pool");
        let config = ApiConfig {
            bind_address: addr,
            db_pool: pool,
        };

        assert_eq!(config.bind_address.port(), 8080);
        assert_eq!(
            config.bind_address.ip(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
    }

    #[tokio::test]
    async fn test_router_setup() {
        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
        let pool = PgPool::connect_lazy("postgres://postgres:postgres@localhost:5432/test")
            .expect("Failed to create database pool");
        let config = ApiConfig {
            bind_address: addr,
            db_pool: pool,
        };

        // Start server in background
        let server = tokio::spawn(serve(config));

        // Give it a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Cleanup
        server.abort();
    }
}
