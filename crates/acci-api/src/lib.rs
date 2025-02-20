#![allow(clippy::large_stack_arrays, clippy::redundant_pub_crate)]

//! ACCI API crate provides the HTTP API implementation for the ACCI system.
//!
//! This crate implements the REST API endpoints, middleware, and error handling.

pub mod error;
pub mod middleware;
pub mod routes;

use acci_auth::tasks::session_cleanup;
use acci_db::sqlx::PgPool;
use axum::{middleware::from_fn_with_state, Router};
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

/// Starts the API server.
///
/// # Errors
/// Returns an error if:
/// - Server fails to bind to the specified address
/// - Router setup fails
/// - Database connection fails
pub async fn start(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting API server on {}", config.bind_addr);

    // Create the auth router and get session repository
    let (auth_router, session_repo, auth_provider) =
        routes::auth::create_auth_router(config.db_config.clone()).await;

    // Start session cleanup task
    let cleanup_session_repo = session_repo.clone();
    tokio::spawn(async move {
        session_cleanup::run_session_cleanup(cleanup_session_repo, 3600).await;
    });

    // Create protected routes that require authentication
    let protected_routes = Router::new()
        // Add protected routes here
        .route_layer(from_fn_with_state(
            auth_provider,
            middleware::auth::validate_session,
        ));

    // Combine all routes
    let app = Router::new()
        .merge(routes::health::router())
        .merge(auth_router)
        .merge(protected_routes)
        .layer(CorsLayer::permissive());

    let listener = TcpListener::bind(&config.bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[allow(dead_code)]
/// Waits for a shutdown signal (Ctrl+C).
///
/// # Panics
/// Panics if the Ctrl+C handler cannot be installed.
async fn shutdown_signal() {
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
        }
    }
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
