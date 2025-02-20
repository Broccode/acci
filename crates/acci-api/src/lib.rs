#![allow(clippy::large_stack_arrays, clippy::redundant_pub_crate)]

//! ACCI API crate provides the HTTP API implementation for the ACCI system.
//!
//! This crate implements the REST API endpoints, middleware, and error handling.

pub mod error;
pub mod middleware;
pub mod routes;

use acci_auth::{providers::basic::BasicAuthProvider, tasks::session_cleanup::run_session_cleanup};
use acci_core::auth::AuthConfig;
use acci_db::{
    repositories::{PgSessionRepository, PgUserRepository},
    DbConfig,
};
use axum::{
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use sqlx::postgres::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::middleware::auth::validate_session;

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// The address to bind to
    pub bind_addr: SocketAddr,
    /// The database configuration
    pub db_config: DbConfig,
    /// The authentication configuration
    pub auth_config: AuthConfig,
    /// The database connection pool
    pub db_pool: PgPool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
            db_config: DbConfig::default(),
            auth_config: AuthConfig::default(),
            db_pool: PgPool::connect_lazy("postgres://postgres:postgres@localhost:5432/postgres")
                .expect("Failed to create database pool"),
        }
    }
}

/// API server state
#[derive(Debug, Clone)]
pub struct ApiState {
    /// The database connection pool
    pub db_pool: PgPool,
    /// The authentication configuration
    pub auth_config: AuthConfig,
}

impl Default for ApiState {
    fn default() -> Self {
        Self {
            db_pool: PgPool::connect_lazy("postgres://postgres:postgres@localhost:5432/postgres")
                .expect("Failed to create database pool"),
            auth_config: AuthConfig::default(),
        }
    }
}

/// Starts the API server
///
/// # Arguments
///
/// * `config` - The server configuration
///
/// # Returns
///
/// A result indicating success or failure
///
/// # Errors
///
/// Returns an error if:
/// * The server fails to bind to the address
/// * The database connection fails
/// * The server fails to start
pub async fn start_server(config: ApiConfig) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting API server on {}", config.bind_addr);

    let user_repo = Arc::new(PgUserRepository::new(config.db_pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(config.db_pool));

    let auth_provider = Arc::new(BasicAuthProvider::new(
        user_repo,
        session_repo,
        config.auth_config,
    ));

    let app = Router::new()
        .route("/health", get(routes::health::health_check))
        .route("/auth/login", post(routes::auth::login))
        .route(
            "/auth/validate",
            get(routes::auth::validate)
                .layer(from_fn_with_state(auth_provider.clone(), validate_session)),
        )
        .with_state(auth_provider);

    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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
        .merge(routes::health::create_health_routes())
        .merge(routes::auth::create_auth_routes(Arc::new(
            BasicAuthProvider::new(
                Arc::new(PgUserRepository::new(config.db_pool.clone())),
                Arc::new(PgSessionRepository::new(config.db_pool)),
                config.auth_config,
            ),
        )))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    // Use a more compact logging approach
    tracing::info!(server.address = %config.bind_addr);

    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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

    let user_repo = Arc::new(PgUserRepository::new(config.db_pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(config.db_pool.clone()));
    let auth_provider = Arc::new(BasicAuthProvider::new(
        user_repo,
        session_repo.clone(),
        AuthConfig::default(),
    ));

    // Start session cleanup task
    let cleanup_session_repo = session_repo.clone();
    tokio::spawn(async move {
        run_session_cleanup(cleanup_session_repo, 3600).await;
    });

    // Create protected routes that require authentication
    let protected_routes = Router::new()
        // Add protected routes here
        .route_layer(from_fn_with_state(
            auth_provider.clone(),
            middleware::auth::validate_session,
        ));

    // Combine all routes
    let app = Router::new()
        .merge(routes::health::create_health_routes())
        .merge(routes::auth::create_auth_routes(auth_provider))
        .merge(protected_routes)
        .layer(CorsLayer::permissive());

    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[allow(dead_code)]
/// Waits for a shutdown signal (Ctrl+C).
///
/// # Panics
/// Panics if the Ctrl+C handler cannot be installed.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            info!("Received terminate signal");
        },
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
            bind_addr: addr,
            db_config: DbConfig::default(),
            auth_config: AuthConfig::default(),
            db_pool: pool,
        };

        assert_eq!(config.bind_addr.port(), 8080);
        assert_eq!(
            config.bind_addr.ip(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
    }

    #[tokio::test]
    async fn test_router_setup() {
        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
        let pool = PgPool::connect_lazy("postgres://postgres:postgres@localhost:5432/test")
            .expect("Failed to create database pool");
        let config = ApiConfig {
            bind_addr: addr,
            db_config: DbConfig::default(),
            auth_config: AuthConfig::default(),
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

/// Runs the API server with the given authentication configuration
///
/// # Arguments
///
/// * `config` - The authentication configuration
///
/// # Errors
///
/// Returns an error if:
/// * The server fails to bind to the address
/// * The database connection fails
/// * The server fails to start
pub async fn run_server(config: AuthConfig) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Starting server on {}", addr);

    let pool = PgPool::connect("postgres://postgres:postgres@localhost:5432/postgres").await?;

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));

    let auth_provider = Arc::new(BasicAuthProvider::new(
        user_repo.clone(),
        session_repo.clone(),
        config,
    ));

    // Create router
    let app = Router::new()
        .merge(routes::health::create_health_routes())
        .merge(routes::auth::create_auth_routes(auth_provider))
        .layer(CorsLayer::permissive());

    // Start session cleanup task
    let cleanup_session_repo = session_repo.clone();
    tokio::spawn(async move {
        run_session_cleanup(cleanup_session_repo, 3600).await;
    });

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Configuration for the API server
#[derive(Debug, Clone)]
pub struct Config {
    /// The database configuration
    pub db_config: DbConfig,
    /// The database connection pool
    pub db_pool: PgPool,
    /// The address to bind the server to
    pub bind_addr: SocketAddr,
}
