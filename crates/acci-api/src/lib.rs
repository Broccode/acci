//! ACCI API crate provides the HTTP API implementation for the ACCI system.
//!
//! This crate implements the REST API endpoints, middleware, and error handling.

pub mod error;
pub mod middleware;
pub mod routes;

use axum::Router;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// The address to bind the server to
    pub bind_address: SocketAddr,
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
