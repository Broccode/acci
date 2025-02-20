//! API routes module.

use axum::{
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use acci_auth::providers::basic::BasicAuthProvider;

use crate::middleware::auth::validate_session;

pub mod auth;
pub mod health;

/// Creates the API router with all routes
pub fn create_router(auth_provider: Arc<BasicAuthProvider>) -> Router {
    Router::new()
        .route("/health", get(health::health_check))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout/:session_id", post(auth::logout))
        .route(
            "/auth/validate",
            get(auth::validate).layer(from_fn_with_state(auth_provider.clone(), validate_session)),
        )
        .with_state(auth_provider)
}
