use std::sync::Arc;

use acci_auth::BasicAuthProvider;
use acci_core::{auth::AuthProvider, error::Error};
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use tracing::instrument;

/// Validates the session token in the request
///
/// # Arguments
///
/// * `auth_provider` - The authentication provider
/// * `req` - The incoming request
/// * `next` - The next middleware in the chain
///
/// # Returns
///
/// The response from the next middleware or an error
#[instrument(skip_all)]
pub async fn validate_session(
    State(auth_provider): State<Arc<BasicAuthProvider>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();

    match auth_provider.validate_token(token).await {
        Ok(_) => Ok(next.run(req).await),
        Err(e) => match e {
            Error::NotFound(_) => Err(StatusCode::NOT_FOUND),
            Error::InvalidToken(_) => Err(StatusCode::UNAUTHORIZED),
            _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
        },
    }
}
