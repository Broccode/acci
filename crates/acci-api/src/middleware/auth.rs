use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::TypedHeader;
use headers::{authorization::Bearer, Authorization};
use std::sync::Arc;

use acci_auth::providers::basic::BasicAuthProvider;
use acci_core::{auth::AuthProvider, error::Error};
use tracing::{error, info};

/// Validates the session token in the Authorization header.
///
/// This middleware extracts the Bearer token from the Authorization header,
/// validates it using the auth provider, and ensures the session is still valid.
///
/// # Errors
///
/// Returns a 401 Unauthorized response if:
/// - No Authorization header is present
/// - The token is invalid
/// - The session has expired
/// - The session is not found
pub async fn validate_session(
    State(auth_provider): State<Arc<BasicAuthProvider>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = auth.token();

    match auth_provider.validate_token(token.to_string()).await {
        Ok(session) => {
            // Add session info to request extensions
            request.extensions_mut().insert(session);
            info!("Session validated successfully");
            Ok(next.run(request).await)
        },
        Err(e) => {
            error!("Session validation failed: {}", e);
            match e {
                Error::InvalidToken(_) | Error::NotFound(_) => Err(StatusCode::UNAUTHORIZED),
                _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        },
    }
}
