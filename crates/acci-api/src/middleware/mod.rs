//! API middleware implementations.

use tower_http::cors::{Any, CorsLayer};

/// Creates the default CORS middleware
pub fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any)
}
