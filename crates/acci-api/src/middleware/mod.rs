//! API middleware implementations.

use tower_http::cors::{Any, CorsLayer};

/// Creates the default CORS middleware
pub fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_endpoint() -> &'static str {
        "Hello, World!"
    }

    #[tokio::test]
    async fn test_cors_middleware() {
        let app = Router::new()
            .route("/test", get(test_endpoint))
            .layer(cors());

        // Test preflight request
        let preflight = Request::builder()
            .method(Method::OPTIONS)
            .uri("/test")
            .header("Origin", "http://example.com")
            .header("Access-Control-Request-Method", "GET")
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(preflight).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .contains_key("access-control-allow-origin"));
        assert!(response
            .headers()
            .contains_key("access-control-allow-methods"));
        assert!(response
            .headers()
            .contains_key("access-control-allow-headers"));

        // Test actual request
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("Origin", "http://example.com")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
}

pub mod auth;

pub use axum::middleware::{from_fn, from_fn_with_state};
