use acci_api::{middleware, routes::health};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use tower::ServiceExt;
use tower_http::trace::TraceLayer;

#[allow(clippy::disallowed_methods)]
#[tokio::test]
async fn test_health_check() {
    // Arrange
    let app = Router::new()
        .merge(health::create_health_routes())
        .layer(TraceLayer::new_for_http())
        .layer(middleware::cors());

    // Act
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("Failed to build request"),
        )
        .await
        .expect("Failed to execute request");

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
}
