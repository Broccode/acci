use acci_api::{middleware, routes::health::HealthResponse};
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
        .merge(acci_api::routes::health::router())
        .layer(TraceLayer::new_for_http())
        .layer(middleware::cors());

    // Act
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let health_response: HealthResponse = serde_json::from_reader(bytes.as_ref()).unwrap();

    assert_eq!(health_response.status, "ok");
    assert!(!health_response.version.is_empty());
}
