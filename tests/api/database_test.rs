use acci_db::{create_pool, test_connection, DbConfig};

#[tokio::test]
async fn test_create_pool() {
    let config = DbConfig {
        url: "postgres://acci:development_only@localhost:5432/acci".to_string(),
        max_connections: 2,
        connect_timeout: 5,
    };
    let pool = create_pool(config).await.unwrap();
    assert!(pool.acquire().await.is_ok());
}

#[tokio::test]
async fn test_connection_success() {
    let config = DbConfig {
        url: "postgres://acci:development_only@localhost:5432/acci".to_string(),
        max_connections: 2,
        connect_timeout: 5,
    };
    let pool = create_pool(config).await.unwrap();
    let result = test_connection(&pool).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_invalid_connection_config() {
    let config = DbConfig {
        url: "postgres://invalid:invalid@localhost:5432/nonexistent".to_string(),
        max_connections: 1,
        connect_timeout: 1,
    };
    let result = create_pool(config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_connection_pool_limits() {
    let config = DbConfig {
        url: "postgres://acci:development_only@localhost:5432/acci".to_string(),
        max_connections: 1,
        connect_timeout: 1,
    };
    let pool = create_pool(config).await.unwrap();

    // Acquire first connection
    let conn1 = pool.acquire().await.unwrap();

    // Second connection should timeout
    let conn2_result = pool.acquire().await;
    assert!(conn2_result.is_err());

    // Release first connection
    drop(conn1);

    // Should be able to acquire a connection again
    assert!(pool.acquire().await.is_ok());
}
