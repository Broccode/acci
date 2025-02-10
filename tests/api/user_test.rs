use acci_db::{create_pool, repositories::UserRepository, run_migrations, sqlx::PgPool, DbConfig};
use anyhow::Result;

async fn setup() -> Result<(PgPool, UserRepository)> {
    let config = DbConfig::default();
    let pool = create_pool(config).await?;
    run_migrations(&pool).await?;
    let repo = UserRepository::new(pool.clone());
    Ok((pool, repo))
}

#[tokio::test]
async fn test_create_user() {
    let (_pool, repo) = setup().await.unwrap();

    let user = acci_db::repositories::user::CreateUser {
        email: "test@example.com".to_string(),
        password_hash: "hash123".to_string(),
        full_name: "Test User".to_string(),
    };

    let created = repo.create(user).await.unwrap();
    assert_eq!(created.email, "test@example.com");
    assert_eq!(created.full_name, "Test User");
}

#[tokio::test]
async fn test_get_user_by_email() {
    let (_pool, repo) = setup().await.unwrap();

    let user = acci_db::repositories::user::CreateUser {
        email: "find@example.com".to_string(),
        password_hash: "hash123".to_string(),
        full_name: "Find User".to_string(),
    };

    let created = repo.create(user).await.unwrap();
    let found = repo
        .get_by_email("find@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created.id, found.id);
}
