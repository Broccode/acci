use acci_db::{create_pool, repositories::UserRepository, run_migrations, DbConfig};
use anyhow::Result;
use testcontainers::{clients, Container, PostgresImage};

async fn setup() -> Result<(Container<'static, PostgresImage>, UserRepository)> {
    let docker = clients::Cli::default();
    let postgres = PostgresImage::default();
    let container = docker.run(postgres);
    let port = container.get_host_port_ipv4(5432);

    let config = DbConfig {
        url: format!("postgres://postgres:postgres@localhost:{}/postgres", port),
        ..Default::default()
    };

    let pool = create_pool(config).await?;
    run_migrations(&pool).await?;
    let repo = UserRepository::new(pool);
    Ok((container, repo))
}

#[tokio::test]
async fn test_create_user() {
    let (_container, repo) = setup().await.unwrap();

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
    let (_container, repo) = setup().await.unwrap();

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
