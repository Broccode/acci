use acci_auth::{AuthConfig, AuthProvider, BasicAuthProvider, Credentials};
use acci_core::auth::TestUserConfig;
use acci_db::repositories::user::{PgUserRepository, UserRepository};
use anyhow::Result;
use std::sync::Arc;

use crate::helpers::db::setup_database;

async fn setup() -> Result<(Box<dyn std::any::Any>, PgUserRepository)> {
    let (container, pool) = setup_database().await?;
    let repo = PgUserRepository::new(pool);
    Ok((container, repo))
}

#[tokio::test]
async fn test_test_users_authentication() -> Result<()> {
    let (_container, repo) = setup().await?;
    let test_config = TestUserConfig::default();
    let auth_config = AuthConfig::default();
    let provider = BasicAuthProvider::new(Arc::new(repo), auth_config);

    // Test admin authentication
    let admin = &test_config.users[0];
    let admin_result = provider
        .authenticate(Credentials {
            username: admin.email.clone(),
            password: admin.password.clone(),
        })
        .await;
    assert!(admin_result.is_ok(), "Admin authentication should succeed");

    // Test regular user authentication
    let user = &test_config.users[1];
    let user_result = provider
        .authenticate(Credentials {
            username: user.email.clone(),
            password: user.password.clone(),
        })
        .await;
    assert!(user_result.is_ok(), "User authentication should succeed");

    Ok(())
}

#[tokio::test]
async fn test_test_users_exist() -> Result<()> {
    let (_container, repo) = setup().await?;
    let test_config = TestUserConfig::default();

    // Check admin exists
    let admin = repo.get_by_email(&test_config.users[0].email).await?;
    assert!(admin.is_some(), "Test admin user should exist");

    // Check regular user exists
    let user = repo.get_by_email(&test_config.users[1].email).await?;
    assert!(user.is_some(), "Test user should exist");

    Ok(())
}
