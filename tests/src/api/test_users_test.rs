use crate::{
    helpers::db::setup_database,
    mocks::{MockSessionRepository, MockUserRepository},
};
use acci_auth::{providers::basic::BasicAuthProvider, AuthConfig, AuthProvider, Credentials};
use acci_core::{auth::TestUserConfig, error::Error};
use acci_db::repositories::{session::PgSessionRepository, user::PgUserRepository};
use anyhow::Result;
use std::sync::Arc;

async fn setup() -> Result<(
    Box<dyn std::any::Any>,
    PgUserRepository,
    PgSessionRepository,
)> {
    let (container, pool) = setup_database().await?;
    let user_repo = PgUserRepository::new(pool.clone());
    let session_repo = PgSessionRepository::new(pool);
    Ok((container, user_repo, session_repo))
}

#[tokio::test]
async fn test_test_users_authentication() -> Result<()> {
    let (_container, user_repo, session_repo) = setup().await?;
    let test_config = TestUserConfig::default();
    let auth_config = AuthConfig::default();
    let provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), auth_config);

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
    let (_container, user_repo, _) = setup().await?;
    let test_config = TestUserConfig::default();

    // Check admin exists
    let admin = user_repo.get_by_email(&test_config.users[0].email).await?;
    assert!(admin.is_some(), "Test admin user should exist");

    // Check regular user exists
    let user = user_repo.get_by_email(&test_config.users[1].email).await?;
    assert!(user.is_some(), "Test user should exist");

    Ok(())
}

#[tokio::test]
async fn test_authenticate_test_admin_user() -> Result<(), Error> {
    let user_repo = Arc::new(MockUserRepository::new());
    let session_repo = Arc::new(MockSessionRepository::new());
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo, session_repo, config);
    let test_config = TestUserConfig::default();
    let admin_user = &test_config.users[0]; // Admin is first user

    let credentials = Credentials {
        username: admin_user.email.clone(),
        password: admin_user.password.clone(),
    };

    let result = provider.authenticate(credentials).await?;
    assert!(result.session.token.starts_with("ey")); // JWT tokens start with "ey"
    assert!(result.session.expires_at > result.session.created_at);
    assert_eq!(result.token_type, "Bearer");

    Ok(())
}

#[tokio::test]
async fn test_authenticate_test_regular_user() -> Result<(), Error> {
    let user_repo = Arc::new(MockUserRepository::new());
    let session_repo = Arc::new(MockSessionRepository::new());
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo, session_repo, config);
    let test_config = TestUserConfig::default();
    let regular_user = &test_config.users[1]; // Regular user is second user

    let credentials = Credentials {
        username: regular_user.email.clone(),
        password: regular_user.password.clone(),
    };

    let result = provider.authenticate(credentials).await?;
    assert!(result.session.token.starts_with("ey")); // JWT tokens start with "ey"
    assert!(result.session.expires_at > result.session.created_at);
    assert_eq!(result.token_type, "Bearer");

    Ok(())
}

#[tokio::test]
async fn test_authenticate_test_user_invalid_password() -> Result<(), Error> {
    let user_repo = Arc::new(MockUserRepository::new());
    let session_repo = Arc::new(MockSessionRepository::new());
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo, session_repo, config);
    let test_config = TestUserConfig::default();
    let admin_user = &test_config.users[0];

    let credentials = Credentials {
        username: admin_user.email.clone(),
        password: "wrong_password".to_string(),
    };

    let result = provider.authenticate(credentials).await;
    assert!(matches!(result, Err(Error::InvalidCredentials)));

    Ok(())
}

#[cfg(not(debug_assertions))]
#[tokio::test]
async fn test_test_users_disabled_in_release() -> Result<(), Error> {
    let user_repo = Arc::new(MockUserRepository::new());
    let session_repo = Arc::new(MockSessionRepository::new());
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo, session_repo, config);
    let test_config = TestUserConfig::default();
    let admin_user = &test_config.users[0];

    let credentials = Credentials {
        username: admin_user.email.clone(),
        password: admin_user.password.clone(),
    };

    // In release mode, test users should be disabled and authentication should fall back to database
    let result = provider.authenticate(credentials).await;
    assert!(matches!(result, Err(Error::InvalidCredentials)));

    Ok(())
}
