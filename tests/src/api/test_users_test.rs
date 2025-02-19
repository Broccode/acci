use crate::{
    helpers::db::setup_database,
    mocks::{MockSessionRepository, MockUserRepository},
};
use acci_auth::providers::basic::BasicAuthProvider;
use acci_core::{
    auth::{AuthConfig, AuthProvider, AuthResponse, Credentials, TestUserConfig},
    error::Error,
    models::User,
};
use acci_db::{
    models::Session,
    repositories::{
        session::{PgSessionRepository, SessionRepository},
        user::{PgUserRepository, UserRepository},
    },
};
use anyhow::Result;
use mockall::predicate::eq;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

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
    let auth_config = AuthConfig::default();
    let provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), auth_config);

    // Add a small delay to ensure database is ready
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Test admin authentication
    let admin_credentials = Credentials {
        username: "test.admin@example.com".to_string(),
        password: "test123!admin".to_string(),
    };
    let admin_result = provider.authenticate(admin_credentials).await;
    assert!(
        admin_result.is_ok(),
        "Admin authentication should succeed: {:?}",
        admin_result.err()
    );

    // Test regular user authentication
    let user_credentials = Credentials {
        username: "test.user@example.com".to_string(),
        password: "test123!user".to_string(),
    };
    let user_result = provider.authenticate(user_credentials).await;
    assert!(
        user_result.is_ok(),
        "User authentication should succeed: {:?}",
        user_result.err()
    );

    Ok(())
}

#[tokio::test]
async fn test_test_users_exist() -> Result<()> {
    let (_container, user_repo, _) = setup().await?;
    let test_config = TestUserConfig::default();

    // Check admin exists
    let admin = user_repo
        .get_user_by_username(&test_config.users[0].username)
        .await?;
    assert!(admin.is_some(), "Test admin user should exist");

    // Check regular user exists
    let user = user_repo
        .get_user_by_username(&test_config.users[1].username)
        .await?;
    assert!(user.is_some(), "Test user should exist");

    Ok(())
}

#[tokio::test]
async fn test_authenticate_test_admin_user() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    #[allow(unused_mut)]
    let mut session_repo = MockSessionRepository::default();
    let config = AuthConfig::default();
    let test_config = TestUserConfig::default();
    let admin_username = test_config.users[0].username.clone();
    let admin_password = test_config.users[0].password.clone();

    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let email_clone = admin_username.clone();

    user_repo
        .expect_get_user_by_username()
        .with(eq(admin_username.clone()))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: email_clone.clone(),
                email: "test@example.com".to_string(),
                password_hash: "$argon2id$v=19$m=4096,t=3,p=1$salt$hash".to_string(),
                full_name: "Test Admin".to_string(),
                is_admin: true,
                created_at: now,
                updated_at: now,
            }))
        });

    session_repo
        .expect_create_session()
        .returning(move |user_id, token, expires_at| {
            Ok(Session {
                id: Uuid::new_v4(),
                user_id,
                token: token.to_string(),
                created_at: now,
                expires_at,
            })
        });

    let provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config);

    let credentials = Credentials {
        username: admin_username,
        password: admin_password,
    };

    let result = provider.authenticate(credentials).await?;
    assert!(result.session.token.starts_with("ey")); // JWT tokens start with "ey"
    assert!(result.session.expires_at > result.session.created_at);
    assert_eq!(result.token_type, "Bearer");

    Ok(())
}

#[tokio::test]
async fn test_authenticate_test_regular_user() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    #[allow(unused_mut)]
    let mut session_repo = MockSessionRepository::default();
    let config = AuthConfig::default();
    let test_config = TestUserConfig::default();
    let user_username = test_config.users[1].username.clone();
    let user_password = test_config.users[1].password.clone();

    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let email_clone = user_username.clone();

    user_repo
        .expect_get_user_by_username()
        .with(eq(user_username.clone()))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: email_clone.clone(),
                email: "test@example.com".to_string(),
                password_hash: "$argon2id$v=19$m=4096,t=3,p=1$salt$hash".to_string(),
                full_name: "Test User".to_string(),
                is_admin: false,
                created_at: now,
                updated_at: now,
            }))
        });

    session_repo
        .expect_create_session()
        .returning(move |user_id, token, expires_at| {
            Ok(Session {
                id: Uuid::new_v4(),
                user_id,
                token: token.to_string(),
                created_at: now,
                expires_at,
            })
        });

    let provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config);

    let credentials = Credentials {
        username: user_username,
        password: user_password,
    };

    let result = provider.authenticate(credentials).await?;
    assert!(result.session.token.starts_with("ey")); // JWT tokens start with "ey"
    assert!(result.session.expires_at > result.session.created_at);
    assert_eq!(result.token_type, "Bearer");

    Ok(())
}

#[tokio::test]
async fn test_authenticate_test_user_invalid_password() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    #[allow(unused_mut)]
    let mut session_repo = MockSessionRepository::default();
    let config = AuthConfig::default();
    let test_config = TestUserConfig::default();
    let admin_username = test_config.users[0].username.clone();

    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let email_clone = admin_username.clone();

    user_repo
        .expect_get_user_by_username()
        .with(eq(admin_username.clone()))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: email_clone.clone(),
                email: "test@example.com".to_string(),
                password_hash: "$argon2id$v=19$m=4096,t=3,p=1$salt$hash".to_string(),
                full_name: "Test Admin".to_string(),
                is_admin: true,
                created_at: now,
                updated_at: now,
            }))
        });

    let provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config);

    let credentials = Credentials {
        username: admin_username,
        password: "wrong_password".to_string(),
    };

    let result = provider.authenticate(credentials).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidCredentials));

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
        username: admin_user.username.clone(),
        password: admin_user.password.clone(),
    };

    // In release mode, test users should be disabled and authentication should fall back to database
    let result = provider.authenticate(credentials).await;
    assert!(matches!(result, Err(Error::InvalidCredentials)));

    Ok(())
}
