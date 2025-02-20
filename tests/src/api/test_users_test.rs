use crate::{
    helpers::auth,
    helpers::db::setup_database,
    mocks::{MockSessionRepository, MockUserRepository},
};
use acci_auth::providers::basic::BasicAuthProvider;
use acci_core::{
    auth::{AuthConfig, AuthProvider, Credentials, TestUser, TestUserConfig},
    error::Error,
    models::User,
};
use acci_db::{
    models::Session,
    repositories::{
        session::PgSessionRepository,
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

    // Set environment to test mode
    sqlx::query("SET app.environment = 'test'")
        .execute(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set test environment: {}", e))?;

    // Run migrations to create test users
    acci_db::run_migrations(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;

    let user_repo = PgUserRepository::new(pool.clone());
    let session_repo = PgSessionRepository::new(pool);
    Ok((container, user_repo, session_repo))
}

async fn generate_test_user_hash(password: &str) -> Result<String> {
    let hash = auth::hash_password(password)?;
    println!("Generated hash for '{}': {}", password, hash);
    Ok(hash)
}

#[tokio::test]
async fn test_test_users_authentication() -> Result<()> {
    let (_container, user_repo, session_repo) = setup().await?;
    let auth_config = AuthConfig::default();
    let test_config = TestUserConfig {
        users: vec![
            TestUser {
                username: "test_admin".to_string(),
                password: "Admin123!@#".to_string(),
                full_name: "Test Admin".to_string(),
                role: "admin".to_string(),
            },
            TestUser {
                username: "test_user".to_string(),
                password: "Test123!@#".to_string(),
                full_name: "Test User".to_string(),
                role: "user".to_string(),
            },
        ],
        enabled: true,
    };

    // Generate and print hashes for test users
    for user in &test_config.users {
        let hash = generate_test_user_hash(&user.password).await?;
        println!("Test user '{}' hash: {}", user.username, hash);
    }

    // Verify test users exist and print their details
    for user in &test_config.users {
        let db_user = user_repo
            .get_user_by_username(&user.username)
            .await?
            .expect(&format!(
                "Test user {} should exist after migration",
                user.username
            ));

        println!("Found user: {}", user.username);
        println!("Password hash: {}", db_user.password_hash);
        println!("Expected password: {}", user.password);

        // Verify password hash
        let is_valid = auth::verify_password(&user.password, &db_user.password_hash)?;
        println!("Password verification result: {}", is_valid);
    }

    let provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), auth_config);

    // Test admin authentication
    let admin_credentials = Credentials {
        username: test_config.users[0].username.clone(),
        password: test_config.users[0].password.clone(),
    };
    let admin_result = provider.authenticate(admin_credentials).await;
    assert!(
        admin_result.is_ok(),
        "Admin authentication should succeed: {:?}",
        admin_result.err()
    );

    // Test regular user authentication
    let user_credentials = Credentials {
        username: test_config.users[1].username.clone(),
        password: test_config.users[1].password.clone(),
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
    let mut user_repo = MockUserRepository::default();
    let mut session_repo = MockSessionRepository::default();
    let config = AuthConfig::default();
    let test_config = TestUserConfig::default();
    let admin_username = test_config.users[0].username.clone();
    let admin_password = test_config.users[0].password.clone();

    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let email_clone = admin_username.clone();

    // Create a valid password hash
    let password_hash = auth::hash_password(&admin_password)
        .expect("Password hashing should succeed in test setup");

    user_repo
        .expect_get_user_by_username()
        .with(eq(admin_username.clone()))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: email_clone.clone(),
                email: "test@example.com".to_string(),
                password_hash: password_hash.clone(),
                full_name: "Test Admin".to_string(),
                is_admin: true,
                is_active: true,
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

    session_repo
        .expect_update_session_token()
        .returning(|_, _| Ok(()));

    let provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config);

    let credentials = Credentials {
        username: admin_username,
        password: "Admin123!@#".to_string(),
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

    // Create a valid password hash
    let password_hash =
        auth::hash_password(&user_password).expect("Password hashing should succeed in test setup");

    user_repo
        .expect_get_user_by_username()
        .with(eq(user_username.clone()))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: email_clone.clone(),
                email: "test@example.com".to_string(),
                password_hash: password_hash.clone(),
                full_name: "Test User".to_string(),
                is_admin: false,
                is_active: true,
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

    session_repo
        .expect_update_session_token()
        .returning(|_, _| Ok(()));

    let provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config);

    let credentials = Credentials {
        username: user_username,
        password: "Test123!@#".to_string(),
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

    // Create a valid password hash for the correct password
    let password_hash = auth::hash_password(&test_config.users[0].password)
        .expect("Password hashing should succeed in test setup");

    user_repo
        .expect_get_user_by_username()
        .with(eq(admin_username.clone()))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: email_clone.clone(),
                email: "test@example.com".to_string(),
                password_hash: password_hash.clone(),
                full_name: "Test Admin".to_string(),
                is_admin: true,
                is_active: true,
                created_at: now,
                updated_at: now,
            }))
        });

    let provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config);

    let credentials = Credentials {
        username: admin_username,
        password: "WrongPass123!@#".to_string(),
    };

    let result = provider.authenticate(credentials).await;
    assert!(
        matches!(result, Err(Error::InvalidCredentials(_))),
        "Should return InvalidCredentials error for wrong password"
    );

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
