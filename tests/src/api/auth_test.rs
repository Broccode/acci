use acci_auth::providers::basic::BasicAuthProvider;
use acci_core::{
    auth::{AuthConfig, AuthProvider, AuthResponse, AuthSession, Credentials},
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
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::helpers::{auth, db::setup_database};
use crate::mocks::{session::MockSessionRepository, user::MockUserRepository};
use mockall::predicate::eq;

async fn setup_test_user(repo: &impl UserRepository) -> Result<(User, String), Error> {
    let username = "test_user";
    let password = "test_password";
    let hash = auth::hash_password(password).map_err(|e| Error::internal(e.to_string()))?;

    let user = repo
        .create_user(username, &hash)
        .await
        .map_err(|e| Error::internal(format!("Failed to create test user: {}", e)))?;

    Ok((user, password.to_string()))
}

#[tokio::test]
async fn test_basic_auth_flow() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    let mut session_repo = MockSessionRepository::new();
    let _config = AuthConfig::default();

    // Setup mock expectations
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    user_repo
        .expect_get_user_by_username()
        .with(eq("test_user"))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: "test_user".to_string(),
                email: "test_user@example.com".to_string(),
                password_hash: auth::hash_password("test_password")
                    .expect("Password hashing should succeed in test setup"),
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

    session_repo
        .expect_update_session_token()
        .returning(|_, _| Ok(()));

    let auth_provider = BasicAuthProvider::new(
        Arc::new(user_repo),
        Arc::new(session_repo),
        AuthConfig::default(),
    );

    // Test authentication
    let result = auth_provider
        .authenticate(Credentials {
            username: "test_user".to_string(),
            password: "test_password".to_string(),
        })
        .await?;

    assert_eq!(result.token_type, "Bearer", "Token type should be Bearer");
    assert!(
        !result.session.token.is_empty(),
        "Session token should not be empty"
    );
    assert_eq!(
        result.session.user_id, user_id,
        "Session user_id should match the authenticated user"
    );
    assert!(
        result.session.expires_at > result.session.created_at,
        "Session expiry should be after creation time"
    );

    Ok(())
}

#[tokio::test]
async fn test_invalid_credentials() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    let mut session_repo = MockSessionRepository::new();
    let _config = AuthConfig::default();

    // Setup mock expectations
    user_repo
        .expect_get_user_by_username()
        .returning(|_| Ok(None));

    let auth_provider = BasicAuthProvider::new(
        Arc::new(user_repo),
        Arc::new(session_repo),
        AuthConfig::default(),
    );

    // Test invalid credentials
    let result = auth_provider
        .authenticate(Credentials {
            username: "nonexistent".to_string(),
            password: "wrong_password".to_string(),
        })
        .await;

    assert!(
        matches!(result, Err(Error::NotFound(_))),
        "Should return NotFound error for non-existent user"
    );

    Ok(())
}

#[tokio::test]
async fn test_session_management() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    let mut session_repo = MockSessionRepository::new();
    let _config = AuthConfig::default();

    // Setup mock expectations
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    user_repo
        .expect_get_user_by_username()
        .with(eq("test_user"))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: "test_user".to_string(),
                email: "test_user@example.com".to_string(),
                password_hash: auth::hash_password("test_password")
                    .expect("Password hashing should succeed in test setup"),
                full_name: "Test User".to_string(),
                is_admin: false,
                created_at: now,
                updated_at: now,
            }))
        });

    session_repo
        .expect_create_session()
        .returning(move |user_id, token, expires_at| {
            let session_id = Uuid::new_v4();
            Ok(Session {
                id: session_id,
                user_id,
                token: token.to_string(),
                created_at: now,
                expires_at,
            })
        });

    session_repo
        .expect_update_session_token()
        .returning(|_, _| Ok(()));

    session_repo.expect_get_session().returning(move |id| {
        Ok(Some(Session {
            id,
            user_id,
            token: "test_token".to_string(),
            created_at: now,
            expires_at: now + time::Duration::hours(1),
        }))
    });

    user_repo.expect_get_user_by_id().returning(move |id| {
        Ok(Some(User {
            id,
            username: "test_user".to_string(),
            email: "test_user@example.com".to_string(),
            password_hash: auth::hash_password("test_password")
                .expect("Password hashing should succeed in test setup"),
            full_name: "Test User".to_string(),
            is_admin: false,
            created_at: now,
            updated_at: now,
        }))
    });

    let auth_provider = BasicAuthProvider::new(
        Arc::new(user_repo),
        Arc::new(session_repo),
        AuthConfig::default(),
    );

    // Test authentication and session creation
    let auth_result = auth_provider
        .authenticate(Credentials {
            username: "test_user".to_string(),
            password: "test_password".to_string(),
        })
        .await?;

    assert_eq!(
        auth_result.token_type, "Bearer",
        "Token type should be Bearer"
    );
    assert!(
        !auth_result.session.token.is_empty(),
        "Session token should not be empty"
    );
    assert_eq!(
        auth_result.session.user_id, user_id,
        "Session user_id should match the authenticated user"
    );
    assert!(
        auth_result.session.expires_at > auth_result.session.created_at,
        "Session expiry should be after creation time"
    );

    Ok(())
}

#[tokio::test]
async fn test_token_validation() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    let mut session_repo = MockSessionRepository::new();
    let _config = AuthConfig::default();

    // Setup mock expectations
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    user_repo.expect_get_user_by_username().returning(move |_| {
        Ok(Some(User {
            id: user_id,
            username: "test_user".to_string(),
            email: "test_user@example.com".to_string(),
            password_hash: auth::hash_password("test_password")
                .expect("Password hashing should succeed in test setup"),
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

    session_repo
        .expect_update_session_token()
        .returning(|_, _| Ok(()));

    let auth_provider = BasicAuthProvider::new(
        Arc::new(user_repo),
        Arc::new(session_repo),
        AuthConfig::default(),
    );

    // Test authentication and token validation
    let auth_result = auth_provider
        .authenticate(Credentials {
            username: "test_user".to_string(),
            password: "test_password".to_string(),
        })
        .await?;

    let session = auth_provider
        .validate_token(auth_result.session.token.clone())
        .await?;
    assert_eq!(
        session.user_id, user_id,
        "Validated session should have correct user_id"
    );

    Ok(())
}

#[tokio::test]
async fn test_logout() -> Result<(), Error> {
    let user_repo = MockUserRepository::new();
    let mut session_repo = MockSessionRepository::new();
    let session_id = Uuid::new_v4();

    session_repo
        .expect_delete_session()
        .with(eq(session_id))
        .returning(|_| Ok(()));

    let _config = AuthConfig::default();
    let auth_provider = BasicAuthProvider::new(
        Arc::new(user_repo),
        Arc::new(session_repo),
        AuthConfig::default(),
    );

    auth_provider.logout(session_id).await?;

    Ok(())
}

#[test]
fn test_password_hash_and_verify() -> Result<(), Error> {
    let password = "test_password";
    let hash = auth::hash_password(password)?;

    assert!(
        auth::verify_password(password, &hash)?,
        "Password verification should succeed with correct password"
    );
    assert!(
        !auth::verify_password("wrong_password", &hash)?,
        "Password verification should fail with wrong password"
    );
    Ok(())
}

#[test]
fn test_password_hash_different_salts() -> Result<(), Error> {
    let password = "test_password";
    let hash1 = auth::hash_password(password)?;
    let hash2 = auth::hash_password(password)?;

    // Different salts should produce different hashes
    assert_ne!(
        hash1, hash2,
        "Different salt values should produce different hashes"
    );

    // But both should verify correctly
    assert!(
        auth::verify_password(password, &hash1)?,
        "First hash should verify correctly"
    );
    assert!(
        auth::verify_password(password, &hash2)?,
        "Second hash should verify correctly"
    );
    Ok(())
}

#[test]
fn test_password_verify_invalid_hash() {
    let result = auth::verify_password("test", "invalid_hash");
    assert!(
        result.is_err(),
        "Verification should fail with invalid hash format"
    );
}

#[tokio::test]
async fn test_authenticate_valid_credentials() -> Result<(), Error> {
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let _config = AuthConfig::default();

    let (user, password) = setup_test_user(&*user_repo).await?;

    let credentials = Credentials {
        username: user.username,
        password,
    };

    let auth_provider = BasicAuthProvider::new(user_repo.clone(), session_repo, _config);

    let result = auth_provider.authenticate(credentials).await?;
    assert_eq!(
        result.session.user_id, user.id,
        "Session user_id should match the authenticated user"
    );
    assert_eq!(result.token_type, "Bearer", "Token type should be Bearer");
    Ok(())
}

#[tokio::test]
async fn test_authenticate_invalid_password() -> Result<(), Error> {
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let _config = AuthConfig::default();

    let (user, _) = setup_test_user(&*user_repo).await?;

    let credentials = Credentials {
        username: user.username,
        password: "wrong_password".to_string(),
    };

    let auth_provider = BasicAuthProvider::new(user_repo.clone(), session_repo, _config);

    let result = auth_provider.authenticate(credentials).await;
    assert!(
        matches!(result, Err(Error::InvalidCredentials)),
        "Should return InvalidCredentials error for wrong password"
    );
    Ok(())
}

#[tokio::test]
async fn test_authenticate_nonexistent_user() -> Result<(), Error> {
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let _config = AuthConfig::default();

    let credentials = Credentials {
        username: "nonexistent".to_string(),
        password: "any_password".to_string(),
    };

    let auth_provider = BasicAuthProvider::new(user_repo.clone(), session_repo, _config);

    let result = auth_provider.authenticate(credentials).await;
    assert!(
        matches!(result, Err(Error::InvalidCredentials)),
        "Should return InvalidCredentials error for non-existent user"
    );
    Ok(())
}

#[tokio::test]
async fn test_token_expiration() -> Result<(), Error> {
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));

    // Create config with very short token duration
    let config = AuthConfig {
        token_duration: 1, // 1 second
        ..AuthConfig::default()
    };

    let auth_provider = BasicAuthProvider::new(user_repo.clone(), session_repo, config);

    let (user, password) = setup_test_user(&*user_repo).await?;

    // Get a valid token through authentication
    let credentials = Credentials {
        username: user.username,
        password,
    };

    let auth_response = auth_provider.authenticate(credentials).await?;
    let token = auth_response.session.token;

    // Wait for token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify token is no longer valid
    let result = auth_provider.validate_token(token.clone()).await;
    assert!(
        result.is_err(),
        "Token validation should fail after expiration"
    );

    Ok(())
}

#[tokio::test]
async fn test_concurrent_sessions() -> Result<(), Error> {
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let username = "test_user".to_string();
    let username_clone = username.clone();
    let username_clone2 = username.clone();

    let mut user_repo = MockUserRepository::new();
    user_repo
        .expect_get_user_by_username()
        .with(eq(username.clone()))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: username_clone.clone(),
                email: "test@example.com".to_string(),
                password_hash: auth::hash_password("test_password")
                    .expect("Password hashing should succeed in test setup"),
                full_name: "Test User".to_string(),
                is_admin: false,
                created_at: now,
                updated_at: now,
            }))
        })
        .times(2);

    user_repo
        .expect_get_user_by_id()
        .with(eq(user_id))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: username_clone2.clone(),
                email: "test@example.com".to_string(),
                password_hash: auth::hash_password("test_password")
                    .expect("Password hashing should succeed in test setup"),
                full_name: "Test User".to_string(),
                is_admin: false,
                created_at: now,
                updated_at: now,
            }))
        })
        .times(2);

    let mut session_repo = MockSessionRepository::default();
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
        })
        .times(2);

    session_repo
        .expect_get_session()
        .returning(move |_| {
            Ok(Some(Session {
                id: Uuid::new_v4(),
                user_id,
                token: "test_token".to_string(),
                created_at: now,
                expires_at: now + time::Duration::hours(1),
            }))
        })
        .times(2);

    session_repo
        .expect_delete_session()
        .returning(|_| Ok(()))
        .times(1);

    session_repo
        .expect_update_session_token()
        .returning(|_, _| Ok(()));

    let config = AuthConfig::default();
    let provider =
        BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config.clone());

    // Create multiple sessions
    let credentials = Credentials {
        username,
        password: "test_password".to_string(),
    };

    let session1 = provider.authenticate(credentials.clone()).await?;
    let session2 = provider.authenticate(credentials).await?;

    // Verify both sessions are valid
    assert!(
        provider
            .validate_token(session1.session.token.clone())
            .await
            .is_ok(),
        "First session should be valid"
    );
    assert!(
        provider
            .validate_token(session2.session.token.clone())
            .await
            .is_ok(),
        "Second session should be valid"
    );

    // Logout from one session
    provider.logout(session1.session.session_id).await?;

    Ok(())
}

#[test]
fn test_create_token() -> Result<(), Error> {
    let user_id = Uuid::new_v4();
    let config = AuthConfig {
        token_duration: 3600,
        token_issuer: "test_issuer".to_string(),
        jwt_secret: "test_secret".to_string(),
    };

    let (token, iat, exp) = auth::create_test_token(user_id, &config)?;

    // Basic validation
    assert!(!token.is_empty(), "Token should not be empty");
    assert!(
        exp > iat,
        "Token expiration time should be after issued time"
    );
    assert_eq!(
        exp - iat,
        config.token_duration,
        "Token duration should match config"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_default_admin() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    let mut session_repo = MockSessionRepository::default();
    let _config = AuthConfig::default();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    user_repo
        .expect_get_user_by_username()
        .with(eq("admin"))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                username: "admin".to_string(),
                email: "admin@example.com".to_string(),
                password_hash: auth::hash_password("whiskey")
                    .expect("Password hashing should succeed in test setup"),
                full_name: "Admin User".to_string(),
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

    session_repo
        .expect_update_session_token()
        .returning(|_, _| Ok(()));

    let auth_provider =
        BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), _config);

    let credentials = Credentials {
        username: "admin".to_string(),
        password: "whiskey".to_string(),
    };

    let result = auth_provider.authenticate(credentials).await;
    assert!(
        result.is_ok(),
        "Default admin authentication should succeed"
    );
    Ok(())
}

#[tokio::test]
async fn test_login_invalid_credentials() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    user_repo
        .expect_get_user_by_username()
        .with(eq("invalid"))
        .returning(|_| Ok(None));

    let session_repo = MockSessionRepository::new();
    let auth_provider = BasicAuthProvider::new(
        Arc::new(user_repo),
        Arc::new(session_repo),
        AuthConfig::default(),
    );

    let credentials = Credentials {
        username: "invalid".to_string(),
        password: "wrongpassword".to_string(),
    };

    let result = auth_provider.authenticate(credentials).await;
    assert!(
        matches!(result, Err(Error::InvalidCredentials)),
        "Should return InvalidCredentials error for invalid credentials"
    );
    Ok(())
}
