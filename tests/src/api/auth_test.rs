use crate::{
    helpers::{auth, db::setup_database},
    mocks::{MockSessionRepository, MockUserRepository},
};
use acci_auth::{providers::basic::BasicAuthProvider, AuthConfig, AuthProvider, Credentials};
use acci_core::error::Error;
use acci_db::{
    repositories::{
        session::PgSessionRepository,
        user::{CreateUser, PgUserRepository, UserRepository},
    },
    Session, User,
};
use mockall::predicate::eq;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

async fn setup_test_user(repo: &impl UserRepository) -> Result<(User, String), Error> {
    let password = "test_password";
    let hash = auth::hash_password(password).map_err(|e| Error::internal(e.to_string()))?;

    let user = repo
        .create(CreateUser {
            email: "test@example.com".to_string(),
            password_hash: hash,
            full_name: "Test User".to_string(),
        })
        .await
        .map_err(|e| Error::internal(format!("Failed to create test user: {}", e)))?;

    Ok((user, password.to_string()))
}

#[tokio::test]
async fn test_authenticate_valid_credentials() -> Result<(), Error> {
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo, config);

    let (user, password) = setup_test_user(&*user_repo).await?;

    let credentials = Credentials {
        username: user.email,
        password,
    };

    let result = provider.authenticate(credentials).await?;
    assert_eq!(result.session.user_id, user.id);
    assert_eq!(result.token_type, "Bearer");
    Ok(())
}

#[tokio::test]
async fn test_authenticate_invalid_password() -> Result<(), Error> {
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo, config);

    let (user, _) = setup_test_user(&*user_repo).await?;

    let credentials = Credentials {
        username: user.email,
        password: "wrong_password".to_string(),
    };

    let result = provider.authenticate(credentials).await;
    assert!(matches!(result, Err(Error::InvalidCredentials)));
    Ok(())
}

#[tokio::test]
async fn test_authenticate_nonexistent_user() -> Result<(), Error> {
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo, config);

    let credentials = Credentials {
        username: "nonexistent@example.com".to_string(),
        password: "any_password".to_string(),
    };

    let result = provider.authenticate(credentials).await;
    assert!(matches!(result, Err(Error::InvalidCredentials)));
    Ok(())
}

#[tokio::test]
async fn test_token_validation() -> Result<(), Error> {
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::hours(1);

    let mut user_repo = MockUserRepository::new();
    user_repo
        .expect_get_by_id()
        .with(eq(user_id))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                email: "test@example.com".to_string(),
                password_hash: "$argon2id$v=19$m=4096,t=3,p=1$salt$hash".to_string(),
                full_name: "Test User".to_string(),
                created_at: now,
                updated_at: now,
            }))
        });

    let mut session_repo = MockSessionRepository::default();
    session_repo.expect_get_session().returning(move |_| {
        Ok(Some(Session {
            session_id,
            user_id,
            created_at: now,
            expires_at,
        }))
    });

    let config = AuthConfig::default();
    let provider =
        BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config.clone());

    let (token, _, _) = auth::create_test_token(user_id, &config)?;

    // Validate the token
    let session = provider.validate_token(&token).await?;
    assert_eq!(session.user_id, user_id);

    Ok(())
}

#[tokio::test]
async fn test_logout() -> Result<(), Error> {
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo, config);

    let (user, password) = setup_test_user(&*user_repo).await?;

    // Get a valid session through authentication
    let credentials = Credentials {
        username: user.email,
        password,
    };

    let auth_response = provider.authenticate(credentials).await?;
    let session_id = auth_response.session.session_id;

    // Test logout
    provider.logout(session_id).await?;

    // Verify token is no longer valid
    let result = provider.validate_token(&auth_response.session.token).await;
    assert!(result.is_err());

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

    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo, config);

    let (user, password) = setup_test_user(&*user_repo).await?;

    // Get a valid token through authentication
    let credentials = Credentials {
        username: user.email,
        password,
    };

    let auth_response = provider.authenticate(credentials).await?;
    let token = auth_response.session.token;

    // Wait for token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify token is no longer valid
    let result = provider.validate_token(&token).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_concurrent_sessions() -> Result<(), Error> {
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::hours(1);
    let email = "test@example.com".to_string();
    let email_clone = email.clone();
    let email_clone2 = email.clone();

    let mut user_repo = MockUserRepository::new();
    user_repo
        .expect_get_by_email()
        .with(eq(email.clone()))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                email: email_clone.clone(),
                password_hash: auth::hash_password("test_password").unwrap(),
                full_name: "Test User".to_string(),
                created_at: now,
                updated_at: now,
            }))
        })
        .times(2);

    user_repo
        .expect_get_by_id()
        .with(eq(user_id))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                email: email_clone2.clone(),
                password_hash: auth::hash_password("test_password").unwrap(),
                full_name: "Test User".to_string(),
                created_at: now,
                updated_at: now,
            }))
        })
        .times(2);

    let mut session_repo = MockSessionRepository::default();
    session_repo
        .expect_create_session()
        .returning(move |session| {
            Ok(Session {
                session_id: Uuid::new_v4(),
                user_id: session.user_id,
                created_at: session.created_at,
                expires_at: session.expires_at,
            })
        })
        .times(2);

    session_repo
        .expect_get_session()
        .returning(move |_| {
            Ok(Some(Session {
                session_id: Uuid::new_v4(),
                user_id,
                created_at: now,
                expires_at,
            }))
        })
        .times(2);

    session_repo
        .expect_delete_session()
        .returning(|_| Ok(()))
        .times(1);

    let config = AuthConfig::default();
    let provider =
        BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config.clone());

    // Create multiple sessions
    let credentials = Credentials {
        username: email,
        password: "test_password".to_string(),
    };

    let session1 = provider.authenticate(credentials.clone()).await?;
    let session2 = provider.authenticate(credentials).await?;

    // Verify both sessions are valid
    assert!(provider
        .validate_token(&session1.session.token)
        .await
        .is_ok());
    assert!(provider
        .validate_token(&session2.session.token)
        .await
        .is_ok());

    // Logout from one session
    provider.logout(session1.session.session_id).await?;

    Ok(())
}

#[test]
fn test_password_hash_and_verify() -> Result<(), Error> {
    let password = "test_password";
    let hash = auth::hash_password(password)?;

    assert!(auth::verify_password(password, &hash)?);
    assert!(!auth::verify_password("wrong_password", &hash)?);
    Ok(())
}

#[test]
fn test_password_hash_different_salts() -> Result<(), Error> {
    let password = "test_password";
    let hash1 = auth::hash_password(password)?;
    let hash2 = auth::hash_password(password)?;

    // Different salts should produce different hashes
    assert_ne!(hash1, hash2);

    // But both should verify correctly
    assert!(auth::verify_password(password, &hash1)?);
    assert!(auth::verify_password(password, &hash2)?);
    Ok(())
}

#[test]
fn test_password_verify_invalid_hash() {
    let result = auth::verify_password("test", "invalid_hash");
    assert!(result.is_err());
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
    assert!(!token.is_empty());
    assert!(exp > iat);
    assert_eq!(exp - iat, config.token_duration);

    Ok(())
}

#[tokio::test]
async fn test_login_default_admin() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    let mut session_repo = MockSessionRepository::default();
    let config = AuthConfig::default();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    user_repo
        .expect_get_by_email()
        .with(eq("admin"))
        .returning(move |_| {
            Ok(Some(User {
                id: user_id,
                email: "admin".to_string(),
                password_hash: auth::hash_password("whiskey")?,
                full_name: "Default Admin".to_string(),
                created_at: now,
                updated_at: now,
            }))
        });

    session_repo.expect_create_session().returning(|session| {
        Ok(Session {
            session_id: Uuid::new_v4(),
            user_id: session.user_id,
            created_at: session.created_at,
            expires_at: session.expires_at,
        })
    });

    let auth_provider = BasicAuthProvider::new(Arc::new(user_repo), Arc::new(session_repo), config);

    let credentials = Credentials {
        username: "admin".to_string(),
        password: "whiskey".to_string(),
    };

    let result = auth_provider.authenticate(credentials).await;
    assert!(result.is_ok());
    Ok(())
}

#[tokio::test]
async fn test_login_invalid_credentials() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    user_repo
        .expect_get_by_email()
        .with(eq("invalid@example.com"))
        .returning(|_| Ok(None));

    let session_repo = Arc::new(MockSessionRepository::new());
    let auth_provider =
        BasicAuthProvider::new(Arc::new(user_repo), session_repo, AuthConfig::default());

    let credentials = Credentials {
        username: "invalid@example.com".to_string(),
        password: "wrongpassword".to_string(),
    };

    let result = auth_provider.authenticate(credentials).await;
    assert!(matches!(result, Err(Error::InvalidCredentials)));
    Ok(())
}
