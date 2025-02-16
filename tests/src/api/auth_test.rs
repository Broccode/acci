use acci_auth::providers::basic::BasicAuthProvider;
use acci_core::{
    auth::{hash_password, AuthConfig, AuthProvider, Credentials},
    error::Error,
};
use acci_db::{
    models::Session,
    repositories::{
        session::{PgSessionRepository, SessionRepository},
        user::{CreateUser, PgUserRepository, User, UserRepository},
    },
};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::helpers::db::setup_database;

async fn setup_test_user(repo: &impl UserRepository) -> Result<(User, String), Error> {
    let password = "test_password";
    let hash = hash_password(password).map_err(|e| Error::internal(e.to_string()))?;

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
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo, config);

    let (user, password) = setup_test_user(&*user_repo).await?;

    // Get a valid token through authentication
    let credentials = Credentials {
        username: user.email,
        password,
    };

    let auth_response = provider.authenticate(credentials).await?;
    let token = auth_response.session.token;

    // Validate the token
    let session = provider.validate_token(&token).await?;
    assert_eq!(session.user_id, user.id);

    // Test with invalid token
    let result = provider.validate_token("invalid_token").await;
    assert!(result.is_err());

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
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo, config);

    let (user, password) = setup_test_user(&*user_repo).await?;

    // Create multiple sessions for the same user
    let credentials = Credentials {
        username: user.email.clone(),
        password: password.clone(),
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

    // Verify first session is invalid but second remains valid
    assert!(provider
        .validate_token(&session1.session.token)
        .await
        .is_err());
    assert!(provider
        .validate_token(&session2.session.token)
        .await
        .is_ok());

    Ok(())
}
