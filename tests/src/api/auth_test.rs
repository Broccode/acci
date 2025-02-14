use acci_auth::providers::basic::BasicAuthProvider;
use acci_core::{
    auth::{hash_password, AuthConfig, AuthProvider, Credentials},
    error::Error,
};
use acci_db::repositories::user::{CreateUser, PgUserRepository, User, UserRepository};
use std::sync::Arc;

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
    let repo = PgUserRepository::new(pool);
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(Arc::new(repo.clone()), config);

    let (user, password) = setup_test_user(&repo).await?;

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
    let repo = PgUserRepository::new(pool);
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(Arc::new(repo.clone()), config);

    let (user, _) = setup_test_user(&repo).await?;

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
    let repo = PgUserRepository::new(pool);
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(Arc::new(repo.clone()), config);

    let credentials = Credentials {
        username: "nonexistent@example.com".to_string(),
        password: "any_password".to_string(),
    };

    let result = provider.authenticate(credentials).await;
    assert!(matches!(result, Err(Error::InvalidCredentials)));
    Ok(())
}
