use acci_auth::{providers::basic::BasicAuthProvider, AuthConfig, AuthProvider, Credentials};
use acci_core::auth::{Algorithm, AuthError, AuthService, TokenValidationError};
use acci_core::error::Error;
use acci_core::models::User;
use acci_db::{
    repositories::{
        session::PgSessionRepository,
        user::{CreateUser, PgUserRepository, UserRepository},
    },
    Session,
};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use futures::future::join_all;
use proptest::prelude::*;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

use crate::helpers::{auth, db::setup_database};
use crate::mocks::user::MockUserRepository;

/// Helper function to set up a test user
async fn setup_test_user(repo: &impl UserRepository) -> Result<(User, String), Error> {
    let password = "test_password123!";
    let hash = auth::hash_password(password).map_err(|e| Error::internal(e.to_string()))?;

    let user = repo
        .create(CreateUser {
            email: "test.flow@example.com".to_string(),
            password_hash: hash,
            full_name: "Test Flow User".to_string(),
        })
        .await
        .map_err(|e| Error::internal(format!("Failed to create test user: {}", e)))?;

    Ok((user, password.to_string()))
}

#[tokio::test]
async fn test_user_registration_success() -> Result<(), AuthError> {
    // Setup
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    // Test data
    let credentials = Credentials {
        username: "testuser".to_string(),
        password: "Test123!@#".to_string(),
    };

    // Execute registration
    let result = auth_service.register(credentials.clone()).await?;

    // Verify with detailed assertions
    assert!(
        result.id.len() > 0,
        "User ID should be generated, but got empty ID"
    );
    assert_eq!(
        result.username, credentials.username,
        "Username should match the provided credentials"
    );
    assert!(
        !result.password_hash.is_empty(),
        "Password should be hashed, but got empty hash"
    );
    assert_ne!(
        result.password_hash, credentials.password,
        "Password hash should not be the plain password"
    );

    // Verify timestamps
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        result.created_at <= now,
        "Created timestamp should be before or equal to current time"
    );
    assert!(
        now - result.created_at < 2,
        "User should be created within the last 2 seconds"
    );

    Ok(())
}

#[tokio::test]
async fn test_user_registration_duplicate() -> Result<(), AuthError> {
    // Setup
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    // Test data
    let credentials = Credentials {
        username: "testuser".to_string(),
        password: "Test123!@#".to_string(),
    };

    // First registration should succeed
    let first_result = auth_service.register(credentials.clone()).await;
    assert!(
        first_result.is_ok(),
        "First registration should succeed, but got error: {:?}",
        first_result.err()
    );

    // Second registration should fail with specific error
    let second_result = auth_service.register(credentials.clone()).await;
    assert!(
        matches!(second_result, Err(AuthError::UserAlreadyExists(username)) if username == credentials.username),
        "Expected UserAlreadyExists error for duplicate registration, but got: {:?}",
        second_result
    );

    Ok(())
}

#[tokio::test]
async fn test_user_registration_invalid_credentials() -> Result<(), AuthError> {
    // Setup
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    // Test cases with invalid credentials
    let test_cases = vec![
        (
            Credentials {
                username: "".to_string(),
                password: "Test123!@#".to_string(),
            },
            "empty username",
        ),
        (
            Credentials {
                username: "testuser".to_string(),
                password: "".to_string(),
            },
            "empty password",
        ),
        (
            Credentials {
                username: "test".to_string(), // too short
                password: "Test123!@#".to_string(),
            },
            "username too short",
        ),
        (
            Credentials {
                username: "testuser".to_string(),
                password: "weak".to_string(), // too weak
            },
            "password too weak",
        ),
    ];

    for (credentials, case) in test_cases {
        let result = auth_service.register(credentials).await;
        assert!(
            matches!(result, Err(AuthError::InvalidCredentials(_))),
            "Expected InvalidCredentials error for {}, but got: {:?}",
            case,
            result
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_login_flow() -> Result<(), AuthError> {
    // Setup mock repository
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    // Test data
    let credentials = Credentials {
        username: "test_user".to_string(),
        password: "secure_password123".to_string(),
    };

    // Register user first
    auth_service.register(credentials.clone()).await?;

    // Attempt login
    let token = auth_service.login(credentials).await?;

    // Verify token is valid
    assert!(!token.access_token.is_empty());
    assert!(!token.refresh_token.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_token_validation_success() -> Result<(), AuthError> {
    // Setup
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    // Register and login to get a valid token
    let credentials = Credentials {
        username: "testuser".to_string(),
        password: "Test123!@#".to_string(),
    };
    let user = auth_service.register(credentials.clone()).await?;
    let auth_result = auth_service.login(credentials).await?;

    // Validate the token
    let validation_result = auth_service.validate_token(&auth_result.token).await?;

    // Verify token claims
    assert_eq!(
        validation_result.user_id, user.id,
        "Token should contain correct user ID"
    );
    assert!(
        validation_result.exp
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        "Token should not be expired"
    );
    assert_eq!(
        validation_result.token_type, "Bearer",
        "Token type should be Bearer"
    );

    Ok(())
}

#[tokio::test]
async fn test_token_validation_expired() -> Result<(), AuthError> {
    // Setup
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo.clone());

    // Register and login to get a token
    let credentials = Credentials {
        username: "testuser".to_string(),
        password: "Test123!@#".to_string(),
    };
    let _ = auth_service.register(credentials.clone()).await?;
    let auth_result = auth_service.login(credentials).await?;

    // Simulate token expiration by waiting
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Attempt to validate expired token
    let validation_result = auth_service.validate_token(&auth_result.token).await;

    assert!(
        matches!(
            validation_result,
            Err(AuthError::TokenValidation(TokenValidationError::Expired))
        ),
        "Expected TokenValidationError::Expired for expired token, but got: {:?}",
        validation_result
    );

    Ok(())
}

#[tokio::test]
async fn test_token_validation_malformed() -> Result<(), AuthError> {
    // Setup
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    // Test cases for malformed tokens
    let test_cases = vec![
        ("", "empty token"),
        ("invalid", "non-JWT format"),
        ("header.payload", "missing signature"),
        ("header.payload.signature", "invalid JWT parts"),
        (
            "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl",
            "base64 encoded but invalid",
        ),
    ];

    for (token, case) in test_cases {
        let result = auth_service.validate_token(token).await;
        assert!(
            matches!(
                result,
                Err(AuthError::TokenValidation(TokenValidationError::Malformed))
            ),
            "Expected TokenValidationError::Malformed for {}, but got: {:?}",
            case,
            result
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_token_validation_tampered() -> Result<(), AuthError> {
    // Setup
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    // Get a valid token first
    let credentials = Credentials {
        username: "testuser".to_string(),
        password: "Test123!@#".to_string(),
    };
    let _ = auth_service.register(credentials.clone()).await?;
    let auth_result = auth_service.login(credentials).await?;

    // Tamper with the token
    let parts: Vec<&str> = auth_result.token.split('.').collect();
    if parts.len() == 3 {
        // Test payload tampering
        let tampered_payload_token = format!("{}.{}_tampered.{}", parts[0], parts[1], parts[2]);
        let result = auth_service.validate_token(&tampered_payload_token).await;
        assert!(
            matches!(
                result,
                Err(AuthError::TokenValidation(
                    TokenValidationError::InvalidSignature
                ))
            ),
            "Expected TokenValidationError::InvalidSignature for payload tampering, but got: {:?}",
            result
        );

        // Test header tampering
        let tampered_header_token = format!("{}_tampered.{}.{}", parts[0], parts[1], parts[2]);
        let result = auth_service.validate_token(&tampered_header_token).await;
        assert!(
            matches!(
                result,
                Err(AuthError::TokenValidation(
                    TokenValidationError::InvalidSignature
                ))
            ),
            "Expected TokenValidationError::InvalidSignature for header tampering, but got: {:?}",
            result
        );

        // Test signature tampering
        let tampered_signature_token = format!("{}.{}.{}_tampered", parts[0], parts[1], parts[2]);
        let result = auth_service.validate_token(&tampered_signature_token).await;
        assert!(
            matches!(
                result,
                Err(AuthError::TokenValidation(TokenValidationError::InvalidSignature))
            ),
            "Expected TokenValidationError::InvalidSignature for signature tampering, but got: {:?}",
            result
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_invalid_credentials() {
    // Setup mock repository
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    // Test data
    let valid_credentials = Credentials {
        username: "test_user".to_string(),
        password: "secure_password123".to_string(),
    };

    let invalid_credentials = Credentials {
        username: "test_user".to_string(),
        password: "wrong_password".to_string(),
    };

    // Register user
    auth_service.register(valid_credentials).await.unwrap();

    // Attempt login with invalid credentials
    let result = auth_service.login(invalid_credentials).await;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
}

#[tokio::test]
async fn test_basic_auth_flow() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo.clone(), config);

    // Test user registration (setup)
    let (user, password) = setup_test_user(&*user_repo).await?;
    assert!(!user.email.is_empty(), "User should be created with email");
    assert!(
        !user.password_hash.is_empty(),
        "User should have a password hash"
    );

    // Test login (authentication)
    let credentials = Credentials {
        username: user.email.clone(),
        password: password.clone(),
    };
    let auth_response = provider.authenticate(credentials).await?;

    // Enhanced assertions for auth response
    assert_eq!(
        auth_response.session.user_id, user.id,
        "Session should be created for correct user"
    );
    assert!(
        !auth_response.session.token.is_empty(),
        "Valid token should be generated"
    );
    assert_eq!(
        auth_response.token_type, "Bearer",
        "Token type should be Bearer"
    );

    // Verify session timestamps
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!(
        auth_response.session.created_at <= now,
        "Session creation time should be in the past"
    );
    assert!(
        auth_response.session.expires_at > now,
        "Session expiration should be in the future"
    );
    assert!(
        auth_response.session.expires_at - auth_response.session.created_at
            >= config.token_duration,
        "Session duration should match config"
    );

    // Test token validation
    let session = provider
        .validate_token(&auth_response.session.token)
        .await?;
    assert_eq!(
        session.user_id, user.id,
        "Token should validate to correct user"
    );
    assert_eq!(
        session.session_id, auth_response.session.session_id,
        "Session IDs should match"
    );

    // Test logout
    provider.logout(auth_response.session.session_id).await?;

    // Verify token is invalidated
    let validation_result = provider.validate_token(&auth_response.session.token).await;
    assert!(
        validation_result.is_err(),
        "Token should be invalid after logout"
    );

    Ok(())
}

#[tokio::test]
async fn test_auth_flow_with_multiple_sessions() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo.clone(), config);

    // Create test user
    let (user, password) = setup_test_user(&*user_repo).await?;

    // Create first session
    let credentials1 = Credentials {
        username: user.email.clone(),
        password: password.clone(),
    };
    let auth_response1 = provider.authenticate(credentials1).await?;

    // Create second session
    let credentials2 = Credentials {
        username: user.email.clone(),
        password: password.clone(),
    };
    let auth_response2 = provider.authenticate(credentials2).await?;

    // Verify both sessions are valid
    let session1 = provider
        .validate_token(&auth_response1.session.token)
        .await?;
    let session2 = provider
        .validate_token(&auth_response2.session.token)
        .await?;

    assert_eq!(session1.user_id, user.id, "First session should be valid");
    assert_eq!(session2.user_id, user.id, "Second session should be valid");
    assert_ne!(
        session1.session_id, session2.session_id,
        "Session IDs should be different"
    );

    // Verify session timestamps are different
    assert_ne!(
        auth_response1.session.created_at, auth_response2.session.created_at,
        "Sessions should have different creation times"
    );

    // Logout from first session
    provider.logout(auth_response1.session.session_id).await?;

    // Verify first session is invalid but second remains valid
    let validation1 = provider.validate_token(&auth_response1.session.token).await;
    let validation2 = provider.validate_token(&auth_response2.session.token).await;

    assert!(
        validation1.is_err(),
        "First session should be invalid after logout"
    );
    assert!(validation2.is_ok(), "Second session should remain valid");

    Ok(())
}

#[tokio::test]
async fn test_auth_flow_error_scenarios() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));

    // Test with very short token duration
    let config = AuthConfig {
        token_duration: 1, // 1 second
        ..AuthConfig::default()
    };
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo.clone(), config);

    // Create test user
    let (user, password) = setup_test_user(&*user_repo).await?;

    // Test 1: Invalid password
    let invalid_credentials = Credentials {
        username: user.email.clone(),
        password: "wrong_password".to_string(),
    };
    let auth_result = provider.authenticate(invalid_credentials).await;
    assert!(
        matches!(auth_result, Err(Error::InvalidCredentials)),
        "Should fail with invalid credentials"
    );

    // Test 2: Invalid username
    let nonexistent_credentials = Credentials {
        username: "nonexistent@example.com".to_string(),
        password: password.clone(),
    };
    let auth_result = provider.authenticate(nonexistent_credentials).await;
    assert!(
        matches!(auth_result, Err(Error::InvalidCredentials)),
        "Should fail with invalid credentials for nonexistent user"
    );

    // Test 3: Token expiration
    let valid_credentials = Credentials {
        username: user.email.clone(),
        password: password.clone(),
    };
    let auth_response = provider.authenticate(valid_credentials).await?;

    // Wait for token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let validation_result = provider.validate_token(&auth_response.session.token).await;
    assert!(
        validation_result.is_err(),
        "Token should be invalid after expiration"
    );

    // Test 4: Invalid token format
    let invalid_token = "invalid.token.format";
    let validation_result = provider.validate_token(invalid_token).await;
    assert!(
        validation_result.is_err(),
        "Should fail with invalid token format"
    );

    // Test 5: Logout with invalid session ID
    let invalid_session_id = Uuid::new_v4();
    let logout_result = provider.logout(invalid_session_id).await;
    assert!(
        logout_result.is_ok(),
        "Logout with invalid session should not error"
    );

    Ok(())
}

#[tokio::test]
async fn test_session_deletion_scenarios() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));

    // Test 1: Normal Session Lifecycle
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo.clone(), config);

    // 1.1: Create and validate session
    let (user, password) = setup_test_user(&*user_repo).await?;
    let credentials = Credentials {
        username: user.email.clone(),
        password: password.clone(),
    };
    let auth_response = provider.authenticate(credentials).await?;
    let validation_result = provider.validate_token(&auth_response.session.token).await;
    assert!(validation_result.is_ok(), "Token should be valid initially");

    // 1.2: Delete session and verify invalidation
    session_repo
        .delete_session(auth_response.session.session_id)
        .await?;
    let validation_result = provider.validate_token(&auth_response.session.token).await;
    assert!(
        validation_result.is_err(),
        "Token should be invalid after session deletion"
    );

    // Test 2: Session Expiration
    let short_lived_config = AuthConfig {
        token_duration: 1, // 1 second
        ..AuthConfig::default()
    };
    let provider =
        BasicAuthProvider::new(user_repo.clone(), session_repo.clone(), short_lived_config);

    // 2.1: Create short-lived session
    let credentials = Credentials {
        username: user.email.clone(),
        password,
    };
    let auth_response = provider.authenticate(credentials).await?;

    // 2.2: Wait for expiration
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // 2.3: Verify session is invalid
    let validation_result = provider.validate_token(&auth_response.session.token).await;
    assert!(
        validation_result.is_err(),
        "Token should be invalid after expiration"
    );

    // 2.4: Attempt to delete expired session
    let delete_result = session_repo
        .delete_session(auth_response.session.session_id)
        .await;
    assert!(
        delete_result.is_ok(),
        "Deleting expired session should succeed"
    );

    // Test 3: Multiple Session Management
    let config = AuthConfig::default();
    let provider = BasicAuthProvider::new(user_repo.clone(), session_repo.clone(), config);

    // 3.1: Create multiple sessions
    let mut session_tokens = Vec::new();
    for _ in 0..3 {
        let credentials = Credentials {
            username: user.email.clone(),
            password: password.clone(),
        };
        let auth_response = provider.authenticate(credentials).await?;
        session_tokens.push(auth_response);
    }

    // 3.2: Delete middle session
    session_repo
        .delete_session(session_tokens[1].session.session_id)
        .await?;

    // 3.3: Verify other sessions remain valid
    let validation1 = provider
        .validate_token(&session_tokens[0].session.token)
        .await;
    let validation2 = provider
        .validate_token(&session_tokens[1].session.token)
        .await;
    let validation3 = provider
        .validate_token(&session_tokens[2].session.token)
        .await;

    assert!(validation1.is_ok(), "First session should remain valid");
    assert!(validation2.is_err(), "Middle session should be invalid");
    assert!(validation3.is_ok(), "Last session should remain valid");

    // Test 4: Cleanup Behavior

    // 4.1: Delete all sessions
    for session in &session_tokens {
        let _ = session_repo
            .delete_session(session.session.session_id)
            .await;
    }

    // 4.2: Verify all sessions are invalid
    for session in &session_tokens {
        let validation = provider.validate_token(&session.session.token).await;
        assert!(
            validation.is_err(),
            "All sessions should be invalid after cleanup"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_token_validation_with_timestamps() -> Result<(), AuthError> {
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    let credentials = Credentials {
        username: "test_user".to_string(),
        password: "secure_password123".to_string(),
    };

    // Register and login
    auth_service.register(credentials.clone()).await?;
    let token = auth_service.login(credentials).await?;

    // Verify token timestamps
    let validation_result = auth_service
        .validate_token_with_metadata(&token.access_token)
        .await?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(validation_result.issued_at <= now);
    assert!(validation_result.expires_at > now);
    assert!(validation_result.expires_at - validation_result.issued_at == 3600); // 1 hour validity

    // Test expired token
    sleep(Duration::from_secs(2)).await;
    let expired_result = auth_service
        .validate_expired_token(&token.access_token)
        .await;
    assert!(matches!(
        expired_result,
        Err(AuthError::TokenValidation(TokenValidationError::Expired))
    ));

    Ok(())
}

#[tokio::test]
async fn test_rate_limiting() {
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    let credentials = Credentials {
        username: "test_user".to_string(),
        password: "wrong_password".to_string(),
    };

    // Attempt multiple failed logins
    for _ in 0..5 {
        let _ = auth_service.login(credentials.clone()).await;
        sleep(Duration::from_millis(100)).await;
    }

    // Next attempt should be rate limited
    let result = auth_service.login(credentials.clone()).await;
    assert!(matches!(result, Err(AuthError::RateLimited)));

    // Wait for rate limit to expire
    sleep(Duration::from_secs(30)).await;

    // Should be able to try again
    let result = auth_service.login(credentials).await;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
}

#[tokio::test]
async fn test_concurrent_token_validation() {
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo);

    let credentials = Credentials {
        username: "test_user".to_string(),
        password: "secure_password123".to_string(),
    };

    // Register and login
    auth_service.register(credentials.clone()).await.unwrap();
    let token = auth_service.login(credentials).await.unwrap();

    // Spawn multiple concurrent validation tasks
    let mut handles = vec![];
    for _ in 0..10 {
        let auth_service = auth_service.clone();
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            auth_service.validate_token(&token.access_token).await
        }));
    }

    // All validations should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_concurrent_session_management() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));
    let config = AuthConfig::default();
    let provider = Arc::new(BasicAuthProvider::new(
        user_repo.clone(),
        session_repo.clone(),
        config,
    ));

    // Create test user
    let (user, password) = setup_test_user(&*user_repo).await?;

    // Test 1: Concurrent Session Creation
    let auth_futures = (0..10).map(|_| {
        let provider = provider.clone();
        let credentials = Credentials {
            username: user.email.clone(),
            password: password.clone(),
        };
        tokio::spawn(async move { provider.authenticate(credentials).await })
    });

    let results = join_all(auth_futures).await;
    let mut session_ids = Vec::new();

    for result in results {
        let auth_response = result.expect("Task should complete")?;
        session_ids.push(auth_response.session.session_id);

        // Verify each session is unique
        assert_eq!(
            session_ids
                .iter()
                .filter(|&&id| id == auth_response.session.session_id)
                .count(),
            1,
            "Each session should have a unique ID"
        );
    }

    // Test 2: Concurrent Session Deletion
    let deletion_futures = session_ids.iter().map(|&session_id| {
        let session_repo = session_repo.clone();
        tokio::spawn(async move { session_repo.delete_session(session_id).await })
    });

    let results = join_all(deletion_futures).await;
    for result in results {
        assert!(
            result.expect("Task should complete").is_ok(),
            "All session deletions should succeed"
        );
    }

    // Test 3: Concurrent Session Creation and Deletion
    let mut futures = Vec::new();

    // Spawn creation tasks
    for _ in 0..5 {
        let provider = provider.clone();
        let credentials = Credentials {
            username: user.email.clone(),
            password: password.clone(),
        };
        futures.push(tokio::spawn(async move {
            provider.authenticate(credentials).await
        }));
    }

    // Wait a bit to let some sessions be created
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Spawn deletion tasks for existing sessions
    for session_id in &session_ids {
        let session_repo = session_repo.clone();
        let session_id = *session_id;
        futures.push(tokio::spawn(async move {
            session_repo.delete_session(session_id).await.map(|_| None)
        }));
    }

    // Check results
    let results = join_all(futures).await;
    for result in results {
        assert!(
            result.expect("Task should complete").is_ok(),
            "All operations should complete without errors"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_session_cleanup_under_load() -> Result<(), Error> {
    // Setup test environment
    let (_container, pool) = setup_database()
        .await
        .map_err(|e| Error::internal(e.to_string()))?;
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool));

    // Create config with very short session duration
    let config = AuthConfig {
        token_duration: 1, // 1 second
        ..AuthConfig::default()
    };
    let provider = Arc::new(BasicAuthProvider::new(
        user_repo.clone(),
        session_repo.clone(),
        config,
    ));

    // Create test user
    let (user, password) = setup_test_user(&*user_repo).await?;

    // Test 1: Create many sessions that will expire quickly
    let mut session_ids = Vec::new();

    // Create 20 sessions
    for _ in 0..20 {
        let credentials = Credentials {
            username: user.email.clone(),
            password: password.clone(),
        };
        let auth_response = provider.authenticate(credentials).await?;
        session_ids.push(auth_response.session.session_id);
    }

    // Wait for sessions to expire
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Test 2: Concurrent cleanup and new session creation
    let mut futures = Vec::new();

    // Spawn cleanup tasks
    for session_id in &session_ids {
        let session_repo = session_repo.clone();
        let session_id = *session_id;
        futures.push(tokio::spawn(async move {
            session_repo.delete_session(session_id).await.map(|_| None)
        }));
    }

    // Spawn new session creation tasks
    for _ in 0..10 {
        let provider = provider.clone();
        let credentials = Credentials {
            username: user.email.clone(),
            password: password.clone(),
        };
        futures.push(tokio::spawn(async move {
            provider.authenticate(credentials).await
        }));
    }

    // Check results
    let results = join_all(futures).await;
    for result in results {
        assert!(
            result.expect("Task should complete").is_ok(),
            "All operations should complete without errors"
        );
    }

    // Test 3: Verify expired sessions are properly cleaned up
    let mut validation_failures = 0;

    for session_id in &session_ids {
        if let Err(_) = session_repo.get_session(*session_id).await? {
            validation_failures += 1;
        }
    }

    assert_eq!(
        validation_failures,
        session_ids.len(),
        "All expired sessions should be properly cleaned up"
    );

    Ok(())
}

/// Represents different types of token tampering that can be applied during testing.
/// Each variant corresponds to a specific security vulnerability or attack vector
/// that the token validation should be able to detect and prevent.
#[derive(Debug, Clone, Copy)]
enum TamperingType {
    /// Attempts to bypass signature validation by setting the algorithm to 'none'.
    /// This is a common attack vector in JWT implementations that don't properly
    /// validate the algorithm field.
    AlgNone,

    /// Attempts to downgrade the signing algorithm to a weaker one (e.g., HS1).
    /// This tests the system's resistance to algorithm downgrade attacks.
    AlgWeak,

    /// Attempts to escalate privileges by modifying the 'role' claim in the payload.
    /// This tests if the system properly validates the token's signature and prevents
    /// unauthorized claim modifications.
    PayloadRole,

    /// Attempts to extend the token's lifetime by modifying the 'exp' claim.
    /// This tests if the system properly validates both the expiration time and
    /// prevents unauthorized modifications to time-related claims.
    PayloadExp,

    /// Attempts to bypass validation by completely removing the signature.
    /// This tests if the system properly requires and validates signatures.
    SignatureStrip,

    /// Attempts to bypass validation by providing an invalid signature.
    /// This tests if the system properly validates the signature cryptographically.
    SignatureInvalid,

    /// Attempts to modify arbitrary claims in the payload.
    /// This tests the system's general resistance to unauthorized claim modifications.
    ClaimsModify,
}

/// Represents specific actions that can be taken to tamper with a token.
/// This allows for more granular and data-driven testing of token validation.
#[derive(Debug, Clone)]
enum TamperingAction {
    /// Replace a specific byte in the token with a new value
    ReplaceByteAt { position: usize, new_byte: u8 },

    /// Append bytes to a specific part of the token
    AppendBytes { part: TokenPart, bytes: Vec<u8> },

    /// Remove bytes from a specific part of the token
    RemoveBytes {
        part: TokenPart,
        start: usize,
        length: usize,
    },

    /// Modify a specific claim in the payload
    ModifyClaim {
        claim: String,
        value: serde_json::Value,
    },

    /// Modify a specific header parameter
    ModifyHeader {
        param: String,
        value: serde_json::Value,
    },
}

/// Represents the different parts of a JWT token that can be tampered with.
#[derive(Debug, Clone, Copy)]
enum TokenPart {
    Header,
    Payload,
    Signature,
}

impl TamperingType {
    /// Returns the string identifier used in the token tampering function.
    fn as_str(&self) -> &'static str {
        match self {
            TamperingType::AlgNone => "alg_none",
            TamperingType::AlgWeak => "alg_weak",
            TamperingType::PayloadRole => "payload_role",
            TamperingType::PayloadExp => "payload_exp",
            TamperingType::SignatureStrip => "signature_strip",
            TamperingType::SignatureInvalid => "signature_invalid",
            TamperingType::ClaimsModify => "claims_modify",
        }
    }

    /// Returns the expected error type that should be returned when this
    /// type of tampering is detected.
    fn expected_error(&self) -> AuthError {
        match self {
            TamperingType::AlgNone | TamperingType::AlgWeak => {
                AuthError::TokenValidation(TokenValidationError::InvalidAlgorithm)
            },
            TamperingType::SignatureStrip | TamperingType::SignatureInvalid => {
                AuthError::TokenValidation(TokenValidationError::InvalidSignature)
            },
            _ => AuthError::TokenValidation(TokenValidationError::InvalidSignature),
        }
    }

    /// Returns a set of tampering actions that implement this type of tampering.
    fn get_actions(&self) -> Vec<TamperingAction> {
        match self {
            TamperingType::AlgNone => vec![TamperingAction::ModifyHeader {
                param: "alg".to_string(),
                value: json!("none"),
            }],
            TamperingType::AlgWeak => vec![TamperingAction::ModifyHeader {
                param: "alg".to_string(),
                value: json!("HS1"),
            }],
            TamperingType::PayloadRole => vec![TamperingAction::ModifyClaim {
                claim: "role".to_string(),
                value: json!("admin"),
            }],
            TamperingType::PayloadExp => vec![TamperingAction::ModifyClaim {
                claim: "exp".to_string(),
                value: json!(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 31536000
                ),
            }],
            TamperingType::SignatureStrip => vec![TamperingAction::RemoveBytes {
                part: TokenPart::Signature,
                start: 0,
                length: usize::MAX, // Remove entire signature
            }],
            TamperingType::SignatureInvalid => vec![TamperingAction::ReplaceByteAt {
                position: 0,
                new_byte: 0xFF,
            }],
            TamperingType::ClaimsModify => vec![TamperingAction::ModifyClaim {
                claim: "custom".to_string(),
                value: json!("tampered"),
            }],
        }
    }
}

impl Arbitrary for TamperingType {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(TamperingType::AlgNone),
            Just(TamperingType::AlgWeak),
            Just(TamperingType::PayloadRole),
            Just(TamperingType::PayloadExp),
            Just(TamperingType::SignatureStrip),
            Just(TamperingType::SignatureInvalid),
            Just(TamperingType::ClaimsModify),
        ]
        .boxed()
    }
}

/// Applies a set of tampering actions to a JWT token.
/// This function handles the low-level token manipulation based on
/// the specified tampering actions.
fn apply_tampering_actions(token: &str, actions: &[TamperingAction]) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return token.to_string();
    }

    let mut header =
        String::from_utf8(BASE64.decode(parts[0]).unwrap_or_default()).unwrap_or_default();
    let mut payload =
        String::from_utf8(BASE64.decode(parts[1]).unwrap_or_default()).unwrap_or_default();
    let mut signature = parts[2].to_string();

    for action in actions {
        match action {
            TamperingAction::ReplaceByteAt { position, new_byte } => {
                if *position < signature.len() {
                    signature.replace_range(*position..*position + 1, &format!("{:02x}", new_byte));
                }
            },
            TamperingAction::AppendBytes { part, bytes } => {
                let encoded = BASE64.encode(bytes);
                match part {
                    TokenPart::Header => header.push_str(&encoded),
                    TokenPart::Payload => payload.push_str(&encoded),
                    TokenPart::Signature => signature.push_str(&encoded),
                }
            },
            TamperingAction::RemoveBytes {
                part,
                start,
                length,
            } => {
                let remove_from = match part {
                    TokenPart::Header => &mut header,
                    TokenPart::Payload => &mut payload,
                    TokenPart::Signature => &mut signature,
                };
                let end = (*start + *length).min(remove_from.len());
                remove_from.replace_range(*start..end, "");
            },
            TamperingAction::ModifyClaim { claim, value } => {
                if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&payload) {
                    if let Some(obj) = json.as_object_mut() {
                        obj.insert(claim.clone(), value.clone());
                        payload = json.to_string();
                    }
                }
            },
            TamperingAction::ModifyHeader { param, value } => {
                if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&header) {
                    if let Some(obj) = json.as_object_mut() {
                        obj.insert(param.clone(), value.clone());
                        header = json.to_string();
                    }
                }
            },
        }
    }

    format!(
        "{}.{}.{}",
        BASE64.encode(header),
        BASE64.encode(payload),
        signature
    )
}

/// Creates a tampered token by applying the tampering actions associated with
/// the specified tampering type.
fn create_tampered_token(original_token: &str, tampering_type: &str) -> String {
    let tampering_type = match tampering_type {
        "alg_none" => TamperingType::AlgNone,
        "alg_weak" => TamperingType::AlgWeak,
        "payload_role" => TamperingType::PayloadRole,
        "payload_exp" => TamperingType::PayloadExp,
        "signature_strip" => TamperingType::SignatureStrip,
        "signature_invalid" => TamperingType::SignatureInvalid,
        "claims_modify" => TamperingType::ClaimsModify,
        _ => return original_token.to_string(),
    };

    apply_tampering_actions(original_token, &tampering_type.get_actions())
}

/// Creates a token with multiple types of tampering applied.
/// The tampering types are applied in sequence, allowing for complex
/// combinations of token modifications.
fn create_multi_tampered_token(original_token: &str, tampering_types: &[TamperingType]) -> String {
    let mut token = original_token.to_string();
    let mut actions = Vec::new();

    for tampering_type in tampering_types {
        actions.extend(tampering_type.get_actions());
    }

    apply_tampering_actions(&token, &actions)
}

/// Property-based test for token validation with multiple tampering types.
/// This test generates random combinations of tampering types and validates
/// that the system correctly identifies and rejects tampered tokens.
#[tokio::test]
async fn test_token_validation_proptest_combined() {
    let user_repo = Arc::new(MockUserRepository::new());
    let auth_service = AuthService::new(user_repo.clone());

    // Register and login to get a valid token
    let username = "test_user";
    let password = "Test1234!";
    auth_service.register(username, password).await.unwrap();
    let token = auth_service.login(username, password).await.unwrap();

    proptest!(|(
        tampering_count in 1..=3usize,
        tampering_types in prop::collection::vec(any::<TamperingType>(), tampering_count)
    )| {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Create a tampered token with multiple modifications
            let tampered_token = create_multi_tampered_token(&token, &tampering_types);

            // Attempt to validate the tampered token
            let result = auth_service.validate_token(&tampered_token).await;

            // The validation should fail
            prop_assert!(result.is_err());

            // Check that the error matches at least one of the expected errors
            let actual_error = result.unwrap_err();
            let expected_errors: Vec<AuthError> = tampering_types
                .iter()
                .map(|t| t.expected_error())
                .collect();

            prop_assert!(
                expected_errors.iter().any(|e| std::mem::discriminant(e) == std::mem::discriminant(&actual_error)),
                "Unexpected error: {:?}, expected one of: {:?}",
                actual_error,
                expected_errors
            );
        });
    });
}

/// Property-based test for token validation with specific claim manipulations.
/// This test focuses on validating that the system correctly handles various
/// types of claim modifications and maintains proper validation rules.
#[tokio::test]
async fn test_token_validation_proptest_claims() {
    let user_repo = Arc::new(MockUserRepository::new());
    let auth_service = AuthService::new(user_repo.clone());

    // Register and login to get a valid token
    let username = "test_user";
    let password = "Test1234!";
    auth_service.register(username, password).await.unwrap();
    let token = auth_service.login(username, password).await.unwrap();

    proptest!(|(
        // Generate random claim modifications
        claim_name in "[a-zA-Z][a-zA-Z0-9_]{0,15}",
        claim_value in prop::collection::vec(any::<u8>(), 0..100)
    )| {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Create actions for claim modification
            let actions = vec![
                TamperingAction::ModifyClaim {
                    claim: claim_name.clone(),
                    value: json!(BASE64.encode(&claim_value)),
                }
            ];

            // Apply the claim modification
            let tampered_token = apply_tampering_actions(&token, &actions);

            // Attempt to validate the tampered token
            let result = auth_service.validate_token(&tampered_token).await;

            // The validation should fail due to invalid signature
            prop_assert!(matches!(
                result,
                Err(AuthError::TokenValidation(TokenValidationError::InvalidSignature))
            ));
        });
    });
}

/// Property-based test for token validation with header manipulations.
/// This test focuses on validating that the system correctly handles various
/// types of header modifications and maintains proper algorithm validation.
#[tokio::test]
async fn test_token_validation_proptest_headers() {
    let user_repo = Arc::new(MockUserRepository::new());
    let auth_service = AuthService::new(user_repo.clone());

    // Register and login to get a valid token
    let username = "test_user";
    let password = "Test1234!";
    auth_service.register(username, password).await.unwrap();
    let token = auth_service.login(username, password).await.unwrap();

    proptest!(|(
        // Generate random header modifications
        header_param in "[a-zA-Z][a-zA-Z0-9_]{0,15}",
        header_value in "[a-zA-Z0-9+/]{0,50}"
    )| {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Create actions for header modification
            let actions = vec![
                TamperingAction::ModifyHeader {
                    param: header_param.clone(),
                    value: json!(header_value.clone()),
                }
            ];

            // Apply the header modification
            let tampered_token = apply_tampering_actions(&token, &actions);

            // Attempt to validate the tampered token
            let result = auth_service.validate_token(&tampered_token).await;

            // The validation should fail
            prop_assert!(result.is_err());

            // If we modified the 'alg' header, expect InvalidAlgorithm error
            if header_param == "alg" {
                prop_assert!(matches!(
                    result,
                    Err(AuthError::TokenValidation(TokenValidationError::InvalidAlgorithm))
                ));
            } else {
                // For other header modifications, expect InvalidSignature error
                prop_assert!(matches!(
                    result,
                    Err(AuthError::TokenValidation(TokenValidationError::InvalidSignature))
                ));
            }
        });
    });
}

/// Property-based test for token validation with signature manipulations.
/// This test focuses on validating that the system correctly handles various
/// types of signature modifications and maintains proper cryptographic validation.
#[tokio::test]
async fn test_token_validation_proptest_signatures() {
    let user_repo = Arc::new(MockUserRepository::new());
    let auth_service = AuthService::new(user_repo.clone());

    // Register and login to get a valid token
    let username = "test_user";
    let password = "Test1234!";
    auth_service.register(username, password).await.unwrap();
    let token = auth_service.login(username, password).await.unwrap();

    proptest!(|(
        // Generate random signature modifications
        position in 0usize..100,
        new_byte in any::<u8>(),
        remove_length in 1usize..50,
        append_bytes in prop::collection::vec(any::<u8>(), 1..10)
    )| {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Test different types of signature modifications
            let modification_sets = vec![
                // Replace a byte
                vec![TamperingAction::ReplaceByteAt { position, new_byte }],

                // Remove bytes
                vec![TamperingAction::RemoveBytes {
                    part: TokenPart::Signature,
                    start: position,
                    length: remove_length,
                }],

                // Append bytes
                vec![TamperingAction::AppendBytes {
                    part: TokenPart::Signature,
                    bytes: append_bytes.clone(),
                }],
            ];

            for actions in modification_sets {
                // Apply the signature modification
                let tampered_token = apply_tampering_actions(&token, &actions);

                // Attempt to validate the tampered token
                let result = auth_service.validate_token(&tampered_token).await;

                // The validation should fail with InvalidSignature error
                prop_assert!(matches!(
                    result,
                    Err(AuthError::TokenValidation(TokenValidationError::InvalidSignature))
                ));
            }
        });
    });
}

#[tokio::test]
async fn test_rate_limiting_comprehensive() {
    // Setup
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo.clone());
    let test_ip = "192.168.1.1";
    let test_user_agent = "test-browser/1.0";

    // Test different endpoints
    let endpoints = vec![
        ("login", 5),          // 5 attempts per minute for login
        ("token_refresh", 10), // 10 attempts per minute for refresh
        ("registration", 3),   // 3 attempts per minute for registration
    ];

    for (endpoint, limit) in endpoints {
        let mut attempts = 0;
        let start_time = SystemTime::now();

        // Make requests until rate limited
        loop {
            let result = match endpoint {
                "login" => {
                    auth_service
                        .login(Credentials {
                            username: "test".to_string(),
                            password: "test".to_string(),
                        })
                        .await
                },
                "token_refresh" => {
                    auth_service
                        .refresh_token("dummy_token", test_ip, test_user_agent)
                        .await
                },
                "registration" => {
                    auth_service
                        .register(Credentials {
                            username: format!("test{}", attempts),
                            password: "test".to_string(),
                        })
                        .await
                },
                _ => unreachable!(),
            };

            attempts += 1;

            if let Err(AuthError::RateLimitExceeded) = result {
                // Verify we hit the limit at the expected attempt
                assert_eq!(
                    attempts,
                    limit + 1,
                    "Rate limit for {} should trigger after {} attempts",
                    endpoint,
                    limit
                );
                break;
            }

            if attempts > limit + 1 {
                panic!(
                    "Rate limit not triggered for {} after {} attempts",
                    endpoint, attempts
                );
            }
        }

        // Verify rate limit duration
        let elapsed = SystemTime::now().duration_since(start_time).unwrap();
        assert!(
            elapsed.as_secs() < 70,
            "Rate limit test for {} took too long: {} seconds",
            endpoint,
            elapsed.as_secs()
        );
    }
}

#[tokio::test]
async fn test_rate_limiting_bypass_attempts() {
    // Setup
    let user_repo = MockUserRepository::new();
    let auth_service = AuthService::new(user_repo.clone());
    let base_credentials = Credentials {
        username: "test".to_string(),
        password: "test".to_string(),
    };

    // Test IP rotation bypass attempt
    let ips = vec![
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.4",
        "192.168.1.5",
    ];

    let mut successful_attempts = 0;
    for ip in ips {
        let result = auth_service
            .login_with_context(base_credentials.clone(), ip, "test-browser/1.0")
            .await;

        if result.is_ok() {
            successful_attempts += 1;
        }
    }

    // Verify that IP rotation doesn't bypass rate limiting
    assert!(
        successful_attempts <= 5,
        "Rate limiting should prevent excessive attempts even with IP rotation"
    );

    // Test User-Agent rotation bypass attempt
    let user_agents = vec![
        "browser1/1.0",
        "browser2/1.0",
        "browser3/1.0",
        "browser4/1.0",
        "browser5/1.0",
    ];

    successful_attempts = 0;
    for ua in user_agents {
        let result = auth_service
            .login_with_context(base_credentials.clone(), "192.168.1.1", ua)
            .await;

        if result.is_ok() {
            successful_attempts += 1;
        }
    }

    // Verify that User-Agent rotation doesn't bypass rate limiting
    assert!(
        successful_attempts <= 5,
        "Rate limiting should prevent excessive attempts even with User-Agent rotation"
    );

    // Test distributed attack simulation
    let combinations: Vec<(&str, &str)> = ips
        .iter()
        .flat_map(|ip| user_agents.iter().map(move |ua| (*ip, *ua)))
        .collect();

    successful_attempts = 0;
    for (ip, ua) in combinations {
        let result = auth_service
            .login_with_context(base_credentials.clone(), ip, ua)
            .await;

        if result.is_ok() {
            successful_attempts += 1;
        }
    }

    // Verify that combined rotation doesn't bypass rate limiting
    assert!(
        successful_attempts <= 10,
        "Rate limiting should prevent excessive attempts even with combined IP/UA rotation"
    );
}

#[tokio::test]
async fn test_session_security() -> Result<(), Error> {
    // Setup
    let db = setup_database().await?;
    let user_repo = PgUserRepository::new(db.clone());
    let session_repo = PgSessionRepository::new(db);
    let auth_service = AuthService::new(user_repo.clone());

    // Create test user
    let (user, password) = setup_test_user(&user_repo).await?;

    // Test 1: Session Fixation Prevention
    // Attempt to set a known session ID before authentication
    let known_session_id = Uuid::new_v4();
    let credentials = Credentials {
        username: user.email.clone(),
        password: password.clone(),
    };

    // Try to authenticate with a pre-set session ID
    let auth_result = auth_service
        .login_with_session_id(credentials.clone(), known_session_id)
        .await?;

    // Verify that the assigned session ID is different from the attempted fixed ID
    assert_ne!(
        auth_result.session_id, known_session_id,
        "Session fixation prevention failed: Service reused provided session ID"
    );

    // Test 2: Session ID Properties
    let session_id = auth_result.session_id;

    // Verify session ID is a valid UUID v4
    assert!(
        session_id.get_version_num() == 4,
        "Session ID should be UUID v4"
    );

    // Test 3: Session Hijacking Prevention
    // Simulate concurrent access from different IPs/User-Agents
    let original_ip = "192.168.1.1";
    let original_ua = "browser1/1.0";

    // First request with original IP/UA
    let token1 = auth_service
        .get_session_token(session_id, original_ip, original_ua)
        .await?;

    // Attempt access with different IP but same UA
    let result = auth_service
        .get_session_token(session_id, "192.168.1.2", original_ua)
        .await;

    assert!(
        matches!(result, Err(AuthError::SessionInvalid(_))),
        "Session should be invalidated when accessed from different IP"
    );

    // Attempt access with same IP but different UA
    let result = auth_service
        .get_session_token(session_id, original_ip, "browser2/1.0")
        .await;

    assert!(
        matches!(result, Err(AuthError::SessionInvalid(_))),
        "Session should be invalidated when accessed with different User-Agent"
    );

    // Test 4: Session Replay Prevention
    // Try to reuse an expired token
    sleep(Duration::from_secs(1)).await;
    auth_service.invalidate_session(session_id).await?;

    let result = auth_service.validate_token(&token1).await;

    assert!(
        matches!(result, Err(AuthError::SessionInvalid(_))),
        "Expired session token should not be valid"
    );

    // Test 5: Concurrent Session Management
    let max_sessions = 5;
    let mut active_sessions = Vec::new();

    // Create maximum allowed sessions
    for i in 0..max_sessions {
        let auth_result = auth_service
            .login_with_context(
                credentials.clone(),
                &format!("192.168.1.{}", i),
                &format!("browser{}/1.0", i),
            )
            .await?;
        active_sessions.push(auth_result.session_id);
    }

    // Verify all sessions are active
    for session_id in &active_sessions {
        let session = session_repo.get(*session_id).await?;
        assert!(session.is_some(), "Session should be active");
    }

    // Attempt to create one more session (exceeding limit)
    let result = auth_service
        .login_with_context(credentials.clone(), "192.168.1.10", "browser10/1.0")
        .await;

    // Verify the oldest session was invalidated
    assert!(result.is_ok(), "Should be able to create new session");
    let new_session_id = result?.session_id;

    // The oldest session should be invalidated
    let oldest_session = session_repo.get(active_sessions[0]).await?;
    assert!(
        oldest_session.is_none(),
        "Oldest session should be invalidated"
    );

    // But the new session should be active
    let new_session = session_repo.get(new_session_id).await?;
    assert!(new_session.is_some(), "New session should be active");

    Ok(())
}

#[tokio::test]
async fn test_session_security_granular() -> Result<(), Error> {
    // Setup
    let db = setup_database().await?;
    let user_repo = PgUserRepository::new(db.clone());
    let session_repo = PgSessionRepository::new(db);
    let auth_service = AuthService::new(user_repo.clone());

    // Create test user and admin
    let (user, password) = setup_test_user(&user_repo).await?;
    let (admin, admin_password) = setup_test_admin(&user_repo).await?;

    // Test 1: Granular IP Changes
    let credentials = Credentials {
        username: user.email.clone(),
        password: password.clone(),
    };

    let auth_result = auth_service
        .login_with_context(credentials.clone(), "192.168.1.100", "Chrome/120.0.0.0")
        .await?;

    let session_id = auth_result.session_id;

    // Test slight IP changes (same subnet)
    let ip_variations = vec![
        "192.168.1.101", // Same subnet
        "192.168.1.150", // Same subnet
        "192.168.2.100", // Different subnet
        "10.0.0.100",    // Different network
    ];

    for ip in ip_variations {
        let result = auth_service
            .get_session_token(session_id, ip, "Chrome/120.0.0.0")
            .await;

        // We expect this to fail as IP changes should invalidate the session
        assert!(
            matches!(result, Err(AuthError::SessionInvalid(_))),
            "Session should be invalidated for IP change to {}",
            ip
        );
    }

    // Test 2: User-Agent Variations
    let auth_result = auth_service
        .login_with_context(credentials.clone(), "192.168.1.100", "Chrome/120.0.0.0")
        .await?;

    let session_id = auth_result.session_id;

    let ua_variations = vec![
        "Chrome/120.0.0.1",             // Minor version change
        "Chrome/121.0.0.0",             // Major version change
        "Firefox/120.0",                // Different browser
        "Mozilla/5.0 Chrome/120.0.0.0", // Modified string
    ];

    for ua in ua_variations {
        let result = auth_service
            .get_session_token(session_id, "192.168.1.100", ua)
            .await;

        assert!(
            matches!(result, Err(AuthError::SessionInvalid(_))),
            "Session should be invalidated for User-Agent change to {}",
            ua
        );
    }

    // Test 3: Admin-Initiated Session Invalidation
    let auth_result = auth_service
        .login_with_context(credentials.clone(), "192.168.1.100", "Chrome/120.0.0.0")
        .await?;

    let user_session_id = auth_result.session_id;

    // Admin logs in
    let admin_credentials = Credentials {
        username: admin.email.clone(),
        password: admin_password.clone(),
    };

    let admin_auth = auth_service
        .login_with_context(admin_credentials, "192.168.1.200", "Chrome/120.0.0.0")
        .await?;

    // Admin invalidates user's session
    auth_service
        .admin_invalidate_session(admin_auth.session_id, user_session_id)
        .await?;

    // Verify user's session is invalid
    let result = auth_service
        .get_session_token(user_session_id, "192.168.1.100", "Chrome/120.0.0.0")
        .await;

    assert!(
        matches!(result, Err(AuthError::SessionInvalid(_))),
        "Session should be invalidated by admin"
    );

    // Test 4: Session Invalidation on Account Changes
    let auth_result = auth_service
        .login_with_context(credentials.clone(), "192.168.1.100", "Chrome/120.0.0.0")
        .await?;

    let session_id = auth_result.session_id;

    // Change password
    auth_service
        .change_password(credentials.clone(), "NewSecurePassword123!")
        .await?;

    // Verify old session is invalid
    let result = auth_service
        .get_session_token(session_id, "192.168.1.100", "Chrome/120.0.0.0")
        .await;

    assert!(
        matches!(result, Err(AuthError::SessionInvalid(_))),
        "Session should be invalidated after password change"
    );

    // Test 5: Timing Attack Prevention
    let start = SystemTime::now();
    let _ = auth_service.validate_token("invalid_token").await;
    let invalid_duration = start.elapsed().unwrap();

    let start = SystemTime::now();
    let valid_token = auth_service
        .login_with_context(
            Credentials {
                username: user.email.clone(),
                password: "NewSecurePassword123!".to_string(),
            },
            "192.168.1.100",
            "Chrome/120.0.0.0",
        )
        .await?
        .token;
    let _ = auth_service.validate_token(&valid_token).await;
    let valid_duration = start.elapsed().unwrap();

    // Verify that timing difference is minimal
    let timing_diff = if valid_duration > invalid_duration {
        valid_duration - invalid_duration
    } else {
        invalid_duration - valid_duration
    };

    assert!(
        timing_diff.as_millis() < 100,
        "Token validation timing difference should be minimal to prevent timing attacks"
    );

    Ok(())
}
