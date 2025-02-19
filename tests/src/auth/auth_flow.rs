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
use metrics::{counter, Counter};
use once_cell::sync::Lazy;
use proptest::prelude::*;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::helpers::{auth, clock::TestClock, db::setup_database};
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

/// Metrics for rate limiting tests
static RATE_LIMIT_METRICS: Lazy<RateLimitMetrics> = Lazy::new(|| RateLimitMetrics::new());

struct RateLimitMetrics {
    attempts: Counter,
    exceeded: Counter,
    reset: Counter,
}

impl RateLimitMetrics {
    fn new() -> Self {
        Self {
            attempts: counter!(
                "rate_limit_attempts_total",
                "Total number of rate-limited endpoint attempts"
            ),
            exceeded: counter!(
                "rate_limit_exceeded_total",
                "Total number of rate limit exceeded events"
            ),
            reset: counter!(
                "rate_limit_reset_total",
                "Total number of rate limit reset events"
            ),
        }
    }

    fn record_attempt(&self) {
        self.attempts.increment(1);
    }

    fn record_exceeded(&self) {
        self.exceeded.increment(1);
    }

    fn record_reset(&self) {
        self.reset.increment(1);
    }
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
        .expect("System time should be after Unix epoch")
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
                .expect("System time should be after Unix epoch")
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
    let clock = TestClock::new();
    let auth_service = AuthService::new_with_clock(user_repo.clone(), clock.clone());

    // Register and login to get a token
    let credentials = Credentials {
        username: "testuser".to_string(),
        password: "Test123!@#".to_string(),
    };
    let _ = auth_service.register(credentials.clone()).await?;
    let auth_result = auth_service.login(credentials).await?;

    // Simulate token expiration by advancing the clock
    clock.advance(Duration::from_secs(3601)); // Advance by 1 hour and 1 second to ensure expiration

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
    auth_service
        .register(valid_credentials)
        .await
        .expect("User registration should succeed");

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
    let clock = TestClock::new();

    // Test with very short token duration
    let config = AuthConfig {
        token_duration: 3600, // 1 hour
        ..AuthConfig::default()
    };
    let provider = BasicAuthProvider::new_with_clock(
        user_repo.clone(),
        session_repo.clone(),
        config,
        clock.clone(),
    );

    // Create test user
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
    let now = clock
        .now()
        .duration_since(UNIX_EPOCH)
        .expect("Test clock time should be after Unix epoch")
        .as_secs();
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
    let clock = TestClock::new();

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
    let clock = TestClock::new();

    // Test with very short token duration
    let config = AuthConfig {
        token_duration: 3600, // 1 hour
        ..AuthConfig::default()
    };
    let provider = BasicAuthProvider::new_with_clock(
        user_repo.clone(),
        session_repo.clone(),
        config,
        clock.clone(),
    );

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

    // Advance clock past token expiration
    clock.advance(Duration::from_secs(3601)); // Advance by 1 hour and 1 second to ensure expiration

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
    let clock = TestClock::new();

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
        token_duration: 3600, // 1 hour
        ..AuthConfig::default()
    };
    let provider = BasicAuthProvider::new_with_clock(
        user_repo.clone(),
        session_repo.clone(),
        short_lived_config,
        clock.clone(),
    );

    // 2.1: Create short-lived session
    let credentials = Credentials {
        username: user.email.clone(),
        password,
    };
    let auth_response = provider.authenticate(credentials).await?;

    // 2.2: Advance clock past expiration
    clock.advance(Duration::from_secs(3601)); // Advance by 1 hour and 1 second to ensure expiration

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
    let clock = TestClock::new();
    let auth_service = AuthService::new(user_repo, clock.clone());

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

    let now = clock
        .now()
        .duration_since(UNIX_EPOCH)
        .expect("Test clock time should be after Unix epoch")
        .as_secs();
    assert!(validation_result.issued_at <= now);
    assert!(validation_result.expires_at > now);
    assert!(validation_result.expires_at - validation_result.issued_at == 3600); // 1 hour validity

    // Test expired token
    clock.advance(Duration::from_secs(3601)); // Advance past token expiration
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
    let clock = TestClock::new();
    let auth_service = AuthService::new(user_repo, clock.clone());

    let credentials = Credentials {
        username: "test_user".to_string(),
        password: "wrong_password".to_string(),
    };

    // Attempt multiple failed logins
    for _ in 0..5 {
        let _ = auth_service.login(credentials.clone()).await;
        clock.advance(Duration::from_millis(100));
    }

    // Next attempt should be rate limited
    let result = auth_service.login(credentials.clone()).await;
    assert!(matches!(result, Err(AuthError::RateLimited)));

    // Wait for rate limit to expire
    clock.advance(Duration::from_secs(30));

    // Should be able to try again
    let result = auth_service.login(credentials).await;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
}

#[tokio::test]
async fn test_concurrent_token_validation() {
    let user_repo = MockUserRepository::new();
    let clock = TestClock::new();
    let auth_service = AuthService::new(user_repo, clock.clone());

    let credentials = Credentials {
        username: "test_user".to_string(),
        password: "secure_password123".to_string(),
    };

    // Register and login
    auth_service
        .register(credentials.clone())
        .await
        .expect("Initial user registration should succeed");
    let token = auth_service
        .login(credentials)
        .await
        .expect("Login should succeed after registration");

    // Spawn multiple concurrent validation tasks
    let mut handles = vec![];
    for _ in 0..10 {
        let auth_service = auth_service.clone();
        let token = token.clone();
        let clock = clock.clone();
        handles.push(tokio::spawn(async move {
            clock.advance(Duration::from_millis(rand::random::<u64>() % 100));
            auth_service.validate_token(&token.access_token).await
        }));
    }

    // All validations should succeed
    for handle in handles {
        let result = handle.await.expect("Concurrent operation should complete");
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
    let clock = TestClock::new();
    let config = AuthConfig::default();
    let provider = Arc::new(BasicAuthProvider::new(
        user_repo.clone(),
        session_repo.clone(),
        config,
        clock.clone(),
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
        let clock = clock.clone();
        tokio::spawn(async move {
            clock.advance(Duration::from_millis(rand::random::<u64>() % 100));
            provider.authenticate(credentials).await
        })
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
        let clock = clock.clone();
        tokio::spawn(async move {
            clock.advance(Duration::from_millis(rand::random::<u64>() % 100));
            session_repo.delete_session(session_id).await
        })
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
        let clock = clock.clone();
        futures.push(tokio::spawn(async move {
            clock.advance(Duration::from_millis(rand::random::<u64>() % 100));
            provider.authenticate(credentials).await
        }));
    }

    // Simulate time passing
    clock.advance(Duration::from_millis(50));

    // Spawn deletion tasks for existing sessions
    for session_id in &session_ids {
        let session_repo = session_repo.clone();
        let session_id = *session_id;
        let clock = clock.clone();
        futures.push(tokio::spawn(async move {
            clock.advance(Duration::from_millis(rand::random::<u64>() % 100));
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
    let clock = TestClock::new();

    // Create config with very short session duration
    let config = AuthConfig {
        token_duration: 3600, // 1 hour
        ..AuthConfig::default()
    };
    let provider = Arc::new(BasicAuthProvider::new_with_clock(
        user_repo.clone(),
        session_repo.clone(),
        config,
        clock.clone(),
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
        clock.advance(Duration::from_millis(10)); // Small time increment between sessions
    }

    // Wait for sessions to expire
    clock.advance(Duration::from_secs(2));

    // Test 2: Concurrent cleanup and new session creation
    let mut futures = Vec::new();

    // Spawn cleanup tasks
    for session_id in &session_ids {
        let session_repo = session_repo.clone();
        let session_id = *session_id;
        let clock = clock.clone();
        futures.push(tokio::spawn(async move {
            clock.advance(Duration::from_millis(rand::random::<u64>() % 100));
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
        let clock = clock.clone();
        futures.push(tokio::spawn(async move {
            clock.advance(Duration::from_millis(rand::random::<u64>() % 100));
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
