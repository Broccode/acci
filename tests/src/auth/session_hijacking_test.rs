use crate::mocks::{MockSessionRepository, MockUserRepository};
use acci_auth::AuthService;
use acci_core::{
    auth::{AuthError, Credentials},
    error::Error,
    models::User,
};
use acci_db::models::Session;
use mockall::predicate::eq;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// Tests for advanced session hijacking scenarios
#[tokio::test]
async fn test_session_token_reuse() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    let mut session_repo = MockSessionRepository::new();
    let now = OffsetDateTime::now_utc();
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();

    // Setup test user
    let test_user = User {
        id: user_id,
        username: "test.user@example.com".to_string(),
        email: "test.user@example.com".to_string(),
        password_hash: "hashed_password".to_string(),
        is_admin: false,
        created_at: now,
        updated_at: now,
    };

    user_repo
        .expect_get_user_by_username()
        .with(eq(&test_user.username))
        .returning(move |_| Ok(Some(test_user.clone())));

    let token = "test_token".to_string();
    let expires_at = now + time::Duration::hours(24);

    session_repo
        .expect_create_session()
        .with(eq(user_id), eq(token.as_str()), eq(expires_at))
        .returning(move |user_id, token, expires_at| {
            Ok(Session {
                id: session_id,
                user_id,
                token: token.to_string(),
                created_at: now,
                expires_at,
            })
        });

    session_repo
        .expect_delete_session()
        .with(eq(session_id))
        .returning(|_| Ok(()));

    session_repo
        .expect_get_session()
        .with(eq(session_id))
        .returning(|_| Ok(None));

    let auth_service = AuthService::new(Arc::new(user_repo), Arc::new(session_repo));

    // Test 1: Token Reuse After Logout
    let credentials = Credentials {
        username: test_user.username.clone(),
        password: "test_password".to_string(),
    };

    let auth_result = auth_service.authenticate(&credentials).await?;
    let token = auth_result.token.clone();

    // Logout
    auth_service.logout(auth_result.session_id).await?;

    // Attempt to reuse token
    let reuse_result = auth_service.validate_token(&token).await;
    assert!(matches!(reuse_result, Err(Error::NotFound(_))));

    Ok(())
}

#[tokio::test]
async fn test_session_token_manipulation() -> Result<(), Error> {
    // Setup
    let db = setup_database().await?;
    let user_repo = PgUserRepository::new(db.clone());
    let session_repo = PgSessionRepository::new(db);
    let auth_service = AuthService::new(user_repo.clone());

    // Create test user
    let (user, password) = setup_test_user(&user_repo).await?;

    // Get valid token
    let auth_result = auth_service
        .login_with_context(
            user.email.clone(),
            password.clone(),
            "192.168.1.1",
            "Chrome/120.0.0.0",
        )
        .await?;

    let valid_token = auth_result.token;

    // Test 1: Modified Token Parts
    let parts: Vec<&str> = valid_token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have three parts");

    // Modify header
    let modified_token = format!("{}x.{}.{}", parts[0], parts[1], parts[2]);
    let result = auth_service
        .validate_token_with_context(&modified_token, "192.168.1.1", "Chrome/120.0.0.0")
        .await;
    assert!(
        matches!(result, Err(AuthError::TokenInvalid(_))),
        "Modified header should be rejected"
    );

    // Modify payload
    let modified_token = format!("{}.{}x.{}", parts[0], parts[1], parts[2]);
    let result = auth_service
        .validate_token_with_context(&modified_token, "192.168.1.1", "Chrome/120.0.0.0")
        .await;
    assert!(
        matches!(result, Err(AuthError::TokenInvalid(_))),
        "Modified payload should be rejected"
    );

    // Modify signature
    let modified_token = format!("{}.{}.{}x", parts[0], parts[1], parts[2]);
    let result = auth_service
        .validate_token_with_context(&modified_token, "192.168.1.1", "Chrome/120.0.0.0")
        .await;
    assert!(
        matches!(result, Err(AuthError::TokenInvalid(_))),
        "Modified signature should be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn test_session_context_manipulation() -> Result<(), Error> {
    // Setup
    let db = setup_database().await?;
    let user_repo = PgUserRepository::new(db.clone());
    let session_repo = PgSessionRepository::new(db);
    let auth_service = AuthService::new(user_repo.clone());

    // Create test user
    let (user, password) = setup_test_user(&user_repo).await?;

    // Test 1: IP Address Manipulation
    let auth_result = auth_service
        .login_with_context(
            user.email.clone(),
            password.clone(),
            "192.168.1.1",
            "Chrome/120.0.0.0",
        )
        .await?;

    let token = auth_result.token;

    // Test various IP manipulation scenarios
    let ip_tests = vec![
        ("192.168.1.2", "Slight IP change"),
        ("192.168.2.1", "Different subnet"),
        ("10.0.0.1", "Different network"),
        ("2001:db8::1", "IPv6 address"),
        ("127.0.0.1", "Localhost"),
    ];

    for (ip, scenario) in ip_tests {
        let result = auth_service
            .validate_token_with_context(&token, ip, "Chrome/120.0.0.0")
            .await;
        assert!(
            matches!(result, Err(AuthError::SessionInvalid(_))),
            "Token should be invalid with {} ({})",
            ip,
            scenario
        );
    }

    // Test 2: User-Agent Manipulation
    let auth_result = auth_service
        .login_with_context(
            user.email.clone(),
            password.clone(),
            "192.168.1.1",
            "Chrome/120.0.0.0",
        )
        .await?;

    let token = auth_result.token;

    // Test various User-Agent manipulation scenarios
    let ua_tests = vec![
        ("Chrome/120.0.0.1", "Minor version change"),
        ("Chrome/121.0.0.0", "Major version change"),
        ("Firefox/120.0", "Different browser"),
        ("Chrome/120.0.0.0 Mobile", "Added mobile flag"),
        ("", "Empty User-Agent"),
    ];

    for (ua, scenario) in ua_tests {
        let result = auth_service
            .validate_token_with_context(&token, "192.168.1.1", ua)
            .await;
        assert!(
            matches!(result, Err(AuthError::SessionInvalid(_))),
            "Token should be invalid with UA '{}' ({})",
            ua,
            scenario
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_concurrent_session_manipulation() -> Result<(), Error> {
    // Setup
    let db = setup_database().await?;
    let user_repo = PgUserRepository::new(db.clone());
    let session_repo = PgSessionRepository::new(db);
    let auth_service = AuthService::new(user_repo.clone());

    // Create test user
    let (user, password) = setup_test_user(&user_repo).await?;

    // Test 1: Concurrent Session Creation
    let mut sessions = Vec::new();
    for i in 0..5 {
        let auth_result = auth_service
            .login_with_context(
                user.email.clone(),
                password.clone(),
                &format!("192.168.1.{}", i),
                &format!("Chrome/120.0.0.{}", i),
            )
            .await?;
        sessions.push(auth_result);

        // Small delay to ensure different timestamps
        sleep(Duration::from_millis(100)).await;
    }

    // Verify all sessions are unique
    let session_ids: Vec<Uuid> = sessions.iter().map(|s| s.session_id).collect();
    let unique_sessions: std::collections::HashSet<_> = session_ids.iter().collect();
    assert_eq!(
        session_ids.len(),
        unique_sessions.len(),
        "All sessions should have unique IDs"
    );

    // Test 2: Session Invalidation Race Condition
    let last_session = sessions.last().unwrap().clone();

    // Attempt concurrent validation and invalidation
    let (validation_result, invalidation_result) = tokio::join!(
        auth_service.validate_token_with_context(
            &last_session.token,
            "192.168.1.4",
            "Chrome/120.0.0.4"
        ),
        auth_service.logout(last_session.session_id)
    );

    // Either the validation should succeed and invalidation fail, or vice versa
    assert!(
        (validation_result.is_ok() && invalidation_result.is_err())
            || (validation_result.is_err() && invalidation_result.is_ok()),
        "Session operations should be atomic"
    );

    // Test 3: Concurrent Session Updates
    if let Some(first_session) = sessions.first() {
        let session_id = first_session.session_id;
        let token = first_session.token.clone();

        // Attempt concurrent operations
        let futures = vec![
            auth_service.validate_token_with_context(&token, "192.168.1.0", "Chrome/120.0.0.0"),
            auth_service.refresh_session(session_id),
            auth_service.logout(session_id),
        ];

        let results = futures::future::join_all(futures).await;

        // Only one operation should succeed
        let successes = results.iter().filter(|r| r.is_ok()).count();
        assert!(
            successes <= 1,
            "Only one concurrent session operation should succeed"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_session_enumeration_prevention() -> Result<(), Error> {
    // Setup
    let db = setup_database().await?;
    let user_repo = PgUserRepository::new(db.clone());
    let session_repo = PgSessionRepository::new(db);
    let auth_service = AuthService::new(user_repo.clone());

    // Create test user
    let (user, password) = setup_test_user(&user_repo).await?;

    // Test 1: Session ID Enumeration
    let valid_auth = auth_service
        .login_with_context(
            user.email.clone(),
            password.clone(),
            "192.168.1.1",
            "Chrome/120.0.0.0",
        )
        .await?;

    // Test sequential UUIDs
    let mut test_session_id = valid_auth.session_id;
    for _ in 0..5 {
        test_session_id = Uuid::new_v4();
        let result = auth_service.get_session_info(test_session_id).await;

        // Response time should be similar for valid and invalid sessions
        let start = std::time::Instant::now();
        let _ = auth_service.get_session_info(test_session_id).await;
        let invalid_duration = start.elapsed();

        let start = std::time::Instant::now();
        let _ = auth_service.get_session_info(valid_auth.session_id).await;
        let valid_duration = start.elapsed();

        let duration_diff = if valid_duration > invalid_duration {
            valid_duration - invalid_duration
        } else {
            invalid_duration - valid_duration
        };

        assert!(
            duration_diff.as_millis() < 100,
            "Session lookup timing should be similar for valid and invalid sessions"
        );
    }

    // Test 2: Session Token Format Validation
    let invalid_token_tests = vec![
        "invalid",
        "invalid.token",
        "invalid.token.signature",
        &format!("{}.{}", valid_auth.token, "extra_part"),
        "",
    ];

    for invalid_token in invalid_token_tests {
        let result = auth_service
            .validate_token_with_context(invalid_token, "192.168.1.1", "Chrome/120.0.0.0")
            .await;
        assert!(
            matches!(result, Err(AuthError::TokenInvalid(_))),
            "Invalid token format '{}' should be rejected",
            invalid_token
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_admin_session_invalidation() -> Result<(), Error> {
    // Setup
    let db = setup_database().await?;
    let user_repo = PgUserRepository::new(db.clone());
    let session_repo = PgSessionRepository::new(db);
    let auth_service = AuthService::new(user_repo.clone());

    // Create test users
    let (admin, admin_password) = setup_test_admin(&user_repo).await?;
    let (user, user_password) = setup_test_user(&user_repo).await?;

    // Test 1: Admin Invalidates User Session
    let admin_auth = auth_service
        .login_with_context(
            admin.email.clone(),
            admin_password.clone(),
            "192.168.1.100",
            "Chrome/120.0.0.0",
        )
        .await?;

    let user_auth = auth_service
        .login_with_context(
            user.email.clone(),
            user_password.clone(),
            "192.168.1.200",
            "Chrome/120.0.0.0",
        )
        .await?;

    // Admin invalidates user session
    auth_service
        .admin_invalidate_session(admin_auth.session_id, user_auth.session_id)
        .await?;

    // Verify user session is invalid
    let validation_result = auth_service
        .validate_token_with_context(&user_auth.token, "192.168.1.200", "Chrome/120.0.0.0")
        .await;

    assert!(
        matches!(validation_result, Err(AuthError::SessionInvalid(_))),
        "User session should be invalid after admin invalidation"
    );

    // Verify admin session remains valid
    let admin_validation = auth_service
        .validate_token_with_context(&admin_auth.token, "192.168.1.100", "Chrome/120.0.0.0")
        .await;

    assert!(
        admin_validation.is_ok(),
        "Admin session should remain valid after invalidating user session"
    );

    // Test 2: Non-Admin Cannot Invalidate Sessions
    let user2_auth = auth_service
        .login_with_context(
            user.email.clone(),
            user_password.clone(),
            "192.168.1.201",
            "Chrome/120.0.0.0",
        )
        .await?;

    // Regular user attempts to invalidate admin session
    let invalidation_result = auth_service
        .admin_invalidate_session(user2_auth.session_id, admin_auth.session_id)
        .await;

    assert!(
        matches!(invalidation_result, Err(AuthError::PermissionDenied(_))),
        "Non-admin user should not be able to invalidate sessions"
    );

    // Test 3: Admin Cannot Invalidate Own Session
    let self_invalidation = auth_service
        .admin_invalidate_session(admin_auth.session_id, admin_auth.session_id)
        .await;

    assert!(
        matches!(self_invalidation, Err(AuthError::InvalidOperation(_))),
        "Admin should not be able to invalidate their own session"
    );

    // Test 4: Invalid Session IDs
    let invalid_session_id = Uuid::new_v4();

    // Try to invalidate non-existent session
    let result = auth_service
        .admin_invalidate_session(admin_auth.session_id, invalid_session_id)
        .await;

    assert!(
        result.is_ok(),
        "Invalidating non-existent session should not error"
    );

    // Try to invalidate with non-existent admin session
    let result = auth_service
        .admin_invalidate_session(invalid_session_id, user_auth.session_id)
        .await;

    assert!(
        matches!(result, Err(AuthError::SessionInvalid(_))),
        "Using invalid admin session should fail"
    );

    // Test 5: Concurrent Session Invalidation
    let user3_auth = auth_service
        .login_with_context(
            user.email.clone(),
            user_password.clone(),
            "192.168.1.202",
            "Chrome/120.0.0.0",
        )
        .await?;

    // Attempt concurrent validation and invalidation
    let (validation_result, invalidation_result) = tokio::join!(
        auth_service.validate_token_with_context(
            &user3_auth.token,
            "192.168.1.202",
            "Chrome/120.0.0.0"
        ),
        auth_service.admin_invalidate_session(admin_auth.session_id, user3_auth.session_id)
    );

    // Either the validation should succeed and invalidation fail, or vice versa
    assert!(
        (validation_result.is_ok() && invalidation_result.is_err())
            || (validation_result.is_err() && invalidation_result.is_ok()),
        "Session operations should be atomic"
    );

    // Verify session is eventually invalidated
    let final_validation = auth_service
        .validate_token_with_context(&user3_auth.token, "192.168.1.202", "Chrome/120.0.0.0")
        .await;

    assert!(
        matches!(final_validation, Err(AuthError::SessionInvalid(_))),
        "Session should be invalid after concurrent operations complete"
    );

    Ok(())
}
