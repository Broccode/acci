use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use futures::future::join_all;
use uuid::Uuid;

use acci_db::{
    models::Session,
    repositories::{PgSessionRepository, SessionRepository},
};

use crate::helpers::db::get_test_db_pool;

/// Asserts that two DateTime<Utc> values are approximately equal within a 1-second tolerance.
/// This is useful for comparing timestamps that are set using Utc::now(), as there might be
/// small differences due to the time elapsed between creating the timestamp and performing the assertion.
///
/// # Arguments
///
/// * `actual` - The actual DateTime value from the test
/// * `expected` - The expected DateTime value to compare against
///
/// # Panics
///
/// Panics if the difference between the timestamps is greater than 1 second,
/// with a detailed error message showing the actual difference and both timestamps.
fn assert_timestamp_approx_equal(actual: DateTime<Utc>, expected: DateTime<Utc>) {
    let diff = (actual - expected).num_seconds().abs();
    assert!(
        diff < 1,
        "Timestamps not approx. equal (within 1 second). Diff: {} sec, Actual: {:?}, Expected: {:?}",
        diff,
        actual,
        expected
    );
}

/// Creates a new PgSessionRepository instance for testing purposes.
/// This function sets up a clean database connection pool for each test,
/// ensuring test isolation by providing a fresh database state.
///
/// The database is automatically cleaned up between tests to prevent
/// interference between test cases.
///
/// # Returns
///
/// Returns a Result containing the new PgSessionRepository instance,
/// or an error if the database connection pool cannot be created.
///
/// # Errors
///
/// This function will return an error if:
/// * The database connection pool cannot be created
/// * The database is not accessible
/// * The required database migrations have not been run
async fn setup_test_session_repo() -> Result<PgSessionRepository> {
    let pool = get_test_db_pool().await;
    Ok(PgSessionRepository::new(pool))
}

#[tokio::test]
async fn test_create_session() -> Result<()> {
    // Arrange: Set up repository and create test data
    let repo = setup_test_session_repo().await?;
    let user_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(1);
    let session = Session::new(user_id, expires_at);

    // Act: Create the session
    let created_session = repo.create_session(&session).await?;

    // Assert: Verify the session was created correctly
    assert_eq!(
        created_session.session_id, session.session_id,
        "Created session should have the same session_id as the input session"
    );
    assert_eq!(
        created_session.user_id, user_id,
        "Created session should be associated with the correct user_id"
    );
    assert_timestamp_approx_equal(created_session.created_at, session.created_at);
    assert_timestamp_approx_equal(created_session.expires_at, expires_at);

    Ok(())
}

#[tokio::test]
async fn test_get_session() -> Result<()> {
    // Arrange: Set up repository and create a session
    let repo = setup_test_session_repo().await?;
    let user_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(1);
    let session = Session::new(user_id, expires_at);
    let created_session = repo.create_session(&session).await?;

    // Act: Retrieve the session
    let retrieved_session = repo.get_session(session.session_id).await?.unwrap();

    // Assert: Verify the retrieved session matches the created one
    assert_eq!(
        retrieved_session.session_id, session.session_id,
        "Retrieved session should have the same session_id as the created session"
    );
    assert_eq!(
        retrieved_session.user_id, user_id,
        "Retrieved session should be associated with the correct user_id"
    );
    assert_eq!(
        retrieved_session.created_at, created_session.created_at,
        "Retrieved session should have the same creation timestamp"
    );
    assert_eq!(
        retrieved_session.expires_at, created_session.expires_at,
        "Retrieved session should have the same expiration timestamp"
    );

    Ok(())
}

#[tokio::test]
async fn test_get_user_sessions() -> Result<()> {
    // Arrange: Set up repository and create a session
    let repo = setup_test_session_repo().await?;
    let user_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(1);
    let session = Session::new(user_id, expires_at);
    let created_session = repo.create_session(&session).await?;

    // Act: Retrieve all sessions for the user
    let user_sessions = repo.get_user_sessions(user_id).await?;

    // Assert: Verify we got exactly one session with correct data
    assert_eq!(
        user_sessions.len(),
        1,
        "Should retrieve exactly one session for the user, specifically the one we just created"
    );
    assert_eq!(
        user_sessions[0].session_id, session.session_id,
        "Retrieved session should have the correct session_id"
    );
    assert_eq!(
        user_sessions[0].created_at, created_session.created_at,
        "Retrieved session should have the same creation timestamp"
    );
    assert_eq!(
        user_sessions[0].expires_at, created_session.expires_at,
        "Retrieved session should have the same expiration timestamp"
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_session() -> Result<()> {
    // Arrange: Set up repository and create a session
    let repo = setup_test_session_repo().await?;
    let user_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(1);
    let session = Session::new(user_id, expires_at);
    repo.create_session(&session).await?;

    // Act: Delete the session
    repo.delete_session(session.session_id).await?;

    // Assert: Verify the session was deleted
    let deleted_session = repo.get_session(session.session_id).await?;
    assert!(
        deleted_session.is_none(),
        "Session should not be found in the database after deletion"
    );

    Ok(())
}

#[tokio::test]
async fn test_expired_sessions() -> Result<()> {
    // Arrange: Set up repository and create expired and valid sessions
    let repo = setup_test_session_repo().await?;
    let user_id = Uuid::new_v4();
    let expired_at = Utc::now() - Duration::hours(1);
    let expired_session = Session::new(user_id, expired_at);
    repo.create_session(&expired_session).await?;

    let valid_at = Utc::now() + Duration::hours(1);
    let valid_session = Session::new(user_id, valid_at);
    repo.create_session(&valid_session).await?;

    // Assert session expiry status
    assert!(
        expired_session.is_expired(),
        "Session created with past expiration time should be marked as expired"
    );
    assert!(
        !valid_session.is_expired(),
        "Session created with future expiration time should not be marked as expired"
    );

    // Act: Delete expired sessions
    let deleted_count = repo.delete_expired_sessions().await?;

    // Assert: Verify only expired session was deleted
    assert_eq!(
        deleted_count, 1,
        "Should have deleted exactly one expired session, leaving the valid one"
    );
    let remaining_sessions = repo.get_user_sessions(user_id).await?;
    assert_eq!(
        remaining_sessions.len(),
        1,
        "Should have exactly one remaining valid session after cleanup"
    );
    assert_eq!(
        remaining_sessions[0].session_id, valid_session.session_id,
        "The remaining session should be the valid (non-expired) session"
    );

    Ok(())
}

#[tokio::test]
async fn test_session_not_found() -> Result<()> {
    // Arrange: Set up repository
    let repo = setup_test_session_repo().await?;
    let non_existent_id = Uuid::new_v4();

    // Act: Try to retrieve non-existent session
    let session = repo.get_session(non_existent_id).await?;

    // Assert: Verify session is None
    assert!(
        session.is_none(),
        "get_session should return None for a non-existent session ID"
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_non_existent_session() -> Result<()> {
    // Arrange: Set up repository
    let repo = setup_test_session_repo().await?;
    let non_existent_id = Uuid::new_v4();

    // Act & Assert: Delete should not error for non-existent session
    repo.delete_session(non_existent_id).await?;

    Ok(())
}

#[tokio::test]
async fn test_multiple_user_sessions() -> Result<()> {
    // Arrange: Set up repository and create multiple sessions
    let repo = setup_test_session_repo().await?;
    let user_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(1);
    let session1 = Session::new(user_id, expires_at);
    let session2 = Session::new(user_id, expires_at);
    let session3 = Session::new(user_id, expires_at);

    // Act: Create sessions and retrieve them
    repo.create_session(&session1).await?;
    repo.create_session(&session2).await?;
    repo.create_session(&session3).await?;
    let user_sessions = repo.get_user_sessions(user_id).await?;

    // Assert: Verify all sessions were created and can be retrieved
    assert_eq!(
        user_sessions.len(),
        3,
        "Should retrieve exactly three sessions for the user"
    );
    let session_ids: Vec<Uuid> = user_sessions.iter().map(|s| s.session_id).collect();
    assert!(
        session_ids.contains(&session1.session_id),
        "Retrieved sessions should contain the first created session"
    );
    assert!(
        session_ids.contains(&session2.session_id),
        "Retrieved sessions should contain the second created session"
    );
    assert!(
        session_ids.contains(&session3.session_id),
        "Retrieved sessions should contain the third created session"
    );

    Ok(())
}

#[tokio::test]
async fn test_concurrent_session_operations() -> Result<()> {
    // Arrange: Set up repository
    let repo = setup_test_session_repo().await?;
    let user_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(1);

    // Act: Create multiple sessions concurrently
    let mut create_futures = Vec::new();
    for _ in 0..5 {
        let session = Session::new(user_id, expires_at);
        create_futures.push(repo.create_session(&session));
    }

    // Assert: Verify all session creations succeeded
    let results = join_all(create_futures).await;
    for result in results {
        assert!(
            result.is_ok(),
            "Each concurrent session creation should succeed without errors"
        );
    }

    // Verify all sessions were created
    let user_sessions = repo.get_user_sessions(user_id).await?;
    assert_eq!(
        user_sessions.len(),
        5,
        "Should have successfully created exactly five sessions concurrently"
    );

    // Act: Delete sessions concurrently
    let delete_futures: Vec<_> = user_sessions
        .iter()
        .map(|s| repo.delete_session(s.session_id))
        .collect();

    // Assert: Verify all session deletions succeeded
    let results = join_all(delete_futures).await;
    for result in results {
        assert!(
            result.is_ok(),
            "Each concurrent session deletion should succeed without errors"
        );
    }

    // Verify all sessions were deleted
    let remaining_sessions = repo.get_user_sessions(user_id).await?;
    assert_eq!(
        remaining_sessions.len(),
        0,
        "All sessions should be successfully deleted after concurrent deletion"
    );

    Ok(())
}

#[tokio::test]
async fn test_expired_sessions_parameterized() -> Result<()> {
    // Arrange: Set up repository
    let repo = setup_test_session_repo().await?;

    // Test cases with different expiry durations
    let test_cases = vec![
        ("seconds", Duration::seconds(-10)),
        ("minutes", Duration::minutes(-30)),
        ("hours", Duration::hours(-2)),
        ("days", Duration::days(-1)),
    ];

    for (duration_name, expired_duration) in test_cases {
        // Arrange: Create expired and valid sessions
        let user_id = Uuid::new_v4();
        let expired_at = Utc::now() + expired_duration;
        let expired_session = Session::new(user_id, expired_at);
        repo.create_session(&expired_session).await?;

        let valid_at = Utc::now() + Duration::hours(1);
        let valid_session = Session::new(user_id, valid_at);
        repo.create_session(&valid_session).await?;

        // Act: Delete expired sessions
        let deleted_count = repo.delete_expired_sessions().await?;

        // Assert: Verify only expired session was deleted
        assert_eq!(
            deleted_count, 1,
            "Should delete exactly one session expired by {} (duration: {:?})",
            duration_name, expired_duration
        );

        let remaining_sessions = repo.get_user_sessions(user_id).await?;
        assert_eq!(
            remaining_sessions.len(),
            1,
            "Should have one valid session remaining after deleting session expired by {}",
            duration_name
        );
        assert_eq!(
            remaining_sessions[0].session_id, valid_session.session_id,
            "Remaining session should be the valid one after deleting session expired by {}",
            duration_name
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_invalidate_user_sessions() {
    let pool = setup_test_db().await;
    let repo = PgSessionRepository::new(pool.clone());

    // Create a test user
    let user_id = Uuid::new_v4();

    // Create multiple sessions for the user
    let session1 = Session {
        session_id: Uuid::new_v4(),
        user_id,
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
    };
    let session2 = Session {
        session_id: Uuid::new_v4(),
        user_id,
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
    };

    // Insert the sessions
    repo.create_session(&session1).await.unwrap();
    repo.create_session(&session2).await.unwrap();

    // Verify sessions exist
    let sessions = repo.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 2, "Expected 2 sessions to be created");

    // Invalidate all sessions for the user
    let invalidated = repo.invalidate_user_sessions(user_id).await.unwrap();
    assert_eq!(invalidated, 2, "Expected 2 sessions to be invalidated");

    // Verify sessions were deleted
    let sessions = repo.get_user_sessions(user_id).await.unwrap();
    assert!(
        sessions.is_empty(),
        "Expected all sessions to be invalidated"
    );
}
