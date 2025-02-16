use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Represents a user session in the system.
///
/// A session is created when a user logs in and is used to track their authentication state.
/// It includes information about when the session was created and when it expires.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Session {
    /// Unique identifier for the session
    pub session_id: Uuid,
    /// ID of the user this session belongs to
    pub user_id: Uuid,
    /// Timestamp when the session was created
    pub created_at: OffsetDateTime,
    /// Timestamp when the session expires
    pub expires_at: OffsetDateTime,
}

impl Session {
    /// Creates a new session for a user with the specified expiration time.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user this session belongs to
    /// * `expires_at` - When the session should expire
    ///
    /// # Returns
    ///
    /// A new session instance with a randomly generated session ID
    #[must_use]
    pub fn new(user_id: Uuid, expires_at: OffsetDateTime) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            user_id,
            created_at: OffsetDateTime::now_utc(),
            expires_at,
        }
    }

    /// Checks if the session has expired.
    ///
    /// # Returns
    ///
    /// `true` if the current time is past the session's expiration time, `false` otherwise
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at < OffsetDateTime::now_utc()
    }
}
