use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Represents a user in the system.
#[allow(clippy::large_stack_arrays)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user.
    pub id: Uuid,
    /// Username of the user.
    pub username: String,
    /// Email address of the user.
    pub email: String,
    /// Full name of the user.
    pub full_name: String,
    /// Hashed password of the user.
    pub password_hash: String,
    /// Whether the user has administrative privileges.
    pub is_admin: bool,
    /// Whether the user account is active.
    pub is_active: bool,
    /// Timestamp when the user was created.
    pub created_at: OffsetDateTime,
    /// Timestamp when the user was last updated.
    pub updated_at: OffsetDateTime,
}
