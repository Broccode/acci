use time::OffsetDateTime;
use uuid::Uuid;

/// Represents a user in the system.
///
/// A user is an entity that can authenticate and interact with the system.
/// It stores basic user information and authentication details.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    /// Unique identifier for the user
    pub id: Uuid,
    /// Username used for authentication
    pub username: String,
    /// Email address for communication
    pub email: String,
    /// Hashed password for secure authentication
    pub password_hash: String,
    /// Indicates whether the user account is active
    pub is_active: bool,
    /// Timestamp when the user account was created
    pub created_at: OffsetDateTime,
    /// Timestamp when the user account was last updated
    pub updated_at: OffsetDateTime,
}

impl User {
    /// Creates a new user with the specified username and password hash.
    ///
    /// # Arguments
    ///
    /// * `username` - The username for the new user
    /// * `password_hash` - The pre-hashed password for the user
    ///
    /// # Returns
    ///
    /// A new user instance with a randomly generated user ID and current timestamps
    #[must_use]
    pub fn new(username: String, password_hash: String) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: Uuid::new_v4(),
            username,
            email: String::new(),
            password_hash,
            is_active: true,
            created_at: now,
            updated_at: now,
        }
    }
}
