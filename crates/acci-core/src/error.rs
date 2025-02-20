//! Error types for the ACCI system.

use thiserror::Error;

/// A specialized Result type for ACCI operations.
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for ACCI operations.
#[derive(Debug, Error)]
pub enum Error {
    /// An error occurred while performing an I/O operation.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An error occurred while performing a serialization/deserialization operation.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A validation error occurred.
    #[error("Validation error: {0}")]
    Validation(String),

    /// An internal error occurred.
    #[error("Internal error: {0}")]
    Internal(String),

    /// A resource was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// An authentication error occurred with the specified message.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// The provided credentials are invalid.
    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),

    /// Token validation failed with the specified error message.
    #[error("Token validation failed: {0}")]
    TokenValidationFailed(String),

    /// The user session has expired.
    #[error("Session expired")]
    SessionExpired,

    /// The requested session could not be found.
    #[error("Session not found")]
    SessionNotFound,

    /// A database error occurred with the specified message.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// The provided credentials are already in use.
    #[error("Already exists: {0}")]
    AlreadyExists(String),

    /// Permission denied for the operation.
    #[error("Permission denied")]
    PermissionDenied,

    /// Authorization error occurred with the specified message.
    #[error("Authorization error: {0}")]
    Authorization(String),

    /// Rate limit exceeded for the operation.
    #[error("Rate limit exceeded")]
    RateLimit,

    /// Invalid token error occurred with the specified message.
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// Session error occurred with the specified message.
    #[error("Session error: {0}")]
    Session(String),

    /// Forbidden error occurred with the specified message.
    #[error("Forbidden: {0}")]
    Forbidden(String),
}

impl Error {
    /// Creates a new validation error with the given message.
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation(message.into())
    }

    /// Creates a new internal error with the given message.
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal(message.into())
    }

    /// Creates a new not found error with the given message.
    pub fn not_found<S: Into<String>>(message: S) -> Self {
        Self::NotFound(message.into())
    }
}

impl From<time::error::ComponentRange> for Error {
    fn from(err: time::error::ComponentRange) -> Self {
        Self::internal(format!("Invalid timestamp: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error() {
        let err = Error::validation("invalid input");
        assert!(matches!(err, Error::Validation { .. }));
        assert_eq!(err.to_string(), "Validation error: invalid input");
    }

    #[test]
    fn test_internal_error() {
        let err = Error::internal("something went wrong");
        assert!(matches!(err, Error::Internal { .. }));
        assert_eq!(err.to_string(), "Internal error: something went wrong");
    }

    #[test]
    fn test_not_found_error() {
        let err = Error::not_found("user not found");
        assert!(matches!(err, Error::NotFound { .. }));
        assert_eq!(err.to_string(), "Not found: user not found");
    }
}
