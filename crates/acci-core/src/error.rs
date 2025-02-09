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
    #[error("Validation error: {message}")]
    Validation {
        /// A message describing the validation error.
        message: String,
    },

    /// An internal error occurred.
    #[error("Internal error: {message}")]
    Internal {
        /// A message describing the internal error.
        message: String,
    },
}

impl Error {
    /// Creates a new validation error with the given message.
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Creates a new internal error with the given message.
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
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
}
