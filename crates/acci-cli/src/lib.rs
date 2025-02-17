//! CLI utilities and error handling for the ACCI system.
//! Provides common functionality for command-line tools including error types and formatting.
use serde::Serialize;
use std::fmt::Display;

/// Adds two unsigned 64-bit integers.
///
/// # Arguments
/// * `left` - First number to add
/// * `right` - Second number to add
#[must_use]
pub const fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

/// Represents an error that occurred during CLI operations.
#[derive(Debug, Serialize)]
pub struct CliError {
    /// The type of error that occurred
    pub code: ErrorCode,
    /// A human-readable error message
    pub message: String,
    /// Optional additional error details
    pub details: Option<String>,
}

/// Categorizes the type of CLI error that occurred.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Error during input validation
    ValidationError,
    /// Error during database operations
    DatabaseError,
    /// Error processing user input
    InputError,
    /// System-level error
    SystemError,
}

impl CliError {
    /// Creates a new validation error.
    ///
    /// # Arguments
    /// * `message` - The error message
    /// * `details` - Optional additional details
    pub fn validation(message: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        Self {
            code: ErrorCode::ValidationError,
            message: message.into(),
            details: details.map(Into::into),
        }
    }

    /// Creates a new database error.
    ///
    /// # Arguments
    /// * `message` - The error message
    /// * `details` - Optional additional details
    pub fn database(message: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        Self {
            code: ErrorCode::DatabaseError,
            message: message.into(),
            details: details.map(Into::into),
        }
    }

    /// Creates a new input error.
    ///
    /// # Arguments
    /// * `message` - The error message
    /// * `details` - Optional additional details
    pub fn input(message: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        Self {
            code: ErrorCode::InputError,
            message: message.into(),
            details: details.map(Into::into),
        }
    }

    /// Creates a new system error.
    ///
    /// # Arguments
    /// * `message` - The error message
    /// * `details` - Optional additional details
    pub fn system(message: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        Self {
            code: ErrorCode::SystemError,
            message: message.into(),
            details: details.map(Into::into),
        }
    }

    /// Prints the error in a human-readable format.
    pub fn print(&self) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => eprintln!("{json}"),
            Err(_) => eprintln!("Error: {} ({})", self.message, self.code),
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidationError => write!(f, "validation_error"),
            Self::DatabaseError => write!(f, "database_error"),
            Self::InputError => write!(f, "input_error"),
            Self::SystemError => write!(f, "system_error"),
        }
    }
}
