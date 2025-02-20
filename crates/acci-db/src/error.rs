//! Error types for database operations.
//!
//! This module defines the error types that can occur during database operations.
//! It provides a unified error type that can be used across the database layer.

use acci_core::error::Error;

/// Maps a `SQLx` error to our core error type
#[must_use]
pub fn map_sqlx_error(error: sqlx::Error) -> Error {
    match &error {
        sqlx::Error::RowNotFound => Error::NotFound("Entity not found".to_string()),
        sqlx::Error::Database(e) => {
            if let Some(code) = e.code() {
                match code.as_ref() {
                    "23505" => Error::Validation("Unique constraint violation".to_string()),
                    _ => Error::Database(error),
                }
            } else {
                Error::Database(error)
            }
        },
        _ => Error::Database(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::error::Error as SqlxError;

    #[test]
    fn test_map_sqlx_error_not_found() {
        let error = map_sqlx_error(SqlxError::RowNotFound);
        assert!(matches!(error, Error::NotFound(_)));
    }

    #[test]
    fn test_map_sqlx_error_database() {
        let error = map_sqlx_error(SqlxError::Protocol("test error".to_string()));
        assert!(matches!(error, Error::Database(_)));
    }
}
