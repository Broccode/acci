use thiserror::Error;

/// Database specific error types
#[derive(Debug, Error)]
pub enum DbError {
    /// Database connection error
    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Migration error
    #[error("Migration error: {0}")]
    Migration(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::error::Error as SqlxError;

    #[test]
    fn test_db_error_display_sqlx() {
        let inner = SqlxError::PoolTimedOut;
        let error = DbError::Sqlx(inner);
        assert!(error.to_string().contains("Database error"));
    }

    #[test]
    fn test_db_error_display_migration() {
        let error = DbError::Migration("Failed to apply migration".to_string());
        assert!(error.to_string().contains("Migration error"));
        assert!(error.to_string().contains("Failed to apply migration"));
    }

    #[test]
    fn test_db_error_debug() {
        let error = DbError::Migration("Test error".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Migration"));
        assert!(debug_str.contains("Test error"));
    }

    #[test]
    fn test_db_error_from_sqlx() {
        let sqlx_error = SqlxError::PoolTimedOut;
        let db_error: DbError = sqlx_error.into();
        match db_error {
            DbError::Sqlx(_) => (),
            _ => panic!("Expected SqlxError variant"),
        }
    }
}
