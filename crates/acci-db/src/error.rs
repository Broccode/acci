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
