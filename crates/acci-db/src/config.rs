use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;
use thiserror::Error;

/// Database configuration error types
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Required environment variable is missing
    #[error("Missing environment variable: {0}")]
    MissingEnv(String),

    /// Database connection error
    #[error("Database connection error: {0}")]
    Connection(#[from] sqlx::Error),

    /// Invalid configuration value
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
}

/// Database configuration
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Database host
    pub host: String,
    /// Database port
    pub port: u16,
    /// Database name
    pub name: String,
    /// Database user
    pub user: String,
    /// Database password
    pub password: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
}

impl DbConfig {
    /// Creates a new database configuration from environment variables.
    ///
    /// Required environment variables:
    /// - `DATABASE_HOST`: Database host (default: localhost)
    /// - `DATABASE_PORT`: Database port (default: 5432)
    /// - `DATABASE_NAME`: Database name
    /// - `DATABASE_USER`: Database user
    /// - `DATABASE_PASSWORD`: Database password
    /// - `DATABASE_MAX_CONNECTIONS`: Maximum number of connections (default: 5)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required environment variables are missing
    /// - Port number is invalid
    /// - Max connections value is invalid
    pub fn from_env() -> Result<Self, ConfigError> {
        let host = env::var("DATABASE_HOST").unwrap_or_else(|_| "localhost".to_string());
        let port = env::var("DATABASE_PORT")
            .unwrap_or_else(|_| "5432".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue("Invalid port number".to_string()))?;
        let name = env::var("DATABASE_NAME")
            .map_err(|_| ConfigError::MissingEnv("DATABASE_NAME".to_string()))?;
        let user = env::var("DATABASE_USER")
            .map_err(|_| ConfigError::MissingEnv("DATABASE_USER".to_string()))?;
        let password = env::var("DATABASE_PASSWORD")
            .map_err(|_| ConfigError::MissingEnv("DATABASE_PASSWORD".to_string()))?;
        let max_connections = env::var("DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue("Invalid max connections value".to_string()))?;

        Ok(Self {
            host,
            port,
            name,
            user,
            password,
            max_connections,
        })
    }

    /// Creates a connection pool using the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Connection URL is invalid
    /// - Database connection fails
    pub async fn create_pool(&self) -> Result<PgPool, ConfigError> {
        let connection_string = format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, self.name
        );

        PgPoolOptions::new()
            .max_connections(self.max_connections)
            .connect(&connection_string)
            .await
            .map_err(ConfigError::Connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_from_env_with_defaults() {
        env::set_var("DATABASE_NAME", "test_db");
        env::set_var("DATABASE_USER", "test_user");
        env::set_var("DATABASE_PASSWORD", "test_pass");

        let config = DbConfig::from_env().unwrap();

        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.name, "test_db");
        assert_eq!(config.user, "test_user");
        assert_eq!(config.password, "test_pass");
        assert_eq!(config.max_connections, 5);

        env::remove_var("DATABASE_NAME");
        env::remove_var("DATABASE_USER");
        env::remove_var("DATABASE_PASSWORD");
    }

    #[test]
    fn test_from_env_with_custom_values() {
        env::set_var("DATABASE_HOST", "db.example.com");
        env::set_var("DATABASE_PORT", "5433");
        env::set_var("DATABASE_NAME", "prod_db");
        env::set_var("DATABASE_USER", "prod_user");
        env::set_var("DATABASE_PASSWORD", "prod_pass");
        env::set_var("DATABASE_MAX_CONNECTIONS", "10");

        let config = DbConfig::from_env().unwrap();

        assert_eq!(config.host, "db.example.com");
        assert_eq!(config.port, 5433);
        assert_eq!(config.name, "prod_db");
        assert_eq!(config.user, "prod_user");
        assert_eq!(config.password, "prod_pass");
        assert_eq!(config.max_connections, 10);

        env::remove_var("DATABASE_HOST");
        env::remove_var("DATABASE_PORT");
        env::remove_var("DATABASE_NAME");
        env::remove_var("DATABASE_USER");
        env::remove_var("DATABASE_PASSWORD");
        env::remove_var("DATABASE_MAX_CONNECTIONS");
    }

    #[test]
    fn test_from_env_missing_required() {
        env::remove_var("DATABASE_NAME");
        env::remove_var("DATABASE_USER");
        env::remove_var("DATABASE_PASSWORD");

        let result = DbConfig::from_env();
        assert!(result.is_err());
    }

    #[test]
    fn test_from_env_invalid_port() {
        env::set_var("DATABASE_PORT", "invalid");
        env::set_var("DATABASE_NAME", "test_db");
        env::set_var("DATABASE_USER", "test_user");
        env::set_var("DATABASE_PASSWORD", "test_pass");

        let result = DbConfig::from_env();
        assert!(result.is_err());

        env::remove_var("DATABASE_PORT");
        env::remove_var("DATABASE_NAME");
        env::remove_var("DATABASE_USER");
        env::remove_var("DATABASE_PASSWORD");
    }
}
