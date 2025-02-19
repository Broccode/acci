use acci_auth::providers::basic::BasicAuthProvider;
use acci_core::auth::{AuthConfig, AuthProvider, Credentials};
use acci_db::{
    create_pool,
    repositories::{
        session::PgSessionRepository,
        user::{PgUserRepository, UserRepository},
    },
    run_migrations,
    sqlx::{self, PgPool},
    DbConfig,
};
use anyhow::Result;
use std::sync::Arc;
use testcontainers_modules::{postgres, testcontainers::runners::AsyncRunner};

use crate::helpers::db::setup_database;

async fn setup() -> Result<(Box<dyn std::any::Any>, PgUserRepository, PgPool)> {
    let container = postgres::Postgres::default().start().await?;
    let port = container.get_host_port_ipv4(5432).await?;

    let config = DbConfig {
        url: format!("postgres://postgres:postgres@localhost:{}/postgres", port),
        ..Default::default()
    };

    let pool = create_pool(config).await?;

    // Enable crypto extension in postgres database
    sqlx::query("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"")
        .execute(&pool)
        .await?;

    // Enable UUID extension in postgres database
    sqlx::query("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
        .execute(&pool)
        .await?;

    // Create schema and ensure extension is available
    sqlx::query("CREATE SCHEMA IF NOT EXISTS acci")
        .execute(&pool)
        .await?;

    run_migrations(&pool).await?;
    let repo = PgUserRepository::new(pool.clone());
    Ok((Box::new(container), repo, pool))
}

#[tokio::test]
async fn test_default_admin_user_exists() -> Result<()> {
    let (_container, repo, _) = setup().await?;

    // Get the default admin user
    let user = repo.get_user_by_username("admin").await?;

    assert!(user.is_some(), "Default admin user should exist");
    let user = user.expect("Default admin user should exist after migration");
    assert_eq!(user.username, "admin");
    assert_eq!(user.email, "admin@example.com");
    assert!(
        user.is_admin,
        "Default admin user should have admin privileges"
    );

    Ok(())
}

#[tokio::test]
async fn test_default_admin_authentication() -> Result<()> {
    let (_container, pool) = setup_database().await?;

    // Create auth provider and try to authenticate
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool.clone()));
    let auth_provider = BasicAuthProvider::new(user_repo, session_repo, AuthConfig::default());

    // Add a small delay to ensure database is ready
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify default admin user exists in DB directly
    let admin_user = sqlx::query_as::<_, (String, bool, String)>(
        "SELECT username, is_admin, password_hash FROM acci.users WHERE username = 'admin'",
    )
    .fetch_optional(&pool)
    .await?;

    match admin_user {
        Some((username, is_admin, password_hash)) => {
            assert_eq!(username, "admin", "Admin username should be 'admin'");
            assert!(is_admin, "Admin user should have is_admin = true");
            println!("Password hash from database: {}", password_hash);

            // Generate hash of "Admin123!@#" using the same hashing function
            let expected_hash = crate::helpers::auth::hash_password("Admin123!@#")
                .expect("Failed to hash default password in test");
            println!("Expected hash of 'Admin123!@#': {}", expected_hash);

            // Verify the password directly using auth::verify_password
            let password_valid =
                crate::helpers::auth::verify_password("Admin123!@#", &password_hash)
                    .expect("Failed to verify password in test");
            println!("Password verification result: {}", password_valid);
        },
        None => {
            panic!("Default admin user not found in database after migrations!");
        },
    }

    let credentials = Credentials {
        username: "admin".to_string(),
        password: "Admin123!@#".to_string(),
    };

    let result = auth_provider.authenticate(credentials).await;
    assert!(
        result.is_ok(),
        "Default admin authentication should succeed: {:?}",
        result.err()
    );

    Ok(())
}
