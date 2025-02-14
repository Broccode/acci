//! This binary is used to hash the passwords for the test users.
//! It is used to ensure that the passwords are hashed correctly before they are stored in the database.
//! It is also used to verify that the passwords are hashed correctly after they are retrieved from the database.

use acci_core::auth::{hash_password, TestUserConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let test_config = TestUserConfig::default();

    // Generate hash for admin user
    let admin = &test_config.users[0];
    let admin_hash = hash_password(&admin.password)?;
    println!("Admin user ({}):", admin.email);
    println!("Password: {}", admin.password);
    println!("Hash: {}\n", admin_hash);

    // Generate hash for regular user
    let user = &test_config.users[1];
    let user_hash = hash_password(&user.password)?;
    println!("Regular user ({}):", user.email);
    println!("Password: {}", user.password);
    println!("Hash: {}", user_hash);

    Ok(())
}
