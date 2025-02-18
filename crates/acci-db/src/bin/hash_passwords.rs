//! This binary is used to hash the passwords for the test users.
//! It is used to ensure that the passwords are hashed correctly before they are stored in the database.
//! It is also used to verify that the passwords are hashed correctly after they are retrieved from the database.

#![allow(clippy::large_stack_arrays)]

use acci_core::auth::TestUserConfig;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

fn main() {
    let test_config = TestUserConfig::default();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    println!("Generating password hashes for test users...");
    for user in test_config.users {
        let hash = argon2
            .hash_password(user.password.as_bytes(), &salt)
            .expect("Failed to hash password");

        println!("-- User: {}", user.username);
        println!("-- Password: {}", user.password);
        println!("-- Hash: {hash}");
    }
}
