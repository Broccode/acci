//! This binary is used to hash the passwords for the test users.
//! It is used to ensure that the passwords are hashed correctly before they are stored in the database.
//! It is also used to verify that the passwords are hashed correctly after they are retrieved from the database.

use acci_core::auth::TestUserConfig;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

fn main() {
    let test_config = TestUserConfig::default();
    let argon2 = Argon2::default();

    for user in test_config.users {
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2
            .hash_password(user.password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        println!("-- User: {}", user.email);
        println!("-- Password: {}", user.password);
        println!("-- Hash: {}", hash);
        println!();
    }
}
