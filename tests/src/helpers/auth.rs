use acci_core::auth::AuthConfig;
use acci_core::error::Error;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use jsonwebtoken;
use serde::{Deserialize, Serialize};
use std::env;
use time;
use uuid::Uuid;

// Configurable via environment variables, with secure defaults
pub fn get_argon2_memory_size() -> u32 {
    env::var("ARGON2_MEMORY_SIZE")
        .unwrap_or_else(|_| "19456".to_string())
        .parse()
        .unwrap_or(19456)
}

pub fn get_argon2_iterations() -> u32 {
    env::var("ARGON2_ITERATIONS")
        .unwrap_or_else(|_| "2".to_string())
        .parse()
        .unwrap_or(2)
}

pub fn get_argon2_parallelism() -> u32 {
    env::var("ARGON2_PARALLELISM")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .unwrap_or(1)
}

pub fn get_min_password_length() -> usize {
    std::env::var("MIN_PASSWORD_LENGTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8) // 8 characters minimum
}

fn create_argon2_instance() -> Argon2<'static> {
    let params = Params::new(
        get_argon2_memory_size(),
        get_argon2_iterations(),
        get_argon2_parallelism(),
        None,
    )
    .expect("Invalid Argon2 parameters");
    println!("Argon2 Hashing Parameters: {:?}", params);
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| Error::internal(format!("Failed to parse password hash: {}", e)))?;
    println!(
        "Parsed Hash Parameters for Verification: {:?}",
        parsed_hash.params
    );
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = create_argon2_instance();
    println!(
        "Argon2 Instance Params during hashing: {:?}",
        argon2.params()
    );
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::internal(format!("Failed to hash password: {}", e)))?
        .to_string();
    Ok(password_hash)
}

pub fn create_test_token(user_id: Uuid, config: &AuthConfig) -> Result<(String, i64, i64), Error> {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::{Deserialize, Serialize};
    use time::{Duration, OffsetDateTime};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        iss: String,
        exp: i64,
        iat: i64,
        jti: String,
    }

    let now = OffsetDateTime::now_utc();
    let exp = now + Duration::seconds(config.token_duration);

    let claims = Claims {
        sub: user_id.to_string(),
        iss: config.token_issuer.clone(),
        exp: exp.unix_timestamp(),
        iat: now.unix_timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| Error::internal(format!("Failed to create JWT token: {e}")))?;

    Ok((token, now.unix_timestamp(), exp.unix_timestamp()))
}
