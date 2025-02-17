use acci_auth::AuthConfig;
use acci_core::error::Error;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use uuid::Uuid;

pub fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| Error::internal(format!("Failed to parse password hash: {e}")))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| Error::internal(format!("Failed to hash password: {e}")))
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
