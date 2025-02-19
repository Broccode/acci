#[cfg(test)]
mod password_hash_tests {
    use acci_auth::password::{
        hash_password, verify_password, ARGON2_MEMORY_COST, ARGON2_PARALLELISM, ARGON2_TIME_COST,
    };
    use acci_core::error::Error;
    use argon2::Argon2;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    const MAX_TIMING_DIFF_MS: u128 = 1; // Maximum allowed timing difference in milliseconds

    #[tokio::test]
    async fn test_password_hashing_mutations() -> Result<(), Error> {
        // Test mutation: Basic validation
        #[cfg(test)]
        async fn test_basic_validation() -> Result<(), Error> {
            let password = "secure_password_123";

            // Original behavior
            let hash = hash_password(password)?;
            assert!(verify_password(password, &hash)?);

            // Mutation 1: Empty password
            match hash_password("") {
                Err(Error::ValidationError(msg)) => assert!(msg.contains("empty")),
                _ => panic!("Expected ValidationError for empty password"),
            }

            // Mutation 2: Very long password
            let long_password = "a".repeat(1000);
            match hash_password(&long_password) {
                Err(Error::ValidationError(msg)) => assert!(msg.contains("length")),
                _ => panic!("Expected ValidationError for too long password"),
            }

            Ok(())
        }

        // Test mutation: Salt uniqueness with HashSet
        #[cfg(test)]
        async fn test_salt_uniqueness() -> Result<(), Error> {
            let password = "same_password_123";
            let mut hashes = HashSet::new();

            // Generate multiple hashes and ensure they're unique
            for _ in 0..10 {
                let hash = hash_password(password)?;
                assert!(hashes.insert(hash.clone()), "Generated hash was not unique");
                assert!(verify_password(password, &hash)?);
            }

            assert_eq!(hashes.len(), 10, "Expected 10 unique hashes");

            Ok(())
        }

        // Test mutation: Argon2 parameters
        #[cfg(test)]
        async fn test_argon2_parameters() -> Result<(), Error> {
            let password = "secure_password_123";
            let hash = hash_password(password)?;

            // Parse the hash to verify Argon2 parameters
            let parsed = argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(
                    ARGON2_MEMORY_COST,
                    ARGON2_TIME_COST,
                    ARGON2_PARALLELISM,
                    None,
                )
                .unwrap(),
            );

            // Verify the hash can be parsed with our expected parameters
            assert!(parsed
                .verify_hash(hash.as_bytes(), password.as_bytes())
                .is_ok());

            // Verify with wrong parameters fails
            let wrong_params = argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(
                    ARGON2_MEMORY_COST / 2, // Wrong memory cost
                    ARGON2_TIME_COST,
                    ARGON2_PARALLELISM,
                    None,
                )
                .unwrap(),
            );

            assert!(wrong_params
                .verify_hash(hash.as_bytes(), password.as_bytes())
                .is_err());

            Ok(())
        }

        // Test mutation: Timing attacks with explicit threshold
        #[cfg(test)]
        async fn test_timing_attacks() -> Result<(), Error> {
            let password = "secure_password_123";
            let hash = hash_password(password)?;

            let mut valid_times = Vec::new();
            let mut invalid_times = Vec::new();

            // Multiple measurements for statistical significance
            for _ in 0..100 {
                // Valid password timing
                let start = Instant::now();
                let _ = verify_password(password, &hash)?;
                valid_times.push(start.elapsed());

                // Invalid password timing
                let start = Instant::now();
                let _ = verify_password("wrong_password_123", &hash)?;
                invalid_times.push(start.elapsed());
            }

            // Calculate average times
            let avg_valid =
                valid_times.iter().sum::<Duration>().as_millis() / valid_times.len() as u128;
            let avg_invalid =
                invalid_times.iter().sum::<Duration>().as_millis() / invalid_times.len() as u128;

            // Time difference should be minimal
            let time_diff = if avg_valid > avg_invalid {
                avg_valid - avg_invalid
            } else {
                avg_invalid - avg_valid
            };

            assert!(
                time_diff <= MAX_TIMING_DIFF_MS,
                "Time difference too large: {} ms (valid: {} ms, invalid: {} ms)",
                time_diff,
                avg_valid,
                avg_invalid
            );

            Ok(())
        }

        // Test mutation: Hash verification
        #[cfg(test)]
        async fn test_hash_verification() -> Result<(), Error> {
            let password = "secure_password_123";
            let hash = hash_password(password)?;

            // Original behavior
            assert!(verify_password(password, &hash)?);

            // Mutation 1: Wrong password
            assert!(!verify_password("wrong_password", &hash)?);

            // Mutation 2: Empty hash
            match verify_password(password, "") {
                Err(Error::ValidationError(msg)) => assert!(msg.contains("hash format")),
                _ => panic!("Expected ValidationError for empty hash"),
            }

            // Mutation 3: Invalid hash format
            match verify_password(password, "invalid_hash_format") {
                Err(Error::ValidationError(msg)) => assert!(msg.contains("hash format")),
                _ => panic!("Expected ValidationError for invalid hash format"),
            }

            // Mutation 4: Truncated password
            assert!(!verify_password(&password[..password.len() - 1], &hash)?);

            Ok(())
        }

        // Property-based tests for password validation
        proptest! {
            #[test]
            fn test_password_properties(
                // Generate passwords with varying lengths and characters
                password in "[A-Za-z0-9!@#$%^&*()]{8,100}"
            ) {
                // Basic validation
                let hash = hash_password(&password).unwrap();

                // Verify the password works with its hash
                assert!(verify_password(&password, &hash).unwrap());

                // Verify slightly modified passwords fail
                if !password.is_empty() {
                    // Change one character
                    let mut modified = password.clone();
                    if let Some(last) = modified.chars().last() {
                        let new_char = if last.is_ascii_uppercase() {
                            last.to_ascii_lowercase()
                        } else {
                            last.to_ascii_uppercase()
                        };
                        modified.pop();
                        modified.push(new_char);
                    }
                    assert!(!verify_password(&modified, &hash).unwrap());

                    // Truncate password
                    assert!(!verify_password(&password[..password.len()-1], &hash).unwrap());

                    // Append character
                    assert!(!verify_password(&format!("{}a", password), &hash).unwrap());
                }
            }
        }

        // Run all mutation tests
        test_basic_validation().await?;
        test_salt_uniqueness().await?;
        test_argon2_parameters().await?;
        test_timing_attacks().await?;
        test_hash_verification().await?;

        Ok(())
    }
}
