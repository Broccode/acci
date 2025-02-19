#[cfg(test)]
mod token_mutation_tests {
    use crate::helpers::test_utils::setup_test_env;
    use acci_auth::{Claims, TokenError, TokenValidator};
    use acci_core::error::Error;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn test_token_validation_mutations() {
        let test_env = setup_test_env().await;
        let validator = TokenValidator::new(&test_env.config);

        // Test mutation: Timestamp validation bypass
        #[cfg(test)]
        async fn test_timestamp_mutation() -> Result<(), Error> {
            let future_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 3600; // 1 hour in future

            let mut claims = Claims::new();
            claims.exp = Some(future_time);

            // Original behavior
            assert!(validator.validate_timestamp(&claims).is_ok());

            // Mutation 1: Ignore expiration
            let mutated_claims = Claims::new(); // No expiration set
            assert!(validator.validate_timestamp(&mutated_claims).is_err());

            // Mutation 2: Wrong timestamp comparison
            claims.exp = Some(future_time - 7200); // 1 hour in past
            assert!(validator.validate_timestamp(&claims).is_err());

            Ok(())
        }

        // Test mutation: Signature verification bypass
        #[cfg(test)]
        async fn test_signature_mutation() -> Result<(), Error> {
            let token = "valid.token.here";

            // Original behavior
            assert!(validator.verify_signature(token).is_ok());

            // Mutation 1: Empty token
            assert!(validator.verify_signature("").is_err());

            // Mutation 2: Invalid format
            assert!(validator.verify_signature("invalid-token").is_err());

            // Mutation 3: Missing segments
            assert!(validator.verify_signature("header.payload").is_err());

            Ok(())
        }

        // Test mutation: Algorithm validation bypass
        #[cfg(test)]
        async fn test_algorithm_mutation() -> Result<(), Error> {
            let token = "header.payload.signature";

            // Original behavior
            assert!(validator.verify_algorithm(token).is_ok());

            // Mutation 1: None algorithm
            let none_token = "eyJhbGciOiJub25lIn0.payload.signature";
            assert!(validator.verify_algorithm(none_token).is_err());

            // Mutation 2: Wrong algorithm
            let wrong_alg_token = "eyJhbGciOiJIUzUxMiJ9.payload.signature";
            assert!(validator.verify_algorithm(wrong_alg_token).is_err());

            Ok(())
        }

        // Test mutation: Claim validation bypass
        #[cfg(test)]
        async fn test_claim_mutation() -> Result<(), Error> {
            let mut claims = Claims::new();
            claims.sub = Some("user123".to_string());
            claims.iss = Some("acci".to_string());

            // Original behavior
            assert!(validator.validate_claims(&claims).is_ok());

            // Mutation 1: Missing required claims
            let empty_claims = Claims::new();
            assert!(validator.validate_claims(&empty_claims).is_err());

            // Mutation 2: Invalid issuer
            claims.iss = Some("invalid".to_string());
            assert!(validator.validate_claims(&claims).is_err());

            // Mutation 3: Invalid subject format
            claims.sub = Some("".to_string());
            assert!(validator.validate_claims(&claims).is_err());

            Ok(())
        }

        // Run all mutation tests
        test_timestamp_mutation().await?;
        test_signature_mutation().await?;
        test_algorithm_mutation().await?;
        test_claim_mutation().await?;
    }
}
