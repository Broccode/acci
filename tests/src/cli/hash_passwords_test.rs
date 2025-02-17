use acci_core::auth::verify_password;
use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use regex::Regex;
use std::collections::HashSet;

#[test]
fn test_hash_password_command() {
    // Test with valid password
    let assert = AssertCommand::cargo_bin("hash_passwords")
        .unwrap()
        .arg("secure_password123")
        .assert();

    assert.success();

    // Get hash from output
    let output = assert.get_output();
    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Verify hash format using regex
    let hash_format =
        Regex::new(r"\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+").unwrap();
    assert!(
        hash_format.is_match(&hash),
        "Hash should match Argon2 format: {}",
        hash
    );

    // Verify hash length is within expected bounds
    assert!(
        hash.len() >= 50 && hash.len() <= 120,
        "Hash length should be between 50 and 120 characters"
    );

    // Verify hash is valid and can be used to verify the original password
    assert!(
        verify_password("secure_password123", &hash).is_ok(),
        "Hash should verify against original password"
    );
}

#[test]
fn test_hash_password_salt_uniqueness() {
    // Generate multiple hashes for the same password
    let mut hashes = HashSet::new();
    for _ in 0..5 {
        let output = AssertCommand::cargo_bin("hash_passwords")
            .unwrap()
            .arg("same_password")
            .output()
            .unwrap();

        let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        hashes.insert(hash);
    }

    // Verify all hashes are unique (different salts)
    assert_eq!(
        hashes.len(),
        5,
        "All hashes should be unique due to different salts"
    );

    // Verify all hashes can validate the original password
    for hash in hashes {
        assert!(
            verify_password("same_password", &hash).is_ok(),
            "All hashes should verify the same password"
        );
    }
}

#[test]
fn test_hash_password_empty() {
    AssertCommand::cargo_bin("hash_passwords")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "error: the following required arguments were not provided",
        ))
        .stderr(predicate::str::contains("<PASSWORD>"));
}

#[test]
fn test_hash_password_multiple_arguments() {
    AssertCommand::cargo_bin("hash_passwords")
        .unwrap()
        .args(["pass1", "pass2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error: unexpected argument"));
}

#[test]
fn test_hash_password_special_characters() {
    let password = "P@ssw0rd!$%^&*()";
    let assert = AssertCommand::cargo_bin("hash_passwords")
        .unwrap()
        .arg(password)
        .assert();

    assert.success();

    let hash = String::from_utf8_lossy(&assert.get_output().stdout)
        .trim()
        .to_string();
    assert!(
        verify_password(password, &hash).is_ok(),
        "Hash should verify against password with special characters"
    );
}

#[test]
fn test_hash_password_unicode() {
    let password = "パスワード123アБВ";
    let assert = AssertCommand::cargo_bin("hash_passwords")
        .unwrap()
        .arg(password)
        .assert();

    assert.success();

    let hash = String::from_utf8_lossy(&assert.get_output().stdout)
        .trim()
        .to_string();
    assert!(
        verify_password(password, &hash).is_ok(),
        "Hash should verify against password with Unicode characters"
    );
}

#[test]
fn test_hash_password_performance() {
    use std::time::Instant;

    let password = "benchmark_password";
    let start = Instant::now();

    let assert = AssertCommand::cargo_bin("hash_passwords")
        .unwrap()
        .arg(password)
        .assert();

    assert.success();

    let duration = start.elapsed();

    // Hash generation should take between 100ms and 500ms
    // This ensures it's not too fast (insecure) or too slow (poor UX)
    assert!(
        duration.as_millis() >= 100 && duration.as_millis() <= 500,
        "Hash generation took {:?}, should be between 100ms and 500ms",
        duration
    );
}

#[test]
fn test_hash_password_very_long() {
    // Test with a very long password (1024 characters)
    let long_password = "a".repeat(1024);
    let assert = AssertCommand::cargo_bin("hash_passwords")
        .unwrap()
        .arg(&long_password)
        .assert();

    assert.success();

    let hash = String::from_utf8_lossy(&assert.get_output().stdout)
        .trim()
        .to_string();
    assert!(
        verify_password(&long_password, &hash).is_ok(),
        "Hash should verify against very long password"
    );
}

#[test]
fn test_hash_password_short() {
    // Test with a very short password
    let short_password = "ab";
    AssertCommand::cargo_bin("hash_passwords")
        .unwrap()
        .arg(short_password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("error: password too short"));
}
