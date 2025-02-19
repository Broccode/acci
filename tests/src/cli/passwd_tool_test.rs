use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use serde_json::Value;
use std::io::Write;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_password_hash_basic() -> anyhow::Result<()> {
    let assert = AssertCommand::cargo_bin("acci-passwd")?
        .arg("--password")
        .arg("test123!")
        .assert();

    assert
        .success()
        .stdout(predicate::str::is_match(r"^\$argon2.*$")?);

    Ok(())
}

#[tokio::test]
async fn test_password_hash_json_output() -> anyhow::Result<()> {
    let assert = AssertCommand::cargo_bin("acci-passwd")?
        .arg("--password")
        .arg("test123!")
        .arg("--format")
        .arg("json")
        .assert();

    assert.success();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    assert!(json["hash"]
        .as_str()
        .expect("Hash should be a string")
        .starts_with("$argon2"));
    assert_eq!(
        json["algorithm"]
            .as_str()
            .expect("Algorithm should be a string"),
        "argon2id"
    );
    assert_eq!(
        json["version"]
            .as_str()
            .expect("Version should be a string"),
        "19"
    );

    // Verify Argon2 parameters
    let params = &json["parameters"];
    assert_eq!(
        params["m_cost"]
            .as_u64()
            .expect("Memory cost should be a number"),
        4096
    ); // Memory cost
    assert_eq!(
        params["t_cost"]
            .as_u64()
            .expect("Time cost should be a number"),
        3
    ); // Time cost
    assert_eq!(
        params["p_cost"]
            .as_u64()
            .expect("Parallelism should be a number"),
        1
    ); // Parallelism
    assert_eq!(
        params["output_len"]
            .as_u64()
            .expect("Output length should be a number"),
        32
    ); // Hash length

    Ok(())
}

#[tokio::test]
async fn test_password_hash_stdin() -> anyhow::Result<()> {
    let mut file = NamedTempFile::new()?;
    writeln!(file, "test123!")?;

    let assert = AssertCommand::cargo_bin("acci-passwd")?
        .arg("--stdin")
        .pipe_stdin(file.path())?
        .assert();

    assert
        .success()
        .stdout(predicate::str::is_match(r"^\$argon2.*$")?);

    Ok(())
}

#[tokio::test]
async fn test_password_hash_validation() -> anyhow::Result<()> {
    // Test missing password
    let assert = AssertCommand::cargo_bin("acci-passwd")?.assert();
    assert
        .failure()
        .stderr(predicate::str::contains("Password must be provided"));

    // Test empty password via argument
    let assert = AssertCommand::cargo_bin("acci-passwd")?
        .arg("--password")
        .arg("")
        .assert();
    assert.failure().stderr(predicate::str::contains(
        "Password must be at least 8 characters",
    ));

    // Test empty password via stdin
    let mut file = NamedTempFile::new()?;
    writeln!(file, "")?;

    let assert = AssertCommand::cargo_bin("acci-passwd")?
        .arg("--stdin")
        .pipe_stdin(file.path())?
        .assert();
    assert.failure().stderr(predicate::str::contains(
        "Password must be at least 8 characters",
    ));

    // Test short password
    let assert = AssertCommand::cargo_bin("acci-passwd")?
        .arg("--password")
        .arg("short")
        .assert();
    assert.failure().stderr(predicate::str::contains(
        "Password must be at least 8 characters",
    ));

    // Test invalid format option (should default to text)
    let assert = AssertCommand::cargo_bin("acci-passwd")?
        .arg("--password")
        .arg("test123!")
        .arg("--format")
        .arg("invalid")
        .assert();
    assert
        .success()
        .stdout(predicate::str::is_match(r"^\$argon2.*$")?);

    Ok(())
}

#[tokio::test]
async fn test_password_hash_special_chars() -> anyhow::Result<()> {
    let special_passwords = [
        "test!@#$%^&*()",
        "пароль123",
        "パスワード123",
        "密码123",
        r#"test"'`~,.<>/?;:[]{}\|+="#,
    ];

    for password in &special_passwords {
        let assert = AssertCommand::cargo_bin("acci-passwd")?
            .arg("--password")
            .arg(password)
            .assert();

        assert
            .success()
            .stdout(predicate::str::is_match(r"^\$argon2.*$")?);
    }

    Ok(())
}

#[tokio::test]
async fn test_password_hash_concurrent() -> anyhow::Result<()> {
    let mut handles = vec![];

    // Spawn multiple concurrent password hashing operations
    for i in 0..5 {
        let handle = tokio::spawn(async move {
            AssertCommand::cargo_bin("acci-passwd")
                .expect("Failed to create acci-passwd command")
                .arg("--password")
                .arg(format!("test123!{}", i))
                .arg("--format")
                .arg("json")
                .assert()
                .success()
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await??;
    }

    Ok(())
}

#[tokio::test]
async fn test_password_hash_uniqueness() -> anyhow::Result<()> {
    // Hash the same password multiple times
    let password = "test123!";
    let mut hashes = Vec::new();

    for _ in 0..3 {
        let assert = AssertCommand::cargo_bin("acci-passwd")?
            .arg("--password")
            .arg(password)
            .assert();

        let output = assert.success().get_output();
        let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        hashes.push(hash);
    }

    // Verify all hashes are different (due to random salt)
    for i in 0..hashes.len() {
        for j in i + 1..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "Hashes should be unique due to random salt"
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_password_hash_performance() -> anyhow::Result<()> {
    use std::time::Instant;

    let password = "test123!";
    let start = Instant::now();

    let assert = AssertCommand::cargo_bin("acci-passwd")?
        .arg("--password")
        .arg(password)
        .assert();

    assert.success();
    let duration = start.elapsed();

    // Hashing should take a reasonable amount of time for security
    // but not too long for usability
    assert!(
        duration.as_millis() >= 100,
        "Hashing should not be too fast (minimum 100ms)"
    );
    assert!(
        duration.as_millis() <= 1000,
        "Hashing should not be too slow (maximum 1000ms)"
    );

    Ok(())
}

#[tokio::test]
async fn test_help_output() -> anyhow::Result<()> {
    let assert = AssertCommand::cargo_bin("acci-passwd")?
        .arg("--help")
        .assert();

    assert
        .success()
        .stdout(predicate::str::contains("ACCI Password Hashing Tool"))
        .stdout(predicate::str::contains("Argon2id algorithm"))
        .stdout(predicate::str::contains("cryptographically secure"))
        .stdout(predicate::str::contains("unique salt"))
        .stdout(predicate::str::contains(
            "avoid the password appearing in shell history",
        ));

    Ok(())
}
