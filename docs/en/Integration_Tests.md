# Integration Tests

This document describes the structure and usage of integration tests in the ACCI project.

## Directory Structure

```text
tests/
├── Cargo.toml             # Test crate configuration
└── src/
    ├── lib.rs            # Main test library entry point
    ├── api/              # API integration tests
    │   ├── mod.rs        # API module configuration
    │   ├── health_test.rs    # Health endpoint tests
    │   ├── user_test.rs      # User management tests
    │   └── ...
    └── helpers/          # Shared test utilities
        ├── mod.rs        # Helper module configuration
        └── db.rs         # Database test helpers
```

## Test Organization

- All test modules are marked with `#[cfg(test)]`
- Tests are organized by feature area under the `api/` directory
- Common test utilities are centralized in the `helpers/` directory
- Each test file focuses on a specific feature or endpoint
- Test files follow the naming convention `*_test.rs`

## Database Testing with TestContainers

We use the `testcontainers` framework to run integration tests against a real PostgreSQL database:

- Each test gets its own isolated PostgreSQL container
- Containers are automatically cleaned up after tests complete
- Database setup includes:
  - Required PostgreSQL extensions (pgcrypto, uuid-ossp)
  - Schema creation
  - Migration execution
  - Test data initialization

### Database Helper Usage

```rust
use crate::helpers::db::setup_database;

async fn setup() -> Result<(Box<dyn std::any::Any>, PgUserRepository)> {
    let (container, pool) = setup_database().await?;
    let repo = PgUserRepository::new(pool);
    Ok((container, repo))
}
```

## Adding New Integration Tests

To add a new integration test:

1. Create a new file in `tests/src/api/` named `your_feature_test.rs`
2. Add the module to `tests/src/api/mod.rs`:

   ```rust
   mod your_feature_test;
   ```

3. Structure your test file:

   ```rust
   use anyhow::Result;
   use crate::helpers::db::setup_database;
   
   async fn setup() -> Result<(Box<dyn std::any::Any>, YourRepository)> {
       let (container, pool) = setup_database().await?;
       let repo = YourRepository::new(pool);
       Ok((container, repo))
   }
   
   #[tokio::test]
   async fn test_your_feature() -> Result<()> {
       let (_container, repo) = setup().await?;
       // Your test code here
       Ok(())
   }
   ```

### Best Practices

1. **Test Independence**
   - Each test should run in isolation
   - Don't rely on state from other tests
   - Use the setup helper to get a fresh database

2. **Resource Cleanup**
   - Keep the container handle in scope until test completion
   - Use the `Result` type for proper error handling
   - Let the test framework handle container cleanup

3. **Test Organization**
   - Group related tests in the same file
   - Use descriptive test names
   - Add comments explaining complex test scenarios

4. **Database Usage**
   - Use the provided database helpers
   - Don't modify the schema directly in tests
   - Use migrations for schema changes

5. **Error Handling**
   - Use `anyhow::Result` for test results
   - Add descriptive error messages
   - Test both success and error cases

### Example Test Structure

```rust
use anyhow::Result;
use crate::helpers::db::setup_database;

async fn setup() -> Result<(Box<dyn std::any::Any>, TestRepo)> {
    let (container, pool) = setup_database().await?;
    let repo = TestRepo::new(pool);
    Ok((container, repo))
}

#[tokio::test]
async fn test_successful_operation() -> Result<()> {
    // Arrange
    let (_container, repo) = setup().await?;
    
    // Act
    let result = repo.do_something().await?;
    
    // Assert
    assert!(result.is_ok());
    Ok(())
}

#[tokio::test]
async fn test_error_handling() -> Result<()> {
    // Arrange
    let (_container, repo) = setup().await?;
    
    // Act
    let result = repo.invalid_operation().await;
    
    // Assert
    assert!(result.is_err());
    Ok(())
}
```

## Running Tests

To run all integration tests:

```bash
cargo test
```

To run specific tests:

```bash
cargo test test_name
```

To run tests with output:

```bash
cargo test -- --nocapture
```
