# ACCI CLI Tools

This package provides command-line tools for managing the ACCI system.

## Installation

The tools are installed as part of the ACCI system. You can also install them separately using:

```bash
cargo install acci-cli
```

## Available Tools

### acci-users

A tool for managing users in the ACCI system.

#### Commands

- `add`: Add a new user
- `list`: List all users
- `delete`: Delete a user
- `reset`: Reset a user's password

#### Examples

```bash
# Add a new user
acci-users --database-url "postgres://localhost/acci" add \
    --email "user@example.com" \
    --password "secure123!" \
    --full-name "John Doe"

# List all users
acci-users --database-url "postgres://localhost/acci" list

# Reset a user's password
acci-users --database-url "postgres://localhost/acci" reset \
    --email "user@example.com" \
    --password "newpass123!"

# Delete a user
acci-users --database-url "postgres://localhost/acci" delete \
    --email "user@example.com"
```

**Note**: For security, it's recommended to use the `DATABASE_URL` environment variable instead of passing it as a command-line argument:

```bash
export DATABASE_URL="postgres://localhost/acci"
acci-users add --email "user@example.com" --password "secure123!" --full-name "John Doe"
```

### acci-passwd

A secure password hashing tool that uses the Argon2id algorithm.

#### Options

- `--password`: Password to hash
- `--stdin`: Read password from stdin
- `--format`: Output format (text/json)

#### Examples

```bash
# Hash a password (basic)
acci-passwd --password "mysecurepass123!"

# Hash a password with JSON output
acci-passwd --password "mysecurepass123!" --format json

# Hash a password from stdin (more secure, avoids shell history)
echo "mysecurepass123!" | acci-passwd --stdin

# Use in scripts
PASSWORD=$(acci-passwd --password "mysecurepass123!" --format json)
echo $PASSWORD | jq .hash
```

## Error Handling

Both tools use a standardized JSON error format for error output. Example error output:

```json
{
  "code": "validation_error",
  "message": "Invalid input",
  "details": "Password must be at least 8 characters long"
}
```

Error codes:

- `validation_error`: Input validation failed
- `database_error`: Database operation failed
- `input_error`: Invalid or missing input
- `system_error`: System-level error

## Security Considerations

1. Always use environment variables for sensitive information like database URLs
2. Use `--stdin` with `acci-passwd` when possible to avoid passwords in shell history
3. Ensure proper file permissions when storing hashed passwords
4. Follow your organization's security policies for password requirements

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test user_tool_test
cargo test --test passwd_tool_test
```

### Adding New Features

1. Implement the feature
2. Add comprehensive tests
3. Update documentation
4. Submit a pull request

## License

This project is licensed under the Apache License, Version 2.0.
