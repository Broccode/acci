# Development Environment

## Overview

Our development environment is configured to provide a consistent and efficient workflow across all development machines. This document outlines the key components and setup procedures.

## Prerequisites

- Rust (latest stable version)
- Docker and Docker Compose
- VS Code or JetBrains RustRover
- Git

## IDE Configuration

### VS Code

The repository includes pre-configured VS Code settings:

- Rust-analyzer extension settings
- Custom tasks for common operations
- Debugging configurations
- Recommended extensions

### RustRover

Recommended settings for RustRover are provided in the repository:

- Run/Debug configurations
- Code style settings
- Live templates
- Custom macros

## Docker Development Environment

Our Docker development environment provides:

- Consistent development environment across all machines
- Isolated testing environment
- Local service dependencies
- Hot-reload capabilities

### Key Features

1. Multi-stage builds for optimal image size
2. Development-specific configurations
3. Volume mounting for fast development cycles
4. Integration with IDE debugging

## Linting and Formatting

### Clippy Configuration

Custom Clippy rules are defined in `.clippy.toml`:

- Strict linting rules
- Project-specific configurations
- Performance-related checks
- Safety-related checks

### Rustfmt Configuration

Consistent code formatting is enforced through rustfmt:

- Standard Rust formatting rules
- Custom configurations for project specifics
- Integration with IDE formatting

## Testing Infrastructure

- Unit tests alongside source code
- Integration tests in `/tests` directory
- End-to-end tests with Docker compose
- Test helpers and utilities

## Development Workflow

1. Clone the repository
2. Install prerequisites
3. Run `cargo build` to verify setup
4. Start Docker development environment
5. Open in VS Code or RustRover
6. Begin development with hot-reload

## Best Practices

1. Always use the Docker development environment
2. Run tests before committing
3. Follow the linting rules
4. Keep dependencies up to date
5. Document new development requirements
