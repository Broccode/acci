# Repository Structure

## Overview

The repository follows a standard Rust workspace structure with additional organization for enterprise-grade development. Below is a detailed breakdown of the key directories and their purposes.

## Directory Structure

```text
acci/
├── .github/                    # GitHub specific configurations
│   ├── workflows/             # CI/CD pipeline definitions
│   └── ISSUE_TEMPLATE/        # Issue and PR templates
├── .vscode/                   # VS Code configurations
├── crates/                    # Rust workspace members
│   ├── acci-core/            # Core library functionality
│   ├── acci-db/              # Database access layer
│   └── acci-api/             # API implementation
├── deploy/                    # Deployment configurations
│   ├── docker/               # Docker-related files
│   └── k8s/                  # Kubernetes manifests
├── docs/                      # Project documentation
│   └── infrastructure/       # Infrastructure documentation
├── src/                      # Main application source
└── tests/                    # Integration tests
    ├── api/                  # API integration tests
    ├── database/             # Database integration tests
    └── helpers/              # Test helper functions
```

## Key Configuration Files

- `.clippy.toml` - Custom Clippy linting rules
- `.cursorrules` - Project-specific development guidelines
- `.editorconfig` - Editor configuration for consistent coding style
- `.gitignore` - Git ignore patterns
- `Cargo.toml` - Workspace and dependency definitions
- `deny.toml` - Dependency audit configuration
- `devbox.json` - Development environment configuration
- `rust-toolchain.toml` - Rust toolchain specification
- `CHANGELOG.md` - Project changelog
- `MILESTONES.md` - Project milestones and progress
- `PLAN.md` - Detailed project planning document
- `bom.json` - Software Bill of Materials

## Development Guidelines

1. All new crates should be added under the `crates/` directory
2. Documentation must be maintained in English
3. Configuration files should be placed in the repository root
4. Tests should be organized by type (unit, integration, e2e)
5. Docker-related files should be placed in `deploy/docker/`
6. Each crate should have its own comprehensive test suite
7. API documentation must be generated using rustdoc
8. Database migrations should be version controlled
9. Security-related configurations must be properly managed

## Best Practices

1. See .cursorrules for more details
2. Follow the established directory structure for new components
3. Keep documentation in sync across all language versions
4. Update relevant configuration files when adding new features
5. Maintain clear separation of concerns between crates
6. Follow the testing directory structure for new tests
7. Use proper error handling and logging throughout the codebase
8. Implement comprehensive testing for all new features
9. Follow security best practices for all components
10. Keep dependencies up to date and regularly audited
11. Maintain proper versioning and changelog updates

## Security Considerations

1. Sensitive configuration must use environment variables
2. API keys and secrets must never be committed to the repository
3. Regular security audits must be performed
4. Dependencies must be regularly updated and verified
5. All security-related changes must be documented

## Documentation Standards

1. All public APIs must be documented
2. Code examples must be included where appropriate
3. Configuration options must be thoroughly explained
4. Security implications must be clearly stated
5. Version compatibility must be documented
6. Breaking changes must be highlighted
7. Documentation must be kept in sync with code changes

## Testing Requirements

1. Unit tests for all business logic
2. Integration tests for API endpoints
3. Database migration tests
4. Performance benchmarks where applicable
5. Security testing for authentication/authorization
6. Load testing for critical endpoints
7. Proper test isolation and cleanup
