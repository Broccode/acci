# Repository Structure

## Overview

The repository follows a standard Rust workspace structure with additional organization for enterprise-grade development. Below is a detailed breakdown of the key directories and their purposes.

## Directory Structure

```text
acci/
├── .github/                    # GitHub specific configurations
│   └── workflows/             # CI/CD pipeline definitions
├── .vscode/                   # VS Code configurations
├── crates/                    # Rust workspace members
│   └── acci-core/            # Core library functionality
├── deploy/                    # Deployment configurations
│   └── docker/               # Docker-related files
├── docs/                      # Project documentation
│   ├── en/                   # English documentation
│   ├── de/                   # German documentation
│   └── sq/                   # Albanian documentation
├── src/                      # Main application source
└── tests/                    # Integration tests
```

## Key Configuration Files

- `.clippy.toml` - Custom Clippy linting rules
- `.cursorrules` - Project-specific development guidelines
- `Cargo.toml` - Workspace and dependency definitions
- `deny.toml` - Dependency audit configuration
- `CHANGELOG.md` - Project changelog
- `MILESTONES.md` - Project milestones and progress
- `PLAN.md` - Detailed project planning document

## Development Guidelines

1. All new crates should be added under the `crates/` directory
2. Documentation must be maintained in all three languages (EN, DE, SQ)
3. Configuration files should be placed in the repository root
4. Tests should be organized by type (unit, integration, e2e)
5. Docker-related files should be placed in `deploy/docker/`

## Best Practices

1. Follow the established directory structure for new components
2. Keep documentation in sync across all language versions
3. Update relevant configuration files when adding new features
4. Maintain clear separation of concerns between crates
5. Follow the testing directory structure for new tests
