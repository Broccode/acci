# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Version Numbering

This project uses a three-number versioning system (X.Y.Z):

X (Major): Breaking changes, major feature overhauls
Y (Minor): New features, significant improvements
Z (Patch): Bug fixes, minor improvements

Example: Version 1.2.3

1: Major version
2: Minor version
3: Patch version

When to increment:

Major (X): When making incompatible changes that might break existing functionality
Minor (Y): When adding functionality in a backward-compatible manner
Patch (Z): When making backward-compatible bug fixes

## Making Changelog Entries For New Changes in Development

Add changes under the [Unreleased] section

Categorize them under appropriate headers:

Added for new features

Changed for changes in existing functionality

Deprecated for soon-to-be removed features

Removed for removed features

Fixed for bug fixes

Security for vulnerability fixes

Technical for technical changes/dependencies

Keep entries concise but descriptive

## When Releasing a Version

Convert the [Unreleased] section to a version number with date (e.g., [1.0.0] - 2024-01-20)

Create a new empty [Unreleased] section at the top

## General Rules

Newest changes always go at the top of the file

Each version should be in descending order (newest to oldest)

Group related changes under the same category

Use bullet points for each entry

## Development Workflow

For Every Code Change:

ALWAYS add an entry to the [Unreleased] section in this changelog

Write clear, descriptive change notes

Categorize changes appropriately using the headers above

Commit changes with meaningful commit messages

For Version Releases:

Move [Unreleased] changes to a new version section with today's date

Update version number in ProjectSettings.asset (bundleVersion)

Create a git tag for the version

Create a new empty [Unreleased] section at the top

## Release Process

When asked to make a release, follow these steps:

Review Changes:

Review all changes under [Unreleased]

Ensure all changes are properly categorized

Verify all changes are documented

Choose Version Number:

For new features: increment minor version (0.1.0 → 0.2.0)

For bug fixes: increment patch version (0.1.0 → 0.1.1)

For breaking changes: increment major version (0.1.0 → 1.0.0)

Update Files:

Move [Unreleased] changes to new version section with today's date

Update version in ProjectSettings.asset (bundleVersion)

Create new empty [Unreleased] section

Commit and Tag:

Commit all changes with message "release: Version X.Y.Z"

Create a git tag for the version (e.g., v0.2.0)

## [Unreleased]

### Added

- Completed core infrastructure setup (M1.1):
  - Basic repository structure with workspace configuration
  - Development environment with Docker setup
  - Initial linting configuration
  - Basic CI/CD pipeline with GitHub Actions
  - Test automation framework
- Partial completion of MVP Backend (M1.2):
  - Basic Axum setup with health check endpoint
  - Error handling structure with custom API errors
  - CORS and tracing middleware
  - Health check endpoint returning service status and version
  - Integration tests for health check endpoint:
    - Test coverage for HTTP status codes
    - Response payload validation
    - Middleware integration testing
  - Database integration:
    - PostgreSQL setup in Docker Compose
    - SQLx integration with offline mode support
    - Database migrations system
    - CLI tool for database management
    - Initial users table migration
    - Make commands for database operations
- Leptos frontend framework dependencies (leptos, leptos_meta, leptos_router) to workspace dependencies
- wasm-bindgen-test for frontend testing capabilities
- User Repository implementation in acci-db:
  - CRUD operations for user management
  - Email-based user lookup
  - Secure password hash storage
  - Automatic timestamp handling
  - Comprehensive test coverage
  - SQLx integration with type-safe queries
  - UUID-based user identification

### Changed

- Switched Leptos frontend framework from CSR (Client-Side Rendering) to SSR (Server-Side Rendering) for improved performance and SEO capabilities
- Enhanced User Repository implementation:
  - Added comprehensive documentation for all public types and functions
  - Fixed schema usage to properly use 'acci' schema for all database operations
  - Improved error handling documentation
  - Added proper clippy configuration and fixed all warnings
  - Added documentation for potential panics and error conditions

### Technical

- Updated workspace dependencies to latest versions:
  - tokio to 1.43.0
  - axum to 0.8.1
  - hyper to 1.6.0
  - serde to 1.0.217
  - Other dependencies updated to their latest stable versions
- Enhanced development environment:
  - Added structured shell scripts in devbox configuration
  - Improved init_hook for better rustup integration
  - Added convenient scripts for testing and documentation
- Updated Rust toolchain configuration:
  - Set specific Rust version to 1.84.1
  - Added support for multiple targets including WebAssembly
  - Configured minimal profile with essential components
- Improved workspace configuration:
  - Moved all dependency versions to workspace
  - Added SQLx with runtime-tokio-rustls and macros support
  - Added Clap for CLI tools
  - Enabled acci-db crate in workspace
  - Added acci-db binary target for database management
- Enhanced development guidelines in `.cursorrules`:
  - Added clear AI assistant role and expertise definition
  - Added explicit references to project guideline files
  - Improved formatting and structure of guidelines
  - Enhanced markdown formatting for better readability

## [0.1.6] - 2024-03-26

### Technical

- Modified production Docker build:
  - Temporarily disabled frontend assets copying to container
  - Simplified container image size by removing unused static files

## [0.1.5] - 2024-03-26

### Technical

- Enhanced Docker build process:
  - Added temporary main.rs for initial dependency build phase
  - Optimized two-phase build process: dependencies first, then full application
  - Improved build reliability by ensuring all required files exist during dependency resolution

## [0.1.4] - 2024-03-26

### Added

- Added proper library configurations for all workspace crates:
  - Added [lib] sections with explicit name and path configurations
  - Created initial lib.rs files with placeholder implementations
  - Configured proper dependencies and workspace inheritance

### Technical

- Improved Docker build process by removing dummy file creation
- Updated Rust version to 1.84.1 in Docker build

## [0.1.3] - 2024-03-26

### Added

- Added binary target configuration in root Cargo.toml
- Created initial main.rs with basic logging setup and entry point

## [0.1.2] - 2024-03-26

### Fixed

- Added missing root crate target (lib.rs) to fix Docker build process

## [0.1.1] - 2024-03-26

### Added

- License Management Framework with enterprise licensing and tenant-specific feature control
  - Basic license validation for MVP phase
  - Feature flag system for license control
  - Tenant-specific resource control
  - Offline validation support
  - License expiration notifications
  - License key generation and validation
  - Usage analytics and reporting capabilities
  - Emergency override system for critical situations
  - Tenant quota management system
  - Resource allocation tracking

### Technical

- Fixed permissions in docs-sync GitHub Action workflow to properly create translation issues
- Added Cargo.toml configurations for all workspace crates:
  - acci-api: Added axum integration and dependencies on auth/db
  - acci-auth: Added core authentication dependencies
  - acci-db: Added SQLx integration for database access
  - acci-frontend: Added Leptos framework and WASM testing support
  - All crates inherit workspace-wide configuration and lints

## [0.1.0] - 2024-02-09

### Changed

- Simplified core module structure by temporarily disabling unused modules (models, traits, types)
- Adjusted core prelude exports to match current module structure
- Enhanced multi-tenancy architecture with license and feature management capabilities
- Extended tenant isolation system to support feature-based access control
- Defined comprehensive test organization structure:
  - Separated unit tests (inline) and integration tests (/tests)
  - Established clear test directory structure with dedicated categories
  - Standardized test file naming and organization
  - Implemented container management guidelines for integration tests
  - Added test helper utilities and fixtures organization
- Enhanced development guidelines in `.cursorrules`:
  - Added clear AI assistant role and expertise definition
  - Added explicit references to project guideline files
  - Improved formatting and structure of guidelines
  - Enhanced markdown formatting for better readability

### Technical

- Set up Rust workspace with initial dependencies
- Configured workspace-wide lints and MSRV
- Implemented basic error handling in core crate
- Added Docker Compose configuration for development environment
- Configured multi-stage Dockerfile for development
- Added GitHub Actions workflows for:
  - Testing and linting
  - Security auditing
  - SBOM generation
  - License compliance checking
  - Release automation
  - Documentation deployment
  - Translation synchronization
- Enhanced test infrastructure:
  - Defined `/tests` directory structure for integration tests
  - Added support for testcontainers-rs framework
  - Implemented test categories (api, database, e2e, services)
  - Created helper utilities for container management
  - Set up test fixtures organization
  - Established naming conventions for test files
  - Added guidelines for container lifecycle management
- Updated development guidelines:
  - Added explicit file references for PLAN.md, MILESTONES.md, and CHANGELOG.md
  - Improved markdown formatting in `.cursorrules`
  - Enhanced section organization in guidelines

### Fixed

- Fixed SBOM generation in CI pipeline by correcting cargo-cyclonedx command syntax
- Fixed Clippy lint group priorities for pedantic and nursery groups
