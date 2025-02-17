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

- Added detailed documentation for pre-commit hook setup in `scripts/SETUP_PRE_COMMIT.md`
- Comprehensive test strategy integration overview with detailed phase transitions
- Resource allocation details including FTE requirements and infrastructure costs
- Expanded risk management section with concrete mitigation strategies
- Observability integration configuration for test metrics
- Alert configuration for test quality monitoring
- Links to related testing documentation
- Maintenance and update guidelines for testing documentation
- Comprehensive authentication test suite improvements:
  - Property-based testing for auth flows
  - Detailed error scenario coverage
  - Configuration testing for rate limiting
  - Concurrent authentication flow testing
  - Enhanced token tampering tests
  - Registration validation tests
- Enhanced CLI tool test coverage:
  - Comprehensive test suite for database CLI tool
  - Improved password hashing tool tests
  - Enhanced test user management tool tests
  - Property-based testing for password hashing
  - Detailed output format validation
  - Extensive error scenario coverage
  - Performance benchmarking for critical operations
- Enhanced CI pipeline with comprehensive test metrics collection
  - Added mutation testing with cargo-mutants
  - Added performance benchmark tracking
  - Added detailed coverage reporting for critical paths
  - Added metrics collection and reporting to Prometheus
- New test metrics scripts
  - Added performance regression checking
  - Added test metrics report generation
  - Added Prometheus metrics push capability
- Configurable test metrics thresholds
  - Added JSON configuration for all test metrics
  - Component-specific coverage thresholds
  - Performance and memory usage limits
- Enhanced metrics reporting
  - Detailed component coverage tracking
  - Performance percentiles (p50, p90, p99)
  - Memory usage monitoring
  - Status tracking for coverage, mutation, and performance
- Comprehensive test metrics documentation
  - Added detailed system overview
  - Configuration guide
  - Usage instructions
  - Maintenance procedures
  - Troubleshooting guide
  - System architecture diagram
  - Customization examples
- Grafana alerting rules
  - Coverage alerts
  - Performance regression alerts
  - Memory usage alerts
  - Component-specific alerts
  - Customized notification policies
  - Mutation score regression alerts
  - Granular performance alerts (p50, p90, p99)
  - Enhanced flaky test detection
- Alert resolution documentation
  - Detailed investigation procedures
  - Step-by-step resolution guides
  - Escalation procedures
  - Contact information
  - Response time requirements
  - Alert-specific troubleshooting
  - Severity level definitions
  - Investigation tools and commands
  - Automation opportunities
  - Dashboard links
  - Runbook references
- Enhanced Grafana alerting rules
  - Added component coverage regression detection
  - Added test execution error monitoring
  - Added resource usage alerts (CPU & Memory)
  - Added test duration trend analysis
  - Added runbook and dashboard links to all alerts
  - Added team assignments for better routing
- Improved notification policies
  - Added team-specific Slack channels
  - Enhanced alert grouping by team and category
  - Optimized notification intervals
  - Added dedicated performance alert channel
- Enhanced token validation testing framework with granular tampering actions
- New property-based tests for comprehensive token validation:
  - Combined tampering scenarios
  - Claim-specific manipulations
  - Header modifications
  - Signature tampering tests
- Improved test documentation and error reporting
- Data-driven approach to token manipulation testing
- CLI tools for user management and password hashing
  - `acci-users` tool for managing users (add, list, delete, reset password)
  - `acci-passwd` tool for password hashing with Argon2id
  - Comprehensive test suite for both tools
  - Support for JSON output format in password hashing
  - Concurrent operation support
  - Error handling and input validation
  - Standardized JSON error output format
  - Enhanced documentation with usage examples
  - Improved security considerations and best practices
  - Explicit input validation using validator crate
- Improved CI/CD pipeline:
  - Enhanced coverage reporting with detailed component analysis
  - Switched from Codecov to Coveralls for better integration
  - Added comprehensive security reporting
  - Improved metrics collection and visualization
  - Enhanced artifact organization and documentation
  - Added detailed test execution time tracking
  - Implemented strict coverage thresholds by component
  - Added automated security vulnerability reporting
  - Enhanced SBOM generation and documentation
  - Improved test metrics reporting with detailed breakdowns
- Comprehensive rate limiting tests including bypass attempts
- Tests for endpoint-specific rate limits
- Tests for IP and User-Agent rotation attempts
- Comprehensive session security tests
- Session fixation prevention tests
- Session hijacking prevention tests
- Session replay prevention tests
- Concurrent session management tests
- Granular session security tests
- Admin-initiated session invalidation tests
- Session invalidation on account changes tests
- Basic timing attack prevention tests

### Changed

- Updated error handling in CLI tools:
  - Replaced generic error handling with specific error types
  - Added NotFound error variant for resource lookup failures
  - Improved user-facing error messages in CLI tools
  - Enhanced error handling documentation
- Reorganized documentation structure:
  - Moved all test-related documentation from `docs/infrastructure/` to `docs/tests/`
  - Moved action plans from `docs/infrastructure/` to root `docs/` directory
  - Improved documentation organization for better maintainability
  - Updated document cross-references to reflect new structure
- Updated CI workflow to include additional test quality checks
- Improved security audit reporting with JSON output
- Enhanced artifact collection for test metrics
- Improved Prometheus metric naming and documentation
- Updated metrics collection to use external configuration
- Enhanced performance metrics collection with percentiles
- Refined alerting thresholds and policies
- Improved metrics documentation structure
- Enhanced flaky test handling with rate and count thresholds
- Updated alert notification policies with team-specific channels
- Improved alert resolution procedures with detailed guides
- Enhanced documentation with tool-specific guidance
- Updated alert severity classifications
- Improved runbook organization and references
- Refined alert conditions for better accuracy
  - Updated regression detection thresholds
  - Improved trend analysis timeframes
  - Enhanced resource usage monitoring
  - Optimized alert timing parameters
- Enhanced alert annotations
  - Added runbook links for all alerts
  - Added dashboard links for quick access
  - Improved alert descriptions
  - Added team ownership information
- Refactored token tampering functionality for better reusability
- Improved error handling in token validation tests
- Enhanced test coverage for security-critical scenarios
- Enhanced test infrastructure:
  - Improved coverage reporting granularity
  - Added component-specific coverage thresholds
  - Enhanced security audit reporting
  - Improved metrics collection and visualization
  - Updated test execution time tracking
  - Enhanced artifact organization
  - Improved documentation generation

### Fixed

- Fixed unused_mut linter warnings in test files by adding #[allow(unused_mut)] attributes for MockSessionRepository instances
- Clarified resource allocation and infrastructure requirements
- Added missing links between testing documentation files
- Improved consistency in metrics definitions across phases
- Fixed `BasicAuthProvider::authenticate` to return `AuthResponse` instead of `AuthSession`
- Fixed constructor arguments in `BasicAuthProvider::new` to include `session_repo`
- Fixed session repository implementation in `crates/acci-db/src/repositories/session.rs`
- Fixed error handling in `crates/acci-core/src/error.rs`
- Fixed authentication route implementation in `crates/acci-api/src/routes/auth.rs`

### Security

- Added extensive security-focused tests for authentication:
  - Token tampering detection
  - Rate limiting validation
  - Concurrent session handling
  - Error scenario coverage
- Added detailed security vulnerability reporting in CI
- Implemented critical vulnerability checks in security audit
- Enhanced security metrics tracking
- Added security-specific alerting rules
- Improved security incident response procedures
- Enhanced security tool integration documentation
- Added comprehensive testing for JWT security vulnerabilities
- Improved validation of token claims and headers
- Enhanced detection of token tampering attempts
- Enhanced rate limiting test coverage for authentication endpoints
- Added distributed attack simulation tests
- Improved session security validation
- Added session ID property validation
- Enhanced session invalidation tests
- Added granular IP and User-Agent validation
- Implemented timing attack prevention checks

### TODO

- Parameterize rate limits in integration tests
- Add metrics assertions for rate limiting events
- Implement load tests for rate limiting under high concurrency
- Add tests for advanced bypass techniques
- Support different types of rate limits (time window, sliding window)
- Add more granular session hijacking tests
- Implement admin-initiated session invalidation tests
- Add tests for session invalidation on account changes
- Document security assumptions in tests
- Add timing attack prevention tests
- Parameterize session security test data using proptest
- Expand timing attack tests with sophisticated analysis
- Add negative test cases for session invalidation
- Implement property-based tests for session ID generation
- Add session security integration tests
- Document session security assumptions and requirements

## [0.1.24] - 2024-03-28

### Changed

- Restructured documentation directory:
  - Moved all documentation to root docs/ directory
  - Removed language-specific subdirectories (de/, sq/)
  - Unified infrastructure documentation in single location
  - Simplified documentation structure for better maintainability
- Updated test execution documentation in Integration_Tests.md to use Make targets instead of direct cargo commands for better consistency and maintainability
- Modified Makefile targets to exclude integration tests:
  - Added `--exclude acci-tests` to `clippy` target to prevent unwanted changes in test files
  - Added `--exclude acci-tests` to `fix` target to preserve test-specific imports
- Enhanced pre-commit hook script to improve development workflow:
  - Added proper error handling with `set -e`
  - Improved script organization with clear comments
  - Added automatic directory change to repository root
  - Added clear status messages for better user feedback

### Added

- Added French and Spanish translations to README.md
- Added new helper module `tests/src/helpers/auth.rs` for authentication test utilities
- Added new mock implementation `tests/src/mocks/user.rs` for user testing
- Added pre-commit hook script in `scripts/pre-commit.sh` that runs code formatting, fixing, linting and unit tests before each commit

### Changed

- Translated testing section in .cursorrules from German to English for consistency with the rest of the documentation
- Enhanced test infrastructure:
  - Improved session repository mocking in `tests/src/mocks/session.rs`
  - Updated authentication test cases in `tests/src/api/auth_test.rs`
  - Refined test user testing in `tests/src/api/test_users_test.rs`
  - Updated migration tests in `tests/src/api/migrations_test.rs`
  - Enhanced test helper organization in `tests/src/helpers/mod.rs`

### Fixed

- Fixed test user password hashes in database migration to match the actual test user passwords
- Added helper program to generate correct Argon2 password hashes
- Fixed test targets in Makefile to properly separate unit and integration tests:
  - test-unit now excludes acci-tests crate
  - test-integration now correctly runs tests in acci-tests crate
  - Fixed incorrect test pattern in integration test target
- Fixed Clippy warnings:
  - Added missing error documentation for hash_password function
  - Added #[allow(clippy::large_stack_arrays)] at crate level for acci-db
  - Added Eq implementation for Environment enum
  - Used Self instead of type name in Environment::default implementation

## [0.1.23] - 2024-03-28

### Technical

- Updated dependencies in Cargo.lock to latest compatible versions:
  - cc v1.2.13 -> v1.2.14
  - clap v4.5.28 -> v4.5.29
  - clap_builder v4.5.27 -> v4.5.29
  - equivalent v1.0.1 -> v1.0.2
  - miniz_oxide v0.8.3 -> v0.8.4
  - ring v0.17.8 -> v0.17.9
  - rustls v0.23.22 -> v0.23.23
  - smallvec v1.13.2 -> v1.14.0

## [0.1.22] - 2024-03-28

### Fixed

- Improved database initialization and migrations:
  - Schema and extensions are now created in the first migration
  - Ensured correct migration order
  - Sessions table is created in the correct schema
  - UUID generation explicitly uses public schema
  - Enhanced error handling during database initialization
  - Applied DRY principle in Makefile by using existing targets

### Changed

- Switched from `chrono::DateTime<Utc>` to `time::OffsetDateTime` for better SQLx compatibility
- Unified database commands in Makefile
- Enhanced integration tests:
  - Improved connection pool configuration for better stability
  - Increased connection pool limits and timeouts
  - Added proper error handling in email case sensitivity tests
  - Added small delay after user creation to ensure transaction completion
  - Improved test assertions with better error messages
  - Reduced test execution time from 16s to 9s

## [0.1.21] - 2024-03-28

### Added

- Test user configuration in acci-core
- Database migration for predefined test users
- Password hash generation tool in acci-db
- Mock repository implementation for integration testing
- Comprehensive test coverage for test user authentication

### Fixed

- Session invalidation and concurrent sessions
- Case-sensitive email search in user repository

### Changed

- Improved documentation and code structure
- Switched code coverage reporting from Codecov to Coveralls.io

## [0.1.20] - 2024-03-28

### Fixed

- Fixed Docker production build by adding missing root main.rs file

## [0.1.19] - 2024-03-28

### Fixed

- Fixed Docker production build by adding missing test_users.rs binary file for acci-db crate

## [0.1.18] - 2024-03-28

### Fixed

- Fixed Docker production build by adding missing dummy files for all crates:
  - Added main.rs and bin files for acci-db
  - Ensured all required source files are present for dependency resolution

## [0.1.17] - 2024-03-28

### Fixed

- Fixed Docker production build by adding missing lib.rs dummy file for acci-api crate

## [0.1.16] - 2024-03-28

### Fixed

- Fixed Docker production build by removing tests from workspace members in Dockerfile.prod

## [0.1.15] - 2024-03-28

### Fixed

- Fixed Docker production build by excluding test workspace from release builds to prevent missing Cargo.toml errors

## [0.1.14] - 2024-03-28

### Fixed

- Fixed Docker production build by excluding test workspace from release builds to prevent missing Cargo.toml errors

## [0.1.13] - 2024-03-28

### Fixed

- Fixed Docker production build by excluding test workspace from release builds to prevent missing Cargo.toml errors

## [0.1.12] - 2024-03-28

### Changed

- Updated database migrations to use Argon2 instead of Blowfish for password hashing:
  - Changed default admin user migration to use pre-computed Argon2 hash
  - Updated test users migration to use pre-computed Argon2 hashes
  - Ensured consistent password hashing across codebase
- Removed unused migrate binary from acci-db crate to simplify the codebase
- Updated project description to correctly reflect ACCI as an enterprise application framework rather than just a license management system:
  - Updated README.md in all languages (EN, DE, SQ)
  - Adjusted feature descriptions to show license management as one of many features
  - Maintained consistent terminology across all documentation
- Restructured milestone M3.4 to better reflect the role of license management as a feature:
  - Renamed from "License Management System" to "Enterprise Features and License Management"
  - Adjusted subtasks to align with the framework's broader scope
  - Updated task descriptions to maintain consistency with overall architecture
- Updated milestone documentation to reflect authentication progress in all supported languages (EN, DE, SQ)
- Improved dependency management:
  - Moved all dependency definitions to workspace level
  - Implemented strict workspace inheritance for shared dependencies
  - Added dependency management guidelines to .cursorrules
  - Removed redundant version specifications in individual crates
  - Centralized feature configuration in workspace
- Updated acci-db binary to use DATABASE_URL environment variable:
  - Added proper environment variable handling
  - Improved error messages and logging
  - Added fallback to default configuration
- Added missing documentation for Environment enum and variants
- Moved auth integration tests from `acci-auth/tests` to central integration test suite
- Fixed password hashing in auth integration tests
- Cleaned up test module exports in integration tests

### Added

- Added comprehensive README.md in three languages (EN, DE, SQ):
  - Project description and key features
  - Quick start guide with make commands
  - Links to language-specific documentation
  - License and security information
  - Contributing guidelines
- Added database migration for default admin user:
  - Secure password hashing using pgcrypto's blowfish
  - Default credentials: admin/whiskey
  - Idempotent migration with conflict handling
  - Integration tests for migration and authentication
  - Test infrastructure with Docker containers
- Implemented default test user for development:
  - Username: admin
  - Password: whiskey
  - Secure password hashing with Argon2
  - Comprehensive test coverage for authentication flow
  - Mock repository implementation for testing
- Basic Authentication Provider Infrastructure:
  - Modular provider system for extensible authentication methods
  - Trait-based approach for provider implementations
  - Support for multiple authentication strategies
  - Password security with Argon2 implementation
  - JWT token management and validation
  - User authentication traits and repository integration
  - Comprehensive test coverage for auth components
  - Security-first implementation following best practices
- Login endpoint implementation:
  - REST API endpoint for user authentication ✅
  - Request validation and error handling ✅
  - Proper error mapping between core and API layers ✅
  - Integration with BasicAuthProvider ✅
  - Comprehensive test coverage with mock repositories ✅
  - CORS support for authentication endpoints ✅
  - Structured logging with sensitive data masking ✅
  - Proper dependency injection for database access ✅
  - Unit tests for invalid credentials scenario ✅
- Updated milestone documentation to reflect authentication progress in all supported languages (EN, DE, SQ)
- Added test-users make targets for managing test users in development:
  - test-users-list: List all test users and their status
  - test-users-reset: Reset test users to default configuration
  - test-users-clean: Delete all test users

### Technical

- Enhanced test infrastructure:
  - Added mock repositories for unit testing
  - Implemented proper dependency injection in tests
  - Added test coverage for error scenarios
  - Improved test isolation and maintainability
  - Added structured test organization
- Improved code quality:
  - Fixed clippy warnings
  - Added proper documentation
  - Implemented proper error handling
  - Added structured logging
  - Improved type safety with proper imports
- Fixed dependency configuration in acci-api:
  - Moved rand_core from dev-dependencies to dependencies
  - Ensured proper workspace inheritance for cryptographic dependencies
  - Fixed import resolution for OsRng in auth tests
  - Resolved version conflicts in rand and rand_core dependencies
  - Updated getrandom to version 0.3.1 for better compatibility
- Fixed cyclic dependency between acci-auth and acci-db:
  - Removed direct dependency from acci-db to acci-auth
  - Moved password hashing functionality to acci-core
  - Improved crate architecture by centralizing core functionality
- Fixed dependency configuration in acci-db:
  - Added acci-auth dependency for test-users binary
  - Resolved import resolution for password hashing functionality

### Fixed

- Fixed test user password hashes in database migration to match the actual test user passwords
- Added helper program to generate correct Argon2 password hashes
- Fixed test targets in Makefile to properly separate unit and integration tests:
  - test-unit now excludes acci-tests crate
  - test-integration now correctly runs tests in acci-tests crate
  - Fixed incorrect test pattern in integration test target
- Fixed Clippy warnings:
  - Added missing error documentation for hash_password function
  - Added #[allow(clippy::large_stack_arrays)] at crate level for acci-db
  - Added Eq implementation for Environment enum
  - Used Self instead of type name in Environment::default implementation

## [0.1.11] - 2024-03-27

### Added

- Added `.editorconfig` file for consistent code formatting across different editors and IDEs:
  - Configured specific rules for Rust files matching rustfmt settings
  - Added specialized configurations for TOML, Markdown, YAML, and JSON files
  - Set up proper Git commit message formatting
  - Configured documentation-specific rules
  - Added Makefile-specific tab configuration

### Changed

- Completed database integration milestone (M1.2):
  - Finalized PostgreSQL setup with migrations system
  - Completed user schema design with UUID and timestamp support
  - Implemented full Repository pattern with CRUD operations
  - Added comprehensive test coverage using testcontainers
  - Integrated CLI tools for database management
  - Updated milestone documentation to reflect completion

## [0.1.10] - 2024-03-27

### Changed

- Moved user repository tests from `user.rs` to integration tests in `user_test.rs`
- Fixed UUID import in tests to use SQLx's UUID type instead of direct uuid crate

## [0.1.9] - 2024-03-27

### Technical

- Updated workspace version to match package version
- Synchronized version numbers across workspace crates

## [0.1.8] - 2024-03-27

### Fixed

- Fixed Docker build process by creating proper dummy source files for each crate and maintaining correct directory structure during build phases

## [0.1.7] - 2024-03-27

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
- Enhanced test coverage for database layer:
  - Comprehensive unit tests for database connection handling
  - Test coverage for connection pool limits and timeouts
  - Error handling tests for invalid configurations
  - Migration error handling tests
  - Complete test coverage for DbError type
  - Environment-aware test configuration
  - Connection pool lifecycle tests

### Changed

- Switched Leptos frontend framework from CSR (Client-Side Rendering) to SSR (Server-Side Rendering) for improved performance and SEO capabilities
- Enhanced User Repository implementation:
  - Added comprehensive documentation for all public types and functions
  - Fixed schema usage to properly use 'acci' schema for all database operations
  - Improved error handling documentation
  - Added proper clippy configuration and fixed all warnings
  - Added documentation for potential panics and error conditions
- Improved test organization and separation:
  - Moved database-dependent tests to integration tests
  - Enhanced unit tests to be independent of external dependencies
  - Fixed body handling in API error tests
  - Simplified test database configuration
  - Improved test isolation and maintainability
- Refactored database integration tests:
  - Migrated to testcontainers for improved test isolation
  - Added proper database initialization with extensions
  - Improved connection pool testing with better timeout handling
  - Enhanced error condition testing for invalid configurations
  - Added proper cleanup of test resources

### Technical

- Updated workspace dependencies to latest versions:
  - tokio to 1.43.0
  - axum to 0.8.1
  - hyper to 1.6.0
  - serde to 1.0.217
  - Other dependencies updated to their latest stable versions
- Switched from chrono to time crate for timestamp handling in User repository
- Moved uuid dependency to workspace dependencies for better version management
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
- Improved code quality through Clippy fixes:
  - Optimized error handling in API responses
  - Enhanced logging structure with proper allow attributes
  - Removed unnecessary imports
  - Improved JSON serialization without macro usage
  - Added proper test configuration for Clippy rules
  - Limited Clippy checks to libraries and binaries to avoid integration test issues
- Improved test organization and execution:
  - Separated unit tests and integration tests in CI pipeline
  - Moved database-dependent tests from repository modules to integration tests
  - Added separate make commands for running unit and integration tests
  - Enhanced test documentation and organization
  - Optimized CI pipeline to run tests in correct order with proper database setup
  - Switched to testcontainers for database integration tests
  - Added Docker-in-Docker support for CI pipeline
- Updated Leptos stack to version 0.7 to address unmaintained dependencies:
  - Resolved unmaintained `instant` dependency issue (RUSTSEC-2024-0384)
  - Resolved unmaintained `proc-macro-error` dependency issue (RUSTSEC-2024-0370)

### Security

- Updated sqlx to version 0.8.1 to fix Binary Protocol Misinterpretation vulnerability (RUSTSEC-2024-0363)

### Fixed

- Fixed database setup in integration tests:
  - Added pgcrypto extension for cryptographic functions
  - Added uuid-ossp extension for UUID generation
  - Ensured extensions are created before schema creation
  - Improved test database initialization reliability

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
