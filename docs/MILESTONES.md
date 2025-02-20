# Project Milestones

## Overview

This document defines the key milestones for developing our enterprise-grade Rust-based system. The milestones are structured following an MVP (Minimum Viable Product) approach, with clear phases for iterative development and delivery.

## MVP Phase (M1)

**Timeframe**: 2-3 weeks

### M1.1: Core Infrastructure ✅ (Completed)

- Basic repository setup
  - GitHub repository structure
  - Development environment (Docker)
  - Basic linting setup
- CI/CD foundation
  - Simple GitHub Actions pipeline
  - Basic test automation

### M1.2: MVP Backend (In Progress)

### Basic Axum Setup ✅

- Health check endpoint implemented ✅
- Error handling structure with custom API errors ✅
- CORS and tracing middleware ✅
- Health check endpoint returning service status and version ✅
- Integration tests for health check endpoint ✅

### Database Integration ✅

- PostgreSQL setup in Docker Compose ✅
- SQLx integration with offline mode support ✅
- Database migrations system ✅
- Initial users table migration ✅
- CLI tool for database management ✅
- Make commands for database operations ✅
- User Repository implementation ✅
  - CRUD operations ✅
  - Email-based lookup ✅
  - Secure password storage ✅
  - Automatic timestamps ✅
  - UUID-based identification ✅
  - Comprehensive test coverage ✅

### Simple Authentication (In Progress)

- Basic Authentication Provider Infrastructure ✅
  - Password security with Argon2 ✅
  - JWT token management ✅
  - User authentication traits ✅
  - Repository integration ✅
  - Secure token generation with CSRNG ✅
  - Environment-based configuration ✅

- Login Endpoint Implementation ✅
  - REST API endpoint for user authentication ✅
  - Request validation and error handling ✅
  - Proper error mapping between core and API layers ✅
  - Integration with BasicAuthProvider ✅
  - Comprehensive test coverage with mock repositories ✅
  - CORS support for authentication endpoints ✅
  - Structured logging with sensitive data masking ✅
  - Proper dependency injection for database access ✅

- Session Management (In Progress)
  - Session repository implementation ✅
  - Session model and database schema ✅
  - Session validation middleware ✅
  - Session creation on login ✅
  - Session cleanup task implementation ✅
  - Session cleanup integration ✅
  - Session invalidation on logout ✅
  - Session hijacking prevention ✅
    - IP address validation ✅
    - User agent validation ✅
    - Secure token storage ✅
    - Token rotation on security events ✅
  - Integration tests for session lifecycle ✅

- Test User Configuration ✅
  - Default admin user migration ✅
  - Test user migrations ✅
  - Password hash generation tool ✅
  - Test user management commands ✅
  - Integration tests for test users ✅

### Remaining Tasks for M1.2

1. Enhance API Documentation:
   - Add OpenAPI/Swagger documentation
   - Document authentication flow
   - Add example requests/responses

2. Improve Observability:
   - Add structured logging to all endpoints
   - Add request correlation IDs
   - Add basic metrics collection

3. Security Hardening:
   - Enforce HTTPS in production
   - Add rate limiting for authentication endpoints
   - Add brute-force protection
   - Regular security audits
   - Penetration testing

### M1.3: MVP Frontend (Week 2-3)

- [ ] Basic Leptos setup
  - Project structure
  - Simple routing
- [ ] Minimal UI
  - Login form
  - Basic layout
  - Success page after login

## Phase 2: Core Features (M2)

**Timeframe**: 6-8 weeks

### M2.1: Enhanced Security (Week 1-2)

- [ ] Multi-factor authentication
- [ ] RBAC implementation
- [ ] API key management
- [ ] Security headers
- [ ] SBOM generation (CycloneDX)

### M2.2: Multi-tenancy (Week 3-4)

- [ ] Tenant isolation
- [ ] Tenant-specific configuration
- [ ] Database partitioning
- [ ] Tenant onboarding

### M2.3: API Enhancement (Week 5-6)

- [ ] REST API expansion
- [ ] GraphQL integration
- [ ] API documentation (OpenAPI)
- [ ] Rate limiting
- [ ] API versioning

### M2.4: Observability (Week 7-8)

- [ ] OpenTelemetry integration
- [ ] Prometheus metrics
- [ ] Grafana dashboards
- [ ] Distributed tracing
- [ ] Enhanced logging

### M2.5: Basic License Management (Week 8)

- [ ] Basic license validation
  - [ ] Simple license key check
  - [ ] Basic feature flag system

## Phase 3: Enterprise Features (M3)

**Timeframe**: 6-8 weeks

### M3.1: Advanced Features

- [ ] Event sourcing
- [ ] CQRS implementation
- [ ] Workflow engine
- [ ] Plugin architecture

### M3.2: Performance & Scaling

- [ ] Caching strategy
- [ ] Load balancing
- [ ] Auto-scaling
- [ ] Performance optimization

### M3.3: Advanced Security

- [ ] End-to-end encryption
- [ ] PII data masking
- [ ] Advanced audit logging
- [ ] Compliance reporting

### M3.4: License Management System

- [ ] Enterprise License Management
  - [ ] License key generation infrastructure
  - [ ] Time-based license validation
  - [ ] Feature-based access control
  - [ ] Offline validation support
  - [ ] License renewal workflow
  - [ ] Usage analytics and reporting

- [ ] Multi-tenant Feature Control
  - [ ] Tenant feature configuration system
  - [ ] Quota management implementation
  - [ ] Resource tracking and analytics
  - [ ] Tenant-specific policy engine
  - [ ] Billing integration framework

## Phase 4: Production Readiness (M4)

**Timeframe**: 4-6 weeks

### M4.1: Production Infrastructure

- [ ] Production Docker setup
- [ ] Zero-downtime deployment
- [ ] Backup strategy
- [ ] Disaster recovery

### M4.2: Documentation & Training

- [ ] Operations manual
- [ ] API documentation
- [ ] Developer guides
- [ ] Training materials

## Questions to Clarify

1. Are there specific MVP features that should be prioritized?
2. What are the minimal security requirements for the MVP?
3. Are there existing systems to integrate with in the MVP phase?
4. What are the basic performance requirements for the MVP?

## Notes

- All milestones follow best practices from `.cursorrules`
- Each milestone requires complete documentation
- Code reviews are mandatory
- Automated tests are required
- Regular security audits
- Continuous performance monitoring
- For each completed milestone step:
  - Developer documentation must be added to `/docs/{lang}` in all supported languages (EN, DE, SQ)
  - Documentation must follow the established structure and terminology
  - Documentation must be reviewed and approved before milestone completion
  - Documentation must include:
    - Technical architecture details
    - Implementation decisions
    - API documentation if applicable
    - Configuration guidelines
    - Troubleshooting guides
    - Code examples
    - Performance considerations
    - Security implications

## Documentation Strategy

### Structure

Each milestone's documentation will be organized in the following directories:

- `/docs/en/` - English documentation (primary)
- `/docs/de/` - German documentation
- `/docs/sq/` - Albanian documentation

### Documentation Requirements

1. All milestone documentation must be:
   - Written in clear, technical language
   - Consistent across all supported languages
   - Version controlled
   - Reviewed by technical and language experts
   - Updated with each milestone iteration
   - Cross-referenced with related documentation
   - Searchable and well-structured

2. Documentation Format:
   - Markdown files for general documentation
   - OpenAPI/Swagger for API documentation
   - Mermaid diagrams for visual representations
   - Code examples with syntax highlighting
   - Step-by-step guides where applicable

3. Quality Assurance:
   - Technical review of primary (English) documentation
   - Translation review by native speakers
   - Consistency check across all languages
   - Validation of technical accuracy
   - Verification of completeness

## Testing Strategy

### Test Organization

1. Unit Tests:
   - Located inline with the source code
   - Fast execution for quick feedback
   - Run by default with `cargo test`
   - Focus on single components/functions
   - Mock external dependencies

2. Integration Tests:
   - Separate test directory (`tests/`)
   - Must use testcontainers-rs framework for container-based tests
   - Excluded from default test run to avoid delays
   - Run with `cargo test --test '*'`
   - Test real interactions between components
   - Test database interactions
   - Test external service integrations

### Test Directory Structure

```text
tests/
├── api/              # API integration tests
├── database/         # Database integration tests
├── e2e/             # End-to-end tests
├── fixtures/         # Test fixtures and data
├── helpers/         # Test helper functions
└── services/        # Service integration tests
```

Each test directory should contain:

- `mod.rs` - Module declarations and common utilities
- `*_test.rs` - Actual test files
- `common/` - Shared test utilities for that specific test category

### Integration Test Guidelines

1. File Naming:
   - Test files must end with `_test.rs`
   - Names should clearly indicate the tested component
   - Example: `user_service_test.rs`, `auth_api_test.rs`

2. Test Organization:
   - One test file per component/service
   - Clear test categories using test modules
   - Shared setup in `mod.rs`
   - Common utilities in `helpers/`

3. Container Management:
   - Container lifecycle in `helpers/containers.rs`
   - Reuse containers where possible
   - Proper cleanup in `Drop` implementations
   - Version-pinned images in constants

### Test Requirements

1. Test Structure:
   - Clear separation between unit and integration tests
   - Proper test naming convention
   - Descriptive test cases
   - Comprehensive test coverage
   - Performance considerations for test execution

2. Container-based Testing:
   - Use testcontainers-rs for all container-dependent tests
   - Proper cleanup after test execution
   - Isolated test environments
   - Version-pinned container images
   - Configurable container settings

3. Test Quality:
   - No flaky tests allowed
   - Proper error messages
   - Comprehensive assertions
   - Clean test data management
   - Proper mocking of external services

4. CI/CD Integration:
   - Separate pipeline stages for unit and integration tests
   - Proper caching of test containers
   - Parallel test execution where possible
   - Test result reporting
   - Coverage reporting

## Dependencies

```mermaid
graph TD
    M1-->M2
    M2-->M3
    M3-->M4
```

## MVP Success Criteria

1. Test user can log in through the UI
2. Successful login redirects to a simple success page
3. Basic error handling works
4. Simple deployment works
5. Basic documentation exists
