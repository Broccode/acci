# Authentication Testing Strategy

## Overview

This document outlines the testing strategy for the authentication module, focusing on security, reliability, and edge cases. It serves as a living document that guides our testing efforts and evolves with our understanding of authentication challenges.

## Test Categories

### 1. Basic Authentication Flow Tests (`auth_flow.rs`)

Tests the core authentication workflow including:

- User registration (e.g., `test_registration_valid_credentials`)
- Login (e.g., `test_login_valid_password`)
- Token validation (e.g., `test_token_validation_active`)
- Logout (e.g., `test_logout_active_session`)
- Session management (e.g., `test_session_creation_success`)
- Timestamp validation (e.g., `test_token_timestamps_valid`)

Key test: `test_basic_auth_flow()`

### 2. Multiple Session Management (`auth_flow.rs`)

Tests handling of multiple concurrent sessions for a single user:

- Multiple session creation (e.g., `test_multiple_sessions_same_user`)
- Session isolation (e.g., `test_session_isolation_cross_user`)
- Independent session validation (e.g., `test_validate_multiple_sessions`)
- Selective session invalidation (e.g., `test_invalidate_specific_session`)

Key test: `test_auth_flow_with_multiple_sessions()`

### 3. Error Scenarios (`auth_flow.rs`)

Tests various error conditions and edge cases:

- Invalid credentials (e.g., `test_login_invalid_password`)
- Token expiration (e.g., `test_token_validation_expired`)
- Invalid token format (e.g., `test_token_validation_malformed`)
- Non-existent session logout (e.g., `test_logout_nonexistent_session`)
- Rate limiting (planned, e.g., `test_login_rate_limit_exceeded`)

Key test: `test_auth_flow_error_scenarios()`

### 4. Token Security (`auth_flow.rs`)

Tests token tampering and security measures:

- Payload tampering (e.g., modifying user roles in token)
- Signature tampering (e.g., attempting signature bypass)
- Header tampering (e.g., changing algorithm to 'none')
- Structural integrity (e.g., missing/extra JWT parts)
- JWT format validation (e.g., malformed base64)
- Advanced claim manipulation (e.g., extending expiration time)
- Algorithm tampering (e.g., downgrading from RS256 to HS256)

Key test: `test_token_tampering_scenarios()`

### 5. Session Lifecycle (`auth_flow.rs`)

Tests session management and deletion:

- Session creation (e.g., `test_session_creation_success`)
- Session validation (e.g., `test_session_validation_active`)
- Explicit session deletion (e.g., `test_session_deletion_success`)
- Session expiration (e.g., `test_session_expiration_cleanup`)
- Logout behavior with deleted sessions (e.g., `test_logout_deleted_session`)

Key test: `test_session_deletion_scenarios()`

### 6. Concurrency Testing (`auth_flow.rs`)

Tests concurrent operations and race conditions:

#### 6.1 Token Validation Concurrency

- Concurrent token validation
  - Scenario: 100 simultaneous validation requests for same token
  - Scenario: Token validation during session deletion
  - Scenario: Validation requests under connection pool saturation
  - Scenario: Validation near token expiration time

Key test: `test_concurrent_token_validation()`

#### 6.2 Session Management Concurrency

- Concurrent session creation
  - Scenario: Multiple sessions created simultaneously for same user
  - Scenario: Session creation during cleanup process
  - Scenario: Creation under high database load
  - Scenario: Creation with connection pool exhaustion

Key test: `test_concurrent_session_management()`

#### 6.3 Session Cleanup Under Load

- Concurrent cleanup and creation
  - Scenario: Cleanup running during active session creation
  - Scenario: Multiple cleanup tasks running simultaneously
  - Scenario: Cleanup during high-load login period
  - Scenario: Cleanup with database connection limitations

Key test: `test_session_cleanup_under_load()`

## Test Coverage Goals

1. **Authentication Flow**: 95% branch coverage
   - All success paths (login, logout, token validation)
   - All error paths (invalid credentials, expired tokens)
   - Edge cases (boundary conditions, invalid inputs)
   - Mutation score ≥90% for critical paths

2. **Token Management**: 100% branch coverage
   - Token generation (all JWT fields and claims)
   - Token validation (signature, expiration, claims)
   - Token expiration (time-based scenarios)
   - Token security (tampering attempts)
   - Mutation score ≥95% for token validation

3. **Session Management**: 95% branch coverage
   - Session creation (success and failure paths)
   - Session validation (active and expired)
   - Session deletion (explicit and automatic)
   - Multiple sessions (concurrent operations)
   - Mutation score ≥90% for session operations

4. **Concurrency**: 90% branch coverage
   - Race conditions (simultaneous operations)
   - Resource contention (database connections)
   - Connection pool behavior (saturation scenarios)
   - Cleanup processes (background tasks)
   - Interleaving coverage ≥85% (measured by tokio-loom)

## Security Testing Focus

1. **Token Security**
   - JWT integrity (signature validation)
   - Signature validation (prevent bypasses)
   - Expiration handling (time-based attacks)
   - Tampering detection (modified claims)
   - Algorithm verification (prevent downgrades)
   - Claim manipulation prevention (role escalation)

   Example vulnerabilities:
   - JWT signature bypass (algorithm confusion)
   - Token replay attacks
   - Expiration time manipulation
   - Role/permission elevation
   - Algorithm downgrade (RS256 to HS256)

   Security Metrics:
   - OWASP Top 10 coverage: 100% for relevant vulnerabilities
   - Known vulnerability resolution time: Critical < 24h, High < 72h
   - Token tampering detection rate: 100%
   - Algorithm downgrade prevention: 100%
   - Security scanner findings: Zero high/critical

   Tools:
   - OWASP ZAP for automated scanning
   - JWT_Tool for token testing
   - Custom security test suite
   - Dependency vulnerability scanners

2. **Session Security**
   - Session isolation (prevent cross-user access)
   - Proper invalidation (immediate effect)
   - Expiration handling (automatic cleanup)
   - Concurrent access (race conditions)
   - Race condition prevention (atomic operations)

   Example vulnerabilities:
   - Session fixation
   - Session hijacking
   - Session replay
   - Concurrent session manipulation
   - Session enumeration

   Security Metrics:
   - Session fixation prevention: 100%
   - Session hijacking prevention: 100%
   - Session enumeration prevention: 100%
   - Concurrent session limit enforcement: 100%
   - Session cleanup accuracy: 100%

   Tools:
   - Custom session security test suite
   - Load testing tools for session management
   - Database session tracking tools

3. **Authentication Security**
   - Credential validation (password policies)
   - Rate limiting (prevent brute force)
   - Error handling (information leakage)
   - Brute force protection (exponential backoff)

   Example vulnerabilities:
   - Credential stuffing
   - Password spraying
   - Timing attacks
   - Username enumeration
   - Rate limit bypass

   Security Metrics:
   - Brute force prevention effectiveness: 100%
   - Rate limiting effectiveness: 100%
   - Password policy enforcement: 100%
   - Information leakage prevention: 100%
   - Timing attack resistance: 100%

   Tools:
   - Custom authentication test suite
   - Timing analysis tools
   - Rate limit testing tools

## Test Data Generation

### 1. Property-Based Test Data

Property-based testing is particularly valuable for authentication systems because:

- It helps discover edge cases that manual test writing might miss
- It generates a wide range of inputs to test boundary conditions
- It automatically shrinks failing cases to minimal examples
- It provides better coverage of input space than hand-written tests
- It helps find unexpected interactions between different parts of the system

- **User Credentials**

  ```rust
  // Valid input strategies
  fn valid_email_strategy() -> impl Strategy<Value = String> {
      "[a-zA-Z0-9]{3,10}@[a-zA-Z0-9]{3,10}\\.[a-zA-Z]{2,5}"
          .prop_map(|s| s.to_lowercase())
  }

  fn valid_password_strategy() -> impl Strategy<Value = String> {
      "[A-Za-z0-9!@#$%^&*()]{8,32}"
  }

  // Success case strategies
  fn valid_user_strategy() -> impl Strategy<Value = User> {
      (valid_email_strategy(), valid_password_strategy())
          .prop_map(|(email, password)| User {
              email,
              password_hash: hash_password(&password).unwrap(),
              full_name: "Test User".to_string(),
              created_at: OffsetDateTime::now_utc(),
          })
  }

  // Example of a complete property-based test
  #[test]
  fn test_password_validation_properties() {
      let password_strategy = valid_password_strategy();
      proptest!(|(password in password_strategy)| {
          // Property: Valid passwords should pass validation
          assert!(validate_password(&password).is_ok());

          // Property: Password hash should be different from original
          let hash = hash_password(&password).unwrap();
          assert_ne!(password, hash);

          // Property: Same password should verify against its hash
          assert!(verify_password(&password, &hash).unwrap());

          // Property: Different passwords should not verify
          let different_password = password.chars().rev().collect::<String>();
          if different_password != password {
              assert!(!verify_password(&different_password, &hash).unwrap());
          }
      });
  }
  ```

- **Session Data**

  ```rust
  fn valid_session_strategy() -> impl Strategy<Value = Session> {
      (uuid::Uuid::new_v4(), valid_user_strategy(), timestamp_strategy())
          .prop_map(|(id, user, created)| Session::new(id, user, created))
  }

  // Example of session-based property test
  #[test]
  fn test_session_properties() {
      let session_strategy = valid_session_strategy();
      proptest!(|(session in session_strategy)| {
          // Property: Sessions should have valid timestamps
          let now = OffsetDateTime::now_utc();
          assert!(session.created_at <= now.unix_timestamp());
          assert!(session.expires_at > now.unix_timestamp());

          // Property: Session ID should be unique
          let another_session = Session::new(
              session.user_id,
              session.created_at,
              session.expires_at
          );
          assert_ne!(session.session_id, another_session.session_id);

          // Property: Session should be valid until expiration
          if now.unix_timestamp() < session.expires_at {
              assert!(session.is_valid());
          }
      });
  }
  ```

- **Token Data**

  ```rust
  // Token generation strategies
  fn valid_claims_strategy() -> impl Strategy<Value = Claims> {
      (
          valid_user_strategy(),
          timestamp_strategy(),
          vec!["user", "admin"].into_iter().prop_map(String::from)
      ).prop_map(|(user, exp, role)| Claims {
          sub: user.id.to_string(),
          exp,
          role,
          iat: OffsetDateTime::now_utc().unix_timestamp(),
      })
  }

  fn valid_key_strategy() -> impl Strategy<Value = Vec<u8>> {
      prop::collection::vec(any::<u8>(), 32..64)
  }

  fn valid_token_strategy() -> impl Strategy<Value = Token> {
      (valid_claims_strategy(), valid_key_strategy())
          .prop_map(|(claims, key)| {
              // Create JWT with claims and sign with key
              Token::new(claims).sign(&key)
          })
  }

  #[test]
  fn test_token_properties() {
      let token_strategy = valid_token_strategy();
      proptest!(|(token in token_strategy)| {
          // Property: Valid tokens should verify
          assert!(token.verify().is_ok());

          // Property: Claims should be extractable
          let claims = token.claims().unwrap();
          assert!(claims.exp > OffsetDateTime::now_utc().unix_timestamp());

          // Property: Modifying the token should invalidate it
          let mut invalid_token = token.clone();
          invalid_token.raw = format!("{}x", invalid_token.raw);
          assert!(invalid_token.verify().is_err());
      });
  }
  ```

### 2. Security Test Data

Security test data needs regular updates to stay current with emerging threats and attack patterns.
The examples below should be reviewed and updated monthly based on:

- New CVE entries related to authentication
- OWASP Top 10 changes
- Industry security advisories
- Penetration testing findings

- **Attack Vectors**

  ```rust
  // SQL Injection attempts for authentication
  fn sql_injection_strategy() -> impl Strategy<Value = String> {
      prop_oneof![
          Just("' OR '1'='1"),
          Just("' OR '1'='1' --"),
          Just("admin'--"),
          Just("' UNION SELECT '1','1','1"),
          Just("'; DROP TABLE users--"),
      ]
  }

  // XSS attempts in user data
  fn xss_attack_strategy() -> impl Strategy<Value = String> {
      prop_oneof![
          Just("<script>alert('xss')</script>"),
          Just("javascript:alert('xss')"),
          Just("<img src=x onerror=alert('xss')>"),
          Just("<svg onload=alert('xss')>"),
          Just("'><script>alert('xss')</script>"),
      ]
  }

  // NoSQL injection attempts
  fn nosql_injection_strategy() -> impl Strategy<Value = String> {
      prop_oneof![
          Just("[$ne]"),
          Just("{$gt: ''}"),
          Just("{$where: 'return true'}"),
          Just("[$exists]"),
      ]
  }

  // Valid but potentially tricky inputs
  fn edge_case_input_strategy() -> impl Strategy<Value = String> {
      prop_oneof![
          Just("user@example.com"),  // Basic valid email
          Just("user+test@example.com"),  // Email with plus
          Just("user@subdomain.example.com"),  // Subdomain
          Just("user.name@example.com"),  // Dots in local part
          Just("üser@example.com"),  // Unicode in local part
      ]
  }

  // Example of security property test
  #[test]
  fn test_input_sanitization_properties() {
      let attack_strategy = prop_oneof![
          sql_injection_strategy(),
          xss_attack_strategy(),
          nosql_injection_strategy(),
      ];

      proptest!(|(attack in attack_strategy)| {
          // Property: Malicious inputs should be rejected
          let result = validate_user_input(&attack);
          assert!(result.is_err());

          // Property: Sanitized input should not contain dangerous patterns
          let sanitized = sanitize_input(&attack);
          assert!(!contains_dangerous_patterns(&sanitized));

          // Property: Sanitization should not allow bypass
          let credentials = Credentials {
              username: attack.clone(),
              password: "valid_password".to_string(),
          };
          let auth_result = authenticate(credentials).await;
          assert!(auth_result.is_err());
      });

      // Test that valid edge cases are accepted
      let edge_case_strategy = edge_case_input_strategy();
      proptest!(|(input in edge_case_strategy)| {
          // Property: Valid edge cases should be accepted
          let result = validate_user_input(&input);
          assert!(result.is_ok());

          // Property: Sanitization should not modify valid input
          let sanitized = sanitize_input(&input);
          assert_eq!(input, sanitized);
      });
  }
  ```

### 3. Load Test Data

Load testing requires both realistic data generation and appropriate tools for execution.
We use the following tools for load testing:

- k6 for HTTP-level load testing
- Gatling for scenario-based load testing
- Custom Rust benchmarks for component-level testing

- **Concurrent Users**

  ```rust
  fn concurrent_user_strategy(count: usize) -> impl Strategy<Value = Vec<User>> {
      prop::collection::vec(valid_user_strategy(), count)
  }
  ```

- **Session Patterns**

  ```rust
  // Define common session patterns for load testing
  #[derive(Debug, Clone)]
  enum SessionPattern {
      // Heavy login/logout activity
      LoginHeavy {
          login_rate: f64,    // logins per second
          logout_rate: f64,   // logouts per second
          duration: Duration, // test duration
      },
      // Heavy token validation
      ValidationHeavy {
          validation_rate: f64,  // validations per second
          invalid_ratio: f64,    // ratio of invalid tokens
          duration: Duration,
      },
      // Mixed operations
      Mixed {
          operations: Vec<(Operation, f64)>, // (operation, rate)
          duration: Duration,
      },
  }

  impl SessionPattern {
      // Generate k6 script for this pattern
      fn to_k6_script(&self) -> String {
          match self {
              SessionPattern::LoginHeavy { .. } => {
                  format!(
                      r#"
                      import http from 'k6/http';
                      import { sleep } from 'k6';

                      export let options = {{
                          vus: 100,
                          duration: '30s',
                      }};

                      export default function() {{
                          // Login request
                          let response = http.post('http://localhost:8080/auth/login', {{
                              username: 'test@example.com',
                              password: 'password123',
                          }});

                          sleep(1);

                          // Logout request
                          http.post('http://localhost:8080/auth/logout', {{
                              token: response.json('token'),
                          }});
                      }}
                      "#
                  )
              },
              // ... similar implementations for other patterns
          }
      }

      // Generate Gatling scenario for this pattern
      fn to_gatling_scenario(&self) -> String {
          // Similar to k6 but in Scala for Gatling
          todo!()
      }
  }

  fn login_heavy_pattern() -> SessionPattern {
      SessionPattern::LoginHeavy {
          login_rate: 10.0,  // 10 logins per second
          logout_rate: 8.0,  // 8 logouts per second
          duration: Duration::from_secs(300), // 5 minutes
      }
  }

  fn validation_heavy_pattern() -> SessionPattern {
      SessionPattern::ValidationHeavy {
          validation_rate: 100.0, // 100 validations per second
          invalid_ratio: 0.1,     // 10% invalid tokens
          duration: Duration::from_secs(300),
      }
  }

  fn mixed_operation_pattern() -> SessionPattern {
      SessionPattern::Mixed {
          operations: vec![
              (Operation::Login, 5.0),
              (Operation::Validate, 50.0),
              (Operation::Logout, 4.0),
              (Operation::Refresh, 10.0),
          ],
          duration: Duration::from_secs(600), // 10 minutes
      }
  }

  fn session_pattern_strategy() -> impl Strategy<Value = SessionPattern> {
      prop_oneof![
          login_heavy_pattern(),
          validation_heavy_pattern(),
          mixed_operation_pattern()
      ]
  }
  ```

## Test Maintenance Guidelines

### 1. Property Test Maintenance

- **Regular Review**
  - Review property tests monthly
  - Update properties when requirements change
  - Adjust generators for new edge cases
  - Monitor test execution time

- **Performance Optimization**
  - Limit test case complexity
  - Use appropriate shrinking strategies
  - Cache expensive generators
  - Profile slow property tests

### 2. Mutation Test Maintenance

- **Periodic Analysis**
  - Review surviving mutants weekly
  - Update tests for persistent survivors
  - Document intentional survivors
  - Track mutation score trends

- **Optimization**
  - Focus on critical code paths
  - Use test timeouts effectively
  - Parallelize mutation testing
  - Exclude irrelevant mutations

### 3. Security Test Maintenance

- **Regular Updates**
  - Update attack vectors monthly
  - Add tests for new vulnerabilities
  - Review security tool configurations
  - Update security metrics

- **Vulnerability Management**
  - Track known vulnerabilities
  - Prioritize security fixes
  - Document mitigation strategies
  - Monitor security alerts

### 4. Load Test Maintenance

- **Performance Monitoring**
  - Update load patterns quarterly
  - Adjust concurrency levels
  - Review resource utilization
  - Update performance metrics

- **Infrastructure**
  - Maintain test environment
  - Update load testing tools
  - Monitor resource availability
  - Document performance baselines

## Test Implementation Guidelines

1. **Test Organization**
   - Unit tests alongside code
     - Location: Same file as implementation
     - Naming: `test_unit_<function>_<scenario>`
   - Integration tests in `/tests`
     - Location: `/tests/src/<module>/`
     - Naming: `test_integration_<feature>_<scenario>`
   - Security tests in dedicated files
     - Location: `/tests/src/security/`
     - Naming: `test_security_<vulnerability>_<scenario>`
   - Performance tests separate
     - Location: `/tests/performance/`
     - Naming: `test_perf_<feature>_<metric>`
   - Concurrency tests isolated
     - Location: `/tests/src/concurrent/`
     - Naming: `test_concurrent_<operation>_<scenario>`

2. **Test Naming**
   - Clear, descriptive names
     - Example: `test_login_invalid_password`
   - Indicate scenario being tested
     - Example: `test_token_validation_expired`
   - Follow `test_<scenario>_<condition>` pattern
     - Example: `test_session_creation_duplicate`
   - Concurrency tests prefixed with `test_concurrent_`
     - Example: `test_concurrent_session_creation_high_load`

3. **Assertions**
   - Comprehensive checks
     - Example: `assert_eq!(session.user_id, user.id)`
   - Clear error messages
     - Example: `"Session should be created for correct user"`
   - Proper error type validation
     - Example: `assert!(matches!(result, Err(Error::InvalidCredentials)))`
   - Timestamp validation where applicable
     - Example: `assert!(session.expires_at > now)`
   - Concurrency success/failure counts
     - Example: `assert!(success_count > 0 && failure_count > 0)`

4. **Security Considerations**
   - No sensitive data in tests
     - Example: Use test-specific credentials
   - Secure handling of test credentials
     - Example: Generate random passwords
   - Proper cleanup after tests
     - Example: Delete all test sessions
   - Isolation between tests
     - Example: Use unique test users
   - Transaction isolation levels
     - Example: Use `READ COMMITTED` for session tests

5. **Concurrency Testing**
   - Use `tokio::spawn` for concurrent tasks
     - Example: `tokio::spawn(async move { validate_token(token).await })`
   - Proper task joining with `join_all`
     - Example: `join_all(validation_futures).await`
   - Resource cleanup
     - Example: Ensure all sessions are deleted
   - Connection pool management
     - Example: Monitor pool saturation
   - Timing considerations
     - Example: Use appropriate delays between operations

## Monitoring and Maintenance

1. **Coverage Monitoring**
   - Regular coverage reports
     - Tool: tarpaulin
     - Frequency: Every PR
   - Coverage threshold enforcement
     - Minimum: 90% branch coverage
     - Critical paths: 100% coverage
   - Critical path identification
     - Tool: cargo-llvm-cov
     - Focus: Authentication flows
   - Concurrency coverage analysis
     - Tool: tokio-test
     - Metric: Interleaving coverage

2. **Security Updates**
   - Regular security review
     - Frequency: Monthly
     - Tool: cargo-audit
   - Dependency updates
     - Frequency: Weekly
     - Tool: dependabot
   - New vulnerability testing
     - Source: security advisories
     - Tool: cargo-deny
   - Attack vector monitoring
     - Source: OWASP Top 10
     - Tool: Security scanners
   - Algorithm security review
     - Frequency: Quarterly
     - Focus: Cryptographic algorithms

3. **Performance Monitoring**
   - Response time tracking
     - Tool: prometheus
     - Threshold: p95 < 100ms
   - Resource usage monitoring
     - Tool: grafana
     - Metrics: CPU, memory, I/O
   - Bottleneck identification
     - Tool: async-profiler
     - Focus: Hot paths
   - Scalability testing
     - Tool: k6
     - Target: 10k req/s
   - Cleanup task impact
     - Tool: metrics-rs
     - Threshold: < 5% overhead

4. **Concurrency Monitoring**
   - Race condition detection
     - Tool: tokio-loom
     - Focus: State mutations
   - Resource contention tracking
     - Tool: prometheus
     - Metric: Lock wait times
   - Connection pool statistics
     - Tool: db-metrics
     - Threshold: 80% utilization
   - Transaction isolation verification
     - Tool: pg-isolation-tester
     - Focus: ACID properties
   - Cleanup task timing
     - Tool: tracing
     - Threshold: < 5s duration

## Mutation Testing Integration

### CI/CD Integration

```yaml
# .github/workflows/mutation.yml
name: Mutation Testing

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  mutation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install cargo-mutants
        run: cargo install cargo-mutants
      
      - name: Run mutation tests
        run: |
          cargo mutants --target-dir=target/mutants \
            --package acci-auth \
            --filter-path src/auth/ \
            --output-format=json > mutation-report.json
      
      - name: Check mutation score
        run: |
          score=$(jq '.score' mutation-report.json)
          if (( $(echo "$score < 90" | bc -l) )); then
            echo "Mutation score below threshold: $score% < 90%"
            exit 1
          fi
      
      - name: Upload mutation report
        uses: actions/upload-artifact@v3
        with:
          name: mutation-report
          path: mutation-report.json
```

### Local Workflow

1. **Pre-commit Hook**

   ```bash
   #!/bin/bash
   # .git/hooks/pre-commit
   
   # Run mutation tests on changed files
   changed_files=$(git diff --cached --name-only | grep "src/auth/")
   if [ -n "$changed_files" ]; then
     cargo mutants --target-dir=target/mutants \
       --package acci-auth \
       --filter-path "$changed_files" \
       --fail-fast
   fi
   ```

2. **Development Workflow**

   ```bash
   # Run mutation tests during development
   cargo mutants --package acci-auth --filter-path src/auth/token.rs
   
   # Run with detailed output
   cargo mutants --package acci-auth --verbose
   
   # Run specific mutation operators
   cargo mutants --package acci-auth --operators arithmetic,comparison
   ```

## Security Metrics Collection

### 1. Automated Security Scanning

The security scanning workflow integrates with our observability stack:

- Results are stored in Elasticsearch
- Metrics are visualized in Grafana
- Alerts are sent to Slack
- Reports are generated in Markdown and PDF

```yaml
# .github/workflows/security.yml
name: Security Scanning

on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  push:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: OWASP ZAP Scan
        uses: zaproxy/action-full-scan@v0.4.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
      
      - name: Run JWT Security Scan
        run: |
          jwt_tool --scan-tokens \
            --wordlist jwt-secrets.txt \
            --target http://localhost:8080
      
      - name: Generate Security Report
        run: |
          ./scripts/generate-security-report.sh \
            --zap-results=zap-results.json \
            --jwt-results=jwt-results.json \
            --output=security-report.md
      
      - name: Check Security Score
        run: |
          score=$(./scripts/calculate-security-score.sh)
          if (( $(echo "$score < 90" | bc -l) )); then
            echo "Security score below threshold: $score% < 90%"
            exit 1
          fi
```

### 2. Security Report Generation

```bash
#!/bin/bash
# scripts/generate-security-report.sh

# Process ZAP results
zap_alerts=$(jq '.alerts[] | select(.risk >= "High")' zap-results.json)
zap_score=$(calculate_zap_score "$zap_alerts")

# Process JWT scan results
jwt_issues=$(jq '.issues[] | select(.severity >= 7)' jwt-results.json)
jwt_score=$(calculate_jwt_score "$jwt_issues")

# Calculate scores based on severity levels
function calculate_zap_score() {
    local alerts=$1
    local total_weight=0
    local score=100

    # Weight factors for different risk levels
    local critical_weight=10
    local high_weight=7
    local medium_weight=4
    local low_weight=1

    # Calculate score reductions based on findings
    while IFS= read -r alert; do
        risk=$(echo "$alert" | jq -r '.risk')
        case "$risk" in
            "Critical")
                score=$((score - critical_weight))
                total_weight=$((total_weight + critical_weight))
                ;;
            "High")
                score=$((score - high_weight))
                total_weight=$((total_weight + high_weight))
                ;;
            "Medium")
                score=$((score - medium_weight))
                total_weight=$((total_weight + medium_weight))
                ;;
            "Low")
                score=$((score - low_weight))
                total_weight=$((total_weight + low_weight))
                ;;
        esac
    done <<< "$(echo "$alerts" | jq -c '.[]')"

    # Normalize score
    if [ $total_weight -gt 0 ]; then
        score=$((score * 100 / (100 + total_weight)))
    fi

    echo $score
}

function calculate_jwt_score() {
    local issues=$1
    local total_weight=0
    local score=100

    # Weight factors for different severity levels
    local critical_weight=10
    local high_weight=7
    local medium_weight=4
    local low_weight=1

    # Calculate score reductions based on findings
    while IFS= read -r issue; do
        severity=$(echo "$issue" | jq -r '.severity')
        if [ $severity -ge 9 ]; then
            score=$((score - critical_weight))
            total_weight=$((total_weight + critical_weight))
        elif [ $severity -ge 7 ]; then
            score=$((score - high_weight))
            total_weight=$((total_weight + high_weight))
        elif [ $severity -ge 4 ]; then
            score=$((score - medium_weight))
            total_weight=$((total_weight + medium_weight))
        else
            score=$((score - low_weight))
            total_weight=$((total_weight + low_weight))
        fi
    done <<< "$(echo "$issues" | jq -c '.[]')"

    # Normalize score
    if [ $total_weight -gt 0 ]; then
        score=$((score * 100 / (100 + total_weight)))
    fi

    echo $score
}

function format_findings() {
    local zap_alerts=$1
    local jwt_issues=$2
    local markdown=""

    # Format ZAP findings
    markdown+="### ZAP Findings\n\n"
    while IFS= read -r alert; do
        risk=$(echo "$alert" | jq -r '.risk')
        name=$(echo "$alert" | jq -r '.name')
        url=$(echo "$alert" | jq -r '.url')
        solution=$(echo "$alert" | jq -r '.solution')

        markdown+="#### $name (Risk: $risk)\n"
        markdown+="- URL: $url\n"
        markdown+="- Solution: $solution\n\n"
    done <<< "$(echo "$zap_alerts" | jq -c '.[]')"

    # Format JWT findings
    markdown+="### JWT Security Issues\n\n"
    while IFS= read -r issue; do
        severity=$(echo "$issue" | jq -r '.severity')
        title=$(echo "$issue" | jq -r '.title')
        description=$(echo "$issue" | jq -r '.description')
        mitigation=$(echo "$issue" | jq -r '.mitigation')

        markdown+="#### $title (Severity: $severity)\n"
        markdown+="- Description: $description\n"
        markdown+="- Mitigation: $mitigation\n\n"
    done <<< "$(echo "$jwt_issues" | jq -c '.[]')"

    echo -e "$markdown"
}

function generate_recommendations() {
    local zap_alerts=$1
    local jwt_issues=$2
    local markdown=""

    markdown+="## Security Recommendations\n\n"

    # Generate recommendations based on findings
    markdown+="### High Priority\n\n"
    # ZAP recommendations
    while IFS= read -r alert; do
        risk=$(echo "$alert" | jq -r '.risk')
        if [ "$risk" = "High" ] || [ "$risk" = "Critical" ]; then
            name=$(echo "$alert" | jq -r '.name')
            solution=$(echo "$alert" | jq -r '.solution')
            markdown+="1. **$name**\n   - $solution\n\n"
        fi
    done <<< "$(echo "$zap_alerts" | jq -c '.[]')"

    # JWT recommendations
    while IFS= read -r issue; do
        severity=$(echo "$issue" | jq -r '.severity')
        if [ $severity -ge 7 ]; then
            title=$(echo "$issue" | jq -r '.title')
            mitigation=$(echo "$issue" | jq -r '.mitigation')
            markdown+="1. **$title**\n   - $mitigation\n\n"
        fi
    done <<< "$(echo "$jwt_issues" | jq -c '.[]')"

    echo -e "$markdown"
}

# Generate markdown report
cat << EOF > security-report.md
# Security Scan Report

## Overview
- ZAP Security Score: $zap_score
- JWT Security Score: $jwt_score
- Overall Security Score: $(( (zap_score + jwt_score) / 2 ))

## High Risk Findings
$(format_findings "$zap_alerts" "$jwt_issues")

## Recommendations
$(generate_recommendations "$zap_alerts" "$jwt_issues")

## Scan Details
- Scan Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
- ZAP Version: $(zap-cli version)
- JWT Tool Version: $(jwt_tool --version)
- Target Environment: $(hostname)

## Next Steps
1. Review and prioritize findings
2. Create JIRA tickets for high-priority issues
3. Schedule remediation work
4. Plan follow-up scan after fixes

## Historical Trends
- Previous Score (7 days ago): XX
- Previous Score (30 days ago): XX
- Score Trend: [Improving/Stable/Declining]

## Contact
For questions about this report, contact:
- Security Team: security@example.com
- DevOps Team: devops@example.com
EOF
```

### 3. Grafana Dashboard Integration

```typescript
// grafana/dashboards/security.json
{
  "dashboard": {
    "title": "Authentication Security Metrics",
    "panels": [
      {
        "title": "Security Score Trend",
        "type": "graph",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "auth_security_score",
            "legendFormat": "Overall Score"
          }
        ]
      },
      {
        "title": "Authentication Failures",
        "type": "graph",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "rate(auth_failures_total[5m])",
            "legendFormat": "Failure Rate"
          }
        ]
      },
      {
        "title": "Token Tampering Attempts",
        "type": "graph",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "rate(auth_token_tampering_total[5m])",
            "legendFormat": "Tampering Rate"
          }
        ]
      }
    ]
  }
}
```

### 4. Prometheus Metrics Collection

```rust
// src/metrics/security.rs

use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec,
    Counter, CounterVec, Gauge, HistogramVec,
};

lazy_static! {
    // Security score metrics
    pub static ref SECURITY_SCORE: Gauge = register_gauge!(
        "auth_security_score",
        "Overall security score from 0 to 100"
    ).unwrap();

    // Authentication metrics
    pub static ref AUTH_ATTEMPTS: CounterVec = register_counter_vec!(
        "auth_attempts_total",
        "Total number of authentication attempts",
        &["status", "method"]
    ).unwrap();

    pub static ref AUTH_FAILURES: CounterVec = register_counter_vec!(
        "auth_failures_total",
        "Total number of authentication failures",
        &["reason"]
    ).unwrap();

    // Token metrics
    pub static ref TOKEN_OPERATIONS: CounterVec = register_counter_vec!(
        "auth_token_operations_total",
        "Total number of token operations",
        &["operation", "status"]
    ).unwrap();

    pub static ref TOKEN_TAMPERING: Counter = register_counter!(
        "auth_token_tampering_total",
        "Total number of detected token tampering attempts"
    ).unwrap();

    // Session metrics
    pub static ref ACTIVE_SESSIONS: Gauge = register_gauge!(
        "auth_active_sessions",
        "Number of currently active sessions"
    ).unwrap();

    pub static ref SESSION_DURATION: HistogramVec = register_histogram_vec!(
        "auth_session_duration_seconds",
        "Duration of authentication sessions",
        &["status"],
        vec![60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0]
    ).unwrap();
}

// Example usage in authentication code
impl AuthenticationService {
    pub async fn authenticate(&self, credentials: Credentials) -> Result<AuthResponse, Error> {
        AUTH_ATTEMPTS.with_label_values(&["attempt", "password"]).inc();

        match self.validate_credentials(credentials).await {
            Ok(user) => {
                AUTH_ATTEMPTS.with_label_values(&["success", "password"]).inc();
                // Create session and token...
                ACTIVE_SESSIONS.inc();
                Ok(response)
            }
            Err(e) => {
                AUTH_ATTEMPTS.with_label_values(&["failure", "password"]).inc();
                AUTH_FAILURES.with_label_values(&[e.reason()]).inc();
                Err(e)
            }
        }
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, Error> {
        TOKEN_OPERATIONS.with_label_values(&["validate", "attempt"]).inc();

        match self.jwt_validator.validate(token) {
            Ok(claims) => {
                TOKEN_OPERATIONS.with_label_values(&["validate", "success"]).inc();
                Ok(claims)
            }
            Err(e) if e.is_tampering() => {
                TOKEN_TAMPERING.inc();
                TOKEN_OPERATIONS.with_label_values(&["validate", "tampering"]).inc();
                Err(e)
            }
            Err(e) => {
                TOKEN_OPERATIONS.with_label_values(&["validate", "error"]).inc();
                Err(e)
            }
        }
    }

    pub async fn end_session(&self, session_id: Uuid) -> Result<(), Error> {
        if let Some(session) = self.session_store.get(session_id).await? {
            let duration = (Utc::now() - session.created_at).num_seconds() as f64;
            SESSION_DURATION.with_label_values(&["ended"]).observe(duration);
            ACTIVE_SESSIONS.dec();
        }
        Ok(())
    }
}
```

Example Prometheus Queries:

1. Authentication Success Rate:

   ```promql
   sum(rate(auth_attempts_total{status="success"}[5m])) /
   sum(rate(auth_attempts_total{status="attempt"}[5m])) * 100
   ```

2. Token Tampering Rate:

   ```promql
   rate(auth_token_tampering_total[5m])
   ```

3. Average Session Duration:

   ```promql
   rate(auth_session_duration_seconds_sum[1h]) /
   rate(auth_session_duration_seconds_count[1h])
   ```

4. Authentication Failure Distribution:

   ```promql
   topk(5, sum by (reason) (rate(auth_failures_total[1h])))
   ```

5. Active Sessions with Alert Threshold:

   ```promql
   auth_active_sessions > bool 1000
   ```

## Test Maintenance Guidelines

### 1. Property Test Maintenance

**Weekly Tasks:**

- Review property test results
- Update generators for new edge cases
- Profile slow property tests
- Update documentation

**Monthly Tasks:**

- Review and update security test data
- Add tests for new vulnerabilities
- Update attack vector strategies
- Verify coverage goals

### 2. Mutation Test Maintenance

**Weekly Tasks:**

- Review mutation test results
- Analyze surviving mutants
- Update tests for persistent survivors
- Track mutation score trends

**Interpreting Mutation Results:**

- Score < 85%: Insufficient test coverage
- 85-90%: Good coverage, room for improvement
- 90-95%: Excellent coverage
- > 95%: Exceptional coverage

**Common Mutation Operators:**

1. Conditional Operators:
   - `==` → `!=`
   - `>` → `>=`
   - `&&` → `||`

2. Arithmetic Operators:
   - `+` → `-`
   - `*` → `/`
   - `%` → `*`

3. Return Values:
   - `Ok(x)` → `Err(x)`
   - `Some(x)` → `None`
   - `true` → `false`

### 3. Security Test Maintenance

**Weekly Tasks:**

- Review security scan results
- Update security test data
- Track vulnerability trends
- Update security metrics

**Monthly Tasks:**

- Full security assessment
- Update attack vectors
- Review security policies
- Update security documentation

**Quarterly Tasks:**

- Penetration testing
- Threat modeling review
- Security architecture review
- Update security roadmap

## Concurrency Testing Scenarios

### 1. Race Conditions in Session Management

```rust
#[tokio::test]
async fn test_concurrent_session_deletion_race() {
    // Setup: Create a session
    let session = create_test_session().await?;
    
    // Scenario: Concurrent deletion and validation
    let (deletion_result, validation_result) = tokio::join!(
        delete_session(session.id),
        validate_session(session.id)
    );

    // Both operations should complete without errors
    assert!(deletion_result.is_ok());
    match validation_result {
        Ok(_) | Err(Error::SessionNotFound) => (),
        err => panic!("Unexpected error: {:?}", err),
    }
}

#[tokio::test]
async fn test_concurrent_session_updates() {
    // Setup: Create a session
    let session = create_test_session().await?;
    
    // Scenario: Concurrent updates to session data
    let updates = (0..10).map(|_| {
        let session_id = session.id;
        tokio::spawn(async move {
            update_session_data(session_id, generate_random_data()).await
        })
    });

    // All updates should complete without conflicts
    let results = join_all(updates).await;
    for result in results {
        assert!(result.is_ok());
    }

    // Final session state should be valid
    let final_session = get_session(session.id).await?;
    assert!(final_session.is_valid());
}
```

### 2. Resource Exhaustion Scenarios

```rust
#[tokio::test]
async fn test_connection_pool_exhaustion() {
    // Setup: Create a small connection pool
    let pool = create_test_pool(5);
    
    // Scenario: More concurrent requests than connections
    let requests = (0..20).map(|_| {
        tokio::spawn(async {
            authenticate_user(pool.clone(), valid_credentials()).await
        })
    });

    // Some requests should succeed, others should fail gracefully
    let results = join_all(requests).await;
    let (successes, failures): (Vec<_>, Vec<_>) = results
        .into_iter()
        .partition(|r| r.is_ok());

    assert!(!successes.is_empty(), "Some requests should succeed");
    assert!(!failures.is_empty(), "Some requests should fail gracefully");
    
    // All failures should be pool exhaustion errors
    for failure in failures {
        assert!(matches!(
            failure,
            Err(Error::PoolExhausted)
        ));
    }
}
```

### 3. Cleanup Task Interference

```rust
#[tokio::test]
async fn test_cleanup_task_interference() {
    // Setup: Create expired sessions
    let sessions = create_expired_sessions(100).await?;
    
    // Scenario: Run cleanup while creating new sessions
    let cleanup_task = tokio::spawn(async {
        run_session_cleanup().await
    });

    // Simultaneously create new sessions
    let creation_tasks = (0..50).map(|_| {
        tokio::spawn(async {
            create_new_session().await
        })
    });

    // Wait for all tasks
    let (cleanup_result, creation_results) = tokio::join!(
        cleanup_task,
        join_all(creation_tasks)
    );

    // Cleanup should succeed
    assert!(cleanup_result.is_ok());

    // New sessions should be created successfully
    for result in creation_results {
        assert!(result.is_ok());
    }

    // Verify cleanup was effective
    for session in sessions {
        let result = get_session(session.id).await;
        assert!(matches!(result, Err(Error::SessionNotFound)));
    }
}
```
