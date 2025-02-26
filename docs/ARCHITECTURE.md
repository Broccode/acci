# arc42 Software Architecture Documentation – ACCI Project

## 1. Introduction & Goals

### 1.1 Requirements & Goals

The ACCI project is an **enterprise-grade Rust-based system** designed for **secure multi-tenancy, high scalability, and compliance**.  
The key goals of the project are:

- **Secure authentication & authorization** (OAuth2, OpenID Connect, RBAC)
- **Multi-tenancy support** with strict tenant isolation
- **High-performance API** (REST & GraphQL)
- **Enterprise license management**
- **Observability & Monitoring** (OpenTelemetry, Prometheus, Grafana)
- **Resilient infrastructure** (Docker, Kubernetes, Zero-downtime deployments)

### 1.2 Stakeholders

| **Stakeholder**   | **Role** |
|------------------|----------|
| Project Managers | Oversee development progress, ensure roadmap adherence |
| Developers | Implement core system functionality |
| DevOps Engineers | Manage CI/CD, infrastructure, and deployment |
| Security Team | Ensure compliance with security best practices |
| End Users | Access the system as authenticated tenants |
| Compliance Officers | Verify adherence to ISO 27001, GDPR |

---

## 2. Constraints

### 2.1 Technical Constraints

- **Rust-based backend** using **Axum & async-graphql**
- **PostgreSQL** as the primary database with **pgvector for AI capabilities**
- **Redis 7.2 for caching**
- **RabbitMQ 3.12 for messaging**
- **Keycloak for identity management**
- **Docker & Kubernetes for deployments**

### 2.2 Organizational Constraints

- **Project documentation must be available in EN, DE, SQ**
- **CI/CD must include security scans & compliance checks**
- **Deployment must support zero-downtime rollouts**

---

## 3. System Scope & Context

### 3.1 Business Context

ACCI is a multi-tenant **enterprise SaaS platform**. It provides:

- **Authentication & Role Management**
- **Feature-based access control**
- **API rate limiting & monitoring**
- **Enterprise licensing & tenant management**

**External Interfaces:**

- **Users** authenticate via a web frontend
- **Third-party services** interact via REST & GraphQL APIs
- **Monitoring tools** collect logs & metrics (OpenTelemetry, Prometheus)

### 3.2 Technical Context

```mermaid
graph TD
    User[User] -->|Authenticates| Frontend[Frontend]
    Frontend -->|API Requests| API[ACCI API]
    API -->|Process| Logic[Business Logic]
    Logic -->|Store| DB[(PostgreSQL)]
    Logic -->|Cache| Cache[(Redis)]
    Logic -->|Queue| MQ[RabbitMQ]
    Logic -->|Auth| Auth[Keycloak]
    Monitor[Monitoring] -->|Observe| Telemetry[OpenTelemetry]
```

---

## 4. Solution Strategy

- **Domain-Driven Design (DDD) & Hexagonal Architecture**
- **CQRS & Event Sourcing for scalability**
- **REST & GraphQL APIs for flexibility**
- **Multi-stage CI/CD pipeline for automated testing & deployment**
- **SBOM (Software Bill of Materials) for supply chain security**
- **Automated security audits & compliance enforcement**

---

## 5. Building Block View

```text
root
├── acci-api (REST & GraphQL endpoints)
├── acci-core (Business logic, authentication, multi-tenancy)
├── acci-db (Database access & repository layer)
├── acci-auth (Authentication & role management)
├── acci-frontend (Web interface)
├── acci-observability (Logging & monitoring)
```

---

## 6. Runtime View

### 6.1 User Login Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant API
    participant Auth (Keycloak)
    participant Database

    User ->> Frontend: Enter Credentials
    Frontend ->> API: Send login request
    API ->> Auth (Keycloak): Validate credentials
    Auth (Keycloak) -->> API: Return JWT Token
    API ->> Database: Fetch user data
    API -->> Frontend: Return session details
```

### 6.2 Session Management

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant API
    participant Auth (Keycloak)
    participant Session Store
    participant Database

    User ->> Frontend: Login with Credentials
    Frontend ->> API: POST /auth/login
    API ->> Auth (Keycloak): Validate credentials
    Auth (Keycloak) -->> API: Return JWT Token
    API ->> Database: Fetch user data
    API ->> Session Store: Create session
    Session Store -->> API: Return session ID
    API -->> Frontend: Return session details & JWT
    
    Note over Frontend,API: Subsequent Requests
    Frontend ->> API: Request with JWT
    API ->> Session Store: Validate session
    Session Store -->> API: Session valid/invalid
    alt Session Valid
        API ->> Database: Process request
        API -->> Frontend: Return response
    else Session Invalid
        API -->> Frontend: 401 Unauthorized
    end
```

### 6.3 Observability Architecture

```mermaid
graph TD
    subgraph Application
        API[API Endpoints]
        Auth[Auth Service]
        DB[Database Service]
    end
    
    subgraph Observability
        Logger[Structured Logger]
        Metrics[Metrics Collector]
        Traces[Trace Collector]
    end
    
    subgraph Storage
        Loki[Loki]
        Prometheus[Prometheus]
        Tempo[Tempo]
    end
    
    subgraph Visualization
        Grafana[Grafana Dashboards]
    end
    
    API --> Logger
    Auth --> Logger
    DB --> Logger
    Logger --> Loki
    
    API --> Metrics
    Auth --> Metrics
    DB --> Metrics
    Metrics --> Prometheus
    
    API --> Traces
    Auth --> Traces
    DB --> Traces
    Traces --> Tempo
    
    Loki --> Grafana
    Prometheus --> Grafana
    Tempo --> Grafana
```

### 6.4 Authentication Flow Details

```mermaid
graph TD
    subgraph Frontend
        Login[Login Form]
        Token[Token Storage]
    end
    
    subgraph API Gateway
        Auth[Auth Middleware]
        Session[Session Validator]
    end
    
    subgraph Services
        Basic[Basic Auth Provider]
        JWT[JWT Service]
        UserRepo[User Repository]
        SessionRepo[Session Repository]
    end
    
    Login -->|Credentials| Auth
    Auth -->|Validate| Basic
    Basic -->|Lookup| UserRepo
    Basic -->|Create Token| JWT
    JWT -->|Create| SessionRepo
    Auth -->|Return| Token
    
    Token -->|Subsequent Requests| Session
    Session -->|Validate| SessionRepo
```

---

## 7. Deployment View

| **Environment** | **Technology** |
|---------------|---------------|
| **Development** | Docker Compose |
| **Staging** | Kubernetes on AWS |
| **Production** | Kubernetes with Traefik |

---

## 8. Cross-Cutting Concepts

### **Security**

- **OAuth2 & OpenID Connect for authentication**
- **Role-based access control (RBAC)**
- **Multi-factor authentication (TOTP, WebAuthn)**
- **Data encryption (AES-256)**
- **PII data masking**

### **Observability**

- **Tracing with OpenTelemetry**
- **Metrics with Prometheus**
- **Logging with Loki & Grafana dashboards**

### Session Management

- **Session Storage:**
  - PostgreSQL-based session store
  - UUID session identifiers
  - JWT token association
  - Automatic expiration
  - Concurrent session handling
  - Session invalidation on logout

- **Session Security:**
  - Secure session ID generation
  - Token rotation on security events
  - Session fixation prevention
  - IP binding (optional)
  - User agent validation
  - Rate limiting per session

- **Session Lifecycle:**
  - Creation on successful login
  - Validation on each request
  - Automatic cleanup of expired sessions
  - Manual invalidation on logout
  - Forced invalidation for security
  - Session extension on activity

### Observability

- **Structured Logging:**
  - JSON log format
  - Correlation IDs
  - Request/Response logging
  - Error context capture
  - PII data masking
  - Log level management

- **Metrics Collection:**
  - Request rates
  - Error rates
  - Response times
  - Resource usage
  - Business metrics
  - SLO compliance

- **Distributed Tracing:**
  - Request tracing
  - Service dependencies
  - Database operations
  - External calls
  - Error propagation
  - Performance bottlenecks

---

## 9. Architecture Decisions

| **Decision** | **Rationale** | **Status** |
|-------------|--------------|-----------|
| Use Rust & Axum | High performance, memory safety | ✅ Approved |
| Use PostgreSQL | Relational consistency, scalability | ✅ Approved |
| Use Keycloak | Enterprise-grade identity management | ✅ Approved |
| Use Event Sourcing | Scalability & auditability | ✅ Approved |

---

## 10. Quality Requirements

| **Category** | **Requirement** |
|-------------|--------------|
| **Performance** | API response time < 100ms |
| **Scalability** | Supports 100k+ concurrent users |
| **Security** | OWASP Top 10 compliance |
| **Compliance** | ISO 27001 & GDPR adherence |
| **Availability** | 99.99% uptime requirement |

---

## 11. Risks & Technical Debt

| **Risk** | **Impact** | **Mitigation** |
|---------|-----------|--------------|
| **Multi-tenancy complexity** | High | Tenant partitioning & resource tracking |
| **Security vulnerabilities** | Critical | Regular audits & automated security scans |
| **Database scaling** | Medium | Sharding & read replicas |
| **CI/CD bottlenecks** | Medium | Parallel test execution & caching |

---

## 12. Glossary

| **Term** | **Definition** |
|---------|--------------|
| **RBAC** | Role-Based Access Control |
| **JWT** | JSON Web Token |
| **SBOM** | Software Bill of Materials |
| **CQRS** | Command Query Responsibility Segregation |

---

## Next Steps

- **Review architecture documentation with the team**
- **Implement additional quality assurance testing**
- **Optimize CI/CD performance & monitoring**
