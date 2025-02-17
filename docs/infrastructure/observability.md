# Observability Infrastructure

## Overview

The ACCI project implements a comprehensive observability stack based on OpenTelemetry, providing insights into application performance, behavior, and health through logs, metrics, and traces.

## Components

### 1. Logging Infrastructure

#### Implementation

- **Transport:** OpenTelemetry + Loki
- **Format:** Structured JSON
- **Library:** `tracing` crate with JSON formatter

#### Log Levels

- **ERROR:** System errors requiring immediate attention
- **WARN:** Potential issues or degraded service
- **INFO:** Important business events and state changes
- **DEBUG:** Detailed information for debugging
- **TRACE:** Very detailed debugging information

#### Log Fields

Every log entry includes:

- **timestamp:** ISO 8601 format
- **level:** Log level
- **target:** Module/component name
- **message:** Log message
- **correlation_id:** Request tracking ID
- **span_id:** OpenTelemetry span ID
- **trace_id:** OpenTelemetry trace ID

Additional context fields:

- **user_id:** If authenticated
- **tenant_id:** For multi-tenant requests
- **request_path:** For API requests
- **duration_ms:** For timed operations

### 2. Metrics Collection

#### Implementation

- **Transport:** OpenTelemetry + Prometheus
- **Storage:** Prometheus with configurable retention
- **Visualization:** Grafana dashboards

#### Core Metrics

1. **HTTP Metrics:**
   - Request count
   - Response times (p50, p90, p99)
   - Error rates
   - Status code distribution

2. **Database Metrics:**
   - Query execution time
   - Connection pool status
   - Transaction count
   - Error rates

3. **Authentication Metrics:**
   - Login attempts
   - Success/failure rates
   - Token validation rate
   - Session count

4. **Resource Metrics:**
   - CPU usage
   - Memory usage
   - Disk I/O
   - Network I/O

### 3. Distributed Tracing

#### Implementation

- **Transport:** OpenTelemetry + Tempo
- **Sampling:** Adaptive based on traffic
- **Visualization:** Grafana Tempo

#### Trace Points

1. **API Layer:**
   - Request receipt
   - Middleware processing
   - Route handling
   - Response generation

2. **Authentication:**
   - Credential validation
   - Token generation
   - Session management
   - Authorization checks

3. **Database Operations:**
   - Query execution
   - Transaction boundaries
   - Connection acquisition
   - Error handling

## Infrastructure Setup

### Local Development

```yaml
version: '3.8'
services:
  # Logging
  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    volumes:
      - loki-data:/loki

  # Metrics
  prometheus:
    image: prom/prometheus:v2.45.0
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus

  # Tracing
  tempo:
    image: grafana/tempo:2.3.0
    ports:
      - "3200:3200"
    volumes:
      - tempo-data:/tmp/tempo

  # Visualization
  grafana:
    image: grafana/grafana:10.0.0
    ports:
      - "3000:3000"
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
      - grafana-data:/var/lib/grafana

volumes:
  loki-data:
  prometheus-data:
  tempo-data:
  grafana-data:
```

### Production Setup

For production, we recommend:

1. **Logging:**
   - Loki cluster with replication
   - Log retention policies
   - Log rotation
   - Backup strategy

2. **Metrics:**
   - Prometheus with HA setup
   - Long-term storage (Thanos)
   - Alert manager configuration
   - Recording rules

3. **Tracing:**
   - Tempo with replication
   - Sampling strategy
   - Retention configuration
   - Backup strategy

## Dashboards

### 1. Overview Dashboard

- System health status
- Key performance indicators
- Error rates
- Resource usage

### 2. API Dashboard

- Request rates
- Response times
- Error distribution
- Endpoint usage

### 3. Authentication Dashboard

- Login success/failure
- Token usage
- Session statistics
- Security events

### 4. Database Dashboard

- Query performance
- Connection pool status
- Transaction rates
- Error tracking

## Alerts

### Critical Alerts

1. **System Health:**
   - High error rate
   - Service unavailable
   - Resource exhaustion
   - Database connectivity

2. **Security:**
   - Multiple login failures
   - Unusual traffic patterns
   - Token validation failures
   - Session anomalies

### Warning Alerts

1. **Performance:**
   - High latency
   - Increased error rate
   - Resource pressure
   - Connection pool saturation

2. **Business:**
   - License expiration
   - Quota approaching
   - Feature usage spikes
   - User activity anomalies

## Integration

### Application Integration

```rust
use opentelemetry::trace::Tracer;
use tracing::{info, error, warn};

// Initialize tracing
pub fn init_telemetry() -> Result<(), Box<dyn Error>> {
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .install_batch(opentelemetry::runtime::Tokio)?;

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

    Ok(())
}

// Example usage
async fn handle_request(req: Request) -> Result<Response, Error> {
    let trace_id = req.trace_id();
    
    info!(
        trace_id = %trace_id,
        path = %req.path(),
        method = %req.method(),
        "Handling request"
    );

    // Process request
    match process_request(req).await {
        Ok(response) => {
            info!(
                trace_id = %trace_id,
                status = response.status(),
                duration_ms = request_duration.as_millis(),
                "Request completed successfully"
            );
            Ok(response)
        }
        Err(e) => {
            error!(
                trace_id = %trace_id,
                error = %e,
                "Request failed"
            );
            Err(e)
        }
    }
}
```

### Middleware Integration

```rust
use axum::{
    middleware::Next,
    response::Response,
};
use metrics::{counter, histogram};
use tracing::Span;

pub async fn telemetry_middleware<B>(
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let path = req.uri().path().to_owned();
    let method = req.method().to_string();
    let start = Instant::now();

    // Create span for request
    let span = span!(
        Level::INFO,
        "http_request",
        method = %method,
        path = %path,
    );

    // Record request metric
    counter!("http_requests_total", "path" => path.clone(), "method" => method.clone());

    let response = next.run(req).await;

    // Record duration
    let duration = start.elapsed();
    histogram!(
        "http_request_duration_seconds",
        duration.as_secs_f64(),
        "path" => path,
        "method" => method,
        "status" => response.status().as_u16().to_string(),
    );

    response
}
```

## Future Improvements

1. **Enhanced Tracing:**
   - Business transaction tracking
   - Cross-service correlation
   - Custom span attributes
   - Baggage propagation

2. **Metrics Enhancement:**
   - Business metrics
   - SLO monitoring
   - Custom dashboards
   - Metric aggregation

3. **Log Analysis:**
   - Log pattern detection
   - Anomaly detection
   - Log correlation
   - Custom log parsing
