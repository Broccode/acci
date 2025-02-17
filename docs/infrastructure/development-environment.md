# Development Environment

## Overview

Our development environment is configured to provide a consistent and efficient workflow across all development machines. This document outlines the key components and setup procedures.

## Prerequisites

- Rust (latest stable version)
- Docker and Docker Compose
- VS Code or JetBrains RustRover
- Git
- devbox (optional, for development environment isolation)

## Development Environment Management

### Devbox Configuration (Optional)

The project optionally uses devbox for consistent development environment isolation. While not required, it provides additional benefits for reproducible development environments. The configuration is defined in `devbox.json`:

```
