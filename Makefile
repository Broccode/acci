.PHONY: dev dev-down dev-rebuild db-reset db-migrate sqlx-prepare clippy test test-unit test-integration coverage coverage-html fmt help test-users-list test-users-reset test-users-clean

# Development Environment Variables
export DATABASE_URL=postgres://acci:development_only@localhost:5432/acci

help:
	@echo "Available commands:"
	@echo "  make dev          - Start development environment"
	@echo "  make dev-down     - Stop development environment"
	@echo "  make dev-rebuild  - Rebuild all development containers from scratch"
	@echo "  make db-reset     - Reset database (drop and recreate)"
	@echo "  make db-migrate   - Run database migrations"
	@echo "  make sqlx-prepare - Prepare SQLx offline mode"
	@echo "  make clippy       - Run clippy with all targets and treat warnings as errors"
	@echo "  make test         - Run all tests"
	@echo "  make test-unit    - Run unit tests only"
	@echo "  make test-integration - Run integration tests only"
	@echo "  make coverage     - Generate LCOV coverage report"
	@echo "  make coverage-html - Generate HTML coverage report"
	@echo "  make fmt          - Format all code with rustfmt"
	@echo "  make test-users-list  - List all test users"
	@echo "  make test-users-reset - Reset test users to default configuration"
	@echo "  make test-users-clean - Delete all test users"

dev:
	docker compose -f deploy/docker/docker-compose.dev.yml up -d

dev-down:
	docker compose -f deploy/docker/docker-compose.dev.yml down

dev-rebuild:
	docker compose -f deploy/docker/docker-compose.dev.yml down
	docker compose -f deploy/docker/docker-compose.dev.yml build --no-cache
	docker compose -f deploy/docker/docker-compose.dev.yml up -d

db-reset:
	docker compose -f deploy/docker/docker-compose.dev.yml down -v
	docker compose -f deploy/docker/docker-compose.dev.yml up -d db
	sleep 3
	(cd crates/acci-db && SQLX_OFFLINE=true cargo run --bin acci-db -- reset)

db-migrate:
	(cd crates/acci-db && SQLX_OFFLINE=true DATABASE_URL=postgres://acci:development_only@localhost:5432/acci cargo run --bin acci-db -- migrate)

sqlx-prepare:
	@for pkg in acci-api acci-auth acci-core acci-db; do \
		echo "Preparing SQLx queries for package $$pkg"; \
		cargo sqlx prepare --workspace -- --manifest-path crates/$$pkg/Cargo.toml --all-targets || exit $$?; \
	done

clippy:
	cargo clippy --lib --bins --all-features -- -D warnings

test: test-unit test-integration

test-unit:
	cargo test --lib --bins --all-features --workspace --exclude acci-tests

test-integration:
	cargo test -p acci-tests --lib --all-features

coverage:
	cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
	@echo "Coverage info written to lcov.info"

coverage-html:
	cargo llvm-cov --all-features --workspace --html
	@echo "HTML coverage report generated in target/llvm-cov/html/index.html"

fmt:
	cargo fmt --all --verbose
	@echo "Code formatting complete."

test-users-list:
	(cd crates/acci-db && cargo run --bin test_users -- list)

test-users-reset:
	(cd crates/acci-db && cargo run --bin test_users -- reset)

test-users-clean:
	(cd crates/acci-db && cargo run --bin test_users -- clean)
