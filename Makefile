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

db-reset: db-down db-up db-migrate db-prepare

db-down:
	docker compose -f deploy/docker/docker-compose.dev.yml down -v

db-up:
	docker compose -f deploy/docker/docker-compose.dev.yml up -d db
	sleep 3

db-migrate:
	cd crates/acci-db && cargo sqlx database reset -y -f --database-url postgres://acci:development_only@localhost:5432/acci

db-prepare:
	-(cd crates/acci-db && cargo sqlx migrate run --database-url postgres://acci:development_only@localhost:5432/acci)
	$(MAKE) sqlx-prepare
	$(MAKE) test-users-reset

sqlx-prepare:
	@for pkg in acci-api acci-auth acci-db; do \
		echo "Preparing SQLx queries for package $$pkg"; \
		cargo sqlx prepare --workspace --database-url postgres://acci:development_only@localhost:5432/acci -- --manifest-path crates/$$pkg/Cargo.toml --all-targets || exit $$?; \
	done

clippy:
	cargo clippy --workspace --lib --bins --fix --allow-dirty --allow-staged --all-features --exclude acci-tests -- -D warnings

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
	find . -name "*.rs" -not -path "./target/*" -not -path "*/target/*" -exec rustfmt --edition 2021 {} +
	@echo "Code formatting complete."

fix:
	cargo fix --broken-code --allow-dirty --allow-staged --workspace --all-targets --all-features --exclude acci-tests
	@echo "Code fixing complete."

prepare-commit:
	$(MAKE) fmt
	$(MAKE) fix
	$(MAKE) clippy
	$(MAKE) test-unit

test-users-list:
	DATABASE_URL=postgres://acci:development_only@localhost:5432/acci cargo run -p acci-db --bin test_users -- list

test-users-reset:
	DATABASE_URL=postgres://acci:development_only@localhost:5432/acci cargo run -p acci-db --bin test_users -- reset

test-users-clean:
	DATABASE_URL=postgres://acci:development_only@localhost:5432/acci cargo run -p acci-db --bin test_users -- clean
