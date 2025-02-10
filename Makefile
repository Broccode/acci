.PHONY: dev dev-down dev-rebuild db-reset db-migrate sqlx-prepare help

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
	(cd crates/acci-db && cargo run --bin acci-db -- reset)

db-migrate:
	(cd crates/acci-db && DATABASE_URL=postgres://acci:development_only@localhost:5432/acci cargo run --bin acci-db -- migrate)

sqlx-prepare:
	cargo sqlx prepare --workspace
