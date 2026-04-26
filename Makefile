.PHONY: dev up down migrate migrate-enterprise seed \
        test test-enterprise test-integration test-smoke test-all \
        build build-enterprise build-all \
        lint vet \
        docker docker-enterprise \
        helm-validate migration-smoke \
        frontend-dev frontend-build

# ─────────────────────────────────────────────────────────────────────────────
# Development
# ─────────────────────────────────────────────────────────────────────────────

up:
	docker compose up -d

down:
	docker compose down

dev:
	docker compose up -d postgres redis
	cd backend && go run ./cmd/shadowai

# ─────────────────────────────────────────────────────────────────────────────
# Migrations
# ─────────────────────────────────────────────────────────────────────────────

migrate:
	@for f in backend/migrations/*.sql; do \
		echo "Running $$f..."; \
		docker compose exec -T postgres psql -U shadowai -d shadowai < "$$f"; \
	done

migrate-enterprise: migrate
	@for f in backend/migrations-enterprise/*.sql; do \
		echo "Running $$f..."; \
		docker compose exec -T postgres psql -U shadowai -d shadowai < "$$f"; \
	done

seed:
	docker compose exec -T postgres psql -U shadowai -d shadowai < scripts/seed.sql

# ─────────────────────────────────────────────────────────────────────────────
# Testing
# ─────────────────────────────────────────────────────────────────────────────

test:
	cd backend && go test ./... -count=1

test-enterprise:
	cd backend && go test -tags enterprise ./... -count=1

test-integration:
	cd backend && go test -tags 'enterprise integration' ./integration/... -count=1 -v -timeout 10m

# O3.1: Enterprise smoke harness — full end-to-end against real PG+Redis.
# Requires Docker. Covers migrations, auth, MFA, break-glass, governance,
# SCIM, evidence chain, health probes.
test-smoke:
	cd backend && go test -tags 'enterprise smoke' ./smoke/... -count=1 -v -timeout 15m

test-all: test test-enterprise

# ─────────────────────────────────────────────────────────────────────────────
# Building
# ─────────────────────────────────────────────────────────────────────────────

build:
	cd backend && CGO_ENABLED=0 go build -ldflags="-w -s" ./...

build-enterprise:
	cd backend && CGO_ENABLED=0 go build -tags enterprise -ldflags="-w -s" ./...

# Explicit CLI build gate — these binaries are all baked into the runtime image.
build-cli:
	cd backend && for cmd in audit-verify audit-export-evidence evidence-upload audit-evidence-report audit-collect-evidence migrate; do \
		echo "Building $$cmd..."; \
		CGO_ENABLED=0 go build -ldflags="-w -s" -o /dev/null ./cmd/$$cmd; \
	done

build-all: build build-enterprise build-cli

# ─────────────────────────────────────────────────────────────────────────────
# Performance benchmarks (Scale1)
# ─────────────────────────────────────────────────────────────────────────────

# perf-smoke: fast sanity run (100 samples each). Does NOT block CI.
perf-smoke:
	cd backend && go run -tags enterprise ./cmd/shadowai-bench -- \
		--suite all --short --format table

# perf-full: full measurement run (2000 samples each). For manual baseline capture.
# Output: docs/performance-baseline-$(shell date +%Y%m%d).json
perf-full:
	cd backend && go run -tags enterprise ./cmd/shadowai-bench -- \
		--suite all --samples 2000 --warmup 200 \
		--format json \
		--output ../docs/performance-baseline-$(shell date +%Y%m%d).json \
	&& echo "Baseline written to docs/performance-baseline-$(shell date +%Y%m%d).json"

# ─────────────────────────────────────────────────────────────────────────────
# Code quality
# ─────────────────────────────────────────────────────────────────────────────

lint:
	cd backend && golangci-lint run ./...

vet:
	cd backend && go vet ./... && go vet -tags enterprise ./...

# ─────────────────────────────────────────────────────────────────────────────
# Docker
# ─────────────────────────────────────────────────────────────────────────────

docker:
	docker build -t shadowai:core ./backend

docker-enterprise:
	docker build --build-arg BUILD_TAGS=enterprise -t shadowai:enterprise ./backend

# ─────────────────────────────────────────────────────────────────────────────
# Helm
# ─────────────────────────────────────────────────────────────────────────────

helm-validate:
	helm lint ./deploy/helm/shadowai --set "existingSecret=shadowai-secrets"
	helm template shadowai ./deploy/helm/shadowai \
		--set "existingSecret=shadowai-secrets" --set "image.tag=ci" > /dev/null \
		&& echo "✓ base values"
	helm template shadowai ./deploy/helm/shadowai \
		-f ./deploy/helm/shadowai/values-prod.yaml \
		--set "existingSecret=shadowai-secrets" --set "image.tag=ci" > /dev/null \
		&& echo "✓ prod values"

# ─────────────────────────────────────────────────────────────────────────────
# Migration smoke (requires DATABASE_URL)
# Usage: DATABASE_URL=postgres://... make migration-smoke
# ─────────────────────────────────────────────────────────────────────────────

migration-smoke:
	@[ -n "$(DATABASE_URL)" ] || (echo "ERROR: DATABASE_URL not set" && exit 1)
	cd backend && go run ./cmd/migrate --dir ./migrations
	cd backend && go run ./cmd/migrate --dir ./migrations --enterprise-dir ./migrations-enterprise
	@echo "✓ migration smoke passed"

# ─────────────────────────────────────────────────────────────────────────────
# Frontend
# ─────────────────────────────────────────────────────────────────────────────

frontend-dev:
	cd frontend && npm run dev

frontend-build:
	cd frontend && npm run build
