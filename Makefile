.PHONY: dev up down migrate seed test lint

up:
	docker compose up -d

down:
	docker compose down

dev:
	docker compose up -d postgres redis
	cd backend && go run ./cmd/shadowai

migrate:
	@for f in backend/migrations/*.sql; do \
		echo "Running $$f..."; \
		docker compose exec -T postgres psql -U shadowai -d shadowai < "$$f"; \
	done

seed:
	docker compose exec -T postgres psql -U shadowai -d shadowai < scripts/seed.sql

test:
	cd backend && go test ./...

lint:
	cd backend && golangci-lint run ./...

frontend-dev:
	cd frontend && npm run dev

frontend-build:
	cd frontend && npm run build
