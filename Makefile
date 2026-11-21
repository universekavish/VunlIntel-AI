.PHONY: help setup up down restart ps logs config migrate test test-backend test-backend-live test-e2e test-frontend lint lint-backend lint-frontend format

help:
	@echo "setup          Copy .env.example to .env (does not overwrite an existing .env)"
	@echo "up             Build and start the development stack"
	@echo "down           Stop the development stack"
	@echo "restart        Restart the development stack"
	@echo "ps             Show service and health status"
	@echo "logs           Follow service logs"
	@echo "config         Validate and print the resolved Compose configuration"
	@echo "migrate        Apply database migrations to the configured DATABASE_URL"
	@echo "test           Run backend and frontend checks"
	@echo "test-backend-live Run opt-in live official-source smoke tests"
	@echo "test-e2e       Run cross-surface API end-to-end tests"
	@echo "lint           Run backend and frontend linters"
	@echo "format         Format Python files"

setup:
	@test -f .env || cp .env.example .env
	@echo "Created .env from .env.example. Review it before starting services."

up:
	docker compose up --build -d

down:
	docker compose down

restart:
	docker compose restart

ps:
	docker compose ps

logs:
	docker compose logs -f --tail=100

config:
	docker compose config --quiet

migrate:
	cd backend && alembic upgrade head

test: test-backend test-frontend

test-backend:
	cd backend && python -m pytest --cov=app --cov-report=term-missing

test-backend-live:
	cd backend && VULNINTEL_RUN_LIVE_INGESTION=1 python -m pytest -q -m live tests/integration/test_ingestion_live.py

test-e2e:
	cd backend && python -m pytest -q tests/integration/test_phase9_e2e.py

test-frontend:
	cd frontend && npm run typecheck

lint: lint-backend lint-frontend

lint-backend:
	cd backend && python -m ruff check .

lint-frontend:
	cd frontend && npm run lint

format:
	cd backend && python -m ruff format .
