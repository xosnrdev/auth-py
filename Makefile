.PHONY: all check fix dev run migrate migrate-apply stop clean help verify

all: help

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

VENV_DIR := .venv
DB_HOST := postgres
DB_WAIT_TIMEOUT := 30
SERVER_PORT := 8000
MAX_COMPLEXITY := 10
PID_FILE := ./uvicorn.pid

DOCKER := $(shell command -v docker 2> /dev/null)
ifeq ($(DOCKER),)
$(error "Docker is not installed. Please install Docker from https://docs.docker.com/get-docker/")
endif

UV := $(shell command -v uv 2> /dev/null)
ifeq ($(UV),)
$(error "uv is not installed. Please install uv from https://github.com/astral/uv")
endif

PYTHON := $(shell command -v python3 2> /dev/null)
ifeq ($(PYTHON),)
$(error "Python 3 is not installed. Please install Python 3.")
endif

export PYTHONPATH := $(shell pwd)
export PYTHONWARNINGS := default

help:
	@echo "=== Makefile for working with fastapi applications ==="
	@echo ""
	@echo "Setup Commands:"
	@echo "  make verify         - Verify system requirements"
	@echo "  make dev            - Set up development environment"
	@echo ""
	@echo "Development Commands:"
	@echo "  make run            - Run the FastAPI server"
	@echo "  make check          - Run code quality checks"
	@echo "  make fix            - Fix safe code style issues"
	@echo ""
	@echo "Database Commands:"
	@echo "  make migrate        - Generate database migration script"
	@echo "  make migrate-apply  - Apply database migrations"
	@echo ""
	@echo "Cleanup Commands:"
	@echo "  make stop           - Stop the server and services"
	@echo "  make clean          - Full cleanup of environment"

verify:
	@echo "Verifying system requirements..."
	@echo "Docker version: $$(docker --version)"
	@echo "Python version: $$($(PYTHON) --version)"
	@echo "uv version: $$(uv --version)"
	@echo "System requirements verified."

check:
	@echo "Running code quality checks..."
	@echo "Running linter..."
	@uvx ruff check
	@echo "Running type checker..."
	@mypy .
	@echo "Code quality checks passed."

fix:
	@echo "Running safe code style fixes..."
	@echo "Running ruff autofix..."
	@uvx ruff check --fix --unsafe-fixes
	@echo "Code style fixes applied successfully."

check-db:
	@echo "Checking database connection..."
	@for i in $$(seq 1 $(DB_WAIT_TIMEOUT)); do \
		if docker compose exec -T $(DB_HOST) pg_isready -q; then \
			echo "Database is ready after $$i seconds."; \
			exit 0; \
		fi; \
		echo "Waiting for database... ($$i/$(DB_WAIT_TIMEOUT))"; \
		sleep 1; \
	done; \
	echo "ERROR: Database connection timed out after $(DB_WAIT_TIMEOUT) seconds."; \
	exit 1

setup-venv:
	@echo "Setting up virtual environment..."
	@if [ ! -d $(VENV_DIR) ]; then \
		echo "Creating new virtual environment..."; \
		uv sync \
		echo "Virtual environment created successfully."; \
	else \
		echo "Virtual environment exists, updating dependencies..."; \
		uv sync; \
		echo "Virtual environment updated successfully."; \
	fi

dev: verify setup-venv
	@echo "Setting up development environment..."
	@echo "Starting Docker Compose services..."
	@docker compose up -d postgres redis
	@echo "Docker services started. Checking database connection..."
	@for i in $$(seq 1 $(DB_WAIT_TIMEOUT)); do \
		if docker compose exec -T $(DB_HOST) pg_isready -q; then \
			echo "Database is ready after $$i seconds."; \
			break; \
		fi; \
		if [ $$i -eq $(DB_WAIT_TIMEOUT) ]; then \
			echo "ERROR: Database connection timed out after $(DB_WAIT_TIMEOUT) seconds."; \
			exit 1; \
		fi; \
		echo "Waiting for database... ($$i/$(DB_WAIT_TIMEOUT))"; \
		sleep 1; \
	done
	@echo "Setting up database schema..."
	@mkdir -p alembic/versions
	@if [ -d alembic/versions ] && [ "$$(ls -A alembic/versions 2>/dev/null)" ]; then \
		echo "Applying existing migrations..."; \
		alembic upgrade head; \
	else \
		echo "Creating initial migration..."; \
		alembic revision --autogenerate -m "Initial migration"; \
		echo "Applying initial migration..."; \
		alembic upgrade head; \
	fi
	@echo "Development environment is ready."

run: dev
	@echo "Starting FastAPI server..."
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		echo "FastAPI server is already running with PID: $$(cat $(PID_FILE))"; \
	else \
		echo "Starting server on port $(SERVER_PORT)..."; \
		uvx uvicorn app.main:app --reload --port $(SERVER_PORT) & \
		new_pid=$$!; \
		echo "$$new_pid" > $(PID_FILE); \
		echo "Server started with PID: $$new_pid"; \
	fi
	@echo "Server startup complete."

migrate:
	@echo "Generating database migration..."
	@echo "Checking database connection..."
	@if ! docker compose exec -T $(DB_HOST) pg_isready -q; then \
		echo "ERROR: Database is not available. Run 'make dev' first."; \
		exit 1; \
	fi
	@echo "Detecting model changes..."
	@mkdir -p alembic/versions
	@current_rev=$$(alembic current 2>/dev/null | grep -v "No current revision" | head -1 | awk '{print $$1}'); \
	if [ -z "$$current_rev" ]; then \
		echo "Creating initial migration..."; \
		migration_name="Initial migration"; \
	else \
		echo "Creating incremental migration..."; \
		migration_name="Model updates"; \
	fi; \
	alembic revision --autogenerate -m "$$migration_name"
	@echo "Migration script generated successfully."
	@echo "Please review migration files in alembic/versions/ before applying."
	@echo "To apply migrations, run: make migrate-apply"

migrate-apply:
	@echo "Applying database migrations..."
	@echo "Checking database connection..."
	@if ! docker compose exec -T $(DB_HOST) pg_isready -q; then \
		echo "ERROR: Database is not available. Run 'make dev' first."; \
		exit 1; \
	fi
	@echo "Previous migration state:"
	@alembic current
	@echo "Applying migrations..."
	@alembic upgrade head
	@echo "New migration state:"
	@alembic current
	@echo "Migrations applied successfully."

stop:
	@echo "Stopping services..."
	@if [ -f $(PID_FILE) ]; then \
		pid=$$(cat $(PID_FILE)); \
		if kill -0 $$pid 2>/dev/null; then \
			echo "Stopping FastAPI server with PID: $$pid"; \
			kill $$pid; \
			for i in $$(seq 1 5); do \
				if ! kill -0 $$pid 2>/dev/null; then \
					break; \
				fi; \
				sleep 1; \
			done; \
			if kill -0 $$pid 2>/dev/null; then \
				echo "Force stopping FastAPI server with PID: $$pid"; \
				kill -9 $$pid; \
			fi; \
		else \
			echo "No running FastAPI server found with PID: $$pid"; \
		fi; \
		rm -f $(PID_FILE); \
	else \
		echo "No FastAPI server PID file found."; \
		uvicorn_pids=$$(pgrep -f "uvicorn app.main:app" || echo ""); \
		if [ -n "$$uvicorn_pids" ]; then \
			echo "Found orphaned uvicorn processes. Stopping PIDs: $$uvicorn_pids"; \
			kill $$uvicorn_pids 2>/dev/null; \
		fi; \
	fi; \
	echo "Stopping Docker Compose services..."; \
	docker compose stop; \
	echo "All services stopped successfully."

clean: stop
	@echo "Cleaning up environment..."
	@echo "Removing Docker Compose resources..."
	@docker compose down -v --remove-orphans
	@echo "Removing cache files..."
	@find . -name "__pycache__" -type d -exec rm -rf {} +
	@find . -name "*.pyc" -type f -delete
	@find . -name ".pytest_cache" -type d -exec rm -rf {} +
	@find . -name ".ruff_cache" -type d -exec rm -rf {} +
	@find . -name ".mypy_cache" -type d -exec rm -rf {} +
	@echo "Environment cleaned successfully."