#!/usr/bin/env bash

set -e
set -u
set -o pipefail

readonly MAX_RETRIES=30
readonly RETRY_INTERVAL=2

check_docker_running() {
  if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again." >&2
    return 1
  fi
  return 0
}

check_containers_running() {
  if ! docker compose -f docker-compose.dev.yml ps --services --filter "status=running" | grep -q "postgres\|redis"; then
    echo "Starting Docker containers..."
    if ! docker compose -f docker-compose.dev.yml up -d; then
      echo "Error: Failed to start Docker containers." >&2
      return 1
    fi
  else
    echo "Docker containers are already running."
  fi
  return 0
}

wait_for_postgres() {
  local retries=0
  
  echo "Waiting for PostgreSQL to be ready..."
  while [ "$retries" -lt "$MAX_RETRIES" ]; do
    if docker compose -f docker-compose.dev.yml exec -T postgres pg_isready 2>/dev/null; then
      echo "PostgreSQL is ready."
      return 0
    fi
    
    echo "PostgreSQL is not ready yet. Retrying in ${RETRY_INTERVAL}s... (${retries}/${MAX_RETRIES})"
    sleep "$RETRY_INTERVAL"
    retries=$((retries+1))
  done
  
  echo "Error: PostgreSQL did not become ready within time limit." >&2
  return 1
}

check_redis() {
  echo "Checking Redis connection..."
  if ! docker compose -f docker-compose.dev.yml exec -T redis redis-cli ping 2>/dev/null | grep -q "PONG"; then
    echo "Error: Redis is not responding correctly." >&2
    return 1
  fi
  echo "Redis is ready."
  return 0
}

handle_migrations() {
  echo "Managing database migrations..."
  
  if ! mkdir -p alembic/versions; then
    echo "Error: Failed to create migrations directory." >&2
    return 1
  fi
  
  if [ "$(find alembic/versions -name "*.py" 2>/dev/null | wc -l)" -gt 0 ]; then
    echo "Migration files exist. Running upgrade..."
    if ! alembic upgrade head; then
      echo "Error: Database upgrade failed." >&2
      return 1
    fi
  else
    echo "No migration files found. Creating initial migration..."
    if ! alembic revision --autogenerate -m "Initial migration"; then
      echo "Error: Failed to create initial migration." >&2
      return 1
    fi
    
    if ! alembic upgrade head; then
      echo "Error: Initial migration failed." >&2
      return 1
    fi
  fi
  
  return 0
}

main() {
  local exit_code=0
  
  if ! check_docker_running; then
    exit_code=1
    return "$exit_code"
  fi
  
  if ! check_containers_running; then
    exit_code=2
    return "$exit_code"
  fi
  
  if ! wait_for_postgres; then
    exit_code=3
    return "$exit_code"
  fi
  
  if ! check_redis; then
    exit_code=4
    return "$exit_code"
  fi
  
  if ! handle_migrations; then
    exit_code=5
    return "$exit_code"
  fi
  
  echo "Environment setup completed successfully."
  return 0
}

main
exit $?