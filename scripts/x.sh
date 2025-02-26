#!/usr/bin/env bash
set -e

docker compose -f docker-compose.dev.yml up -d

docker compose -f docker-compose.dev.yml exec postgres pg_isready
docker compose -f docker-compose.dev.yml exec redis redis-cli ping

current_revision=$(alembic current --verbose | tail -n 1 | awk '{print $NF}')
head_revision=$(alembic heads --verbose | tail -n 1 | awk '{print $NF}')

echo "Current DB revision: $current_revision"
echo "Head revision:        $head_revision"

if [ "$current_revision" != "$head_revision" ]; then
    echo "Models changed - generating new migration"
    alembic revision --autogenerate -m "Auto-generated migration"
else
    echo "No model changes detected - skipping migration generation"
fi

alembic upgrade head