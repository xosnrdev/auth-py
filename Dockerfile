FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/auth-py

WORKDIR /auth-py

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PATH="/auth-py/.venv/bin:$PATH"

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY pyproject.toml uv.lock app ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync

CMD ["fastapi", "run", "--workers", "4", "app/main.py"]