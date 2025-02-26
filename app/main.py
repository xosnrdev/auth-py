"""FastAPI application entry point."""

from app.core.registrar import register_app

app = register_app()
