"""FastAPI application entry point."""

from app.core.registrar import create_app

app = create_app()
