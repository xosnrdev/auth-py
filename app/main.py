from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncEngine

from app.api.v1 import router as api_v1_router
from app.core.config import settings
from app.db.base import engine
from app.models import Base


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    # Startup: create database tables
    async with engine.begin() as conn:
        # await conn.run_sync(Base.metadata.drop_all)  # Uncomment to reset DB
        await conn.run_sync(Base.metadata.create_all)

    yield

    # Shutdown: close database connections
    if isinstance(engine, AsyncEngine):
        await engine.dispose()


app = FastAPI(
    title="Authentication Service",
    description="RFC IETF Compliant Authentication Service",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

# Include API routes
app.include_router(api_v1_router, prefix="/api")


@app.get("/")
async def read_root() -> dict[str, str]:
    return {"message": "Hello World"}
