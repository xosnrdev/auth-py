from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine

from app.db.base import Base, engine


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


@app.get("/")
async def read_root() -> dict[str, str]:
    return {"message": "Hello World"}
