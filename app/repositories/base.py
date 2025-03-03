"""Base repository with generic CRUD operations."""

from datetime import UTC, datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import (
    DatabaseError,
    DuplicateError,
    NotFoundError,
)
from app.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)

MAX_LIMIT: int = 100
DEFAULT_LIMIT: int = 20


class BaseRepository(Generic[ModelType]):
    """Generic repository for database operations."""

    def __init__(self, session: AsyncSession, model: type[ModelType]) -> None:
        """Initialize repository with session and model.

        Args:
            session: SQLAlchemy async session
            model: SQLAlchemy model class
        """
        assert session is not None, "Session cannot be None"
        assert model is not None, "Model cannot be None"
        assert issubclass(model, Base), "Model must inherit from Base"

        self._session = session
        self._model = model

    async def create(self, data: dict[str, Any]) -> ModelType:
        """Create a new record.

        Args:
            data: Dictionary of model attributes

        Returns:
            Created model instance

        Raises:
            DuplicateError: If unique constraint is violated
            DatabaseError: For other database errors
        """
        assert data is not None, "Data cannot be None"

        try:
            instance = self._model(**data)
            self._session.add(instance)
            await self._session.flush()
            await self._session.commit()
            return instance

        except IntegrityError as e:
            await self._session.rollback()
            raise DuplicateError(str(e)) from e

        except SQLAlchemyError as e:
            await self._session.rollback()
            raise DatabaseError(str(e)) from e

    async def get_by_id(self, id: UUID) -> ModelType:
        """Get record by ID.

        Args:
            id: UUID of the record

        Returns:
            Model instance

        Raises:
            NotFoundError: If record not found
            DatabaseError: For database errors
        """
        assert id is not None, "ID cannot be None"

        try:
            instance = await self._session.get(self._model, id)
            if instance is None:
                raise NotFoundError(f"{self._model.__name__} not found")
            return instance

        except SQLAlchemyError as e:
            raise DatabaseError(str(e)) from e

    async def get_all(
        self,
        *,
        offset: int = 0,
        limit: int = DEFAULT_LIMIT,
    ) -> list[ModelType]:
        """Get all records with pagination.

        Args:
            offset: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of model instances

        Raises:
            DatabaseError: For database errors
        """
        assert offset >= 0, "Offset must be non-negative"
        assert 0 < limit <= MAX_LIMIT, f"Limit must be between 1 and {MAX_LIMIT}"

        try:
            query = select(self._model).offset(offset).limit(limit)
            result = await self._session.execute(query)
            return list(result.scalars().all())

        except SQLAlchemyError as e:
            raise DatabaseError(str(e)) from e

    async def update(
        self,
        id: UUID,
        data: dict[str, Any],
    ) -> ModelType:
        """Update a record.

        Args:
            id: UUID of the record
            data: Dictionary of attributes to update

        Returns:
            Updated model instance

        Raises:
            NotFoundError: If record not found
            DuplicateError: If unique constraint is violated
            DatabaseError: For other database errors
        """
        assert id is not None, "ID cannot be None"
        assert data is not None, "Data cannot be None"

        try:
            instance = await self.get_by_id(id)

            # Update attributes
            for key, value in data.items():
                setattr(instance, key, value)

            # Update timestamp
            instance.updated_at = datetime.now(UTC)

            await self._session.flush()
            return instance

        except IntegrityError as e:
            await self._session.rollback()
            raise DuplicateError(str(e)) from e

        except SQLAlchemyError as e:
            await self._session.rollback()
            raise DatabaseError(str(e)) from e

    async def delete(self, id: UUID) -> None:
        """Delete a record.

        Args:
            id: UUID of the record to delete

        Raises:
            NotFoundError: If record not found
            DatabaseError: For database errors
        """
        assert id is not None, "ID cannot be None"

        try:
            instance = await self.get_by_id(id)
            await self._session.delete(instance)
            await self._session.flush()

        except SQLAlchemyError as e:
            await self._session.rollback()
            raise DatabaseError(str(e)) from e

    async def exists(self, id: UUID) -> bool:
        """Check if record exists.

        Args:
            id: UUID of the record

        Returns:
            True if record exists, False otherwise

        Raises:
            DatabaseError: For database errors
        """
        assert id is not None, "ID cannot be None"

        try:
            instance = await self._session.get(self._model, id)
            return instance is not None

        except SQLAlchemyError as e:
            raise DatabaseError(str(e)) from e

    async def count(self, filters: dict[str, Any] | None = None) -> int:
        """Count records with optional filters.

        Args:
            filters: Optional dictionary of filters
                Special suffixes:
                - _gt: Greater than
                - _lt: Less than
                - _gte: Greater than or equal
                - _lte: Less than or equal

        Returns:
            Number of records

        Raises:
            DatabaseError: For database errors
        """
        try:
            query = select(func.count()).select_from(self._model)

            if filters:
                for key, value in filters.items():
                    # Handle special comparison operators
                    if key.endswith("_gt"):
                        field = key[:-3]  # Remove _gt suffix
                        query = query.where(getattr(self._model, field) > value)
                    elif key.endswith("_lt"):
                        field = key[:-3]  # Remove _lt suffix
                        query = query.where(getattr(self._model, field) < value)
                    elif key.endswith("_gte"):
                        field = key[:-4]  # Remove _gte suffix
                        query = query.where(getattr(self._model, field) >= value)
                    elif key.endswith("_lte"):
                        field = key[:-4]  # Remove _lte suffix
                        query = query.where(getattr(self._model, field) <= value)
                    else:
                        # Handle exact matches
                        query = query.where(getattr(self._model, key) == value)

            result = await self._session.execute(query)
            return result.scalar() or 0

        except SQLAlchemyError as e:
            raise DatabaseError(str(e)) from e

    def _build_query(self) -> Select[tuple[ModelType]]:
        """Build base query for the model.

        Returns:
            SQLAlchemy select statement
        """
        return select(self._model)
