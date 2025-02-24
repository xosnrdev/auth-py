"""SQLAlchemy base model with UUID and timestamps.

Example:
```python
class Product(Base):
    name: Mapped[str]
    price: Mapped[float]

# Create with auto fields
product = Product(name="Widget", price=9.99)
# id: auto-generated UUID4
# created_at: current UTC timestamp
# updated_at: auto-updates on save

# Convert to dict (UUIDs as hex)
data = product.dict()
assert data == {
    "id": "123e4567...",  # UUID as hex
    "name": "Widget",
    "price": 9.99,
    "created_at": "2025-02-23T...",  # UTC ISO format
    "updated_at": "2025-02-23T..."   # UTC ISO format
}
```

Critical Notes:
- All IDs are UUID4
- All timestamps use UTC
- created_at set on insert
- updated_at changes on update
- PostgreSQL functions used
- Timezone awareness required
"""

from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID, uuid4

from sqlalchemy import DateTime, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Constants
UUID_LENGTH: Final[int] = 32  # Hex string length
TIMESTAMP_FORMAT: Final[str] = 'YYYY-MM-DD"T"HH24:MI:SS.US"TZ"'  # PostgreSQL format
PG_UUID_FUNCTION: Final[str] = "gen_random_uuid()"
PG_TIMESTAMP_FUNCTION: Final[str] = "CURRENT_TIMESTAMP"


class Base(DeclarativeBase):
    """Base model with UUID and timestamps."""

    # Primary key
    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
        server_default=text(PG_UUID_FUNCTION),
    )

    # Audit timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text(PG_TIMESTAMP_FUNCTION),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text(PG_TIMESTAMP_FUNCTION),
        onupdate=text(PG_TIMESTAMP_FUNCTION),
    )

    def dict(self) -> dict[str, Any]:
        """Convert model to dict with hex UUIDs."""
        result: dict[str, Any] = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            # Convert UUID to hex string
            if isinstance(value, UUID):
                assert len(value.hex) == UUID_LENGTH, "Invalid UUID length"
                result[column.name] = value.hex
            # Ensure timestamps are UTC
            elif isinstance(value, datetime):
                assert value.tzinfo is not None, "Timestamp must be timezone-aware"
                result[column.name] = value.astimezone(UTC).isoformat()
            else:
                result[column.name] = value
        return result
