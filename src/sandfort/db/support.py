"""Small helpers shared by models and repositories."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, cast

from sqlalchemy.engine import CursorResult, Result
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sandfort.errors import ALREADY_EXISTS, Conflict


def as_utc(value: datetime) -> datetime:
    """Normalise to tz-aware UTC; SQLite hands back naive datetimes that are already UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def opt_utc(value: datetime | None) -> datetime | None:
    return None if value is None else as_utc(value)


def in_check(column: str, enum: type[StrEnum]) -> str:
    """CHECK expression restricting ``column`` to the values of ``enum``."""
    values = ", ".join(f"'{member.value}'" for member in enum)
    return f"{column} IN ({values})"


def rowcount(result: Result[Any]) -> int:
    """Rows matched by an UPDATE/DELETE executed through the session."""
    return cast(CursorResult[Any], result).rowcount


async def flush_or_conflict(
    session: AsyncSession, message: str, *, reason: str = ALREADY_EXISTS
) -> None:
    """Flush pending inserts, mapping constraint violations to ``Conflict``.

    ``reason`` is the conflict's machine-readable reason; an insert that violates a
    constraint almost always collides with a row that already exists.
    The session's transaction is unusable after a failed flush; the unit of
    work rolls it back when the ``async with`` block exits.
    """
    try:
        await session.flush()
    except IntegrityError as exc:
        raise Conflict(message, reason=reason) from exc
