"""Clock abstraction so time-dependent logic is testable."""

from datetime import UTC, datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    """Source of the current tz-aware UTC time."""

    def now(self) -> datetime: ...


class SystemClock:
    """Wall-clock time in UTC."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class FrozenClock:
    """Test clock that only moves when told to."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = _require_aware(start or datetime(2026, 1, 1, tzinfo=UTC))

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> datetime:
        self._now = self._now + delta
        return self._now

    def set(self, value: datetime) -> None:
        self._now = _require_aware(value)


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("clock values must be timezone-aware")
    return value
