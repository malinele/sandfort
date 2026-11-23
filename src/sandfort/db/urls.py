"""Database URL switch: async drivers for the app, sync drivers for alembic.

``SANDFORT_DATABASE_URL`` may name a bare backend (``sqlite://``,
``postgresql://``, or the ``postgres://`` alias); the matching async driver is
filled in. Alembic runs synchronously, so async drivers are mapped back to a sync one.
"""

from sqlalchemy.engine import URL, make_url

POSTGRESQL = "postgresql"
ASYNC_DRIVERS = {
    "sqlite": "sqlite+aiosqlite",
    "postgresql": "postgresql+asyncpg",
    "postgres": "postgresql+asyncpg",
}
SYNC_DRIVERS = {
    "sqlite+aiosqlite": "sqlite",
    "postgresql+asyncpg": "postgresql+psycopg",
    "postgres": "postgresql+psycopg",
}


def to_async_url(raw: str) -> URL:
    url = make_url(raw)
    driver = ASYNC_DRIVERS.get(url.drivername)
    return url if driver is None else url.set(drivername=driver)


def to_sync_url(raw: str) -> URL:
    url = make_url(raw)
    driver = SYNC_DRIVERS.get(url.drivername)
    return url if driver is None else url.set(drivername=driver)


def is_sqlite(url: URL) -> bool:
    return url.get_backend_name() == "sqlite"


def is_postgres(url: URL) -> bool:
    return url.get_backend_name() == POSTGRESQL
