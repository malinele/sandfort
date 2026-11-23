"""Async engine/session factory with SQLite pragmas and a BEGIN IMMEDIATE hook.

SQLite (dev) goes through aiosqlite; Postgres (prod) goes through asyncpg with a
pool sized by ``database_pool_size`` / ``database_max_overflow``. Any other URL is
handed to SQLAlchemy unchanged apart from filling in a default async driver.
"""

from typing import Any

from sqlalchemy import Connection, event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sandfort.config import Settings
from sandfort.db.urls import is_postgres, is_sqlite, to_async_url

SQLITE_BUSY_TIMEOUT_MS = 5000
SQLITE_PRAGMAS = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA foreign_keys=ON",
    f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}",
)


def _install_sqlite_hooks(engine: AsyncEngine) -> None:
    sync_engine = engine.sync_engine

    @event.listens_for(sync_engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        # Stop the driver from emitting its own BEGIN; _on_begin owns transaction start.
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        try:
            for pragma in SQLITE_PRAGMAS:
                cursor.execute(pragma)
        finally:
            cursor.close()

    @event.listens_for(sync_engine, "begin")
    def _on_begin(connection: Connection) -> None:
        # Take the write lock up front so lock contention shows up as busy_timeout waits
        # at BEGIN rather than as mid-transaction "database is locked" failures.
        connection.exec_driver_sql("BEGIN IMMEDIATE")


def create_engine(settings: Settings) -> AsyncEngine:
    url = to_async_url(settings.database_url)
    if is_sqlite(url):
        engine = create_async_engine(url)
        _install_sqlite_hooks(engine)
        return engine
    if is_postgres(url):
        return create_async_engine(
            url,
            pool_pre_ping=True,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
        )
    return create_async_engine(url, pool_pre_ping=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
