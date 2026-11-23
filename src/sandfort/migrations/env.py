"""Alembic environment.

The database URL comes from the ``sqlalchemy.url`` option when set (tests,
programmatic callers) and otherwise from ``Settings`` /
``SANDFORT_DATABASE_URL``. Migrations run on a synchronous driver, so async
URLs are mapped back via ``to_sync_url``; SQLite uses batch mode for ALTERs.
"""

from alembic import context
from sqlalchemy import create_engine, pool

from sandfort.config import Settings
from sandfort.db import models  # noqa: F401  (registers tables on Base.metadata)
from sandfort.db.base import Base
from sandfort.db.urls import is_sqlite, to_sync_url

config = context.config
target_metadata = Base.metadata


def _database_url() -> str:
    configured = config.get_main_option("sqlalchemy.url")
    raw = configured or Settings.from_env().database_url
    return to_sync_url(raw).render_as_string(hide_password=False)


def run_migrations_offline() -> None:
    url = _database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_database_url(), poolclass=pool.NullPool)
    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=is_sqlite(engine.url),
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
