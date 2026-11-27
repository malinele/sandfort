"""A task cancelled while its SQLite statement runs must not keep the write lock.

Every transaction starts with ``BEGIN IMMEDIATE`` (``sandfort.db.engine``), so it holds the
database write lock from its first statement. When the task is cancelled while a statement is
still running in the aiosqlite thread, SQLAlchemy closes the connection without a ``ROLLBACK``.
sqlite3 cannot finish that close while a cursor still holds the unfinished statement, so the
transaction and the write lock stayed open until the cancelled task was garbage collected.
Worker shutdown hit this: ``_stop_workers`` cancels each worker loop, and a loop cancelled in
the middle of a read left every later writer waiting out ``busy_timeout``.

The statement under test blocks in a SQL function until the test lets it go, so the
cancellation always lands while the statement runs. The garbage collector is off during each
test: a collection would release the lock and hide the bug.
"""

import asyncio
import gc
import sqlite3
import threading
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine

from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.sqlite_connection import RollbackOnCloseConnection
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.workers.reconciler import PassLoop

WAIT_S = 5.0
LONG_INTERVAL_S = 3600.0


@dataclass(frozen=True)
class Gate:
    """``blocking()`` sets ``started`` and returns only once ``release`` is set."""

    started: threading.Event
    release: threading.Event

    def blocking(self) -> int:
        self.started.set()
        self.release.wait(WAIT_S)
        return 1


@pytest.fixture
def no_gc() -> Iterator[None]:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "lock.db"
    with sqlite3.connect(path) as raw:
        raw.execute("CREATE TABLE marks (x INTEGER)")
    return path


@pytest.fixture
def gate() -> Gate:
    return Gate(threading.Event(), threading.Event())


@pytest.fixture
async def engine(db_path: Path, gate: Gate, no_gc: None) -> AsyncIterator[AsyncEngine]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    built = create_engine(Settings(driver="fake", database_url=f"sqlite+aiosqlite:///{db_path}"))

    @event.listens_for(built.sync_engine, "connect")
    def _register(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.run_async(
            lambda driver: driver.create_function("blocking", 0, gate.blocking)
        )

    yield built
    gate.release.set()
    await built.dispose()


def write_lock_is_free(path: Path) -> bool:
    """True when another connection can take the write lock without waiting."""
    raw = sqlite3.connect(path, timeout=0, isolation_level=None)
    try:
        raw.execute("BEGIN IMMEDIATE")
        raw.execute("ROLLBACK")
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        raw.close()


def marks(path: Path) -> int:
    with sqlite3.connect(path) as raw:
        return int(raw.execute("SELECT count(*) FROM marks").fetchone()[0])


async def started(gate: Gate) -> None:
    assert await asyncio.to_thread(gate.started.wait, WAIT_S), "the statement never started"


async def test_a_unit_of_work_cancelled_mid_statement_releases_the_write_lock(
    engine: AsyncEngine, db_path: Path, gate: Gate
) -> None:
    factory = create_session_factory(engine)

    async def read() -> None:
        async with UnitOfWork(factory) as uow:
            await uow.session.execute(text("SELECT blocking()"))

    task = asyncio.create_task(read())
    await started(gate)
    assert not write_lock_is_free(db_path)  # the open transaction holds the lock

    task.cancel()
    gate.release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert write_lock_is_free(db_path)


async def test_a_cancelled_transaction_is_rolled_back_not_committed(
    engine: AsyncEngine, db_path: Path, gate: Gate
) -> None:
    factory = create_session_factory(engine)

    async def write_then_read() -> None:
        async with UnitOfWork(factory) as uow:
            await uow.session.execute(text("INSERT INTO marks (x) VALUES (1)"))
            await uow.session.execute(text("SELECT blocking()"))
            await uow.commit()

    task = asyncio.create_task(write_then_read())
    await started(gate)
    task.cancel()
    gate.release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert write_lock_is_free(db_path)
    assert marks(db_path) == 0


async def test_a_worker_loop_stopped_mid_statement_leaves_no_write_lock(
    engine: AsyncEngine, db_path: Path, gate: Gate
) -> None:
    factory = create_session_factory(engine)

    async def one_pass() -> None:
        async with UnitOfWork(factory) as uow:
            await uow.session.execute(text("SELECT blocking()"))

    loop = PassLoop("lock test", one_pass, LONG_INTERVAL_S)
    loop.start()
    await started(gate)

    stopping = asyncio.create_task(loop.stop())  # the shutdown path: stop() cancels the pass
    await asyncio.sleep(0)
    gate.release.set()
    await stopping

    assert not loop.running
    assert write_lock_is_free(db_path)


def test_close_rolls_back_an_open_transaction_and_still_closes(db_path: Path) -> None:
    raw = sqlite3.connect(db_path, factory=RollbackOnCloseConnection, isolation_level=None)
    raw.execute("BEGIN IMMEDIATE")
    raw.execute("INSERT INTO marks (x) VALUES (1)")

    raw.close()

    assert write_lock_is_free(db_path)
    assert marks(db_path) == 0
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        raw.execute("SELECT 1")


async def test_a_completed_transaction_still_commits_and_frees_the_lock(
    engine: AsyncEngine, db_path: Path
) -> None:
    factory = create_session_factory(engine)

    async with UnitOfWork(factory) as uow:
        await uow.session.execute(text("INSERT INTO marks (x) VALUES (1)"))
        await uow.commit()
    await engine.dispose()

    assert write_lock_is_free(db_path)
    assert marks(db_path) == 1
