"""Seed S2 checks: phase-2 interfaces import, the fake driver satisfies them, tokens/SSE work."""

import asyncio
import importlib
import io
import sqlite3
import tarfile
from collections.abc import AsyncIterator
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from sandfort.api.schemas.toolbox_fs import MAX_INLINE_READ_BYTES, MAX_UPLOAD_BYTES
from sandfort.api.schemas.toolbox_git import GitCloneRequest
from sandfort.api.sse import KEEPALIVE_COMMENT, format_event, with_keepalive
from sandfort.auth.connect_tokens import (
    ConnectGrant,
    ConnectTokenInvalid,
    InMemoryConnectTokenStore,
)
from sandfort.clock import FrozenClock
from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import (
    ArchiveStreamDriver,
    LogsDriver,
    PtySessionDriver,
    SandboxSpec,
)
from sandfort.drivers.fake import FakeDriver

ROOT = Path(__file__).resolve().parents[1]
NEW_MODULES = [
    "sandfort.drivers.docker.archive",
    "sandfort.drivers.docker.pty",
    "sandfort.drivers.docker.logs",
    "sandfort.api.schemas.toolbox_fs",
    "sandfort.api.schemas.toolbox_sessions",
    "sandfort.api.schemas.toolbox_git",
    "sandfort.api.schemas.toolbox_pty",
    "sandfort.api.sse",
    "sandfort.auth.connect_tokens",
    "sandfort.db.models.exec",
    "sandfort.db.models.pty",
    "sandfort.db.repositories.exec",
    "sandfort.db.repositories.pty",
    "sandfort.migrations.versions.r0002_phase2",
]


@pytest.mark.parametrize("module", NEW_MODULES)
def test_new_module_imports(module: str) -> None:
    assert importlib.import_module(module) is not None


def test_size_caps() -> None:
    assert MAX_UPLOAD_BYTES == 256 * 1024 * 1024
    assert MAX_INLINE_READ_BYTES == 2 * 1024 * 1024


def test_git_credential_token_is_hidden() -> None:
    payload = {
        "url": "https://example.test/repo.git",
        "path": "/work",
        "credential": {"username": "u", "token": "s3cret"},
    }

    request = GitCloneRequest.model_validate(payload)

    assert request.credential is not None
    assert request.credential.token == "s3cret"
    assert "s3cret" not in repr(request)
    assert "s3cret" not in request.model_dump_json()


async def running_sandbox(driver: FakeDriver) -> str:
    spec = SandboxSpec(
        sandbox_id="sbx_x",
        org_id="org_x",
        name="sf-sbx_x",
        image="python:3.12-slim",
        resources=ResourceSpec(),
    )
    info = await driver.create(spec)
    await driver.start(info.ref)
    return info.ref


def test_fake_driver_satisfies_phase2_protocols() -> None:
    driver = FakeDriver()

    assert isinstance(driver, ArchiveStreamDriver)
    assert isinstance(driver, PtySessionDriver)
    assert isinstance(driver, LogsDriver)


async def test_fake_archive_round_trip() -> None:
    driver = FakeDriver()
    ref = await running_sandbox(driver)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo("hello.txt")
        member.size = 5
        archive.addfile(member, io.BytesIO(b"hello"))

    async def chunks() -> AsyncIterator[bytes]:
        yield buffer.getvalue()

    await driver.put_archive(ref, "/work", chunks())
    stat, stream = await driver.get_archive_with_stat(ref, "/work/hello.txt")
    payload = b"".join([chunk async for chunk in stream])

    assert stat["name"] == "hello.txt"
    assert stat["size"] == 5
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r") as archive:
        extracted = archive.extractfile("hello.txt")
        assert extracted is not None
        assert extracted.read() == b"hello"


async def test_fake_pty_echoes_writes() -> None:
    driver = FakeDriver()
    ref = await running_sandbox(driver)

    handle = await driver.create_pty(ref, ["/bin/bash"], {}, rows=24, cols=80)
    await driver.resize_pty(handle, 40, 100)
    await driver.write_pty(handle, b"ls\n")

    assert await driver.read_pty(handle) == b"ls\n"
    await driver.close_pty(handle)
    assert await driver.read_pty(handle) == b""


async def test_fake_logs_replay_with_tail_and_since() -> None:
    clock = FrozenClock()
    driver = FakeDriver(clock=clock)
    ref = await running_sandbox(driver)
    driver.append_log(ref, "one")
    clock.advance(timedelta(seconds=10))
    second = driver.append_log(ref, "two", stream="stderr")
    clock.advance(timedelta(seconds=10))
    driver.append_log(ref, "three")

    everything = [entry.line async for entry in driver.stream_logs(ref)]
    last = [entry.line async for entry in driver.stream_logs(ref, tail=1)]
    recent = [entry async for entry in driver.stream_logs(ref, since=second.timestamp)]

    assert everything == ["one", "two", "three"]
    assert last == ["three"]
    assert [entry.line for entry in recent] == ["two", "three"]
    assert recent[0].stream == "stderr"


async def test_connect_token_single_use() -> None:
    store = InMemoryConnectTokenStore(clock=FrozenClock())

    token = await store.mint("org_a", "sbx_a", "pty_a")
    grant = await store.redeem(token)

    assert grant == ConnectGrant(org_id="org_a", sandbox_id="sbx_a", pty_id="pty_a")
    with pytest.raises(ConnectTokenInvalid):
        await store.redeem(token)


async def test_connect_token_unknown_is_rejected() -> None:
    store = InMemoryConnectTokenStore(clock=FrozenClock())

    with pytest.raises(ConnectTokenInvalid):
        await store.redeem("nope")


async def test_connect_token_expires() -> None:
    clock = FrozenClock()
    store = InMemoryConnectTokenStore(clock=clock, ttl=timedelta(seconds=30))
    token = await store.mint("org_a", "sbx_a", "pty_a")

    clock.advance(timedelta(seconds=30))

    with pytest.raises(ConnectTokenInvalid):
        await store.redeem(token)


def test_format_event_wire_text() -> None:
    frame = format_event({"line": "hi", "n": 1}, event="log", event_id="7")

    assert frame == 'event: log\nid: 7\ndata: {"line":"hi","n":1}\n\n'


def test_format_event_data_only() -> None:
    assert format_event("x") == 'data: "x"\n\n'


async def test_with_keepalive_emits_comment_while_idle() -> None:
    release = asyncio.Event()

    async def source() -> AsyncIterator[str]:
        await release.wait()
        yield format_event({"n": 1})

    stream = with_keepalive(source(), interval_s=0.01)

    assert await anext(stream) == KEEPALIVE_COMMENT
    release.set()
    assert await anext(stream) == 'data: {"n":1}\n\n'
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


def test_migration_chain_creates_phase2_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "s2.db"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")

    command.upgrade(config, "head")

    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        tables = {row[0] for row in rows}
        version = connection.execute("SELECT version_num FROM alembic_version").fetchall()
    assert {"exec_sessions", "exec_commands", "pty_sessions"} <= tables
    assert version == [(ScriptDirectory.from_config(config).get_current_head(),)]
