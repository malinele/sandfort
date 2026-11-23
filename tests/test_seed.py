"""Seed S1 checks: these must pass before any work package starts."""

import io
import tarfile
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta

import pytest

from sandfort import ids
from sandfort.api.envelope import fail, ok
from sandfort.api.schemas.common import Meta
from sandfort.clock import FrozenClock
from sandfort.config import Settings, is_reserved_env_name
from sandfort.domain.lifecycle import (
    TRANSITIONS,
    IllegalTransition,
    assert_transition,
    can_transition,
)
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import SandboxState
from sandfort.drivers.base import ExecRequest, InstanceState, SandboxSpec
from sandfort.drivers.errors import DriverNotFound
from sandfort.drivers.fake import FakeDriver
from sandfort.errors import NotFound, QuotaExceeded

S = SandboxState


async def test_fake_driver_round_trip() -> None:
    driver = FakeDriver()
    spec = SandboxSpec(
        sandbox_id="sbx_x",
        org_id="org_x",
        name="sf-sbx_x",
        image="python:3.12-slim",
        resources=ResourceSpec(),
        env={"FOO": "bar"},
    )

    created = await driver.create(spec)
    assert created.state is InstanceState.CREATED
    assert (await driver.create(spec)).ref == created.ref  # idempotent on name

    await driver.start(created.ref)
    result = await driver.exec(created.ref, ExecRequest(argv=["echo", "hello"]))
    assert (result.exit_code, result.stdout) == (0, b"hello\n")
    failed = await driver.exec(created.ref, ExecRequest(argv=["sh", "-c", "exit 3"]))
    assert failed.exit_code == 3
    env_out = await driver.exec(created.ref, ExecRequest(argv=["env"]))
    assert b"FOO=bar" in env_out.stdout
    assert [info.ref for info in await driver.list_managed(org_id="org_x")] == [created.ref]

    await driver.stop(created.ref)
    assert (await driver.inspect(created.ref)).state is InstanceState.EXITED

    await driver.destroy(created.ref)
    with pytest.raises(DriverNotFound):
        await driver.inspect(created.ref)


async def test_fake_driver_archive_round_trip() -> None:
    driver = FakeDriver()
    info = await driver.create(
        SandboxSpec(
            sandbox_id="sbx_y",
            org_id="org_y",
            name="sf-sbx_y",
            image="alpine",
            resources=ResourceSpec(),
        )
    )
    await driver.start(info.ref)

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo("hello.txt")
        member.size = 2
        archive.addfile(member, io.BytesIO(b"hi"))

    async def chunks() -> AsyncIterator[bytes]:
        yield buffer.getvalue()

    await driver.put_archive(info.ref, "/work", chunks())
    payload = b"".join([chunk async for chunk in driver.get_archive(info.ref, "/work/hello.txt")])
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        extracted = archive.extractfile("hello.txt")
        assert extracted is not None
        assert extracted.read() == b"hi"


def test_lifecycle_transition_table() -> None:
    explicit = {
        (S.PENDING, S.CREATING),
        (S.CREATING, S.STARTED),
        (S.STARTED, S.STOPPING),
        (S.STOPPING, S.STOPPED),
        (S.STOPPED, S.STARTING),
        (S.STARTING, S.STARTED),
        (S.CREATING, S.ERROR),
        (S.STARTING, S.ERROR),
        (S.STOPPING, S.ERROR),
        (S.DESTROYING, S.DESTROYED),
    }
    non_terminal = [state for state in SandboxState if state not in (S.DESTROYING, S.DESTROYED)]
    to_destroying = {(state, S.DESTROYING) for state in non_terminal}
    actual = {(source, target) for source, targets in TRANSITIONS.items() for target in targets}
    assert actual == explicit | to_destroying
    assert set(TRANSITIONS) == set(SandboxState)
    assert TRANSITIONS[S.DESTROYED] == frozenset()


def test_lifecycle_assert_transition() -> None:
    assert_transition(S.PENDING, S.CREATING)
    assert can_transition(S.STARTED, S.DESTROYING)
    with pytest.raises(IllegalTransition):
        assert_transition(S.STOPPED, S.STARTED)
    with pytest.raises(IllegalTransition):
        assert_transition(S.DESTROYED, S.PENDING)


@pytest.mark.parametrize(
    ("factory", "prefix"),
    [
        (ids.new_sandbox_id, "sbx"),
        (ids.new_org_id, "org"),
        (ids.new_api_key_id, "key"),
        (ids.new_snapshot_id, "snap"),
        (ids.new_volume_id, "vol"),
        (ids.new_job_id, "job"),
        (ids.new_event_id, "evt"),
    ],
)
def test_ids_have_prefix_and_fit_column(factory: Callable[[], str], prefix: str) -> None:
    value = factory()
    assert value.startswith(prefix + "_")
    assert len(value) <= ids.MAX_ID_LENGTH
    assert ids.parse_id(value)[0] == prefix
    assert ids.has_prefix(value, prefix)


def test_ids_sort_by_time_and_reject_garbage() -> None:
    earlier = ids.new_id(ids.SANDBOX, now_ms=1_000)
    later = ids.new_id(ids.SANDBOX, now_ms=2_000)
    assert earlier < later
    assert ids.new_sandbox_id() != ids.new_sandbox_id()
    with pytest.raises(ValueError):
        ids.parse_id("nope_123")
    with pytest.raises(ValueError):
        ids.new_id("bogus")


def test_frozen_clock() -> None:
    clock = FrozenClock(datetime(2026, 5, 1, 12, 0, tzinfo=UTC))
    assert clock.now() == clock.now()
    clock.advance(timedelta(minutes=15))
    assert clock.now() == datetime(2026, 5, 1, 12, 15, tzinfo=UTC)
    with pytest.raises(ValueError):
        FrozenClock(datetime(2026, 1, 1))


def test_envelope_shape() -> None:
    success = ok({"id": "sbx_1"}, meta=Meta(next_cursor="abc")).model_dump()
    assert set(success) == {"success", "data", "error", "meta"}
    assert success["success"] is True
    assert success["data"] == {"id": "sbx_1"}
    assert success["error"] is None
    assert success["meta"] == {"next_cursor": "abc"}

    failure = fail("NOT_FOUND", "no such sandbox", request_id="req-1").model_dump()
    assert set(failure) == {"success", "data", "error", "meta"}
    assert failure["success"] is False
    assert failure["data"] is None
    assert failure["error"] == {
        "code": "NOT_FOUND",
        "message": "no such sandbox",
        "details": {},
        "request_id": "req-1",
    }


def test_error_taxonomy_codes_and_statuses() -> None:
    assert (NotFound.code, NotFound.status) == ("NOT_FOUND", 404)
    assert (QuotaExceeded.code, QuotaExceeded.status) == ("QUOTA_EXCEEDED", 429)
    assert NotFound("x", details={"id": "1"}).details == {"id": "1"}


def test_settings_from_env_and_reserved_prefix() -> None:
    settings = Settings.from_env({"SANDFORT_PORT": "9000", "SANDFORT_DRIVER": "fake"})
    assert (settings.port, settings.driver) == (9000, "fake")
    assert Settings.from_env({}).port == 8000
    with pytest.raises(ValueError):
        Settings.from_env({"SANDFORT_PORT": "abc"})
    assert is_reserved_env_name("sandfort_database_url")
    assert not is_reserved_env_name("PATH")
