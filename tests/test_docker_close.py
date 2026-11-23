"""Driver shutdown (docs/driver-offload-design.md, "Shutdown" and delivery slice six).

``DockerDriver.aclose`` is idempotent, kills the live terminals, refuses new lane calls with
``DriverError``, waits for the running calls to return their tokens and closes the docker-py
client. The api lifespan calls it on the raw driver after the workers stop and before the
engine is disposed, and skips a driver that has no ``aclose``.

No docker daemon: only in-process fakes, gated threads and local socket pairs.
"""

import asyncio
import logging
import socket
import threading
import time
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI

from sandfort.api.app import _serve_lifespan
from sandfort.api.deps import DRIVER_ATTR
from sandfort.api.wiring import ENGINE_ATTR, JOB_RUNNER_ATTR
from sandfort.config import Settings
from sandfort.drivers.docker import lanes
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.errors import DriverError

WAIT_S = 5.0  # generous upper bound for anything that must happen
POLL_S = 0.005
SETTLE_S = 0.15  # long enough for a closing driver that could finish to have finished
THREAD_TIMEOUT_S = 10.0  # a gate nobody opens frees its thread after this
DRAIN_TIMEOUT_S = 0.2  # shortened ``lanes.CLOSE_TIMEOUT_S`` for the timeout case

REF = "abc123"
INSPECT_ATTRS: dict[str, Any] = {
    "Id": REF,
    "Name": "/sf-sbx_1",
    "Created": "2026-10-30T12:00:00.123456789Z",
    "State": {"Status": "running", "Running": True, "Paused": False},
    "Config": {"Image": "alpine:3.20", "Labels": None},
    "HostConfig": {},
}
CLOSE_ORDER = [
    "workers.start",
    "serving",
    "workers.stop",
    "driver.aclose",
    "engine.dispose",
]


class Gate:
    """A blocking fake: ``enter`` parks its thread until ``release``, and is counted."""

    def __init__(self) -> None:
        self._open = threading.Event()
        self._lock = threading.Lock()
        self._entered = 0

    def enter(self) -> None:
        with self._lock:
            self._entered += 1
        if not self._open.wait(THREAD_TIMEOUT_S):
            raise TimeoutError("gate was never released")

    @property
    def entered(self) -> int:
        with self._lock:
            return self._entered

    def release(self) -> None:
        self._open.set()


class FakeClient:
    """A docker-py stand-in that records terminal kills and client closes."""

    def __init__(
        self, gate: Gate | None = None, socks: list[socket.socket] | None = None
    ) -> None:
        self._gate = gate
        self._socks = list(socks or [])
        self.exec_creates: list[dict[str, Any]] = []
        self.closed = 0
        self.api = SimpleNamespace(
            inspect_container=self._inspect,
            start=lambda ref: None,
            exec_create=self._exec_create,
            exec_start=self._exec_start,
            exec_resize=lambda *_, **__: None,
            exec_inspect=lambda exec_id: {"Running": True},
        )

    def _inspect(self, ref: str) -> dict[str, Any]:
        if self._gate is not None:
            self._gate.enter()
        return INSPECT_ATTRS

    def _exec_create(self, ref: str, **kwargs: Any) -> dict[str, str]:
        self.exec_creates.append(kwargs)
        return {"Id": f"exec{len(self.exec_creates)}"}

    def _exec_start(self, exec_id: str, **kwargs: Any) -> socket.socket | None:
        return self._socks.pop(0) if kwargs.get("socket") else None

    def close(self) -> None:
        self.closed += 1

    def kills(self) -> list[dict[str, Any]]:
        """The exec_create calls that are kill scripts: terminals are created with a tty."""
        return [kwargs for kwargs in self.exec_creates if "tty" not in kwargs]


@pytest.fixture(autouse=True)
def default_lanes() -> Iterator[None]:
    lanes.configure_thread_limit()
    yield
    lanes.configure_thread_limit()  # also reopens lanes that a test closed


@pytest.fixture
def gate() -> Iterator[Gate]:
    made = Gate()
    yield made
    made.release()


def borrowed() -> tuple[int, int]:
    """Borrowed tokens as ``(bulk, total)``."""
    return lanes.bulk_limiter().borrowed_tokens, lanes.total_limiter().borrowed_tokens


async def wait_for(predicate: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + WAIT_S
    while not predicate():
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        await asyncio.sleep(POLL_S)


async def wait_until_idle() -> None:
    await wait_for(lambda: borrowed() == (0, 0), "every token to be freed")


# --- aclose on the driver --------------------------------------------------------------


async def test_aclose_is_idempotent() -> None:
    client = FakeClient()
    driver = DockerDriver(Settings(), client=client)

    await driver.aclose()
    await driver.aclose()
    await asyncio.gather(driver.aclose(), driver.aclose())

    assert client.closed == 1  # the client was closed once, by the first call
    assert borrowed() == (0, 0)


async def test_aclose_tolerates_a_client_without_close() -> None:
    driver = DockerDriver(Settings(), client=SimpleNamespace(api=SimpleNamespace()))

    await driver.aclose()

    assert borrowed() == (0, 0)


async def test_aclose_kills_every_live_terminal() -> None:
    first_reader, first_peer = socket.socketpair()
    second_reader, second_peer = socket.socketpair()
    client = FakeClient(socks=[first_reader, second_reader])
    driver = DockerDriver(Settings(), client=client)
    first = await driver.create_pty(REF, ["sh"], {}, 24, 80)
    second = await driver.create_pty(REF, ["sh"], {}, 24, 80)
    try:
        assert client.kills() == []

        await driver.aclose()

        assert len(client.kills()) == 2  # one kill script per terminal
        assert first_reader.fileno() == -1  # the hijacked sockets were dropped
        assert second_reader.fileno() == -1
        for handle in (first, second):
            with pytest.raises(DriverError):
                await driver.read_pty(handle)  # the handle no longer resolves
            await driver.close_pty(handle)  # and closing it again is a no-op
        assert len(client.kills()) == 2
        assert client.closed == 1
        assert borrowed() == (0, 0)
    finally:
        first_peer.close()
        second_peer.close()


async def test_calls_after_close_raise_the_driver_error() -> None:
    driver = DockerDriver(Settings(), client=FakeClient())
    await driver.aclose()

    with pytest.raises(DriverError, match=lanes.CLOSED_MESSAGE):
        await driver.inspect(REF)
    with pytest.raises(DriverError, match=lanes.CLOSED_MESSAGE):
        await driver.start(REF)
    with pytest.raises(DriverError, match=lanes.CLOSED_MESSAGE):
        await driver.create_pty(REF, ["sh"], {}, 24, 80)
    with pytest.raises(DriverError, match=lanes.CLOSED_MESSAGE):
        await lanes.run_blocking(lambda: None)  # the control lane
    with pytest.raises(DriverError, match=lanes.CLOSED_MESSAGE):
        await lanes.run_bulk(lambda: None)  # the bulk lane
    assert borrowed() == (0, 0)  # a refused call takes no token


async def test_aclose_waits_for_a_running_call_before_closing_the_client(gate: Gate) -> None:
    client = FakeClient(gate=gate)
    driver = DockerDriver(Settings(), client=client)
    running = asyncio.create_task(driver.inspect(REF))
    await wait_for(lambda: gate.entered == 1, "the call to park")

    closing = asyncio.create_task(driver.aclose())
    await asyncio.sleep(SETTLE_S)
    try:
        assert not closing.done()  # draining: the call still holds its token
        assert client.closed == 0
        with pytest.raises(DriverError, match=lanes.CLOSED_MESSAGE):
            await driver.inspect(REF)  # new calls are refused while it drains
    finally:
        gate.release()
    await asyncio.wait_for(closing, WAIT_S)

    assert (await running).ref == REF  # the running call finished against the open client
    assert client.closed == 1
    assert borrowed() == (0, 0)


async def test_aclose_continues_after_the_drain_timeout(
    gate: Gate, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(lanes, "CLOSE_TIMEOUT_S", DRAIN_TIMEOUT_S)
    client = FakeClient(gate=gate)
    driver = DockerDriver(Settings(), client=client)
    running = asyncio.create_task(driver.inspect(REF))
    await wait_for(lambda: gate.entered == 1, "the call to park")

    with caplog.at_level(logging.WARNING):
        await asyncio.wait_for(driver.aclose(), WAIT_S)

    assert client.closed == 1  # it moved on and closed the client anyway
    assert any("still borrowed" in record.getMessage() for record in caplog.records)
    assert borrowed() == (0, 1)  # the stuck control call still holds its one token
    gate.release()
    assert (await running).ref == REF
    await wait_until_idle()


async def test_a_call_queued_when_the_driver_closes_is_refused(gate: Gate) -> None:
    settings = Settings(docker_thread_limit=1, docker_bulk_threads=1)
    client = FakeClient(gate=gate)
    driver = DockerDriver(settings, client=client)
    running = asyncio.create_task(driver.inspect(REF))
    await wait_for(lambda: gate.entered == 1, "the call to park")
    queued = asyncio.create_task(driver.inspect(REF))  # waits for the one total token
    await asyncio.sleep(SETTLE_S)
    closing = asyncio.create_task(driver.aclose())
    await asyncio.sleep(SETTLE_S)
    gate.release()

    with pytest.raises(DriverError, match=lanes.CLOSED_MESSAGE):
        await asyncio.wait_for(queued, WAIT_S)
    await asyncio.wait_for(closing, WAIT_S)

    assert (await running).ref == REF
    assert gate.entered == 1  # the queued call never reached the client
    assert borrowed() == (0, 0)


async def test_a_driver_built_after_a_close_has_open_lanes() -> None:
    first = DockerDriver(Settings(), client=FakeClient())
    await first.aclose()

    second = DockerDriver(Settings(), client=FakeClient())

    assert (await second.inspect(REF)).ref == REF
    await second.aclose()


# --- the lifespan order ----------------------------------------------------------------


class StubWorker:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def start(self) -> None:
        self._events.append("workers.start")

    async def stop(self) -> None:
        self._events.append("workers.stop")


class StubEngine:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def dispose(self) -> None:
        self._events.append("engine.dispose")


class RecordingDriver:
    """A driver whose only member is a recording ``aclose``."""

    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def aclose(self) -> None:
        self._events.append("driver.aclose")


class FailingCloseDriver(RecordingDriver):
    async def aclose(self) -> None:
        await super().aclose()
        raise RuntimeError("close blew up")


class DriverWithoutAclose:
    """What the fake driver and third-party entry points look like to the lifespan."""


def lifespan_app(events: list[str], driver: object) -> FastAPI:
    """An app whose state holds stubs only; a single worker (the job runner) is enabled."""
    app = FastAPI()
    app.state.settings = Settings(
        job_execution_enabled=True,
        autostop_enabled=False,
        reconcile_enabled=False,
        gc_enabled=False,
        webhook_dispatcher_enabled=False,
        metering_enabled=False,
        audit_retention_days=0,
        node_heartbeat_enabled=False,
    )
    setattr(app.state, ENGINE_ATTR, StubEngine(events))
    setattr(app.state, DRIVER_ATTR, driver)
    setattr(app.state, JOB_RUNNER_ATTR, StubWorker(events))
    return app


async def test_lifespan_closes_the_driver_after_the_workers_and_before_the_engine() -> None:
    events: list[str] = []
    app = lifespan_app(events, RecordingDriver(events))

    async with _serve_lifespan(app, with_workers=True):
        events.append("serving")

    assert events == CLOSE_ORDER


async def test_lifespan_skips_a_driver_without_aclose() -> None:
    events: list[str] = []
    app = lifespan_app(events, DriverWithoutAclose())

    async with _serve_lifespan(app, with_workers=True):
        events.append("serving")

    assert events == [name for name in CLOSE_ORDER if name != "driver.aclose"]


async def test_lifespan_disposes_the_engine_when_the_driver_close_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    events: list[str] = []
    app = lifespan_app(events, FailingCloseDriver(events))

    with caplog.at_level(logging.ERROR):
        async with _serve_lifespan(app, with_workers=True):
            events.append("serving")

    assert events == CLOSE_ORDER  # the failed close did not skip the engine
    assert any("driver close failed" in record.getMessage() for record in caplog.records)
