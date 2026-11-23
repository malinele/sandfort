"""The event loop stays responsive while a slow docker call runs (offload design, slice 1).

Technique (docs/driver-offload-design.md, section "Gates"): ``DockerDriver`` takes an injected
client, so the tests hand it a slow fake. Its methods either call ``time.sleep`` or block in
``select``/``recv`` on a ``socket.socketpair()`` that a helper thread feeds late. A ticker
task records the largest gap between its ``asyncio.sleep`` wake-ups while the driver call
runs; the assertion is that the gap stays under ``LAG_BOUND_S``.

The negative controls call the same slow method directly on the loop. One asserts the ticker
sees a lag of at least ``CONTROL_MIN_LAG_S``, so the probe is proven able to fail. The other
asserts the responsiveness bound itself and is marked ``xfail(strict=True)``: the suite stays
green, and ``pytest --runxfail tests/test_docker_loop_responsive.py`` runs it on demand to
show the bound violated.

No docker daemon and no network: only in-process fakes and local socket pairs.
"""

import asyncio
import contextlib
import socket
import struct
import threading
import time
from collections.abc import AsyncIterator, Iterator
from types import SimpleNamespace
from typing import Any, Self

import pytest

from sandfort.config import Settings
from sandfort.drivers.base import ExecRequest, ExitEvent, OutputChunk
from sandfort.drivers.docker.driver import DockerDriver

SETTINGS = Settings()

SLOW_S = 0.3  # how long the fake docker call is slow
TICK_S = 0.005  # ticker period
LAG_BOUND_S = 0.1  # responsive: the largest ticker gap stays below this
CONTROL_MIN_LAG_S = 0.27  # blocking control: the ticker must see at least this much
SLOW_ENOUGH_S = 0.2  # the measured window really covered a slow call (generous: load-proof)
WARMUP_S = 0.02  # let the ticker record a few ticks before the call starts
SETTLE_S = 0.03  # let the ticker wake once more after the call, so a stall gets recorded
JOIN_TIMEOUT_S = 5.0

REF = "abc123"
INSPECT_ATTRS: dict[str, Any] = {
    "Id": REF,
    "Name": "/sf-sbx_1",
    "Created": "2026-10-30T12:00:00.123456789Z",
    "State": {"Status": "running", "Running": True, "Paused": False},
    "Config": {"Image": "alpine:3.20", "Labels": None},
    "HostConfig": {},
}
LOG_PAYLOAD = b"2026-11-02T10:00:00.000000000Z hello\n"


class LoopProbe:
    """Async context manager running a ticker task; ``max_gap`` is its largest wake-up gap."""

    def __init__(self) -> None:
        self.max_gap = 0.0
        self.busy_s = 0.0
        self._began = 0.0
        self._task: asyncio.Task[None] | None = None

    async def _tick(self) -> None:
        last = time.perf_counter()
        while True:
            await asyncio.sleep(TICK_S)
            now = time.perf_counter()
            self.max_gap = max(self.max_gap, now - last)
            last = now

    async def __aenter__(self) -> Self:
        self._task = asyncio.ensure_future(self._tick())
        await asyncio.sleep(WARMUP_S)
        self._began = time.perf_counter()
        return self

    async def __aexit__(self, *_: object) -> None:
        self.busy_s = time.perf_counter() - self._began
        await asyncio.sleep(SETTLE_S)
        assert self._task is not None
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task


def assert_responsive(probe: LoopProbe) -> None:
    assert probe.busy_s >= SLOW_ENOUGH_S, f"the call was not slow ({probe.busy_s:.3f}s)"
    assert probe.max_gap < LAG_BOUND_S, f"event loop stalled for {probe.max_gap:.3f}s"


@contextlib.contextmanager
def slow_peer(data: bytes) -> Iterator[socket.socket]:
    """A socket that receives ``data`` after ``SLOW_S`` and then reaches EOF."""
    reader, writer = socket.socketpair()

    def feed() -> None:
        time.sleep(SLOW_S)
        with contextlib.suppress(OSError):
            writer.sendall(data)
            writer.shutdown(socket.SHUT_WR)

    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    try:
        yield reader
    finally:
        feeder.join(timeout=JOIN_TIMEOUT_S)
        reader.close()
        writer.close()


def frame(stream_kind: int, payload: bytes) -> bytes:
    """One docker multiplexed frame: 8-byte header (kind, size) plus the payload."""
    return struct.pack(">BxxxI", stream_kind, len(payload)) + payload


def make_unary_client() -> SimpleNamespace:
    def inspect_container(ref: str) -> dict[str, Any]:
        time.sleep(SLOW_S)
        return INSPECT_ATTRS

    return SimpleNamespace(api=SimpleNamespace(inspect_container=inspect_container))


def make_exec_client(sock: socket.socket) -> SimpleNamespace:
    return SimpleNamespace(
        api=SimpleNamespace(
            exec_create=lambda ref, **_: {"Id": "exec1"},
            exec_start=lambda exec_id, **_: sock,
            exec_inspect=lambda exec_id: {"Running": False, "ExitCode": 0},
        )
    )


def make_logs_client(sock: socket.socket) -> SimpleNamespace:
    response = SimpleNamespace(raw=SimpleNamespace(read=sock.recv), close=lambda: None)
    return SimpleNamespace(
        api=SimpleNamespace(
            _get=lambda url, **_: response,
            _url=lambda path, *_: path,
            _raise_for_status=lambda resp: None,
            _get_raw_response_socket=lambda resp: sock,
            _disable_socket_timeout=lambda held: None,
        )
    )


def make_pty_client(sock: socket.socket) -> SimpleNamespace:
    return SimpleNamespace(
        api=SimpleNamespace(
            exec_create=lambda ref, **_: {"Id": "pty1"},
            exec_start=lambda exec_id, **_: sock,
            exec_resize=lambda *_, **__: None,
            exec_inspect=lambda exec_id: {"Running": False},
        )
    )


# --- the property: a slow docker call never stalls the loop --------------------------


async def test_unary_call_keeps_the_loop_responsive() -> None:
    driver = DockerDriver(SETTINGS, client=make_unary_client())
    async with LoopProbe() as probe:
        info = await driver.inspect(REF)
    assert info.ref == REF
    assert_responsive(probe)


async def test_exec_stream_keeps_the_loop_responsive() -> None:
    with slow_peer(frame(1, b"hello\n")) as sock:
        driver = DockerDriver(SETTINGS, client=make_exec_client(sock))
        async with LoopProbe() as probe:
            events = [e async for e in driver.exec_stream(REF, ExecRequest(argv=["true"]))]
    assert events[0] == OutputChunk("stdout", b"hello\n")
    assert isinstance(events[-1], ExitEvent)
    assert events[-1].exit_code == 0
    assert_responsive(probe)


async def test_log_follow_keeps_the_loop_responsive() -> None:
    with slow_peer(frame(1, LOG_PAYLOAD)) as sock:
        driver = DockerDriver(SETTINGS, client=make_logs_client(sock))
        async with LoopProbe() as probe:
            entries = [entry async for entry in driver.stream_logs(REF, follow=True)]
    assert [(entry.stream, entry.line) for entry in entries] == [("stdout", "hello")]
    assert_responsive(probe)


async def test_pty_read_keeps_the_loop_responsive() -> None:
    with slow_peer(b"hi") as sock:
        driver = DockerDriver(SETTINGS, client=make_pty_client(sock))
        async with LoopProbe() as probe:
            handle = await driver.create_pty(REF, ["sh"], {}, 24, 80)
            data = await driver.read_pty(handle)
        await driver.close_pty(handle)
    assert data == b"hi"
    assert_responsive(probe)


async def test_archive_upload_keeps_the_loop_responsive() -> None:
    received: list[bytes] = []

    def put_archive(ref: str, dest_path: str, source: Any) -> bool:
        received.extend(source)  # pulls each chunk from the loop through anyio.from_thread
        time.sleep(SLOW_S)
        return True

    async def tar_chunks() -> AsyncIterator[bytes]:
        yield b"tar-"
        yield b"data"

    client = SimpleNamespace(api=SimpleNamespace(put_archive=put_archive))
    driver = DockerDriver(SETTINGS, client=client)
    async with LoopProbe() as probe:
        await driver.put_archive(REF, "/work", tar_chunks())
    assert b"".join(received) == b"tar-data"
    assert_responsive(probe)


# --- negative controls: the same slow call made directly on the loop ----------------


async def test_control_probe_sees_a_blocking_call_on_the_loop() -> None:
    client = make_unary_client()
    async with LoopProbe() as probe:
        client.api.inspect_container(REF)  # no offload: blocks the loop for SLOW_S
    assert probe.max_gap >= CONTROL_MIN_LAG_S


@pytest.mark.xfail(
    strict=True,
    reason="negative control: a direct blocking call on the loop violates the lag bound",
)
async def test_control_blocking_call_on_the_loop_violates_the_bound() -> None:
    client = make_unary_client()
    async with LoopProbe() as probe:
        client.api.inspect_container(REF)  # no offload: blocks the loop for SLOW_S
    assert_responsive(probe)
