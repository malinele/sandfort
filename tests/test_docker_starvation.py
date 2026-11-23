"""Streams run in the bulk lane, so they cannot starve control calls (offload design, slice 4).

Gate of the design: lanes are sized total 4 and bulk 3. Four log followers are parked on a
gated fake response; the bulk lane holds three of them and the fourth queues. A short control
call (``inspect``) must still complete within ``CONTROL_DEADLINE_S``. On the old routing every
stream read used ``run_blocking``, the four followers took all four tokens and the control
call never got one.

The remaining tests pin the routing of each other stream operation the design assigns to the
bulk lane: a parked exec poll, pty read, pty write, upload and download chunk read each hold
one bulk token and one total token.

Slice five adds the long unary calls: with the bulk lane full of parked image pulls, ``inspect``
and ``start`` still complete within the same bound, and a parked pull (also the one inside
create), commit, flatten, image remove, volume ``df`` and build progress read each hold one bulk
token and one total token.

No docker daemon: only in-process fakes, gated threads and local socket pairs.
"""

import asyncio
import socket
import struct
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.drivers.base import ExecEvent, ExecRequest, ExitEvent, LogEntry, OutputChunk
from sandfort.drivers.docker import lanes
from sandfort.drivers.docker.containers import _create_pulling_missing
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.errors import DriverConflict

TOTAL_THREADS = 4
BULK_THREADS = 3
FOLLOWERS = TOTAL_THREADS  # one more than the bulk lane can hold

WAIT_S = 5.0  # generous upper bound for anything that must happen
POLL_S = 0.005
SETTLE_S = 0.1  # long enough for a follower that could take a token to have taken it
CONTROL_DEADLINE_S = 1.0  # the design's bound for a control call under a saturated bulk lane
THREAD_TIMEOUT_S = 10.0  # a gate nobody opens frees its thread after this
WRITE_BYTES = 8 * 1024 * 1024  # far more than a socket pair buffers, so sendall blocks

REF = "abc123"
BULK_AND_TOTAL = (1, 1)
INSPECT_ATTRS: dict[str, Any] = {
    "Id": REF,
    "Name": "/sf-sbx_1",
    "Created": "2026-10-30T12:00:00.123456789Z",
    "State": {"Status": "running", "Running": True, "Paused": False},
    "Config": {"Image": "alpine:3.20", "Labels": None},
    "HostConfig": {},
}
IMAGE_REFERENCE = "alpine:3.20"
IMAGE_ID = "sha256:img1"
IMAGE_DIGEST = "sha256:abc"
IMAGE_ATTRS: dict[str, Any] = {
    "Id": IMAGE_ID,
    "Size": 10,
    "RootFS": {"Layers": ["layer1"]},
    "RepoDigests": [f"alpine@{IMAGE_DIGEST}"],
}


class Gate:
    """A blocking fake: each ``enter`` parks its thread until ``release``, and is counted."""

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

    def shutdown(self, how: int) -> None:
        """What ``_LogStream.wake`` calls on the socket: unpark the reader."""
        self.release()

    def read(self, size: int) -> bytes:
        """``response.raw.read`` of a quiet follow stream: parks, then reports EOF."""
        self.enter()
        return b""


class GatedDownload:
    """The iterator docker-py returns for an archive download or a build log; it parks first."""

    def __init__(self, gate: Gate) -> None:
        self._gate = gate

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        self._gate.enter()
        raise StopIteration


@pytest.fixture(autouse=True)
def default_lanes() -> Iterator[None]:
    lanes.configure_thread_limit()
    yield
    lanes.configure_thread_limit()


@pytest.fixture
def gate() -> Iterator[Gate]:
    made = Gate()
    yield made
    made.release()


def small_lane_settings() -> Settings:
    return Settings(docker_thread_limit=TOTAL_THREADS, docker_bulk_threads=BULK_THREADS)


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


def frame(stream_kind: int, payload: bytes) -> bytes:
    """One docker multiplexed frame: 8-byte header (kind, size) plus the payload."""
    return struct.pack(">BxxxI", stream_kind, len(payload)) + payload


def make_logs_client(gate: Gate) -> SimpleNamespace:
    response = SimpleNamespace(raw=SimpleNamespace(read=gate.read), close=lambda: None)
    return SimpleNamespace(
        api=SimpleNamespace(
            _get=lambda url, **_: response,
            _url=lambda path, *_: path,
            _raise_for_status=lambda resp: None,
            _get_raw_response_socket=lambda resp: gate,
            _disable_socket_timeout=lambda held: None,
            inspect_container=lambda ref: INSPECT_ATTRS,
        )
    )


def make_exec_client(sock: socket.socket) -> SimpleNamespace:
    return SimpleNamespace(
        api=SimpleNamespace(
            exec_create=lambda ref, **_: {"Id": "exec1"},
            exec_start=lambda exec_id, **_: sock,
            exec_inspect=lambda exec_id: {"Running": False, "ExitCode": 0},
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


def make_download_client(gate: Gate) -> SimpleNamespace:
    def get_archive(ref: str, path: str, chunk_size: int) -> tuple[GatedDownload, dict[str, int]]:
        return GatedDownload(gate), {"size": 1}

    return SimpleNamespace(api=SimpleNamespace(get_archive=get_archive))


async def follow(driver: DockerDriver) -> list[LogEntry]:
    return [entry async for entry in driver.stream_logs(REF, follow=True)]


async def collect(events: AsyncIterator[ExecEvent]) -> list[ExecEvent]:
    return [event async for event in events]


async def drain(chunks: AsyncIterator[bytes]) -> list[bytes]:
    return [chunk async for chunk in chunks]


# --- the gate of the design: a saturated bulk lane leaves the control lane alive ------


async def test_parked_log_followers_leave_a_token_for_a_control_call(gate: Gate) -> None:
    driver = DockerDriver(small_lane_settings(), client=make_logs_client(gate))
    followers = [asyncio.create_task(follow(driver)) for _ in range(FOLLOWERS)]
    try:
        await wait_for(lambda: gate.entered >= BULK_THREADS, "the followers to park in recv")
        await asyncio.sleep(SETTLE_S)  # the fourth follower had time to take a token if it could

        info = await asyncio.wait_for(driver.inspect(REF), CONTROL_DEADLINE_S)

        assert info.ref == REF
        assert gate.entered == BULK_THREADS  # the bulk lane is full, the fourth follower queues
        assert borrowed() == (BULK_THREADS, BULK_THREADS)
    finally:
        gate.release()
        results = await asyncio.gather(*followers, return_exceptions=True)
    assert results == [[]] * FOLLOWERS  # every follower ended cleanly at EOF
    await wait_until_idle()


# --- routing pins: each stream operation of the bulk lane holds a bulk token ----------


async def test_log_follow_read_holds_a_bulk_token(gate: Gate) -> None:
    driver = DockerDriver(Settings(), client=make_logs_client(gate))
    follower = asyncio.create_task(follow(driver))
    try:
        await wait_for(lambda: gate.entered == 1, "the follower to park in recv")
        assert borrowed() == BULK_AND_TOTAL
    finally:
        gate.release()
    assert await follower == []
    await wait_until_idle()


async def test_exec_output_poll_holds_a_bulk_token() -> None:
    reader, peer = socket.socketpair()
    driver = DockerDriver(Settings(), client=make_exec_client(reader))
    run = asyncio.create_task(collect(driver.exec_stream(REF, ExecRequest(argv=["true"]))))
    try:
        await wait_for(lambda: borrowed() == BULK_AND_TOTAL, "an exec poll to hold a bulk token")
        peer.sendall(frame(1, b"out"))
        peer.shutdown(socket.SHUT_WR)
        events = await asyncio.wait_for(run, WAIT_S)
    finally:
        run.cancel()
        peer.close()
        reader.close()
    assert events[0] == OutputChunk("stdout", b"out")
    assert isinstance(events[-1], ExitEvent)
    await wait_until_idle()


async def test_pty_read_poll_holds_a_bulk_token() -> None:
    reader, peer = socket.socketpair()
    driver = DockerDriver(Settings(), client=make_pty_client(reader))
    handle = await driver.create_pty(REF, ["sh"], {}, 24, 80)
    read = asyncio.create_task(driver.read_pty(handle))
    try:
        await wait_for(lambda: borrowed() == BULK_AND_TOTAL, "a pty poll to hold a bulk token")
        peer.sendall(b"hi")
        assert await asyncio.wait_for(read, WAIT_S) == b"hi"
    finally:
        read.cancel()
        await driver.close_pty(handle)
        peer.close()
        reader.close()
    await wait_until_idle()


async def test_pty_write_blocked_on_a_full_socket_holds_a_bulk_token() -> None:
    reader, peer = socket.socketpair()
    driver = DockerDriver(Settings(), client=make_pty_client(reader))
    handle = await driver.create_pty(REF, ["sh"], {}, 24, 80)
    write = asyncio.create_task(driver.write_pty(handle, bytes(WRITE_BYTES)))
    try:
        await wait_for(lambda: borrowed() == BULK_AND_TOTAL, "sendall to block on a full socket")
    finally:
        peer.close()  # the blocked sendall fails, which frees its thread
    with pytest.raises(DriverConflict):
        await asyncio.wait_for(write, WAIT_S)
    await driver.close_pty(handle)
    reader.close()
    await wait_until_idle()


async def test_archive_upload_holds_a_bulk_token_for_its_whole_duration(gate: Gate) -> None:
    def put_archive(ref: str, dest_path: str, source: Any) -> bool:
        gate.enter()
        return True

    async def tar_chunks() -> AsyncIterator[bytes]:
        yield b"tar"

    client = SimpleNamespace(api=SimpleNamespace(put_archive=put_archive))
    driver = DockerDriver(Settings(), client=client)
    upload = asyncio.create_task(driver.put_archive(REF, "/work", tar_chunks()))
    try:
        await wait_for(lambda: gate.entered == 1, "the upload to park")
        assert borrowed() == BULK_AND_TOTAL
    finally:
        gate.release()
    await upload
    await wait_until_idle()


async def test_archive_download_chunk_read_holds_a_bulk_token(gate: Gate) -> None:
    driver = DockerDriver(Settings(), client=make_download_client(gate))
    _, chunks = await driver.get_archive_with_stat(REF, "/work")
    assert borrowed() == (0, 0)  # opening the download was a control call and has finished
    download = asyncio.create_task(drain(chunks))
    try:
        await wait_for(lambda: gate.entered == 1, "the chunk read to park")
        assert borrowed() == BULK_AND_TOTAL
    finally:
        gate.release()
    assert await download == []
    await wait_until_idle()


# --- slice five: long unary calls run in the bulk lane --------------------------------


def gated[T](gate: Gate, value: T) -> Callable[..., T]:
    """A fake docker-py method that parks on ``gate`` and then returns ``value``."""

    def call(*_: Any, **__: Any) -> T:
        gate.enter()
        return value

    return call


def make_image_client(gate: Gate) -> SimpleNamespace:
    """A fake client whose long unary calls park on ``gate``; the short ones answer at once."""
    return SimpleNamespace(
        images=SimpleNamespace(pull=gated(gate, SimpleNamespace(attrs=IMAGE_ATTRS))),
        api=SimpleNamespace(
            inspect_container=lambda ref: INSPECT_ATTRS,
            inspect_image=lambda ref: IMAGE_ATTRS,
            inspect_volume=lambda ref: {"Name": "vol1"},
            start=lambda ref: None,
            pause=lambda ref: None,
            unpause=lambda ref: None,
            commit=gated(gate, {"Id": IMAGE_ID}),
            export=lambda ref: iter(()),
            import_image=gated(gate, None),
            remove_image=gated(gate, None),
            df=gated(gate, {"Volumes": []}),
            build=lambda **_: GatedDownload(gate),
        ),
    )


async def hold_a_bulk_token[T](gate: Gate, call: Awaitable[T]) -> T:
    """Run ``call`` until it parks in ``gate``, pin its tokens, then let it finish."""
    task = asyncio.ensure_future(call)
    try:
        await wait_for(lambda: gate.entered == 1, "the call to park")
        assert borrowed() == BULK_AND_TOTAL
    finally:
        gate.release()
    result = await asyncio.wait_for(task, WAIT_S)
    await wait_until_idle()
    return result


async def test_parked_pulls_leave_a_token_for_inspect_and_start(gate: Gate) -> None:
    driver = DockerDriver(small_lane_settings(), client=make_image_client(gate))
    pulls = [
        asyncio.create_task(driver.pull_image_digest(IMAGE_REFERENCE)) for _ in range(TOTAL_THREADS)
    ]
    try:
        await wait_for(lambda: gate.entered >= BULK_THREADS, "the pulls to park")
        await asyncio.sleep(SETTLE_S)  # the fourth pull had time to take a token if it could

        info = await asyncio.wait_for(driver.inspect(REF), CONTROL_DEADLINE_S)
        await asyncio.wait_for(driver.start(REF), CONTROL_DEADLINE_S)

        assert info.ref == REF
        assert gate.entered == BULK_THREADS  # the bulk lane is full, the fourth pull queues
        assert borrowed() == (BULK_THREADS, BULK_THREADS)
    finally:
        gate.release()
        results = await asyncio.gather(*pulls, return_exceptions=True)
    assert results == [IMAGE_DIGEST] * TOTAL_THREADS  # every pull finished with its digest
    await wait_until_idle()


async def test_image_pull_holds_a_bulk_token(gate: Gate) -> None:
    driver = DockerDriver(Settings(), client=make_image_client(gate))
    info = await hold_a_bulk_token(gate, driver.pull_image(IMAGE_REFERENCE))
    assert (info.ref, info.digest) == (IMAGE_REFERENCE, IMAGE_ID)


async def test_pull_inside_create_holds_a_bulk_token_and_runs_once(gate: Gate) -> None:
    errors = pytest.importorskip("docker.errors")
    container = SimpleNamespace(attrs=INSPECT_ATTRS)
    outcomes: list[Any] = [errors.ImageNotFound("missing"), container]
    created_from: list[str] = []

    def create(image: str, **_: Any) -> Any:
        created_from.append(image)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    client = SimpleNamespace(
        containers=SimpleNamespace(create=create),
        images=SimpleNamespace(pull=gated(gate, None)),
    )
    created = await hold_a_bulk_token(gate, _create_pulling_missing(client, IMAGE_REFERENCE, {}))
    assert created is container
    assert created_from == [IMAGE_REFERENCE] * 2  # the failed create, then the retry
    assert gate.entered == 1  # exactly one pull


async def test_container_commit_holds_a_bulk_token(gate: Gate) -> None:
    driver = DockerDriver(Settings(), client=make_image_client(gate))
    result = await hold_a_bulk_token(gate, driver.commit_container(REF, "snap:1"))
    assert (result.digest, result.layer_count) == (IMAGE_ID, 1)


async def test_container_flatten_export_import_holds_a_bulk_token(gate: Gate) -> None:
    driver = DockerDriver(Settings(), client=make_image_client(gate))
    result = await hold_a_bulk_token(gate, driver.flatten_container(REF, "snap:1"))
    assert (result.digest, result.layer_count) == (IMAGE_ID, 1)


async def test_image_remove_holds_a_bulk_token(gate: Gate) -> None:
    driver = DockerDriver(Settings(), client=make_image_client(gate))
    await hold_a_bulk_token(gate, driver.remove_image(IMAGE_REFERENCE))


async def test_volume_disk_usage_holds_a_bulk_token(gate: Gate) -> None:
    driver = DockerDriver(Settings(), client=make_image_client(gate))
    info = await hold_a_bulk_token(gate, driver.inspect_volume("vol1"))
    assert info == {"name": "vol1", "ref": "vol1", "labels": {}}  # df knew no size


async def test_build_progress_read_holds_a_bulk_token(gate: Gate) -> None:
    driver = DockerDriver(Settings(), client=make_image_client(gate))
    handle = await driver.start_build(
        {"Dockerfile": b"FROM alpine"}, "snap:1", cpu_millicores=1000, memory_mib=256, timeout_s=30
    )
    digest = await hold_a_bulk_token(gate, handle.result())
    assert digest == IMAGE_ID
