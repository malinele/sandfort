"""The docker container-exit watcher, its wiring and the reconciler's kick helper.

Unit tests drive the watcher with a fake docker client whose ``events`` returns scripted
streams; the last test (marked ``docker``, skipped without a daemon) uses the real daemon.
"""

import asyncio
import logging
import queue
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from types import SimpleNamespace
from typing import Any

import pytest

from sandfort.api.wiring import WatchedReconciler, docker_client_of
from sandfort.clock import SystemClock
from sandfort.drivers.docker import events as events_module
from sandfort.drivers.docker.events import THREAD_NAME, ContainerExitWatcher, die_filters
from sandfort.drivers.docker.labels import LABEL_MANAGED
from sandfort.workers import reconciler as reconciler_module

LOGGER_NAME = events_module.logger.name
FAST_BACKOFF_S = 0.01
WAIT_S = 3.0
STOP_BUDGET_S = 2.0
END = object()


def die_event(container_id: str = "c0ffee") -> dict[str, Any]:
    return {
        "Type": "container",
        "Action": "die",
        "id": container_id,
        "Actor": {"ID": container_id, "Attributes": {LABEL_MANAGED: "true"}},
        "time": 1_793_757_600,
    }


class FakeStream:
    """An iterable fed from a queue; ``close`` ends it, like closing a docker-py stream."""

    def __init__(self, items: tuple[Any, ...] = (), *, block: bool = False) -> None:
        self._queue: queue.Queue[Any] = queue.Queue()
        for item in items:
            self._queue.put(item)
        if not block:
            self._queue.put(END)
        self.closed = False

    def __iter__(self) -> "FakeStream":
        return self

    def __next__(self) -> Any:
        item = self._queue.get()
        if item is END:
            raise StopIteration
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        self.closed = True
        self._queue.put(END)


class FakeClient:
    """``events`` hands out the scripted streams in order, then streams that block."""

    def __init__(self, *streams: FakeStream | Exception) -> None:
        self._streams = list(streams)
        self.calls: list[dict[str, Any]] = []
        self.opened: list[FakeStream] = []

    def events(self, **kwargs: Any) -> FakeStream:
        self.calls.append(kwargs)
        scripted = self._streams.pop(0) if self._streams else FakeStream(block=True)
        if isinstance(scripted, Exception):
            raise scripted
        self.opened.append(scripted)
        return scripted


class Recorder:
    """A callback that notes the event and the loop/thread it ran on."""

    def __init__(self) -> None:
        self.events: list[Mapping[str, Any]] = []
        self.loops: list[asyncio.AbstractEventLoop] = []
        self.threads: list[threading.Thread] = []

    def __call__(self, event: Mapping[str, Any]) -> None:
        self.events.append(event)
        self.loops.append(asyncio.get_running_loop())
        self.threads.append(threading.current_thread())


async def wait_until(predicate: Callable[[], bool], timeout_s: float = WAIT_S) -> None:
    deadline = time.monotonic() + timeout_s
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.01)


def make_watcher(client: Any, callback: Callable[[Mapping[str, Any]], None]) -> Any:
    return ContainerExitWatcher(client, callback, backoff_s=FAST_BACKOFF_S)


async def test_managed_die_event_invokes_the_callback_on_the_loop() -> None:
    client = FakeClient(FakeStream((die_event("abc"),), block=True))
    recorder = Recorder()
    watcher = make_watcher(client, recorder)
    watcher.start()
    try:
        await wait_until(lambda: bool(recorder.events))
    finally:
        await watcher.stop()

    assert recorder.events[0]["id"] == "abc"
    assert recorder.loops[0] is asyncio.get_running_loop()
    assert recorder.threads[0] is threading.main_thread()


async def test_stream_is_opened_decoded_with_the_managed_die_filters() -> None:
    client = FakeClient()
    watcher = make_watcher(client, Recorder())
    watcher.start()
    try:
        await wait_until(lambda: bool(client.calls))
    finally:
        await watcher.stop()

    first = client.calls[0]
    assert first["decode"] is True
    assert first["filters"] == die_filters()
    assert first["filters"]["type"] == ["container"]
    assert first["filters"]["event"] == ["die"]
    assert first["filters"]["label"] == [f"{LABEL_MANAGED}=true"]
    assert "since" not in first


async def test_watcher_reconnects_after_the_stream_ends() -> None:
    client = FakeClient(FakeStream(), FakeStream((die_event("again"),), block=True))
    recorder = Recorder()
    watcher = make_watcher(client, recorder)
    watcher.start()
    try:
        await wait_until(lambda: bool(recorder.events))
    finally:
        await watcher.stop()

    assert len(client.calls) == 2
    assert recorder.events[0]["id"] == "again"
    assert "since" not in client.calls[0]
    assert isinstance(client.calls[1]["since"], int)  # exits during the gap are replayed


async def test_stop_ends_the_thread_promptly_and_closes_the_stream() -> None:
    client = FakeClient()  # one blocking stream: the thread sits in a read
    watcher = make_watcher(client, Recorder())
    watcher.start()
    await wait_until(lambda: bool(client.opened))
    thread = watcher._thread
    assert thread is not None
    assert thread.name == THREAD_NAME

    started = time.monotonic()
    await watcher.stop()

    assert time.monotonic() - started < STOP_BUDGET_S
    assert not thread.is_alive()
    assert client.opened[0].closed
    assert not watcher.running


async def test_open_failure_is_logged_and_retried(caplog: pytest.LogCaptureFixture) -> None:
    client = FakeClient(
        ConnectionError("daemon is away"), FakeStream((die_event("back"),), block=True)
    )
    recorder = Recorder()
    watcher = make_watcher(client, recorder)
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        watcher.start()
        try:
            await wait_until(lambda: bool(recorder.events))
        finally:
            await watcher.stop()

    assert any("event stream failed" in record.message for record in caplog.records)
    assert recorder.events[0]["id"] == "back"


async def test_error_inside_the_stream_is_logged_and_does_not_escape(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = FakeClient(
        FakeStream((die_event("one"), OSError("socket reset"))),
        FakeStream((die_event("two"),), block=True),
    )
    recorder = Recorder()
    watcher = make_watcher(client, recorder)
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        watcher.start()
        try:
            await wait_until(lambda: len(recorder.events) == 2)
        finally:
            await watcher.stop()

    assert [event["id"] for event in recorder.events] == ["one", "two"]
    assert any(record.levelno == logging.WARNING for record in caplog.records)


async def test_failing_callback_is_logged_and_later_events_still_arrive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    seen: list[str] = []

    def callback(event: Mapping[str, Any]) -> None:
        seen.append(event["id"])
        if event["id"] == "bad":
            raise RuntimeError("listener bug")

    client = FakeClient(FakeStream((die_event("bad"), die_event("good")), block=True))
    watcher = make_watcher(client, callback)
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        watcher.start()
        try:
            await wait_until(lambda: seen == ["bad", "good"])
        finally:
            await watcher.stop()

    assert any("callback failed" in record.message for record in caplog.records)


async def test_stop_without_start_and_double_stop_are_harmless() -> None:
    watcher = make_watcher(FakeClient(), Recorder())
    await watcher.stop()
    watcher.start()
    await watcher.stop()
    await watcher.stop()
    assert not watcher.running


def make_reconciler() -> WatchedReconciler:
    driver: Any = SimpleNamespace(name="stub")  # no inventory: a reconcile pass is skipped
    uow_factory: Any = lambda: None  # noqa: E731  (never called: the pass is skipped)
    return WatchedReconciler(uow_factory, driver, SystemClock(), interval_s=3600.0, grace_s=60.0)


async def test_kick_with_rechecks_kicks_now_and_after_each_delay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reconciler_module, "RECHECK_KICK_DELAYS_S", (0.02, 0.04))
    reconciler = make_reconciler()
    kicks: list[float] = []
    started = time.monotonic()
    monkeypatch.setattr(reconciler, "kick", lambda: kicks.append(time.monotonic() - started))

    reconciler.kick_with_rechecks()
    assert len(kicks) == 1  # the immediate kick happens inside the call
    await wait_until(lambda: len(kicks) == 3)

    assert kicks[1] >= 0.02
    assert kicks[2] >= 0.04


def test_recheck_delays_match_the_exec_path() -> None:
    assert reconciler_module.RECHECK_KICK_DELAYS_S == (1.5, 5.0)


async def test_exit_event_kicks_the_watched_reconciler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reconciler_module, "RECHECK_KICK_DELAYS_S", (0.02, 0.04))
    client = FakeClient(FakeStream((die_event(),), block=True))
    reconciler = make_reconciler()
    reconciler.watch(client)
    kicks: list[int] = []
    monkeypatch.setattr(reconciler, "kick", lambda: kicks.append(1))

    reconciler.start()
    try:
        await wait_until(lambda: len(kicks) == 3)
    finally:
        await reconciler.stop()

    assert not reconciler.running
    assert client.opened[0].closed  # stopping the reconciler stopped the watcher


async def test_reconciler_without_a_docker_client_starts_no_watcher() -> None:
    reconciler = make_reconciler()
    reconciler.start()
    try:
        assert reconciler.running
        assert not any(t.name == THREAD_NAME for t in threading.enumerate())
    finally:
        await reconciler.stop()


def test_docker_client_of_only_answers_for_the_docker_driver() -> None:
    client = object()
    assert docker_client_of(SimpleNamespace(name="docker", _client=client)) is client
    assert docker_client_of(SimpleNamespace(name="fake", _client=client)) is None
    assert docker_client_of(SimpleNamespace(name="docker")) is None


@pytest.mark.docker
async def test_real_daemon_kill_of_a_managed_container_fires_the_callback() -> None:
    docker = pytest.importorskip("docker")
    from sandfort.drivers.docker.client import make_client

    try:
        client = make_client()
        client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    image = "alpine:3.20"
    try:
        client.images.get(image)
    except docker.errors.ImageNotFound:
        client.images.pull(image)

    recorder = Recorder()
    watcher = ContainerExitWatcher(client, recorder)
    watcher.start()
    container = client.containers.run(
        image,
        ["sleep", "60"],
        detach=True,
        name=f"sf-events-test-{uuid.uuid4().hex[:8]}",
        labels={LABEL_MANAGED: "true"},
    )
    try:
        await asyncio.sleep(0.5)  # let the watcher's stream attach before the exit
        container.kill()
        await wait_until(
            # Docker 29+ drops the legacy top-level "id"; the container id is Actor.ID.
            lambda: any(
                container.id in (event.get("id"), (event.get("Actor") or {}).get("ID"))
                for event in recorder.events
            ),
            10.0,
        )
    finally:
        await watcher.stop()
        container.remove(force=True)
        client.close()
