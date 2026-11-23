# ruff: noqa: F811
"""R65: pid files a sandbox stop left behind (the wrapper was SIGKILLed) go when it starts again.

A stopped container cannot run an exec, so the cleanup that follows a kill cannot happen at
the kill. ``DockerDriver.start`` removes the leftovers best effort. The unit tests run the
exec's command on the local ``sh`` against a temporary directory.
"""

import logging
import subprocess
from pathlib import Path
from typing import Any

import pytest
import requests
from tests.test_docker_exec import client, remove_all, start_sandbox  # noqa: F401, F811

from sandfort.config import Settings
from sandfort.drivers.base import ExecRequest
from sandfort.drivers.docker import containers as containers_module
from sandfort.drivers.docker import pid_files
from sandfort.drivers.docker.driver import DockerDriver

LOGGER = pid_files.logger.name
SHELL_TIMEOUT_S = 30
LIST_PID_FILES = "ls -A /tmp | grep -E '^[.]sf-(exec|pty)-.*[.]pid$'; true"


class RecordingApi:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.created: list[dict[str, Any]] = []
        self.started: list[dict[str, Any]] = []

    def exec_create(self, container: str, **kwargs: Any) -> dict[str, str]:
        if self.error is not None:
            raise self.error
        self.created.append(kwargs)
        return {"Id": f"exec{len(self.created)}"}

    def exec_start(self, exec_id: str, **kwargs: Any) -> bytes:
        self.started.append(kwargs)
        return b""


class Client:
    def __init__(self, api: RecordingApi) -> None:
        self.api = api


def test_the_cleanup_removes_both_kinds_of_pid_file_and_nothing_else(tmp_path: Path) -> None:
    api = RecordingApi()
    for name in (".sf-exec-a.pid", ".sf-pty-b.pid", "keep.pid", ".sf-exec-a.log"):
        (tmp_path / name).write_text("1\n")

    pid_files.remove_stale_pid_files_blocking(Client(api), "ref", str(tmp_path))

    (call,) = api.created
    subprocess.run(call["cmd"], check=True, timeout=SHELL_TIMEOUT_S, capture_output=True)
    assert sorted(p.name for p in tmp_path.iterdir()) == [".sf-exec-a.log", "keep.pid"]
    assert api.started == [{"detach": True}]


def test_the_cleanup_with_no_pid_file_succeeds(tmp_path: Path) -> None:
    api = RecordingApi()

    pid_files.remove_stale_pid_files_blocking(Client(api), "ref", str(tmp_path))

    (call,) = api.created
    assert subprocess.run(call["cmd"], timeout=SHELL_TIMEOUT_S).returncode == 0


def docker_errors() -> tuple[Exception, Exception]:
    docker_module = pytest.importorskip("docker")
    response = requests.Response()
    response.status_code = 409
    response.reason = "Conflict"
    response._content = b'{"message": "Container is not running"}'
    return (
        docker_module.errors.NotFound("no such container"),
        docker_module.errors.APIError(
            "Container is not running", response=response, explanation="Container is not running"
        ),
    )


@pytest.mark.parametrize("which", [0, 1])
def test_a_stopped_or_removed_container_is_logged_at_debug(
    caplog: pytest.LogCaptureFixture, which: int
) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER)

    pid_files.remove_stale_pid_files_blocking(Client(RecordingApi(docker_errors()[which])), "r")

    records = [r for r in caplog.records if r.name == LOGGER]
    assert records
    assert {r.levelno for r in records} == {logging.DEBUG}


def test_any_other_failure_is_a_warning_and_never_raises(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER)

    pid_files.remove_stale_pid_files_blocking(Client(RecordingApi(RuntimeError("down"))), "r")

    assert [r.levelno for r in caplog.records if r.name == LOGGER] == [logging.WARNING]


async def test_the_driver_cleans_after_the_start(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []

    async def started(client: Any, ref: str, nameservers: Any = ()) -> None:
        order.append("start")

    def cleaned(client: Any, ref: str, directory: str = "/tmp") -> None:
        order.append("clean")

    monkeypatch.setattr(containers_module, "start_container", started)
    monkeypatch.setattr(pid_files, "remove_stale_pid_files_blocking", cleaned)

    await DockerDriver(Settings(), client=Client(RecordingApi())).start("ref")  # type: ignore[arg-type]

    assert order == ["start", "clean"]


@pytest.mark.docker
async def test_a_command_killed_by_a_sandbox_stop_leaves_no_pid_file_after_the_restart(
    client: Any,  # noqa: F811
) -> None:
    import asyncio

    driver = DockerDriver(Settings(), client=client)
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        async def run() -> None:
            request = ExecRequest(argv=["sleep", "300"], timeout_s=100)
            async for _ in driver.exec_stream(ref, request):
                pass

        command = asyncio.create_task(run())
        await asyncio.sleep(2)
        running = await driver.exec(ref, ExecRequest(argv=["sh", "-c", LIST_PID_FILES]))
        assert running.stdout.strip(), "the running command has a pid file"
        await driver.stop(ref, timeout_s=1)
        await command
        await driver.start(ref)
        await asyncio.sleep(1)  # the cleanup exec is detached
        after = await driver.exec(ref, ExecRequest(argv=["sh", "-c", LIST_PID_FILES]))

        stale = set(running.stdout.split()) & set(after.stdout.split())
        assert stale == set()
    finally:
        remove_all(client, created)
