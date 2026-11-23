"""Docker exec against a real local daemon (skipped when none is reachable)."""

import contextlib
import time
import uuid
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.drivers.base import ExecRequest, ExitEvent, OutputChunk, SandboxSpec
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.driver import DockerDriver

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

IMAGE = "alpine:3.20"
TIMEOUT_S = 2.0
KILL_DEADLINE_S = 3.0
FLOOD_CAP_BYTES = 64 * 1024


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        docker_client = make_client()
        docker_client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    try:
        docker_client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        try:
            docker_client.images.pull(IMAGE)
        except Exception as exc:
            pytest.skip(f"cannot pull {IMAGE}: {exc}")
    return docker_client


@pytest.fixture
def driver(client: Any) -> DockerDriver:
    return DockerDriver(Settings(), client=client)


def make_spec() -> SandboxSpec:
    token = uuid.uuid4().hex[:10]
    return SandboxSpec(
        sandbox_id=f"sbx_t{token}",
        org_id=f"org_t{token}",
        name=f"sf-sbx_t{token}",
        image=IMAGE,
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=1),
        labels={"suite": "test_docker_exec"},
    )


async def start_sandbox(driver: DockerDriver, created: list[str]) -> str:
    """Create and start a sandbox; its name is registered before anything can fail."""
    spec = make_spec()
    created.append(spec.name)
    info = await driver.create(spec)
    await driver.start(info.ref)
    return info.ref


def force_remove(client: Any, ref: str) -> None:
    with contextlib.suppress(docker.errors.NotFound):
        client.api.remove_container(ref, v=True, force=True)


def remove_all(client: Any, refs: list[str]) -> None:
    for ref in refs:
        force_remove(client, ref)


async def process_listing(driver: DockerDriver, ref: str) -> str:
    result = await driver.exec(ref, ExecRequest(argv=["ps"]))
    return result.stdout.decode()


async def test_exit_code_is_reported(client: Any, driver: DockerDriver) -> None:
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        result = await driver.exec(ref, ExecRequest(argv=["sh", "-c", "exit 3"]))

        assert result.exit_code == 3
        assert result.timed_out is False
        assert result.truncated is False
    finally:
        remove_all(client, created)


async def test_stdout_and_stderr_are_separated(client: Any, driver: DockerDriver) -> None:
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        result = await driver.exec(
            ref, ExecRequest(argv=["sh", "-c", "echo out; echo err >&2; echo out2"])
        )

        assert result.exit_code == 0
        assert result.stdout == b"out\nout2\n"
        assert result.stderr == b"err\n"
    finally:
        remove_all(client, created)


async def test_stdin_cwd_and_env_are_applied(client: Any, driver: DockerDriver) -> None:
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        piped = await driver.exec(ref, ExecRequest(argv=["cat"], stdin=b"hello"))
        context = await driver.exec(
            ref,
            ExecRequest(
                argv=["sh", "-c", "pwd; echo $GREETING"], cwd="/tmp", env={"GREETING": "hi"}
            ),
        )

        assert piped.stdout == b"hello"
        assert context.stdout == b"/tmp\nhi\n"
    finally:
        remove_all(client, created)


async def test_stream_yields_chunks_then_one_exit_event(
    client: Any, driver: DockerDriver
) -> None:
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        events = [
            event
            async for event in driver.exec_stream(
                ref, ExecRequest(argv=["sh", "-c", "echo a; echo b >&2; exit 2"])
            )
        ]

        chunks = [event for event in events if isinstance(event, OutputChunk)]
        assert {(c.stream, c.data) for c in chunks} == {("stdout", b"a\n"), ("stderr", b"b\n")}
        assert isinstance(events[-1], ExitEvent)
        assert events[-1].exit_code == 2
        assert sum(isinstance(event, ExitEvent) for event in events) == 1
    finally:
        remove_all(client, created)


async def test_timeout_kills_process_inside_container(client: Any, driver: DockerDriver) -> None:
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        started = time.monotonic()
        result = await driver.exec(ref, ExecRequest(argv=["sleep", "600"], timeout_s=TIMEOUT_S))
        elapsed = time.monotonic() - started

        assert result.timed_out is True
        assert TIMEOUT_S <= elapsed < KILL_DEADLINE_S
        assert "sleep 600" not in await process_listing(driver, ref)
    finally:
        remove_all(client, created)


async def test_timeout_kills_child_processes_too(client: Any, driver: DockerDriver) -> None:
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        result = await driver.exec(
            ref, ExecRequest(argv=["sh", "-c", "sleep 601 & sleep 602; wait"], timeout_s=1.0)
        )

        assert result.timed_out is True
        assert "sleep 60" not in await process_listing(driver, ref)
    finally:
        remove_all(client, created)


async def test_yes_flood_is_truncated_at_the_cap(client: Any, driver: DockerDriver) -> None:
    created: list[str] = []
    try:
        ref = await start_sandbox(driver, created)

        result = await driver.exec(
            ref, ExecRequest(argv=["yes"], timeout_s=30, max_output_bytes=FLOOD_CAP_BYTES)
        )

        assert result.truncated is True
        assert result.timed_out is False
        assert len(result.stdout) == FLOOD_CAP_BYTES
        survivors = [
            line for line in (await process_listing(driver, ref)).splitlines()
            if line.split()[-1:] == ["yes"]
        ]
        assert survivors == []
    finally:
        remove_all(client, created)
