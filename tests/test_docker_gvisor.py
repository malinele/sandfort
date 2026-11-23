"""gVisor (``runsc``) sandboxes against a real local daemon (skipped unless it lists runsc).

gVisor mounts a private in-memory tmpfs over ``/tmp`` (invisible to docker's archive API, not
covered by the disk quota or snapshots) when ``/tmp`` is empty at start. The driver puts a
``.sandfort-keep`` marker into ``/tmp`` before every runsc start, so ``/tmp`` stays in the
root filesystem. This checks that ``/tmp`` is not a separate mount inside the sandbox, also
after stop + start, drives the filesystem toolbox through a ``/tmp`` round trip (mkdir,
upload, read back inside the sandbox, download), checks exit codes and checks that delete
removes the sandbox.
"""

import contextlib
import socket
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sandfort.clock import FrozenClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import Org
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import ExecRequest, ExecResult, SandboxSpec
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.hardening import GVISOR_RUNTIME, GVISOR_TMP_PATH, HardeningOptions
from sandfort.drivers.errors import DriverNotFound
from sandfort.ids import new_org_id, new_sandbox_id
from sandfort.services.audit import AuditRecorder
from sandfort.toolbox.fs import Actor, FsToolbox

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "alpine:3.20"
NOW = datetime(2026, 11, 4, 0, 0, tzinfo=UTC)
DATA_DIR = f"{GVISOR_TMP_PATH}/sf-gvisor/data"
FILE_PATH = f"{DATA_DIR}/hello.txt"
PAYLOAD = b"hello from a gvisor sandbox\n"
EXIT_CODE = 3
TIMEOUT_S = 30.0
GVISOR_KERNEL_MARK = "gvisor"
DNS_PROBE_HOST = "pypi.org"
RESOLV_CONF_PATH = "/etc/resolv.conf"
PROC_MOUNTS_PATH = "/proc/mounts"
TMP_MARKER_NAME = ".sandfort-keep"
STOP_TIMEOUT_S = 5.0
SessionFactory = async_sessionmaker[AsyncSession]


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        docker_client = make_client()
        docker_client.ping()
        runtimes = docker_client.info().get("Runtimes") or {}
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    if GVISOR_RUNTIME not in runtimes:
        pytest.skip(f"the daemon lists no {GVISOR_RUNTIME!r} runtime")
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
    options = HardeningOptions(runtime=GVISOR_RUNTIME, gvisor=True)
    return DockerDriver(Settings(), client=client, options=options)


@pytest.fixture
async def session_factory(tmp_path: Path) -> AsyncIterator[SessionFactory]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'gvisor.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(Settings(database_url=url))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()


def make_spec() -> SandboxSpec:
    sandbox_id = new_sandbox_id()
    return SandboxSpec(
        sandbox_id=sandbox_id,
        org_id=new_org_id(),
        name=f"sf-{sandbox_id}",
        image=IMAGE,
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=512, disk_gib=1),
        labels={"suite": "test_docker_gvisor"},
    )


async def register(factory: SessionFactory, spec: SandboxSpec, ref: str) -> None:
    """Store the org and a started sandbox row so the toolbox guard accepts the calls."""
    slug = f"gvisor-{uuid.uuid4().hex[:6]}"
    org = Org(id=spec.org_id, name="Gvisor", slug=slug, created_at=NOW)
    sandbox = Sandbox(
        id=spec.sandbox_id,
        org_id=spec.org_id,
        name=spec.sandbox_id,
        state=SandboxState.STARTED,
        image_ref=IMAGE,
        driver="docker",
        driver_ref=ref,
        started_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )
    async with UnitOfWork(factory) as uow:
        await uow.orgs.add(org)
        await uow.sandboxes.add(sandbox)
        await uow.commit()


async def run(driver: DockerDriver, ref: str, *argv: str) -> ExecResult:
    return await driver.exec(ref, ExecRequest(argv=list(argv), timeout_s=TIMEOUT_S))


def host_resolves(name: str) -> bool:
    """True when this process can resolve ``name`` (the test host has working DNS)."""
    try:
        socket.getaddrinfo(name, None)
    except OSError:
        return False
    return True


async def assert_resolves(driver: DockerDriver, ref: str, name: str) -> None:
    """``name`` resolves inside the sandbox and resolv.conf lists the written nameservers."""
    conf = await run(driver, ref, "cat", RESOLV_CONF_PATH)
    assert conf.exit_code == 0, conf
    text = conf.stdout.decode()
    assert "127.0.0.11" not in text, text
    assert "nameserver 1.1.1.1" in text, text
    lookup = await run(driver, ref, "getent", "hosts", name)
    assert lookup.exit_code == 0 and lookup.stdout.strip(), lookup


async def payload_body() -> AsyncIterator[bytes]:
    yield PAYLOAD


async def assert_tmp_is_not_a_mount(driver: DockerDriver, ref: str) -> None:
    """/tmp is part of the root filesystem: no line of /proc/mounts mounts anything on it."""
    mounts = await run(driver, ref, "cat", PROC_MOUNTS_PATH)
    assert mounts.exit_code == 0, mounts
    text = mounts.stdout.decode()
    assert f" {GVISOR_TMP_PATH} " not in text, text
    marker = await run(driver, ref, "test", "-e", f"{GVISOR_TMP_PATH}/{TMP_MARKER_NAME}")
    assert marker.exit_code == 0, marker


async def fs_round_trip(
    factory: SessionFactory, driver: DockerDriver, spec: SandboxSpec, ref: str
) -> None:
    """mkdir, upload, read back inside the sandbox and download a file under /tmp."""
    toolbox = FsToolbox(driver, AuditRecorder(FrozenClock(NOW)), FrozenClock(NOW))
    actor = Actor(org_id=spec.org_id, key_id=None)
    sandbox_id = spec.sandbox_id

    _, created = await toolbox.mkdir(UnitOfWork(factory), actor, sandbox_id, DATA_DIR)
    assert created is True
    uploaded = await toolbox.upload_file(
        UnitOfWork(factory),
        actor,
        sandbox_id,
        FILE_PATH,
        payload_body(),
        size=len(PAYLOAD),
        max_bytes=len(PAYLOAD),
    )
    assert uploaded == (FILE_PATH, len(PAYLOAD))

    read_back = await run(driver, ref, "cat", FILE_PATH)
    assert (read_back.exit_code, read_back.stdout) == (0, PAYLOAD), read_back

    download = await toolbox.download_path(UnitOfWork(factory), actor, sandbox_id, FILE_PATH)
    try:
        assert download.kind == "file"
        assert b"".join([chunk async for chunk in download.stream]) == PAYLOAD
    finally:
        await download.close()


async def test_gvisor_sandbox_runs_the_toolbox_under_tmp_and_deletes_cleanly(
    client: Any, driver: DockerDriver, session_factory: SessionFactory
) -> None:
    spec = make_spec()
    ref = ""
    try:
        info = await driver.create(spec)
        ref = info.ref
        await driver.start(ref)
        assert client.api.inspect_container(ref)["HostConfig"]["Runtime"] == GVISOR_RUNTIME
        assert not client.api.inspect_container(ref)["Mounts"]
        await assert_tmp_is_not_a_mount(driver, ref)
        await register(session_factory, spec, ref)

        kernel = await run(driver, ref, "uname", "-r")
        assert kernel.exit_code == 0, kernel
        assert GVISOR_KERNEL_MARK in kernel.stdout.decode().lower(), kernel

        await fs_round_trip(session_factory, driver, spec, ref)

        failing = await run(driver, ref, "sh", "-c", f"exit {EXIT_CODE}")
        assert (failing.exit_code, failing.timed_out) == (EXIT_CODE, False)

        await driver.destroy(ref)
        with pytest.raises(DriverNotFound):
            await driver.inspect(ref)
        ref = ""
    finally:
        if ref:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(ref, v=True, force=True)


async def test_gvisor_tmp_stays_in_the_root_filesystem_after_stop_and_start(
    client: Any, driver: DockerDriver
) -> None:
    spec = make_spec()
    ref = ""
    try:
        ref = (await driver.create(spec)).ref
        await driver.start(ref)
        await assert_tmp_is_not_a_mount(driver, ref)

        await driver.stop(ref, timeout_s=STOP_TIMEOUT_S)
        await driver.start(ref)  # the marker is put again before every runsc start
        await assert_tmp_is_not_a_mount(driver, ref)
    finally:
        if ref:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(ref, v=True, force=True)


async def test_gvisor_sandbox_resolves_names_and_still_does_after_stop_and_start(
    client: Any, driver: DockerDriver
) -> None:
    if not host_resolves(DNS_PROBE_HOST):
        pytest.skip(f"this host cannot resolve {DNS_PROBE_HOST}: no internet to test DNS against")
    spec = make_spec()
    ref = ""
    try:
        ref = (await driver.create(spec)).ref
        await driver.start(ref)
        await assert_resolves(driver, ref, DNS_PROBE_HOST)

        await driver.stop(ref, timeout_s=STOP_TIMEOUT_S)
        await driver.start(ref)  # docker rewrites resolv.conf on every start
        await assert_resolves(driver, ref, DNS_PROBE_HOST)
    finally:
        if ref:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(ref, v=True, force=True)
