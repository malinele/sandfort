"""WP 5.4 isolation against a real local daemon (skipped when none is reachable).

A fork bomb launched through the process toolbox exhausts its sandbox's pid budget while
the daemon and a control sandbox created beforehand stay healthy. With the repository's
seccomp profile configured, creating a user namespace fails inside the sandbox while
ordinary commands still run (skipped when the daemon rejects the profile, and under gVisor,
which is itself the syscall boundary and does not apply the host seccomp profile).
"""

import contextlib
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import Sandbox, SandboxState
from sandfort.drivers.base import ExecRequest, ExecResult, SandboxSpec
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.driver import DockerDriver
from sandfort.drivers.docker.hardening import GVISOR_RUNTIME, PIDS_LIMIT, SECCOMP_OPT_PREFIX
from sandfort.drivers.errors import DriverError
from sandfort.toolbox.process import execute

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

ROOT = Path(__file__).resolve().parents[1]
REPO_PROFILE = ROOT / "deploy" / "seccomp.json"
IMAGE = "alpine:3.20"
NOW = datetime(2026, 10, 31, 3, 0, tzinfo=UTC)
BOMB_TIMEOUT_S = 20.0
CONTROL_TIMEOUT_S = 15.0
# Deterministic pid pressure: the script first spawns far more background sleepers than the
# pid budget allows. Each holder outlives the whole test window (HOLD_S > BOMB_TIMEOUT_S) and
# has its output sent to /dev/null so it cannot hold the exec stream open, so the budget can
# never free itself up. Once spawns fail (busybox sh may abort right there with a non-zero
# status) every further fork must fail, and the probe loop exits 70 on the first failed fork.
HOLD_S = 600
HOLDERS = PIDS_LIMIT * 4
FORK_BOMB = (
    f"i=0; while [ $i -lt {HOLDERS} ]; do sleep {HOLD_S} >/dev/null 2>&1 & i=$((i + 1)); done; "
    "i=0; while [ $i -lt 200 ]; do probe=$(echo x) || exit 70; i=$((i + 1)); done; exit 0"
)
CreateSandbox = Callable[[DockerDriver], Awaitable[Sandbox]]


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


def make_spec() -> SandboxSpec:
    token = uuid.uuid4().hex[:10]
    return SandboxSpec(
        sandbox_id=f"sbx_t{token}",
        org_id=f"org_t{token}",
        name=f"sf-sbx_t{token}",
        image=IMAGE,
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=256, disk_gib=1),
        labels={"suite": "test_docker_hardening_phase5"},
    )


def as_sandbox(spec: SandboxSpec, ref: str) -> Sandbox:
    return Sandbox(
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


@pytest.fixture
async def sandboxes(client: Any) -> AsyncIterator[CreateSandbox]:
    """Create-and-start sandboxes on a given driver; all are force-removed afterwards."""
    names: list[str] = []

    async def create(driver: DockerDriver) -> Sandbox:
        spec = make_spec()
        names.append(spec.name)
        info = await driver.create(spec)
        await driver.start(info.ref)
        return as_sandbox(spec, info.ref)

    try:
        yield create
    finally:
        for name in names:
            with contextlib.suppress(docker.errors.NotFound):
                client.api.remove_container(name, v=True, force=True)


async def run(
    driver: DockerDriver, sandbox: Sandbox, argv: list[str], timeout_s: float
) -> ExecResult:
    """Exec through the process toolbox, as the API route does."""
    return await execute(driver, sandbox, ExecRequest(argv=argv, timeout_s=timeout_s))


def host_config(client: Any, sandbox: Sandbox) -> Any:
    return client.api.inspect_container(sandbox.driver_ref)["HostConfig"]


async def test_fork_bomb_exhausts_its_pid_budget_and_spares_the_host(
    client: Any, sandboxes: CreateSandbox
) -> None:
    driver = DockerDriver(Settings(), client=client)
    control = await sandboxes(driver)
    bombed = await sandboxes(driver)
    assert host_config(client, bombed)["PidsLimit"] == PIDS_LIMIT

    bomb = await run(driver, bombed, ["sh", "-c", FORK_BOMB], BOMB_TIMEOUT_S)

    assert bomb.exit_code != 0 or bomb.timed_out, bomb
    assert client.ping() is True
    healthy = await run(driver, control, ["true"], CONTROL_TIMEOUT_S)
    assert (healthy.exit_code, healthy.timed_out) == (0, False)


async def test_repository_seccomp_profile_denies_user_namespaces(
    client: Any, sandboxes: CreateSandbox
) -> None:
    driver = DockerDriver(Settings(seccomp_profile_path=str(REPO_PROFILE)), client=client)
    try:
        sandbox = await sandboxes(driver)
    except DriverError as exc:
        pytest.skip(f"the daemon rejected the seccomp profile: {exc}")
    config = host_config(client, sandbox)
    if GVISOR_RUNTIME in (client.info().get("DefaultRuntime"), config.get("Runtime")):
        pytest.skip("gVisor is the syscall boundary; it does not apply the host seccomp profile")
    security_opt = config["SecurityOpt"] or []
    assert any(opt.startswith(SECCOMP_OPT_PREFIX) for opt in security_opt)
    present = await run(driver, sandbox, ["sh", "-c", "command -v unshare"], CONTROL_TIMEOUT_S)
    if present.exit_code != 0:
        pytest.skip(f"{IMAGE} has no unshare binary")

    denied = await run(driver, sandbox, ["unshare", "-U", "true"], CONTROL_TIMEOUT_S)
    plain = await run(driver, sandbox, ["echo", "still-works"], CONTROL_TIMEOUT_S)
    listing = await run(driver, sandbox, ["sh", "-c", "ls / >/dev/null"], CONTROL_TIMEOUT_S)

    assert denied.exit_code != 0, denied
    assert (plain.exit_code, plain.stdout) == (0, b"still-works\n")
    assert listing.exit_code == 0, listing
