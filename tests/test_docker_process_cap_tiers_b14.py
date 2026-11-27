"""B14: what bounds a fork loop on each isolation tier, against a real local daemon.

The driver passes ``pids_limit=512`` for ``container`` and ``microvm``, and 1536 plus an
``nproc`` ulimit of 512 for ``gvisor``. These tests run one fork loop through
``docker exec`` in a container built by ``build_host_config`` exactly as the driver builds it
(1 CPU, 512 MiB unless stated, no swap, ``block_all``) and pin what bounds it per tier, as
measured on the beta VM on 2026-11-26 and 2026-11-27 (``docs/isolation-tiers.md``, "Process
limits per tier"). ``gvisor`` and
``microvm`` skip without ``runsc`` or ``kata``. The containers carry no ``sandfort.managed``
label, so the reconciler never adopts them.
"""

import re
import uuid
from dataclasses import dataclass
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import NetworkPolicy
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.hardening import PIDS_LIMIT, build_host_config, options_from_settings

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

IMAGE = "alpine:3.20"
TIER_MAP = (("container", "runc"), ("gvisor", "runsc"), ("microvm", "kata"))
HOLDERS = 1500
HOLD_S = 120
MEMORY_MIB = 512
SLACK = 16
TEST_TIMEOUT_S = 300
EAGAIN_TEXT = "Resource temporarily unavailable"
# $! stays unchanged when a fork fails and the shell goes on, so the loop stops there; SLACK
# covers tini, the keepalive and the exec shell, which share pids.max with the children.
LOOP = (
    "cat /sys/fs/cgroup/pids.max 2>&1 | head -n 1; echo ulimit_u=$(ulimit -u); last=; i=0; "
    f"while [ $i -lt {HOLDERS} ]; do sleep {HOLD_S} >/dev/null 2>&1 & "
    'if [ "$!" = "$last" ]; then echo fork_failed; break; fi; '
    "last=$!; i=$((i + 1)); echo n=$i; done; echo loop_done"
)
SPAWNED = re.compile(r"^n=(\d+)$", re.MULTILINE)
ULIMIT = re.compile(r"^ulimit_u=(\S*)$", re.MULTILINE)


@dataclass(frozen=True)
class LoopResult:
    output: str
    first_line: str
    ulimit_u: str
    spawned: int
    eagain: bool
    exec_error: bool
    still_running: bool


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


def runtimes(client: Any) -> set[str]:
    return set(client.info().get("Runtimes", {}))


def require_runtime(client: Any, name: str) -> None:
    if name not in runtimes(client):
        pytest.skip(f"the daemon has no {name} runtime")


def spec(tier: str, memory_mib: int = MEMORY_MIB) -> SandboxSpec:
    suffix = uuid.uuid4().hex[:8]
    return SandboxSpec(
        sandbox_id=f"sbx_b14_{suffix}",
        org_id="org_b14",
        name=f"b14-{tier}-{suffix}",
        image=IMAGE,
        resources=ResourceSpec(cpu_millicores=1000, memory_mib=memory_mib, disk_gib=1),
        network=NetworkPolicy(block_all=True),
        isolation=tier,
    )


def read_stream(stream: Any) -> tuple[str, bool]:
    chunks: list[bytes] = []
    errored = False
    try:
        for chunk in stream:
            chunks.append(chunk)
    except Exception:
        # A dying sandbox or VM can break the exec stream; keep what arrived.
        errored = True
    return b"".join(chunks).decode("utf-8", "replace"), errored


def parse(output: str, exec_error: bool, still_running: bool) -> LoopResult:
    lines = output.strip().splitlines()
    counts = [int(match) for match in SPAWNED.findall(output)]
    ulimit = ULIMIT.search(output)
    return LoopResult(
        output=output,
        first_line=lines[0].strip() if lines else "",
        ulimit_u=ulimit.group(1) if ulimit else "",
        spawned=max(counts, default=0),
        eagain=EAGAIN_TEXT in output,
        exec_error=exec_error,
        still_running=still_running,
    )


def run_loop(client: Any, tier: str, memory_mib: int = MEMORY_MIB) -> LoopResult:
    """Run ``LOOP`` in a container built as the driver builds it for ``tier``."""
    sandbox = spec(tier, memory_mib)
    settings = Settings(isolation_runtimes=TIER_MAP)
    kwargs = build_host_config(sandbox, settings, options_from_settings(settings))
    container = client.containers.create(IMAGE, ["sleep", "600"], name=sandbox.name, **kwargs)
    try:
        container.start()
        result = container.exec_run(["sh", "-c", LOOP], stream=True)
        output, errored = read_stream(result.output)
        container.reload()
        return parse(output, errored, container.status == "running")
    finally:
        container.remove(force=True)


def assert_nproc_cap(r: LoopResult) -> None:
    """The loop ended at the guest ``nproc`` cap and the sandbox kept running."""
    tail = r.output[-2000:]
    assert r.first_line != str(PIDS_LIMIT), tail
    assert r.ulimit_u == "512", tail
    assert r.eagain, tail
    assert PIDS_LIMIT - SLACK <= r.spawned < PIDS_LIMIT, tail
    assert r.still_running, tail


@pytest.mark.timeout(TEST_TIMEOUT_S)
def test_container_tier_caps_the_fork_loop_with_eagain_below_the_pids_limit(client: Any) -> None:
    require_runtime(client, "runc")

    r = run_loop(client, "container")

    tail = r.output[-2000:]
    assert r.first_line == str(PIDS_LIMIT), tail
    assert r.eagain, tail
    assert PIDS_LIMIT - SLACK <= r.spawned < PIDS_LIMIT, tail


@pytest.mark.timeout(TEST_TIMEOUT_S)
def test_gvisor_tier_nproc_caps_the_fork_loop_with_the_sandbox_alive(client: Any) -> None:
    """Pins the 2026-11-27 measurement: EAGAIN at 509 children with the sandbox alive.

    That is at the driver's 512 MiB. A failure means gVisor changed, so re-measure before
    editing the docs.
    """
    require_runtime(client, "runsc")

    r = run_loop(client, "gvisor")

    assert_nproc_cap(r)


@pytest.mark.timeout(TEST_TIMEOUT_S)
def test_gvisor_tier_cap_is_independent_of_the_memory_limit(client: Any) -> None:
    """At 2 GiB the memory limit cannot be what stops the loop, so the cap must be.

    The 2026-11-26 note said memory ended the loop. With the raised host pids limit and
    ``nproc`` the cap is the stopper at any size.
    """
    require_runtime(client, "runsc")

    r = run_loop(client, "gvisor", memory_mib=2048)

    assert_nproc_cap(r)


@pytest.mark.timeout(TEST_TIMEOUT_S)
def test_microvm_tier_guest_sees_pids_max_unbounded_and_passes_the_pids_limit(
    client: Any,
) -> None:
    """Kata clears the pids limit before the guest, so the loop passes 512 children.

    The VM may end during the loop, which ``read_stream`` tolerates. A failure means Kata
    started passing the pids limit through.
    """
    require_runtime(client, "kata")

    r = run_loop(client, "microvm")

    tail = r.output[-2000:]
    assert r.first_line != str(PIDS_LIMIT), tail
    assert r.spawned > PIDS_LIMIT, tail
