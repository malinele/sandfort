"""B16 against a real Linux daemon: the host connection cap on ``sf-br0`` (skipped without one).

``deploy/host-setup.sh`` adds one connlimit rule to ``SANDFORT-EGRESS``: a new flow from a
sandbox address is rejected once that address holds ``SF_SANDBOX_CONN_LIMIT`` tracked flows.
The probe opens many non-blocking connections to an address nothing answers (RFC 5737), so
every admitted flow stays half-open and counted, while a flow past the limit is answered with
a TCP reset, which the probe sees as ``ECONNREFUSED``.

The test needs a host where the script ran with a limit the test knows: set
``SANDFORT_TEST_CONN_LIMIT`` to that number. ``SANDFORT_TEST_CONN_CAP_TARGET`` (``host:port``)
overrides the default target. It runs once per isolation tier whose runtime the daemon has.
"""

import json
import os
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import NetworkPolicy
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.hardening import NOFILE_LIMIT, build_host_config, options_from_settings

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

CAP_ENV = "SANDFORT_TEST_CONN_LIMIT"
TARGET_ENV = "SANDFORT_TEST_CONN_CAP_TARGET"
DEFAULT_TARGET = "192.0.2.1:9"  # RFC 5737 documentation range: not a private reject, no answer
IMAGE = "python:3.12-alpine3.20"
BRIDGE = Path("/sys/class/net/sf-br0")
OVER = 32  # connections attempted beyond the limit
SMALL = 8  # a probe far below the limit
# The kernel counts every tracked flow for the address, including ones the probe no longer
# owns (half-open flows being retried and recently reset ones conntrack has not expired),
# so refusals begin a few tens of flows below the limit. Measured 2026-11-27 on the beta VM
# (kernel 6.8, limit 512): first refusal at 487-489 admitted, on every tier, run to run.
# The hard property stays exact: admitted never exceeds the limit.
COUNT_SLACK = 64
TIER_MAP = (("container", "runc"), ("gvisor", "runsc"), ("microvm", "kata"))
SYN_SENT = Path("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent")
SYN_SENT_DEFAULT_S = 120
HOLD_MARGIN_S = 5
FD_MARGIN = 16  # descriptors the interpreter itself holds
LINE_WAIT_S = 30.0
POLL_S = 0.5

# Run as: python -c PROBE host port count. Prints one JSON line, then idles with every socket
# closed (which stops SYN retransmits) so the container stays up until the test removes it.
PROBE = """
import errno, json, socket, sys, time
host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
pending = []
refused = 0
for _ in range(count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    rc = sock.connect_ex((host, port))
    if rc in (0, errno.EINPROGRESS):
        pending.append(sock)
    else:
        refused += rc == errno.ECONNREFUSED
        sock.close()
    time.sleep(0.001)
time.sleep(3)
for sock in pending:
    refused += sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == errno.ECONNREFUSED
print(json.dumps({"total": count, "refused": refused, "admitted": count - refused}), flush=True)
for sock in pending:
    sock.close()
time.sleep(600)
"""


@pytest.fixture(scope="module")
def conn_cap() -> int:
    raw = os.environ.get(CAP_ENV, "")
    if not raw.isdigit() or int(raw) < 1:
        pytest.skip(f"{CAP_ENV} must be the host's connection limit (a positive integer)")
    if not BRIDGE.exists():
        pytest.skip("no sf-br0 bridge: run deploy/host-setup.sh on this host first")
    cap = int(raw)
    if cap + OVER + FD_MARGIN > NOFILE_LIMIT:
        pytest.skip(f"limit {cap} does not fit the sandbox open-file limit {NOFILE_LIMIT}")
    return cap


@pytest.fixture(scope="module")
def client() -> Iterator[Any]:
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
    try:
        yield docker_client
    finally:
        docker_client.close()


def probe_spec(tier: str) -> SandboxSpec:
    token = uuid.uuid4().hex[:8]
    return SandboxSpec(
        sandbox_id=f"sbx_b16_{token}",
        org_id="org_b16",
        name=f"b16-{tier}-{token}",
        image=IMAGE,
        resources=ResourceSpec(),
        network=NetworkPolicy(),  # no labels: the sandbox lands on sf-net
        isolation=tier,
    )


def read_result(container: Any) -> dict[str, int] | None:
    output = bytes(container.logs(stdout=True, stderr=False)).decode("utf-8", "replace")
    for line in output.splitlines():
        if line.startswith("{"):
            parsed: dict[str, int] = json.loads(line)
            return parsed
    return None


def start_probe(client: Any, tier: str, count: int) -> tuple[Any, dict[str, int]]:
    """Start a probe container built as the driver would; (container, its JSON result)."""
    host, _, port = os.environ.get(TARGET_ENV, DEFAULT_TARGET).partition(":")
    spec = probe_spec(tier)
    settings = Settings(isolation_runtimes=TIER_MAP)
    kwargs = build_host_config(spec, settings, options_from_settings(settings))
    command = ["python", "-c", PROBE, host, port, str(count)]
    container = client.containers.create(IMAGE, command, name=spec.name, **kwargs)
    container.start()
    deadline = time.monotonic() + LINE_WAIT_S
    while time.monotonic() < deadline:
        result = read_result(container)
        if result is not None:
            return container, result
        time.sleep(POLL_S)
    logs = bytes(container.logs()).decode("utf-8", "replace")
    container.remove(force=True)
    pytest.fail(f"probe printed no result within {LINE_WAIT_S} s: {logs}")


def hold_seconds() -> int:
    try:
        return int(SYN_SENT.read_text()) + HOLD_MARGIN_S
    except (OSError, ValueError):
        return SYN_SENT_DEFAULT_S + HOLD_MARGIN_S


@pytest.mark.timeout(400)
@pytest.mark.parametrize(
    ("tier", "runtime"), [("container", "runc"), ("gvisor", "runsc"), ("microvm", "kata")]
)
def test_open_network_flows_are_capped_per_sandbox_address(
    conn_cap: int, client: Any, tier: str, runtime: str
) -> None:
    if runtime not in client.info().get("Runtimes", {}):
        pytest.skip(f"the daemon has no {runtime} runtime")
    started: list[Any] = []
    last_line = time.monotonic()
    try:
        first, a = start_probe(client, tier, SMALL)
        started.append(first)
        # The case must run on the runtime it is named for, not the daemon default.
        assert first.attrs["HostConfig"]["Runtime"] == runtime, first.attrs["HostConfig"]
        assert a["refused"] == 0, a

        second, b = start_probe(client, tier, conn_cap + OVER)
        started.append(second)
        last_line = time.monotonic()
        assert conn_cap - COUNT_SLACK <= b["admitted"] <= conn_cap, b
        assert b["refused"] >= OVER, b
        assert b["refused"] + b["admitted"] == b["total"], b

        third, c = start_probe(client, tier, SMALL)  # b is still alive: another address
        started.append(third)
        last_line = time.monotonic()
        assert c["refused"] == 0, c
        assert client.ping() is True
    finally:
        # Hold until conntrack forgets the half-open flows, so the next tenant on a reused
        # address does not inherit a counted address.
        remaining = last_line + hold_seconds() - time.monotonic()
        if started and remaining > 0:
            time.sleep(remaining)
        for container in started:
            container.remove(force=True)
