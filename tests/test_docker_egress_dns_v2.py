"""Egress v2 round 4, D3 and D4 against a real Linux daemon (skipped when none is reachable).

D3: a runc container on ``sf-egress-net`` with ``dns=[sink]`` cannot resolve a public name,
the sink's counter rises (the query reached the sink, assumption A2) and a stub upstream sees
zero queries (assumption A1). The stub binds ``SANDFORT_TEST_DNS_STUB`` (``ip:port``) when
that is set to the host resolver's address, which is what makes "zero queries" meaningful on
the beta VM; without it the stub listens on a loopback port and the sink counter is the only
proof. D4: the same container under gVisor gets no ``dns`` and fails to resolve at once.

The sink here is a minimal REFUSED responder on the bridge gateway, so the driver change is
tested apart from the proxy's real sink (``tests/test_egress_dns_sink_v2.py``). Binding port 53
needs root or ``CAP_NET_BIND_SERVICE``; without it the tests skip.
"""

import asyncio
import os
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from sandfort.config import Settings
from sandfort.domain.resources import ResourceSpec
from sandfort.domain.sandbox import EGRESS_RESTRICTED_LABEL, NetworkPolicy
from sandfort.drivers.base import SandboxSpec
from sandfort.drivers.docker.client import make_client
from sandfort.drivers.docker.egress_probe import gateway_of
from sandfort.drivers.docker.hardening import build_host_config, options_from_settings
from sandfort.drivers.docker.networks import EGRESS_NETWORK_NAME, ensure_network

pytestmark = pytest.mark.docker

docker = pytest.importorskip("docker")

IMAGE = "alpine:3.20"
PUBLIC_NAME = "example.com"
RESOLVE = f"getent hosts {PUBLIC_NAME}; echo rc=$?"
TIER_MAP = (("container", ""), ("gvisor", "runsc"))
DNS_PORT = 53
WAIT_S = 60.0
QUICK_FAIL_S = 15.0
REFUSED_FLAGS = b"\x80\x05"  # QR set, RCODE 5 (REFUSED)
DNS_HEADER_BYTES = 12
STUB_ENV = "SANDFORT_TEST_DNS_STUB"


class UdpCounter:
    """A UDP socket that counts datagrams; ``refuse`` answers each one with REFUSED."""

    def __init__(self, address: str, port: int, *, refuse: bool) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((address, port))
        self._socket.settimeout(0.2)
        self._refuse = refuse
        self._stop = threading.Event()
        self.sources: list[str] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def count(self) -> int:
        return len(self.sources)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, source = self._socket.recvfrom(512)
            except TimeoutError:
                continue
            except OSError:
                return
            self.sources.append(source[0])
            if self._refuse and len(data) >= DNS_HEADER_BYTES:
                self._socket.sendto(data[:2] + REFUSED_FLAGS + data[4:DNS_HEADER_BYTES], source)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._socket.close()


@pytest.fixture(scope="module")
def client() -> Any:
    try:
        docker_client = make_client()
        docker_client.ping()
    except Exception as exc:
        pytest.skip(f"no reachable Docker daemon: {exc}")
    try:
        yield docker_client
    finally:
        docker_client.close()


@pytest.fixture(scope="module")
def gateway(client: Any) -> str:
    asyncio.run(ensure_network(client, EGRESS_NETWORK_NAME))
    attrs = client.networks.get(EGRESS_NETWORK_NAME).attrs
    address = gateway_of(attrs)
    if address is None:
        pytest.skip("the egress network reports no gateway address")
    return address


@pytest.fixture
def sink(gateway: str) -> Iterator[UdpCounter]:
    try:
        counter = UdpCounter(gateway, DNS_PORT, refuse=True)
    except OSError as exc:
        pytest.skip(f"cannot bind the sink on {gateway}:{DNS_PORT}: {exc}")
    yield counter
    counter.close()


@pytest.fixture
def stub_upstream() -> Iterator[UdpCounter]:
    configured = os.environ.get(STUB_ENV, "")
    address, _, port = configured.partition(":") if configured else ("127.0.0.1", "", "0")
    try:
        counter = UdpCounter(address, int(port or DNS_PORT), refuse=True)
    except OSError as exc:
        pytest.skip(f"cannot bind the stub upstream: {exc}")
    yield counter
    counter.close()


def egress_spec(tier: str) -> SandboxSpec:
    return SandboxSpec(
        sandbox_id=f"sbx_dns_{uuid.uuid4().hex[:8]}",
        org_id="org_dns",
        name="dns-v2",
        image=IMAGE,
        resources=ResourceSpec(),
        labels={EGRESS_RESTRICTED_LABEL: "true"},
        network=NetworkPolicy(),
        isolation=tier,
    )


def run_resolve(client: Any, tier: str, sink_address: str) -> tuple[str, float]:
    """Run ``getent hosts`` in a container built exactly as the driver would; (output, seconds)."""
    settings = Settings(isolation_runtimes=TIER_MAP, egress_dns_sink_address=sink_address)
    kwargs = build_host_config(egress_spec(tier), settings, options_from_settings(settings))
    try:
        client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        client.images.pull(IMAGE)
    container = client.containers.create(IMAGE, ["sh", "-c", RESOLVE], **kwargs)
    try:
        started = time.monotonic()
        container.start()
        container.wait(timeout=WAIT_S)
        elapsed = time.monotonic() - started
        return bytes(container.logs(stdout=True, stderr=True)).decode("utf-8", "replace"), elapsed
    finally:
        container.remove(force=True)


def runtimes(client: Any) -> set[str]:
    return set(client.info().get("Runtimes", {}))


def test_d3_runc_on_the_egress_net_cannot_resolve_and_the_sink_sees_the_query(
    client: Any, sink: UdpCounter, stub_upstream: UdpCounter, gateway: str
) -> None:
    output, _ = run_resolve(client, "container", gateway)

    assert "rc=0" not in output, output  # getent found an address: the name leaked
    assert PUBLIC_NAME not in output
    assert sink.count >= 1, "the embedded resolver never forwarded to the sink (A2)"
    assert stub_upstream.count == 0, "the embedded resolver fell back to the upstream (A1)"


def test_d4_gvisor_on_the_egress_net_fails_at_once_without_a_dns_kwarg(
    client: Any, gateway: str
) -> None:
    if "runsc" not in runtimes(client):
        pytest.skip("the daemon has no runsc runtime")
    settings = Settings(isolation_runtimes=TIER_MAP, egress_dns_sink_address=gateway)
    config = build_host_config(egress_spec("gvisor"), settings, options_from_settings(settings))
    assert "dns" not in config

    output, elapsed = run_resolve(client, "gvisor", gateway)

    assert "rc=0" not in output, output
    assert elapsed < QUICK_FAIL_S, f"gVisor resolution took {elapsed:.1f} s to fail"
