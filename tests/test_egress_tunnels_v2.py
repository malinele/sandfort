"""TunnelRegistry tests (egress v2 round 2, design sections 5.4 and 12.3); hermetic, no network.

Tunnels are real asyncio tasks that sleep until cancelled and record the cancellation. Sweeps run
against a real PolicyClient over httpx.MockTransport with a fake clock shared with the registry.
The mock route signs its answers with a key derived here from the documented label. Case ids
(U2, U3, U4, U8, U9, K7, K8) are those of docs/egress-v2-design.md 12.3 and 12.7.
"""

import asyncio
import base64
import hashlib
import hmac
import json
from collections.abc import AsyncIterator, Callable, Sequence
from ipaddress import ip_address
from typing import Any

import httpx
import pytest

from sandfort.egress.policy_client import PolicyClient, PolicyEntry
from sandfort.egress.tunnels import TunnelRecord, TunnelRegistry

SECRET = "test-egress-secret"
NOW = 1_795_000_000
K_RESP = hmac.new(SECRET.encode(), b"sandfort/egress/policy/response/v1", hashlib.sha256).digest()
LITERAL = "198.51.100.7"
Opener = Callable[..., TunnelRecord]


def _entry(*rules: str, found: bool = True, generation: int = 0, epoch: int = 1) -> PolicyEntry:
    return PolicyEntry(found, generation, epoch, tuple(rules), 0.0)


class FakeClock:
    now = 0.0

    def __call__(self) -> float:
        return self.now


class Route:
    """A policy route whose answer is whatever ``policies`` holds, or a transport failure."""

    def __init__(self) -> None:
        self.policies: dict[str, dict[str, Any]] = {}
        self.failure: Exception | None = None
        self.sent: list[list[str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["sandbox_ids"]
        self.sent.append(ids)
        if self.failure is not None:
            raise self.failure
        records = [
            {"sandbox_id": i, "found": True, **self.policies[i]}
            if i in self.policies
            else {"sandbox_id": i, "found": False}
            for i in ids
        ]
        body = json.dumps({"issued_at": NOW, "policies": records}).encode()
        request_digest = hashlib.sha256(request.content).hexdigest()  # bound to this request
        message = f"{NOW}\n{request_digest}\n{hashlib.sha256(body).hexdigest()}".encode()
        mac = hmac.new(K_RESP, message, hashlib.sha256).digest()
        signature = f"t={NOW},s={base64.urlsafe_b64encode(mac).rstrip(b'=').decode()}"
        return httpx.Response(200, content=body, headers={"X-Sandfort-Egress-Signature": signature})


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def registry(clock: FakeClock) -> TunnelRegistry:
    return TunnelRegistry(clock=clock)


@pytest.fixture
def route() -> Route:
    return Route()


@pytest.fixture
async def client(route: Route, clock: FakeClock) -> AsyncIterator[PolicyClient]:
    policy_client = PolicyClient(
        "http://policy.test",
        SECRET,
        cache_s=5.0,
        timeout_s=2.0,
        max_stale_s=60.0,
        transport=httpx.MockTransport(route.handler),
        clock=clock,
        now=lambda: NOW,
    )
    yield policy_client
    await policy_client.aclose()


@pytest.fixture
async def open_tunnel() -> AsyncIterator[Opener]:
    """Starts a task that sleeps until cancelled; every task is reaped at the end of the test."""
    tasks: list[asyncio.Task[None]] = []

    def opener(
        sandbox_id: str = "sbx_1",
        host: str = "a.example.com",
        *,
        address: str = "203.0.113.9",
        version: int = 1,
        epoch: int | None = None,
        generation: int = 0,
    ) -> TunnelRecord:
        async def sleep_forever() -> None:
            await asyncio.Event().wait()

        task = asyncio.create_task(sleep_forever())
        tasks.append(task)
        epoch = 1 if version == 2 and epoch is None else epoch
        record = TunnelRecord(
            sandbox_id, host, ip_address(address), 443, generation, version, epoch, task
        )
        return record

    yield opener
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def _cancelled(*records: TunnelRecord) -> list[bool]:
    await asyncio.sleep(0)  # let the cancellation reach each task
    return [record.task.cancelled() for record in records]


async def test_bookkeeping_follows_register_and_unregister(
    registry: TunnelRegistry, open_tunnel: Opener
) -> None:
    first, second = open_tunnel("sbx_1"), open_tunnel("sbx_1", "b.example.com")
    other = open_tunnel("sbx_2")
    assert registry.sandbox_ids_with_tunnels() == ()
    assert registry.tunnels_of("sbx_1") == ()
    assert not registry.has_tunnels("sbx_1")

    assert registry.register(first) is first
    registry.register(second)
    registry.register(other)
    assert registry.tunnels_of("sbx_1") == (first, second)
    assert set(registry.sandbox_ids_with_tunnels()) == {"sbx_1", "sbx_2"}
    assert registry.has_tunnels("sbx_1")

    registry.unregister(first)
    assert registry.tunnels_of("sbx_1") == (second,)
    registry.unregister(second)
    registry.unregister(second)  # unregistering twice is harmless
    assert not registry.has_tunnels("sbx_1")
    assert registry.sandbox_ids_with_tunnels() == ("sbx_2",)


async def test_u2_name_tunnel_dropped_from_the_rules_is_cancelled(
    registry: TunnelRegistry, open_tunnel: Opener
) -> None:
    dropped = registry.register(open_tunnel(host="a.example.com"))
    kept = registry.register(open_tunnel(host="b.example.com"))
    covered = registry.register(open_tunnel(host="deep.api.example.org"))

    registry.recheck_sandbox("sbx_1", _entry("b.example.com", ".example.org"))

    assert await _cancelled(dropped, kept, covered) == [True, False, False]


async def test_u3_literal_tunnel_outside_every_cidr_is_cancelled(
    registry: TunnelRegistry, open_tunnel: Opener
) -> None:
    inside = registry.register(open_tunnel(host=LITERAL, address=LITERAL))
    outside = registry.register(open_tunnel(host="203.0.113.5", address="203.0.113.5"))
    beyond = registry.register(open_tunnel(host="198.51.100.200", address="198.51.100.200"))

    registry.recheck_sandbox("sbx_1", _entry("198.51.100.0/25", "203.0.113.4/30"))
    assert await _cancelled(inside, outside, beyond) == [False, False, True]

    registry.recheck_sandbox("sbx_1", _entry("api.example.com"))  # names never admit a literal
    assert await _cancelled(inside, outside) == [True, True]


async def test_a_name_tunnel_is_not_admitted_by_cidr_rules_alone(
    registry: TunnelRegistry, open_tunnel: Opener
) -> None:
    named = registry.register(open_tunnel(host="a.example.com", address=LITERAL))

    registry.recheck_sandbox("sbx_1", _entry("198.51.100.0/24"))

    assert await _cancelled(named) == [True]


async def test_u4_empty_rules_cancel_every_tunnel_of_the_sandbox_only(
    registry: TunnelRegistry, open_tunnel: Opener
) -> None:
    name = registry.register(open_tunnel(host="a.example.com"))
    literal = registry.register(open_tunnel(host=LITERAL, address=LITERAL, version=2))
    elsewhere = registry.register(open_tunnel("sbx_2"))

    registry.recheck_sandbox("sbx_1", _entry())

    assert await _cancelled(name, literal, elsewhere) == [True, True, False]


async def test_a_sandbox_without_tunnels_is_a_no_op(registry: TunnelRegistry) -> None:
    registry.recheck_sandbox("sbx_unknown", _entry())


async def test_u8_k8_found_false_cancels_every_tunnel_of_either_version(
    registry: TunnelRegistry, open_tunnel: Opener
) -> None:
    v1 = registry.register(open_tunnel(version=1))
    v2 = registry.register(open_tunnel(version=2))

    registry.recheck_sandbox("sbx_1", _entry("a.example.com", found=False))

    assert await _cancelled(v1, v2) == [True, True]


async def test_u9_an_epoch_change_cancels_v2_tunnels_of_the_old_epoch(
    registry: TunnelRegistry, open_tunnel: Opener
) -> None:
    old = registry.register(open_tunnel(version=2, epoch=1))
    current = registry.register(open_tunnel(version=2, epoch=2))
    v1 = registry.register(open_tunnel(version=1))

    registry.recheck_sandbox("sbx_1", _entry("a.example.com", epoch=2))

    assert await _cancelled(old, current, v1) == [True, False, False]


async def test_k7_generation_one_cancels_v1_tunnels_and_keeps_v2_ones(
    registry: TunnelRegistry, open_tunnel: Opener
) -> None:
    v1 = registry.register(open_tunnel(version=1))
    v2 = registry.register(open_tunnel(version=2, epoch=1, generation=1))

    registry.recheck_sandbox("sbx_1", _entry("a.example.com", generation=1, epoch=1))

    assert await _cancelled(v1, v2) == [True, False]


async def test_a_v1_tunnel_survives_a_generation_zero_row_that_still_admits_it(
    registry: TunnelRegistry, open_tunnel: Opener
) -> None:
    v1 = registry.register(open_tunnel(version=1))

    registry.recheck_sandbox("sbx_1", _entry("a.example.com", generation=0))

    assert await _cancelled(v1) == [False]


async def test_sweep_without_tunnels_sends_no_request(
    registry: TunnelRegistry, client: PolicyClient, route: Route
) -> None:
    await registry.sweep_once(client)

    assert route.sent == []


async def test_sweep_refreshes_every_sandbox_with_tunnels_and_the_change_closes_dropped_ones(
    registry: TunnelRegistry,
    client: PolicyClient,
    route: Route,
    clock: FakeClock,
    open_tunnel: Opener,
) -> None:
    dropped = registry.register(open_tunnel("sbx_1", "a.example.com", version=2))
    kept = registry.register(open_tunnel("sbx_1", "b.example.com", version=2))
    quiet = registry.register(open_tunnel("sbx_2", "c.example.com", version=2))
    route.policies["sbx_1"] = {
        "generation": 1,
        "epoch": 1,
        "rules": ["a.example.com", "b.example.com"],
    }
    route.policies["sbx_2"] = {"generation": 1, "epoch": 1, "rules": ["c.example.com"]}
    client.set_on_change(registry.recheck_sandbox)
    await client.refresh_many(["sbx_1", "sbx_2"])  # the entries the sweep will replace
    route.sent.clear()

    clock.now = 5.0
    route.policies["sbx_1"] = {"generation": 2, "epoch": 1, "rules": ["b.example.com"]}
    await registry.sweep_once(client)

    assert route.sent == [["sbx_1", "sbx_2"]]  # one batch for the whole node
    assert await _cancelled(dropped, kept, quiet) == [True, False, False]


async def test_a_successful_sweep_keeps_tunnels_of_a_sandbox_whose_policy_is_unchanged(
    registry: TunnelRegistry,
    client: PolicyClient,
    route: Route,
    clock: FakeClock,
    open_tunnel: Opener,
) -> None:
    route.policies["sbx_1"] = {"generation": 1, "epoch": 1, "rules": ["a.example.com"]}
    tunnel = registry.register(open_tunnel(version=2))
    client.set_on_change(registry.recheck_sandbox)

    for second in (5.0, 10.0, 200.0):
        clock.now = second
        await registry.sweep_once(client)

    assert await _cancelled(tunnel) == [False]


async def test_clause_4_tunnels_close_once_the_last_refresh_is_older_than_m(
    registry: TunnelRegistry,
    client: PolicyClient,
    route: Route,
    clock: FakeClock,
    open_tunnel: Opener,
) -> None:
    route.policies["sbx_1"] = {"generation": 1, "epoch": 1, "rules": ["a.example.com"]}
    tunnel = registry.register(open_tunnel(version=2))
    await registry.sweep_once(client)  # a successful refresh at 0
    route.failure = httpx.ConnectError("route down")

    clock.now = 60.0
    await registry.sweep_once(client)
    assert await _cancelled(tunnel) == [False]  # exactly M old: still within the bound

    clock.now = 61.0
    await registry.sweep_once(client)
    assert await _cancelled(tunnel) == [True]


async def test_clause_4_holds_when_the_refresh_raises_a_generic_exception(
    registry: TunnelRegistry,
    client: PolicyClient,
    route: Route,
    clock: FakeClock,
    open_tunnel: Opener,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route.policies["sbx_1"] = {"generation": 1, "epoch": 1, "rules": ["a.example.com"]}
    tunnel = registry.register(open_tunnel(version=2))
    await registry.sweep_once(client)  # a successful refresh at 0

    async def broken(sandbox_ids: Sequence[str]) -> None:
        raise RuntimeError("refresh blew up")

    monkeypatch.setattr(client, "refresh_many", broken)
    clock.now = 61.0  # older than M = 60
    with pytest.raises(RuntimeError):
        await registry.sweep_once(client)

    assert await _cancelled(tunnel) == [True]


async def test_a_sandbox_that_was_never_refreshed_is_closed_by_the_sweep(
    registry: TunnelRegistry, client: PolicyClient, route: Route, open_tunnel: Opener
) -> None:
    route.failure = httpx.ConnectError("route down")
    tunnel = registry.register(open_tunnel(version=2))

    await registry.sweep_once(client)

    assert await _cancelled(tunnel) == [True]
