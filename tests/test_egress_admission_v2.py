"""Admission budgets, the decision table and the step 11 re-check (egress v2 round 2).

Contract: docs/egress-v2-design.md 4.1, 4.1.1, 4.2.1, 12.2 (P9) and 12.3 (U12, U13). The policy
route is httpx.MockTransport under a fake clock, signed with the wire contract; the budget
tests shrink the module constants and assert the real values separately.
"""

import asyncio
import base64
import json
import logging
import time
import types
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

import httpx
import pytest

from sandfort.egress import admission as adm
from sandfort.egress import proxy as proxy_module
from sandfort.egress import upstream as upstream_module
from sandfort.egress.auth import EgressCredential
from sandfort.egress.policy_client import PolicyClient, PolicyEntry
from sandfort.egress.policy_wire import SIGNATURE_HEADER, response_key, sign_response
from sandfort.egress.proxy import EgressProxy
from sandfort.egress.relay import Deny
from sandfort.egress.tokens import mint_egress_token
from sandfort.egress.tunnels import TunnelRegistry

SECRET = "test-egress-secret"
SANDBOX = "sbx_1"
NAME = "echo.test"
NOW = 1_795_000_000
ISSUED = datetime(2026, 11, 24, tzinfo=UTC)
IO_TIMEOUT_S = 5.0
A, B, CIDR, LITERAL = "a.example.com", "b.example.com", "198.51.100.0/24", "198.51.100.7"
UNAVAILABLE, NO_POLICY = "egress policy unavailable", "no policy for sandbox"
HOST_REFUSED = "host is not in the allowlist"
ADDRESS_REFUSED = "address is not in the allowlist"
CONNECTED = ip_address("203.0.113.9")


class Env:  # the simulated policy route (absent ids: found false) and a fake clock
    def __init__(self) -> None:
        self.policies: dict[str, dict[str, Any]] = {}
        self.sent: list[list[str]] = []
        self.failure: Exception | None = None
        self.now = 0.0
        self.made: list[PolicyClient] = []

    def set(self, generation: int, epoch: int, rules: list[str]) -> None:
        self.policies[SANDBOX] = {"generation": generation, "epoch": epoch, "rules": rules}

    def handler(self, request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["sandbox_ids"]
        self.sent.append(ids)
        if self.failure is not None:
            raise self.failure
        records = [{"sandbox_id": i, "found": i in self.policies, **self.policies.get(i, {})}
                   for i in ids]  # fmt: skip
        body = json.dumps({"issued_at": NOW, "policies": records}).encode()
        signature = sign_response(response_key(SECRET), request.content, body, NOW)
        return httpx.Response(200, content=body, headers={SIGNATURE_HEADER: signature})

    def client(self, **overrides: Any) -> PolicyClient:
        settings: dict[str, Any] = {"cache_s": 5.0, "timeout_s": 2.0, "max_stale_s": 60.0}
        settings.update(transport=httpx.MockTransport(self.handler), clock=lambda: self.now)
        self.made.append(
            PolicyClient("http://policy.test", SECRET, now=lambda: NOW, **{**settings, **overrides})
        )
        return self.made[-1]


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    environment = Env()
    yield environment
    for client in environment.made:
        await client.aclose()


def _v1(*allow: str) -> EgressCredential:
    return EgressCredential(SANDBOX, 1, allow, None, ISSUED, ISSUED + timedelta(days=1))


def _v2(epoch: int) -> EgressCredential:
    return EgressCredential(SANDBOX, 2, (), epoch, ISSUED, ISSUED + timedelta(days=1))


def _entry(found: bool = True, generation: int = 0, epoch: int = 0, *rules: str) -> PolicyEntry:
    return PolicyEntry(found, generation, epoch, rules, 0.0)


# ---- the cap and decide: the decision table of section 4.1 step 5 ---------------------------


def test_budget_constants_and_the_cap() -> None:
    assert (upstream_module.RESOLVE_TIMEOUT_S, upstream_module.CONNECT_TIMEOUT_S) == (5.0, 10.0)
    assert (upstream_module.CONNECT_ROUND_S, proxy_module.REQUEST_TIMEOUT_S) == (12.0, 15.0)
    assert (adm.admission_cap_s(2.0), adm.admission_cap_s(3.0)) == (38.0, 40.0)  # 2L + 10 + 24


@pytest.mark.parametrize(
    "case",
    [
        (_v2(1), None, False, 503, UNAVAILABLE),
        (_v1(A), _entry(False), True, 407, NO_POLICY),
        (_v2(1), _entry(False), True, 407, NO_POLICY),
        (_v2(1), _entry(True, 3, 2, A), True, 407, "credential epoch mismatch"),
        (_v1(A), _entry(True, 1, 0, A), True, 407, "v1 token superseded"),
        (_v1(A), _entry(True, 9, 0, A), True, 407, "v1 token superseded"),
    ],
)
def test_decide_refusals(case: Any) -> None:
    credential, entry, configured, status, detail = case
    with pytest.raises(Deny) as raised:
        adm.decide(credential, entry, policy_configured=configured)

    assert (raised.value.status, raised.value.detail) == (status, detail)
    assert ("Proxy-Authenticate" in raised.value.headers) == (status == 407)


def test_decide_v1_without_policy_follows_its_claims_with_gen_dash() -> None:
    rules, generation = adm.decide(_v1("claimed.test"), None, policy_configured=False)

    assert rules.admits_name("claimed.test") and not rules.admits_name("other.test")
    assert generation == "-"


def test_decide_v1_generation_zero_uses_the_row_not_the_claims() -> None:
    entry = _entry(True, 0, 0, A, CIDR)
    rules, generation = adm.decide(_v1("claimed.test"), entry, policy_configured=True)

    assert rules.admits_name(A) and rules.admits_address(ip_address(LITERAL))
    assert not rules.admits_name("claimed.test")
    assert generation == "0"


class FakeWriter:
    closed = False

    def get_extra_info(self, name: str, default: object = None) -> object:
        return (str(CONNECTED), 443) if name == "peername" else default

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class Steps:
    def __init__(self, during: Callable[[], Awaitable[None]] | None = None) -> None:
        self.calls: list[str] = []
        self.during, self.failing, self.writer = during, "", FakeWriter()

    def take_slot(self) -> None:
        self.calls.append("slot")
        if self.failing == "slot":
            raise Deny(429, "Too Many Requests", "slot refused")

    async def dial(self) -> tuple[Any, list[Any]]:
        self.calls.append("dial")
        if self.failing == "dial":
            raise Deny(502, "Bad Gateway", "dial refused")
        if self.during is not None:
            await self.during()
        return (object(), self.writer), [ip_address("198.51.100.8")]


async def _admit(
    credential: EgressCredential,
    steps: Steps,
    client: PolicyClient | None,
    tunnels: TunnelRegistry,
    seen: adm.Seen | None = None,
    host: str = A,
) -> Any:
    literal = ip_address(host) if host[0].isdigit() else None
    return await adm.admit_target(
        credential, seen or adm.Seen(), policy=client, tunnels=tunnels, host=host,
        address=literal, port=443, take_slot=steps.take_slot, dial=steps.dial,
    )  # fmt: skip


def _slow_connect(env: Env, change: Callable[[], None]) -> Callable[[], Awaitable[None]]:
    # the 12 s connect of U12: the route changes as it starts, the clock moves 12 s
    async def during() -> None:
        change()
        env.now += 12.0

    return during


async def test_v1_without_policy_is_admitted_on_claims_and_registered() -> None:
    tunnels, steps, seen = TunnelRegistry(), Steps(), adm.Seen()

    upstream = await _admit(_v1(A), steps, None, tunnels, seen)

    assert upstream[1] is steps.writer and steps.calls == ["slot", "dial"]
    assert seen.gen == "-" and seen.slot_held
    (record,) = tunnels.tunnels_of(SANDBOX)
    assert seen.tunnel is record
    assert (record.host, record.address, record.port) == (A, CONNECTED, 443)
    assert (record.generation, record.token_version, record.epoch) == (0, 1, None)
    assert record.task is asyncio.current_task()


@pytest.mark.parametrize(
    "case",
    [
        (_v1(A), A, None, 407, NO_POLICY),
        (_v2(1), B, (1, 1, [A]), 403, HOST_REFUSED),
        (_v2(1), A, (1, 1, [CIDR]), 403, HOST_REFUSED),
        (_v2(1), LITERAL, (1, 1, [LITERAL]), 403, ADDRESS_REFUSED),
    ],
)
async def test_step_5_and_6_refusals_cost_no_slot_and_no_dial(env: Env, case: Any) -> None:
    credential, host, row, status, detail = case
    if row is not None:
        env.set(*row)
    tunnels, steps = TunnelRegistry(), Steps()

    with pytest.raises(Deny) as raised:
        await _admit(credential, steps, env.client(), tunnels, host=host)

    assert (raised.value.status, raised.value.detail) == (status, detail)
    assert steps.calls == [] and tunnels.sandbox_ids_with_tunnels() == ()


@pytest.mark.parametrize("failing", ["slot", "dial"])
async def test_a_refused_slot_or_failed_dial_propagates(env: Env, failing: str) -> None:
    env.set(1, 1, [A])
    steps, seen, tunnels = Steps(), adm.Seen(), TunnelRegistry()
    steps.failing = failing

    with pytest.raises(Deny) as raised:
        await _admit(_v2(1), steps, env.client(), tunnels, seen)

    assert raised.value.detail == f"{failing} refused"
    assert seen.slot_held == (failing == "dial")  # the caller releases it on the dial path
    assert seen.upstream is None and tunnels.sandbox_ids_with_tunnels() == ()


@pytest.mark.parametrize(
    "case",
    [
        (_v2(1), A, (2, 1, [B]), 403, HOST_REFUSED),  # U12: the PATCH dropped the name
        (_v2(1), LITERAL, (2, 1, [A]), 403, ADDRESS_REFUSED),  # the CIDR rule went away
        (_v2(1), A, (1, 2, [A]), 407, "credential epoch mismatch"),
        (_v1(A), A, (1, 0, [A]), 407, "v1 token superseded"),
        (_v2(1), A, None, 407, NO_POLICY),
        (_v2(1), A, "down", 503, UNAVAILABLE),
    ],
)
async def test_step_11_refuses_and_closes_the_upstream_first(env: Env, case: Any) -> None:
    credential, host, change, status, detail = case
    env.set(0 if credential.version == 1 else 1, 1, [A, CIDR])

    def apply() -> None:
        if change == "down":
            env.failure = httpx.ConnectError("down")
        elif change is None:
            env.policies.clear()
        else:
            env.set(*change)

    steps, seen, tunnels = Steps(_slow_connect(env, apply)), adm.Seen(), TunnelRegistry()

    with pytest.raises(Deny) as raised:
        await _admit(credential, steps, env.client(), tunnels, seen, host)

    assert (raised.value.status, raised.value.detail) == (status, detail)
    assert steps.writer.closed  # closed before the refusal reached the caller
    assert seen.upstream is None and seen.tunnel is None
    assert tunnels.sandbox_ids_with_tunnels() == ()


async def test_u13_a_widened_policy_is_admitted_under_the_new_generation(env: Env) -> None:
    env.set(1, 1, [A])
    steps = Steps(_slow_connect(env, lambda: env.set(2, 1, [A, B])))
    seen, tunnels = adm.Seen(), TunnelRegistry()

    await _admit(_v2(1), steps, env.client(), tunnels, seen)

    assert len(env.sent) == 2  # the stale entry was refreshed at step 11
    assert seen.gen == "2" and tunnels.tunnels_of(SANDBOX)[0].generation == 2
    assert not steps.writer.closed


async def test_step_11_uses_the_current_entry_not_the_one_step_5_used(env: Env) -> None:
    env.set(1, 1, [A])
    client = env.client()

    async def another_connect_refreshes() -> None:  # a sweep or another CONNECT lands newer data
        env.set(2, 1, [B])
        env.now += 1.0
        await client.refresh_many([SANDBOX])

    with pytest.raises(Deny) as raised:
        await _admit(_v2(1), Steps(another_connect_refreshes), client, TunnelRegistry())

    assert raised.value.detail == HOST_REFUSED
    assert len(env.sent) == 2  # lookup and refresh; step 11 found a fresh entry, no third


async def test_recheck_without_a_policy_matches_only_the_claims() -> None:
    assert await adm.recheck(_v1(A), None, sandbox_id=SANDBOX, host=A, address=None) is None

    with pytest.raises(Deny) as raised:
        await adm.recheck(_v1(A), None, sandbox_id=SANDBOX, host=B, address=None)
    assert raised.value.detail == HOST_REFUSED


# ---- P9 and the REQUEST_TIMEOUT_S split, end to end over loopback ----------------------------


async def _loopback(host: str) -> list[str]:
    return ["127.0.0.1"]


def _proxy(**kwargs: Any) -> EgressProxy:
    kwargs.setdefault("resolver", _loopback)
    return EgressProxy(SECRET, checker=lambda address: None, **kwargs)


async def _answer(proxy: EgressProxy, target: str | None) -> tuple[bytes, float]:
    """CONNECT ``target`` with a v1 token for ``NAME`` (``None``: send nothing); first chunk."""
    token = mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=[NAME], now=datetime.now(UTC))
    credential = base64.b64encode(f"{SANDBOX}:{token}".encode()).decode("ascii")
    server = await proxy.start("127.0.0.1", 0)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", _port(server))
        if target is not None:
            head = f"CONNECT {target} HTTP/1.1\r\nProxy-Authorization: Basic {credential}\r\n\r\n"
            writer.write(head.encode())
        started = time.monotonic()
        answer = await asyncio.wait_for(reader.read(1024), IO_TIMEOUT_S)
        writer.close()
        return answer, time.monotonic() - started
    finally:
        server.close()
        await server.wait_closed()


def _port(server: asyncio.Server) -> int:
    return int(server.sockets[0].getsockname()[1])


async def test_p9_a_hung_resolver_is_502_after_the_resolve_budget(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    monkeypatch.setattr(upstream_module, "RESOLVE_TIMEOUT_S", 0.2)

    async def hangs(host: str) -> list[str]:
        await asyncio.sleep(3600)
        return []

    proxy = _proxy(resolver=hangs)
    raw, elapsed = await _answer(proxy, f"{NAME}:443")

    assert raw.split(b" ", 2)[1] == b"502" and 0.15 <= elapsed < IO_TIMEOUT_S
    assert "reason=host does not resolve" in caplog.text
    assert proxy.tunnels.sandbox_ids_with_tunnels() == ()


async def test_p9_a_slow_opener_is_cut_by_the_round_not_the_per_address_timeout(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    monkeypatch.setattr(upstream_module, "CONNECT_ROUND_S", 0.25)
    monkeypatch.setattr(upstream_module, "CONNECT_TIMEOUT_S", 0.2)
    attempts: list[str] = []

    async def slow_failure(host: str, port: int) -> None:
        attempts.append(host)
        await asyncio.sleep(0.1)  # under the per-address timeout, yet each attempt fails
        raise OSError("unreachable")

    names = {"get_running_loop": asyncio.get_running_loop, "wait_for": asyncio.wait_for}
    shim = types.SimpleNamespace(**names, open_connection=slow_failure)
    monkeypatch.setattr(upstream_module, "asyncio", shim)

    async def eight(host: str) -> list[str]:
        return ["127.0.0.1"] * 8

    proxy = _proxy(resolver=eight)
    raw, _ = await _answer(proxy, f"{NAME}:443")

    assert raw.split(b" ", 2)[1] == b"502"
    assert "reason=upstream connection failed" in caplog.text
    assert 1 <= len(attempts) <= 4  # eight sequential 0.1 s attempts would take 0.8 s
    assert proxy.tunnels.sandbox_ids_with_tunnels() == ()
