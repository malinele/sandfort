"""v1 tokens against the policy lookup (docs/egress-v2-design.md 5.5, 12.7: K1, K5 to K9).

Also: ``auth`` parsing and dispatch, the C, L, M limits of ``proxy_limits`` (L < C), the sweep
loop, the ``admission`` wiring helpers and the 4.1.1 request-read and admission-cap budgets.
Policy route: httpx.MockTransport, fake clock, wire-contract signatures; loopback sockets.
"""

import asyncio
import base64
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any

import httpx
import pytest

from sandfort.egress import admission as adm
from sandfort.egress import auth
from sandfort.egress import proxy as proxy_module
from sandfort.egress import proxy_limits as limits
from sandfort.egress.policy_client import PolicyClient
from sandfort.egress.policy_wire import SIGNATURE_HEADER, response_key, sign_response
from sandfort.egress.proxy import EgressProxy, ProxyConfig, build_proxy, main
from sandfort.egress.relay import Deny
from sandfort.egress.tokens import LEGACY_TOKEN_CUTOVER, mint_egress_token
from sandfort.egress.tokens_v2 import mint_egress_token_v2
from sandfort.egress.tunnels import TunnelRegistry, sweep_while_serving

SECRET = "test-egress-secret"
SANDBOX = "sbx_1"
NAME = "echo.test"
NOW = 1_795_000_000
IO_TIMEOUT_S = 5.0


class Env:  # the simulated policy route (absent ids: found false) and a fake clock
    def __init__(self) -> None:
        self.policies: dict[str, dict[str, Any]] = {}
        self.sent: list[list[str]] = []
        self.resolved: list[str] = []
        self.unsigned = False  # an old api answers 404 without a signature
        self.now = 0.0

    def set(self, generation: int, epoch: int, rules: list[str]) -> None:
        self.policies[SANDBOX] = {"generation": generation, "epoch": epoch, "rules": rules}

    def handler(self, request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["sandbox_ids"]
        self.sent.append(ids)
        if self.unsigned:
            return httpx.Response(404, content=b'{"detail":"Not Found"}')
        records = [{"sandbox_id": i, "found": i in self.policies, **self.policies.get(i, {})}
                   for i in ids]  # fmt: skip
        body = json.dumps({"issued_at": NOW, "policies": records}).encode()
        signature = sign_response(response_key(SECRET), request.content, body, NOW)
        return httpx.Response(200, content=body, headers={SIGNATURE_HEADER: signature})

    def client(self, **overrides: Any) -> PolicyClient:
        settings: dict[str, Any] = {"cache_s": 5.0, "timeout_s": 2.0, "max_stale_s": 60.0}
        settings.update(transport=httpx.MockTransport(self.handler), clock=lambda: self.now)
        settings.update(overrides)
        return PolicyClient("http://policy.test", SECRET, now=lambda: NOW, **settings)


@pytest.fixture
def env() -> Env:
    return Env()


@pytest.fixture(autouse=True)
def _log_level(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")


@dataclass
class Harness:
    proxy: EgressProxy
    port: int
    upstream_port: int
    writers: list[asyncio.StreamWriter] = field(default_factory=list)

    async def connect(self, host: str, token: str) -> tuple[int, asyncio.StreamReader]:
        """CONNECT to ``host`` as the sandbox: the status (0 when closed unanswered), reader."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        raw = base64.b64encode(f"{SANDBOX}:{token}".encode()).decode("ascii")
        head = f"CONNECT {host}:{self.upstream_port} HTTP/1.1\r\nProxy-Authorization: Basic {raw}"
        writer.write(f"{head}\r\n\r\n".encode())
        answer = await asyncio.wait_for(reader.read(1024), IO_TIMEOUT_S)
        return (int(answer.split(b" ", 2)[1]) if answer else 0), reader


@asynccontextmanager
async def _serving(env: Env, *, policy: bool = True) -> AsyncIterator[Harness]:
    async def resolve(host: str) -> list[str]:
        env.resolved.append(host)
        return ["127.0.0.1"]

    async def idle_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read()
        writer.close()

    proxy = EgressProxy(SECRET, resolver=resolve, checker=lambda address: None,
                        policy_client=env.client() if policy else None)  # fmt: skip
    server = await proxy.start("127.0.0.1", 0)
    upstream = await asyncio.start_server(idle_upstream, "127.0.0.1", 0)
    harness = Harness(
        proxy, server.sockets[0].getsockname()[1], upstream.sockets[0].getsockname()[1]
    )
    try:
        yield harness
    finally:
        for writer in harness.writers:
            writer.close()
        for listener in (server, upstream):
            listener.close()
            await listener.wait_closed()


def _v1(*allow: str) -> str:
    return mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=allow, now=datetime.now(UTC))


async def _closed(reader: asyncio.StreamReader) -> bool:
    try:
        return await asyncio.wait_for(reader.read(1), IO_TIMEOUT_S) == b""
    except ConnectionError:
        return True


async def test_k1_without_a_policy_url_v1_claims_decide_with_zero_lookups(
    env: Env, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    lookups: list[object] = []
    monkeypatch.setattr(PolicyClient, "_post", lambda *args: lookups.append(args))
    async with _serving(env, policy=False) as harness:
        status, _ = await harness.connect(NAME, _v1(NAME))

    assert status == 200 and lookups == [] and env.sent == []
    assert "allow sandbox=sbx_1" in caplog.text and "gen=-" in caplog.text


def test_k1_build_proxy_logs_the_exact_startup_warning_without_the_policy_url(
    caplog: pytest.LogCaptureFixture,
) -> None:
    warning = (
        "egress policy URL is not set: v2 tokens get 503 and v1 tokens follow their claims"
        " with no revocation"
    )
    build_proxy(ProxyConfig("127.0.0.1", 3128, SECRET), discover=lambda: ())

    assert warning in [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


async def test_k5_generation_zero_row_decides_with_exactly_one_lookup(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    env.set(0, 0, [NAME])
    async with _serving(env) as harness:
        status, _ = await harness.connect(NAME, _v1(NAME))

    assert status == 200 and len(env.sent) == 1
    assert "allow sandbox=sbx_1" in caplog.text and "gen=0" in caplog.text


async def test_k6_the_row_decides_and_the_claims_are_ignored(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    env.set(0, 0, [NAME, "rowonly.test"])
    token = _v1(NAME, "claimed.test")
    async with _serving(env) as harness:
        claimed, _ = await harness.connect("claimed.test", token)
        in_row, _ = await harness.connect("rowonly.test", token)
        both, _ = await harness.connect(NAME, token)

    assert (claimed, in_row, both) == (403, 200, 200)
    assert (
        "reason=host is not in the allowlist" in caplog.text and "claimed.test" not in env.resolved
    )


async def _revoked(env: Env, harness: Harness, change: Any) -> tuple[bool, int]:
    """Open a v1 tunnel under generation 0, change the row, sweep: (tunnel closed, next CONNECT)."""
    env.set(0, 0, [NAME])
    status, tunnel = await harness.connect(NAME, _v1(NAME))
    assert status == 200 and harness.proxy.tunnels.has_tunnels(SANDBOX)
    change()
    env.now += 5.1
    await harness.proxy.sweep_once()
    again, _ = await harness.connect(NAME, _v1(NAME))
    return await _closed(tunnel) and harness.proxy.tunnels.sandbox_ids_with_tunnels() == (), again


async def test_k7_generation_one_supersedes_v1_and_closes_its_open_tunnel(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    async with _serving(env) as harness:
        closed, again = await _revoked(env, harness, lambda: env.set(1, 0, [NAME]))  # reset

    assert closed and again == 407 and "reason=v1 token superseded" in caplog.text


async def test_k8_not_found_is_407_and_closes_open_v1_tunnels_at_the_sweep(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    async with _serving(env) as harness:
        closed, again = await _revoked(env, harness, env.policies.clear)  # deleted

    assert closed and again == 407 and "reason=no policy for sandbox" in caplog.text


async def test_k9_an_unsigned_404_is_503_never_407_and_never_decided_by_the_claims(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    env.unsigned = True
    async with _serving(env) as harness:
        status, _ = await harness.connect(NAME, _v1(NAME))

    assert status == 503 and len(env.sent) == 1 and env.resolved == []
    assert "reason=egress policy unavailable" in caplog.text


async def test_sweep_while_serving_sweeps_each_interval_and_survives_a_failed_sweep(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    sweeps: list[int] = []

    class Registry:
        async def sweep_once(self, client: PolicyClient) -> None:
            sweeps.append(1)
            if len(sweeps) == 1:
                raise RuntimeError("boom")

    states = iter([True, True, True, True, False])
    client = env.client(cache_s=0.01)
    await asyncio.wait_for(sweep_while_serving(Registry(), client, lambda: next(states)), 5)  # type: ignore[arg-type]

    assert len(sweeps) == 2 and "egress sweep failed" in caplog.text


async def test_wiring_helpers_policy_client_from_and_wire_policy(env: Env) -> None:
    assert adm.policy_client_from(ProxyConfig("127.0.0.1", 3128, SECRET)) is None
    config = ProxyConfig("127.0.0.1", 3128, SECRET, policy_url="http://api:8000",
                         policy_cache_s=7, policy_timeout_s=3, policy_max_stale_s=90)  # fmt: skip
    built = adm.policy_client_from(config)
    assert built is not None
    assert (built.cache_s, built.timeout_s, built.max_stale_s) == (7, 3, 90)
    await built.aclose()

    registry, lookup_s = adm.wire_policy(None)  # K7 and K8 run the callback end to end
    assert isinstance(registry, TunnelRegistry) and lookup_s == limits.DEFAULT_POLICY_TIMEOUT_S == 2
    assert adm.wire_policy(env.client(timeout_s=3.0))[1] == 3.0


async def test_request_timeout_bounds_only_the_request_read(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(proxy_module, "REQUEST_TIMEOUT_S", 0.2)
    async with _serving(env, policy=False) as harness:
        real_open = harness.proxy._open

        async def slow_open(addresses: list[Any], port: int) -> Any:
            await asyncio.sleep(0.6)  # three times REQUEST_TIMEOUT_S, well inside the 38 s cap
            return await real_open(addresses, port)

        harness.proxy._open = slow_open  # type: ignore[method-assign]  # test seam
        reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
        started = time.monotonic()
        silent = await asyncio.wait_for(reader.read(1024), IO_TIMEOUT_S)  # sends nothing
        elapsed = time.monotonic() - started
        writer.close()
        slow, _ = await harness.connect(NAME, _v1(NAME))

    assert silent == b"" and 0.15 <= elapsed < IO_TIMEOUT_S  # closed after the read budget
    assert slow == 200  # an admission over the read budget is not cut off


async def test_the_admission_cap_wraps_everything_after_the_read(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    lookups: list[float] = []
    monkeypatch.setattr(proxy_module, "admission_cap_s", lambda s: lookups.append(s) or 0.3)
    async with _serving(env, policy=False) as harness:

        async def never(addresses: list[Any], port: int) -> Any:
            await asyncio.sleep(3600)

        harness.proxy._open = never  # type: ignore[method-assign]  # test seam
        started = time.monotonic()
        status, _ = await harness.connect(NAME, _v1(NAME))
        elapsed = time.monotonic() - started
        await asyncio.sleep(0.1)

        assert harness.proxy.open_connections == 0
    assert lookups == [float(limits.DEFAULT_POLICY_TIMEOUT_S)]
    assert status == 0 and 0.25 <= elapsed < IO_TIMEOUT_S


def _header(user: str, token: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode("ascii")


_authenticate = partial(
    auth.authenticate, SECRET, now=datetime.now(UTC), max_lifetime_s=None, legacy_before=None
)


@pytest.mark.parametrize(
    ("header", "detail"),
    [
        (None, "no credential"),
        ("Bearer abc", "credential is not basic"),
        ("Basic !!!", "credential is not decodable"),
        ("Basic " + base64.b64encode(b"sbx_1").decode(), "credential has no password"),
        (_header(SANDBOX, "garbage"), "invalid token"),
        (_header(SANDBOX, "sfe2_garbage"), "invalid token"),
        (_header("sbx_other", _v1(NAME)), "username does not match the token"),
    ],
)
def test_authenticate_refuses_with_a_407(header: str | None, detail: str) -> None:
    with pytest.raises(Deny) as raised:
        _authenticate(header)

    assert (raised.value.status, raised.value.detail) == (407, detail)


def test_authenticate_dispatches_on_the_token_prefix() -> None:
    v2 = mint_egress_token_v2(SECRET, sandbox_id=SANDBOX, epoch=3, now=datetime.now(UTC))
    first = _authenticate(_header(SANDBOX, _v1("a.test", "b.test")))
    second = _authenticate(_header(SANDBOX, v2))

    assert (first.version, first.allowlist, first.epoch) == (1, ("a.test", "b.test"), None)
    assert (second.version, second.allowlist, second.epoch) == (2, (), 3)


def test_note_legacy_logs_a_token_that_predates_the_cutover_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    old, now, week = LEGACY_TOKEN_CUTOVER - timedelta(days=10), datetime.now(UTC), 7 * 86400
    token = mint_egress_token(
        SECRET, sandbox_id=SANDBOX, allowlist=[NAME], now=old, ttl_s=34_560_000
    )
    kwargs: dict[str, Any] = {"max_lifetime_s": week}
    cut, noted = LEGACY_TOKEN_CUTOVER, set[str]()
    credential = auth.authenticate(
        SECRET, _header(SANDBOX, token), now=now, legacy_before=cut, **kwargs
    )

    for _ in range(2):
        auth.note_legacy(noted, credential, now, cutover=cut, **kwargs)

    records = [r for r in caplog.records if "accepted legacy egress token" in r.getMessage()]
    assert len(records) == 1 and noted == {SANDBOX}


def test_limit_names_defaults_and_values() -> None:
    assert (limits.ENV_POLICY_URL, limits.ENV_POLICY_CACHE_S) == (
        "SANDFORT_EGRESS_POLICY_URL", "SANDFORT_EGRESS_POLICY_CACHE_S")  # fmt: skip
    assert (limits.ENV_POLICY_TIMEOUT_S, limits.ENV_POLICY_MAX_STALE_S) == (
        "SANDFORT_EGRESS_POLICY_TIMEOUT_S", "SANDFORT_EGRESS_POLICY_MAX_STALE_S")  # fmt: skip
    assert (limits.DEFAULT_POLICY_CACHE_S, limits.DEFAULT_POLICY_TIMEOUT_S) == (5, 2)
    assert limits.DEFAULT_POLICY_MAX_STALE_S == 60
    base = {"SANDFORT_EGRESS_SECRET": SECRET}
    config = ProxyConfig.from_env(base)
    assert (config.policy_url, config.policy_cache_s) == ("", 5)
    assert (config.policy_timeout_s, config.policy_max_stale_s) == (2, 60)
    environ = {limits.ENV_POLICY_URL: "http://api:8000", limits.ENV_POLICY_CACHE_S: "10"}
    environ.update({limits.ENV_POLICY_TIMEOUT_S: "9", limits.ENV_POLICY_MAX_STALE_S: "10"})
    config = ProxyConfig.from_env({**base, **environ})
    assert (config.policy_url, config.policy_cache_s) == ("http://api:8000", 10)
    assert (config.policy_timeout_s, config.policy_max_stale_s) == (9, 10)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"CACHE": "5", "TIMEOUT": "5"}, "SANDFORT_EGRESS_POLICY_TIMEOUT_S must be less than"),
        ({"CACHE": "3", "TIMEOUT": "4"}, "SANDFORT_EGRESS_POLICY_TIMEOUT_S must be less than"),
        ({"CACHE": "10", "MAX_STALE": "9"}, "SANDFORT_EGRESS_POLICY_MAX_STALE_S must be at least"),
        ({"CACHE": "1"}, "SANDFORT_EGRESS_POLICY_CACHE_S must be an integer 2..60"),
        ({"CACHE": "61"}, "SANDFORT_EGRESS_POLICY_CACHE_S must be an integer 2..60"),
        ({"TIMEOUT": "0"}, "SANDFORT_EGRESS_POLICY_TIMEOUT_S must be an integer 1..10"),
        ({"TIMEOUT": "11"}, "SANDFORT_EGRESS_POLICY_TIMEOUT_S must be an integer 1..10"),
    ],
)
def test_invalid_c_l_m_fail_startup(overrides: dict[str, str], message: str) -> None:
    environ = {"SANDFORT_EGRESS_SECRET": SECRET}
    environ.update({f"SANDFORT_EGRESS_POLICY_{key}_S": value for key, value in overrides.items()})

    with pytest.raises(ValueError, match=message):
        ProxyConfig.from_env(environ)
    assert main(environ) == 2
