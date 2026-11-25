"""Egress proxy policy channel end to end (round 2; design 4.1, 5.2, 5.3; case ids U1 to U16).

Hermetic: loopback client sockets, a mock upstream (the ``_open`` seam), httpx.MockTransport for
the policy route (signed with the real ``policy_wire`` helper) and a fake clock. A "PATCH" is a
change in what the route returns.
"""

import asyncio
import base64
import json
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from sandfort.egress.admission import NO_POLICY_WARNING
from sandfort.egress.logname import redacted_name
from sandfort.egress.policy_client import PolicyClient
from sandfort.egress.policy_wire import SIGNATURE_HEADER, response_key, sign_response
from sandfort.egress.proxy import EgressProxy, ProxyConfig, build_proxy
from sandfort.egress.tokens import mint_egress_token
from sandfort.egress.tokens_v2 import mint_egress_token_v2
from sandfort.webhooks import ssrf

SECRET = "test-egress-secret"
SANDBOX = "sbx_test"
NOW = 1_795_000_000  # pinned wall time for the MACs
PUBLIC = "93.184.216.34"
SLOW_CONNECT_S = 12.0  # a slow upstream, longer than the cache window
IO_TIMEOUT_S = 5.0
UNAVAILABLE = "status=503 reason=egress policy unavailable gen=-"


@pytest.fixture(autouse=True)
def _setup(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setattr(ssrf, "_allow_private_networks", False)
    caplog.set_level(logging.INFO, logger="sandfort.egress")


def _permit_all(address: ssrf.IpAddress) -> None:
    """Stands in for the public-address rules."""


class _Route:
    """The simulated internal policy route; ``mode`` picks how it misbehaves."""

    def __init__(self) -> None:
        self.record: dict[str, Any] = {"sandbox_id": SANDBOX, "found": False}
        self.calls: list[list[str]] = []
        self.mode = "ok"

    def set(self, rules: list[str], *, generation: int = 1, epoch: int = 1) -> None:
        self.record = {"sandbox_id": SANDBOX, "found": True, "rules": rules}
        self.record.update(generation=generation, epoch=epoch)

    def patch(self, rules: list[str], *, epoch: int = 1) -> None:
        self.set(rules, generation=self.record["generation"] + 1, epoch=epoch)

    def remove(self) -> None:
        self.record = {"sandbox_id": SANDBOX, "found": False}

    async def handle(self, request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["sandbox_ids"]
        self.calls.append(ids)
        if self.mode == "hang":
            await asyncio.sleep(30)
        elif self.mode == "error":
            raise httpx.ConnectError("unreachable", request=request)
        if self.mode == "404":  # an api that predates the route answers unsigned
            return httpx.Response(404, content=b'{"detail":"Not Found"}')
        body = json.dumps({"issued_at": NOW, "policies": [self.record]}).encode()
        stamp = NOW - 31 if self.mode == "stale" else NOW
        key = response_key("another-secret" if self.mode == "badsig" else SECRET)
        signature = sign_response(key, request.content, body, stamp)  # bound to this request
        return httpx.Response(200, content=body, headers={SIGNATURE_HEADER: signature})


class _Answer:
    def __init__(self, head: bytes, reader: asyncio.StreamReader, writer: Any) -> None:
        self.status = int(head.split(b" ", 2)[1])
        self.head, self.reader, self.writer = head, reader, writer

    async def closed_by_proxy(self) -> bool:
        try:
            return await asyncio.wait_for(self.reader.read(1), IO_TIMEOUT_S) == b""
        except ConnectionError:
            return True


class _Env:
    def __init__(self, *, policy: bool, timeout_s: float) -> None:
        self.now = 1000.0  # the fake monotonic clock
        self.route = _Route()
        self.resolved: list[str] = []
        self.opened: list[tuple[list[Any], int]] = []
        self.upstreams: list[MagicMock] = []
        self.while_connecting: Callable[[], None] | None = None
        self.client = (
            PolicyClient(
                "http://api.internal:8000",
                SECRET,
                cache_s=5,
                timeout_s=timeout_s,
                max_stale_s=60,
                transport=httpx.MockTransport(self.route.handle),
                clock=lambda: self.now,
                now=lambda: NOW,
            )
            if policy
            else None
        )
        self.proxy = EgressProxy(
            SECRET,
            resolver=self._resolve,
            checker=_permit_all,
            allowed_ports={443},
            policy_client=self.client,
        )
        self.proxy._open = self._open  # type: ignore[method-assign]  # test seam
        self.port = 0
        self.answers: list[_Answer] = []

    async def _resolve(self, host: str) -> list[str]:
        self.resolved.append(host)
        return [PUBLIC]

    async def _open(self, addresses: list[Any], port: int) -> Any:
        self.opened.append((addresses, port))
        if self.while_connecting is not None:
            self.while_connecting()
        upstream = MagicMock(drain=AsyncMock(), wait_closed=AsyncMock())
        upstream.get_extra_info.return_value = None  # the proxy falls back to the vetted address
        self.upstreams.append(upstream)
        return asyncio.StreamReader(), upstream

    async def connect(self, target: str, token: str | None = None) -> _Answer:
        credential = base64.b64encode(f"{SANDBOX}:{token or self.v2()}".encode()).decode()
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        request = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
        writer.write(f"{request}Proxy-Authorization: Basic {credential}\r\n\r\n".encode())
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT_S)
        self.answers.append(_Answer(head, reader, writer))
        return self.answers[-1]

    @staticmethod
    def v2(epoch: int = 1) -> str:
        return mint_egress_token_v2(SECRET, sandbox_id=SANDBOX, epoch=epoch, now=datetime.now(UTC))

    @staticmethod
    def v1(allowlist: list[str]) -> str:
        now = datetime.now(UTC)
        return mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=allowlist, now=now)

    def hosts(self) -> list[str]:
        return [record.host for record in self.proxy.tunnels.tunnels_of(SANDBOX)]

    def patch_during_slow_connect(self, rules: list[str]) -> None:
        """The next upstream connect takes 12 s, and a PATCH to ``rules`` lands meanwhile."""

        def during() -> None:
            self.route.patch(rules)
            self.now += SLOW_CONNECT_S

        self.while_connecting = during


@asynccontextmanager
async def _env(*, policy: bool = True, timeout_s: float = 2.0) -> AsyncIterator[_Env]:
    env = _Env(policy=policy, timeout_s=timeout_s)
    server = await env.proxy.start("127.0.0.1", 0)
    env.port = int(server.sockets[0].getsockname()[1])
    try:
        yield env
    finally:
        for answer in env.answers:
            answer.writer.close()
        server.close()
        await server.wait_closed()
        if env.client is not None:
            await env.client.aclose()


def _lines(caplog: pytest.LogCaptureFixture, prefix: str) -> list[str]:
    return [message for message in caplog.messages if message.startswith(prefix)]


async def test_v2_token_with_found_policy_and_matching_epoch_admits_per_rules(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with _env() as env:
        env.route.set(["a.example.com"], generation=4)
        allowed = await env.connect("a.example.com:443")
        refused = await env.connect("z.example.com:443")
    assert (allowed.status, refused.status) == (200, 403)
    assert env.opened == [([ip_address(PUBLIC)], 443)]
    assert _lines(caplog, "allow")[-1] == "allow sandbox=sbx_test host='a.example.com' gen=4"
    assert _lines(caplog, "deny")[-1] == (
        f"deny sandbox=sbx_test host={redacted_name(SECRET, 'z.example.com')} status=403"
        " reason=host is not in the allowlist gen=4"
    )
    assert env.route.calls == [[SANDBOX]]  # the second CONNECT used the fresh cache entry


@pytest.mark.parametrize(
    ("found", "route_epoch", "reason"),
    [(False, 1, "no policy for sandbox"), (True, 2, "credential epoch mismatch")],
)
async def test_missing_policy_and_epoch_mismatch_are_407(
    found: bool, route_epoch: int, reason: str, caplog: pytest.LogCaptureFixture
) -> None:
    async with _env() as env:
        env.route.set(["a.example.com"], epoch=route_epoch)
        if not found:
            env.route.remove()
        answer = await env.connect("a.example.com:443", env.v2(epoch=1))
    assert answer.status == 407
    assert b'Proxy-Authenticate: Basic realm="sandfort-egress"' in answer.head
    assert f"status=407 reason={reason} gen=" in _lines(caplog, "deny")[-1]
    assert env.opened == []


@pytest.mark.parametrize("mode", ["hang", "error", "badsig", "stale", "404"])
async def test_lookup_failures_are_503_unavailable_never_a_policy_answer(
    mode: str, caplog: pytest.LogCaptureFixture
) -> None:
    async with _env(timeout_s=0.1) as env:
        env.route.set(["a.example.com"])
        env.route.mode = mode  # timeout, transport error, bad or stale MAC, unsigned 404
        answer = await env.connect("a.example.com:443")
    assert answer.status == 503  # an unsigned 404 is not "found: false" (407)
    assert _lines(caplog, "deny")[-1].endswith(UNAVAILABLE)
    assert env.route.calls == [[SANDBOX]]
    assert env.opened == [] and env.resolved == []


def test_build_proxy_logs_the_exact_startup_warning_only_when_the_url_is_unset(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def warnings() -> list[str]:
        return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]

    build_proxy(ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET}), discover=lambda: [])
    assert warnings() == [NO_POLICY_WARNING]
    assert NO_POLICY_WARNING == (
        "egress policy URL is not set: v2 tokens get 503 and v1 tokens follow their claims"
        " with no revocation"
    )
    caplog.clear()
    environ = {"SANDFORT_EGRESS_SECRET": SECRET, "SANDFORT_EGRESS_POLICY_URL": "http://api:8000"}
    build_proxy(ProxyConfig.from_env(environ), discover=lambda: [])
    assert warnings() == []


async def test_a_refused_port_costs_no_lookup() -> None:
    async with _env() as env:
        env.route.set(["a.example.com"])
        answer = await env.connect("a.example.com:8443")
    assert answer.status == 403
    assert env.route.calls == []  # the mock transport saw zero requests
    assert env.resolved == [] and env.opened == []


async def test_policy_url_unset_v2_gets_503_and_v1_follows_claims_with_gen_dash(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with _env(policy=False) as env:
        v2 = await env.connect("a.example.com:443")
        allowed = await env.connect("a.example.com:443", env.v1(["a.example.com"]))
        refused = await env.connect("z.example.com:443", env.v1(["a.example.com"]))
    assert (v2.status, allowed.status, refused.status) == (503, 200, 403)
    deny, allow = _lines(caplog, "deny"), _lines(caplog, "allow")
    assert deny[0].endswith(UNAVAILABLE)
    assert deny[1].endswith("reason=host is not in the allowlist gen=-")
    assert allow[-1].endswith(" gen=-")
    assert len(env.opened) == 1


async def test_u1_a_patch_reaches_new_connections_within_the_cache_window() -> None:
    async with _env() as env:
        env.route.set(["a.example.com"])
        before = await env.connect("b.example.com:443")
        env.route.patch(["a.example.com", "b.example.com"])  # the PATCH, at T
        env.now += 1
        within_window = await env.connect("b.example.com:443")  # entry fetched before T
        env.now += 4.1
        after_window = await env.connect("b.example.com:443")  # T + 5.1
    assert (before.status, within_window.status, after_window.status) == (403, 403, 200)
    assert len(env.route.calls) == 2
    assert env.opened == [([ip_address(PUBLIC)], 443)]


async def test_u2_u3_dropped_name_and_cidr_cancel_their_tunnels_and_keep_the_others() -> None:
    async with _env() as env:
        env.route.set(["a.example.com", "c.example.com", "198.51.100.0/24"])
        gone = await env.connect("a.example.com:443")
        kept = await env.connect("c.example.com:443")
        literal = await env.connect("198.51.100.7:443")
        assert env.hosts() == ["a.example.com", "c.example.com", "198.51.100.7"]
        env.route.patch(["c.example.com"])  # drops the name and the CIDR
        env.now += 6  # T + 6: the next sweep
        await env.proxy.sweep_once()
        assert await gone.closed_by_proxy() and await literal.closed_by_proxy()
        assert env.hosts() == ["c.example.com"]
        assert [u.close.called for u in env.upstreams] == [True, False, True]
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(kept.reader.read(1), 0.1)  # still open
    assert env.resolved == ["a.example.com", "c.example.com"]  # the literal was never resolved


async def test_u4_empty_rules_cancel_every_tunnel_and_refuse_every_connect() -> None:
    async with _env() as env:
        env.route.set(["a.example.com", "c.example.com"])
        first = await env.connect("a.example.com:443")
        second = await env.connect("c.example.com:443")
        env.route.patch([])
        env.now += 6
        await env.proxy.sweep_once()
        refused = await env.connect("a.example.com:443")
        assert await first.closed_by_proxy() and await second.closed_by_proxy()
        assert env.hosts() == []
    assert refused.status == 403


async def test_u8_found_false_cancels_tunnels_at_the_next_sweep_and_refuses_connects() -> None:
    async with _env() as env:
        env.route.set(["a.example.com"])
        tunnel = await env.connect("a.example.com:443")
        env.route.remove()
        env.now += 6
        await env.proxy.sweep_once()
        refused = await env.connect("a.example.com:443")  # answered from the sweep's entry
        assert await tunnel.closed_by_proxy()
    assert refused.status == 407
    assert len(env.route.calls) == 2  # the connect did not look up again


async def test_u9_epoch_change_is_407_within_the_window_and_closes_old_tunnels() -> None:
    async with _env() as env:
        env.route.set(["a.example.com"], epoch=1)
        old = await env.connect("a.example.com:443", env.v2(epoch=1))
        env.route.patch(["a.example.com"], epoch=2)
        env.now += 5.1  # past C
        refused = await env.connect("a.example.com:443", env.v2(epoch=1))
        assert await old.closed_by_proxy()  # the refresh changed the epoch: re-checked at once
    assert refused.status == 407


@pytest.mark.parametrize(
    ("rules", "status", "upstream_closed"),
    [
        pytest.param(["other.example.com"], 403, True, id="u12_name_removed_is_refused"),
        pytest.param(["a.example.com", "b.example.com"], 200, False, id="u13_entry_added_is_kept"),
    ],
)
async def test_u12_u13_a_patch_landing_during_a_slow_connect_is_applied_at_the_recheck(
    rules: list[str], status: int, upstream_closed: bool, caplog: pytest.LogCaptureFixture
) -> None:
    async with _env() as env:
        env.route.set(["a.example.com"], generation=1)
        env.patch_during_slow_connect(rules)
        answer = await env.connect("a.example.com:443")
        # admitted: registered under the new generation; refused: nothing registered
        assert [r.generation for r in env.proxy.tunnels.tunnels_of(SANDBOX)] == (
            [2] if status == 200 else []
        )
        assert env.upstreams[0].close.called is upstream_closed
    assert answer.status == status
    assert len(env.route.calls) == 2  # the re-check refreshed the stale entry
    last = _lines(caplog, "allow" if status == 200 else "deny")[-1]
    # both lines name the generation that decided: the re-check read generation 2 either way
    assert last.endswith(" gen=2" if status == 200 else "reason=host is not in the allowlist gen=2")


async def test_u15_a_recheck_refresh_with_a_new_generation_rechecks_other_tunnels_at_once() -> None:
    async with _env() as env:
        env.route.set(["a.example.com", "c.example.com"])
        other = await env.connect("c.example.com:443")  # open before the change
        env.patch_during_slow_connect(["a.example.com"])
        answer = await env.connect("a.example.com:443")  # no sweep runs in this test
        assert answer.status == 200
        assert await other.closed_by_proxy()
        assert env.hosts() == ["a.example.com"]


def test_u16_a_lookup_timeout_not_less_than_the_cache_window_fails_startup() -> None:
    environ = {
        "SANDFORT_EGRESS_SECRET": SECRET,
        "SANDFORT_EGRESS_POLICY_TIMEOUT_S": "5",
        "SANDFORT_EGRESS_POLICY_CACHE_S": "5",
    }
    with pytest.raises(ValueError, match="less than"):
        ProxyConfig.from_env(environ)
