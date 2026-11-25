"""DNS pins through ``EgressProxy`` (egress v2 round 4; design 4.4, cases P1, P5, P6, P7).

The policy route, the fake clock and the mock upstream come from ``test_egress_proxy_v2``; here
the proxy is rebuilt with a pin window. ``tests/test_egress_pinning_v2.py`` covers the store.
"""

import asyncio
import base64
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from tests.test_egress_proxy_v2 import (
    SANDBOX,
    SECRET,
    _Answer,
    _Env,
    _lines,
    _permit_all,
)

from sandfort.egress.logname import redacted_name
from sandfort.egress.proxy import EgressProxy, ProxyConfig
from sandfort.egress.tokens import mint_egress_token

WINDOW_S = 30
CACHE_PAST_S = 6.0  # a little more than the policy cache window of 5 s
SETTLE_S = 5.0
A, B = "a.example.com", "b.example.com"
OTHER = "sbx_other"


@pytest.fixture(autouse=True)
def _log_level(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")


@asynccontextmanager
async def _pinned(*, policy: bool, window_s: float = WINDOW_S) -> AsyncIterator[_Env]:
    env = _Env(policy=policy, timeout_s=2.0)
    env.proxy = EgressProxy(
        SECRET,
        resolver=env._resolve,
        checker=_permit_all,
        allowed_ports={443},
        policy_client=env.client,
        dns_pin_s=window_s,
    )
    env.proxy._open = env._open  # type: ignore[method-assign]  # test seam
    server = await env.proxy.start("127.0.0.1", 0)
    env.port = int(server.sockets[0].getsockname()[1])
    try:
        yield env
    finally:
        for answer in env.answers:
            answer.writer.close()
        server.close()
        await server.wait_closed()
        await env.proxy.aclose()
        if env.client is not None:
            await env.client.aclose()


async def _connect_as(env: _Env, sandbox_id: str, target: str, allow: list[str]) -> _Answer:
    now = datetime.now(UTC)
    token = mint_egress_token(SECRET, sandbox_id=sandbox_id, allowlist=allow, now=now)
    credential = base64.b64encode(f"{sandbox_id}:{token}".encode()).decode()
    reader, writer = await asyncio.open_connection("127.0.0.1", env.port)
    request = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
    writer.write(f"{request}Proxy-Authorization: Basic {credential}\r\n\r\n".encode())
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), SETTLE_S)
    env.answers.append(_Answer(head, reader, writer))
    return env.answers[-1]


async def _until(condition: object) -> None:
    async def poll() -> None:
        while not condition():  # type: ignore[operator]
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), SETTLE_S)


async def _connect_and_release(env: _Env, target: str) -> int:
    """CONNECT, hang up, and wait until the proxy has dropped that tunnel again."""
    before = len(env.proxy.tunnels.tunnels_of(SANDBOX))
    answer = await env.connect(target)
    answer.writer.close()
    await _until(lambda: len(env.proxy.tunnels.tunnels_of(SANDBOX)) == before)
    return answer.status


async def test_p1_two_connects_to_one_name_inside_the_window_resolve_once() -> None:
    async with _pinned(policy=False) as env:
        token = env.v1([A])
        first = await env.connect(f"{A}:443", token)
        second = await env.connect(f"{A}:443", token)
    assert (first.status, second.status) == (200, 200)
    assert env.resolved == [A]  # the second CONNECT used the pin
    assert len(env.opened) == 2 and env.opened[0] == env.opened[1]


async def test_p5_pins_are_per_sandbox() -> None:
    async with _pinned(policy=False) as env:
        mine = await _connect_as(env, SANDBOX, f"{A}:443", [A])
        theirs = await _connect_as(env, OTHER, f"{A}:443", [A])
    assert (mine.status, theirs.status) == (200, 200)
    assert env.resolved == [A, A]  # the other sandbox's CONNECT did not ride on my pin


async def test_p6_window_zero_resolves_every_time() -> None:
    async with _pinned(policy=False, window_s=0) as env:
        token = env.v1([A])
        await env.connect(f"{A}:443", token)
        await env.connect(f"{A}:443", token)
    assert env.resolved == [A, A]


async def test_p7_a_patch_dropping_the_name_drops_the_pin_without_any_open_tunnel() -> None:
    async with _pinned(policy=True) as env:
        env.route.set([A, B])
        assert await _connect_and_release(env, f"{A}:443") == 200
        assert env.resolved == [A] and not env.proxy.tunnels.tunnels_of(SANDBOX)
        env.route.patch([B])  # the PATCH removes A; no tunnel of the sandbox is open
        env.now += CACHE_PAST_S
        assert await _connect_and_release(env, f"{B}:443") == 200  # this refresh sees the change
        refused = await env.connect(f"{A}:443")
        env.route.patch([A, B])  # A is admitted again
        env.now += CACHE_PAST_S
        again = await env.connect(f"{A}:443")
    assert (refused.status, again.status) == (403, 200)
    assert env.resolved == [A, B, A]  # the pin did not outlive the policy that admitted it


async def test_a_policy_change_closes_tunnels_and_drops_pins() -> None:
    async with _pinned(policy=True) as env:
        env.route.set([A, B])
        held = await env.connect(f"{A}:443")  # stays open: a tunnel, and a pin for A
        assert await _connect_and_release(env, f"{B}:443") == 200
        env.route.patch([B])
        env.now += CACHE_PAST_S
        assert await _connect_and_release(env, f"{B}:443") == 200
        await _until(lambda: env.upstreams[0].close.called)  # the registry still closes A's tunnel
        env.route.patch([A, B])
        env.now += CACHE_PAST_S
        again = await env.connect(f"{A}:443")
    assert (held.status, again.status) == (200, 200)
    assert env.resolved == [A, B, A]  # and the pin of A was dropped too
    assert len(env.opened) == 4


def test_from_config_passes_the_pin_window() -> None:
    proxy = EgressProxy.from_config(
        ProxyConfig(host="127.0.0.1", port=0, secret=SECRET, dns_pin_s=7)
    )
    assert proxy._pins._window_s == 7


async def test_a_denied_name_is_logged_as_length_and_keyed_digest_never_raw(
    caplog: pytest.LogCaptureFixture,
) -> None:
    exfil = "zq7-exfil-payload-4f9c." + "x" * 40 + ".attacker-example.test"
    async with _pinned(policy=False) as env:
        refused = await env.connect(f"{exfil}:443", env.v1([A]))
        allowed = await env.connect(f"{A}:443", env.v1([A]))
    assert (refused.status, allowed.status) == (403, 200)
    deny = _lines(caplog, "deny")[-1]
    assert "exfil" not in caplog.text and "attacker-example" not in caplog.text
    assert redacted_name(SECRET, exfil) in deny
    assert f"len={len(exfil)}" in deny
    assert _lines(caplog, "allow")[-1] == f"allow sandbox={SANDBOX} host={A!r} gen=-"
    assert redacted_name(SECRET, exfil) != redacted_name("another-secret", exfil)
