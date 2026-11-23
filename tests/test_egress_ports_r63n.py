"""CONNECT port rule of the egress proxy, built the way the proxy process builds itself.

Security review r63n: on the beta a CONNECT to :8080 and :8443 answered 200 and :22/:25 hung.
The code path under test is ``ProxyConfig.from_env`` -> ``build_proxy``: defaults only, so a
bare process refuses every port but 443 and 80 with 403, before resolving or connecting.
"""

import asyncio
import base64
import logging
import time
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sandfort.egress.proxy import EgressProxy, ProxyConfig, build_proxy
from sandfort.egress.relay import Connection, Deny
from sandfort.egress.tokens import mint_egress_token
from sandfort.webhooks import ssrf

SECRET = "port-rule-secret"
SANDBOX = "sbx_ports"
NAME = "example.com"
IO_TIMEOUT_S = 5.0
FAST_REFUSAL_S = 1.0
REPO = Path(__file__).resolve().parent.parent
REDEPLOY = REPO / "deploy" / "redeploy-beta.sh"


def _permit_all(address: ssrf.IpAddress) -> None:
    """Stand-in for the public-address rules; only the port rule is under test."""


def _auth() -> str:
    token = mint_egress_token(
        SECRET, sandbox_id=SANDBOX, allowlist=[NAME], now=datetime.now(UTC), ttl_s=None
    )
    return base64.b64encode(f"{SANDBOX}:{token}".encode()).decode("ascii")


PUBLIC_ADDRESS = "93.184.216.34"


class _Recorder:
    """Records resolutions and upstream connects; no connect ever leaves the machine."""

    def __init__(self) -> None:
        self.resolved: list[str] = []
        self.opened: list[int] = []

    async def resolve(self, host: str) -> list[str]:
        self.resolved.append(host)
        return [PUBLIC_ADDRESS]

    async def open(self, addresses: list[ssrf.IpAddress], port: int) -> Connection:
        self.opened.append(port)
        raise Deny(502, "Bad Gateway", "upstream connection failed")


@asynccontextmanager
async def _default_proxy(
    recorder: _Recorder, environ: Mapping[str, str] | None = None
) -> AsyncIterator[int]:
    config = ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET, **(environ or {})})
    proxy = EgressProxy.from_config(config, resolver=recorder.resolve, checker=_permit_all)
    proxy._open = recorder.open  # type: ignore[method-assign]  # test seam: no real connect
    server = await proxy.start("127.0.0.1", 0)
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()
        await server.wait_closed()


async def _connect(port: int, target: str) -> tuple[int, float]:
    started = time.monotonic()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        request = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
        writer.write(f"{request}Proxy-Authorization: Basic {_auth()}\r\n\r\n".encode("ascii"))
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT_S)
        return int(head.split(b" ", 2)[1]), time.monotonic() - started
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()


@pytest.mark.parametrize("port", [8080, 8443, 22, 25, 8000, 3306, 65535])
async def test_default_proxy_refuses_a_non_allowed_port_at_once_without_resolving(
    port: int,
) -> None:
    recorder = _Recorder()
    async with _default_proxy(recorder) as proxy_port:
        status, elapsed = await _connect(proxy_port, f"{NAME}:{port}")

    assert status == 403
    assert elapsed < FAST_REFUSAL_S
    assert recorder.resolved == []
    assert recorder.opened == []


@pytest.mark.parametrize("port", [443, 80])
async def test_default_proxy_lets_an_allowed_port_past_the_port_rule(port: int) -> None:
    recorder = _Recorder()
    async with _default_proxy(recorder) as proxy_port:
        status, _ = await _connect(proxy_port, f"{NAME}:{port}")

    assert recorder.resolved == [NAME]  # the port rule let it through
    assert recorder.opened == [port]
    assert status == 502  # the stub upstream refuses; the proxy itself did not answer 403


async def test_a_port_rule_override_applies_to_the_process() -> None:
    recorder = _Recorder()
    async with _default_proxy(recorder, {"SANDFORT_EGRESS_ALLOWED_PORTS": "8443"}) as proxy_port:
        refused, _ = await _connect(proxy_port, f"{NAME}:443")
        past_rule, _ = await _connect(proxy_port, f"{NAME}:8443")

    assert refused == 403
    assert past_rule == 502
    assert recorder.opened == [8443]


def test_startup_logs_the_allowed_ports_so_an_old_process_is_recognisable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET})

    with caplog.at_level(logging.INFO, logger="sandfort.egress"):
        build_proxy(config, discover=lambda: ())

    assert "egress allowed ports: 443,80" in caplog.text


def test_build_proxy_applies_the_default_ports() -> None:
    config = ProxyConfig.from_env({"SANDFORT_EGRESS_SECRET": SECRET})
    built = build_proxy(config, discover=lambda: ())
    assert built.allowed_ports == frozenset({443, 80})


@pytest.mark.skipif(not REDEPLOY.is_file(), reason="private ops script not present in public tree")
def test_redeploy_script_recreates_the_proxy_and_checks_its_startup_line() -> None:
    text = REDEPLOY.read_text(encoding="utf-8")

    assert "remind_proxy_restart" not in text
    assert "up -d --force-recreate api egress" in text
    assert "egress allowed ports:" in text
