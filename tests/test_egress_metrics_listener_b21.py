"""The opt-in loopback listener for the egress counters (backlog B21).

Hermetic: the listener binds loopback on an ephemeral port and the clients are raw sockets, so
the exposition is checked as bytes on the wire.
"""

import asyncio
import logging
import socket
from contextlib import suppress

import pytest
from prometheus_client import CONTENT_TYPE_LATEST

from sandfort.egress import proxy as proxy_module
from sandfort.egress.metrics import EgressMetrics
from sandfort.egress.metrics_listener import MAX_SCRAPES, serving_metrics
from sandfort.egress.proxy import ProxyConfig, _serve
from sandfort.egress.relay import Deny

LOOPBACK = "127.0.0.1"
ENV_LISTEN = "SANDFORT_EGRESS_METRICS_LISTEN"
ENV_SECRET = "SANDFORT_EGRESS_SECRET"
IO_TIMEOUT_S = 5.0
GET_METRICS = b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"
METHOD_DENY = Deny(405, "Method Not Allowed", "method is not CONNECT")
DECISION_SAMPLE = "sandfort_egress_decisions_total{"
DENY_SAMPLE = (
    'sandfort_egress_decisions_total{decision="deny",reason_class="method",status="405"} 1.0'
)
POLL_STEPS = 50
POLL_INTERVAL_S = 0.05
SETTLE_YIELDS = 100


async def _exchange(port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection(LOOPBACK, port)
    try:
        writer.write(request)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), IO_TIMEOUT_S)
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()


def _port_of(server: asyncio.Server | None) -> int:
    assert server is not None
    return int(server.sockets[0].getsockname()[1])


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((LOOPBACK, 0))
        return int(probe.getsockname()[1])


def _config_env(**extra: str) -> dict[str, str]:
    return {ENV_SECRET: "s", **extra}


async def test_get_metrics_returns_the_exposition() -> None:
    m = EgressMetrics()
    m.denied(METHOD_DENY)

    async with serving_metrics((LOOPBACK, 0), m) as server:
        response = await _exchange(_port_of(server), GET_METRICS)

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert ("Content-Type: " + CONTENT_TYPE_LATEST).encode() in response
    assert DENY_SAMPLE.encode() in response


async def test_other_paths_methods_and_garbage_are_refused_and_not_counted() -> None:
    m = EgressMetrics()

    async with serving_metrics((LOOPBACK, 0), m) as server:
        port = _port_of(server)
        missing = await _exchange(port, b"GET /other HTTP/1.1\r\nHost: x\r\n\r\n")
        posted = await _exchange(port, b"POST /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        garbage = await _exchange(port, b"garbage\r\n\r\n")

    assert missing.startswith(b"HTTP/1.1 404")
    assert posted.startswith(b"HTTP/1.1 405")
    assert b"Allow: GET" in posted
    assert garbage.startswith(b"HTTP/1.1 400")
    lines = m.render().decode().splitlines()
    assert not any(line.startswith(DECISION_SAMPLE) for line in lines)


async def test_a_silent_client_is_closed_at_the_read_timeout() -> None:
    async with serving_metrics((LOOPBACK, 0), EgressMetrics(), read_timeout_s=0.1) as server:
        reader, writer = await asyncio.open_connection(LOOPBACK, _port_of(server))
        try:
            assert await asyncio.wait_for(reader.read(), IO_TIMEOUT_S) == b""
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()


async def test_concurrent_scrapes_are_capped() -> None:
    idle: list[asyncio.StreamWriter] = []
    async with serving_metrics((LOOPBACK, 0), EgressMetrics()) as server:
        port = _port_of(server)
        try:
            for _ in range(MAX_SCRAPES):
                idle.append((await asyncio.open_connection(LOOPBACK, port))[1])
            await asyncio.sleep(0.1)

            refused = await _exchange(port, b"")  # a refused scrape is answered unread
        finally:
            for writer in idle:
                writer.close()
                with suppress(OSError):
                    await writer.wait_closed()

        assert refused.startswith(b"HTTP/1.1 503")
        response = b""
        for _ in range(POLL_STEPS):
            try:
                response = await _exchange(port, GET_METRICS)
            except OSError:  # a reset while the closed scrapes are still being released
                response = b""
            if response.startswith(b"HTTP/1.1 200"):
                break
            await asyncio.sleep(POLL_INTERVAL_S)
        assert response.startswith(b"HTTP/1.1 200")


async def test_unset_listen_runs_nothing() -> None:
    async with serving_metrics(None, EgressMetrics()) as server:
        assert server is None


async def test_a_bind_failure_is_logged_and_raised(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
        blocker.bind((LOOPBACK, 0))
        blocker.listen()
        port = int(blocker.getsockname()[1])

        with pytest.raises(OSError):
            async with serving_metrics((LOOPBACK, port), EgressMetrics()):
                pass

    assert "egress metrics cannot bind" in caplog.text


async def test_serve_runs_the_listener_when_configured() -> None:
    port = free_port()
    config = ProxyConfig(host=LOOPBACK, port=0, secret="s", metrics_listen=(LOOPBACK, port))
    task = asyncio.create_task(_serve(config))
    try:
        response = b""
        for _ in range(POLL_STEPS):
            try:
                response = await _exchange(port, GET_METRICS)
            except OSError:
                response = b""
            if response.startswith(b"HTTP/1.1 200"):
                break
            await asyncio.sleep(POLL_INTERVAL_S)
        assert response.startswith(b"HTTP/1.1 200")
        assert b"# TYPE sandfort_egress_decisions_total counter" in response
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


async def test_serve_opens_no_listener_by_default(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    task = asyncio.create_task(_serve(ProxyConfig(host=LOOPBACK, port=0, secret="s")))
    for _ in range(POLL_STEPS):  # the proxy is up once it logs that it is listening
        if any("egress proxy listening" in message for message in caplog.messages):
            break
        await asyncio.sleep(POLL_INTERVAL_S)
    assert any("egress proxy listening" in message for message in caplog.messages)
    for _ in range(SETTLE_YIELDS):  # let a listener that is wrongly on get as far as its log
        await asyncio.sleep(0)
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task

    assert not any("egress metrics listening" in message for message in caplog.messages)


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_metrics_listen_is_off_by_default(raw: str | None) -> None:
    environ = _config_env() if raw is None else _config_env(**{ENV_LISTEN: raw})

    assert ProxyConfig.from_env(environ).metrics_listen is None


def test_metrics_listen_accepts_a_loopback_address_and_port() -> None:
    padded = ProxyConfig.from_env(_config_env(**{ENV_LISTEN: " 127.0.0.1:9464 "}))
    other = ProxyConfig.from_env(_config_env(**{ENV_LISTEN: "127.0.0.2:9464"}))

    assert padded.metrics_listen == (LOOPBACK, 9464)
    assert other.metrics_listen == ("127.0.0.2", 9464)


@pytest.mark.parametrize(
    "raw",
    [
        "0.0.0.0:9464",
        "10.0.0.5:9464",
        "172.19.0.1:9464",
        "[::1]:9464",
        "::1:9464",
        "localhost:9464",
        "127.0.0.1",
        "127.0.0.1:",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:94x4",
        "127.0.0.1:3128",
        "127.0.0.1:53",
        "127.0.0.1:9464,127.0.0.1:9465",
    ],
)
def test_metrics_listen_refuses_every_other_bind(raw: str) -> None:
    with pytest.raises(ValueError, match=ENV_LISTEN):
        ProxyConfig.from_env(_config_env(**{ENV_LISTEN: raw}))


def test_metrics_port_must_differ_from_a_custom_proxy_port() -> None:
    custom = {"SANDFORT_EGRESS_LISTEN_PORT": "8888"}

    with pytest.raises(ValueError, match=ENV_LISTEN):
        ProxyConfig.from_env(_config_env(**custom, **{ENV_LISTEN: "127.0.0.1:8888"}))

    config = ProxyConfig.from_env(_config_env(**custom, **{ENV_LISTEN: "127.0.0.1:3128"}))
    assert config.metrics_listen == (LOOPBACK, 3128)


def test_main_exits_2_on_a_bad_metrics_listen() -> None:
    assert proxy_module.main(_config_env(**{ENV_LISTEN: "0.0.0.0:9464"})) == 2
