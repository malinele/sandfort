"""Scrape handling, teardown and defaults of the egress counters listener (backlog B21).

Hermetic: the listener binds loopback on an ephemeral port and the clients are raw sockets.
"""

import asyncio
from contextlib import suppress

import pytest

from sandfort.egress import metrics_listener
from sandfort.egress.metrics import ALLOW, DECISIONS_TOTAL, STATUS_ALLOW, EgressMetrics
from sandfort.egress.metrics_listener import (
    MAX_SCRAPES,
    SCRAPE_READ_TIMEOUT_S,
    MetricsListener,
    serving_metrics,
)
from sandfort.egress.relay import MAX_LINE_BYTES, Deny

LOOPBACK = "127.0.0.1"
IO_TIMEOUT_S = 5.0
POLL_STEPS = 100
POLL_INTERVAL_S = 0.02
GET_METRICS = b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"
DECISION_SAMPLE = "sandfort_egress_decisions_total{"
ALLOWED = {"decision": ALLOW, "status": STATUS_ALLOW, "reason_class": "allowed"}
METHOD_DENY = Deny(405, "Method Not Allowed", "method is not CONNECT")
DEFAULT_MAX_SCRAPES = 4
DEFAULT_READ_TIMEOUT_S = 5.0


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


def _split(response: bytes) -> tuple[bytes, dict[str, str], bytes]:
    head, _, body = response.partition(b"\r\n\r\n")
    status_line, *header_lines = head.decode("ascii").split("\r\n")
    headers = {k.lower(): v.strip() for k, _, v in (line.partition(":") for line in header_lines)}
    return status_line.encode("ascii"), headers, body


def _decision_lines(m: EgressMetrics) -> list[str]:
    return [line for line in m.render().decode().splitlines() if line.startswith(DECISION_SAMPLE)]


async def test_a_scrape_leaves_the_decision_counters_unchanged() -> None:
    m = EgressMetrics()
    m.denied(METHOD_DENY)

    async with serving_metrics((LOOPBACK, 0), m) as server:
        first = await _exchange(_port_of(server), GET_METRICS)
        second = await _exchange(_port_of(server), GET_METRICS)

    assert m.value(DECISIONS_TOTAL, ALLOWED) == 0.0
    assert len(_decision_lines(m)) == 1
    assert b'decision="allow"' not in first
    assert b'decision="allow"' not in second


async def test_the_scrape_answer_declares_its_exact_length_and_closes() -> None:
    m = EgressMetrics()
    m.denied(METHOD_DENY)

    async with serving_metrics((LOOPBACK, 0), m) as server:
        response = await _exchange(_port_of(server), GET_METRICS)

    status_line, headers, body = _split(response)
    assert status_line == b"HTTP/1.1 200 OK"
    assert int(headers["content-length"]) == len(body) > 0
    assert headers["connection"] == "close"


async def test_a_query_string_is_ignored() -> None:
    m = EgressMetrics()

    async with serving_metrics((LOOPBACK, 0), m) as server:
        response = await _exchange(_port_of(server), b"GET /metrics?name=x HTTP/1.1\r\n\r\n")

    assert response.startswith(b"HTTP/1.1 200 OK")
    assert b"# TYPE sandfort_egress_decisions_total counter" in response


@pytest.mark.parametrize(
    "target", ["/metricsX", "/metrics/", "/", "/metrics%2e", "/metrics/secret"]
)
async def test_only_the_exact_metrics_path_is_served(target: str) -> None:
    m = EgressMetrics()

    async with serving_metrics((LOOPBACK, 0), m) as server:
        response = await _exchange(_port_of(server), f"GET {target} HTTP/1.1\r\n\r\n".encode())

    assert response.startswith(b"HTTP/1.1 404")
    assert b"sandfort_egress" not in response
    assert _decision_lines(m) == []


async def test_a_render_failure_answers_500_and_the_next_scrape_works(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    m = EgressMetrics()
    real_render = m.render
    calls: list[int] = []

    def render_once_broken() -> bytes:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("render broke")
        return real_render()

    monkeypatch.setattr(m, "render", render_once_broken)
    listener = MetricsListener(m)
    server = await listener.start(LOOPBACK, 0)
    try:
        failed = await _exchange(_port_of(server), GET_METRICS)
        recovered = await _exchange(_port_of(server), GET_METRICS)
        for _ in range(POLL_STEPS):
            if listener._active == 0:
                break
            await asyncio.sleep(POLL_INTERVAL_S)
    finally:
        server.close()
        await server.wait_closed()

    assert failed.startswith(b"HTTP/1.1 500")
    assert recovered.startswith(b"HTTP/1.1 200 OK")
    assert listener._active == 0
    assert "egress metrics scrape failed" in caplog.text


async def test_leaving_the_block_stops_the_listener() -> None:
    async with serving_metrics((LOOPBACK, 0), EgressMetrics()) as server:
        assert server is not None
        port = _port_of(server)
        assert server.is_serving()

    assert not server.is_serving()
    with pytest.raises(OSError):
        await asyncio.open_connection(LOOPBACK, port)


def test_the_shipped_defaults_are_four_scrapes_and_five_seconds() -> None:
    listener = MetricsListener(EgressMetrics())

    assert MAX_SCRAPES == DEFAULT_MAX_SCRAPES
    assert SCRAPE_READ_TIMEOUT_S == DEFAULT_READ_TIMEOUT_S
    assert listener._max_scrapes == DEFAULT_MAX_SCRAPES
    assert listener._read_timeout_s == DEFAULT_READ_TIMEOUT_S


async def test_serving_metrics_builds_the_listener_with_the_default_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built: list[MetricsListener] = []

    class _Spy(MetricsListener):
        def __init__(self, *args: object, **kwargs: float) -> None:
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]
            built.append(self)

    monkeypatch.setattr(metrics_listener, "MetricsListener", _Spy)

    async with serving_metrics((LOOPBACK, 0), EgressMetrics()):
        pass

    assert [(b._max_scrapes, b._read_timeout_s) for b in built] == [
        (DEFAULT_MAX_SCRAPES, DEFAULT_READ_TIMEOUT_S)
    ]


async def test_an_over_long_request_line_is_refused_and_the_next_scrape_works() -> None:
    long_line = b"GET /" + b"a" * (MAX_LINE_BYTES + 1) + b" HTTP/1.1\r\n\r\n"

    async with serving_metrics((LOOPBACK, 0), EgressMetrics()) as server:
        refused = await _exchange(_port_of(server), long_line)
        served = await _exchange(_port_of(server), GET_METRICS)

    assert refused.startswith(b"HTTP/1.1 400")
    assert served.startswith(b"HTTP/1.1 200 OK")
