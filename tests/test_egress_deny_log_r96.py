"""Throttle for the egress proxy's deny log line (backlog B15).

Hermetic: unit tests drive ``DenyLog`` with a fake clock; the proxy test talks to a loopback
listener and never dials upstream (every request is refused before a tunnel opens).
"""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest

from sandfort.egress.deny_log import DENY_LOG_INTERVAL_S, DENY_LOG_MAX_ENTRIES, DenyLog
from sandfort.egress.proxy import EgressProxy
from sandfort.egress.relay import Deny

SECRET = "test-egress-secret"
IO_TIMEOUT_S = 5.0
CAP = Deny(429, "Too Many Requests", "too many concurrent connections for sandbox")
HOST_NOT_ALLOWED = Deny(403, "Forbidden", "host is not in the allowlist")


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _host() -> str:
    return "'a.example.com'"


def _denies(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [m for m in caplog.messages if m.startswith("deny ")]


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


@pytest.fixture
def deny_log(clock: _Clock) -> DenyLog:
    return DenyLog(interval_s=60.0, max_entries=8, clock=clock)


def test_first_rejection_is_logged_with_the_existing_format(
    deny_log: DenyLog, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")

    deny_log.log("sbx_a", CAP, "7", _host)

    assert _denies(caplog) == [
        "deny sandbox=sbx_a host='a.example.com' status=429"
        " reason=too many concurrent connections for sandbox gen=7"
    ]


def test_repeats_within_the_interval_are_suppressed(
    deny_log: DenyLog, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")

    for _ in range(50):
        deny_log.log("sbx_a", CAP, "7", _host)
        clock.now += 0.1

    assert len(_denies(caplog)) == 1


def test_line_after_the_interval_carries_the_suppressed_count(
    deny_log: DenyLog, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    for _ in range(4):  # one logged, three suppressed
        deny_log.log("sbx_a", CAP, "7", _host)
    clock.now += 60.0

    deny_log.log("sbx_a", CAP, "7", _host)
    clock.now += 61.0
    deny_log.log("sbx_a", CAP, "7", _host)  # nothing suppressed since the last line

    lines = _denies(caplog)
    assert len(lines) == 3
    assert lines[1].endswith(" gen=7 suppressed=3")
    assert "suppressed" not in lines[2]


def test_deny_under_a_new_generation_is_logged_at_once(
    deny_log: DenyLog, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")

    deny_log.log("sbx_a", CAP, "5", _host)
    clock.now += 1.0  # well inside the interval
    deny_log.log("sbx_a", CAP, "6", _host)

    lines = _denies(caplog)
    assert len(lines) == 2
    assert lines[0].endswith(" gen=5")
    assert lines[1].endswith(" gen=6")


def test_generation_change_carries_the_count_suppressed_under_the_old_one(
    deny_log: DenyLog, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    for _ in range(4):  # one logged, three suppressed under gen 5
        deny_log.log("sbx_a", CAP, "5", _host)
    clock.now += 1.0

    deny_log.log("sbx_a", CAP, "6", _host)
    deny_log.log("sbx_a", CAP, "6", _host)  # same gen again: throttled as before

    lines = _denies(caplog)
    assert len(lines) == 2
    assert lines[1].endswith(" gen=6 suppressed=3")


def test_generation_change_restarts_the_interval(
    deny_log: DenyLog, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    deny_log.log("sbx_a", CAP, "5", _host)
    clock.now += 50.0
    deny_log.log("sbx_a", CAP, "6", _host)
    clock.now += 50.0  # 100 s after the first line, 50 s after the gen=6 line

    deny_log.log("sbx_a", CAP, "6", _host)

    assert len(_denies(caplog)) == 2


def test_reasons_are_independent(deny_log: DenyLog, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")

    deny_log.log("sbx_a", CAP, "7", _host)
    deny_log.log("sbx_a", HOST_NOT_ALLOWED, "7", _host)
    deny_log.log("sbx_a", CAP, "7", _host)

    assert len(_denies(caplog)) == 2


def test_sandboxes_are_independent(deny_log: DenyLog, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")

    deny_log.log("sbx_a", CAP, "7", _host)
    deny_log.log("sbx_b", CAP, "7", _host)
    deny_log.log("sbx_a", CAP, "7", _host)

    assert [line.split()[1] for line in _denies(caplog)] == ["sandbox=sbx_a", "sandbox=sbx_b"]


def test_digits_in_the_detail_do_not_open_new_reasons(
    deny_log: DenyLog, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")

    for port in range(1, 200):  # a port scan is one reason, not 199
        deny_log.log("sbx_a", Deny(403, "Forbidden", f"port {port} is not allowed"), "7", _host)

    assert len(_denies(caplog)) == 1


def test_host_is_only_rendered_for_a_line_that_is_written(
    deny_log: DenyLog,
) -> None:
    rendered: list[int] = []

    def host() -> str:
        rendered.append(1)
        return "h"

    for _ in range(10):
        deny_log.log("sbx_a", CAP, "7", host)

    assert len(rendered) == 1


def test_state_is_bounded_under_a_sandbox_id_flood(
    deny_log: DenyLog, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")

    for number in range(1000):
        deny_log.log(f"sbx_{number}", CAP, "7", _host)

    assert deny_log.tracked <= 8
    assert len(_denies(caplog)) == 1000  # every new key is a first rejection


def test_eviction_drops_the_least_recently_used_key(
    deny_log: DenyLog, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    for number in range(8):
        deny_log.log(f"sbx_{number}", CAP, "7", _host)
    deny_log.log("sbx_0", CAP, "7", _host)  # touch the oldest: suppressed, now most recent
    deny_log.log("sbx_new", CAP, "7", _host)  # evicts sbx_1, not sbx_0
    caplog.clear()

    deny_log.log("sbx_0", CAP, "7", _host)
    deny_log.log("sbx_1", CAP, "7", _host)

    assert [line.split()[1] for line in _denies(caplog)] == ["sandbox=sbx_1"]


def test_defaults_are_named_constants() -> None:
    log = DenyLog()

    assert DENY_LOG_INTERVAL_S == 60.0
    assert DENY_LOG_MAX_ENTRIES >= 1024
    assert log.tracked == 0


@asynccontextmanager
async def _serve(proxy: EgressProxy) -> AsyncIterator[int]:
    server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


async def _refused_status(port: int) -> int:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET / HTTP/1.1\r\n\r\n")
    await writer.drain()
    head = await asyncio.wait_for(reader.readline(), IO_TIMEOUT_S)
    writer.close()
    return int(head.split()[1])


async def test_proxy_answers_every_refusal_but_logs_the_deny_once(
    clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="sandfort.egress")
    proxy = EgressProxy(SECRET, deny_log=DenyLog(interval_s=60.0, clock=clock))

    async with _serve(proxy) as port:
        statuses = [await _refused_status(port) for _ in range(5)]

    assert statuses == [405] * 5  # throttling the log never throttles the answer
    assert len(_denies(caplog)) == 1
    assert "status=405" in _denies(caplog)[0]
