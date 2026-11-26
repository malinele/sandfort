"""Round 94: the preview token stays out of uvicorn's log lines and Sandfort's own logs."""

import io
import logging
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from tests.test_proxy import LOOPBACK, PORT, EchoApp, World, call, closed_port, host_for
from uvicorn.logging import AccessFormatter
from uvicorn.protocols.utils import get_path_with_query_string

from sandfort.logging import JsonFormatter
from sandfort.proxy.hygiene import (
    CONNECT_TOKEN_PARAM,
    REDACTED_LOGGERS,
    TokenRedactingFilter,
    install_log_redaction,
    redact_query_token,
    strip_referer_token,
)
from sandfort.proxy.terminal import REQUIRED_PARAMS
from sandfort.proxy.tokens import TOKEN_PARAM

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "s3cretPreviewTok3n_value-abc"
HTTP_FORMAT = '%s - "%s %s HTTP/%s" %d'
ACCESS_FORMAT = '%(client_addr)s - "%(request_line)s" %(status_code)s'


class Records(logging.Handler):
    """Keeps every record that reaches it, after the logger's filters ran."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class Strict(logging.StreamHandler[io.StringIO]):
    """Writes into a buffer and re-raises a formatting error instead of printing it."""

    def __init__(self) -> None:
        super().__init__(io.StringIO())

    def handleError(self, record: logging.LogRecord) -> None:
        raise  # called inside emit's except block: the formatter's error fails the test


def token_filters(name: str) -> list[logging.Filter]:
    found = logging.getLogger(name).filters
    return [item for item in found if isinstance(item, TokenRedactingFilter)]


@pytest.fixture
def uvicorn_logs() -> Iterator[Records]:
    """A handler on both uvicorn loggers, with no redaction filter until the test adds one.

    The handler sits on the logger itself, so the test does not depend on propagation (an
    earlier test may have loaded uvicorn's logging config, which turns it off).
    """
    handler = Records()
    saved: list[tuple[logging.Logger, int, bool, list[Any]]] = []
    for name in REDACTED_LOGGERS:
        target = logging.getLogger(name)
        saved.append((target, target.level, target.disabled, list(target.filters)))
        for item in token_filters(name):
            target.removeFilter(item)
        target.setLevel(logging.INFO)
        target.disabled = False
        target.addHandler(handler)
    yield handler
    for target, level, disabled, filters in saved:
        target.removeHandler(handler)
        target.setLevel(level)
        target.disabled = disabled
        target.filters[:] = filters


@pytest.fixture
def world() -> World:
    return World()


@pytest.fixture
def echo() -> EchoApp:
    return EchoApp()


@pytest.fixture
async def upstream(echo: EchoApp) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=echo)) as client:
        yield client


def record(message: str, *args: Any) -> logging.LogRecord:
    return logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, message, args, None)


def logged_path(query: str) -> str:
    return get_path_with_query_string({"path": "/p", "query_string": query.encode()})


# -- helpers --------------------------------------------------------------------------------


def test_redact_query_token_replaces_only_the_token_value() -> None:
    query = f"keep=1&{TOKEN_PARAM}={TOKEN}&x="

    assert redact_query_token(query) == f"keep=1&{TOKEN_PARAM}=REDACTED&x="


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (f"sandfort%5Fpreview%5Ftoken={TOKEN}", "sandfort%5Fpreview%5Ftoken=REDACTED"),
        (TOKEN_PARAM, f"{TOKEN_PARAM}=REDACTED"),
        ("a=1&b=two", "a=1&b=two"),
        ("", ""),
    ],
)
def test_redact_query_token_edge_cases(query: str, expected: str) -> None:
    assert redact_query_token(query) == expected


def test_strip_referer_token_keeps_other_params() -> None:
    referer = f"http://h.test/page?keep=1&{TOKEN_PARAM}={TOKEN}&x=2"

    assert strip_referer_token(referer) == "http://h.test/page?keep=1&x=2"


def test_strip_referer_token_drops_an_emptied_query() -> None:
    referer = f"http://h.test/page?{TOKEN_PARAM}={TOKEN}"

    assert strip_referer_token(referer) == "http://h.test/page"


@pytest.mark.parametrize(
    "referer",
    [
        "http://h.test/p",
        "http://h.test/p?a=1&b=2",
        "http://h/",
        "http://h.test/p?a=1&&b=2",
        "http://h.test/p?",
    ],
)
def test_strip_referer_token_leaves_a_clean_referer_unchanged(referer: str) -> None:
    assert strip_referer_token(referer) == referer


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (f"keep=1&{TOKEN_PARAM}={TOKEN}", f"/p?keep=1&{TOKEN_PARAM}=REDACTED"),
        (f'a="&{TOKEN_PARAM}={TOKEN}', f'/p?a="&{TOKEN_PARAM}=REDACTED'),  # raw quote from curl
    ],
)
def test_filter_redacts_the_path_and_keeps_the_args_shape(query: str, expected: str) -> None:
    entry = record(HTTP_FORMAT, "127.0.0.1:1", "GET", logged_path(query), "1.1", 200)

    assert TokenRedactingFilter().filter(entry) is True

    assert entry.msg == HTTP_FORMAT
    assert isinstance(entry.args, tuple)
    assert len(entry.args) == 5
    assert entry.args[2] == expected
    assert TOKEN not in entry.getMessage()


def test_filter_redacts_a_message_without_args() -> None:
    entry = record(f'1.2.3.4:1 - "GET /p?keep=1&{TOKEN_PARAM}={TOKEN} HTTP/1.1" 200')
    expected = f'1.2.3.4:1 - "GET /p?keep=1&{TOKEN_PARAM}=REDACTED HTTP/1.1" 200'

    assert TokenRedactingFilter().filter(entry) is True

    assert entry.getMessage() == expected


def test_filter_redacts_the_terminal_connect_token() -> None:
    path = f"/terminal?sandbox=sbx_1&pty=pty_1&{CONNECT_TOKEN_PARAM}={TOKEN}"
    entry = record(HTTP_FORMAT, "127.0.0.1:1", "GET", path, "1.1", 200)

    TokenRedactingFilter().filter(entry)

    assert CONNECT_TOKEN_PARAM in REQUIRED_PARAMS
    assert isinstance(entry.args, tuple)
    assert entry.args[2] == "/terminal?sandbox=sbx_1&pty=pty_1&token=REDACTED"


def test_filter_leaves_a_record_without_a_token_alone() -> None:
    args = ("127.0.0.1:1", "GET", "/p?keep=1", "1.1", 200)
    entry = record(HTTP_FORMAT, *args)

    assert TokenRedactingFilter().filter(entry) is True

    assert entry.msg == HTTP_FORMAT
    assert entry.args == args


def test_filter_never_raises_on_a_broken_record() -> None:
    entry = record("%d items", "not a number")

    assert TokenRedactingFilter().filter(entry) is True
    assert entry.args == ("not a number",)


def test_install_log_redaction_is_idempotent(uvicorn_logs: Records) -> None:
    install_log_redaction()
    install_log_redaction()

    assert [len(token_filters(name)) for name in REDACTED_LOGGERS] == [1, 1]


# -- log lines ------------------------------------------------------------------------------


async def test_building_the_proxy_installs_the_filter(
    world: World, upstream: httpx.AsyncClient, uvicorn_logs: Records
) -> None:
    assert [len(token_filters(name)) for name in REDACTED_LOGGERS] == [0, 0]

    world.proxy(upstream)

    assert [len(token_filters(name)) for name in REDACTED_LOGGERS] == [1, 1]


async def test_uvicorn_access_line_never_carries_the_token(
    world: World, upstream: httpx.AsyncClient, uvicorn_logs: Records
) -> None:
    world.proxy(upstream)
    path = logged_path(f"keep=1&{TOKEN_PARAM}={TOKEN}")
    access = logging.getLogger("uvicorn.access")

    access.info(HTTP_FORMAT, "127.0.0.1:1", "GET", path, "1.1", 200)

    [entry] = uvicorn_logs.records
    message = entry.getMessage()
    assert TOKEN not in message
    assert "keep=1" in message
    assert f"{TOKEN_PARAM}=REDACTED" in message
    assert TOKEN not in JsonFormatter().format(entry)


async def test_uvicorn_access_formatter_prints_the_redacted_line(
    world: World, upstream: httpx.AsyncClient, uvicorn_logs: Records
) -> None:
    world.proxy(upstream)
    access = logging.getLogger("uvicorn.access")
    strict = Strict()
    strict.setFormatter(AccessFormatter(ACCESS_FORMAT, use_colors=False))
    access.addHandler(strict)
    path = logged_path(f"keep=1&{TOKEN_PARAM}={TOKEN}")

    try:
        access.info(HTTP_FORMAT, "127.0.0.1:1", "GET", path, "1.1", 200)
    finally:
        access.removeHandler(strict)

    line = strict.stream.getvalue()
    assert f'"GET /p?keep=1&{TOKEN_PARAM}=REDACTED HTTP/1.1" 200' in line
    assert TOKEN not in line


@pytest.mark.parametrize(
    ("template", "extra"),
    [
        ('%s - "WebSocket %s" [accepted]', ()),
        ('%s - "WebSocket %s" 403', ()),
        ('%s - "WebSocket %s" %d', (401,)),
    ],
)
async def test_uvicorn_websocket_lines_never_carry_the_token(
    world: World,
    upstream: httpx.AsyncClient,
    uvicorn_logs: Records,
    template: str,
    extra: tuple[Any, ...],
) -> None:
    world.proxy(upstream)
    path = logged_path(f"keep=1&{TOKEN_PARAM}={TOKEN}")

    logging.getLogger("uvicorn.error").info(template, "127.0.0.1:1", path, *extra)

    [entry] = uvicorn_logs.records
    assert TOKEN not in entry.getMessage()
    assert "keep=1" in entry.getMessage()


async def test_proxy_and_httpx_logs_never_carry_the_token(
    world: World, upstream: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    sandbox = await world.add(public=False)
    token = await world.tokens.mint(world.org_id, sandbox.id, PORT)
    refused = await world.add(public=False, endpoint=(LOOPBACK, closed_port()))
    refused_token = await world.tokens.mint(world.org_id, refused.id, PORT)
    proxy, real = world.proxy(upstream), world.proxy()

    try:
        ok = await call(proxy, "GET", host_for(sandbox.id), f"/p?keep=1&{TOKEN_PARAM}={token}")
        bad = await call(real, "GET", host_for(refused.id), f"/p?{TOKEN_PARAM}={refused_token}")
    finally:
        await real.aclose()

    assert (ok.status_code, bad.status_code) == (200, 502)
    # the test's own client logs the proxy URL it calls, token included: leave those lines out
    messages = [item.getMessage() for item in caplog.records]
    lines = [line for line in messages if "http://proxy.test" not in line]
    assert any("http://127.0.0.1:9/p?keep=1 " in line for line in lines)  # the upstream call
    assert not any(token in line or refused_token in line for line in lines)


def test_files_stay_small() -> None:
    paths = [
        ROOT / "src" / "sandfort" / "proxy" / "app.py",
        ROOT / "src" / "sandfort" / "proxy" / "hygiene.py",
        Path(__file__),
        Path(__file__).with_name("test_proxy_token_headers_r94.py"),
    ]
    for path in paths:
        lines = path.read_text().splitlines()
        assert len(lines) < 400, path
        assert all(len(line) <= 100 for line in lines), path
