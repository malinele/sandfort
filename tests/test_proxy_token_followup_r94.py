"""Round 94 follow-up: redaction in every server role, a working proxy access log, edge cases.

The filter used to be installed only where the preview proxy was built, so an API process
without the proxy logged the pty connect token of each websocket handshake. In the shared
process the API's uvicorn config turned propagation off on ``uvicorn.access``, so the proxy's
access lines reached no handler at all.
"""

import logging
from collections.abc import Iterator
from typing import Any

import pytest
from tests.test_main_entry import _serve_env
from tests.test_proxy_token_hygiene_r94 import record, token_filters

import sandfort.main as server_main
from sandfort.proxy.hygiene import (
    REDACTED,
    REDACTED_LOGGERS,
    TOKEN_RESPONSE_HEADERS,
    TokenRedactingFilter,
    install_log_redaction,
    redact_query_token,
    strip_referer_token,
    with_token_response_headers,
)
from sandfort.proxy.tokens import TOKEN_PARAM

ACCESS = "uvicorn.access"
HTTP_FORMAT = '%s - "%s %s HTTP/%s" %d'


@pytest.fixture
def bare_loggers() -> Iterator[None]:
    """The uvicorn loggers without a redaction filter, restored afterwards with propagation."""
    saved: list[tuple[logging.Logger, list[Any], bool, list[logging.Handler]]] = []
    for name in REDACTED_LOGGERS:
        target = logging.getLogger(name)
        saved.append((target, list(target.filters), target.propagate, list(target.handlers)))
        for item in token_filters(name):
            target.removeFilter(item)
    yield
    for target, filters, propagate, handlers in saved:
        target.filters[:] = filters
        target.propagate = propagate
        target.handlers[:] = handlers


@pytest.fixture
def quiet_main(monkeypatch: pytest.MonkeyPatch) -> None:
    """``main`` without real wiring, server start or a new root handler."""
    monkeypatch.setattr(server_main, "configure_logging", lambda level: None)
    monkeypatch.setattr(server_main, "check_preflight", lambda settings: None)
    monkeypatch.setattr(server_main, "build_app", lambda settings: object())
    monkeypatch.setattr(server_main, "build_worker_app", lambda settings: object())
    monkeypatch.setattr(server_main.uvicorn, "run", lambda app, **kwargs: None)


@pytest.mark.usefixtures("bare_loggers", "quiet_main")
@pytest.mark.parametrize("role", ["api", "worker"])
def test_every_role_without_the_proxy_installs_the_redaction(
    monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    _serve_env(monkeypatch, role=role, proxy=False)
    server_main.main([])
    for name in REDACTED_LOGGERS:
        assert len(token_filters(name)) == 1, name


def _start_shared_process(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    servers: list[Any] = []

    async def capture(*started: Any) -> None:
        servers.extend(started)

    monkeypatch.setattr(server_main, "_serve_together", capture)
    monkeypatch.setattr(server_main, "create_app", lambda settings=None: object())
    monkeypatch.setattr(server_main, "create_proxy_app", lambda settings, *, api_app: object())
    _serve_env(monkeypatch, role="all", proxy=True)
    server_main.main([])
    return servers


@pytest.mark.usefixtures("bare_loggers")
def test_the_shared_process_keeps_the_proxy_access_log(monkeypatch: pytest.MonkeyPatch) -> None:
    servers = _start_shared_process(monkeypatch)
    assert [server.config.access_log for server in servers] == [False, True]
    assert logging.getLogger(ACCESS).propagate is True


@pytest.mark.usefixtures("bare_loggers")
def test_a_proxied_access_line_reaches_the_root_handler_redacted(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _start_shared_process(monkeypatch)
    install_log_redaction()
    caplog.set_level(logging.INFO)
    path = f"/p?keep=1&{TOKEN_PARAM}=SECRETAAA1"
    logging.getLogger(ACCESS).info(HTTP_FORMAT, "10.0.0.1:5", "GET", path, "1.1", 200)
    assert "SECRETAAA1" not in caplog.text
    assert f"{TOKEN_PARAM}={REDACTED}" in caplog.text
    assert "keep=1" in caplog.text


def test_every_secret_param_in_a_query_is_redacted() -> None:
    query = f"{TOKEN_PARAM}=A1&token=B2&x=3&{TOKEN_PARAM}=C3"
    expected = f"{TOKEN_PARAM}={REDACTED}&token={REDACTED}&x=3&{TOKEN_PARAM}={REDACTED}"
    assert redact_query_token(query) == expected


def test_a_message_with_two_urls_is_fully_redacted() -> None:
    line = record(f"a /p?token=AAA1 b /q?{TOKEN_PARAM}=BBB2")
    TokenRedactingFilter().filter(line)
    message = line.getMessage()
    assert "AAA1" not in message
    assert "BBB2" not in message


def test_mixed_case_upstream_headers_are_replaced_on_the_token_response() -> None:
    upstream = [
        (b"Cache-Control", b"max-age=60"),
        (b"Referrer-Policy", b"origin"),
        (b"content-type", b"text/plain"),
    ]
    assert with_token_response_headers(upstream) == [
        (b"content-type", b"text/plain"),
        *TOKEN_RESPONSE_HEADERS,
    ]


def test_a_referer_fragment_survives_the_token_strip() -> None:
    referer = f"http://h.test/p?{TOKEN_PARAM}=T0K&a=1#frag"
    assert strip_referer_token(referer) == "http://h.test/p?a=1#frag"
