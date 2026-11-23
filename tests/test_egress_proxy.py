"""Egress token and CONNECT proxy tests; hermetic, loopback sockets only, no Docker."""

import asyncio
import base64
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta

import pytest

from sandfort.egress.proxy import EgressProxy, ProxyConfig, host_allowed
from sandfort.egress.tokens import (
    EGRESS_TOKEN_TTL_S,
    InvalidEgressToken,
    mint_egress_token,
    verify_egress_token,
)
from sandfort.webhooks import ssrf

SECRET = "test-egress-secret"
SANDBOX = "sbx_test"
ECHO_NAME = "echo.test"
IO_TIMEOUT_S = 5.0


def _now() -> datetime:
    return datetime.now(UTC)


def _token(allowlist: list[str], *, secret: str = SECRET, sandbox_id: str = SANDBOX) -> str:
    return mint_egress_token(secret, sandbox_id=sandbox_id, allowlist=allowlist, now=_now())


def _auth_header(sandbox_id: str, token: str) -> str:
    raw = base64.b64encode(f"{sandbox_id}:{token}".encode()).decode("ascii")
    return f"Proxy-Authorization: Basic {raw}"


# ---- tokens ------------------------------------------------------------------------------


def test_token_roundtrip_carries_sandbox_allowlist_and_expiry() -> None:
    now = _now()
    token = mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=["a.test", ".b.test"], now=now)

    claims = verify_egress_token(SECRET, token, now)

    assert claims.sandbox_id == SANDBOX
    assert claims.allowlist == ("a.test", ".b.test")
    assert claims.expires_at - claims.issued_at == timedelta(seconds=EGRESS_TOKEN_TTL_S)


def test_wrong_secret_is_rejected() -> None:
    token = _token(["a.test"])

    with pytest.raises(InvalidEgressToken):
        verify_egress_token("another-secret", token, _now())


def test_tampered_payload_is_rejected() -> None:
    forged_payload = _token(["evil.test"], secret="attacker-secret").split(".")[0]
    genuine_signature = _token(["a.test"]).split(".")[1]

    with pytest.raises(InvalidEgressToken):
        verify_egress_token(SECRET, f"{forged_payload}.{genuine_signature}", _now())


def _swap_char(token: str, index: int) -> str:
    replacement = "A" if token[index] != "A" else "B"
    return token[:index] + replacement + token[index + 1 :]


def test_tampered_signature_middle_character_is_rejected() -> None:
    token = _token(["a.test"])
    signature_start = token.index(".") + 1
    middle = signature_start + (len(token) - signature_start) // 2

    with pytest.raises(InvalidEgressToken):
        verify_egress_token(SECRET, _swap_char(token, middle), _now())


def test_tampered_signature_final_character_is_rejected() -> None:
    token = _token(["a.test"])

    with pytest.raises(InvalidEgressToken):
        verify_egress_token(SECRET, _swap_char(token, len(token) - 1), _now())


def test_expired_token_is_rejected() -> None:
    now = _now()
    token = mint_egress_token(SECRET, sandbox_id=SANDBOX, allowlist=["a.test"], now=now)
    later = now + timedelta(seconds=EGRESS_TOKEN_TTL_S + 1)

    with pytest.raises(InvalidEgressToken):
        verify_egress_token(SECRET, token, later)


@pytest.mark.parametrize("token", ["", "garbage", "sfe_", "sfe_abc", "sfe_a.b.c", "sf_a.b"])
def test_malformed_tokens_raise_the_generic_error(token: str) -> None:
    with pytest.raises(InvalidEgressToken) as caught:
        verify_egress_token(SECRET, token, _now())

    assert str(caught.value) == "invalid egress token"


def test_mint_refuses_an_empty_secret() -> None:
    with pytest.raises(ValueError):
        mint_egress_token("", sandbox_id=SANDBOX, allowlist=["a.test"], now=_now())


# ---- allowlist matching and configuration -------------------------------------------------


@pytest.mark.parametrize(
    ("host", "allowlist", "expected"),
    [
        ("api.example.com", ["api.example.com"], True),
        ("API.Example.com.", ["api.example.com"], True),
        ("x.api.example.com", ["api.example.com"], False),
        ("example.com", [".example.com"], True),
        ("a.b.example.com", [".example.com"], True),
        ("badexample.com", [".example.com"], False),
        ("example.com.evil.test", [".example.com"], False),
        ("anything.test", [], False),
        ("", [".example.com"], False),
    ],
)
def test_host_allowed(host: str, allowlist: list[str], expected: bool) -> None:
    assert host_allowed(host, allowlist) is expected


def test_config_reads_the_environment_and_hides_the_secret_from_repr() -> None:
    config = ProxyConfig.from_env(
        {
            "SANDFORT_EGRESS_SECRET": "hunter2-secret",
            "SANDFORT_EGRESS_LISTEN_HOST": "10.0.0.1",
            "SANDFORT_EGRESS_LISTEN_PORT": "8888",
        }
    )

    assert (config.host, config.port, config.secret) == ("10.0.0.1", 8888, "hunter2-secret")
    assert "hunter2-secret" not in repr(config)


@pytest.mark.parametrize(
    "environ",
    [{}, {"SANDFORT_EGRESS_SECRET": "s", "SANDFORT_EGRESS_LISTEN_PORT": "http"}],
)
def test_config_rejects_missing_secret_and_bad_port(environ: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        ProxyConfig.from_env(environ)


# ---- proxy over real sockets ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _strict_vetting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Other tests may opt in to private networks; the proxy tests need the default rules."""
    monkeypatch.setattr(ssrf, "_allow_private_networks", False)


@asynccontextmanager
async def _echo_server() -> AsyncIterator[int]:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await reader.read(1024)
            writer.write(data)
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def _running(proxy: EgressProxy) -> AsyncIterator[int]:
    server = await proxy.start("127.0.0.1", 0)
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()
        await server.wait_closed()


async def _exchange(port: int, lines: list[str]) -> bytes:
    """Send a raw request and read the answer until the proxy closes the connection."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        await writer.drain()
        return await asyncio.wait_for(reader.read(), IO_TIMEOUT_S)
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()


def _status(raw: bytes) -> int:
    return int(raw.split(b" ", 2)[1])


def _connect(target: str, auth: str | None) -> list[str]:
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if auth is not None:
        lines.append(auth)
    return lines


def _loopback_resolver(calls: list[str]) -> Callable[[str], Awaitable[list[str]]]:
    async def resolve(host: str) -> list[str]:
        calls.append(host)
        return ["127.0.0.1"]

    return resolve


def _permit_all(address: ssrf.IpAddress) -> None:
    """Stands in for the vetting rules in the one test that must reach loopback."""


async def test_allowlisted_localhost_is_refused_because_loopback_is_blocked() -> None:
    async with _echo_server() as echo_port, _running(EgressProxy(SECRET)) as port:
        auth = _auth_header(SANDBOX, _token(["localhost"]))

        raw = await _exchange(port, _connect(f"localhost:{echo_port}", auth))

    assert _status(raw) == 403


async def test_name_resolving_to_loopback_is_refused_by_the_real_vetting_rules() -> None:
    calls: list[str] = []
    proxy = EgressProxy(SECRET, resolver=_loopback_resolver(calls))
    async with _echo_server() as echo_port, _running(proxy) as port:
        auth = _auth_header(SANDBOX, _token([ECHO_NAME]))

        raw = await _exchange(port, _connect(f"{ECHO_NAME}:{echo_port}", auth))

    assert calls == [ECHO_NAME]
    assert _status(raw) == 403


async def test_valid_token_tunnels_to_the_vetted_upstream_when_vetting_is_permissive() -> None:
    calls: list[str] = []
    proxy = EgressProxy(SECRET, resolver=_loopback_resolver(calls), checker=_permit_all)
    async with _echo_server() as echo_port, _running(proxy) as port:
        auth = _auth_header(SANDBOX, _token([ECHO_NAME]))
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            request = "\r\n".join(_connect(f"{ECHO_NAME}:{echo_port}", auth)) + "\r\n\r\n"
            writer.write(request.encode("ascii"))
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT_S)
            writer.write(b"ping")
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(4), IO_TIMEOUT_S)
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    assert _status(head) == 200
    assert echoed == b"ping"
    assert calls == [ECHO_NAME]


async def test_wrong_token_gets_proxy_authentication_required() -> None:
    async with _running(EgressProxy(SECRET)) as port:
        auth = _auth_header(SANDBOX, _token([ECHO_NAME], secret="another-secret"))

        raw = await _exchange(port, _connect(f"{ECHO_NAME}:443", auth))

    assert _status(raw) == 407
    assert b"Proxy-Authenticate: Basic" in raw


async def test_missing_credential_gets_proxy_authentication_required() -> None:
    async with _running(EgressProxy(SECRET)) as port:
        raw = await _exchange(port, _connect(f"{ECHO_NAME}:443", None))

    assert _status(raw) == 407


async def test_username_that_is_not_the_token_sandbox_gets_407() -> None:
    async with _running(EgressProxy(SECRET)) as port:
        auth = _auth_header("sbx_other", _token([ECHO_NAME]))

        raw = await _exchange(port, _connect(f"{ECHO_NAME}:443", auth))

    assert _status(raw) == 407


async def test_host_outside_the_allowlist_is_forbidden_without_resolving_it() -> None:
    calls: list[str] = []
    proxy = EgressProxy(SECRET, resolver=_loopback_resolver(calls))
    async with _running(proxy) as port:
        auth = _auth_header(SANDBOX, _token([ECHO_NAME]))

        raw = await _exchange(port, _connect("other.test:443", auth))

    assert _status(raw) == 403
    assert calls == []


async def test_unresolvable_host_is_refused() -> None:
    async def unresolvable(host: str) -> list[str]:
        raise OSError("no such host")

    async with _running(EgressProxy(SECRET, resolver=unresolvable)) as port:
        auth = _auth_header(SANDBOX, _token([ECHO_NAME]))

        raw = await _exchange(port, _connect(f"{ECHO_NAME}:443", auth))

    assert _status(raw) == 502


async def test_non_connect_request_gets_method_not_allowed() -> None:
    async with _running(EgressProxy(SECRET)) as port:
        auth = _auth_header(SANDBOX, _token([ECHO_NAME]))

        raw = await _exchange(port, ["GET http://echo.test/ HTTP/1.1", "Host: echo.test", auth])

    assert _status(raw) == 405
    assert b"Allow: CONNECT" in raw


async def test_malformed_target_is_a_bad_request() -> None:
    async with _running(EgressProxy(SECRET)) as port:
        auth = _auth_header(SANDBOX, _token([ECHO_NAME]))

        raw = await _exchange(port, _connect("no-port-here", auth))

    assert _status(raw) == 400
