"""PTY toolbox facade (``sandbox.pty``): REST lifecycle plus an interactive websocket session.

``create`` opens a terminal over REST, then connects to the returned websocket url with the
single-use connect token appended as ``?token=``. The token is spent by that one connect and
never kept, logged or shown. Input goes out as binary frames, output arrives as binary
frames; a ``4401`` close means the token was rejected (expired, invalid or already used).
Closing the session closes the websocket, which tears the terminal down on the server.
"""

from collections.abc import AsyncIterator, Iterator
from types import TracebackType
from typing import Any, Self
from urllib.parse import (
    SplitResult,
    parse_qsl,
    quote,
    quote_plus,
    urlencode,
    urlsplit,
    urlunsplit,
)

from websockets.asyncio import client as async_ws
from websockets.exceptions import ConnectionClosed, ConnectionClosedOK, WebSocketException
from websockets.sync import client as sync_ws

from sandfort_sdk._requests import area_path, segment
from sandfort_sdk._transport import AsyncTransport, SyncTransport
from sandfort_sdk.exceptions import SandfortSDKError, TransportError, Unauthorized
from sandfort_sdk.models import PtyInfo, _as_dict, _as_list, _required

WS_CLOSE_UNAUTHORIZED = 4401
PTY_EXIT_CLOSE_BASE = 4000  # the server closes with 4000 + n when the terminal's process exits n
PTY_EXIT_CLOSE_MAX = PTY_EXIT_CLOSE_BASE + 255
DEFAULT_ROWS = 24
DEFAULT_COLS = 80


_WS_SCHEMES = {"http": "ws", "https": "wss"}


def _websocket_scheme(parts: SplitResult, base_url: str | None) -> str:
    """The ``ws`` / ``wss`` scheme to dial; plain ``ws`` is upgraded for an https base, same host.

    An older server behind a TLS-terminating proxy builds ``ws://`` urls for its own public host;
    dialing that plain scheme gets redirected to https and fails, so ``wss`` is used instead.
    """
    scheme = _WS_SCHEMES.get(parts.scheme, parts.scheme)
    if scheme != "ws" or base_url is None:
        return scheme
    base = urlsplit(base_url)
    same_host = (base.hostname, base.port) == (parts.hostname, parts.port)
    return "wss" if base.scheme == "https" and same_host else scheme


def connect_url(websocket_url: str, token: str, base_url: str | None = None) -> str:
    """``websocket_url`` with ``token`` set as its (only) ``token`` query parameter.

    A TLS-terminated server reflects its public base, so the url may arrive with an ``http`` or
    ``https`` scheme; the websocket client needs ``ws`` / ``wss``, so those are mapped here. With
    the client's ``base_url`` given, a plain ``ws`` url for that same https host dials ``wss``.
    """
    parts = urlsplit(websocket_url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "token"]
    scheme = _websocket_scheme(parts, base_url)
    return urlunsplit(parts._replace(scheme=scheme, query=urlencode([*query, ("token", token)])))


def _base_url(transport: SyncTransport | AsyncTransport) -> str:
    """The base url the transport sends its REST calls to."""
    return str(transport._http.base_url)


def _pty_path(sandbox_id: str, pty_id: str | None = None, tail: str = "") -> str:
    suffix = "" if pty_id is None else f"/{segment(pty_id)}"
    return area_path(sandbox_id, "pty", f"{suffix}{tail}")


def _create_body(
    rows: int, cols: int, argv: list[str] | None, env: dict[str, str] | None
) -> dict[str, Any]:
    body: dict[str, Any] = {"rows": rows, "cols": cols, "argv": argv, "env": env}
    return {key: value for key, value in body.items() if value is not None}


def _connect_info(data: Any) -> tuple[str, str, str]:
    """``(pty_id, token, websocket_url)`` from the create reply (errors never echo values)."""
    raw = _as_dict(data, "pty connect")
    pty_id, token, url = _required(raw, "pty connect", "pty_id", "token", "websocket_url")
    return pty_id, token, url


def _ptys(data: Any) -> tuple[PtyInfo, ...]:
    return tuple(PtyInfo.from_payload(item) for item in _as_list(data, "ptys"))


def _connect_error(exc: Exception, token: str) -> TransportError:
    """Connect failure with the token scrubbed (raw and url-encoded) from the detail."""
    detail = f"{type(exc).__name__}: {exc}"
    for secret in (token, quote_plus(token), quote(token, safe="")):
        detail = detail.replace(secret, "***")
    return TransportError(f"pty websocket connect failed: {detail}")


def exit_code_from_close(code: int | None) -> int | None:
    """The terminal's exit code carried by close ``code`` (4000..4255), else ``None``."""
    if code is not None and PTY_EXIT_CLOSE_BASE <= code <= PTY_EXIT_CLOSE_MAX:
        return code - PTY_EXIT_CLOSE_BASE
    return None


def _received_code(exc: ConnectionClosed) -> int | None:
    return None if exc.rcvd is None else exc.rcvd.code


def _final_close_code(seen: int | None, websocket: Any) -> int | None:
    """The close code the server sent: the one seen while reading, else the socket's own."""
    if seen is not None:
        return seen
    code = getattr(websocket, "close_code", None)
    return code if isinstance(code, int) else None


def _closed_error(exc: ConnectionClosed) -> SandfortSDKError | None:
    """``None`` for a normal close, else the typed error for how the socket ended."""
    code = _received_code(exc)
    if code == WS_CLOSE_UNAUTHORIZED:
        return Unauthorized("pty connect token was rejected (expired, invalid or already used)")
    if isinstance(exc, ConnectionClosedOK) or exit_code_from_close(code) is not None:
        return None  # the terminal ended (4000 + n carries the exit code n)
    return TransportError(f"pty websocket closed abnormally: {exc}")


def _send_error(exc: ConnectionClosed) -> SandfortSDKError:
    return _closed_error(exc) or TransportError("pty websocket is closed")


def _as_bytes(message: str | bytes) -> bytes:
    return message if isinstance(message, bytes) else message.encode()


def _open(url: str, token: str) -> sync_ws.ClientConnection:
    try:
        return sync_ws.connect(url, legacy=True)
    except (WebSocketException, OSError) as exc:
        raise _connect_error(exc, token) from None  # the cause may carry the token-bearing url


async def _aopen(url: str, token: str) -> async_ws.ClientConnection:
    try:
        return await async_ws.connect(url)
    except (WebSocketException, OSError) as exc:
        raise _connect_error(exc, token) from None


class PtySession:
    """A connected terminal: ``send_bytes``, iterate output bytes, ``resize``, ``close``."""

    def __init__(self, pty: "Pty", pty_id: str, websocket: sync_ws.ClientConnection) -> None:
        self._pty = pty
        self._websocket = websocket
        self._close_code: int | None = None
        self.id = pty_id

    def __repr__(self) -> str:
        return f"PtySession(id={self.id!r})"

    @property
    def exit_code(self) -> int | None:
        """The terminal process's exit code once the connection closed; else ``None``."""
        return exit_code_from_close(_final_close_code(self._close_code, self._websocket))

    def send_bytes(self, data: bytes) -> None:
        try:
            self._websocket.send(bytes(data))
        except ConnectionClosed as exc:
            raise _send_error(exc) from None

    def __iter__(self) -> Iterator[bytes]:
        """Terminal output until the terminal ends (normal close) or the socket fails."""
        while True:
            try:
                message = self._websocket.recv()
            except ConnectionClosed as exc:
                self._close_code = _received_code(exc)
                error = _closed_error(exc)
                if error is None:
                    return
                raise error from None
            yield _as_bytes(message)

    def resize(self, rows: int, cols: int) -> PtyInfo:
        return self._pty.resize(self.id, rows, cols)

    def close(self) -> None:
        self._websocket.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncPtySession:
    """Async counterpart of :class:`PtySession` (``async with`` / ``async for``)."""

    def __init__(self, pty: "AsyncPty", pty_id: str, websocket: async_ws.ClientConnection) -> None:
        self._pty = pty
        self._websocket = websocket
        self._close_code: int | None = None
        self.id = pty_id

    def __repr__(self) -> str:
        return f"AsyncPtySession(id={self.id!r})"

    @property
    def exit_code(self) -> int | None:
        """The terminal process's exit code once the connection closed; else ``None``."""
        return exit_code_from_close(_final_close_code(self._close_code, self._websocket))

    async def send_bytes(self, data: bytes) -> None:
        try:
            await self._websocket.send(bytes(data))
        except ConnectionClosed as exc:
            raise _send_error(exc) from None

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while True:
            try:
                message = await self._websocket.recv()
            except ConnectionClosed as exc:
                self._close_code = _received_code(exc)
                error = _closed_error(exc)
                if error is None:
                    return
                raise error from None
            yield _as_bytes(message)

    async def resize(self, rows: int, cols: int) -> PtyInfo:
        return await self._pty.resize(self.id, rows, cols)

    async def aclose(self) -> None:
        await self._websocket.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


class Pty:
    """Synchronous pty toolbox of one sandbox."""

    def __init__(self, sandbox_id: str, transport: SyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    def create(
        self,
        *,
        rows: int = DEFAULT_ROWS,
        cols: int = DEFAULT_COLS,
        argv: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> PtySession:
        """Create a terminal and connect to it (``argv=None`` runs the default shell)."""
        body = _create_body(rows, cols, argv, env)
        reply = self._transport.request("POST", _pty_path(self._sandbox_id), json=body)
        pty_id, token, url = _connect_info(reply.data)
        target = connect_url(url, token, _base_url(self._transport))
        return PtySession(self, pty_id, _open(target, token))

    def list_ptys(self) -> tuple[PtyInfo, ...]:
        return _ptys(self._transport.request("GET", _pty_path(self._sandbox_id)).data)

    def get(self, pty_id: str) -> PtyInfo:
        reply = self._transport.request("GET", _pty_path(self._sandbox_id, pty_id))
        return PtyInfo.from_payload(reply.data)

    def resize(self, pty_id: str, rows: int, cols: int) -> PtyInfo:
        path = _pty_path(self._sandbox_id, pty_id, "/resize")
        reply = self._transport.request("POST", path, json={"rows": rows, "cols": cols})
        return PtyInfo.from_payload(reply.data)

    def delete(self, pty_id: str) -> PtyInfo:
        """Close a terminal over REST (e.g. one whose session object is gone)."""
        reply = self._transport.request("DELETE", _pty_path(self._sandbox_id, pty_id))
        return PtyInfo.from_payload(reply.data)


class AsyncPty:
    """Asynchronous pty toolbox of one sandbox."""

    def __init__(self, sandbox_id: str, transport: AsyncTransport) -> None:
        self._sandbox_id = sandbox_id
        self._transport = transport

    async def create(
        self,
        *,
        rows: int = DEFAULT_ROWS,
        cols: int = DEFAULT_COLS,
        argv: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> AsyncPtySession:
        body = _create_body(rows, cols, argv, env)
        reply = await self._transport.request("POST", _pty_path(self._sandbox_id), json=body)
        pty_id, token, url = _connect_info(reply.data)
        target = connect_url(url, token, _base_url(self._transport))
        return AsyncPtySession(self, pty_id, await _aopen(target, token))

    async def list_ptys(self) -> tuple[PtyInfo, ...]:
        return _ptys((await self._transport.request("GET", _pty_path(self._sandbox_id))).data)

    async def get(self, pty_id: str) -> PtyInfo:
        reply = await self._transport.request("GET", _pty_path(self._sandbox_id, pty_id))
        return PtyInfo.from_payload(reply.data)

    async def resize(self, pty_id: str, rows: int, cols: int) -> PtyInfo:
        path = _pty_path(self._sandbox_id, pty_id, "/resize")
        reply = await self._transport.request("POST", path, json={"rows": rows, "cols": cols})
        return PtyInfo.from_payload(reply.data)

    async def delete(self, pty_id: str) -> PtyInfo:
        reply = await self._transport.request("DELETE", _pty_path(self._sandbox_id, pty_id))
        return PtyInfo.from_payload(reply.data)
