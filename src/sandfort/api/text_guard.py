"""One generic guard against lone surrogates and NUL characters in request text (round 53).

A lone UTF-16 surrogate (the JSON escape ``\\ud800``) cannot be encoded as UTF-8 and a NUL
character cannot be stored by every database; either one reaching a route answered 500, or was
stored (labels, env, cwd, audit details) and broke every later read. ``TextGuardMiddleware``
refuses such a request before any route runs, so nothing is stored or audited as accepted:

* the URL path (its raw bytes percent-decoded as strict UTF-8 when the server passes
  ``raw_path``, so an encoded surrogate or invalid UTF-8 in the path is refused before routing
  instead of becoming U+FFFD, round 54; then the decoded path for NUL and surrogates), and
  every query parameter name and value (percent-decoded as strict UTF-8, so invalid UTF-8 in
  the query string is refused as well; a bad name is located by its percent-encoded form,
  never echoed raw);
* a JSON body that is not valid UTF-8 (``invalid_utf8`` at ``["body"]``, round 58), then every
  string in it, object keys included, at any depth. A body is inspected when its
  ``Content-Type`` is absent or names JSON; other bodies (file uploads) are never read.

Three more refusals come from the one parse of a JSON body (``_parse``): an object that repeats a
key (``duplicate_key``, located at the object: ``json.loads`` would keep the last value
silently), nesting deeper than ``MAX_DEPTH`` (also when the parser itself gives up) and an
integer of more than ``MAX_INT_DIGITS`` digits (``integer_too_long``), all at ``["body", ...]``.
A non-empty body whose ``Content-Type`` is neither ``application/json`` nor ``application/*+json``
is a 415 ``UNSUPPORTED_MEDIA_TYPE`` (SCIM, which answers in its own form, and the upload route
excepted).

The answer is 422 ``VALIDATION_ERROR`` with the usual ``details.errors`` entries (``type``,
``loc``, ``msg``); the offending text is never echoed. A bad object key is located at the
object that holds it. The process ``stdin`` field of the exec route may carry NUL (binary
input is legitimate); a lone surrogate is refused there too. The refusal is not audited: it
happens before authentication and nothing about the request is recorded.

The body walk is bounded: it keeps one iterator per nesting level and one mutable path, builds a
location only for a finding, stops after ``MAX_FINDINGS`` and refuses a body nested deeper than
``MAX_DEPTH``. Every JSON body is parsed once; the tree is walked only when the parse saw a
repeated key or a byte-level pre-filter (``needs_parse``, ``_may_be_too_deep``) says it could
hold a surrogate, a NUL or too deep a nesting. A body above ``OFFLOAD_BYTES``
is parsed and walked in a worker thread of the guard's own ``GUARD_LIMITER`` (a few workers), so
a big document does not stall the event loop and guard work never takes threads from the shared
default pool the routes use. Websocket handshakes get the path and query checks; a refused one
gets the same 422 envelope when the server supports the ASGI websocket denial-response
extension, else it is closed with the policy-violation code.
"""

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_from_bytes, unquote, unquote_to_bytes

import anyio.to_thread
from fastapi.exceptions import RequestValidationError
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sandfort.api.errors import REQUEST_ID_ATTR, error_response
from sandfort.api.middleware.body_limit import UPLOAD_PATH
from sandfort.api.safe_json import LONE_SURROGATE
from sandfort.errors import UnsupportedMediaType

NUL = "\x00"
MAX_FINDINGS = 10
MAX_SEGMENT_CHARS = 64
MAX_DEPTH = 64  # nesting levels of arrays and objects a body may have
MAX_INT_DIGITS = 64  # digits an integer in a body may have (a sign is not counted)
OFFLOAD_BYTES = 64 * 1024  # bodies above this are parsed and walked off the event loop
GUARD_WORKERS = 4  # threads the guard may hold at once; it never uses the shared default pool
GUARD_LIMITER = anyio.CapacityLimiter(GUARD_WORKERS)
# What a parse could refuse: a NUL byte (also present in any UTF-16/32 body), a ``\u`` escape for
# NUL or for a code point in the surrogate range, or a UTF-8-encoded surrogate (``json.loads``
# decodes bytes with ``surrogatepass``). Over-matching (an escaped backslash) only costs a parse.
SUSPECT_BYTES = re.compile(rb"\x00|\\u(?:0000|[dD][89a-fA-F][0-9a-fA-F]{2})|\xed[\xa0-\xbf]")
JSON_ESCAPE = b"\\u"
OPENING_BRACKETS = (b"[", b"{")
WS_POLICY_VIOLATION = 1008
WS_DENIAL_EXTENSION = "websocket.http.response"  # ASGI: answer a handshake with an HTTP response
BODYLESS_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
EXEC_PATH = re.compile(r"/v1/sandboxes/[^/]+/toolbox/process/execute/?")
STDIN_KEY = "stdin"

SURROGATE_TYPE = "surrogate_in_string"
NUL_TYPE = "nul_in_string"
UTF8_TYPE = "invalid_utf8"
DEPTH_TYPE = "nesting_too_deep"
INTEGER_TYPE = "integer_too_long"
DUPLICATE_TYPE = "duplicate_key"
_MESSAGES = {
    SURROGATE_TYPE: "Text must not contain a lone UTF-16 surrogate",
    NUL_TYPE: "Text must not contain a NUL character",
    UTF8_TYPE: "Percent-encoded text is not valid UTF-8",
    DEPTH_TYPE: "Body is nested too deeply",
    INTEGER_TYPE: f"Integers may have at most {MAX_INT_DIGITS} digits",
}
UNSUPPORTED_MEDIA_MESSAGE = "request bodies must be sent as application/json"
JSON_MEDIA_TYPE = "application/json"
SCIM_PATH = re.compile(r"/scim/v2(?:/.*)?")  # answers its own media-type errors, in SCIM form
BODY_UTF8_MESSAGE = "Body is not valid UTF-8"  # the body variant of UTF8_TYPE (round 58)


@dataclass(frozen=True, slots=True)
class Finding:
    """One refused piece of text: where it is and which rule it broke (never its content)."""

    loc: tuple[str, ...]
    kind: str
    message: str | None = None  # overrides the fixed wording of ``kind`` (a duplicate key)

    def as_error(self) -> dict[str, Any]:
        message = self.message or (BODY_UTF8_MESSAGE if self.is_body_utf8 else _MESSAGES[self.kind])
        return {"type": self.kind, "loc": list(self.loc), "msg": message}

    @property
    def is_body_utf8(self) -> bool:
        return self.kind == UTF8_TYPE and self.loc == ("body",)


def _problem(text: str, *, allow_nul: bool = False) -> str | None:
    """The rule ``text`` breaks, or ``None``; plain ASCII (the common case) is not scanned."""
    if not text.isascii() and LONE_SURROGATE.search(text) is not None:
        return SURROGATE_TYPE
    return None if allow_nul or NUL not in text else NUL_TYPE


def _segment(part: str) -> str:
    return part if len(part) <= MAX_SEGMENT_CHARS else part[:MAX_SEGMENT_CHARS] + "…"


def _undecodable_kind(data: bytes) -> str:
    """Why ``data`` (not strict UTF-8) was refused: an encoded lone surrogate, or bad bytes."""
    try:
        data.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        return UTF8_TYPE
    return SURROGATE_TYPE


def _raw_path_problem(raw_path: bytes) -> str | None:
    """The rule the percent-decoded bytes of ``raw_path`` break, or ``None`` (round 54).

    The server decodes the path with U+FFFD for bytes that are not UTF-8, so ``scope["path"]``
    alone cannot tell ``%ED%A0%80`` (an encoded surrogate) or ``%FF`` from a real U+FFFD; the
    raw bytes can. A query string a client left on ``raw_path`` is not part of the path.
    """
    decoded = unquote_to_bytes(raw_path.split(b"?", 1)[0])
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return _undecodable_kind(decoded)
    return _problem(text)


def path_findings(path: str, raw_path: bytes | None = None) -> list[Finding]:
    """The path: its raw percent-encoded bytes when the server gives them, then the decoded
    form the router will see (a direct caller may pass a NUL or surrogate there only)."""
    kind = None if raw_path is None else _raw_path_problem(raw_path)
    if kind is None:
        kind = _problem(path)
    return [] if kind is None else [Finding(("path",), kind)]


def _decode_strict(raw: str) -> str | None:
    """Percent-decode ``raw`` (``+`` is a space) as strict UTF-8; ``None`` when it is invalid."""
    try:
        return unquote(raw.replace("+", " "), encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _wire_name(raw_name: str) -> str:
    """A parameter name as it arrived (percent-encoded): named, never echoed raw."""
    return _segment(quote_from_bytes(raw_name.encode("latin-1"), safe="%"))


def query_findings(query_string: bytes) -> list[Finding]:
    """Every parameter name and value of the raw query string, decoded as strict UTF-8."""
    findings: list[Finding] = []
    for pair in query_string.decode("latin-1").split("&"):
        if not pair:
            continue
        raw_name, _, raw_value = pair.partition("=")
        name = _decode_strict(raw_name)
        if name is None:
            findings.append(Finding(("query", _wire_name(raw_name)), UTF8_TYPE))
            continue
        name_problem = _problem(name)
        if name_problem is not None:
            findings.append(Finding(("query", _wire_name(raw_name)), name_problem))
            continue
        value = _decode_strict(raw_value)
        value_problem = UTF8_TYPE if value is None else _problem(value)
        if value_problem is not None:
            findings.append(Finding(("query", _segment(name)), value_problem))
    return findings


class _Repeating(dict[str, Any]):
    """An object whose source repeated a key; ``repeated`` names each such key once.

    Only the parse hook makes these. The last value wins in the dict, as in ``json.loads``, but
    the guard refuses the body, so nothing downstream ever sees the last-wins reading.
    """

    repeated: tuple[str, ...] = ()


class _IntegerTooLong(Exception):
    """Raised by the integer parse hook; never leaves this module."""


def duplicate_finding(path: list[str], key: str) -> Finding:
    """The finding for ``key`` repeated in the object at ``path`` (the key is escaped)."""
    shown = json.dumps(_segment(key), ensure_ascii=False)[1:-1]
    return Finding(("body", *path), DUPLICATE_TYPE, f"duplicate key '{shown}' in the request body")


def _object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded = dict(pairs)
    if len(decoded) == len(pairs):
        return decoded
    seen: set[str] = set()
    repeated: dict[str, None] = {}
    for key, _ in pairs:
        if key in seen:
            repeated[key] = None
        seen.add(key)
    marked = _Repeating(decoded)
    marked.repeated = tuple(repeated)
    return marked


def _parse_int(text: str) -> int:
    if len(text) - text.startswith("-") > MAX_INT_DIGITS:
        raise _IntegerTooLong
    return int(text)


def _parse(body: bytes) -> tuple[Any, bool]:
    """The document and whether any object repeated a key; integers are capped in length."""
    repeats = False

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal repeats
        decoded = _object_hook(pairs)
        repeats = repeats or isinstance(decoded, _Repeating)
        return decoded

    document = json.loads(body, object_pairs_hook=hook, parse_int=_parse_int)
    return document, repeats


type _Child = tuple[str, Any, str | None]  # location segment, value, object key (None: array)


def _array_children(value: list[Any]) -> Iterator[_Child]:
    for index, item in enumerate(value):
        yield str(index), item, None


def _object_children(
    value: dict[str, Any], path: list[str], findings: list[Finding]
) -> Iterator[_Child]:
    """Children of an object; a bad key is recorded at the object that holds it and skipped.

    A key the object repeated is a ``duplicate_key`` finding at the object too. Lazy on
    purpose: ``path`` is the object's own location whenever this generator runs.
    """
    if isinstance(value, _Repeating):
        for repeated in value.repeated:
            if len(findings) < MAX_FINDINGS:
                findings.append(duplicate_finding(path, repeated))
    for key, item in value.items():
        key_problem = _problem(key)
        if key_problem is None:
            yield _segment(key), item, key
        elif len(findings) < MAX_FINDINGS:
            findings.append(Finding(("body", *path), key_problem))


def _children(
    value: list[Any] | dict[str, Any], path: list[str], findings: list[Finding]
) -> Iterator[_Child]:
    if isinstance(value, list):
        return _array_children(value)
    return _object_children(value, path, findings)


def json_findings(
    document: Any, *, nul_allowed_keys: frozenset[str] = frozenset()
) -> list[Finding]:
    """Strings of a parsed JSON ``document``, keys included; at most ``MAX_FINDINGS`` results.

    Walks with a stack of iterators and one mutable path, so memory follows the nesting depth and
    not the element count; a location is built only when a finding is hit. A document nested
    deeper than ``MAX_DEPTH`` is answered with one finding at the body, not walked. The keys in
    ``nul_allowed_keys`` may hold NUL, but only as a direct field of the top-level object.
    """
    if isinstance(document, str):
        kind = _problem(document)
        return [] if kind is None else [Finding(("body",), kind)]
    if not isinstance(document, list | dict):
        return []
    findings: list[Finding] = []
    path: list[str] = []
    stack: list[Iterator[_Child]] = [_children(document, path, findings)]
    while stack and len(findings) < MAX_FINDINGS:
        try:
            segment, child, key = next(stack[-1])
        except StopIteration:
            stack.pop()
            if path:
                path.pop()
            continue
        if isinstance(child, str):
            allowed = len(stack) == 1 and key is not None and key in nul_allowed_keys
            kind = _problem(child, allow_nul=allowed)
            if kind is not None:
                findings.append(Finding(("body", *path, segment), kind))
        elif isinstance(child, list | dict):
            if len(stack) >= MAX_DEPTH:
                return [Finding(("body",), DEPTH_TYPE)]
            path.append(segment)
            stack.append(_children(child, path, findings))
    return findings[:MAX_FINDINGS]


def _scan(body: bytes, nul_allowed_keys: frozenset[str]) -> list[Finding]:
    try:
        document, repeats = _parse(body)
    except RecursionError:
        return [Finding(("body",), DEPTH_TYPE)]  # the parser itself gave up: far too deep
    except _IntegerTooLong:
        return [Finding(("body",), INTEGER_TYPE)]
    except ValueError:
        return []
    if not (repeats or needs_parse(body) or _may_be_too_deep(body)):
        return []
    return json_findings(document, nul_allowed_keys=nul_allowed_keys)


def _may_be_too_deep(body: bytes) -> bool:
    """Nesting can exceed ``MAX_DEPTH`` only with more opening brackets than that (upper bound)."""
    return sum(body.count(bracket) for bracket in OPENING_BRACKETS) > MAX_DEPTH


def needs_parse(body: bytes) -> bool:
    """Whether parsing ``body`` could give a finding; a byte-level check, no JSON parse.

    True for ``SUSPECT_BYTES``, and for a body with any ``\\u`` escape that may be nested deeper
    than ``MAX_DEPTH`` (such a body was always parsed and refused at the body; keep it so).
    """
    if SUSPECT_BYTES.search(body) is not None:
        return True
    return JSON_ESCAPE in body and _may_be_too_deep(body)


def has_invalid_utf8(body: bytes) -> bool:
    """Whether a JSON ``body`` in UTF-8 holds bytes that are not UTF-8 (round 58).

    ASCII is never decoded. A body the JSON parser reads as UTF-16/32 is not judged here, and an
    encoded surrogate (decodable with ``surrogatepass``) is left to the surrogate check.
    """
    if body.isascii() or not json.detect_encoding(body).startswith("utf-8"):
        return False
    try:
        body.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        return True
    return False


def body_findings(body: bytes, *, nul_allowed_keys: frozenset[str] = frozenset()) -> list[Finding]:
    """Findings in a JSON ``body``; a body that is not JSON is left for the route to refuse.

    Every body is parsed once (with the hooks of ``_parse``: a repeated object key, an integer
    of more than ``MAX_INT_DIGITS`` digits and a nesting the parser gives up on are findings).
    The tree is walked only when the parse or ``needs_parse`` says it could hold a finding.
    Invalid UTF-8 is refused first, without echoing any byte.
    """
    if has_invalid_utf8(body):
        return [Finding(("body",), UTF8_TYPE)]
    return _scan(body, nul_allowed_keys)


async def body_findings_async(
    body: bytes, *, nul_allowed_keys: frozenset[str] = frozenset()
) -> list[Finding]:
    """``body_findings``; above ``OFFLOAD_BYTES`` the parse runs on a ``GUARD_LIMITER`` thread."""
    if has_invalid_utf8(body):
        return [Finding(("body",), UTF8_TYPE)]
    if len(body) <= OFFLOAD_BYTES:
        return _scan(body, nul_allowed_keys)
    return await anyio.to_thread.run_sync(
        lambda: _scan(body, nul_allowed_keys), limiter=GUARD_LIMITER
    )


def _media_type(headers: Headers) -> str | None:
    content_type = headers.get("content-type")
    if content_type is None:
        return None
    return content_type.partition(";")[0].strip().lower()


def _is_json_media(media_type: str | None) -> bool:
    """Absent, ``application/json`` or ``application/<x>+json`` (what the routes parse)."""
    if media_type is None or media_type == JSON_MEDIA_TYPE:
        return True
    return media_type.startswith("application/") and media_type.endswith("+json")


async def _read_body(receive: Receive) -> tuple[bytes, Message | None]:
    """The whole request body; a disconnect message is returned instead of being swallowed."""
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            return b"".join(chunks), message
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            return b"".join(chunks), None


def _replaying(body: bytes, disconnect: Message | None, receive: Receive) -> Receive:
    """A ``receive`` that serves the buffered body once, then whatever the server sends next."""
    pending: list[Message] = [{"type": "http.request", "body": body, "more_body": False}]
    if disconnect is not None:
        pending = [disconnect]

    async def replay() -> Message:
        return pending.pop(0) if pending else await receive()

    return replay


class TextGuardMiddleware:
    """Refuses a request carrying a lone surrogate or NUL text, a repeated object key, a body nested
    too deeply or holding an integer with too many digits, or a non-JSON body (see the module
    docstring)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        findings = [
            *path_findings(scope["path"], scope.get("raw_path")),
            *query_findings(scope.get("query_string", b"")),
        ]
        if scope["type"] == "websocket":
            if not findings:
                await self.app(scope, receive, send)
            elif WS_DENIAL_EXTENSION in scope.get("extensions", {}):
                await self._refuse(findings, scope, receive, send)  # the HTTP 422 envelope
            else:
                # Closed before accept: the code is advisory only; the server turns a close
                # before accept into a handshake rejection (HTTP 403), the client never sees 1008.
                await send({"type": "websocket.close", "code": WS_POLICY_VIOLATION})
            return
        downstream = receive
        if not findings and self._inspects_body(scope):
            body, disconnect = await _read_body(receive)
            downstream = _replaying(body, disconnect, receive)
            if _is_json_media(_media_type(Headers(scope=scope))):
                allowed = (
                    frozenset({STDIN_KEY}) if EXEC_PATH.fullmatch(scope["path"]) else frozenset()
                )
                findings = await body_findings_async(body, nul_allowed_keys=allowed)
            elif body and not SCIM_PATH.fullmatch(scope["path"]):
                await self._refuse_media(scope, receive, send)
                return
        if findings:
            await self._refuse(findings, scope, receive, send)
            return
        await self.app(scope, downstream, send)

    @staticmethod
    def _inspects_body(scope: Scope) -> bool:
        return scope["method"] not in BODYLESS_METHODS and not UPLOAD_PATH.fullmatch(scope["path"])

    @staticmethod
    async def _refuse_media(scope: Scope, receive: Receive, send: Send) -> None:
        refusal = UnsupportedMediaType(
            UNSUPPORTED_MEDIA_MESSAGE, details={"supported": [JSON_MEDIA_TYPE]}
        )
        request_id = scope.get("state", {}).get(REQUEST_ID_ATTR)
        await error_response(refusal, request_id=request_id)(scope, receive, send)

    @staticmethod
    async def _refuse(
        findings: Iterable[Finding], scope: Scope, receive: Receive, send: Send
    ) -> None:
        refusal = RequestValidationError([finding.as_error() for finding in findings])
        request_id = scope.get("state", {}).get(REQUEST_ID_ATTR)
        await error_response(refusal, request_id=request_id)(scope, receive, send)
