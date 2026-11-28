"""Preview token hygiene: keep the ``TOKEN_PARAM`` value out of logs, Referer and caches.

The proxy strips the token from the forwarded query, but the first request still carries it in
its URL. ``TokenRedactingFilter`` rewrites uvicorn's access and websocket log lines so the value
reads ``REDACTED``. ``strip_referer_token`` cuts the parameter from a ``Referer`` and
``strip_header_token`` does the same for any header value, wherever the parameter sits in it.
The proxy runs it on every forwarded request header, so an edge's ``X-Url`` or ``X-Pathname``
cannot carry the token to the app. ``PROXY_RESPONSE_HEADERS`` go on every response the proxy
builds itself, and
``with_token_response_headers`` puts ``TOKEN_RESPONSE_HEADERS`` on the response to a
token-bearing URL. That one says ``strict-origin``, not ``no-referrer``: under ``no-referrer``
a browser sends ``Origin: null`` on a form POST, and the cookie check refuses that.
"""

import logging
import re
from typing import Final
from urllib.parse import unquote_plus

from sandfort.proxy.tokens import TOKEN_PARAM, split_query_token

REDACTED: Final = "REDACTED"
# uvicorn logs HTTP requests on uvicorn.access and websocket handshakes on uvicorn.error.
REDACTED_LOGGERS: Final = ("uvicorn.access", "uvicorn.error")
# The single use pty connect token of GET /terminal and of the API's pty websocket
# (terminal.REQUIRED_PARAMS). The filter redacts it in log lines only, never in a request.
CONNECT_TOKEN_PARAM: Final = "token"
_SECRET_PARAMS: Final = frozenset({TOKEN_PARAM, CONNECT_TOKEN_PARAM})
NO_REFERRER: Final = (b"referrer-policy", b"no-referrer")
STRICT_ORIGIN: Final = (b"referrer-policy", b"strict-origin")
NO_STORE: Final = (b"cache-control", b"no-store")
PROXY_RESPONSE_HEADERS: Final = (NO_REFERRER, NO_STORE)
TOKEN_RESPONSE_HEADERS: Final = (STRICT_ORIGIN, NO_STORE)
_REPLACED_ON_TOKEN: Final = frozenset({NO_REFERRER[0], NO_STORE[0]})
_QUERY: Final = re.compile(r"\?([^\s\"]*)")
# The auth path accepts the name literally or percent escaped (either hex case), so each
# character of TOKEN_PARAM matches both forms. IGNORECASE also removes an uppercase name,
# which strips more than auth accepts and is safe. The value stops at & # whitespace , " and '.
_HEADER_TOKEN_NAME: Final = "".join(
    "(?:" + re.escape(char) + "|%" + f"{ord(char):02x}" + ")" for char in TOKEN_PARAM
)
_HEADER_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"(?P<sep>[?&])" + _HEADER_TOKEN_NAME + r"=[^&#\s,\"']*", re.IGNORECASE
)

type Headers = list[tuple[bytes, bytes]]


def redact_query_token(query: str) -> str:
    """``query`` with each secret parameter's value replaced by ``REDACTED``, the rest as is."""
    parts: list[str] = []
    for part in query.split("&"):
        name = part.partition("=")[0]
        parts.append(f"{name}={REDACTED}" if unquote_plus(name) in _SECRET_PARAMS else part)
    return "&".join(parts)


def redact_path(value: str) -> str:
    """A log argument with everything after its first ``?`` passed through the redaction."""
    head, mark, query = value.partition("?")
    return f"{head}{mark}{redact_query_token(query)}" if mark else value


def _redact_arg(arg: object) -> object:
    return redact_path(arg) if isinstance(arg, str) else arg


def _redact_match(found: re.Match[str]) -> str:
    return "?" + redact_query_token(found[1])


def strip_referer_token(referer: str) -> str:
    """A ``Referer`` value without ``TOKEN_PARAM``. A ``?`` left with nothing is dropped."""
    head, mark, rest = referer.partition("?")
    if not mark:
        return referer
    query, hash_mark, fragment = rest.partition("#")
    token, kept = split_query_token(query.encode("latin-1"))
    if token is None:
        return referer  # no token: the value goes on byte exact
    tail = "?" + kept.decode("latin-1") if kept else ""
    return f"{head}{tail}{hash_mark}{fragment}"


def _drop_one(value: str) -> str | None:
    """``value`` without its first token parameter, or ``None`` when it has none.

    A ``?`` that would be left in front of another parameter stays, and one left with nothing
    after it goes, so the URL stays well formed.
    """
    found = _HEADER_TOKEN.search(value)
    if found is None:
        return None
    head, rest = value[: found.start()], value[found.end() :]
    if found["sep"] == "?" and rest.startswith("&"):
        return f"{head}?{rest[1:]}"
    return head + rest


def strip_header_token(value: str) -> str:
    """The header value without any ``TOKEN_PARAM`` parameter, byte exact when it has none.

    Removes every parameter named ``TOKEN_PARAM``, literal or percent encoded, after any ``?``
    or ``&`` in the value, including one after a ``#``. Every pass shortens the value, so the
    loop ends, and a header value is a few KiB at most.
    """
    if "=" not in value:
        return value
    while (stripped := _drop_one(value)) is not None:
        value = stripped
    return value


def with_token_response_headers(headers: Headers) -> Headers:
    """``headers`` with ``Referrer-Policy`` and ``Cache-Control`` set to the token pair."""
    kept = [(key, value) for key, value in headers if key.lower() not in _REPLACED_ON_TOKEN]
    return [*kept, *TOKEN_RESPONSE_HEADERS]


class TokenRedactingFilter(logging.Filter):
    """Redacts secret query values in a record and keeps the shape of its args.

    uvicorn's ``AccessFormatter`` unpacks exactly five args, so each ``str`` arg is redacted
    in place and ``msg`` stays the format string. Only a record without args gets its ``msg``
    rewritten. A dict arg is left alone. The filter never drops a record and never formats one.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and args:
            record.args = tuple(_redact_arg(arg) for arg in args)
        elif not args and isinstance(record.msg, str):
            record.msg = _QUERY.sub(_redact_match, record.msg)
        return True


def install_log_redaction() -> None:
    """Add one ``TokenRedactingFilter`` to each of ``REDACTED_LOGGERS``, at most once."""
    for name in REDACTED_LOGGERS:
        target = logging.getLogger(name)
        if not any(isinstance(found, TokenRedactingFilter) for found in target.filters):
            target.addFilter(TokenRedactingFilter())
