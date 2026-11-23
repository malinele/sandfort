"""One-line hints that follow an error: what the person can do next.

A hint is plain text chosen from the error alone; :func:`sandfort_cli.output.cli_errors` prints
it under the error line (text) or as ``error.hint`` (json). This module imports nothing from
:mod:`sandfort_cli.output`, so ``output`` can use it.
"""

import builtins
import re

import httpx
from sandfort_sdk import ApiError

# The 503 code of a host without room, and the start of its hint line.
CAPACITY_CODE = "CAPACITY"
CAPACITY_HINT = "the host is full"
# A Retry-After above this many seconds is shown as "over 60 min" (a header is server text; a
# huge value must not turn into a promise of a number of days).
MAX_RETRY_SHOWN_S = 3600
RETRY_SHOWN_CAP = "over 60 min"

# Python exception class names that leak into error text (``failed: RemoteProtocolError: ...``)
# and the plain words that replace them. A class that is not listed here but is a builtin or
# httpx exception gets its name split into lower-case words (``OverflowError`` -> ``overflow``).
PLAIN_ERROR_NAMES = {
    "IsADirectoryError": "is a directory",
    "NotADirectoryError": "is not a directory",
    "FileNotFoundError": "file not found",
    "FileExistsError": "file already exists",
    "PermissionError": "permission denied",
    "ConnectionResetError": "connection reset by the other side",
    "ConnectionRefusedError": "connection refused",
    "ConnectionAbortedError": "connection aborted",
    "ConnectionError": "connection failed",
    "BrokenPipeError": "connection closed early",
    "TimeoutError": "timed out",
    "InterruptedError": "interrupted",
    "OSError": "operating system error",
    "IOError": "operating system error",
    "EOFError": "input ended early",
    "UnicodeDecodeError": "not valid text",
    "UnicodeEncodeError": "not valid text",
    "UnicodeError": "not valid text",
    "ValueError": "invalid value",
    "TypeError": "wrong kind of value",
    "KeyError": "missing key",
    "IndexError": "index out of range",
    "AttributeError": "missing attribute",
    "RuntimeError": "internal error",
    "RecursionError": "nested too deeply",
    "MemoryError": "out of memory",
    "RemoteProtocolError": "the server broke the connection",
    "LocalProtocolError": "the request could not be sent",
    "ReadError": "reading from the server failed",
    "WriteError": "sending to the server failed",
    "ConnectError": "could not connect to the server",
    "ConnectTimeout": "timed out connecting to the server",
    "ReadTimeout": "timed out waiting for the server",
    "WriteTimeout": "timed out sending to the server",
    "PoolTimeout": "timed out waiting for a free connection",
    "TimeoutException": "timed out",
    "NetworkError": "network error",
    "TransportError": "network error",
    "ProxyError": "proxy error",
    "TooManyRedirects": "too many redirects",
    "UnsupportedProtocol": "unsupported url scheme",
    "DecodingError": "the reply could not be decoded",
    "SSLError": "TLS error",
    "SSLCertVerificationError": "the server certificate was not accepted",
    "JSONDecodeError": "not valid JSON",
}
# A class name as the text shows it: optionally dotted (``httpx.ReadError``), a name that ends
# like an exception, not part of a longer word.
_ERROR_NAME_RE = re.compile(
    r"(?<![\w.])(?:[a-z_][a-z_0-9]*\.)*([A-Z][A-Za-z0-9]*(?:Error|Exception|Timeout|Redirects))\b"
)
_CAMEL_WORD_RE = re.compile(r"[A-Z][a-z0-9]*")
_ERROR_SUFFIXES = ("Error", "Exception")


def _is_exception_class(name: str) -> bool:
    for namespace in (builtins, httpx):
        found = getattr(namespace, name, None)
        if isinstance(found, type) and issubclass(found, BaseException):
            return True
    return False


def plain_error_name(name: str) -> str | None:
    """The plain words for a Python exception class name, or ``None`` when ``name`` is not a
    builtin or httpx exception class."""
    if name in PLAIN_ERROR_NAMES:
        return PLAIN_ERROR_NAMES[name]
    if not _is_exception_class(name):
        return None
    stem = name.removesuffix(_ERROR_SUFFIXES[0]).removesuffix(_ERROR_SUFFIXES[1])
    return " ".join(word.lower() for word in _CAMEL_WORD_RE.findall(stem)) or "error"


def _plain_match(match: "re.Match[str]") -> str:
    plain = plain_error_name(match.group(1))
    return match.group(0) if plain is None else plain


def plain_error_names(text: str) -> str:
    """``text`` with every Python exception class name written in plain words:
    ``failed: RemoteProtocolError: peer closed`` reads ``failed: the server broke the connection:
    peer closed``. Names that are not builtin or httpx exceptions are left as they are."""
    return _ERROR_NAME_RE.sub(_plain_match, text)


def capacity_hint(exc: ApiError) -> str:
    """The hint of a 503 CAPACITY error: the ``Retry-After`` the server sent
    (``retry_after_header_s``, capped for display) when it sent a usable one, else a generic
    wording. The SDK's retry delay (``retry_after_s``, 1 without a header) is never shown."""
    sent = getattr(exc, "retry_after_header_s", None)
    if not isinstance(sent, int) or isinstance(sent, bool) or sent <= 0:
        return f"{CAPACITY_HINT}; retry later or ask the operator"
    wait = RETRY_SHOWN_CAP if sent > MAX_RETRY_SHOWN_S else f"{sent} s"
    return f"{CAPACITY_HINT}; retry in {wait}"


def hint_for(exc: BaseException) -> str | None:
    """The built-in hint for ``exc``, or ``None``; only a CAPACITY error has one."""
    if isinstance(exc, ApiError) and exc.code == CAPACITY_CODE:
        return capacity_hint(exc)
    return None
