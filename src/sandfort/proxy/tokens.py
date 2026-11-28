"""Preview tokens: multi-use, time-limited grants bound to an org, sandbox and port.

Unlike connect tokens (single use), a preview token is validated but never consumed:
it stays valid until it expires. ``InMemoryPreviewTokenStore`` is the single-process
implementation and keeps only a SHA-256 digest of each token. The proxy reads a token from
the ``TOKEN_HEADER`` request header, the ``TOKEN_PARAM`` query parameter or the
``COOKIE_NAME`` cookie, in that order of precedence, and from the form body of a ``POST`` to
``HANDOFF_PATH``. The ``split_*`` helpers take it out of what is forwarded to the sandbox.
"""

import hashlib
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol
from urllib.parse import unquote_plus, urlsplit

from sandfort.clock import Clock, SystemClock
from sandfort.errors import Unauthorized
from sandfort.proxy.routing import MAX_PORT, MIN_PORT

DEFAULT_TTL = timedelta(hours=1)
TOKEN_BYTES = 32
TOKEN_PARAM = "sandfort_preview_token"  # query parameter name
TOKEN_HEADER = "sandfort-preview-token"  # request header name, lower case, never forwarded
HANDOFF_PATH = "/__sandfort/preview"  # reserved on preview hosts, answered by the proxy (B27)
# __Host- makes browsers accept the cookie only with Secure, Path=/ and no Domain, so a sibling
# host on the parent domain cannot overwrite it; an unprefixed cookie of that name is ignored.
COOKIE_NAME = f"__Host-{TOKEN_PARAM}"
MAX_TOKEN_LENGTH = 128
_TOKEN_SHAPE = re.compile(rf"[A-Za-z0-9_-]{{1,{MAX_TOKEN_LENGTH}}}")
_SAME_SITE_VALUES = frozenset({"same-origin", "none"})


@dataclass(frozen=True, slots=True)
class PreviewGrant:
    org_id: str
    sandbox_id: str
    port: int
    expires_at: datetime


class PreviewTokenInvalid(Unauthorized):
    """The token is missing, unknown, expired or bound to another sandbox or port."""


class PreviewTokenStore(Protocol):
    async def mint(
        self, org_id: str, sandbox_id: str, port: int, ttl: timedelta = DEFAULT_TTL
    ) -> str:
        """Create an opaque token bound to the grant, valid for ``ttl``."""
        ...

    async def redeem(self, token: str) -> PreviewGrant:
        """Validate without consuming; raise ``PreviewTokenInvalid`` if unknown or expired."""
        ...


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class InMemoryPreviewTokenStore:
    def __init__(self, clock: Clock | None = None) -> None:
        self._clock: Clock = clock or SystemClock()
        self._entries: dict[str, PreviewGrant] = {}

    async def mint(
        self, org_id: str, sandbox_id: str, port: int, ttl: timedelta = DEFAULT_TTL
    ) -> str:
        if not MIN_PORT <= port <= MAX_PORT:
            raise ValueError(f"preview port must be {MIN_PORT}..{MAX_PORT}: {port}")
        if ttl <= timedelta(0):
            raise ValueError("preview token ttl must be positive")
        token = secrets.token_urlsafe(TOKEN_BYTES)
        expires_at = self._clock.now() + ttl
        grant = PreviewGrant(org_id=org_id, sandbox_id=sandbox_id, port=port, expires_at=expires_at)
        self._entries[_digest(token)] = grant
        return token

    async def redeem(self, token: str) -> PreviewGrant:
        key = _digest(token)
        grant = self._entries.get(key)
        if grant is None:
            raise PreviewTokenInvalid("preview token is invalid")
        if self._clock.now() >= grant.expires_at:
            del self._entries[key]
            raise PreviewTokenInvalid("preview token has expired")
        return grant


def split_query_token(query: bytes) -> tuple[str | None, bytes]:
    """``(preview token, raw query string without it)``; other parameters stay byte-exact."""
    token: str | None = None
    kept: list[bytes] = []
    for part in query.split(b"&"):
        name, _, value = part.partition(b"=")
        if unquote_plus(name.decode("latin-1")) == TOKEN_PARAM:
            token = unquote_plus(value.decode("latin-1"))
        elif part:
            kept.append(part)
    return token, b"&".join(kept)


def split_cookie_token(cookie_headers: Iterable[str]) -> tuple[str | None, str | None]:
    """``(preview token cookie, the other cookies as one Cookie header or None)``.

    Only the ``__Host-`` prefixed cookie counts as a token. An unprefixed cookie with the
    plain ``TOKEN_PARAM`` name could have been set by a sibling host: it is ignored and, like
    the real one, never forwarded to the sandbox.
    """
    token: str | None = None
    kept: list[str] = []
    for header in cookie_headers:
        for item in (piece.strip() for piece in header.split(";")):
            name, _, value = item.partition("=")
            if name == COOKIE_NAME:
                token = value
            elif name == TOKEN_PARAM:
                continue
            elif item:
                kept.append(item)
    return token, "; ".join(kept) or None


def token_cookie(token: str, *, secure: bool = True) -> str | None:
    """``Set-Cookie`` value that keeps a query token for later requests.

    The cookie is ``__Host-`` prefixed: ``Path=/``, no ``Domain`` and always ``Secure``, since
    browsers drop the prefix otherwise. ``secure`` is accepted for callers that derive it from
    the ASGI scheme, which is wrong behind a TLS-terminating proxy; it cannot turn Secure off.
    ``None`` unless the token is url-safe base64 of at most ``MAX_TOKEN_LENGTH`` characters,
    so a crafted token can never inject cookie attributes.
    """
    if not _TOKEN_SHAPE.fullmatch(token):
        return None
    del secure
    return f"{COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Lax"


def strip_cookie_domain(set_cookie: bytes) -> bytes:
    """An upstream ``Set-Cookie`` value without its ``Domain`` attribute; the rest is kept."""
    parts = set_cookie.split(b";")
    kept = [p for i, p in enumerate(parts) if i == 0 or _attribute_name(p) != b"domain"]
    return b";".join(kept)


def _attribute_name(part: bytes) -> bytes:
    return part.partition(b"=")[0].strip().lower()


def fetch_metadata_consistent(headers: Iterable[tuple[bytes, bytes]]) -> bool:
    """Whether ``Origin`` and ``Sec-Fetch-Site`` fit a same-origin or direct request.

    ``Origin``, when present, must name exactly the request ``Host``; ``Sec-Fetch-Site``, when
    present, must be ``same-origin`` or ``none``. A request with neither header passes.
    """
    seen = {key.lower(): value.decode("latin-1").strip() for key, value in headers}
    origin, site = seen.get(b"origin"), seen.get(b"sec-fetch-site")
    if site is not None and site.lower() not in _SAME_SITE_VALUES:
        return False
    if origin is None:
        return True
    host = seen.get(b"host", "").lower()
    return bool(host) and urlsplit(origin).netloc.lower() == host


async def authorize_preview(
    store: PreviewTokenStore,
    *,
    sandbox_id: str,
    port: int,
    public: bool,
    token: str | None,
) -> PreviewGrant | None:
    """Decide access to ``port`` of ``sandbox_id``.

    Public sandboxes bypass tokens and return ``None`` (any token is ignored). Private
    sandboxes need a token bound to exactly this sandbox and port; otherwise
    ``PreviewTokenInvalid`` is raised.
    """
    if public:
        return None
    if not token:
        raise PreviewTokenInvalid("preview token is required")
    grant = await store.redeem(token)
    if grant.sandbox_id != sandbox_id or grant.port != port:
        raise PreviewTokenInvalid("preview token is not valid for this sandbox and port")
    return grant
