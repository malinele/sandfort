"""Optional bearer-token check for ``GET /metrics`` (empty ``metrics_token`` = open)."""

import hashlib
import hmac

from sandfort.config import Settings
from sandfort.errors import Unauthorized

METRICS_UNAUTHORIZED_MESSAGE = "invalid or missing metrics token"
BEARER_SCHEME = "bearer"


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def require_metrics_token(settings: Settings, authorization: str | None) -> None:
    """Return when ``/metrics`` is open or ``authorization`` carries the configured bearer token.

    Every failure raises the same ``Unauthorized`` message, so a scraper learns nothing about
    which check failed. Both sides are hashed first so the comparison is constant time.
    """
    if not settings.metrics_token:
        return
    scheme, _, token = (authorization or "").partition(" ")
    presented = _digest(token.strip())
    expected = _digest(settings.metrics_token)
    if scheme.lower() != BEARER_SCHEME or not hmac.compare_digest(presented, expected):
        raise Unauthorized(METRICS_UNAUTHORIZED_MESSAGE)
