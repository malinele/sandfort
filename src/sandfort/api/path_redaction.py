"""Redaction of Sandfort secrets that a client pasted into a URL path.

The audit chain is append-only, so a secret stored in a row can never be removed. A refused
request records its path (``details.path``); a caller who put an API key, a session token, a
webhook secret or an opaque preview/connect token into the path (``GET /v1/sandboxes/sbx_<key>``)
must not leave that text in the chain. ``redact_path`` replaces the secret with ``<redacted>``
and keeps the route shape: the segments, the slashes and any text around the secret.

What is recognised: API keys and SCIM tokens (``sf_<env>_...``), session tokens (``sfs_...``),
webhook secrets (``whsec_`` plus base64, which may itself contain ``/``) and any other opaque
run of 40 or more URL-safe characters that is not plain hex (preview and connect tokens are 43
characters of ``token_urlsafe``; Sandfort ids are at most 30 characters).
"""

import re
from typing import Final

REDACTED: Final = "<redacted>"

_BOUNDARY = r"(?<![A-Za-z0-9])"
_KEYED = rf"{_BOUNDARY}sf_[a-z0-9]+_[A-Za-z0-9_-]{{8,}}"
_SESSION = rf"{_BOUNDARY}sfs_[A-Za-z0-9_.-]{{8,}}"
_WEBHOOK = rf"{_BOUNDARY}whsec_[A-Za-z0-9+/=_-]{{8,}}"
_OPAQUE = r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])"
_PREFIXED = re.compile("|".join((_WEBHOOK, _KEYED, _SESSION)))
_OPAQUE_RUN = re.compile(_OPAQUE)
_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+")


def _opaque(match: re.Match[str]) -> str:
    text = match.group(0)
    if _HEX_ONLY.fullmatch(text):  # a digest or hex id is not a pasted secret
        return text
    return REDACTED


def redact_path(path: str) -> str:
    """``path`` with every Sandfort secret replaced by ``<redacted>``."""
    return _OPAQUE_RUN.sub(_opaque, _PREFIXED.sub(REDACTED, path))
