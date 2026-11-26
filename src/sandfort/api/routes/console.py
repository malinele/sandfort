"""``GET /console``: a minimal read-only web console, one self-contained html page.

The page itself needs no authentication because it carries no data. The operator types an api
key into a field; the key lives only in page memory (a script variable) and is sent as a bearer
header to the existing json api. The security posture mirrors the web terminal page: a
nonce-based content security policy, ``no-store`` and no referrer. Every value reaches the dom
through ``textContent``, never through html concatenation. The page text lives in
``console_assets.py`` and ``console_audit.py``.
"""

import secrets

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from sandfort.api.console_assets import NONCE_TOKEN, PAGE

router = APIRouter(tags=["console"])

CONSOLE_PATH = "/console"
NONCE_BYTES = 16

# The committed openapi/sandfort.v1.json is regenerated owner-side; a page is not an API
# operation, so this route stays out of the export.
_IN_SCHEMA = False


def _page_headers(nonce: str) -> dict[str, str]:
    policy = "; ".join(
        (
            "default-src 'none'",
            f"script-src 'nonce-{nonce}'",
            f"style-src 'nonce-{nonce}'",
            "connect-src 'self'",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        )
    )
    return {
        "content-security-policy": policy,
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
    }


@router.get(CONSOLE_PATH, include_in_schema=_IN_SCHEMA, response_class=HTMLResponse)
async def console_page() -> HTMLResponse:
    """The console page; a fresh nonce per response, no data and no authentication."""
    nonce = secrets.token_urlsafe(NONCE_BYTES)
    return HTMLResponse(PAGE.replace(NONCE_TOKEN, nonce), headers=_page_headers(nonce))
