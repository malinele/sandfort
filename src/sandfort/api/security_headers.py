"""Fixed security headers on every API response.

``SecurityHeadersMiddleware`` adds ``X-Content-Type-Options``, ``X-Frame-Options`` and
``Referrer-Policy`` to the response start of every HTTP request, and a restrictive
``Content-Security-Policy`` to JSON and empty-bodied answers. HTML pages the app serves (the
interactive docs, the console) keep whatever policy they set themselves: they get no CSP here
(the docs pages set ``DOCS_CONTENT_SECURITY_POLICY_VALUE``, ReDoc its own variant).
A header a route already set is never overwritten.

It is a pure ASGI middleware that only touches the ``http.response.start`` message and passes
every body chunk through untouched, so streamed responses (the snapshot export, server-sent
events) are never buffered.

An unhandled exception is answered by Starlette's outermost error middleware, outside this one.
The middleware therefore builds that 500 itself (with the shared error builder) when nothing was
sent yet, and re-raises so the server still logs the failure.
"""

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CONTENT_TYPE_OPTIONS_HEADER = "X-Content-Type-Options"
CONTENT_TYPE_OPTIONS_VALUE = "nosniff"
FRAME_OPTIONS_HEADER = "X-Frame-Options"
FRAME_OPTIONS_VALUE = "DENY"
REFERRER_POLICY_HEADER = "Referrer-Policy"
REFERRER_POLICY_VALUE = "no-referrer"
CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy"
CONTENT_SECURITY_POLICY_VALUE = "default-src 'none'; frame-ancestors 'none'"
# The two interactive docs pages (``/docs``, ``/redoc``) set this themselves; the middleware's
# ``setdefault`` keeps it. Scripts come from the app itself (the bootstrap script) and the
# pinned jsdelivr bundles, which the pages load with integrity hashes: no inline script. Both
# UIs inject styles at run time, hence ``'unsafe-inline'`` in ``style-src`` only.
_DOCS_CDN = "https://cdn.jsdelivr.net"
# The ReDoc bundle loads its logo from this host; it is the only remote image source allowed,
# and only on ``/redoc``: nothing on ``/docs`` loads it.
_REDOC_LOGO_HOST = "https://cdn.redoc.ly"
_DOCS_IMG_SRC = "img-src 'self' data:"


def _docs_policy(img_src: str) -> str:
    return "; ".join(
        (
            "default-src 'none'",
            f"script-src 'self' {_DOCS_CDN}",
            f"style-src {_DOCS_CDN} 'unsafe-inline'",
            img_src,
            "connect-src 'self'",
            "worker-src blob:",
            "font-src data:",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        )
    )


# ``/docs``: no remote image source.
DOCS_CONTENT_SECURITY_POLICY_VALUE = _docs_policy(_DOCS_IMG_SRC)
# ``/redoc``: the same policy plus the ReDoc logo host in ``img-src``.
REDOC_CONTENT_SECURITY_POLICY_VALUE = _docs_policy(f"{_DOCS_IMG_SRC} {_REDOC_LOGO_HOST}")

_JSON_TYPE = "application/json"
_JSON_SUFFIX = "+json"
_REQUEST_ID_KEY = "request_id"


def is_json_or_empty(headers: Headers) -> bool:
    """True for a JSON content type, or for an answer with no content type or a zero length."""
    content_type = headers.get("content-type")
    if content_type is None:
        return True
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == _JSON_TYPE or media_type.endswith(_JSON_SUFFIX):
        return True
    return headers.get("content-length") == "0"


def apply_security_headers(headers: MutableHeaders) -> None:
    """Set the fixed headers that the response does not carry yet."""
    csp_applies = is_json_or_empty(headers)
    headers.setdefault(CONTENT_TYPE_OPTIONS_HEADER, CONTENT_TYPE_OPTIONS_VALUE)
    headers.setdefault(FRAME_OPTIONS_HEADER, FRAME_OPTIONS_VALUE)
    headers.setdefault(REFERRER_POLICY_HEADER, REFERRER_POLICY_VALUE)
    if csp_applies:
        headers.setdefault(CONTENT_SECURITY_POLICY_HEADER, CONTENT_SECURITY_POLICY_VALUE)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                apply_security_headers(MutableHeaders(scope=message))
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception as exc:
            if not response_started:
                await _send_internal_error(exc, scope, receive, send_with_headers)
            raise


async def _send_internal_error(exc: Exception, scope: Scope, receive: Receive, send: Send) -> None:
    # Deferred: api.errors imports the header constants from this module.
    from sandfort.api.errors import error_response

    request_id = scope.get("state", {}).get(_REQUEST_ID_KEY)
    await error_response(exc, request_id=request_id)(scope, receive, send)
