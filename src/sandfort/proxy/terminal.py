"""The web terminal page the preview proxy serves at ``GET /terminal`` (WP 5.2).

It is served only when the ``Host`` header is not a preview hostname, so sandbox apps keep
their own ``/terminal`` paths. Three query parameters are required: ``sandbox``, ``pty`` and
``token`` (the single-use connect token ``POST .../toolbox/pty`` returns); a missing or blank
one answers 400 and the values are never echoed in the error. The page loads xterm.js 5.5.0
from pinned jsdelivr paths, each tag with a sha384 ``integrity`` attribute and
``crossorigin="anonymous"`` (the browser refuses a file whose bytes differ), and opens the
API's pty websocket at
``<api base>/v1/sandboxes/{sandbox}/toolbox/pty/{pty}/connect?token=<token>``. The API base is
``Settings.public_api_url`` or, when that is empty, the request's own host on the API port.
Keystrokes go to the socket as text frames; socket bytes are written into the terminal.

LIMITATION: the page never resizes the pty. The terminal renders at xterm's default size and
the pty keeps the size it was created with (resize it through the REST API if needed). The
connect token is spent on the first connect, so reloading the page needs a new token.
"""

import json
import secrets
from string import Template
from urllib.parse import quote

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.types import Receive, Scope, Send

from sandfort.api.envelope import fail
from sandfort.api.safe_json import SafeJSONResponse
from sandfort.config import Settings
from sandfort.errors import ValidationFailed
from sandfort.proxy import routing

TERMINAL_PATH = "/terminal"
REQUIRED_PARAMS = ("sandbox", "pty", "token")
MAX_PARAM_LENGTH = 1024
NONCE_BYTES = 16
XTERM_VERSION = "5.5.0"
XTERM_BASE_URL = f"https://cdn.jsdelivr.net/npm/@xterm/xterm@{XTERM_VERSION}"
XTERM_SCRIPT_URL = f"{XTERM_BASE_URL}/lib/xterm.js"
XTERM_STYLESHEET_URL = f"{XTERM_BASE_URL}/css/xterm.css"
# sha384 of the exact files at the pinned URLs above, recompute both when XTERM_VERSION changes
XTERM_SCRIPT_INTEGRITY = "sha384-M169f14mRZOXm3hD/v2Ti0ThIT/RnAQagXA9nlE15yHAtrW19gdePJh/HaTzUOe/"
XTERM_STYLESHEET_INTEGRITY = (
    "sha384-8Xk9wy/gzEDUKrXtrmCFa2bBuK3BpjpDuL/p0SeKQX19Khl/M+lHOgD/CyYf7efP"
)
PTY_CONNECT_PATH = "/v1/sandboxes/{sandbox}/toolbox/pty/{pty}/connect"
_WS_SCHEMES = {"http": "ws", "https": "wss", "ws": "ws", "wss": "wss"}

_PAGE = Template(
    """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<title>sandfort terminal</title>
<link rel="stylesheet" href="${stylesheet_url}"
  integrity="${stylesheet_integrity}" crossorigin="anonymous">
<style>
html, body { margin: 0; height: 100%; background: #000; }
#terminal { height: 100%; }
</style>
<script nonce="${nonce}" src="${script_url}"
  integrity="${script_integrity}" crossorigin="anonymous"></script>
</head>
<body>
<div id="terminal"></div>
<script nonce="${nonce}">
(function () {
  "use strict";
  var term = new Terminal({ cursorBlink: true });
  term.open(document.getElementById("terminal"));
  var socket = new WebSocket(${websocket_url});
  socket.binaryType = "arraybuffer";
  socket.onmessage = function (event) {
    term.write(typeof event.data === "string" ? event.data : new Uint8Array(event.data));
  };
  socket.onclose = function (event) {
    term.write("\\r\\n[connection closed: " + event.code + "]\\r\\n");
  };
  term.onData(function (data) {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(data);
    }
  });
  term.focus();
})();
</script>
</body>
</html>
"""
)


def is_preview_host(host: str, preview_domain: str) -> bool:
    """True for any hostname under the preview domain or shaped like a preview hostname."""
    hostname = routing.strip_port(host).lower()
    under_domain = hostname.endswith("." + preview_domain.lower())
    return under_domain or routing.parse_preview_host(hostname) is not None


def is_terminal_request(scope: Scope, preview_domain: str) -> bool:
    """``GET /terminal`` on a host that is not a preview hostname."""
    if scope["type"] != "http" or scope.get("method") != "GET":
        return False
    if scope.get("path") != TERMINAL_PATH:
        return False
    host = Request(scope).headers.get("host") or ""
    return not is_preview_host(host, preview_domain)


def websocket_base(settings: Settings, request: Request) -> str:
    """The API's websocket origin (plus any path prefix ``public_api_url`` carries)."""
    base = settings.public_api_url.rstrip("/")
    if base:
        scheme, sep, rest = base.partition("://")
        return f"{_WS_SCHEMES.get(scheme.lower(), 'ws')}://{rest}" if sep else f"ws://{base}"
    hostname = request.url.hostname or settings.host
    host = f"[{hostname}]" if ":" in hostname else hostname
    scheme = "wss" if request.url.scheme in ("https", "wss") else "ws"
    return f"{scheme}://{host}:{settings.port}"


def pty_websocket_url(base: str, sandbox: str, pty: str, token: str) -> str:
    """The pty connect websocket url; every component is percent-encoded."""
    path = PTY_CONNECT_PATH.format(sandbox=quote(sandbox, safe=""), pty=quote(pty, safe=""))
    return f"{base}{path}?token={quote(token, safe='')}"


def _script_string(value: str) -> str:
    """``value`` as a JavaScript string literal that cannot end the surrounding script."""
    literal = json.dumps(value)  # ASCII only: U+2028 and U+2029 come out escaped
    return literal.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _page_headers(nonce: str) -> dict[str, str]:
    policy = "; ".join(
        (
            "default-src 'none'",
            f"script-src 'nonce-{nonce}'",
            "style-src https://cdn.jsdelivr.net 'unsafe-inline'",  # xterm adds style elements
            "connect-src ws: wss:",
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


def terminal_response(settings: Settings, request: Request) -> Response:
    """The terminal page, or a 400 envelope when a query parameter is missing or too long."""
    values = {name: request.query_params.get(name, "") for name in REQUIRED_PARAMS}
    if any(not value.strip() or len(value) > MAX_PARAM_LENGTH for value in values.values()):
        message = f"query parameters {', '.join(REQUIRED_PARAMS)} are required"
        body = fail(ValidationFailed.code, message).model_dump(mode="json")
        return SafeJSONResponse(body, status_code=ValidationFailed.status)
    url = pty_websocket_url(
        websocket_base(settings, request), values["sandbox"], values["pty"], values["token"]
    )
    nonce = secrets.token_urlsafe(NONCE_BYTES)
    page = _PAGE.substitute(
        stylesheet_url=XTERM_STYLESHEET_URL,
        stylesheet_integrity=XTERM_STYLESHEET_INTEGRITY,
        script_url=XTERM_SCRIPT_URL,
        script_integrity=XTERM_SCRIPT_INTEGRITY,
        websocket_url=_script_string(url),
        nonce=nonce,
    )
    return HTMLResponse(page, headers=_page_headers(nonce))


async def serve_terminal(settings: Settings, scope: Scope, receive: Receive, send: Send) -> None:
    """Answer one ``GET /terminal`` request (see ``is_terminal_request``)."""
    response = terminal_response(settings, Request(scope, receive))
    await response(scope, receive, send)
