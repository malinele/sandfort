"""The preview token handoff on ``HANDOFF_PATH`` (B27): the token rides in a URL fragment.

The mint response's ``browser_url`` is ``https://<preview host>/__sandfort/preview#`` plus
``sandfort_preview_token=<token>``. A browser never sends a fragment, so no request line, header
or redirect ``Location`` carries the token. ``GET`` answers a fixed page whose one script reads
the fragment, drops it with ``history.replaceState``, posts the token as a form body and then
opens ``/``. ``POST`` needs an ``Origin`` equal to ``Host`` and consistent fetch metadata,
checks the token as any preview request does and answers 204 with the token cookie (none for
a public sandbox). The proxy answers both itself, after host routing and the sandbox state
check, so nothing on this path, its body included, ever reaches the sandbox app.
"""

import base64
import hashlib
from collections.abc import Awaitable, Callable, Sequence
from typing import Final

from starlette.types import Receive, Scope, Send

from sandfort.proxy.answers import _header, _headers, _Rejected
from sandfort.proxy.hygiene import PROXY_RESPONSE_HEADERS
from sandfort.proxy.tokens import (
    HANDOFF_PATH,
    PreviewGrant,
    PreviewTokenInvalid,
    fetch_metadata_consistent,
    split_query_token,
    token_cookie,
)

type Authorize = Callable[[str | None], Awaitable[PreviewGrant | None]]
type Headers = Sequence[tuple[bytes, bytes]]

MAX_FORM_BYTES: Final = 1024  # the one form field is under 200 bytes
ALLOW: Final = (b"allow", b"GET, POST")
CROSS_SITE_MESSAGE: Final = "cross-site preview request refused"
METHOD_MESSAGE: Final = "the preview handoff answers GET and POST only"
TOO_LARGE_MESSAGE: Final = "the preview handoff form is too large"
# The page's one script. Its exact text is hashed into the policy, so any edit changes the hash.
SCRIPT: Final = """(async () => {
  const token = new URLSearchParams(location.hash.slice(1)).get("sandfort_preview_token");
  history.replaceState(null, "", location.pathname);
  let opened = false;
  if (token) {
    try {
      const response = await fetch("/__sandfort/preview", {
        method: "POST",
        body: new URLSearchParams({ sandfort_preview_token: token }),
        credentials: "same-origin",
        redirect: "error",
      });
      opened = response.ok;
    } catch {
      opened = false;
    }
  }
  if (opened) {
    location.replace("/");
  } else {
    document.getElementById("status").textContent = "This preview link is not valid.";
  }
})();"""
SCRIPT_HASH: Final = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
POLICY: Final = (
    f"default-src 'none'; script-src 'sha256-{SCRIPT_HASH}'; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
PAGE: Final = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Opening preview</title>
</head>
<body>
<p id="status">Opening the preview.</p>
<noscript><p>JavaScript is needed to open this preview.</p></noscript>
<script>{SCRIPT}</script>
</body>
</html>
""".encode()
PAGE_HEADERS: Final = (
    (b"content-type", b"text/html; charset=utf-8"),
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"same-origin"),  # not no-referrer: the POST must carry its Origin
    (b"x-content-type-options", b"nosniff"),
    (b"content-security-policy", POLICY.encode()),
)


def is_handoff(scope: Scope) -> bool:
    """Whether the request names ``HANDOFF_PATH``, compared on the percent-decoded path."""
    return scope.get("path") == HANDOFF_PATH


async def serve(scope: Scope, receive: Receive, send: Send, authorize: Authorize) -> None:
    """Answer the handoff path. A refusal is raised as ``_Rejected`` before anything is sent.

    ``authorize`` is the proxy's token check for the routed sandbox and port: it raises the 401
    ``_Rejected`` for a bad token and returns ``None`` for a public sandbox.
    """
    method = scope.get("method") if scope["type"] == "http" else None
    if method == "GET":
        await _answer(send, 200, PAGE_HEADERS, PAGE)
        return
    if method != "POST":
        raise _Rejected(405, "METHOD_NOT_ALLOWED", METHOD_MESSAGE, (ALLOW,))
    if _header(scope, b"origin") is None or not fetch_metadata_consistent(_headers(scope)):
        raise _Rejected(401, PreviewTokenInvalid.code, CROSS_SITE_MESSAGE)
    token, _ = split_query_token(await _form_body(receive))
    grant = await authorize(token)
    cookie = None if grant is None or token is None else token_cookie(token)
    granted = () if cookie is None else ((b"set-cookie", cookie.encode("latin-1")),)
    await _answer(send, 204, (*PROXY_RESPONSE_HEADERS, *granted), b"")


async def _form_body(receive: Receive) -> bytes:
    """The whole request body, refused with 413 above ``MAX_FORM_BYTES``."""
    body = b""
    more_body = True
    while more_body:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        body += message.get("body", b"")
        if len(body) > MAX_FORM_BYTES:
            raise _Rejected(413, "PAYLOAD_TOO_LARGE", TOO_LARGE_MESSAGE)
        more_body = bool(message.get("more_body", False))
    return body


async def _answer(send: Send, status: int, headers: Headers, body: bytes) -> None:
    sized = [*headers, (b"content-length", b"%d" % len(body))] if body else [*headers]
    await send({"type": "http.response.start", "status": status, "headers": sized})
    await send({"type": "http.response.body", "body": body})
