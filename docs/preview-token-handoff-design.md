# Preview token handoff: design and decisions

Status: implemented in round 103 (2026-11-28), backlog item B27 (preview token in the first
URL). Sections 1 to 9 are the proposal as written before the code: section 1 describes the proxy
before round 103, and sections 3 to 9 compare three ways to keep the preview token out of every
URL that a log or a browser history can keep. Section 10 records what the code decided.

## 1. What exists today

- `POST /v1/sandboxes/{id}/preview-tokens` mints a token bound to the org, the sandbox and one
  port, multi-use until `expires_at` (60 seconds to 7 days, `MAX_TTL_S` in
  `src/sandfort/api/routes/sandbox_preview.py`). `preview_url` there returns
  `<scheme>://<port>-<sandbox-id>.<preview domain>?sandfort_preview_token=<token>`. The store
  is in memory and keeps only a SHA-256 digest (`InMemoryPreviewTokenStore`,
  `src/sandfort/proxy/tokens.py`, built in `src/sandfort/api/wiring.py`). Nothing revokes a token.
- The proxy reads the token from the `TOKEN_PARAM` query parameter or the `__Host-` cookie
  (`PreviewProxy._route`, `src/sandfort/proxy/app.py`). A valid query token is cut from the
  forwarded query and comes back as `Set-Cookie` with `Path=/`, `Secure`, `HttpOnly` and
  `SameSite=Lax` (`token_cookie`). The cookie is always `Secure`, so a browser keeps it only
  over HTTPS.
- Cookie auth needs `fetch_metadata_consistent`: `Origin`, when sent, must equal `Host`, and
  `Sec-Fetch-Site`, when sent, must be `same-origin` or `none`. A request that carries the token
  in its query skips that check, which is what lets a link clicked on another site work.
- `src/sandfort/proxy/hygiene.py` redacts the token in uvicorn log lines, strips it from every
  forwarded request header (`Referer`, an edge's `X-Url` or `X-Pathname`, round 99), and puts
  `Referrer-Policy: strict-origin` and `Cache-Control: no-store` on a response to a
  token-bearing URL. Its docstring records why not `no-referrer`: a form POST would then carry
  `Origin: null` and fail the cookie check.

What still sees the token: the URL as shared (chat, tickets, mail), the browser history, browser
extensions that read URLs, any front proxy that logs the request line (the beta ingresses run
with `enable-access-log=false`), the edge headers built from `$request_uri` before the proxy
strips them, and the `Location` of the edge's 308 from `http://` to `https://`, which keeps the
query (B27 addendum, probed 2026-11-27). A link unfurler or mail scanner that fetches the URL
gets a working cookie of its own.

Consumers of the URL shape:

- Python SDK `PreviewInfo` (`sdk/python/src/sandfort_sdk/models.py`) and TypeScript SDK
  `PreviewToken` (`sdk/typescript/src/sandbox-ops.ts`) pass the server's `url` through and build
  nothing. The TypeScript `token` property is not enumerable, but `url` is, and it holds the
  same token, so `JSON.stringify` and `console.log` of the object still print it.
- CLI `preview_view` (`cli/src/sandfort_cli/cmd_cmd.py`) finds the token by its query parameter
  name to undo its own masking. A token anywhere else in the URL is printed masked, with the
  token on a separate `token:` line.
- `docs/connect-guide.md` section 4 tells users to open `url` in a browser and treat it as a
  credential.

## 2. Requirements

1. No HTTP request line, header or redirect `Location` carries the token of a browser link.
2. The token never reaches the sandbox app (today's guarantee stays).
3. A link opened from another site (chat, mail) still works on the first click.
4. Non-browser clients (curl, scripts, websocket libraries, the SDKs) keep a documented path.
5. No break for existing callers in the first release that ships it.

## 3. Option (a): fragment handoff

Shape: `https://<host>/__sandfort/preview#sandfort_preview_token=<token>`. A browser never sends
the fragment to a server.

1. `GET /__sandfort/preview` on a preview host: the proxy runs host routing and the sandbox
   state check (404 as today), then answers itself with a fixed HTML page. The request carries
   no credential and nothing reaches the sandbox. Headers: `Cache-Control: no-store`,
   `Referrer-Policy: same-origin`, `X-Content-Type-Options: nosniff` and a CSP of
   `default-src 'none'`, a `script-src` hash of the one inline script, `connect-src 'self'`,
   `base-uri 'none'`, `form-action 'none'` and `frame-ancestors 'none'`.
2. The script reads `location.hash`, removes it with `history.replaceState`, and sends
   `POST /__sandfort/preview` with the token in a form body, `credentials: "same-origin"` and
   `redirect: "error"`.
3. The proxy answers the POST itself: `fetch_metadata_consistent` plus a required `Origin` equal
   to `Host`, then `authorize_preview` and the org check as today, then 204 with the existing
   `token_cookie`. A bad token answers the existing 401 envelope. The body is never forwarded.
   A public sandbox answers 204 without a cookie.
4. The script calls `location.replace("/")`. That navigation is same-origin, so the cookie
   passes the fetch-metadata check and the entry with the fragment leaves session history.

What still sees the token: the link as shared, browser extensions, and the global browser
history. `replaceState` and `location.replace` rewrite the session history entry. Whether
Chrome, Firefox and Safari keep the original fragment URL in their history database is not
measured. Request lines, access logs, `X-Url`, `X-Pathname`, `Referer` and the 308 `Location`
never hold it: after a redirect without a fragment the browser appends the original fragment
itself. uvicorn does not log request bodies.

What breaks: the page needs JavaScript (a `noscript` line says so) and HTTPS, because the
`__Host-` cookie is always `Secure`. A plain-HTTP deployment (`public_preview_url` empty, the
default) cannot use it and keeps the query URL. curl gets the HTML page, not the app, so
non-browser clients need the query token or the header in section 6. Browser websockets work
after the handoff (the handshake is same-origin and sends the cookie). Shared links behave as
today: anyone with the link can open it until `expires_at`. Embedding (B31) does not change: the
`Lax` cookie is still not sent in a cross-site frame. The reserved path makes an app route of
the same name unreachable on a preview host.

CSRF and fetch metadata: the POST holds its own credential in the body, so ambient cookies play
no part. A cross-site page that posts a token can only set a cookie for a grant on the same
sandbox and port, which needs a token for that sandbox. The strict check still refuses a
cross-site POST. `Referrer-Policy` must not be `no-referrer` on the handoff page, for the reason
`hygiene.py` records. The cookie check on later requests is unchanged.

Code impact: no store or `PreviewTokenStore` protocol change. New code is the page, one route in
the proxy, a new field in the mint response, the OpenAPI spec, both SDK models, the CLI, docs.

## 4. Option (b): one-time code in the URL

Shape: `https://<host>/?sandfort_preview_code=<code>`. Mint returns a short-lived code (for
example 120 seconds) that maps to the token. The first request that presents it consumes it,
gets the cookie and a 303 to the same URL without the code.

What still sees it: everything that sees today's query (history, shared link, edge headers, the
308 `Location`, any request-line log). The difference is that a used code is worthless. An unused
code is live until its short expiry, so a log reader who is faster than the user still wins.

What breaks: a link works once. Opening it in a second browser, after clearing cookies or for a
second person needs a new mint. Link unfurlers, mail scanners and browser prefetch or prerender
fetch the URL first and consume the code, and the user then gets 401. Moving the exchange to a
POST interstitial avoids that, and then it is option (a) with a code in the query. curl must keep
a cookie jar (`-c`, `-b`) after the first request, and non-browser websocket clients still need a
multi-use credential. Two parallel first requests race and one loses.

CSRF and fetch metadata: the code request is a top-level navigation that may come from another
site, so it needs the same exemption the query token has today.

Code impact: `PreviewTokenStore` gains a consuming method, a change to a protocol in
`src/sandfort/proxy/tokens.py`. The store stays per process, as today. Mint response, spec, SDK
models, CLI and docs change as in (a).

## 5. Option (c): token in a path segment

Shape: `https://<host>/__sandfort/t/<token>/`, answered with the cookie and a 303 to `/`.

What still sees it: more than today. A path is in every access log line and in `$request_uri`
(so in `X-Url` and `X-Pathname`), and log redaction usually targets the query. History and the
shared link keep it, and `Referer` keeps it for same-origin requests unless the proxy strips it.
The 308 `Location` keeps the path.

What breaks: the same curl and websocket limits as (a), plus tools that normalise or truncate
paths. It needs a new path in the proxy, like (a), and gives no gain over the query.

## 6. Non-browser path: a request header

For curl, scripts and websocket libraries: `Sandfort-Preview-Token: <token>` (name open), read by
the proxy next to the query and the cookie and never forwarded. It appears in no URL. It is not
ambient, so it needs no fetch-metadata check. Browsers cannot set it on a websocket, so browser
websockets keep the cookie. It does not use `Authorization`, which the app may need for itself.

## 7. Comparison

| | Request lines, logs | History, shared link | Link reuse | curl, scripts | Store |
|---|---|---|---|---|---|
| Today (query) | yes, uvicorn redacts | yes | until expiry | works | as is |
| (a) fragment | no | yes (history not measured) | until expiry | header or query | as is |
| (b) one-time code | yes, dead after use | yes, dead after use | one open | cookie jar | protocol |
| (c) path segment | yes, harder to redact | yes | until expiry | header or query | as is |

## 8. Migration and compatibility

1. Additive first release: the proxy serves `/__sandfort/preview` and reads the header. The mint
   response adds a field (for example `browser_url`) only when the preview origin is HTTPS.
   `url` keeps its query shape. The Python and TypeScript models add the optional field. The CLI
   prints `browser_url` when present and keeps `--json` complete. The OpenAPI spec is exported
   again.
2. Docs: `docs/connect-guide.md` section 4 says which URL to open and which to use from scripts.
3. A later release, after owner sign-off: a setting that refuses query tokens on a server that
   wants handoff only (default unchanged), or `url` takes the fragment shape. Either one breaks
   scripts that open `url` with curl, so it ships with notice and a changelog entry.

## 9. Recommendation

Option (a) for browsers plus the header of section 6 for everything else, shipped additively as
in section 8. It meets requirements 1 to 5 except for what no server can control: the link as
shared, extensions and possibly the global history. It changes no store protocol and keeps
multi-use semantics, so no current caller breaks. Reject (c): it exposes more than today. Do not
build (b) now: single-open links break unfurlers, scanners and a second device, and the token
still has no revocation. Reconsider (b) only as an opt-in on top of the (a) POST, if the owner
wants single-open links.

## 10. Decisions as made in code

Round 103 built option (a) and the header of section 6, additively as in section 8 step 1.

1. Header. The name is `Sandfort-Preview-Token` (`TOKEN_HEADER` in
   `src/sandfort/proxy/tokens.py`, held in lower case because HTTP compares header names without
   case). The proxy reads it and never forwards it to the app (`CREDENTIAL_HEADERS` in
   `src/sandfort/proxy/hygiene.py`).
2. Precedence. The proxy takes the token from the header, then the query, then the cookie, and
   checks only the first one present (`PreviewProxy._route` in `src/sandfort/proxy/app.py`). A
   bad header token answers 401 even when a valid cookie is sent too. A header or query token
   skips the fetch-metadata check, and the cookie does not. A header token is never set as a
   cookie. Only a query token that earned the grant is.
3. Path. The reserved path is `/__sandfort/preview` (`HANDOFF_PATH`), compared on the
   percent-decoded path and answered by the proxy (`src/sandfort/proxy/handoff.py`). `GET` gives
   the page. `POST` with an `Origin` equal to `Host` exchanges the form token for the cookie.
   Any other method answers 405, and a form body above 1024 bytes answers 413. Nothing on this
   path reaches the app.
4. Mint response. `browser_url` is a new field next to an unchanged `url`, present only when
   `SANDFORT_PUBLIC_PREVIEW_URL` is an https origin and left out of the JSON otherwise
   (`browser_url` in `src/sandfort/api/routes/sandbox_preview.py`). A plain-HTTP server keeps the
   query URL as its only URL.
5. Query tokens are not refused. No setting turns them off, so `url` keeps working. Whether a
   later release refuses them is still to decide.
6. Landing. The page always opens `/` after the exchange, and the fragment carries no path.
7. CLI. `sandfort preview` prints `url`, so scripts and curl can use its output.
   `sandfort preview --browser` prints `browser_url` when the reply has one whose fragment
   carries the token, and the same output as without the flag otherwise.
   `sandfort --json preview` has `browser_url` whenever the server sent it
   (`cli/src/sandfort_cli/preview_browser.py`).
8. Shared caches. Every proxied answer of a private sandbox, whatever carried the token, gets a
   `Cache-Control` that starts with `private` and keeps the app's other directives except
   `public`, `s-maxage` and `proxy-revalidate`, a `Vary` that names `Cookie` and
   `Sandfort-Preview-Token` (a `Vary: *` stays as sent), and no `CDN-Cache-Control` or
   `Surrogate-Control` (`src/sandfort/proxy/caching.py`). The viewer's browser may still cache
   it. An answer to a URL that names the token parameter keeps `Cache-Control: no-store`, the
   handoff page and its exchange answer with `no-store`, and the answers of a public sandbox pass
   as the app sent them.

Still open: whether the global history of Chrome, Firefox and Safari keeps the fragment URL (not
measured), single-open links (option b, not built), the web terminal's single-use connect token
in `?token=` (unchanged) and whether the TypeScript SDK makes `url` non-enumerable (it is still
enumerable).
