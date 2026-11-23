"""``GET /console``: a minimal read-only web console, one self-contained html page.

The page itself needs no authentication because it carries no data. The operator types an api
key into a field; the key lives only in page memory (a script variable) and is sent as a bearer
header to the existing json api. The security posture mirrors the web terminal page: a
nonce-based content security policy, ``no-store`` and no referrer. Every value reaches the dom
through ``textContent``, never through html concatenation.
"""

import secrets

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["console"])

CONSOLE_PATH = "/console"
NONCE_BYTES = 16
_NONCE_TOKEN = "__NONCE__"

# The committed openapi/sandfort.v1.json is regenerated owner-side; a page is not an API
# operation, so this route stays out of the export.
_IN_SCHEMA = False

_STYLE = """
body{margin:0;padding:16px;background:#0d1117;color:#c9d1d9;
font:14px/1.4 ui-monospace,Menlo,Consolas,monospace}
h1{font-size:16px;margin:0 0 12px}
h2{font-size:14px;margin:20px 0 6px;color:#8b949e}
input{background:#161b22;color:#c9d1d9;border:1px solid #30363d;padding:4px 8px;width:320px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:4px 10px;cursor:pointer}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:3px 10px 3px 0;border-bottom:1px solid #21262d}
th{color:#8b949e;font-weight:normal}
#status{color:#8b949e;margin-left:10px}
.error{color:#f85149}
"""

_BODY = """
<h1>Sandfort console (read-only)</h1>
<form id="keyform">
<input id="key" type="password" autocomplete="off" placeholder="api key (kept in memory only)">
<button type="submit">Connect</button><span id="status"></span>
</form>
<h2>Sandboxes</h2><table id="sandboxes"></table>
<h2>Nodes</h2><table id="nodes"></table>
<h2>Audit (latest 20)</h2><table id="audit"></table>
"""

_SCRIPT_STATE = """
"use strict";
const REFRESH_MS = 5000;
const AUDIT_TAIL = 20;
const AUDIT_PAGE_LIMIT = 100;
const AUDIT_MAX_PAGES = 30;
let apiKey = "";
let timer = null;
const statusEl = document.getElementById("status");
"""

_SCRIPT_FETCH = """
async function getJson(path) {
  const res = await fetch(path, {
    headers: {"Authorization": "Bearer " + apiKey},
    cache: "no-store",
    credentials: "omit",
  });
  if (!res.ok) { throw new Error(path + " -> HTTP " + res.status); }
  return res.json();
}
async function auditTail() {
  let events = [];
  let cursor = null;
  for (let page = 0; page < AUDIT_MAX_PAGES; page++) {
    let path = "/v1/audit-events?limit=" + AUDIT_PAGE_LIMIT;
    if (cursor) { path += "&cursor=" + encodeURIComponent(cursor); }
    const body = await getJson(path);
    events = events.concat(body.data || []).slice(-AUDIT_TAIL);
    cursor = body.meta && body.meta.next_cursor;
    if (!cursor) { break; }
  }
  return events.reverse();
}
"""

_SCRIPT_RENDER = """
function render(id, headers, rows) {
  const table = document.getElementById(id);
  table.replaceChildren();
  const head = table.insertRow();
  for (const text of headers) {
    const cell = document.createElement("th");
    cell.textContent = text;
    head.appendChild(cell);
  }
  for (const row of rows) {
    const tr = table.insertRow();
    for (const value of row) {
      tr.insertCell().textContent = value === null || value === undefined ? "-" : String(value);
    }
  }
}
function setStatus(text, isError) {
  statusEl.textContent = text;
  statusEl.className = isError ? "error" : "";
}
"""

_SCRIPT_LOOP = """
async function refresh() {
  if (!apiKey) { return; }
  try {
    const [boxes, nodes, audit] = await Promise.all(
      [getJson("/v1/sandboxes"), getJson("/v1/nodes"), auditTail()]);
    render("sandboxes", ["id", "name", "state", "node id"],
      (boxes.data || []).map((s) => [s.id, s.name, s.state, s.node_id]));
    render("nodes", ["id", "state", "running", "stale"],
      (nodes.data || []).map((n) => [n.id, n.state, n.running_sandboxes, n.stale]));
    render("audit", ["action", "resource id", "time"],
      audit.map((e) => [e.action, e.target_id, e.occurred_at]));
    setStatus("updated " + new Date().toLocaleTimeString(), false);
  } catch (err) {
    setStatus(String(err.message || err), true);
  }
}
function schedule() {
  if (timer !== null) { clearInterval(timer); timer = null; }
  if (apiKey && !document.hidden) { timer = setInterval(refresh, REFRESH_MS); }
}
document.getElementById("keyform").addEventListener("submit", (event) => {
  event.preventDefault();
  const field = document.getElementById("key");
  apiKey = field.value.trim();
  field.value = "";
  schedule();
  refresh();
});
document.addEventListener("visibilitychange", () => {
  schedule();
  if (!document.hidden) { refresh(); }
});
"""

_SCRIPT = _SCRIPT_STATE + _SCRIPT_FETCH + _SCRIPT_RENDER + _SCRIPT_LOOP

_PAGE = (
    '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
    "<title>Sandfort console</title>\n"
    f'<style nonce="{_NONCE_TOKEN}">{_STYLE}</style>\n'
    f"</head><body>{_BODY}\n"
    f'<script nonce="{_NONCE_TOKEN}">{_SCRIPT}</script>\n'
    "</body></html>\n"
)


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
    return HTMLResponse(_PAGE.replace(_NONCE_TOKEN, nonce), headers=_page_headers(nonce))
