"""The page text of ``GET /console``: style, body and script, assembled into one template.

``PAGE`` still carries ``NONCE_TOKEN`` in the style and script tags. The route replaces it with
a fresh nonce per response. The audit view lives in ``console_audit``. Every value reaches the
dom through ``textContent``, never through html concatenation.
"""

from sandfort.api.console_audit import (
    AUDIT_BODY,
    AUDIT_RULES_JS,
    AUDIT_STYLE,
    AUDIT_VIEW_JS,
)

NONCE_TOKEN = "__NONCE__"

_STYLE = (
    """
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
#status.error{color:#f85149}
"""
    + AUDIT_STYLE
)

_BODY_HEAD = """
<h1>Sandfort console (read-only)</h1>
<form id="keyform">
<input id="key" type="password" autocomplete="off" placeholder="api key (kept in memory only)">
<button type="submit">Connect</button><span id="status"></span>
</form>
<h2>Sandboxes</h2><table id="sandboxes"></table>
<h2>Nodes</h2><table id="nodes"></table>
"""

_BODY = _BODY_HEAD + AUDIT_BODY

_SCRIPT_STATE = """
"use strict";
const REFRESH_MS = 5000;
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
"""

_SCRIPT_RENDER = """
function render(id, headers, rows, classes) {
  const table = document.getElementById(id);
  table.replaceChildren();
  const head = table.insertRow();
  for (const text of headers) {
    const cell = document.createElement("th");
    cell.textContent = text;
    head.appendChild(cell);
  }
  for (const [index, row] of rows.entries()) {
    const tr = table.insertRow();
    const rowClass = classes ? classes[index] : "";
    if (typeof rowClass === "string" && rowClass) { tr.className = rowClass; }
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
    renderAudit(audit);
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
  clearVerify();
  field.value = "";
  schedule();
  refresh();
});
document.addEventListener("visibilitychange", () => {
  schedule();
  if (!document.hidden) { refresh(); }
});
"""

_SCRIPT = (
    _SCRIPT_STATE + _SCRIPT_FETCH + _SCRIPT_RENDER + AUDIT_RULES_JS + AUDIT_VIEW_JS + _SCRIPT_LOOP
)

PAGE = (
    '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
    "<title>Sandfort console</title>\n"
    f'<style nonce="{NONCE_TOKEN}">{_STYLE}</style>\n'
    f"</head><body>{_BODY}\n"
    f'<script nonce="{NONCE_TOKEN}">{_SCRIPT}</script>\n'
    "</body></html>\n"
)
