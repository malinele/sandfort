"""The audit view of the console page: pure rules, dom code, style and body text.

The page asks for the newest 20 audit events in one request and marks the protection moments.
The rules in ``AUDIT_RULES_JS`` have no dom and no fetch, so tests can run them in node. The
dom code in ``AUDIT_VIEW_JS`` only renders through ``textContent`` and takes css classes from a
fixed whitelist, never from event data. The chain check runs only when the button is clicked,
because the call walks the whole chain of the org.
"""

import json

AUDIT_TAIL: int = 20
PROTECTION_STATUSES: tuple[int, ...] = (401, 403, 429)
PROTECTION_CODES: tuple[str, ...] = (
    "FORBIDDEN",
    "UNAUTHORIZED",
    "QUOTA_EXCEEDED",
    "RATE_LIMITED",
    "EGRESS_DENIED",
)
PROTECTION_REFUSAL_ACTION: str = "sandbox.create_refused"
PROTECTION_REFUSAL_REASON: str = "key_cap"

_RULES_CONSTANTS = (
    "const AUDIT_TAIL = "
    + json.dumps(AUDIT_TAIL)
    + ";\nconst PROTECTION_STATUS = "
    + json.dumps(list(PROTECTION_STATUSES))
    + ";\nconst PROTECTION_CODE = "
    + json.dumps(list(PROTECTION_CODES))
    + ";\nconst PROTECTION_REFUSAL_ACTION = "
    + json.dumps(PROTECTION_REFUSAL_ACTION)
    + ";\nconst PROTECTION_REFUSAL_REASON = "
    + json.dumps(PROTECTION_REFUSAL_REASON)
    + ";\n"
)

_RULES_TABLES = """
const ACTION_LABELS = {
  "request.denied": "Request refused",
  "request.failed": "Request failed",
};
const OUTCOME_CLASS = {
  "success": "outcome-success",
  "denied": "outcome-denied",
  "error": "outcome-error",
};
"""

_RULES_FUNCTIONS = """
function isProtection(event) {
  if (!event || typeof event !== "object") { return false; }
  const details = event.details;
  if (!details || typeof details !== "object") { return false; }
  if (PROTECTION_STATUS.includes(details.status)) { return true; }
  if (PROTECTION_CODE.includes(details.error_code)) { return true; }
  return event.action === PROTECTION_REFUSAL_ACTION
    && details.reason === PROTECTION_REFUSAL_REASON;
}
function hasOwn(table, key) {
  return Object.prototype.hasOwnProperty.call(table, key);
}
function actionLabel(action) {
  if (!action) { return "-"; }
  if (hasOwn(ACTION_LABELS, action)) { return ACTION_LABELS[action]; }
  return String(action).replace(/[._]/g, " ");
}
function outcomeClass(outcome) {
  if (typeof outcome === "string" && hasOwn(OUTCOME_CLASS, outcome)) {
    return OUTCOME_CLASS[outcome];
  }
  return "outcome-unknown";
}
function targetText(event) {
  const parts = [event.target_type, event.target_id].filter((part) => part);
  return parts.length ? parts.join(" ") : null;
}
function summaryRows(result) {
  const findings = result.findings || [];
  const rows = [
    ["ok", result.ok ? "yes" : "no"],
    ["checked", result.checked],
    ["newest row id", result.last_id],
    ["newest row hash", result.last_hash],
    ["findings", findings.length],
    ["findings truncated", result.findings_truncated ? "yes" : "no"],
  ];
  if (result.acknowledged_findings > 0) {
    rows.push(["acknowledged findings", result.acknowledged_findings]);
  }
  return rows;
}
"""

AUDIT_RULES_JS = _RULES_CONSTANTS + _RULES_TABLES + _RULES_FUNCTIONS

AUDIT_VIEW_JS = """
const verifyButton = document.getElementById("verify-button");
const verifyStatusEl = document.getElementById("verify-status");
function renderAudit(events) {
  const rows = events.map((e) => [
    isProtection(e) ? "protection" : null, e.outcome, actionLabel(e.action), e.action,
    targetText(e), e.occurred_at]);
  const classes = events.map(
    (e) => outcomeClass(e.outcome) + (isProtection(e) ? " protection" : ""));
  render("audit", ["guard", "outcome", "label", "action", "target", "time"], rows, classes);
}
async function auditTail() {
  const body = await getJson("/v1/audit-events?limit=" + AUDIT_TAIL + "&order=desc");
  return body.data || [];
}
function setVerifyStatus(text, isError) {
  verifyStatusEl.textContent = text;
  verifyStatusEl.className = isError ? "error" : "";
}
function clearVerify() {
  document.getElementById("verify-summary").replaceChildren();
  document.getElementById("verify-findings").replaceChildren();
  setVerifyStatus("", false);
}
async function verifyChain() {
  if (!apiKey) {
    setVerifyStatus("connect with an api key first", true);
    return;
  }
  const keyAtStart = apiKey;
  clearVerify();
  verifyButton.disabled = true;
  setVerifyStatus("verifying", false);
  try {
    const body = await getJson("/v1/audit-events/verify");
    if (apiKey !== keyAtStart) { return; }
    const result = body.data || {};
    render("verify-summary", ["field", "value"], summaryRows(result));
    render("verify-findings", ["kind", "event id", "detail"],
      (result.findings || []).map((f) => [f.kind, f.event_id, f.detail]));
    setVerifyStatus(result.ok ? "chain ok" : "chain not ok", !result.ok);
  } catch (err) {
    if (apiKey !== keyAtStart) { return; }
    setVerifyStatus(String(err.message || err), true);
  } finally {
    verifyButton.disabled = false;
  }
}
verifyButton.addEventListener("click", verifyChain);
"""

AUDIT_STYLE = """
.outcome-denied td{color:#d29922}
.outcome-error td{color:#f85149}
tr.protection td{border-bottom-color:#d29922}
#audit-note,#verify-status{color:#8b949e}
#verify-status{margin-left:10px}
#verify-status.error{color:#f85149}
"""

AUDIT_BODY = (
    '<h2>Audit (newest 20)</h2><table id="audit"></table>\n'
    '<p id="audit-note">'
    "A successful list, verify or export of audit events writes no audit row. "
    "A request refused after its key was resolved, including a revoked or expired key, "
    "usually leaves a request.denied row, and a create refused by the key sandbox cap, "
    "or a create or start refused for host capacity, leaves a sandbox.create_refused or "
    "sandbox.start_refused row instead, and a repeat of a revoked key refusal, or of a "
    "capacity or key cap refusal, by the same key within 60 seconds leaves no further row. "
    "A missing, malformed or unknown key, a key with a wrong secret, a rate limited request "
    "and a request rejected before the key is resolved, such as a body that is not valid "
    "JSON, leave no row. "
    "The hash shown after Verify chain is the hash of the newest chain row, "
    "not of each listed row. "
    "Rows marked protection are refusals with status 401, 403 or 429, or with error code "
    "FORBIDDEN, UNAUTHORIZED, QUOTA_EXCEEDED, RATE_LIMITED or EGRESS_DENIED, and creates "
    "refused by the key sandbox cap. A refusal because the host is full is not marked. "
    "No row with the code RATE_LIMITED or EGRESS_DENIED occurs today."
    "</p>\n"
    '<button id="verify-button" type="button">Verify chain</button>'
    '<span id="verify-status"></span>\n'
    '<table id="verify-summary"></table>\n'
    '<table id="verify-findings"></table>\n'
)
