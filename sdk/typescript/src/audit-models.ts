/** Value objects of the audit routes, mirroring `AuditEvent` and `AuditVerifyResult` in python. */

import { InvalidResponseError } from "./errors.js";
import {
  asArray,
  asRecord,
  requiredBoolean,
  requiredNumber,
  requiredString,
  requiredTimestamp,
  stringOrNull,
} from "./models.js";

export interface AuditEvent {
  id: string;
  orgId: string;
  actorType: string;
  action: string;
  occurredAt: Date;
  /** `success`, `denied` or `error`; `success` when an older server omits it. */
  outcome: string;
  actorId: string | null;
  targetType: string | null;
  targetId: string | null;
  requestId: string | null;
  ip: string | null;
  userAgent: string | null;
  details: Readonly<Record<string, unknown>>;
}

export interface AuditFinding {
  /** `hash_mismatch`, `link_broken`, `missing_hash`, `head_missing` or `head_invalid`. */
  kind: string;
  eventId: string;
  detail: string;
}

export interface AuditReanchor {
  eventId: string;
  acknowledgedThrough: string;
  occurredAt: Date;
  operator: string | null;
  reasonCode: string | null;
  note: string | null;
  findings: number | null;
}

/**
 * Outcome of walking the org's audit hash chain on the server. `firstId`, `lastId` and
 * `lastHash` are `null` when the org has no audit rows; `anchorId` is set only for a walk from
 * `fromId`. `findings` lists only unacknowledged findings; `acknowledgedFindings` counts those
 * a re-anchor covers.
 */
export interface AuditVerifyResult {
  ok: boolean;
  checked: number;
  firstId: string | null;
  lastId: string | null;
  lastHash: string | null;
  findings: readonly AuditFinding[];
  findingsTruncated: boolean;
  anchorId: string | null;
  acknowledgedFindings: number;
  reanchoredBy: string | null;
  reanchor: AuditReanchor | null;
}

export function auditEventFromPayload(data: unknown): AuditEvent {
  const what = "audit event";
  const raw = asRecord(data, what);
  const details = raw["details"];
  if (details !== undefined && details !== null) asRecord(details, "audit event details");
  const outcome = raw["outcome"];
  return {
    id: requiredString(raw, "id", what),
    orgId: requiredString(raw, "org_id", what),
    actorType: requiredString(raw, "actor_type", what),
    action: requiredString(raw, "action", what),
    occurredAt: requiredTimestamp(raw["occurred_at"], what),
    outcome: typeof outcome === "string" ? outcome : "success",
    actorId: stringOrNull(raw["actor_id"]),
    targetType: stringOrNull(raw["target_type"]),
    targetId: stringOrNull(raw["target_id"]),
    requestId: stringOrNull(raw["request_id"]),
    ip: stringOrNull(raw["ip"]),
    userAgent: stringOrNull(raw["user_agent"]),
    details: (details ?? {}) as Record<string, unknown>,
  };
}

function findingFromPayload(data: unknown): AuditFinding {
  const raw = asRecord(data, "audit finding");
  return {
    kind: requiredString(raw, "kind", "audit finding"),
    eventId: requiredString(raw, "event_id", "audit finding"),
    detail: requiredString(raw, "detail", "audit finding"),
  };
}

function reanchorFromPayload(data: unknown): AuditReanchor {
  const what = "audit reanchor";
  const raw = asRecord(data, what);
  const findings = raw["findings"];
  return {
    eventId: requiredString(raw, "event_id", what),
    acknowledgedThrough: requiredString(raw, "acknowledged_through", what),
    occurredAt: requiredTimestamp(raw["occurred_at"], what),
    operator: stringOrNull(raw["operator"]),
    reasonCode: stringOrNull(raw["reason_code"]),
    note: stringOrNull(raw["note"]),
    findings: typeof findings === "number" ? findings : null,
  };
}

function requiredKey(raw: Record<string, unknown>, key: string): void {
  if (!(key in raw)) {
    throw new InvalidResponseError(`audit verify result payload is missing '${key}'`);
  }
}

export function verifyResultFromPayload(data: unknown): AuditVerifyResult {
  const what = "audit verify result";
  const raw = asRecord(data, what);
  for (const key of ["first_id", "last_id", "last_hash"]) requiredKey(raw, key);
  const reanchor = raw["reanchor"];
  const acknowledged = raw["acknowledged_findings"];
  return {
    ok: requiredBoolean(raw, "ok", what),
    checked: requiredNumber(raw, "checked", what),
    firstId: stringOrNull(raw["first_id"]),
    lastId: stringOrNull(raw["last_id"]),
    lastHash: stringOrNull(raw["last_hash"]),
    findings: asArray(raw["findings"], "audit findings").map(findingFromPayload),
    findingsTruncated: requiredBoolean(raw, "findings_truncated", what),
    anchorId: stringOrNull(raw["anchor_id"]),
    acknowledgedFindings: typeof acknowledged === "number" ? acknowledged : 0,
    reanchoredBy: stringOrNull(raw["reanchored_by"]),
    reanchor: reanchor === undefined || reanchor === null ? null : reanchorFromPayload(reanchor),
  };
}
