/** The public status document (`GET /v1/status`, no key needed), as `sandfort_sdk` `StatusInfo`. */

import {
  asRecord,
  requiredString,
  requiredTimestamp,
  stringOrNull,
} from "./models.js";

export const STATUS_PATH = "/v1/status";

export interface StatusNotice {
  message: string;
  updatedAt: Date;
}

export interface StatusInfo {
  /** `"ok"` or `"degraded"`. */
  status: string;
  version: string;
  /** Commit the server was built from; `null` when the server does not know it. */
  buildSha: string | null;
  /** Commit stamped into the running image; compare with `buildSha`. */
  imageSha: string | null;
  /** `null` when either sha is unknown. */
  buildMatchesImage: boolean | null;
  startedAt: Date;
  notice: StatusNotice | null;
  /**
   * Ed25519 public key (urlsafe base64) that signs audit export trailers; `null` while the server
   * signs no heads. The trust anchor for `client.audit.verifyHead()` and `verifyExport()`.
   */
  auditPublicKey: string | null;
  /** First 16 hex characters of the SHA-256 of the raw audit public key; `null` like the key. */
  auditKeyFingerprint: string | null;
}

function noticeFromPayload(data: unknown): StatusNotice | null {
  if (data === undefined || data === null) return null;
  const raw = asRecord(data, "status notice");
  return {
    message: requiredString(raw, "message", "status notice"),
    updatedAt: requiredTimestamp(raw["updated_at"], "status notice"),
  };
}

export function statusFromPayload(data: unknown): StatusInfo {
  const raw = asRecord(data, "status");
  const matches = raw["build_matches_image"];
  return {
    status: requiredString(raw, "status", "status"),
    version: requiredString(raw, "version", "status"),
    buildSha: stringOrNull(raw["build_sha"]),
    imageSha: stringOrNull(raw["image_sha"]),
    buildMatchesImage: typeof matches === "boolean" ? matches : null,
    startedAt: requiredTimestamp(raw["started_at"], "status"),
    notice: noticeFromPayload(raw["notice"]),
    auditPublicKey: stringOrNull(raw["audit_public_key"]),
    auditKeyFingerprint: stringOrNull(raw["audit_key_fingerprint"]),
  };
}
