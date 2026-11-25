/**
 * Auditor-side check of the signed `audit_head` trailer of an audit export, mirroring
 * `sandfort_sdk.audit_head`.
 *
 * The server signs the head with Ed25519 when it has an audit signing key and publishes the
 * public key as `audit_public_key` on `GET /v1/status`. Checking needs that public key alone.
 * The key is the trust anchor and must come from the caller (pinned, or read from the status
 * route of the server being audited). A head names its own `public_key` too, but a forger can
 * sign with any key and name it there, so the line's key is only compared with the anchor: a
 * difference is reason `"key_mismatch"`. The signed bytes are the head without `signature` and
 * `hmac`, as compact JSON with sorted keys and ASCII only (`audit-canonical.ts`). The `hmac`
 * field needs the server's chain key, so it is not checked here.
 */

import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { canonicalJson, decodeBase64Url, encodeBase64Url } from "./audit-canonical.js";
import { ValidationError } from "./errors.js";

export const HEAD_TYPE = "audit_head";
export const HEAD_ALG = "ed25519";
/** The `public_key` argument that makes the `client.audit` facade read the key from the status route. */
export const STATUS_KEY = "status";
export const KEY_ERROR = "public key must be an Ed25519 key: 32 bytes in urlsafe base64";
export const KEY_REQUIRED =
  "a trusted public key is required: pass one, or 'status' on the audit facade";
const EXPECTED_ORG_EMPTY = "expectedOrgId must be a non-empty text";
export const NO_STATUS_KEY =
  "the server publishes no audit_public_key; pass the public key explicitly";

const KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
const UNSIGNED_FIELDS: ReadonlySet<string> = new Set(["signature", "hmac"]);
const BINDING_FIELDS = ["row_count", "first_row_id", "export_sha256"] as const;
const FILTER_FIELDS = ["filtered", "filters"] as const;
const SHA256_HEX_CHARS = 64;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const EARLIEST_SIGNED_AT_MS = Date.UTC(1970, 0, 2);
/** DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32 key bytes follow. */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SIGNED_AT =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})$/;

/** Why a head did not verify; `null` in `HeadVerification.reason` when it did. */
export type HeadReason =
  | "unsigned"
  | "signature"
  | "key_mismatch"
  | "undated"
  | "future_signed_at"
  | "expected_org_mismatch";

/** The outcome of `verifyHead`. */
export interface HeadVerification {
  ok: boolean;
  /** What the head claims; trust it only when `ok` is true. */
  rowId: string;
  entryHash: string;
  /** The TRUSTED key checked against (canonical urlsafe base64), never the key the line names. */
  publicKey: string;
  /**
   * `null` when `ok`, else: `"unsigned"` (no `signature` or `alg`), `"key_mismatch"` (the line
   * names another key than the trusted one), `"signature"`, `"undated"` (the signature verifies
   * but `signed_at` is absent, has no UTC offset or is before 1970-01-02) or `"future_signed_at"`
   * (more than 5 minutes ahead of this machine's clock) or `"expected_org_mismatch"` (the
   * caller passed `expectedOrgId` and the signed head names another org, or none).
   */
  reason: HeadReason | null;
  /** The head's `signed_at`; always set when `ok`, `null` when the head has no valid one. */
  signedAt: Date | null;
  /**
   * The head's `org_id` when it is a non-empty text, else `null`. Like `rowId` it is what the
   * head claims, whether or not the signature holds: trust it only when `ok` is true. Pass
   * `expectedOrgId` to `verifyHead` to have a head of another org refused.
   */
  orgId: string | null;
}

export interface VerifyHeadOptions {
  /**
   * The org the head must name. A signed head that names another org, or none, gives
   * `ok: false` with reason `"expected_org_mismatch"`. Must be a non-empty text. Not to be
   * confused with `"org_mismatch"` of `verifyExport`, where a row's org differs from the head's.
   */
  expectedOrgId?: string;
}

/** The fields of a parsed `audit_head` line. */
export type HeadRecord = Readonly<Record<string, unknown>>;

/** `[row_count, first_row_id, export_sha256]` of a head that binds the export's content. */
export type HeadBinding = readonly [number, string | null, string];

function hasOwn(record: HeadRecord, name: string): boolean {
  return Object.hasOwn(record, name);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The canonical urlsafe base64 text of a public key (urlsafe or standard base64 text, or the 32
 * raw bytes); throws `ValidationError` when it is not an Ed25519 key.
 */
function keyText(value: string | Uint8Array): string {
  const raw =
    typeof value === "string"
      ? decodeBase64Url(value.replace(/\+/g, "-").replace(/\//g, "_"))
      : value;
  if (raw === null || raw.length !== KEY_BYTES) throw new ValidationError(KEY_ERROR);
  return encodeBase64Url(raw);
}

/** The canonical text of the caller's trust anchor; `ValidationError` when missing or malformed. */
export function trustedKeyText(publicKey: string | Uint8Array | null | undefined): string {
  if (publicKey === null || publicKey === undefined) throw new ValidationError(KEY_REQUIRED);
  return keyText(publicKey);
}

/** The signed bytes: the head without `signature` and `hmac`, in the server's canonical form. */
export function canonicalPayload(record: HeadRecord): Uint8Array {
  // fromEntries defines own properties, so a `__proto__` member is signed like any other
  // (plain assignment would hit the prototype setter and drop it from the signed bytes).
  const body = Object.fromEntries(
    Object.entries(record).filter(([name]) => !UNSIGNED_FIELDS.has(name)),
  );
  return new Uint8Array(Buffer.from(canonicalJson(body), "utf8"));
}

function checkFilters(record: HeadRecord): void {
  if (!FILTER_FIELDS.some((name) => hasOwn(record, name))) return;
  const filters = record["filters"];
  if (
    record["filtered"] === true &&
    BINDING_FIELDS.every((name) => hasOwn(record, name)) &&
    isPlainObject(filters) &&
    Object.values(filters).every((value) => typeof value === "string")
  ) {
    return;
  }
  throw new ValidationError(
    "audit_head has an incomplete or malformed filtered marker (filtered, filters)",
  );
}

/** The three content fields come together and have their shapes, or none is present. */
function checkBinding(record: HeadRecord): void {
  checkFilters(record);
  if (!BINDING_FIELDS.some((name) => hasOwn(record, name))) return;
  const count = record["row_count"];
  const first = record["first_row_id"];
  const digest = record["export_sha256"];
  if (
    BINDING_FIELDS.every((name) => hasOwn(record, name)) &&
    typeof count === "number" &&
    Number.isInteger(count) &&
    count >= 0 &&
    (first === null || (typeof first === "string" && first !== "")) &&
    typeof digest === "string" &&
    digest.length === SHA256_HEX_CHARS
  ) {
    return;
  }
  throw new ValidationError(
    `audit_head has an incomplete or malformed content binding (${BINDING_FIELDS.join(", ")})`,
  );
}

function parseJsonObject(line: string): Record<string, unknown> {
  let record: unknown;
  try {
    record = JSON.parse(line);
  } catch (error) {
    if (error instanceof RangeError) throw new ValidationError("head line is nested too deeply");
    throw new ValidationError("head line is not JSON");
  }
  if (!isPlainObject(record)) throw new ValidationError("head line is not a JSON object");
  return record;
}

/** The fields of an `audit_head` line; `ValidationError` when it is not a usable head. */
export function parseHead(headLine: string | HeadRecord): HeadRecord {
  let record: Record<string, unknown>;
  if (typeof headLine === "string") record = parseJsonObject(headLine);
  else if (isPlainObject(headLine)) record = { ...headLine };
  else throw new ValidationError("head must be a JSON line or an object");
  if (record["type"] !== HEAD_TYPE) throw new ValidationError("line is not an audit_head");
  for (const name of ["row_id", "hash"]) {
    const value = record[name];
    if (typeof value !== "string" || value === "") {
      throw new ValidationError(`audit_head lacks a non-empty '${name}'`);
    }
  }
  checkBinding(record);
  return record;
}

/**
 * `[row_count, first_row_id, export_sha256]` of a parsed head; `null` for a legacy head that
 * carries none of them. Call it on a record that `parseHead` accepted.
 */
export function headBinding(record: HeadRecord): HeadBinding | null {
  if (!BINDING_FIELDS.some((name) => hasOwn(record, name))) return null;
  return [
    record["row_count"] as number,
    record["first_row_id"] as string | null,
    record["export_sha256"] as string,
  ];
}

/** Whether a parsed head marks a filtered export (`filtered: true`). */
export function headIsFiltered(record: HeadRecord): boolean {
  return record["filtered"] === true;
}

function absent(value: unknown): boolean {
  return value === null || value === undefined || value === "";
}

function signatureHolds(key: string, record: HeadRecord, signature: string): boolean {
  try {
    const raw = decodeBase64Url(key);
    const sig = decodeBase64Url(signature);
    if (raw === null || sig === null || sig.length !== SIGNATURE_BYTES) return false;
    const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
    const publicKey: KeyObject = createPublicKey({ key: der, format: "der", type: "spki" });
    return verify(null, canonicalPayload(record), publicKey, sig);
  } catch {
    return false;
  }
}

/** The head's `signed_at` when it is an ISO 8601 text with a UTC offset, else `null`. */
function signedAtOf(record: HeadRecord): Date | null {
  const text = record["signed_at"];
  if (typeof text !== "string") return null;
  const match = SIGNED_AT.exec(text);
  if (match === null) return null;
  const [, year, month, day, hour, minute, second, fraction = "", zone = ""] = match;
  const offset = zone === "Z" || zone.includes(":") ? zone : `${zone.slice(0, 3)}:${zone.slice(3)}`;
  const moment = new Date(
    `${year}-${month}-${day}T${hour}:${minute}:${second}${fraction.slice(0, 4)}${offset}`,
  );
  const [y, mo, d] = [Number(year), Number(month), Number(day)];
  const calendar = new Date(Date.UTC(y, mo - 1, d));
  const real =
    calendar.getUTCFullYear() === y && calendar.getUTCMonth() === mo - 1 && calendar.getUTCDate() === d;
  if (!real || Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) return null;
  const ms = moment.getTime();
  if (Number.isNaN(ms) || ms < EARLIEST_SIGNED_AT_MS) return null;
  return moment;
}

/** `ValidationError` for an empty `expectedOrgId`; `undefined` (no org expected) is fine. */
export function checkExpectedOrg(expectedOrgId: string | undefined): void {
  if (expectedOrgId === "") throw new ValidationError(EXPECTED_ORG_EMPTY);
}

/** The head's `org_id` when it is a non-empty text, else `null`. */
function headOrg(record: HeadRecord): string | null {
  const value = record["org_id"];
  return typeof value === "string" && value !== "" ? value : null;
}

/** Whether the line names a key that is not the trusted one (a malformed one counts). */
function namesOtherKey(record: HeadRecord, trusted: string): boolean {
  const named = record["public_key"];
  if (typeof named !== "string" || named === "") return false;
  try {
    return keyText(named) !== trusted;
  } catch {
    return true;
  }
}

/**
 * Check the Ed25519 signature of a head against `publicKey`, the trust anchor (urlsafe or
 * standard base64 text, or the 32 raw bytes). The key must come from the caller or from the
 * status route of the audited server, never from the line: another key in the line gives
 * `ok: false` with reason `"key_mismatch"`, so a head forged under the forger's own key is
 * refused. Throws `ValidationError` for a malformed line or a missing or malformed key; an
 * unsigned head, a wrong key and a tampered line return `ok: false` with a `reason`.
 *
 * `ok` also needs a valid `signed_at` (RFC 3339 with a UTC offset, as the server writes it): a
 * head that verifies but lacks one is `"undated"`, and one dated more than 5 minutes ahead of
 * the local clock is `"future_signed_at"`. Only the signature is checked here, not the `hmac`.
 *
 * With `options.expectedOrgId` the signed head must name that org: another `org_id`, or none (or
 * a non-text one), gives `ok: false` with reason `"expected_org_mismatch"`, so a genuinely signed
 * head of org B is not taken for org A's. It is checked after the signature (an unsigned or
 * tampered head keeps its own reason) and before `signed_at`. An empty `expectedOrgId` throws
 * `ValidationError`.
 */
export function verifyHead(
  headLine: string | HeadRecord,
  publicKey: string | Uint8Array,
  options: VerifyHeadOptions = {},
): HeadVerification {
  const expectedOrgId = options.expectedOrgId;
  checkExpectedOrg(expectedOrgId);
  const record = parseHead(headLine);
  const trusted = trustedKeyText(publicKey);
  const signedAt = signedAtOf(record);
  const rowId = record["row_id"] as string;
  const entryHash = record["hash"] as string;
  const orgId = headOrg(record);
  const outcome = (ok: boolean, reason: HeadReason | null): HeadVerification => ({
    ok,
    rowId,
    entryHash,
    publicKey: trusted,
    reason,
    signedAt,
    orgId,
  });
  const signature = record["signature"];
  if (absent(signature) || absent(record["alg"])) return outcome(false, "unsigned");
  if (record["alg"] !== HEAD_ALG || typeof signature !== "string") return outcome(false, "signature");
  if (namesOtherKey(record, trusted)) return outcome(false, "key_mismatch");
  if (!signatureHolds(trusted, record, signature)) return outcome(false, "signature");
  if (expectedOrgId !== undefined && orgId !== expectedOrgId) {
    return outcome(false, "expected_org_mismatch");
  }
  if (signedAt === null) return outcome(false, "undated");
  if (signedAt.getTime() > Date.now() + MAX_FUTURE_SKEW_MS) return outcome(false, "future_signed_at");
  return outcome(true, null);
}
