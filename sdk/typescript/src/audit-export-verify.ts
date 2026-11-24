/**
 * Auditor-side check of an audit export file against its signed `audit_head` trailer, mirroring
 * `sandfort_sdk.audit_export`.
 *
 * `verifyHead` proves only that the server signed the head. It says nothing about the rows above
 * it: an export with its newest rows cut, old rows under a fresh trailer, or a row whose `hash`
 * or `prev_hash` was edited all pass it. `verifyExport` adds the checks a client can make on the
 * file itself: the last event row is the row the head names, with the head's hash, and every
 * row's `prev_hash` is the previous row's `hash`. A head that carries `row_count`, `first_row_id`
 * and `export_sha256` also binds the export's content (row count, first row id and a SHA-256
 * over every event line), which the checks recompute from the file.
 *
 * Row hashes are keyed (HMAC with the server's chain key), so a client cannot recompute them. An
 * edit of a row's content that keeps its `hash` and `prev_hash` passes the checks against a
 * legacy head; only the server-side check (`client.audit.verifyChain()`, `audit-verify` of the
 * admin CLI) proves the keyed hashes.
 */

import type { LineSource } from "./audit-continuation.js";
import {
  headBinding,
  headIsFiltered,
  trustedKeyText,
  verifyHead,
  type HeadReason,
  type HeadRecord,
  type HeadVerification,
} from "./audit-head.js";
import { scanExport, type ExportScan } from "./audit-scan.js";

/** Why an export did not verify, besides the head reasons. */
export type ExportReason =
  | HeadReason
  | "count_mismatch"
  | "content_mismatch"
  | "first_row_mismatch"
  | "malformed_row"
  | "misplaced_trailer"
  | "org_mismatch"
  | "truncated"
  | "head_mismatch"
  | "chain_break"
  | "unchained_rows"
  | "not_a_continuation"
  | "no_trailer";

/**
 * The outcome of `verifyExport`: the head verification plus the file checks. `ok` and `reason`
 * cover both. `reason` is a head reason when the head fails; otherwise, checked in this order
 * (the three content reasons only when the head binds the content, right after the signature):
 * `"count_mismatch"` (the number of event lines differs), `"content_mismatch"` (the number is
 * right but the SHA-256 over the exact bytes of every event line differs: a line was edited or
 * reordered), `"first_row_mismatch"` (the first event line's id differs), `"malformed_row"` (a
 * line that is not a JSON object, has no text `id`, `occurred_at`, `org_id` or `action`, lacks
 * the `hash` or `prev_hash` key, has a non-text one, or is longer than 1 MiB),
 * `"misplaced_trailer"` (an `audit_head` or `export_summary` line that is not the final
 * non-blank line), `"org_mismatch"` (a row's `org_id` is not the head's), `"truncated"` (the
 * last event row is not the row the head names, the head's row is absent, or there are no event
 * rows), `"head_mismatch"` (the last row is the head's row but its hash differs or is missing),
 * `"chain_break"` (a row's `prev_hash` is not the previous row's `hash`; not checked for a
 * filtered head), `"unchained_rows"` (a row carries no `hash` and `allowUnchained` is false) or,
 * only with `previous`, `"not_a_continuation"` (the earlier export's event lines are not an
 * exact byte prefix of this export's). `"no_trailer"` replaces all of these when the file has
 * valid event rows but its last non-blank line is not a usable `audit_head` (`rowId` and
 * `entryHash` are then empty).
 */
export interface ExportVerification extends Omit<HeadVerification, "reason"> {
  reason: ExportReason | null;
  /** Event rows that carry a `hash`. */
  rows: number;
  /** Id of the first row where the linkage breaks; `null` for `"no_trailer"` and filtered heads. */
  firstBreak: string | null;
  /** Id of the last event row (hashed or not); `null` without rows. */
  lastRowId: string | null;
  /** Event rows that carry no `hash`. */
  unchained: number;
  /**
   * 1-based line number behind `"malformed_row"`, `"misplaced_trailer"`, `"org_mismatch"`,
   * `"unchained_rows"` (the first row without a hash) or `"no_trailer"` (the last non-blank line).
   */
  badLine: number | null;
  /** The head binds the export's content (a head that carries `row_count`, `first_row_id` and `export_sha256`). */
  contentBound: boolean;
  /** The head marks a filtered export: its rows are not a contiguous run, so linkage is not checked. */
  filtered: boolean;
  /** With `previous` and a passing check: the number of event lines of the earlier export. */
  previousRows: number | null;
  /** With `previous` and a passing check: the number of event lines added since. */
  newRows: number | null;
}

export interface VerifyExportOptions {
  /**
   * Accept rows without a `hash` before the first hashed row (they are only counted in
   * `unchained` and skipped by the chain comparison; one after it is still a break).
   */
  allowUnchained?: boolean;
  /** An earlier export of the same org: its event lines must be an exact byte prefix of this one's. */
  previous?: LineSource;
}

function contentReason(scan: ExportScan, head: HeadRecord): ExportReason | null {
  const binding = headBinding(head);
  if (binding === null) return null;
  const [count, first, digest] = binding;
  // The count first: the digest covers every line, so it differs whenever a row is cut or
  // added, and checking it first would hide the more telling reason behind a general one.
  if (scan.lineCount !== count) return "count_mismatch";
  if (scan.linesSha256 !== digest) return "content_mismatch";
  if (scan.firstLineId !== first) return "first_row_mismatch";
  return null;
}

/** The line of the first row whose `org_id` is not the head's; `null` when none. */
function foreignOrgLine(scan: ExportScan, orgId: unknown): number | null {
  for (const [seen, line] of scan.orgs) if (seen !== orgId) return line;
  return null;
}

function fileReason(
  scan: ExportScan,
  head: HeadVerification,
  record: HeadRecord,
  allowUnchained: boolean,
): ExportReason | null {
  if (scan.malformedLine !== null) return "malformed_row";
  if (scan.misplacedLine !== null) return "misplaced_trailer";
  if (foreignOrgLine(scan, record["org_id"]) !== null) return "org_mismatch";
  if (scan.lastRowId !== head.rowId) return "truncated"; // also without any row: the head names one
  if (scan.lastHash !== head.entryHash) return "head_mismatch";
  if (scan.firstBreak !== null && !headIsFiltered(record)) return "chain_break";
  if (scan.unchained > 0 && !allowUnchained) return "unchained_rows";
  if (scan.previousOk === false) return "not_a_continuation";
  return null;
}

function noTrailerResult(scan: ExportScan, publicKey: string | Uint8Array): ExportVerification {
  return {
    ok: false,
    rowId: "",
    entryHash: "",
    publicKey: trustedKeyText(publicKey),
    reason: "no_trailer",
    signedAt: null,
    rows: scan.rows,
    firstBreak: null,
    lastRowId: scan.lastRowId,
    unchained: scan.unchained,
    badLine: scan.trailerLine,
    contentBound: false,
    filtered: false,
    previousRows: null,
    newRows: null,
  };
}

function badLineOf(reason: ExportReason | null, scan: ExportScan, head: HeadRecord): number | null {
  switch (reason) {
    case "malformed_row":
      return scan.malformedLine;
    case "misplaced_trailer":
      return scan.misplacedLine;
    case "unchained_rows":
      return scan.unchainedLine;
    case "org_mismatch":
      return foreignOrgLine(scan, head["org_id"]);
    default:
      return null;
  }
}

/**
 * The head signature of `scan` checked against `publicKey`, then the file checks. A scan without
 * a usable trailer fails with `"no_trailer"` (the key is still validated); throws
 * `ValidationError` for an unusable `publicKey`.
 */
export function exportResult(
  scan: ExportScan,
  publicKey: string | Uint8Array,
  allowUnchained = false,
): ExportVerification {
  const record = scan.head;
  if (record === null) return noTrailerResult(scan, publicKey);
  const head = verifyHead(record, publicKey);
  let reason: ExportReason | null = head.reason;
  if (head.ok) reason = contentReason(scan, record) ?? fileReason(scan, head, record, allowUnchained);
  const filtered = headIsFiltered(record);
  const continued = scan.previousOk !== null && reason === null;
  return {
    ok: reason === null,
    rowId: head.rowId,
    entryHash: head.entryHash,
    publicKey: head.publicKey,
    reason,
    signedAt: head.signedAt,
    rows: scan.rows,
    firstBreak: filtered ? null : scan.firstBreak,
    lastRowId: scan.lastRowId,
    unchained: scan.unchained,
    badLine: badLineOf(reason, scan, record),
    contentBound: headBinding(record) !== null,
    filtered,
    previousRows: continued ? scan.previousLines : null,
    newRows: continued ? scan.lineCount - scan.previousLines : null,
  };
}

/**
 * Check an export against its signed `audit_head` trailer. `lines` is the whole newline-delimited
 * JSON body or its lines (a string, an iterable or an async iterable such as
 * `client.audit.exportLines()`; lines end at `\n` only and a trailing `\r` is part of the bytes).
 * `publicKey` is the trust anchor, as for `verifyHead`. The checks, in order: the head signature;
 * the content binding when the head has one; no malformed line; the head is the last non-blank
 * line; the last event row is the head's row, with its hash; every row's `prev_hash` is the
 * previous row's `hash` (the first hashed row's is not checked, an export may start mid-chain);
 * every row carries a `hash`; and, with `previous`, the earlier export is a byte prefix.
 *
 * A head that binds the content fixes the file's event lines as a whole: any added, removed,
 * reordered or edited line is caught. Against a legacy head only the last row (bound to the
 * signed head) and the neighbour linkage are checked, so rows before the last can be replaced by
 * someone who rewrites `prev_hash` and `hash` consistently, and an older, genuinely signed export
 * still verifies (check `signedAt`). Either way the keyed row hashes cannot be recomputed by a
 * client, so a server that signs a fabricated export verifies: only the server-side
 * verification (`client.audit.verifyChain()`) proves the full chain.
 *
 * Throws `ValidationError` for an unusable file or key: an empty file, a file without any valid
 * event row whose last line is no usable `audit_head` (this includes a last `export_summary`),
 * or a malformed key.
 */
export async function verifyExport(
  lines: LineSource,
  publicKey: string | Uint8Array,
  options: VerifyExportOptions = {},
): Promise<ExportVerification> {
  const scan = await scanExport(lines, options.previous ?? null);
  return exportResult(scan, publicKey, options.allowUnchained ?? false);
}
