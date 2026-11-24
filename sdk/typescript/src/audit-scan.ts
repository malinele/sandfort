/**
 * Reading an audit export: the trailer, the row linkage, the content digest and a continuation,
 * mirroring `sandfort_sdk.audit_scan`. `scanExport` reads an export once, line by line and
 * without keeping the rows. It records what `exportResult` needs: the trailer, the linkage of
 * the event rows, the SHA-256 over the exact text of every event line, and (with `previous`)
 * whether an earlier export is a byte prefix of this one.
 */

import { createHash, type Hash } from "node:crypto";
import { MAX_EXPORT_LINE_CHARS } from "./audit-export.js";
import {
  HEAD_TYPE,
  PrefixCheck,
  SUMMARY_TYPE,
  TRAILER_TYPES,
  linesOf,
  withoutSuffix,
  type LineSource,
} from "./audit-continuation.js";
import { parseHead, type HeadRecord } from "./audit-head.js";
import { ValidationError } from "./errors.js";

export const EMPTY_EXPORT = "the export is empty: no audit_head trailer line";
const ROW_TEXT_FIELDS = ["occurred_at", "org_id", "action"] as const;
const ROW_CHAIN_FIELDS = ["hash", "prev_hash"] as const;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/** What `scanExport` read from an export: the trailer and the row linkage. */
export interface ExportScan {
  head: HeadRecord | null;
  rows: number;
  unchained: number;
  lastRowId: string | null;
  lastHash: string | null;
  firstBreak: string | null;
  malformedLine: number | null;
  misplacedLine: number | null;
  unchainedLine: number | null;
  trailerLine: number | null;
  trailerError: string | null;
  lineCount: number;
  linesSha256: string;
  firstLineId: string | null;
  /** The first two distinct `org_id`s of the rows, each with the line it first appeared on. */
  orgs: readonly (readonly [string, number])[];
  /** `null` without `previous`. */
  previousOk: boolean | null;
  previousLines: number;
}

/** A line that cannot be an event row (or, as the last line, a trailer). */
class MalformedRow extends Error {}

type Row = Record<string, unknown>;

function parseRow(line: string, number: number): Row {
  if (line.length > MAX_EXPORT_LINE_CHARS) {
    throw new MalformedRow(`line ${number} is longer than ${MAX_EXPORT_LINE_CHARS} characters`);
  }
  if (LONE_SURROGATE.test(line)) throw new MalformedRow(`line ${number} is not valid UTF-8`);
  let record: unknown;
  try {
    record = JSON.parse(line);
  } catch (error) {
    const why = error instanceof RangeError ? "is nested too deeply" : "is not JSON";
    throw new MalformedRow(`line ${number} ${why}`);
  }
  if (typeof record !== "object" || record === null || Array.isArray(record)) {
    throw new MalformedRow(`line ${number} is not a JSON object`);
  }
  return record as Row;
}

/** `record[name]` as text; `null` when absent, null or empty. */
function hashField(record: Row, name: string, number: number): string | null {
  const value = record[name];
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") throw new MalformedRow(`line ${number}: '${name}' is not text`);
  return value;
}

function nonEmptyText(record: Row, name: string, number: number): string {
  const value = record[name];
  if (typeof value !== "string" || value === "") {
    throw new MalformedRow(`line ${number}: event row lacks a non-empty text '${name}'`);
  }
  return value;
}

/** Walks the event rows in file order and keeps only what the checks need. */
class Linkage {
  rows = 0;
  unchained = 0;
  lastRowId: string | null = null;
  lastHash: string | null = null;
  firstBreak: string | null = null;
  firstUnchained: number | null = null;
  readonly orgs: [string, number][] = [];

  #breakAt(rowId: string): void {
    this.firstBreak ??= rowId;
  }

  add(record: Row, number: number): void {
    const rowId = nonEmptyText(record, "id", number);
    for (const name of ROW_TEXT_FIELDS) nonEmptyText(record, name, number);
    for (const name of ROW_CHAIN_FIELDS) {
      if (!Object.hasOwn(record, name)) {
        throw new MalformedRow(`line ${number}: event row lacks the '${name}' key`);
      }
    }
    const entryHash = hashField(record, "hash", number);
    const prevHash = hashField(record, "prev_hash", number);
    const orgId = record["org_id"] as string;
    if (this.orgs.length < 2 && this.orgs.every(([seen]) => seen !== orgId)) {
      this.orgs.push([orgId, number]);
    }
    const started = this.rows > 0;
    if (entryHash === null) {
      this.unchained += 1;
      this.firstUnchained ??= number;
      if (started) this.#breakAt(rowId);
    } else {
      if (started && prevHash !== this.lastHash) this.#breakAt(rowId);
      this.rows += 1;
    }
    // Every row, hashed or not, is the candidate last row the head is compared with.
    this.lastRowId = rowId;
    this.lastHash = entryHash;
  }
}

/** Takes the lines of an export one at a time; the last non-blank line is held back. */
class Scanner {
  readonly #linkage = new Linkage();
  readonly #sha: Hash = createHash("sha256");
  readonly #prefix: PrefixCheck | null;
  #pending: [string, number] | null = null;
  #number = 0;
  #malformed: number | null = null;
  #misplaced: number | null = null;
  #lines = 0;
  #firstId: string | null = null;

  constructor(previous: LineSource | null) {
    this.#prefix = previous === null ? null : new PrefixCheck(previous);
  }

  /** Take one raw line; the body keeps a trailing `\r` (it is part of the bytes). */
  async feed(raw: string): Promise<void> {
    this.#number += 1;
    const body = withoutSuffix(raw, "\n");
    if (withoutSuffix(body, "\r").trim() === "") return;
    if (this.#pending !== null) await this.#settle(...this.#pending);
    this.#pending = [body, this.#number];
  }

  /** Count an event line, extend the digest with its exact bytes and compare it. */
  async #take(body: string, record: Row | null): Promise<void> {
    const line = `${body}\n`;
    const id = record?.["id"];
    if (this.#lines === 0 && typeof id === "string") this.#firstId = id;
    this.#lines += 1;
    this.#sha.update(Buffer.from(line, "utf8"));
    await this.#prefix?.feed(line);
  }

  /** A line followed by another one: it must be an event row. */
  async #settle(body: string, number: number): Promise<void> {
    let record: Row | null = null;
    try {
      record = parseRow(withoutSuffix(body, "\r"), number);
    } catch (error) {
      if (!(error instanceof MalformedRow)) throw error;
      this.#malformed ??= number;
    }
    if (record !== null && TRAILER_TYPES.includes(record["type"] as string)) {
      this.#misplaced ??= number;
      return;
    }
    await this.#take(body, record);
    if (record === null) return;
    try {
      this.#linkage.add(record, number);
    } catch (error) {
      if (!(error instanceof MalformedRow)) throw error;
      this.#malformed ??= number;
    }
  }

  /** Close the earlier export's source, whatever way the scan ended. */
  async close(): Promise<void> {
    await this.#prefix?.close();
  }

  async result(): Promise<ExportScan> {
    if (this.#pending === null) throw new ValidationError(EMPTY_EXPORT);
    const [body, number] = this.#pending;
    const line = withoutSuffix(body, "\r");
    try {
      return await this.#scan(parseHead(parseRow(line, number)));
    } catch (error) {
      if (!(error instanceof MalformedRow || error instanceof ValidationError)) throw error;
      return this.#withoutTrailer(line, number, error.message);
    }
  }

  async #scan(
    head: HeadRecord | null,
    trailerLine: number | null = null,
    trailerError: string | null = null,
  ): Promise<ExportScan> {
    const linkage = this.#linkage;
    const previous = this.#prefix === null ? null : await this.#prefix.finish();
    return {
      head,
      rows: linkage.rows,
      unchained: linkage.unchained,
      lastRowId: linkage.lastRowId,
      lastHash: linkage.lastHash,
      firstBreak: linkage.firstBreak,
      malformedLine: this.#malformed,
      misplacedLine: this.#misplaced,
      unchainedLine: linkage.firstUnchained,
      trailerLine,
      trailerError,
      lineCount: this.#lines,
      linesSha256: this.#sha.copy().digest("hex"),
      firstLineId: this.#firstId,
      orgs: linkage.orgs,
      previousOk: previous === null ? null : previous.isPrefix,
      previousLines: previous === null ? 0 : previous.matched,
    };
  }

  /** The last line is no usable `audit_head`: it may itself be a (last) event row. */
  async #withoutTrailer(line: string, number: number, error: string): Promise<ExportScan> {
    try {
      const record = parseRow(line, number);
      // An unsigned export (a last `export_summary`) is the wrong kind of file.
      if (record["type"] === SUMMARY_TYPE) throw new ValidationError(error);
      if (record["type"] !== HEAD_TYPE) this.#linkage.add(record, number);
    } catch (caught) {
      if (!(caught instanceof MalformedRow)) throw caught;
    }
    if (this.#linkage.rows + this.#linkage.unchained === 0) throw new ValidationError(error);
    return this.#scan(null, number, error);
  }
}

/**
 * Read an export (the whole body, or its lines) without keeping the rows. Lines end at `\n` only
 * (one trailing `\r` is dropped); blank lines are skipped. The last non-blank line is the trailer
 * and must be an `audit_head`. Throws `ValidationError` for an empty export, or for a last line
 * that is no usable `audit_head` (an unsigned `export_summary`, junk, a line over 1 MiB, not
 * UTF-8 or nested too deeply) when the file has no valid event row either. With at least one
 * valid event row an unusable last line does not throw: `head` is `null` and the check fails with
 * `"no_trailer"` (a last `export_summary`, the trailer of an unsigned export, always throws). A
 * bad row does not throw: it is recorded in `malformedLine` or `misplacedLine`.
 */
export async function scanExport(
  lines: LineSource,
  previous: LineSource | null = null,
): Promise<ExportScan> {
  const scanner = new Scanner(previous);
  try {
    for await (const raw of linesOf(lines)) await scanner.feed(raw);
    return await scanner.result();
  } finally {
    await scanner.close();
  }
}
