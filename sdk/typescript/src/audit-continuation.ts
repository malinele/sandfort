/**
 * `previous`: is an earlier audit export an exact byte prefix of this one? An export is
 * append-only while the server's chain grows, so a later full export of the same org starts with
 * the exact event lines of an earlier one. `PrefixCheck` compares them in lockstep while the
 * later export is scanned (constant memory: one line of each at a time). The earlier file is not
 * verified here, only its event lines are used: every non-blank line except its trailer and any
 * other trailer-typed line.
 */

import { MAX_EXPORT_LINE_CHARS } from "./audit-export.js";

export const HEAD_TYPE = "audit_head";
export const SUMMARY_TYPE = "export_summary";
export const TRAILER_TYPES: readonly string[] = [HEAD_TYPE, SUMMARY_TYPE];

/**
 * An export as text: the whole body (split at `\n`), or its lines (each element is one line,
 * with or without its `\n`; `client.audit.exportLines()` yields them).
 */
export type LineSource = string | Iterable<string> | AsyncIterable<string>;

export function withoutSuffix(text: string, suffix: string): string {
  return text.endsWith(suffix) ? text.slice(0, text.length - suffix.length) : text;
}

/** The lines of a source; a whole text is split at `\n` only. */
export async function* linesOf(source: LineSource): AsyncGenerator<string, void, undefined> {
  if (typeof source === "string") yield* source.split("\n");
  else yield* source;
}

/** Whether `body` (one line) is a JSON object typed as an audit head or an export summary. */
export function isTrailerLine(body: string): boolean {
  if (body.length > MAX_EXPORT_LINE_CHARS) return false;
  try {
    const record: unknown = JSON.parse(body);
    if (typeof record !== "object" || record === null || Array.isArray(record)) return false;
    return TRAILER_TYPES.includes((record as Record<string, unknown>)["type"] as string);
  } catch {
    return false;
  }
}

/**
 * The event lines of an export, each with its trailing `\n`. Blank lines are skipped; the last
 * non-blank line is dropped when it is a trailer, and so is any trailer-typed line before it.
 * One trailing `\r` is kept (it is part of the bytes).
 */
export async function* eventLines(source: LineSource): AsyncGenerator<string, void, undefined> {
  let pending: string | null = null;
  for await (const raw of linesOf(source)) {
    const body = withoutSuffix(raw, "\n");
    if (withoutSuffix(body, "\r").trim() === "") continue;
    if (pending !== null && !isTrailerLine(withoutSuffix(pending, "\r"))) yield `${pending}\n`;
    pending = body;
  }
  if (pending !== null && !isTrailerLine(withoutSuffix(pending, "\r"))) yield `${pending}\n`;
}

/** Compares the event lines of the export being scanned with those of an earlier export. */
export class PrefixCheck {
  readonly #previous: AsyncGenerator<string, void, undefined>;
  #matched = 0;
  #broken = false;
  #exhausted = false;

  constructor(previous: LineSource) {
    this.#previous = eventLines(previous);
  }

  /** Take the next event line of the later export (with its trailing newline). */
  async feed(line: string): Promise<void> {
    if (this.#broken || this.#exhausted) return;
    const expected = await this.#previous.next();
    if (expected.done === true) this.#exhausted = true;
    else if (expected.value === line) this.#matched += 1;
    else {
      this.#broken = true;
      await this.close();
    }
  }

  /**
   * Close the earlier export's source (its `finally` blocks run). Safe to call again and after
   * the source ended. An error raised while closing is dropped: this runs on exit paths where it
   * must not mask the error that caused the exit.
   */
  async close(): Promise<void> {
    try {
      await this.#previous.return(undefined);
    } catch {
      // the source failed while closing; nothing useful to report
    }
  }

  /** Whether the earlier export is a prefix, and how many of its lines matched, once the later one ended. */
  async finish(): Promise<{ isPrefix: boolean; matched: number }> {
    if (this.#broken) return { isPrefix: false, matched: this.#matched };
    if (!this.#exhausted && (await this.#previous.next()).done !== true) {
      await this.close();
      return { isPrefix: false, matched: this.#matched }; // the earlier export has more lines
    }
    return { isPrefix: true, matched: this.#matched };
  }
}
