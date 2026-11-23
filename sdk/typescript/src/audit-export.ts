/**
 * The audit export as lines: `GET /v1/audit-events/export` answers newline-delimited JSON
 * (one chained row per line, then a trailer line). The body is decoded as it arrives and
 * split on `\n`; nothing is parsed here, so the caller sees the server's lines unchanged.
 * Memory is bounded: a line may hold at most `MAX_EXPORT_LINE_CHARS` characters, and each
 * chunk is scanned for newlines once, so the cost is linear in the body however it is split.
 */

import { InvalidResponseError, withRequestId } from "./errors.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { streamReadFailure } from "./stream-failure.js";
import type { Query, Transport } from "./transport.js";

export const AUDIT_EXPORT_PATH = "/v1/audit-events/export";
/** 1 MiB of text: the cap on one export line (a row is far smaller). */
export const MAX_EXPORT_LINE_CHARS = 1024 * 1024;
const NDJSON_TYPE = "application/x-ndjson";
const BODY_MISSING = "the audit export reply has no body";
const EXPORT_STREAM = "the audit export";
const NEWLINE = "\n";

/**
 * Per-call options of the export. `timeoutMs`, `deadlineMs` and `retries` carry their usual
 * `CallOptions` meaning: an explicit `timeoutMs` bounds the whole stream, body included.
 */
export type ExportRequest = CallOptions;

/**
 * Splits text into lines across chunks. `pending` holds the unfinished line as pieces, so a
 * newline is only searched for in the new chunk and a long line is joined once, when it ends.
 */
class LineSplitter {
  #pieces: string[] = [];
  #chars = 0;

  /** The complete lines (each with its `\n`) that `text` finishes. */
  push(text: string, requestId: string | null): string[] {
    const lines: string[] = [];
    let start = 0;
    for (let end = text.indexOf(NEWLINE); end !== -1; end = text.indexOf(NEWLINE, start)) {
      lines.push(this.#take(text.slice(start, end + 1), requestId));
      start = end + 1;
    }
    this.#keep(text.slice(start), requestId);
    return lines;
  }

  /** The last line when the body ended without a `\n`; `""` when there is none. */
  rest(): string {
    const line = this.#pieces.join("");
    this.#pieces = [];
    this.#chars = 0;
    return line;
  }

  #take(piece: string, requestId: string | null): string {
    this.#keep(piece, requestId);
    return this.rest();
  }

  #keep(piece: string, requestId: string | null): void {
    if (piece === "") return;
    this.#chars += piece.length;
    if (this.#chars > MAX_EXPORT_LINE_CHARS) {
      const message = `an audit export line is longer than ${MAX_EXPORT_LINE_CHARS} characters`;
      throw new InvalidResponseError(withRequestId(message, requestId));
    }
    this.#pieces.push(piece);
  }
}

/** A decoder that refuses invalid UTF-8; its `TypeError` becomes `InvalidResponseError`. */
function decodeText(
  decoder: TextDecoder,
  bytes: Uint8Array | undefined,
  requestId: string | null,
): string {
  try {
    return bytes === undefined ? decoder.decode() : decoder.decode(bytes, { stream: true });
  } catch (cause) {
    const message = withRequestId("the audit export is not valid UTF-8", requestId);
    throw new InvalidResponseError(message, { cause });
  }
}

/** Open the export and yield its lines; the request is sent on the first read. */
export async function* exportLines(
  transport: Transport,
  query: Query,
  request: ExportRequest,
): AsyncGenerator<string, void, undefined> {
  const response = await transport.openStream(
    "GET",
    AUDIT_EXPORT_PATH,
    { query, ...callArgs(request) },
    NDJSON_TYPE,
  );
  const requestId = response.headers.get("x-request-id");
  if (response.body === null) {
    throw new InvalidResponseError(withRequestId(BODY_MISSING, requestId));
  }
  const reader = response.body.getReader();
  const close = (): void => void reader.cancel().catch(() => undefined);
  request.signal?.addEventListener("abort", close, { once: true });
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const splitter = new LineSplitter();
  try {
    for (;;) {
      const chunk = await reader.read().catch((cause: unknown) => {
        throw streamReadFailure(EXPORT_STREAM, cause, request.signal, requestId, response);
      });
      if (chunk.done) break;
      yield* splitter.push(decodeText(decoder, chunk.value, requestId), requestId);
    }
    if (request.signal?.aborted === true) {
      throw streamReadFailure(EXPORT_STREAM, undefined, request.signal, requestId, response);
    }
    const tail = splitter.push(decodeText(decoder, undefined, requestId), requestId);
    yield* tail;
    const last = splitter.rest();
    if (last !== "") yield last;
  } finally {
    request.signal?.removeEventListener("abort", close);
    close();
  }
}
