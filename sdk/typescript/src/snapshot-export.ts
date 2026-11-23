/**
 * The snapshot export as bytes: `GET /v1/snapshots/{id}/export` streams the snapshot's image
 * as a `docker save` tar (`application/x-tar`). The body is handed on exactly as the reader
 * delivers it: nothing is decoded, parsed or copied here, so the caller sees the server's
 * bytes unchanged. The server answers 409 (`InvalidState`) unless the snapshot is `ready`.
 */

import { InvalidResponseError, ValidationError, withRequestId } from "./errors.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { streamReadFailure } from "./stream-failure.js";
import type { Transport } from "./transport.js";

/**
 * 1 h: the floor of the per-request timeout of the whole export stream, body included. The
 * SDK has one timeout per streamed call (there is no first-byte-only wait), so the floor must
 * cover both the server building the tar and the download itself; the follow streams use the
 * same shape. An explicit `timeoutMs` replaces the floor; `deadlineMs` does not raise it and
 * may cut the stream earlier.
 */
export const SNAPSHOT_EXPORT_MIN_TIMEOUT_MS = 3_600_000;
const TAR_TYPE = "application/x-tar";
const BODY_MISSING = "the snapshot export reply has no body";
const EXPORT_STREAM = "the snapshot export";

/**
 * Per-call options of the export. `timeoutMs`, `deadlineMs` and `retries` carry their usual
 * `CallOptions` meaning: an explicit `timeoutMs` replaces the 1 h floor and bounds the whole
 * stream, body included; `deadlineMs` does not raise the floor, it can only end the call
 * sooner.
 */
export type SnapshotExportRequest = CallOptions;

function exportPath(snapshotId: string): string {
  if (snapshotId.trim() === "") throw new ValidationError("'snapshotId' must not be empty");
  return `/v1/snapshots/${encodeURIComponent(snapshotId)}/export`;
}

/**
 * Open the export and yield the tar's chunks as they arrive; the request is sent on the
 * first read. Reading to the end, stopping early and aborting all cancel the body reader.
 */
export async function* exportTar(
  transport: Transport,
  snapshotId: string,
  request: SnapshotExportRequest,
): AsyncGenerator<Uint8Array, void, undefined> {
  const path = exportPath(snapshotId);
  const response = await transport.openStream(
    "GET",
    path,
    {
      ...callArgs(request),
      // The tar may take a while to build and download; an explicit timeoutMs replaces this floor.
      minTimeoutMs: request.timeoutMs === undefined ? SNAPSHOT_EXPORT_MIN_TIMEOUT_MS : undefined,
    },
    TAR_TYPE,
  );
  const requestId = response.headers.get("x-request-id");
  if (response.body === null) {
    throw new InvalidResponseError(withRequestId(BODY_MISSING, requestId));
  }
  const reader = response.body.getReader();
  const close = (): void => void reader.cancel().catch(() => undefined);
  request.signal?.addEventListener("abort", close, { once: true });
  try {
    for (;;) {
      const chunk = await reader.read().catch((cause: unknown) => {
        throw streamReadFailure(EXPORT_STREAM, cause, request.signal, requestId, response);
      });
      if (chunk.done) break;
      yield chunk.value;
    }
    if (request.signal?.aborted === true) {
      throw streamReadFailure(EXPORT_STREAM, undefined, request.signal, requestId, response);
    }
  } finally {
    request.signal?.removeEventListener("abort", close);
    close();
  }
}

/** The chunks joined into one `Uint8Array`: the total is summed first, so there is one allocation. */
export function concatChunks(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}
