/**
 * Declarative image builds, mirroring `Snapshots.build` and `Snapshots.follow_build_logs` of
 * `sandfort_sdk.snapshots`: `POST /v1/images/builds` starts a build from an image spec (or
 * answers the earlier ready snapshot of an identical spec), and
 * `GET /v1/images/builds/{snapshot_id}/logs` streams the build log as server-sent events: one
 * `log` event per line, then a final `state` event that ends the stream.
 */

import { InvalidResponseError, TransportError, ValidationError, withRequestId } from "./errors.js";
import { eventJson, withReplyId } from "./contexts.js";
import { Image } from "./image.js";
import { requiredString } from "./models.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { SseDecoder, type SseFrame } from "./sse.js";
import { streamReadFailure } from "./stream-failure.js";
import type { Transport } from "./transport.js";

export const IMAGE_BUILDS_PATH = "/v1/images/builds";
const SNAPSHOT_STATE_READY = "ready";
/** 1 h: a build may run a long time; an explicit `timeoutMs` replaces this floor. */
const BUILD_LOG_MIN_TIMEOUT_MS = 3_600_000;
const BUILD_LOG_STREAM = "the build log stream";
const BUILD_LOG_ENDED = "build log stream ended before the final state event";
const INDEX = /^\d+$/;

/** Options of `buildSnapshot`: an optional server-side snapshot name. */
export interface BuildSnapshotOptions extends CallOptions {
  /** Snapshot name; the API validates it (1 to 255 characters, `[A-Za-z0-9][A-Za-z0-9_.:/@-]*`). */
  name?: string;
}

/** The raw wire-form spec `buildSnapshot` also accepts in place of an `Image`. */
export type ImageSpecInput = Readonly<Record<string, unknown>>;

/**
 * One event of a build log: a `log` line (`index` is the zero-based line number from the SSE
 * `id`, `null` when the server sent none), or the final `state` event. `succeeded` is true
 * when the final state is `ready`. `digest` and `reason` are `null` when the server sends none.
 */
export type BuildLogEvent =
  | { type: "log"; line: string; index: number | null }
  | {
      type: "state";
      state: string;
      snapshotId: string | null;
      digest: string | null;
      reason: string | null;
      succeeded: boolean;
    };

/** Wire body for `POST /v1/images/builds`; `name` is sent only when given. */
export function imageBuildBody(
  spec: Image | ImageSpecInput,
  name?: string,
): Record<string, unknown> {
  if (typeof spec !== "object" || spec === null || Array.isArray(spec)) {
    throw new ValidationError("'spec' must be an Image or an image spec object");
  }
  const payload = spec instanceof Image ? spec.serialize() : { ...spec };
  return name === undefined ? { spec: payload } : { spec: payload, name };
}

function optionalString(raw: Record<string, unknown>, key: string, what: string): string | null {
  const value = raw[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw new InvalidResponseError(`${what} '${key}' is not a string`);
  return value;
}

function lineIndex(frame: SseFrame): number | null {
  const id = frame.id;
  if (id === undefined || id.trim() === "") return null;
  const index = Number(id);
  if (!INDEX.test(id.trim()) || !Number.isSafeInteger(index)) {
    throw new InvalidResponseError(`build log event id is not an index: ${id}`);
  }
  return index;
}

/** The event a frame carries; `undefined` for event types this SDK ignores. */
function buildEventFromFrame(frame: SseFrame): BuildLogEvent | undefined {
  if (frame.event === "log") {
    const line = eventJson(frame)["line"];
    if (typeof line !== "string") {
      throw new InvalidResponseError("build log event line is not a string");
    }
    return { type: "log", line, index: lineIndex(frame) };
  }
  if (frame.event !== "state") return undefined;
  const what = "build state event";
  const raw = eventJson(frame);
  const state = requiredString(raw, "state", what);
  return {
    type: "state",
    state,
    snapshotId: optionalString(raw, "snapshot_id", what),
    digest: optionalString(raw, "digest", what),
    reason: optionalString(raw, "reason", what),
    succeeded: state === SNAPSHOT_STATE_READY,
  };
}

function buildLogsPath(snapshotId: string): string {
  if (snapshotId.trim() === "") throw new ValidationError("'snapshotId' must not be empty");
  return `${IMAGE_BUILDS_PATH}/${encodeURIComponent(snapshotId)}/logs`;
}

/**
 * Open the build log and yield its events until the final `state` event; the request is sent
 * on the first read. Reading to the end, stopping early and aborting all cancel the body
 * reader. A stream that ends without the `state` event raises `TransportError`.
 */
export async function* followBuildLogs(
  transport: Transport,
  snapshotId: string,
  call: CallOptions,
): AsyncGenerator<BuildLogEvent, void, undefined> {
  const path = buildLogsPath(snapshotId);
  const response = await transport.openStream("GET", path, {
    ...callArgs(call),
    minTimeoutMs: call.timeoutMs === undefined ? BUILD_LOG_MIN_TIMEOUT_MS : undefined,
  });
  const requestId = response.headers.get("x-request-id");
  if (response.body === null) throw new TransportError(withRequestId(BUILD_LOG_ENDED, requestId));
  const reader = response.body.getReader();
  const close = (): void => void reader.cancel().catch(() => undefined);
  call.signal?.addEventListener("abort", close, { once: true });
  try {
    const decoder = new SseDecoder();
    for (;;) {
      const chunk = await reader.read().catch((cause: unknown) => {
        throw streamReadFailure(BUILD_LOG_STREAM, cause, call.signal, requestId, response);
      });
      const frames = withReplyId(response, () =>
        chunk.done ? decoder.end() : decoder.feed(chunk.value),
      );
      for (const frame of frames) {
        const event = withReplyId(response, () => buildEventFromFrame(frame));
        if (event === undefined) continue;
        yield event;
        if (event.type === "state") return;
      }
      if (chunk.done) break;
    }
    if (call.signal?.aborted === true) {
      throw streamReadFailure(BUILD_LOG_STREAM, undefined, call.signal, requestId, response);
    }
    throw new TransportError(withRequestId(BUILD_LOG_ENDED, requestId));
  } finally {
    call.signal?.removeEventListener("abort", close);
    close();
  }
}
