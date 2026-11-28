/**
 * Sandbox operations beyond create/get/list/start/stop/delete: update (PATCH), reset, resize,
 * isolation tiers, preview tokens, `fs stat` and the command-log follow stream. Mirrors
 * `sandfort_sdk` (`Sandbox.reset`, `Sandbox.preview`, `Client.isolation`, `Fs.stat`,
 * `Process.follow_logs`); update and resize have no Python counterpart yet and follow the spec.
 *
 * `SandboxOps` is stateless: the client and every `Sandbox` build one around the shared
 * transport and a function that wraps a returned record into a `Sandbox` handle.
 */

import { InvalidResponseError, TransportError, withRequestId } from "./errors.js";
import { eventJson, streamedError, withReplyId } from "./contexts.js";
import {
  asArray,
  asRecord,
  compact,
  fileEntryFromPayload,
  optionalString,
  requiredNumber,
  requiredString,
  requiredTimestamp,
  sandboxFromPayload,
  type FileEntry,
  type SandboxInfo,
} from "./models.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { withHiddenSecret } from "./secret.js";
import { SseDecoder, type SseFrame } from "./sse.js";
import { streamReadFailure } from "./stream-failure.js";
import type { Transport } from "./transport.js";
import { fail, requireInteger, requireNonBlank } from "./validation.js";
import type { Sandbox } from "./sandbox.js";

const SANDBOXES = "/v1/sandboxes";
export const ISOLATION_PATH = "/v1/isolation";

const MAX_MINUTES = 525_600;
const MAX_LABELS = 32;
const MAX_LABEL_KEY = 63;
const MAX_LABEL_VALUE = 256;
const MIN_CPU_MILLICORES = 100;
const MAX_CPU_MILLICORES = 1_000_000;
const MIN_MEMORY_MIB = 64;
const MAX_MEMORY_MIB = 16_777_216;
const MIN_DISK_GIB = 1;
const MAX_DISK_GIB = 1_048_576;
const MIN_PREVIEW_PORT = 1024;
const MAX_PREVIEW_PORT = 65_535;
const MIN_PREVIEW_TTL_S = 60;
const MAX_PREVIEW_TTL_S = 604_800;
/** A follow stream may outlive the longest command (3600 s), plus a margin. */
const FOLLOW_MIN_TIMEOUT_MS = 3_610_000;
const LOG_STREAM = "the log stream";
const FOLLOW_ENDED = "command log stream ended before the exit event";

// --- types ----------------------------------------------------------------------------------

export interface UpdateSandboxOptions extends CallOptions {
  /** Replaces every user label (at most 32); `null` removes them all. Omit to keep them. */
  labels?: Readonly<Record<string, string>> | null;
  /** Minutes of inactivity before the sandbox stops (-1 turns auto-stop off). */
  autoStopMinutes?: number;
  /** Minutes after stopping before the sandbox is deleted (-1 turns auto-delete off). */
  autoDeleteMinutes?: number;
  /** Whether preview URLs need no token. */
  public?: boolean;
  /**
   * Replaces the egress allowlist (host names, leading-dot domains and CIDR ranges) of a
   * sandbox created with a non-empty one; omit it to keep the list. `[]` is sent as given and
   * refuses every connection; there is no way to remove an allowlist, so `null` is rejected.
   * The `egressPolicyGeneration` on the returned handle rises by 1 only when the list actually
   * changes: a list equal to the stored one is a no-op on the server (200, nothing changes, no
   * audit row). Entries are not checked here, the server validates them: most invalid entries
   * (uppercase, a scheme, a port, a wildcard, a bad or denied CIDR, too many entries) come back
   * as 422 `UNPROCESSABLE`, whitespace or control characters and a malformed request as 422
   * `VALIDATION_ERROR`; the SDK maps both to `ValidationFailed`. The server refuses with 409
   * `INVALID_STATE` (`InvalidState`, a `Conflict`) when the sandbox has no allowlist to
   * replace, was created with an empty list while `blockNetwork` was on, or predates egress v2
   * (`egressPolicyGeneration` 0 with a non-null `egressAllowlist` is a legacy v1 credential:
   * `reset` it to upgrade; with `egressAllowlist: null` the sandbox was created without an
   * allowlist and no update or reset will enable one), and with 403 `FORBIDDEN` when operator
   * policy forbids the change. The proxy applies the new list within its cache window.
   */
  egressAllowlist?: readonly string[];
}

/** New resources of a stopped sandbox; fields left out keep their value. */
export interface ResizeSandboxOptions extends CallOptions {
  cpuMillicores?: number;
  memoryMib?: number;
  diskGib?: number;
}

export interface MintPreviewTokenOptions extends CallOptions {
  /** Port inside the sandbox, 1024 to 65535. */
  port: number;
  /** Lifetime in seconds, 60 to 604800 (server default 3600 when left out). */
  ttlSeconds?: number;
}

export interface PreviewToken {
  /**
   * Not enumerable: it stays out of `JSON.stringify`, `Object.keys` and `console.log`, and a
   * copy (spread, `Object.assign`, `structuredClone`) does not carry it. Read it at once.
   */
  readonly token: string;
  url: string;
  /**
   * Set only when the server's preview origin is HTTPS. Open it in a browser: the token sits in
   * its fragment, so no request line or access log holds it. Use `url` or the
   * `Sandfort-Preview-Token` request header from scripts. Enumerable like `url`, and it holds
   * the same token, so do not log it.
   */
  browserUrl?: string;
  port: number;
  expiresAt: Date;
}

/** The isolation tiers a deployment offers and the one a create gets when it names none. */
export interface IsolationInfo {
  default: string;
  available: readonly string[];
}

export interface FollowCommandLogsOptions extends CallOptions {
  /**
   * Byte offset to start at (default 0). To resume a followed command, pass the `nextOffset`
   * of the last event you saw: the stream then goes on with the following line, with no line
   * repeated and none missing.
   */
  offset?: number;
}

/**
 * One event of a followed command: output as it is written, then the exit. `offset` is the byte
 * where a line starts. `nextOffset` is the resume point after the event (the SSE `id`): pass
 * it as `offset` to continue right after this event; `null` when the server sent no id.
 */
export type FollowLogEvent =
  | { type: "stdout" | "stderr"; offset: number; nextOffset: number | null; line: string }
  | {
      type: "exit";
      exitCode: number | null;
      state: string;
      truncated: boolean;
      nextOffset: number | null;
    };

// --- request bodies -------------------------------------------------------------------------

function requireMinutes(value: number, label: string): void {
  requireInteger(value, label, -1, MAX_MINUTES);
}

function requireLabels(labels: Readonly<Record<string, string>>): void {
  const entries = Object.entries(labels);
  if (entries.length > MAX_LABELS) fail(`labels must have at most ${MAX_LABELS} entries`);
  for (const [key, value] of entries) {
    if (key.length > MAX_LABEL_KEY) fail(`a label key must be at most ${MAX_LABEL_KEY} characters`);
    if (typeof value !== "string" || value.length > MAX_LABEL_VALUE) {
      fail(`a label value must be a string of at most ${MAX_LABEL_VALUE} characters`);
    }
  }
}

export function updateBody(options: UpdateSandboxOptions): Record<string, unknown> {
  const { labels, autoStopMinutes, autoDeleteMinutes, egressAllowlist } = options;
  if (labels !== undefined && labels !== null) requireLabels(labels);
  if (egressAllowlist !== undefined && !Array.isArray(egressAllowlist)) {
    fail("egressAllowlist must be an array of host names, domains or CIDR ranges");
  }
  if (autoStopMinutes !== undefined) requireMinutes(autoStopMinutes, "autoStopMinutes");
  if (autoDeleteMinutes !== undefined) requireMinutes(autoDeleteMinutes, "autoDeleteMinutes");
  if (options.public !== undefined && typeof options.public !== "boolean") {
    fail("public must be a boolean");
  }
  const body = compact({
    labels,
    auto_stop_minutes: autoStopMinutes,
    auto_delete_minutes: autoDeleteMinutes,
    public: options.public,
    egress_allowlist: egressAllowlist === undefined ? undefined : [...egressAllowlist],
  });
  if (Object.keys(body).length === 0) {
    fail(
      "updateSandbox needs at least one of labels, autoStopMinutes, autoDeleteMinutes, public, egressAllowlist",
    );
  }
  return body;
}

export function resizeBody(options: ResizeSandboxOptions): Record<string, unknown> {
  const { cpuMillicores, memoryMib, diskGib } = options;
  if (cpuMillicores !== undefined) {
    requireInteger(cpuMillicores, "cpuMillicores", MIN_CPU_MILLICORES, MAX_CPU_MILLICORES);
  }
  if (memoryMib !== undefined) {
    requireInteger(memoryMib, "memoryMib", MIN_MEMORY_MIB, MAX_MEMORY_MIB);
  }
  if (diskGib !== undefined) requireInteger(diskGib, "diskGib", MIN_DISK_GIB, MAX_DISK_GIB);
  const body = compact({ cpu_millicores: cpuMillicores, memory_mib: memoryMib, disk_gib: diskGib });
  if (Object.keys(body).length === 0) {
    fail("resizeSandbox needs at least one of cpuMillicores, memoryMib, diskGib");
  }
  return body;
}

export function previewBody(options: MintPreviewTokenOptions): Record<string, unknown> {
  requireInteger(options.port, "port", MIN_PREVIEW_PORT, MAX_PREVIEW_PORT);
  if (options.ttlSeconds !== undefined) {
    requireInteger(options.ttlSeconds, "ttlSeconds", MIN_PREVIEW_TTL_S, MAX_PREVIEW_TTL_S);
  }
  return compact({ port: options.port, ttl_seconds: options.ttlSeconds });
}

// --- payload decoding -----------------------------------------------------------------------

export function previewTokenFromPayload(data: unknown): PreviewToken {
  const what = "preview token";
  const raw = asRecord(data, what);
  const token = requiredString(raw, "token", what);
  const browserUrl = optionalString(raw, "browser_url");
  const info = {
    url: requiredString(raw, "url", what),
    ...(browserUrl === undefined ? {} : { browserUrl }),
    port: requiredNumber(raw, "port", what),
    expiresAt: requiredTimestamp(raw["expires_at"], what),
  };
  return withHiddenSecret(info, "token", token) as PreviewToken;
}

export function isolationFromPayload(data: unknown): IsolationInfo {
  const what = "isolation";
  const raw = asRecord(data, what);
  const available = asArray(raw["available"], "isolation tiers").map((tier) => {
    if (typeof tier !== "string") throw new InvalidResponseError("isolation tier must be a string");
    return tier;
  });
  return { default: requiredString(raw, "default", what), available };
}

const BYTE_OFFSET = /^\d+$/;

/** The resume offset an event's SSE `id` carries: `null` when absent, an error when invalid. */
function nextOffsetOf(frame: SseFrame): number | null {
  const id = frame.id?.trim();
  if (id === undefined || id === "") return null;
  const offset = Number(id);
  if (!BYTE_OFFSET.test(id) || !Number.isSafeInteger(offset)) {
    throw new InvalidResponseError(`${frame.event} event id is not a byte offset: ${frame.id}`);
  }
  return offset;
}

function logEventFromFrame(frame: SseFrame): FollowLogEvent | undefined {
  if (frame.event === "stdout" || frame.event === "stderr") {
    const what = `${frame.event} event`;
    const raw = eventJson(frame);
    return {
      type: frame.event,
      offset: requiredNumber(raw, "offset", what),
      nextOffset: nextOffsetOf(frame),
      line: requiredString(raw, "line", what),
    };
  }
  if (frame.event !== "exit") return undefined;
  const raw = eventJson(frame);
  const code = raw["exit_code"];
  if (code !== null && typeof code !== "number") {
    throw new InvalidResponseError("exit event 'exit_code' must be a number or null");
  }
  return {
    type: "exit",
    exitCode: code,
    state: requiredString(raw, "state", "exit event"),
    truncated: raw["truncated"] === true,
    nextOffset: nextOffsetOf(frame),
  };
}

// --- the operations -------------------------------------------------------------------------

export class SandboxOps {
  readonly #transport: Transport;
  readonly #wrap: (info: SandboxInfo) => Sandbox;

  constructor(transport: Transport, wrap: (info: SandboxInfo) => Sandbox) {
    this.#transport = transport;
    this.#wrap = wrap;
  }

  /** PATCH the mutable fields; the other fields keep their value. */
  async update(sandboxId: string, options: UpdateSandboxOptions): Promise<Sandbox> {
    const json = updateBody(options);
    return this.#sandbox("PATCH", this.#path(sandboxId), { json, ...callArgs(options) });
  }

  /** Replace the container with a fresh one from the same image (a started or stopped sandbox). */
  reset(sandboxId: string, call: CallOptions = {}): Promise<Sandbox> {
    return this.#sandbox("POST", this.#path(sandboxId, "/reset"), { ...callArgs(call) });
  }

  /** Change the resources of a stopped sandbox; any other state answers 409 (`Conflict`). */
  async resize(sandboxId: string, options: ResizeSandboxOptions): Promise<Sandbox> {
    const json = resizeBody(options);
    return this.#sandbox("POST", this.#path(sandboxId, "/resize"), { json, ...callArgs(options) });
  }

  async listIsolation(call: CallOptions = {}): Promise<IsolationInfo> {
    const reply = await this.#transport.request("GET", ISOLATION_PATH, { ...callArgs(call) });
    return isolationFromPayload(reply);
  }

  async mintPreviewToken(
    sandboxId: string,
    options: MintPreviewTokenOptions,
  ): Promise<PreviewToken> {
    const json = previewBody(options);
    const path = this.#path(sandboxId, "/preview-tokens");
    const reply = await this.#transport.request("POST", path, { json, ...callArgs(options) });
    return previewTokenFromPayload(reply);
  }

  /**
   * Iterate the output of a command as it is written; the last event is `exit`. Arguments are
   * checked on the first `next()`, which also sends the request. Leaving the loop early closes
   * the connection. A stream that ends without `exit` raises `TransportError`; an `error` event
   * raises the typed error of its code. A per-call `timeoutMs` bounds the whole stream, and a
   * `deadlineMs` (per call or on the client) cuts it too, however long the command still runs.
   * To resume after a break, pass the `nextOffset` of the last event you saw as `offset`.
   */
  followCommandLogs(
    sandboxId: string,
    sessionId: string,
    commandId: string,
    options: FollowCommandLogsOptions = {},
  ): AsyncGenerator<FollowLogEvent, void, undefined> {
    return this.#follow(sandboxId, sessionId, commandId, options);
  }

  async #sandbox(
    method: string,
    path: string,
    options: Parameters<Transport["request"]>[2],
  ): Promise<Sandbox> {
    return this.#wrap(sandboxFromPayload(await this.#transport.request(method, path, options)));
  }

  #path(sandboxId: string, tail = ""): string {
    requireNonBlank(sandboxId, "sandboxId");
    return `${SANDBOXES}/${encodeURIComponent(sandboxId)}${tail}`;
  }

  async *#follow(
    sandboxId: string,
    sessionId: string,
    commandId: string,
    options: FollowCommandLogsOptions,
  ): AsyncGenerator<FollowLogEvent, void, undefined> {
    requireNonBlank(sessionId, "sessionId");
    requireNonBlank(commandId, "commandId");
    if (options.offset !== undefined) {
      requireInteger(options.offset, "offset", 0, Number.MAX_SAFE_INTEGER);
    }
    const toolbox = this.#path(sandboxId, "/toolbox/process/sessions");
    const command = `${encodeURIComponent(sessionId)}/commands/${encodeURIComponent(commandId)}`;
    const path = `${toolbox}/${command}/logs/follow`;
    const response = await this.#transport.openStream("GET", path, {
      query: { offset: options.offset },
      ...callArgs(options),
      // The stream may legitimately run as long as the command; an explicit timeoutMs bounds it.
      minTimeoutMs: options.timeoutMs === undefined ? FOLLOW_MIN_TIMEOUT_MS : undefined,
    });
    const requestId = response.headers.get("x-request-id");
    if (response.body === null) throw new TransportError(withRequestId(FOLLOW_ENDED, requestId));
    const reader = response.body.getReader();
    const close = (): void => void reader.cancel().catch(() => undefined);
    options.signal?.addEventListener("abort", close, { once: true });
    try {
      const decoder = new SseDecoder();
      for (;;) {
        const chunk = await reader.read().catch((cause: unknown) => {
          throw streamReadFailure(LOG_STREAM, cause, options.signal, requestId, response);
        });
        const frames = withReplyId(response, () =>
          chunk.done ? decoder.end() : decoder.feed(chunk.value),
        );
        for (const frame of frames) {
          if (frame.event === "error") {
            throw withReplyId(response, () => streamedError(frame, response));
          }
          const event = withReplyId(response, () => logEventFromFrame(frame));
          if (event === undefined) continue;
          yield event;
          if (event.type === "exit") return;
        }
        if (chunk.done) break;
      }
      if (options.signal?.aborted === true) {
        throw streamReadFailure(LOG_STREAM, undefined, options.signal, requestId, response);
      }
      throw new TransportError(withRequestId(FOLLOW_ENDED, requestId));
    } finally {
      options.signal?.removeEventListener("abort", close);
      close();
    }
  }
}

/** `GET .../fs/stat`: the entry of a path (file, directory or symlink). */
export async function statEntry(
  transport: Transport,
  toolboxPath: string,
  path: string,
  call: CallOptions = {},
): Promise<FileEntry> {
  requireNonBlank(path, "path");
  const reply = await transport.request("GET", `${toolboxPath}/fs/stat`, {
    query: { path },
    ...callArgs(call),
  });
  const entry = asRecord(reply, "fs stat")["entry"];
  if (entry === undefined || entry === null) {
    throw new InvalidResponseError("fs stat payload is missing 'entry'");
  }
  return fileEntryFromPayload(entry);
}
