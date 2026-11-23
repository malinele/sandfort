/**
 * Stateful code contexts: a persistent Python kernel per context, so variables and imports
 * survive between runs. Mirrors `sandfort_sdk.code_contexts`. The state lives in the kernel
 * process and is lost when the sandbox is stopped, reset or deleted; `ensure` brings a context
 * of the same name back, empty. Only Python is supported.
 */

import {
  InvalidResponseError,
  TransportError,
  errorFor,
  withRequestId,
} from "./errors.js";
import { asArray, asRecord, compact, requiredBoolean, requiredString } from "./models.js";
import {
  DEFAULT_EXEC_TIMEOUT_S,
  EXEC_TIMEOUT_MARGIN_MS,
  execResultFromPayload,
  type ExecResult,
} from "./process.js";
import { isRecord, parseJson } from "./reply.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { SseDecoder, type SseFrame } from "./sse.js";
import { streamReadFailure } from "./stream-failure.js";
import type { Transport } from "./transport.js";
import { fail, requireNonBlank, requireTimeoutS } from "./validation.js";

export type CodeContextLanguage = "python";

const LANGUAGE: CodeContextLanguage = "python";
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/;
const STATUS_FOUND = 200;
/** A run may queue for up to `timeoutS` and then run for up to `timeoutS`. */
const QUEUE_AND_RUN = 2;
const RUN_STREAM = "the code context run stream";
const STREAM_ENDED = "code context run stream ended before the result event";

/** A live kernel of a sandbox. */
export interface CodeContextInfo {
  /** Context id, `ctx_` plus 16 hex characters. */
  id: string;
  /** The kernel's working directory. */
  cwd: string;
  /** The name the context was created with; `null` for an unnamed one. */
  name: string | null;
  language: CodeContextLanguage;
}

/** Why a cell was stopped; `null` in `CellResult.stopReason` for a normal exit. */
export type StopReason =
  | "timeout"
  | "queue_timeout"
  | "output_limit"
  | "context_lost"
  | "sandbox_stopped"
  | "sandbox_deleted"
  | "sandbox_reset"
  | "oom_killed"
  | "killed";

/** The exception a cell raised: its class name and `str()` (the traceback is on stderr). */
export interface CellError {
  type: string;
  message: string;
}

/** An `ExecResult` of a code-context run, plus the cell's structured outcome. */
export interface CellResult extends ExecResult {
  sandboxStopped: boolean;
  /** A known `StopReason`, or another string a newer server sends; `null` for a normal exit. */
  stopReason: StopReason | (string & Record<never, never>) | null;
  /** `repr()` of the cell's trailing expression; `null` when there is none or the cell raised. */
  result: string | null;
  /** Set when the cell raised, including `TimeoutError` and `KeyboardInterrupt`. */
  error: CellError | null;
}

/** One event of a streamed run: output as it is written, then the final result. */
export type CodeContextEvent =
  | { type: "stdout"; data: string }
  | { type: "stderr"; data: string }
  | { type: "result"; result: CellResult };

export interface CreateCodeContextOptions extends CallOptions {
  /**
   * Name of the context. When a live context already has it, that one is returned (with its
   * own `cwd`) instead of a new one. Letters, digits, `_`, `.`, `-`; at most 63 characters.
   */
  name?: string;
  /** Only `"python"` is supported (the default). */
  language?: CodeContextLanguage;
  /** Working directory of a new kernel (default: the sandbox's working directory). */
  cwd?: string;
}

export interface EnsureCodeContextOptions extends CallOptions {
  language?: CodeContextLanguage;
  /** Used only when a context is created; a live context keeps its own. */
  cwd?: string;
}

export interface EnsureCodeContextResult {
  context: CodeContextInfo;
  /** `true` for a new, empty context (run the setup cells); `false` for a live one found. */
  created: boolean;
}

export interface ListCodeContextsOptions extends CallOptions {
  /** Only the context of this name. */
  name?: string;
}

export interface RunInCodeContextOptions extends CallOptions {
  /** Per-cell limit in whole seconds (default 60, at most 3600). */
  timeoutS?: number;
}

// --- validation and request building -------------------------------------------------------

function requireName(name: string): void {
  if (typeof name !== "string" || !NAME_PATTERN.test(name)) {
    fail(
      "name must be 1 to 63 characters: letters, digits, '_', '.', '-', " +
        "starting with a letter or digit",
    );
  }
}

function requireLanguage(language: string | undefined): void {
  if (language !== undefined && language !== LANGUAGE) {
    fail(`language must be '${LANGUAGE}', got '${String(language)}'`);
  }
}

function createBody(options: CreateCodeContextOptions): Record<string, unknown> {
  if (options.name !== undefined) requireName(options.name);
  requireLanguage(options.language);
  if (options.cwd !== undefined) requireNonBlank(options.cwd, "cwd");
  return compact({
    language: options.language ?? LANGUAGE,
    name: options.name,
    cwd: options.cwd,
  });
}

function runBody(code: string, options: RunInCodeContextOptions): Record<string, unknown> {
  if (typeof code !== "string") fail("code must be a string");
  if (options.timeoutS !== undefined) requireTimeoutS(options.timeoutS);
  return { language: LANGUAGE, code, timeout_s: options.timeoutS ?? DEFAULT_EXEC_TIMEOUT_S };
}

/**
 * The request timeout a run needs at least: it may queue and then run, each for `timeoutS`.
 * An explicit per-call `timeoutMs` wins, so then there is no floor.
 */
function runRequestTimeoutMs(options: RunInCodeContextOptions): number | undefined {
  if (options.timeoutMs !== undefined) return undefined;
  const timeoutS = options.timeoutS ?? DEFAULT_EXEC_TIMEOUT_S;
  return timeoutS * QUEUE_AND_RUN * 1000 + EXEC_TIMEOUT_MARGIN_MS;
}

// --- payload decoding -----------------------------------------------------------------------

function optionalField<T>(
  raw: Record<string, unknown>,
  key: string,
  what: string,
  kind: "string" | "boolean",
  fallback: T,
): string | boolean | T {
  const value = raw[key];
  if (value === undefined || value === null) return fallback;
  if (typeof value !== kind) throw new InvalidResponseError(`${what} '${key}' must be a ${kind}`);
  return value as string | boolean;
}

export function contextFromPayload(data: unknown): CodeContextInfo {
  const what = "code context";
  const raw = asRecord(data, what);
  return {
    id: requiredString(raw, "id", what),
    cwd: requiredString(raw, "cwd", what),
    name: optionalField(raw, "name", what, "string", null) as string | null,
    language: LANGUAGE,
  };
}

function cellErrorFromPayload(data: unknown): CellError | null {
  if (data === undefined || data === null) return null;
  const what = "cell error";
  const raw = asRecord(data, what);
  return { type: requiredString(raw, "type", what), message: requiredString(raw, "message", what) };
}

export function cellFromPayload(data: unknown): CellResult {
  const what = "cell result";
  const raw = asRecord(data, what);
  return {
    ...execResultFromPayload(data),
    sandboxStopped: optionalField(raw, "sandbox_stopped", what, "boolean", false) as boolean,
    stopReason: optionalField(raw, "stop_reason", what, "string", null) as string | null,
    result: optionalField(raw, "result", what, "string", null) as string | null,
    error: cellErrorFromPayload(raw["error"]),
  };
}

// --- streamed runs --------------------------------------------------------------------------

export function eventJson(frame: SseFrame): Record<string, unknown> {
  const what = `${frame.event} event`;
  const parsed = parseJson(frame.data);
  if (parsed === undefined) throw new InvalidResponseError(`${what} data is not JSON`);
  return asRecord(parsed, what);
}

export function streamedError(frame: SseFrame, response: Response): Error {
  const raw = eventJson(frame);
  const details = raw["details"];
  return errorFor({
    code: requiredString(raw, "code", "error event"),
    message: requiredString(raw, "message", "error event"),
    status: response.status,
    details: isRecord(details) && Object.keys(details).length > 0 ? details : undefined,
    requestId: response.headers.get("x-request-id") ?? undefined,
  });
}

/** The event a frame carries; `undefined` for event types this SDK ignores. */
function eventFromFrame(frame: SseFrame, response: Response): CodeContextEvent | undefined {
  if (frame.event === "stdout" || frame.event === "stderr") {
    const data = requiredString(eventJson(frame), "data", `${frame.event} event`);
    return { type: frame.event, data };
  }
  if (frame.event === "error") throw streamedError(frame, response);
  if (frame.event !== "result") return undefined;
  return { type: "result", result: cellFromPayload(eventJson(frame)) };
}

/** Run `step`; an `InvalidResponseError` it raises gets the request id of `response`. */
export function withReplyId<T>(response: Response, step: () => T): T {
  try {
    return step();
  } catch (error) {
    if (!(error instanceof InvalidResponseError)) throw error;
    const message = withRequestId(error.message, response.headers.get("x-request-id"));
    throw new InvalidResponseError(message, { cause: error });
  }
}

// --- the facade -----------------------------------------------------------------------------

/** Code-context calls of one sandbox; `toolboxPath` is `/v1/sandboxes/{id}/toolbox`. */
export class CodeContexts {
  readonly #transport: Transport;
  readonly #basePath: string;

  constructor(transport: Transport, toolboxPath: string) {
    this.#transport = transport;
    this.#basePath = `${toolboxPath}/code-contexts`;
  }

  /** Start a kernel; with `name`, a live context of that name is returned instead. */
  async create(options: CreateCodeContextOptions = {}): Promise<CodeContextInfo> {
    return (await this.#create(options)).context;
  }

  /**
   * Like `create`, but also says whether the call started the kernel (`created: true`) or
   * found a live one of the same name (`false`); an unnamed call always starts one.
   */
  createWithStatus(options: CreateCodeContextOptions = {}): Promise<EnsureCodeContextResult> {
    return this.#create(options);
  }

  /**
   * The live context named `name`, or a new one. After a sandbox stop and start it starts a new
   * context of the same name: the state (variables, imports) is not restored.
   */
  async ensure(
    name: string,
    options: EnsureCodeContextOptions = {},
  ): Promise<EnsureCodeContextResult> {
    requireName(name);
    return this.#create({ ...options, name });
  }

  async list(options: ListCodeContextsOptions = {}): Promise<readonly CodeContextInfo[]> {
    if (options.name !== undefined) requireName(options.name);
    const reply = await this.#transport.request("GET", this.#basePath, {
      query: { name: options.name },
      ...callArgs(options),
    });
    return asArray(reply, "code contexts").map(contextFromPayload);
  }

  /** Run `code` in the kernel; the state of earlier runs is visible to it. */
  async run(
    contextId: string,
    code: string,
    options: RunInCodeContextOptions = {},
  ): Promise<CellResult> {
    const path = this.#contextPath(contextId, "/run");
    const reply = await this.#transport.request("POST", path, {
      json: runBody(code, options),
      ...callArgs(options),
      minTimeoutMs: runRequestTimeoutMs(options),
    });
    return cellFromPayload(reply);
  }

  /**
   * Run `code` like `run`, yielding its output as it is written and ending with the
   * `result` event. Arguments are checked when this is called; the request is sent on the
   * first `next()`. Leaving the loop early closes the connection. A stream that ends without a
   * result raises `TransportError`; an `error` event raises the typed error of its code.
   */
  streamRun(
    contextId: string,
    code: string,
    options: RunInCodeContextOptions = {},
  ): AsyncGenerator<CodeContextEvent, void, undefined> {
    const path = this.#contextPath(contextId, "/run/stream");
    const json = runBody(code, options);
    return this.#events(path, json, options);
  }

  /** Interrupt the running cell (`KeyboardInterrupt`); the state stays. `false`: no kernel. */
  async interrupt(contextId: string, call: CallOptions = {}): Promise<boolean> {
    const path = this.#contextPath(contextId, "/interrupt");
    const reply = await this.#transport.request("POST", path, { ...callArgs(call) });
    return requiredBoolean(asRecord(reply, "interrupt"), "interrupted", "interrupt");
  }

  /** Kill the kernel; its state is gone. */
  async delete(contextId: string, call: CallOptions = {}): Promise<void> {
    await this.#transport.request("DELETE", this.#contextPath(contextId), { ...callArgs(call) });
  }

  async #create(options: CreateCodeContextOptions): Promise<EnsureCodeContextResult> {
    const reply = await this.#transport.requestEnvelope("POST", this.#basePath, {
      json: createBody(options),
      ...callArgs(options),
    });
    // 200: a live context of the name was found; 201 (or anything else): a new kernel started.
    const created = options.name === undefined || reply.status !== STATUS_FOUND;
    return { context: contextFromPayload(reply.data), created };
  }

  #contextPath(contextId: string, tail = ""): string {
    requireNonBlank(contextId, "contextId");
    return `${this.#basePath}/${encodeURIComponent(contextId)}${tail}`;
  }

  async *#events(
    path: string,
    json: Record<string, unknown>,
    options: RunInCodeContextOptions,
  ): AsyncGenerator<CodeContextEvent, void, undefined> {
    const response = await this.#transport.openStream("POST", path, {
      json,
      ...callArgs(options),
      minTimeoutMs: runRequestTimeoutMs(options),
    });
    const requestId = response.headers.get("x-request-id");
    if (response.body === null) throw new TransportError(withRequestId(STREAM_ENDED, requestId));
    const reader = response.body.getReader();
    const close = (): void => void reader.cancel().catch(() => undefined);
    options.signal?.addEventListener("abort", close, { once: true });
    try {
      const decoder = new SseDecoder();
      for (;;) {
        const chunk = await reader.read().catch((cause: unknown) => {
          throw streamReadFailure(RUN_STREAM, cause, options.signal, requestId, response);
        });
        const frames = withReplyId(response, () =>
          chunk.done ? decoder.end() : decoder.feed(chunk.value),
        );
        for (const frame of frames) {
          const event = withReplyId(response, () => eventFromFrame(frame, response));
          if (event === undefined) continue;
          yield event;
          if (event.type === "result") return;
        }
        if (chunk.done) break;
      }
      if (options.signal?.aborted === true) {
        throw streamReadFailure(RUN_STREAM, undefined, options.signal, requestId, response);
      }
      throw new TransportError(withRequestId(STREAM_ENDED, requestId));
    } finally {
      options.signal?.removeEventListener("abort", close);
      close();
    }
  }
}
