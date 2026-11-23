/**
 * Exec sessions of one sandbox, mirroring the session calls of `sandfort_sdk.process.Process`.
 *
 * Plain request/response only: no server-sent events in this slice, so the python
 * `follow_logs` stream has no counterpart here (use `getCommandLogs` to poll). The server has
 * no delete-session route, so there is no `deleteSession` either.
 */

import { InvalidResponseError, ValidationError } from "./errors.js";
import { requireTimeoutS } from "./validation.js";
import { callArgs, type CallOptions } from "./resilience.js";
import {
  asArray,
  asRecord,
  compact,
  requiredString,
  requiredTimestamp,
  stringOrNull,
  timestampOrNull,
} from "./models.js";
import {
  DEFAULT_EXEC_TIMEOUT_S,
  execRequestTimeoutMs,
  execResultFromPayload,
  type ExecResult,
} from "./process.js";
import type { Transport } from "./transport.js";

export interface SessionInfo {
  id: string;
  sandboxId: string;
  cwd: string | null;
  env: Record<string, string>;
  state: string;
  createdAt: Date;
}

export interface CommandInfo {
  id: string;
  sessionId: string | null;
  /** `"running"`, `"exited"` or `"killed"`. */
  state: string;
  exitCode: number | null;
  stdoutBytes: number;
  stderrBytes: number;
  createdAt: Date;
  finishedAt: Date | null;
}

export interface LogEvent {
  stream: string;
  offset: number;
  line: string;
}

export interface LogPage {
  events: readonly LogEvent[];
  nextOffset: number;
  truncated: boolean;
  complete: boolean;
  state: string | null;
  exitCode: number | null;
}

export interface CreateSessionOptions extends CallOptions {
  cwd?: string;
  env?: Record<string, string>;
}

export interface RunInSessionOptions extends CallOptions {
  /** Server-side limit in whole seconds (default 60). */
  timeoutS?: number;
}

export interface CommandLogsOptions extends CallOptions {
  /** Byte offset to start reading at (default 0, must be >= 0). */
  offset?: number;
  limit?: number;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" ? value : null;
}

function envFromPayload(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (typeof value === "object" && value !== null) {
    for (const [key, item] of Object.entries(value)) out[key] = String(item);
  }
  return out;
}

export function sessionFromPayload(data: unknown): SessionInfo {
  const what = "session";
  const raw = asRecord(data, what);
  return {
    id: requiredString(raw, "id", what),
    sandboxId: requiredString(raw, "sandbox_id", what),
    cwd: stringOrNull(raw["cwd"]),
    env: envFromPayload(raw["env"]),
    state: requiredString(raw, "state", what),
    createdAt: requiredTimestamp(raw["created_at"], what),
  };
}

export function commandFromPayload(data: unknown): CommandInfo {
  const what = "command";
  const raw = asRecord(data, what);
  return {
    id: requiredString(raw, "id", what),
    sessionId: stringOrNull(raw["session_id"]),
    state: requiredString(raw, "state", what),
    exitCode: numberOrNull(raw["exit_code"]),
    stdoutBytes: numberOrNull(raw["stdout_bytes"]) ?? 0,
    stderrBytes: numberOrNull(raw["stderr_bytes"]) ?? 0,
    createdAt: requiredTimestamp(raw["created_at"], what),
    finishedAt: timestampOrNull(raw["finished_at"], what),
  };
}

function logEventFromPayload(data: unknown): LogEvent {
  const what = "log event";
  const raw = asRecord(data, what);
  const offset = raw["offset"];
  if (typeof offset !== "number") {
    throw new InvalidResponseError(`${what} payload is missing 'offset'`);
  }
  return {
    stream: requiredString(raw, "stream", what),
    offset,
    line: requiredString(raw, "line", what),
  };
}

export function logPageFromPayload(data: unknown): LogPage {
  const what = "log page";
  const raw = asRecord(data, what);
  const nextOffset = raw["next_offset"];
  if (typeof nextOffset !== "number") {
    throw new InvalidResponseError(`${what} payload is missing 'next_offset'`);
  }
  const truncated = raw["truncated"];
  const complete = raw["complete"];
  if (typeof truncated !== "boolean" || typeof complete !== "boolean") {
    throw new InvalidResponseError(`${what} payload is missing 'truncated' or 'complete'`);
  }
  return {
    events: asArray(raw["events"], "log events").map((item) => logEventFromPayload(item)),
    nextOffset,
    truncated,
    complete,
    state: stringOrNull(raw["state"]),
    exitCode: numberOrNull(raw["exit_code"]),
  };
}

/** Wire body for `POST .../sessions`; unset options are omitted. */
export function sessionCreateBody(options: CreateSessionOptions): Record<string, unknown> {
  return compact({ cwd: options.cwd, env: options.env });
}

/** Wire body for `POST .../sessions/{id}/commands`. */
export function sessionCommandBody(
  command: string,
  runAsync: boolean,
  timeoutS: number,
): Record<string, unknown> {
  if (command.trim() === "") throw new ValidationError("'command' must not be empty");
  requireTimeoutS(timeoutS);
  return { command, mode: runAsync ? "async" : "sync", timeout_s: timeoutS };
}

/** Session and command calls of one sandbox; `toolboxPath` is `/v1/sandboxes/{id}/toolbox`. */
export class Sessions {
  readonly #transport: Transport;
  readonly #basePath: string;

  constructor(transport: Transport, toolboxPath: string) {
    this.#transport = transport;
    this.#basePath = `${toolboxPath}/process/sessions`;
  }

  async createSession(options: CreateSessionOptions = {}): Promise<SessionInfo> {
    const reply = await this.#transport.request("POST", this.#basePath, {
      json: sessionCreateBody(options),
      ...callArgs(options),
    });
    return sessionFromPayload(reply);
  }

  async listSessions(call: CallOptions = {}): Promise<readonly SessionInfo[]> {
    const reply = await this.#transport.request("GET", this.#basePath, { ...callArgs(call) });
    return asArray(reply, "sessions").map((item) => sessionFromPayload(item));
  }

  async getSession(sessionId: string, call: CallOptions = {}): Promise<SessionInfo> {
    const reply = await this.#transport.request("GET", this.#session(sessionId), {
      ...callArgs(call),
    });
    return sessionFromPayload(reply);
  }

  /** Run a command in the session and wait for it (shell state such as `cd` persists). */
  async runInSession(
    sessionId: string,
    command: string,
    options: RunInSessionOptions = {},
  ): Promise<ExecResult> {
    const body = sessionCommandBody(command, false, options.timeoutS ?? DEFAULT_EXEC_TIMEOUT_S);
    const reply = await this.#transport.request("POST", `${this.#session(sessionId)}/commands`, {
      json: body,
      ...callArgs(options),
      minTimeoutMs: execRequestTimeoutMs(options),
    });
    const result = asRecord(reply, "session exec")["result"];
    if (result === undefined || result === null) {
      throw new InvalidResponseError("session exec payload is missing 'result'");
    }
    return execResultFromPayload(result);
  }

  /** Start a command without waiting; poll it with `getCommand` / `getCommandLogs`. */
  async startCommand(
    sessionId: string,
    command: string,
    options: RunInSessionOptions = {},
  ): Promise<CommandInfo> {
    const body = sessionCommandBody(command, true, options.timeoutS ?? DEFAULT_EXEC_TIMEOUT_S);
    const reply = await this.#transport.request("POST", `${this.#session(sessionId)}/commands`, {
      json: body,
      ...callArgs(options),
    });
    const started = asRecord(reply, "session exec")["command"];
    if (started === undefined || started === null) {
      throw new InvalidResponseError("session exec payload is missing 'command'");
    }
    return commandFromPayload(started);
  }

  async getCommand(
    sessionId: string,
    commandId: string,
    call: CallOptions = {},
  ): Promise<CommandInfo> {
    const reply = await this.#transport.request("GET", this.#command(sessionId, commandId), {
      ...callArgs(call),
    });
    return commandFromPayload(reply);
  }

  /** Collected stdout/stderr of a command from `offset` on (a plain read, not a stream). */
  async getCommandLogs(
    sessionId: string,
    commandId: string,
    options: CommandLogsOptions = {},
  ): Promise<LogPage> {
    const offset = options.offset ?? 0;
    if (offset < 0) throw new ValidationError("offset must be >= 0");
    const reply = await this.#transport.request(
      "GET",
      this.#command(sessionId, commandId, "/logs"),
      { query: { offset, limit: options.limit }, ...callArgs(options) },
    );
    return logPageFromPayload(reply);
  }

  async killCommand(
    sessionId: string,
    commandId: string,
    call: CallOptions = {},
  ): Promise<CommandInfo> {
    const reply = await this.#transport.request(
      "POST",
      this.#command(sessionId, commandId, "/kill"),
      { ...callArgs(call) },
    );
    return commandFromPayload(reply);
  }

  #session(sessionId: string): string {
    return `${this.#basePath}/${encodeURIComponent(sessionId)}`;
  }

  #command(sessionId: string, commandId: string, tail = ""): string {
    return `${this.#session(sessionId)}/commands/${encodeURIComponent(commandId)}${tail}`;
  }
}
