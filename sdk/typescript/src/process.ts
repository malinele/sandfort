/** Process toolbox: one-shot exec and code-run, mirroring `sandfort_sdk.process.Process`. */

import { callArgs, type CallOptions } from "./resilience.js";
import { requireNonBlank, requireTimeoutS } from "./validation.js";
import { asRecord, compact, requiredBoolean, requiredNumber, requiredString } from "./models.js";
import type { Transport } from "./transport.js";

/** Default `timeout_s` for exec and code-run, as in the python sdk and the server schema. */
export const DEFAULT_EXEC_TIMEOUT_S = 60;

/** Languages accepted by `POST .../toolbox/process/code-run`. */
export type CodeLanguage = "python" | "javascript" | "typescript" | "bash";

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
  durationMs: number;
}

/** Head room added to a server-side exec limit so the client does not give up first. */
export const EXEC_TIMEOUT_MARGIN_MS = 10_000;

/**
 * The request timeout an exec with server-side limit `timeoutS` needs at least. An explicit
 * per-call `timeoutMs` wins over it, so then there is no floor (`undefined`).
 */
export function execRequestTimeoutMs(
  call: CallOptions & { timeoutS?: number },
): number | undefined {
  if (call.timeoutMs !== undefined) return undefined;
  return (call.timeoutS ?? DEFAULT_EXEC_TIMEOUT_S) * 1000 + EXEC_TIMEOUT_MARGIN_MS;
}

export interface ExecOptions extends CallOptions {
  cwd?: string;
  env?: Record<string, string>;
  /** Server-side limit in whole seconds (default 60). */
  timeoutS?: number;
  stdin?: string;
}

export interface CodeRunOptions extends CallOptions {
  argv?: readonly string[];
  /** Working directory for the run, any non-blank string (default: the container's). */
  cwd?: string;
  env?: Record<string, string>;
  /** Server-side limit in whole seconds (default 60). */
  timeoutS?: number;
}

/**
 * Wire body for `.../process/execute`: a string is sent as `command` (run by a shell), an
 * array as `argv` (no shell). Key order and omission of unset fields match the python sdk.
 */
export function execBody(
  command: string | readonly string[],
  options: ExecOptions,
): Record<string, unknown> {
  const isShell = typeof command === "string";
  if (options.timeoutS !== undefined) requireTimeoutS(options.timeoutS);
  if (options.cwd !== undefined) requireNonBlank(options.cwd, "cwd");
  return compact({
    command: isShell ? command : undefined,
    argv: isShell ? undefined : [...command],
    cwd: options.cwd,
    env: options.env,
    stdin: options.stdin,
    timeout_s: options.timeoutS ?? DEFAULT_EXEC_TIMEOUT_S,
  });
}

/** Wire body for `.../process/code-run`. */
export function codeRunBody(
  language: CodeLanguage,
  code: string,
  options: CodeRunOptions,
): Record<string, unknown> {
  if (options.timeoutS !== undefined) requireTimeoutS(options.timeoutS);
  if (options.cwd !== undefined) requireNonBlank(options.cwd, "cwd");
  return compact({
    language,
    code,
    argv: options.argv === undefined ? undefined : [...options.argv],
    cwd: options.cwd,
    env: options.env,
    timeout_s: options.timeoutS ?? DEFAULT_EXEC_TIMEOUT_S,
  });
}

export function execResultFromPayload(data: unknown): ExecResult {
  const what = "exec result";
  const raw = asRecord(data, what);
  return {
    exitCode: requiredNumber(raw, "exit_code", what),
    stdout: requiredString(raw, "stdout", what),
    stderr: requiredString(raw, "stderr", what),
    timedOut: requiredBoolean(raw, "timed_out", what),
    truncated: requiredBoolean(raw, "truncated", what),
    durationMs: requiredNumber(raw, "duration_ms", what),
  };
}

/** Process calls of one sandbox; `toolboxPath` is `/v1/sandboxes/{id}/toolbox`. */
export class Process {
  readonly #transport: Transport;
  readonly #basePath: string;

  constructor(transport: Transport, toolboxPath: string) {
    this.#transport = transport;
    this.#basePath = `${toolboxPath}/process`;
  }

  async exec(command: string | readonly string[], options: ExecOptions = {}): Promise<ExecResult> {
    const reply = await this.#transport.request("POST", `${this.#basePath}/execute`, {
      json: execBody(command, options),
      ...callArgs(options),
      minTimeoutMs: execRequestTimeoutMs(options),
    });
    return execResultFromPayload(reply);
  }

  async codeRun(
    language: CodeLanguage,
    code: string,
    options: CodeRunOptions = {},
  ): Promise<ExecResult> {
    const reply = await this.#transport.request("POST", `${this.#basePath}/code-run`, {
      json: codeRunBody(language, code, options),
      ...callArgs(options),
      minTimeoutMs: execRequestTimeoutMs(options),
    });
    return execResultFromPayload(reply);
  }
}
