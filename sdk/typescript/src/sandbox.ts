import {
  CodeContexts,
  type CellResult,
  type CodeContextEvent,
  type CodeContextInfo,
  type CreateCodeContextOptions,
  type EnsureCodeContextOptions,
  type EnsureCodeContextResult,
  type ListCodeContextsOptions,
  type RunInCodeContextOptions,
} from "./contexts.js";
import type { BinaryChannel } from "./fs.js";
import { Fs } from "./fs.js";
import { Git } from "./git.js";
import type { SandboxErrorCode } from "./error-codes.js";
import type { Resources, SandboxInfo, VolumeMountInfo } from "./models.js";
import {
  Process,
  type CodeLanguage,
  type CodeRunOptions,
  type ExecOptions,
  type ExecResult,
} from "./process.js";
import {
  Sessions,
  type CommandInfo,
  type CommandLogsOptions,
  type CreateSessionOptions,
  type LogPage,
  type RunInSessionOptions,
  type SessionInfo,
} from "./sessions.js";
import {
  SandboxOps,
  type FollowCommandLogsOptions,
  type FollowLogEvent,
  type IsolationInfo,
  type MintPreviewTokenOptions,
  type PreviewToken,
  type ResizeSandboxOptions,
  type UpdateSandboxOptions,
} from "./sandbox-ops.js";
import type { CallOptions } from "./resilience.js";
import type { Transport } from "./transport.js";

export const SANDBOXES_PATH = "/v1/sandboxes";

export function sandboxPath(sandboxId: string, suffix = ""): string {
  return `${SANDBOXES_PATH}/${encodeURIComponent(sandboxId)}${suffix}`;
}

/**
 * A sandbox record plus its toolboxes (python: `sandfort_sdk.sandbox.Sandbox`). The record
 * fields are the only own enumerable properties, so the handle compares and serializes as
 * its `SandboxInfo`; `fs` and the process calls live on the prototype.
 */
export class Sandbox implements SandboxInfo {
  readonly id: string;
  readonly name: string;
  readonly state: string;
  readonly resources: Resources;
  readonly env: Record<string, string>;
  readonly labels: Record<string, string>;
  readonly blockNetwork: boolean;
  readonly "public": boolean;
  readonly autoStopMinutes: number;
  readonly autoDeleteMinutes: number;
  readonly errorReason: string | null;
  readonly errorCode: SandboxErrorCode | (string & {}) | null;
  readonly jobId: string | null;
  readonly createdAt?: Date | null | undefined;
  readonly updatedAt?: Date | null | undefined;
  readonly stopCause?: string | null | undefined;
  readonly stoppedAt?: Date | null | undefined;
  readonly isolation?: string | undefined;
  readonly volumes?: readonly VolumeMountInfo[] | undefined;
  readonly egressAllowlist?: readonly string[] | null | undefined;
  readonly egressPolicyGeneration: number;
  readonly #process: Process;
  readonly #fs: Fs;
  readonly #sessions: Sessions;
  readonly #git: Git;
  readonly #contexts: CodeContexts;
  readonly #ops: SandboxOps;

  constructor(info: SandboxInfo, transport: Transport, binary: BinaryChannel) {
    this.id = info.id;
    this.name = info.name;
    this.state = info.state;
    this.resources = info.resources;
    this.env = info.env;
    this.labels = info.labels;
    this.blockNetwork = info.blockNetwork;
    this.public = info.public;
    this.autoStopMinutes = info.autoStopMinutes;
    this.autoDeleteMinutes = info.autoDeleteMinutes;
    this.errorReason = info.errorReason;
    this.errorCode = info.errorCode;
    this.jobId = info.jobId;
    this.createdAt = info.createdAt;
    this.updatedAt = info.updatedAt;
    this.stopCause = info.stopCause;
    this.stoppedAt = info.stoppedAt;
    this.isolation = info.isolation;
    this.volumes = info.volumes;
    this.egressAllowlist = info.egressAllowlist;
    this.egressPolicyGeneration = info.egressPolicyGeneration;
    const toolboxPath = sandboxPath(info.id, "/toolbox");
    this.#process = new Process(transport, toolboxPath);
    this.#fs = new Fs(transport, binary, toolboxPath);
    this.#sessions = new Sessions(transport, toolboxPath);
    this.#git = new Git(transport, toolboxPath);
    this.#contexts = new CodeContexts(transport, toolboxPath);
    this.#ops = new SandboxOps(transport, (next) => new Sandbox(next, transport, binary));
  }

  /** Git toolbox: `clone`, `status`, `add`, `commit`, `push`, `pull` (credential per call). */
  get git(): Git {
    return this.#git;
  }

  createSession(options: CreateSessionOptions = {}): Promise<SessionInfo> {
    return this.#sessions.createSession(options);
  }

  listSessions(call: CallOptions = {}): Promise<readonly SessionInfo[]> {
    return this.#sessions.listSessions(call);
  }

  getSession(sessionId: string, call: CallOptions = {}): Promise<SessionInfo> {
    return this.#sessions.getSession(sessionId, call);
  }

  /** Run a command in a session and wait for its exec result. */
  runInSession(
    sessionId: string,
    command: string,
    options: RunInSessionOptions = {},
  ): Promise<ExecResult> {
    return this.#sessions.runInSession(sessionId, command, options);
  }

  /** Start an async command; poll with `getCommand` / `getCommandLogs`. */
  startCommand(
    sessionId: string,
    command: string,
    options: RunInSessionOptions = {},
  ): Promise<CommandInfo> {
    return this.#sessions.startCommand(sessionId, command, options);
  }

  getCommand(sessionId: string, commandId: string, call: CallOptions = {}): Promise<CommandInfo> {
    return this.#sessions.getCommand(sessionId, commandId, call);
  }

  getCommandLogs(
    sessionId: string,
    commandId: string,
    options: CommandLogsOptions = {},
  ): Promise<LogPage> {
    return this.#sessions.getCommandLogs(sessionId, commandId, options);
  }

  killCommand(sessionId: string, commandId: string, call: CallOptions = {}): Promise<CommandInfo> {
    return this.#sessions.killCommand(sessionId, commandId, call);
  }

  /** Filesystem toolbox: `listDir`, `mkdir`, `move`, `remove`, `uploadFile`, `downloadFile`. */
  get fs(): Fs {
    return this.#fs;
  }

  /** Run a shell command string, or an argv array without a shell. */
  processExec(command: string | readonly string[], options: ExecOptions = {}): Promise<ExecResult> {
    return this.#process.exec(command, options);
  }

  codeRun(language: CodeLanguage, code: string, options: CodeRunOptions = {}): Promise<ExecResult> {
    return this.#process.codeRun(language, code, options);
  }

  /**
   * Start a stateful Python kernel. With a `name` the answer is `{ context, created }` like
   * `ensureCodeContext` (a live context of that name is returned instead of a new one, and
   * `created` says which), matching the Python SDK; without a name it is the new context
   * itself. The two shapes are told apart by `name` in the overloads below.
   */
  createCodeContext(
    options: CreateCodeContextOptions & { name: string },
  ): Promise<EnsureCodeContextResult>;
  createCodeContext(
    options?: CreateCodeContextOptions & { name?: undefined },
  ): Promise<CodeContextInfo>;
  createCodeContext(
    options: CreateCodeContextOptions,
  ): Promise<CodeContextInfo | EnsureCodeContextResult>;
  async createCodeContext(
    options: CreateCodeContextOptions = {},
  ): Promise<CodeContextInfo | EnsureCodeContextResult> {
    const result = await this.#contexts.createWithStatus(options);
    return options.name === undefined ? result.context : result;
  }

  listCodeContexts(options: ListCodeContextsOptions = {}): Promise<readonly CodeContextInfo[]> {
    return this.#contexts.list(options);
  }

  /** The live context named `name` or a new one; `created` tells which (state is not restored). */
  ensureCodeContext(
    name: string,
    options: EnsureCodeContextOptions = {},
  ): Promise<EnsureCodeContextResult> {
    return this.#contexts.ensure(name, options);
  }

  /** Run a cell in a context; variables and imports of earlier runs are visible to it. */
  runInCodeContext(
    contextId: string,
    code: string,
    options: RunInCodeContextOptions = {},
  ): Promise<CellResult> {
    return this.#contexts.run(contextId, code, options);
  }

  /** Run a cell and iterate its output as it is written; the last event is the result. */
  streamCodeContextRun(
    contextId: string,
    code: string,
    options: RunInCodeContextOptions = {},
  ): AsyncGenerator<CodeContextEvent, void, undefined> {
    return this.#contexts.streamRun(contextId, code, options);
  }

  /** Interrupt the running cell; `false` when the context has no live kernel. */
  interruptCodeContext(contextId: string, call: CallOptions = {}): Promise<boolean> {
    return this.#contexts.interrupt(contextId, call);
  }

  /** Kill the kernel of a context; its state is gone. */
  deleteCodeContext(contextId: string, call: CallOptions = {}): Promise<void> {
    return this.#contexts.delete(contextId, call);
  }

  // --- sandbox operations (src/sandbox-ops.ts); each returns a new handle -------------------

  /**
   * PATCH this sandbox: labels, auto-stop / auto-delete minutes, `public`, and the
   * `egressAllowlist` (host names, leading-dot domains and CIDR ranges).
   */
  update(options: UpdateSandboxOptions): Promise<Sandbox> {
    return this.#ops.update(this.id, options);
  }

  /** Replace the container with a fresh one; id, labels, volumes and timers are kept. */
  reset(call: CallOptions = {}): Promise<Sandbox> {
    return this.#ops.reset(this.id, call);
  }

  /** Change the resources of this sandbox; it must be stopped (otherwise 409). */
  resize(options: ResizeSandboxOptions): Promise<Sandbox> {
    return this.#ops.resize(this.id, options);
  }

  listIsolation(call: CallOptions = {}): Promise<IsolationInfo> {
    return this.#ops.listIsolation(call);
  }

  mintPreviewToken(options: MintPreviewTokenOptions): Promise<PreviewToken> {
    return this.#ops.mintPreviewToken(this.id, options);
  }

  /** Iterate the output of a command as it is written; the last event is `exit`. */
  followCommandLogs(
    sessionId: string,
    commandId: string,
    options: FollowCommandLogsOptions = {},
  ): AsyncGenerator<FollowLogEvent, void, undefined> {
    return this.#ops.followCommandLogs(this.id, sessionId, commandId, options);
  }
}
