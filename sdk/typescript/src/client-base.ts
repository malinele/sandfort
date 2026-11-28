/**
 * The part of `SandfortClient` that does not build `Sandbox` handles: the REST facades, volumes,
 * code contexts, terminals and the status route. `SandfortClient` (client.ts) extends it with
 * the sandbox, snapshot and sandbox-operation calls; this class is not exported by the package.
 */

import { ApiKeys } from "./api-keys.js";
import { Audit } from "./audit.js";
import type { SandfortClientOptions } from "./client-options.js";
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
import { BinaryChannel } from "./fs.js";
import { warnIfInsecureBaseUrl } from "./insecure-url.js";
import type { Page } from "./models.js";
import {
  PtyChannel,
  type CreatePtyOptions,
  type PtyConnectToken,
  type PtyInfo,
  type PtySession,
} from "./pty.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { sandboxPath } from "./sandbox.js";
import { Snapshots } from "./snapshots.js";
import { STATUS_PATH, statusFromPayload, type StatusInfo } from "./status.js";
import { Transport } from "./transport.js";
import { Usage } from "./usage.js";
import { requireNonBlank } from "./validation.js";
import {
  Volumes,
  type ListVolumesFilters,
  type ListVolumesOptions,
  type VolumeCreateOptions,
  type VolumeInfo,
} from "./volumes.js";
import { Webhooks } from "./webhooks.js";

interface Facades {
  webhooks?: Webhooks;
  apiKeys?: ApiKeys;
  audit?: Audit;
  usage?: Usage;
}

export abstract class ClientBase {
  protected readonly transport: Transport;
  protected readonly binary: BinaryChannel;
  protected readonly snapshots: Snapshots;
  protected readonly volumes: Volumes;
  protected readonly ptys: PtyChannel;
  protected readonly deadlineMs: number | undefined;

  constructor(options: SandfortClientOptions) {
    this.transport = new Transport(options);
    warnIfInsecureBaseUrl(options.baseUrl);
    this.binary = new BinaryChannel(options);
    this.snapshots = new Snapshots(this.transport);
    this.volumes = new Volumes(this.transport);
    this.ptys = new PtyChannel(this.transport, options.baseUrl, options.webSocket);
    this.deadlineMs = options.deadlineMs;
  }

  // The REST facades, created on first use and then kept. Kept together, right after the
  // constructor, so that new facades land in one place.
  private readonly facades: Facades = {};

  /** Webhook endpoints and their delivery history (`webhooks:write`). */
  get webhooks(): Webhooks {
    return (this.facades.webhooks ??= new Webhooks(this.transport));
  }

  /** API key administration (`api_keys:admin`). */
  get apiKeys(): ApiKeys {
    return (this.facades.apiKeys ??= new ApiKeys(this.transport));
  }

  /** Audit events: list, hash chain verification and export. */
  get audit(): Audit {
    return (this.facades.audit ??= new Audit(this.transport));
  }

  /** Metered usage of the org for a period. */
  get usage(): Usage {
    return (this.facades.usage ??= new Usage(this.transport));
  }

  /** Create a volume; `options.labels` are stored on it and `listVolumes({ labels })` filters. */
  createVolume(name: string, options: VolumeCreateOptions = {}): Promise<VolumeInfo> {
    return this.volumes.create(name, options);
  }

  getVolume(volumeId: string, call: CallOptions = {}): Promise<VolumeInfo> {
    return this.volumes.get(volumeId, call);
  }

  listVolumes(options: ListVolumesOptions = {}): Promise<Page<VolumeInfo>> {
    return this.volumes.list(options);
  }

  /** Every volume matching `filters`, fetched page by page. */
  listVolumesAll(filters: ListVolumesFilters = {}): AsyncGenerator<VolumeInfo, void, undefined> {
    return this.volumes.listAll(filters);
  }

  /** Delete a volume; the server answers 409 (`Conflict`) while a sandbox mounts it. */
  deleteVolume(volumeId: string, call: CallOptions = {}): Promise<VolumeInfo> {
    return this.volumes.delete(volumeId, call);
  }

  /**
   * Start a stateful Python kernel in a started sandbox. With a `name` the answer is
   * `{ context, created }` (a live context of that name is returned instead of a new one,
   * and `created` says which); without a name it is the new context itself.
   */
  createCodeContext(
    sandboxId: string,
    options: CreateCodeContextOptions & { name: string },
  ): Promise<EnsureCodeContextResult>;
  createCodeContext(
    sandboxId: string,
    options?: CreateCodeContextOptions & { name?: undefined },
  ): Promise<CodeContextInfo>;
  createCodeContext(
    sandboxId: string,
    options: CreateCodeContextOptions,
  ): Promise<CodeContextInfo | EnsureCodeContextResult>;
  async createCodeContext(
    sandboxId: string,
    options: CreateCodeContextOptions = {},
  ): Promise<CodeContextInfo | EnsureCodeContextResult> {
    const result = await this.codeContexts(sandboxId).createWithStatus(options);
    return options.name === undefined ? result.context : result;
  }

  async listCodeContexts(
    sandboxId: string,
    options: ListCodeContextsOptions = {},
  ): Promise<readonly CodeContextInfo[]> {
    return this.codeContexts(sandboxId).list(options);
  }

  /** The live context named `name` or a new one; `created` is true for a new, empty one. */
  async ensureCodeContext(
    sandboxId: string,
    name: string,
    options: EnsureCodeContextOptions = {},
  ): Promise<EnsureCodeContextResult> {
    return this.codeContexts(sandboxId).ensure(name, options);
  }

  /** Run a cell in a context; the variables of earlier runs are visible to it. */
  async runInCodeContext(
    sandboxId: string,
    contextId: string,
    code: string,
    options: RunInCodeContextOptions = {},
  ): Promise<CellResult> {
    return this.codeContexts(sandboxId).run(contextId, code, options);
  }

  /** Run a cell and iterate its output as it is written; the last event is the result. */
  streamCodeContextRun(
    sandboxId: string,
    contextId: string,
    code: string,
    options: RunInCodeContextOptions = {},
  ): AsyncGenerator<CodeContextEvent, void, undefined> {
    return this.codeContexts(sandboxId).streamRun(contextId, code, options);
  }

  /** Interrupt the running cell; `false` when the context has no live kernel. */
  async interruptCodeContext(
    sandboxId: string,
    contextId: string,
    call: CallOptions = {},
  ): Promise<boolean> {
    return this.codeContexts(sandboxId).interrupt(contextId, call);
  }

  /** Kill the kernel of a context; its state is gone. */
  async deleteCodeContext(
    sandboxId: string,
    contextId: string,
    call: CallOptions = {},
  ): Promise<void> {
    return this.codeContexts(sandboxId).delete(contextId, call);
  }

  /** Version, build and operator notice of the server (the route needs no valid key). */
  async status(call: CallOptions = {}): Promise<StatusInfo> {
    return statusFromPayload(
      await this.transport.request("GET", STATUS_PATH, { ...callArgs(call) }),
    );
  }

  private codeContexts(sandboxId: string): CodeContexts {
    requireNonBlank(sandboxId, "sandboxId");
    return new CodeContexts(this.transport, sandboxPath(sandboxId, "/toolbox"));
  }

  /** Create a pty without attaching; the token is single-use and expires in 60 s. */
  createPty(sandboxId: string, options: CreatePtyOptions = {}): Promise<PtyConnectToken> {
    return this.ptys.create(sandboxId, options);
  }

  /** Create a pty and attach to it over a WebSocket. */
  connectPty(sandboxId: string, options: CreatePtyOptions = {}): Promise<PtySession> {
    return this.ptys.connect(sandboxId, options);
  }

  listPtys(sandboxId: string, call: CallOptions = {}): Promise<PtyInfo[]> {
    return this.ptys.list(sandboxId, call);
  }

  getPty(sandboxId: string, ptyId: string, call: CallOptions = {}): Promise<PtyInfo> {
    return this.ptys.get(sandboxId, ptyId, call);
  }

  /** Resize a terminal (REST; nothing rides the WebSocket but terminal bytes). */
  resizePty(
    sandboxId: string,
    ptyId: string,
    rows: number,
    cols: number,
    call: CallOptions = {},
  ): Promise<PtyInfo> {
    return this.ptys.resize(sandboxId, ptyId, rows, cols, call);
  }

  /** Kill and detach the terminal process and close its record. */
  deletePty(sandboxId: string, ptyId: string, call: CallOptions = {}): Promise<PtyInfo> {
    return this.ptys.delete(sandboxId, ptyId, call);
  }
}
