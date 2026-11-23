import { ApiKeys } from "./api-keys.js";
import { Audit } from "./audit.js";
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
import { createBody, resolveMounts, type CreateFields, type VolumeMount } from "./create-body.js";
import { SandboxFailedError, SandboxTimeoutError, ValidationError } from "./errors.js";
import { BinaryChannel } from "./fs.js";
import {
  labelFilters,
  pageFromPayload,
  sandboxFromPayload,
  type FileEntry,
  type Page,
  type SandboxInfo,
} from "./models.js";
import { paginate, type Cursor } from "./pagination.js";
import {
  IDEMPOTENCY_HEADER,
  abortableSleep,
  callArgs,
  type CallOptions,
  type ResilienceOptions,
} from "./resilience.js";
import { Sandbox, SANDBOXES_PATH, sandboxPath } from "./sandbox.js";
import {
  SandboxOps,
  statEntry,
  type FollowCommandLogsOptions,
  type FollowLogEvent,
  type IsolationInfo,
  type MintPreviewTokenOptions,
  type PreviewToken,
  type ResizeSandboxOptions,
  type UpdateSandboxOptions,
} from "./sandbox-ops.js";
import {
  SnapshotTimeoutError,
  Snapshots,
  isSnapshotReady,
  type ListSnapshotsFilters,
  type ListSnapshotsOptions,
  type RegisterSnapshotOptions,
  type SnapshotInfo,
} from "./snapshots.js";
import type { SnapshotExportRequest } from "./snapshot-export.js";
import { statusFromPayload, type StatusInfo } from "./status.js";
import { Transport, type FetchLike, type Query } from "./transport.js";
import { Usage } from "./usage.js";
import { requireNonBlank, requirePositiveFinite } from "./validation.js";
import {
  Volumes,
  type ListVolumesFilters,
  type ListVolumesOptions,
  type VolumeCreateOptions,
  type VolumeInfo,
} from "./volumes.js";
import { Webhooks } from "./webhooks.js";

export const DEFAULT_WAIT_TIMEOUT_S = 120;
export const DEFAULT_POLL_INTERVAL_S = 0.5;
/** Upper bound for one server-side long poll, as in the python sdk (the server caps at 60). */
export const MAX_LONG_POLL_S = 30;

/** Added to a long poll's `timeout_s` to get the request timeout of that poll (as for exec). */
const LONG_POLL_REQUEST_MARGIN_MS = 10_000;
/** A long poll never outlasts the client's `deadlineMs` by design: it stops this early. */
const DEADLINE_MARGIN_S = 1;
export const STATUS_PATH = "/v1/status";
const STATE_STARTED = "started";
const UNREACHABLE_STATES: ReadonlySet<string> = new Set(["error", "destroying", "destroyed"]);

export interface SandfortClientOptions extends ResilienceOptions {
  baseUrl: string;
  apiKey: string;
  fetch?: FetchLike;
}

export interface CreateSandboxOptions extends CreateFields, CallOptions {
  /**
   * Sent as the `Idempotency-Key` header: repeating the call with the same key and arguments
   * returns the same sandbox instead of creating another. A keyed create is also resent
   * after a 429 or a 503 `CAPACITY` (see the `retries` client option); an unkeyed one never is.
   */
  idempotencyKey?: string;
  /** Volumes to mount (at most 16); a volume given by name is looked up first. */
  volumes?: readonly VolumeMount[];
  /** Poll until the sandbox is `started` (default true). */
  wait?: boolean;
  waitTimeoutS?: number;
  pollIntervalS?: number;
}

/** Why a sandbox stopped (`stop_cause` in the API). */
export type StopCause = "requested" | "auto_stop" | "container_exited" | "oom_killed" | "unknown";

export interface ListSandboxesOptions extends CallOptions {
  state?: string;
  /** Only sandboxes showing this stop cause. */
  stopCause?: StopCause;
  labels?: Record<string, string>;
  /** Include `destroyed` tombstones when no `state` filter is given (default false). */
  includeDestroyed?: boolean;
  /** Creation-time order, `"asc"` (default, oldest first) or `"desc"`. */
  order?: "asc" | "desc";
  /** A page's `nextCursor`, passed back as is (`null` and `undefined` start at the first page). */
  cursor?: Cursor;
  limit?: number;
}

/** Filters for `listSandboxesAll`: the same on every page, so no cursor. */
export type ListSandboxesFilters = Omit<ListSandboxesOptions, "cursor">;

export interface CreateSnapshotOptions extends CallOptions {
  /**
   * Poll `getSnapshot` until the snapshot is `ready` (default false: like the python sdk's
   * `create_from_sandbox`, the call returns the `pending` snapshot).
   */
  wait?: boolean;
  waitTimeoutS?: number;
  pollIntervalS?: number;
  /** Labels stored on the snapshot record (same bounds and rules as volume labels). */
  labels?: Record<string, string>;
}

function listQuery(options: ListSandboxesOptions): Query {
  return {
    state: options.state,
    cursor: options.cursor,
    limit: options.limit,
    label: labelFilters(options.labels),
    stop_cause: options.stopCause,
    include_destroyed: options.includeDestroyed,
    order: options.order,
  };
}

function isReady(info: SandboxInfo): boolean {
  if (info.state === STATE_STARTED) return true;
  if (UNREACHABLE_STATES.has(info.state)) {
    const reason = info.errorReason ? `: ${info.errorReason}` : "";
    throw new SandboxFailedError(`sandbox ${info.id} is ${info.state}${reason}`, info.id, info.state);
  }
  return false;
}

/** `waitTimeoutS` and `pollIntervalS`, when given, must be positive finite numbers. */
function checkWaitOptions(options: { waitTimeoutS?: number; pollIntervalS?: number }): void {
  if (options.waitTimeoutS !== undefined) requirePositiveFinite(options.waitTimeoutS, "waitTimeoutS");
  if (options.pollIntervalS !== undefined) requirePositiveFinite(options.pollIntervalS, "pollIntervalS");
}

function sleep(seconds: number, signal: AbortSignal | undefined): Promise<void> {
  return abortableSleep(seconds * 1000, signal);
}

interface Facades {
  webhooks?: Webhooks;
  apiKeys?: ApiKeys;
  audit?: Audit;
  usage?: Usage;
}

export class SandfortClient {
  private readonly transport: Transport;
  private readonly binary: BinaryChannel;
  private readonly snapshots: Snapshots;
  private readonly volumes: Volumes;
  private readonly deadlineMs: number | undefined;

  constructor(options: SandfortClientOptions) {
    this.transport = new Transport(options);
    this.binary = new BinaryChannel(options);
    this.snapshots = new Snapshots(this.transport);
    this.volumes = new Volumes(this.transport);
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

  async createSandbox(options: CreateSandboxOptions = {}): Promise<Sandbox> {
    const key = options.idempotencyKey;
    if (key !== undefined) requireNonBlank(key, "idempotencyKey");
    checkWaitOptions(options);
    const mounts = await resolveMounts(options.volumes ?? [], this.volumeLookup(options.signal));
    const reply = await this.transport.request("POST", SANDBOXES_PATH, {
      json: createBody(options, mounts),
      ...callArgs(options),
      ...(key === undefined ? {} : { headers: { [IDEMPOTENCY_HEADER]: key } }),
    });
    const info = sandboxFromPayload(reply);
    if (!(options.wait ?? true)) return this.handle(info);
    const started = await this.waitStarted(
      info,
      options.waitTimeoutS ?? DEFAULT_WAIT_TIMEOUT_S,
      options.pollIntervalS ?? DEFAULT_POLL_INTERVAL_S,
      options.signal,
    );
    return this.handle(started);
  }

  async getSandbox(sandboxId: string, call: CallOptions = {}): Promise<Sandbox> {
    return this.handle(await this.fetchSandbox(sandboxId, call));
  }

  async listSandboxes(options: ListSandboxesOptions = {}): Promise<Page<Sandbox>> {
    const reply = await this.transport.requestEnvelope("GET", SANDBOXES_PATH, {
      query: listQuery(options),
      ...callArgs(options),
    });
    return pageFromPayload(reply.data, reply.nextCursor, (item) =>
      this.handle(sandboxFromPayload(item)),
    );
  }

  /** Every sandbox matching `filters`, fetched page by page with the same filters each time. */
  listSandboxesAll(
    filters: ListSandboxesFilters = {},
  ): AsyncGenerator<Sandbox, void, undefined> {
    return paginate((cursor) => this.listSandboxes({ ...filters, cursor }));
  }

  deleteSandbox(sandboxId: string, call: CallOptions = {}): Promise<Sandbox> {
    return this.act("DELETE", sandboxPath(sandboxId), call);
  }

  startSandbox(sandboxId: string, call: CallOptions = {}): Promise<Sandbox> {
    return this.act("POST", sandboxPath(sandboxId, "/start"), call);
  }

  stopSandbox(sandboxId: string, call: CallOptions = {}): Promise<Sandbox> {
    return this.act("POST", sandboxPath(sandboxId, "/stop"), call);
  }

  /** Commit a sandbox into a snapshot named `name`; `wait` polls until it is `ready`. */
  async createSnapshot(
    sandboxId: string,
    name: string,
    options: CreateSnapshotOptions = {},
  ): Promise<SnapshotInfo> {
    checkWaitOptions(options);
    const info = await this.snapshots.createFromSandbox(sandboxId, name, options);
    if (!(options.wait ?? false)) return info;
    return this.waitSnapshotReady(
      info,
      options.waitTimeoutS ?? DEFAULT_WAIT_TIMEOUT_S,
      options.pollIntervalS ?? DEFAULT_POLL_INTERVAL_S,
      options.signal,
    );
  }

  /** Register a registry image reference as a snapshot (the server pulls it; answers `ready`). */
  registerSnapshot(image: string, options: RegisterSnapshotOptions = {}): Promise<SnapshotInfo> {
    return this.snapshots.register(image, options);
  }

  getSnapshot(snapshotId: string, call: CallOptions = {}): Promise<SnapshotInfo> {
    return this.snapshots.get(snapshotId, call);
  }

  listSnapshots(options: ListSnapshotsOptions = {}): Promise<Page<SnapshotInfo>> {
    return this.snapshots.list(options);
  }

  /** Every snapshot, fetched page by page. */
  listSnapshotsAll(
    filters: ListSnapshotsFilters = {},
  ): AsyncGenerator<SnapshotInfo, void, undefined> {
    return this.snapshots.listAll(filters);
  }

  /** The snapshot's `docker save` tar as chunks, without holding it in memory (409 unless `ready`). */
  exportSnapshotStream(
    snapshotId: string,
    call: SnapshotExportRequest = {},
  ): AsyncGenerator<Uint8Array, void, undefined> {
    return this.snapshots.exportStream(snapshotId, call);
  }

  /** The whole `docker save` tar in memory as one `Uint8Array`; use `exportSnapshotStream` for large ones. */
  exportSnapshotBytes(snapshotId: string, call: SnapshotExportRequest = {}): Promise<Uint8Array> {
    return this.snapshots.exportBytes(snapshotId, call);
  }

  deleteSnapshot(snapshotId: string, call: CallOptions = {}): Promise<SnapshotInfo> {
    return this.snapshots.delete(snapshotId, call);
  }

  /**
   * Resolves volume names against ONE listing: the first name lists every volume, the rest of
   * the same create call reuse that listing.
   */
  private volumeLookup(signal: AbortSignal | undefined): (name: string) => Promise<string> {
    let listing: Promise<ReadonlyMap<string, readonly string[]>> | undefined;
    return async (name) => {
      listing ??= this.volumeIdsByName(signal);
      const ids = (await listing).get(name) ?? [];
      const [only, ...rest] = ids;
      if (only === undefined) throw new ValidationError(`no volume named '${name}'`);
      if (rest.length > 0) throw new ValidationError(`more than one volume is named '${name}'`);
      return only;
    };
  }

  private async volumeIdsByName(
    signal: AbortSignal | undefined,
  ): Promise<ReadonlyMap<string, readonly string[]>> {
    const byName = new Map<string, string[]>();
    for await (const volume of this.volumes.listAll({ signal })) {
      byName.set(volume.name, [...(byName.get(volume.name) ?? []), volume.id]);
    }
    return byName;
  }

  /** Seconds the server may hold one poll: the wait left, capped, and inside any `deadlineMs`. */
  private longPollS(remainingS: number): number {
    const capped = Math.min(remainingS, MAX_LONG_POLL_S);
    if (this.deadlineMs === undefined) return capped;
    return Math.min(capped, Math.max(0, this.deadlineMs / 1000 - DEADLINE_MARGIN_S));
  }

  private codeContexts(sandboxId: string): CodeContexts {
    requireNonBlank(sandboxId, "sandboxId");
    return new CodeContexts(this.transport, sandboxPath(sandboxId, "/toolbox"));
  }

  private handle(info: SandboxInfo): Sandbox {
    return new Sandbox(info, this.transport, this.binary);
  }

  private async act(method: string, path: string, call: CallOptions): Promise<Sandbox> {
    const reply = await this.transport.request(method, path, { ...callArgs(call) });
    return this.handle(sandboxFromPayload(reply));
  }

  private async fetchSandbox(
    sandboxId: string,
    call: CallOptions,
    longPollS?: number,
  ): Promise<SandboxInfo> {
    const poll =
      longPollS === undefined
        ? {}
        : {
            query: { wait_for: STATE_STARTED, timeout_s: longPollS },
            // The request must outlive the server-side hold, whatever `timeoutMs` is.
            minTimeoutMs: Math.ceil(longPollS * 1000) + LONG_POLL_REQUEST_MARGIN_MS,
          };
    const path = sandboxPath(sandboxId);
    const reply = await this.transport.request("GET", path, { ...callArgs(call), ...poll });
    return sandboxFromPayload(reply);
  }

  private async waitStarted(
    initial: SandboxInfo,
    timeoutS: number,
    pollIntervalS: number,
    signal: AbortSignal | undefined,
  ): Promise<SandboxInfo> {
    const deadline = Date.now() + timeoutS * 1000;
    let info = initial;
    for (;;) {
      if (isReady(info)) return info;
      const remainingS = (deadline - Date.now()) / 1000;
      if (remainingS <= 0) {
        throw new SandboxTimeoutError(
          `sandbox ${info.id} still ${info.state} after the wait budget elapsed`,
        );
      }
      info = await this.fetchSandbox(info.id, { signal }, this.longPollS(remainingS));
      if (!isReady(info)) await sleep(pollIntervalS, signal);
    }
  }

  /** The snapshot route has no long poll, so this sleeps between plain reads. */
  private async waitSnapshotReady(
    initial: SnapshotInfo,
    timeoutS: number,
    pollIntervalS: number,
    signal: AbortSignal | undefined,
  ): Promise<SnapshotInfo> {
    const deadline = Date.now() + timeoutS * 1000;
    let info = initial;
    for (;;) {
      if (isSnapshotReady(info)) return info;
      const remainingS = (deadline - Date.now()) / 1000;
      if (remainingS <= 0) {
        throw new SnapshotTimeoutError(
          `snapshot ${info.id} still ${info.state} after the wait budget elapsed`,
          info.id,
        );
      }
      await sleep(Math.min(pollIntervalS, remainingS), signal);
      info = await this.snapshots.get(info.id, { signal });
    }
  }

  // --- sandbox operations (src/sandbox-ops.ts) -----------------------------------------------

  /** PATCH a sandbox: labels, auto-stop / auto-delete minutes, `public`. */
  updateSandbox(sandboxId: string, options: UpdateSandboxOptions): Promise<Sandbox> {
    return this.sandboxOps().update(sandboxId, options);
  }

  /** Replace the container with a fresh one; id, labels, volumes and timers are kept. */
  resetSandbox(sandboxId: string, call: CallOptions = {}): Promise<Sandbox> {
    return this.sandboxOps().reset(sandboxId, call);
  }

  /** Change the resources of a stopped sandbox (any other state answers 409). */
  resizeSandbox(sandboxId: string, options: ResizeSandboxOptions): Promise<Sandbox> {
    return this.sandboxOps().resize(sandboxId, options);
  }

  /** The isolation tiers this deployment offers and the default a create gets. */
  listIsolation(call: CallOptions = {}): Promise<IsolationInfo> {
    return this.sandboxOps().listIsolation(call);
  }

  mintPreviewToken(sandboxId: string, options: MintPreviewTokenOptions): Promise<PreviewToken> {
    return this.sandboxOps().mintPreviewToken(sandboxId, options);
  }

  /** The entry of a path inside a sandbox (file, directory or symlink). */
  statPath(sandboxId: string, path: string, call: CallOptions = {}): Promise<FileEntry> {
    requireNonBlank(sandboxId, "sandboxId");
    return statEntry(this.transport, sandboxPath(sandboxId, "/toolbox"), path, call);
  }

  /** Iterate the output of a command as it is written; the last event is `exit`. */
  followCommandLogs(
    sandboxId: string,
    sessionId: string,
    commandId: string,
    options: FollowCommandLogsOptions = {},
  ): AsyncGenerator<FollowLogEvent, void, undefined> {
    return this.sandboxOps().followCommandLogs(sandboxId, sessionId, commandId, options);
  }

  private sandboxOps(): SandboxOps {
    return new SandboxOps(this.transport, (info) => this.handle(info));
  }
}
