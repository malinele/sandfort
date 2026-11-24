import {
  DEFAULT_POLL_INTERVAL_S,
  DEFAULT_WAIT_TIMEOUT_S,
  checkWaitOptions,
  listQuery,
  type CreateSandboxOptions,
  type CreateSnapshotOptions,
  type ListSandboxesFilters,
  type ListSandboxesOptions,
} from "./client-options.js";
import { ClientBase } from "./client-base.js";
import { createSandboxInfo } from "./client-create.js";
import { fetchSandbox, waitSnapshotReady } from "./client-waits.js";
import {
  pageFromPayload,
  sandboxFromPayload,
  type FileEntry,
  type Page,
  type SandboxInfo,
} from "./models.js";
import { paginate } from "./pagination.js";
import { callArgs, type CallOptions } from "./resilience.js";
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
import type {
  ListSnapshotsFilters,
  ListSnapshotsOptions,
  RegisterSnapshotOptions,
  SnapshotInfo,
} from "./snapshots.js";
import type { SnapshotExportRequest } from "./snapshot-export.js";
import type { BuildLogEvent, BuildSnapshotOptions, ImageSpecInput } from "./image-builds.js";
import type { Image } from "./image.js";
import { requireNonBlank } from "./validation.js";

/** The client: sandbox and snapshot calls here, the rest (facades, volumes, ...) in `ClientBase`. */
export class SandfortClient extends ClientBase {
  async createSandbox(options: CreateSandboxOptions = {}): Promise<Sandbox> {
    const info = await createSandboxInfo(this.transport, this.volumes, this.deadlineMs, options);
    return this.handle(info);
  }

  async getSandbox(sandboxId: string, call: CallOptions = {}): Promise<Sandbox> {
    return this.handle(await fetchSandbox(this.transport, sandboxId, call));
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
    return waitSnapshotReady(
      this.snapshots,
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

  /**
   * Start a declarative image build from an `Image` (or a raw wire-form spec): `pending` while
   * it builds, `ready` with `reused` true when an identical spec was built before.
   */
  buildSnapshot(
    spec: Image | ImageSpecInput,
    options: BuildSnapshotOptions = {},
  ): Promise<SnapshotInfo> {
    return this.snapshots.build(spec, options);
  }

  /** The build log as events: `log` lines, then one final `state` event that ends the stream. */
  followBuildLogs(
    snapshotId: string,
    call: CallOptions = {},
  ): AsyncGenerator<BuildLogEvent, void, undefined> {
    return this.snapshots.followBuildLogs(snapshotId, call);
  }

  deleteSnapshot(snapshotId: string, call: CallOptions = {}): Promise<SnapshotInfo> {
    return this.snapshots.delete(snapshotId, call);
  }

  private handle(info: SandboxInfo): Sandbox {
    return new Sandbox(info, this.transport, this.binary);
  }

  private async act(method: string, path: string, call: CallOptions): Promise<Sandbox> {
    const reply = await this.transport.request(method, path, { ...callArgs(call) });
    return this.handle(sandboxFromPayload(reply));
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
