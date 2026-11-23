/** Snapshot calls (create-from-sandbox, get, list, delete), mirroring `sandfort_sdk.snapshots`. */

import { SandfortError, ValidationError } from "./errors.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { paginate, type Cursor } from "./pagination.js";
import {
  asRecord,
  pageFromPayload,
  requiredNumber,
  requiredString,
  requiredTimestamp,
  stringOrNull,
  type Page,
} from "./models.js";
import { concatChunks, exportTar, type SnapshotExportRequest } from "./snapshot-export.js";
import type { Transport } from "./transport.js";
import { checkLabels, optionalLabels } from "./volumes.js";

export const SNAPSHOTS_PATH = "/v1/snapshots";
export const SNAPSHOT_FROM_SANDBOX_PATH = `${SNAPSHOTS_PATH}/from-sandbox`;
export const SNAPSHOT_STATE_READY = "ready";
/** States a pending snapshot never leaves for `ready`. */
const UNREACHABLE_STATES: ReadonlySet<string> = new Set(["error", "deleting"]);

/** A snapshot; `specHash` and `reused` are only set by image builds. */
export interface SnapshotInfo {
  id: string;
  name: string;
  /** `"pending"`, `"ready"`, `"error"` or `"deleting"`. */
  state: string;
  imageRef: string;
  layerCount: number;
  createdAt: Date;
  digest: string | null;
  sourceSandboxId: string | null;
  specHash: string | null;
  reused: boolean;
  /** Labels stored on the snapshot record (`{}` when the server sends none). */
  labels: Record<string, string>;
  /** Isolation tier recorded on the snapshot, or `null` when the server sends none. */
  isolation: string | null;
}

/** Options of `createFromSandbox`: the per-call fields plus optional snapshot labels. */
export interface CreateFromSandboxOptions extends CallOptions {
  /** Labels stored on the snapshot record (same bounds and rules as volume labels). */
  labels?: Record<string, string>;
}

export interface ListSnapshotsOptions extends CallOptions {
  /** A page's `nextCursor`, passed back as is (`null` and `undefined` start at the first page). */
  cursor?: Cursor;
  limit?: number;
}

/** Filters for `listSnapshotsAll`: the same on every page, so no cursor. */
export type ListSnapshotsFilters = Omit<ListSnapshotsOptions, "cursor">;

/** The snapshot settled in a state that can never become `ready`. */
export class SnapshotFailedError extends SandfortError {
  readonly snapshotId: string;
  readonly state: string;

  constructor(message: string, snapshotId: string, state: string) {
    super(message);
    this.snapshotId = snapshotId;
    this.state = state;
  }
}

/** The wait loop's message: `snapshot <id> still <state> after ...`. */
const TIMEOUT_MESSAGE_ID = /^snapshot (\S+) still /;

/**
 * The snapshot did not reach `ready` within the wait budget. `snapshotId` is the second
 * argument; when a caller omits it, it is read from the wait loop's own message.
 */
export class SnapshotTimeoutError extends SandfortError {
  readonly snapshotId: string;

  constructor(message: string, snapshotId?: string) {
    super(message);
    this.snapshotId = snapshotId ?? TIMEOUT_MESSAGE_ID.exec(message)?.[1] ?? "";
  }
}

export function snapshotFromPayload(data: unknown): SnapshotInfo {
  const what = "snapshot";
  const raw = asRecord(data, what);
  return {
    id: requiredString(raw, "id", what),
    name: requiredString(raw, "name", what),
    state: requiredString(raw, "state", what),
    imageRef: requiredString(raw, "image_ref", what),
    layerCount: requiredNumber(raw, "layer_count", what),
    createdAt: requiredTimestamp(raw["created_at"], what),
    digest: stringOrNull(raw["digest"]),
    sourceSandboxId: stringOrNull(raw["source_sandbox_id"]),
    specHash: stringOrNull(raw["spec_hash"]),
    reused: raw["reused"] === true,
    labels: optionalLabels(raw["labels"]) ?? {},
    isolation: stringOrNull(raw["isolation"]),
  };
}

/** True once ready; throws `SnapshotFailedError` if the snapshot can never become ready. */
export function isSnapshotReady(info: SnapshotInfo): boolean {
  if (info.state === SNAPSHOT_STATE_READY) return true;
  if (UNREACHABLE_STATES.has(info.state)) {
    throw new SnapshotFailedError(`snapshot ${info.id} is ${info.state}`, info.id, info.state);
  }
  return false;
}

/**
 * Wire body for `POST /v1/snapshots/from-sandbox`; `sandboxId` and `name` are required and
 * non-blank, `labels` (volume-label bounds) are sent only when given.
 */
export function snapshotFromSandboxBody(
  sandboxId: string,
  name: string,
  labels?: Readonly<Record<string, string>>,
): Record<string, unknown> {
  if (sandboxId.trim() === "" || name.trim() === "") {
    throw new ValidationError("'sandboxId' and 'name' must not be empty");
  }
  if (labels === undefined) return { sandbox_id: sandboxId, name };
  checkLabels(labels);
  return { sandbox_id: sandboxId, name, labels: { ...labels } };
}

/** Options of `registerSnapshot`: a server-side name and labels, both optional. */
export interface RegisterSnapshotOptions extends CallOptions {
  name?: string;
  labels?: Readonly<Record<string, string>>;
}

/**
 * Wire body for `POST /v1/snapshots` (registration); `image` is required and non-blank,
 * `name` and `labels` (volume-label bounds) are sent only when given.
 */
export function snapshotRegisterBody(
  image: string,
  name?: string,
  labels?: Readonly<Record<string, string>>,
): Record<string, unknown> {
  if (image.trim() === "") {
    throw new ValidationError("'image' must not be empty");
  }
  const named = name === undefined ? { image } : { image, name };
  if (labels === undefined) return named;
  checkLabels(labels);
  return { ...named, labels: { ...labels } };
}

function snapshotPath(snapshotId: string): string {
  return `${SNAPSHOTS_PATH}/${encodeURIComponent(snapshotId)}`;
}

export class Snapshots {
  readonly #transport: Transport;

  constructor(transport: Transport) {
    this.#transport = transport;
  }

  /** Register a registry image reference (the server pulls it and answers `ready`). */
  async register(image: string, call: RegisterSnapshotOptions = {}): Promise<SnapshotInfo> {
    const body = snapshotRegisterBody(image, call.name, call.labels);
    const reply = await this.#transport.request("POST", SNAPSHOTS_PATH, {
      json: body,
      ...callArgs(call),
    });
    return snapshotFromPayload(reply);
  }

  /** Commit a sandbox into a new snapshot (the server answers `pending`). */
  async createFromSandbox(
    sandboxId: string,
    name: string,
    call: CreateFromSandboxOptions = {},
  ): Promise<SnapshotInfo> {
    const body = snapshotFromSandboxBody(sandboxId, name, call.labels);
    const reply = await this.#transport.request("POST", SNAPSHOT_FROM_SANDBOX_PATH, {
      json: body,
      ...callArgs(call),
    });
    return snapshotFromPayload(reply);
  }

  async get(snapshotId: string, call: CallOptions = {}): Promise<SnapshotInfo> {
    const reply = await this.#transport.request("GET", snapshotPath(snapshotId), {
      ...callArgs(call),
    });
    return snapshotFromPayload(reply);
  }

  async list(options: ListSnapshotsOptions = {}): Promise<Page<SnapshotInfo>> {
    const reply = await this.#transport.requestEnvelope("GET", SNAPSHOTS_PATH, {
      query: { cursor: options.cursor, limit: options.limit },
      ...callArgs(options),
    });
    return pageFromPayload(reply.data, reply.nextCursor, snapshotFromPayload);
  }

  /** Every snapshot, fetched page by page. */
  listAll(filters: ListSnapshotsFilters = {}): AsyncGenerator<SnapshotInfo, void, undefined> {
    return paginate((cursor) => this.list({ ...filters, cursor }));
  }

  /**
   * The snapshot's `docker save` tar as it arrives, chunk by chunk, without holding it in
   * memory. The server answers 409 (`InvalidState`) unless the snapshot is `ready`; a blank
   * `snapshotId` is a `ValidationError` raised on the first read, before anything is sent.
   */
  exportStream(
    snapshotId: string,
    call: SnapshotExportRequest = {},
  ): AsyncGenerator<Uint8Array, void, undefined> {
    return exportTar(this.#transport, snapshotId, call);
  }

  /**
   * The whole `docker save` tar as one `Uint8Array`. The entire tar is held in memory, so use
   * `exportStream` for a large snapshot and write the chunks out as they arrive.
   */
  async exportBytes(snapshotId: string, call: SnapshotExportRequest = {}): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    for await (const chunk of this.exportStream(snapshotId, call)) chunks.push(chunk);
    return concatChunks(chunks);
  }

  /** Delete a snapshot; the server answers 409 (`Conflict`) while a sandbox uses it. */
  async delete(snapshotId: string, call: CallOptions = {}): Promise<SnapshotInfo> {
    const reply = await this.#transport.request("DELETE", snapshotPath(snapshotId), {
      ...callArgs(call),
    });
    return snapshotFromPayload(reply);
  }
}
