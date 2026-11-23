/** Volume calls (create, list, get, delete), mirroring `sandfort_sdk.volumes.Volumes`. */

import { ValidationError } from "./errors.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { paginate, type Cursor } from "./pagination.js";
import {
  asRecord,
  labelFilters,
  pageFromPayload,
  requiredString,
  requiredTimestamp,
  type Page,
} from "./models.js";
import type { Transport } from "./transport.js";

export const VOLUMES_PATH = "/v1/volumes";

export interface VolumeInfo {
  id: string;
  name: string;
  /** `"ready"` or `"deleting"`. */
  state: string;
  createdAt: Date;
  /** Last sampled size; `null` until first sampled. */
  sizeBytes: number | null;
  /** Labels on the volume; `undefined` when an older server omits them. */
  labels?: Record<string, string> | undefined;
  /** Soft size limit in bytes; `null` when unlimited, `undefined` on an older server. */
  maxBytes?: number | null | undefined;
  /** True when the sampled size exceeds the limit (a read-write mount is then refused). */
  overLimit?: boolean | undefined;
}

export interface ListVolumesOptions extends CallOptions {
  /** Only volumes carrying every one of these labels. */
  labels?: Record<string, string>;
  /** A page's `nextCursor`, passed back as is (`null` and `undefined` start at the first page). */
  cursor?: Cursor;
  limit?: number;
}

/** Filters for `listVolumesAll`: the same on every page, so no cursor. */
export type ListVolumesFilters = Omit<ListVolumesOptions, "cursor">;

export function volumeFromPayload(data: unknown): VolumeInfo {
  const what = "volume";
  const raw = asRecord(data, what);
  const size = raw["size_bytes"];
  return {
    id: requiredString(raw, "id", what),
    name: requiredString(raw, "name", what),
    state: requiredString(raw, "state", what),
    createdAt: requiredTimestamp(raw["created_at"], what),
    sizeBytes: typeof size === "number" ? size : null,
    labels: optionalLabels(raw["labels"]),
    maxBytes: raw["max_bytes"] === undefined ? undefined : numberOrNull(raw["max_bytes"]),
    overLimit: typeof raw["over_limit"] === "boolean" ? raw["over_limit"] : undefined,
  };
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" ? value : null;
}

export function optionalLabels(value: unknown): Record<string, string> | undefined {
  if (value === undefined || value === null) return undefined;
  const raw = asRecord(value, "volume labels");
  return Object.fromEntries(Object.entries(raw).map(([key, item]) => [key, String(item)]));
}

/** Bounds of `CreateVolumeRequest.labels` in the OpenAPI spec (same as sandbox labels). */
const MAX_LABELS = 32;
const MAX_LABEL_KEY_LENGTH = 63;
const MAX_LABEL_VALUE_LENGTH = 256;

export interface VolumeCreateOptions extends CallOptions {
  /** Labels stored on the volume; `listVolumes({ labels })` filters on them. */
  labels?: Record<string, string>;
}

export function checkLabels(labels: Readonly<Record<string, string>>): void {
  const entries = Object.entries(labels);
  if (entries.length > MAX_LABELS) {
    throw new ValidationError(`labels allows at most ${MAX_LABELS} entries`);
  }
  for (const [key, value] of entries) {
    if (key.trim() === "") throw new ValidationError("label key must not be empty");
    if (key.length > MAX_LABEL_KEY_LENGTH) {
      throw new ValidationError(`label key must be at most ${MAX_LABEL_KEY_LENGTH} characters`);
    }
    if (typeof value !== "string") {
      throw new ValidationError(`label '${key}' value must be a string`);
    }
    if (value.length > MAX_LABEL_VALUE_LENGTH) {
      throw new ValidationError(
        `label value must be at most ${MAX_LABEL_VALUE_LENGTH} characters`,
      );
    }
  }
}

/** Wire body for `POST /v1/volumes`: the name, plus `labels` when given. */
export function volumeCreateBody(
  name: string,
  labels?: Readonly<Record<string, string>>,
): Record<string, unknown> {
  if (name.trim() === "") throw new ValidationError("'name' must not be empty");
  if (labels === undefined) return { name };
  checkLabels(labels);
  return { name, labels: { ...labels } };
}

function volumePath(volumeId: string): string {
  return `${VOLUMES_PATH}/${encodeURIComponent(volumeId)}`;
}

export class Volumes {
  readonly #transport: Transport;

  constructor(transport: Transport) {
    this.#transport = transport;
  }

  async create(name: string, options: VolumeCreateOptions = {}): Promise<VolumeInfo> {
    const reply = await this.#transport.request("POST", VOLUMES_PATH, {
      json: volumeCreateBody(name, options.labels),
      ...callArgs(options),
    });
    return volumeFromPayload(reply);
  }

  async list(options: ListVolumesOptions = {}): Promise<Page<VolumeInfo>> {
    const reply = await this.#transport.requestEnvelope("GET", VOLUMES_PATH, {
      query: {
        label: labelFilters(options.labels),
        cursor: options.cursor,
        limit: options.limit,
      },
      ...callArgs(options),
    });
    return pageFromPayload(reply.data, reply.nextCursor, volumeFromPayload);
  }

  /** Every volume matching `filters`, fetched page by page with the same filters each time. */
  listAll(filters: ListVolumesFilters = {}): AsyncGenerator<VolumeInfo, void, undefined> {
    return paginate((cursor) => this.list({ ...filters, cursor }));
  }

  async get(volumeId: string, call: CallOptions = {}): Promise<VolumeInfo> {
    const reply = await this.#transport.request("GET", volumePath(volumeId), {
      ...callArgs(call),
    });
    return volumeFromPayload(reply);
  }

  /** Delete a volume; the server answers 409 (`Conflict`) while a sandbox mounts it. */
  async delete(volumeId: string, call: CallOptions = {}): Promise<VolumeInfo> {
    const reply = await this.#transport.request("DELETE", volumePath(volumeId), {
      ...callArgs(call),
    });
    return volumeFromPayload(reply);
  }
}
