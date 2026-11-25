import { InvalidResponseError } from "./errors.js";
import type { SandboxErrorCode } from "./error-codes.js";

export interface Resources {
  cpuMillicores: number;
  memoryMib: number;
  diskGib: number;
}

export interface SandboxInfo {
  id: string;
  name: string;
  state: string;
  resources: Resources;
  env: Record<string, string>;
  labels: Record<string, string>;
  blockNetwork: boolean;
  public: boolean;
  autoStopMinutes: number;
  autoDeleteMinutes: number;
  errorReason: string | null;
  /**
   * Machine-readable cause of the `error` state, one of `SANDBOX_ERROR_CODES` (for example
   * `egress_unavailable`); `null` when the server sends none. Like `state`, the field is an
   * open enum: a code a newer server adds comes through as the plain string, never an error.
   */
  errorCode: SandboxErrorCode | (string & {}) | null;
  jobId: string | null;
  /** The optional fields below are `undefined` when the server omits them. */
  createdAt?: Date | null | undefined;
  updatedAt?: Date | null | undefined;
  /** Why the sandbox stopped (`requested`, `auto_stop`, ...); `null` unless stopping/stopped. */
  stopCause?: string | null | undefined;
  stoppedAt?: Date | null | undefined;
  isolation?: string | undefined;
  volumes?: readonly VolumeMountInfo[] | undefined;
  /**
   * Host names, leading-dot domains and CIDR ranges reachable through the egress proxy; `null`
   * means the sandbox was created without an allowlist (the network policy default).
   */
  egressAllowlist?: readonly string[] | null | undefined;
  /**
   * Version of the egress allowlist. 0 is ambiguous on its own: the server sends null when
   * `egressAllowlist` is null and 0 for a legacy v1 sandbox, and both read as 0 here. Read it
   * together with `egressAllowlist`: 0 with a non-null list is a legacy v1 credential (`reset`
   * upgrades it); with `egressAllowlist: null` no allowlist was ever set, and neither `update`
   * nor `reset` will enable one.
   */
  egressPolicyGeneration: number;
}

/** A volume mount as a sandbox response reports it. */
export interface VolumeMountInfo {
  volumeId: string;
  mountPath: string;
  readOnly: boolean;
}

export interface Page<T> {
  items: readonly T[];
  nextCursor: string | null;
}

// --- payload helpers -------------------------------------------------------------------

export function asRecord(data: unknown, what: string): Record<string, unknown> {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new InvalidResponseError(`expected an object for ${what}`);
  }
  return data as Record<string, unknown>;
}

export function asArray(data: unknown, what: string): readonly unknown[] {
  if (!Array.isArray(data)) throw new InvalidResponseError(`expected a list for ${what}`);
  return data;
}

function missing(what: string, key: string): InvalidResponseError {
  return new InvalidResponseError(`${what} payload is missing '${key}'`);
}

export function requiredString(raw: Record<string, unknown>, key: string, what: string): string {
  const value = raw[key];
  if (typeof value !== "string") throw missing(what, key);
  return value;
}

/** A key that must be present and be a string or `null` (a field the server may withhold). */
export function requiredStringOrNull(
  raw: Record<string, unknown>,
  key: string,
  what: string,
): string | null {
  const value = raw[key];
  if (value === null) return null;
  if (typeof value !== "string") throw missing(what, key);
  return value;
}

export function requiredNumber(raw: Record<string, unknown>, key: string, what: string): number {
  const value = raw[key];
  if (typeof value !== "number") throw missing(what, key);
  return value;
}

export function requiredBoolean(raw: Record<string, unknown>, key: string, what: string): boolean {
  const value = raw[key];
  if (typeof value !== "boolean") throw missing(what, key);
  return value;
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === "number" ? value : fallback;
}

export function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/** An ISO-8601 timestamp, or `null` when the field is absent or null. */
export function timestampOrNull(value: unknown, what: string): Date | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new InvalidResponseError(`expected an ISO timestamp for ${what}`);
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new InvalidResponseError(`invalid timestamp for ${what}: ${value}`);
  }
  return parsed;
}

export function requiredTimestamp(value: unknown, what: string): Date {
  const parsed = timestampOrNull(value, what);
  if (parsed === null) throw new InvalidResponseError(`${what} payload is missing a timestamp`);
  return parsed;
}

/** Drop `undefined` values so unset options never reach the wire (python: drop `None`). */
export function compact(body: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(body).filter(([, value]) => value !== undefined));
}

/** `k=v` strings for a repeatable `label` query parameter; `undefined` when there are none. */
export function labelFilters(
  labels: Readonly<Record<string, string>> | undefined,
): string[] | undefined {
  const pairs = Object.entries(labels ?? {}).map(([key, value]) => `${key}=${value}`);
  return pairs.length > 0 ? pairs : undefined;
}

function stringMap(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (typeof value === "object" && value !== null) {
    for (const [key, item] of Object.entries(value)) out[key] = String(item);
  }
  return out;
}

// --- sandboxes -------------------------------------------------------------------------

export function resourcesFromPayload(data: unknown): Resources {
  const raw = asRecord(data ?? {}, "resources");
  return {
    cpuMillicores: numberOr(raw["cpu_millicores"], 1000),
    memoryMib: numberOr(raw["memory_mib"], 512),
    diskGib: numberOr(raw["disk_gib"], 3),
  };
}

/** `undefined` when the key is absent, `null` when the server sent null, else the parsed date. */
function optionalTimestamp(raw: Record<string, unknown>, key: string): Date | null | undefined {
  return raw[key] === undefined ? undefined : timestampOrNull(raw[key], key);
}

function volumeMountFromPayload(data: unknown): VolumeMountInfo {
  const what = "volume mount";
  const raw = asRecord(data, what);
  return {
    volumeId: requiredString(raw, "volume_id", what),
    mountPath: requiredString(raw, "mount_path", what),
    readOnly: raw["read_only"] === true,
  };
}

/** `undefined` when absent or null; any other non-string is a malformed response. */
export function optionalString(raw: Record<string, unknown>, key: string): string | undefined {
  const value = raw[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new InvalidResponseError(`expected a string for '${key}'`);
  }
  return value;
}

function optionalStringList(value: unknown): readonly string[] | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  return asArray(value, "egress allowlist").map((item) => String(item));
}

function egressGeneration(value: unknown): number {
  if (value === undefined || value === null) return 0;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new InvalidResponseError("expected an integer for 'egress_policy_generation'");
  }
  return value;
}

export function sandboxFromPayload(data: unknown): SandboxInfo {
  const raw = asRecord(data, "sandbox");
  const network = raw["network"] == null ? {} : asRecord(raw["network"], "network");
  const volumes = raw["volumes"];
  return {
    id: requiredString(raw, "id", "sandbox"),
    name: requiredString(raw, "name", "sandbox"),
    state: requiredString(raw, "state", "sandbox"),
    resources: resourcesFromPayload(raw["resources"]),
    env: stringMap(raw["env"]),
    labels: stringMap(raw["labels"]),
    blockNetwork: network["block_all"] === true,
    public: raw["public"] === true,
    autoStopMinutes: numberOr(raw["auto_stop_minutes"], 15),
    autoDeleteMinutes: numberOr(raw["auto_delete_minutes"], -1),
    errorReason: stringOrNull(raw["error_reason"]),
    errorCode: stringOrNull(raw["error_code"]),
    jobId: stringOrNull(raw["job_id"]),
    createdAt: optionalTimestamp(raw, "created_at"),
    updatedAt: optionalTimestamp(raw, "updated_at"),
    stopCause: raw["stop_cause"] === undefined ? undefined : stringOrNull(raw["stop_cause"]),
    stoppedAt: optionalTimestamp(raw, "stopped_at"),
    isolation: optionalString(raw, "isolation"),
    volumes:
      volumes === undefined || volumes === null
        ? undefined
        : asArray(volumes, "volumes").map((item) => volumeMountFromPayload(item)),
    egressAllowlist: optionalStringList(raw["egress_allowlist"]),
    egressPolicyGeneration: egressGeneration(raw["egress_policy_generation"]),
  };
}

export function pageFromPayload<T>(
  data: unknown,
  nextCursor: string | null,
  mapItem: (item: unknown) => T,
): Page<T> {
  if (!Array.isArray(data)) throw new InvalidResponseError("expected a list payload");
  return { items: data.map((item: unknown) => mapItem(item)), nextCursor };
}

// --- filesystem ------------------------------------------------------------------------

export interface FileEntry {
  name: string;
  path: string;
  /** `"file"`, `"dir"` or `"symlink"`. */
  kind: string;
  sizeBytes: number;
  mode: string;
  modifiedAt: Date | null;
}

export interface DirListing {
  path: string;
  entries: readonly FileEntry[];
}

export interface MkdirResult {
  path: string;
  created: boolean;
}

export interface MoveResult {
  source: string;
  destination: string;
}

export interface DeleteResult {
  path: string;
  deleted: boolean;
}

export interface UploadResult {
  path: string;
  sizeBytes: number;
}

export function fileEntryFromPayload(data: unknown): FileEntry {
  const what = "file entry";
  const raw = asRecord(data, what);
  return {
    name: requiredString(raw, "name", what),
    path: requiredString(raw, "path", what),
    kind: requiredString(raw, "kind", what),
    sizeBytes: requiredNumber(raw, "size_bytes", what),
    mode: requiredString(raw, "mode", what),
    modifiedAt: timestampOrNull(raw["modified_at"], what),
  };
}

export function dirListingFromPayload(data: unknown): DirListing {
  const what = "directory listing";
  const raw = asRecord(data, what);
  const entries = asArray(raw["entries"], "directory entries");
  return {
    path: requiredString(raw, "path", what),
    entries: entries.map((item) => fileEntryFromPayload(item)),
  };
}

export function mkdirResultFromPayload(data: unknown): MkdirResult {
  const raw = asRecord(data, "mkdir result");
  return {
    path: requiredString(raw, "path", "mkdir result"),
    created: requiredBoolean(raw, "created", "mkdir result"),
  };
}

export function moveResultFromPayload(data: unknown): MoveResult {
  const raw = asRecord(data, "move result");
  return {
    source: requiredString(raw, "source", "move result"),
    destination: requiredString(raw, "destination", "move result"),
  };
}

export function deleteResultFromPayload(data: unknown): DeleteResult {
  const raw = asRecord(data, "delete result");
  return {
    path: requiredString(raw, "path", "delete result"),
    deleted: requiredBoolean(raw, "deleted", "delete result"),
  };
}

export function uploadResultFromPayload(data: unknown): UploadResult {
  const raw = asRecord(data, "upload result");
  return {
    path: requiredString(raw, "path", "upload result"),
    sizeBytes: requiredNumber(raw, "size_bytes", "upload result"),
  };
}
