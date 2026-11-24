/**
 * Validation and wire mapping for `POST /v1/sandboxes` (`CreateSandboxRequest` in
 * `openapi/sandfort.v1.json`). Option names are camelCase; the body uses the schema's
 * snake_case names. Unset options are omitted, as in the python sdk's `create_body`.
 */

import { compact, type Resources } from "./models.js";
import { fail, requireInteger, requireMountPath, requireNonBlank } from "./validation.js";

/** Isolation tiers of the schema; `GET /v1/isolation` lists those a deployment offers. */
export const ISOLATION_TIERS = ["container", "gvisor", "microvm"] as const;
export type IsolationTier = (typeof ISOLATION_TIERS)[number];

/** A volume mounted into the new sandbox: identify it by `volumeId` or by `volumeName`. */
export type VolumeMount = {
  /** Absolute path inside the sandbox. */
  mountPath: string;
  /** Mount read-only (needs `volumes:read`; read-write needs `volumes:write`). */
  readOnly?: boolean;
} & (
  | { volumeId: string; volumeName?: never }
  | { volumeName: string; volumeId?: never }
);

/** A mount whose volume name has been resolved to an id. */
export interface ResolvedMount {
  volumeId: string;
  mountPath: string;
  readOnly: boolean;
}

/** Resources of a new sandbox; omitted fields keep the server defaults (1000 / 512 / 3). */
export type ResourceRequest = Partial<Resources>;

export interface CreateFields {
  name?: string;
  snapshot?: string;
  labels?: Record<string, string>;
  env?: Record<string, string>;
  blockNetwork?: boolean;
  autoStopMinutes?: number;
  autoDeleteMinutes?: number;
  public?: boolean;
  isolation?: IsolationTier;
  resources?: ResourceRequest;
  egressAllowlist?: readonly string[];
  /** Fill resource fields you leave out from the snapshot's recorded resources (a field you set always wins). */
  inheritResources?: boolean;
}

export const MAX_VOLUMES = 16;
const MAX_NAME_LENGTH = 63;
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const MAX_SNAPSHOT_LENGTH = 512;
const MAX_LABELS = 32;
const MAX_LABEL_VALUE_LENGTH = 256;
const MAX_MOUNT_PATH_LENGTH = 255;
const MAX_VOLUME_ID_LENGTH = 64;
const MINUTES_MIN = -1;
const MINUTES_MAX = 525_600;

/** Length in code points, which is what the schema's `maxLength` counts (not UTF-16 units). */
function codePoints(value: string): number {
  return Array.from(value).length;
}

function checkName(name: string): void {
  if (name.length < 1 || name.length > MAX_NAME_LENGTH || !NAME_PATTERN.test(name)) {
    fail(`name must be 1-${MAX_NAME_LENGTH} characters of letters, digits, '_', '.', '-' and start with a letter or digit`);
  }
}

function checkLabels(labels: Record<string, string>): void {
  const entries = Object.entries(labels);
  if (entries.length > MAX_LABELS) fail(`labels allows at most ${MAX_LABELS} entries`);
  for (const [key, value] of entries) {
    if (key.trim() === "") fail("label key must not be empty");
    if (codePoints(key) > MAX_NAME_LENGTH) fail(`label key '${key}' is longer than ${MAX_NAME_LENGTH}`);
    if (typeof value !== "string") fail(`label '${key}' value must be a string`);
    if (codePoints(value) > MAX_LABEL_VALUE_LENGTH) {
      fail(`label '${key}' value is longer than ${MAX_LABEL_VALUE_LENGTH}`);
    }
  }
}

function checkResources(resources: ResourceRequest): void {
  const { cpuMillicores, memoryMib, diskGib } = resources;
  if (cpuMillicores !== undefined) requireInteger(cpuMillicores, "resources.cpuMillicores", 100, 1_000_000);
  if (memoryMib !== undefined) requireInteger(memoryMib, "resources.memoryMib", 64, 16_777_216);
  if (diskGib !== undefined) requireInteger(diskGib, "resources.diskGib", 1, 1_048_576);
}

function resourcesPayload(resources: ResourceRequest): Record<string, unknown> {
  return compact({
    cpu_millicores: resources.cpuMillicores,
    memory_mib: resources.memoryMib,
    disk_gib: resources.diskGib,
  });
}

function checkMountShape(mount: VolumeMount, index: number): void {
  const label = `volumes[${index}]`;
  const hasId = mount.volumeId !== undefined;
  const hasName = mount.volumeName !== undefined;
  if (hasId === hasName) fail(`${label} needs exactly one of volumeId and volumeName`);
  requireNonBlank(mount.volumeId ?? mount.volumeName ?? "", `${label} volume`);
  requireNonBlank(mount.mountPath, `${label}.mountPath`);
  requireMountPath(mount.mountPath, `${label}.mountPath`);
  if (mount.mountPath.length > MAX_MOUNT_PATH_LENGTH) {
    fail(`${label}.mountPath is longer than ${MAX_MOUNT_PATH_LENGTH}`);
  }
}

/** Check the mount list before any request is sent (including name lookups). */
export function checkMounts(mounts: readonly VolumeMount[]): void {
  if (mounts.length > MAX_VOLUMES) fail(`volumes allows at most ${MAX_VOLUMES} mounts`);
  mounts.forEach((mount, index) => checkMountShape(mount, index));
}

/** Mounts with every volume given by id; `lookup` resolves a volume name to its id. */
export async function resolveMounts(
  mounts: readonly VolumeMount[],
  lookup: (name: string) => Promise<string>,
): Promise<readonly ResolvedMount[]> {
  checkMounts(mounts);
  const resolved: ResolvedMount[] = [];
  for (const mount of mounts) {
    const volumeId = mount.volumeId ?? (await lookup(mount.volumeName));
    if (volumeId.length > MAX_VOLUME_ID_LENGTH) fail(`volume id is longer than ${MAX_VOLUME_ID_LENGTH}`);
    resolved.push({ volumeId, mountPath: mount.mountPath, readOnly: mount.readOnly ?? false });
  }
  return resolved;
}

function mountPayload(mount: ResolvedMount): Record<string, unknown> {
  return { volume_id: mount.volumeId, mount_path: mount.mountPath, read_only: mount.readOnly };
}

function checkScalars(fields: CreateFields): void {
  if (fields.name !== undefined) checkName(fields.name);
  if (fields.snapshot !== undefined) {
    // The schema says minLength 1, so a lone space is a valid (if odd) snapshot reference.
    if (fields.snapshot === "") fail("snapshot must not be empty");
    if (codePoints(fields.snapshot) > MAX_SNAPSHOT_LENGTH) {
      fail(`snapshot is longer than ${MAX_SNAPSHOT_LENGTH}`);
    }
  }
  if (fields.isolation !== undefined && !ISOLATION_TIERS.includes(fields.isolation)) {
    fail(`isolation must be one of ${ISOLATION_TIERS.join(", ")}`);
  }
  for (const [label, value] of [
    ["autoStopMinutes", fields.autoStopMinutes],
    ["autoDeleteMinutes", fields.autoDeleteMinutes],
  ] as const) {
    if (value !== undefined) requireInteger(value, label, MINUTES_MIN, MINUTES_MAX);
  }
  if (fields.labels !== undefined) checkLabels(fields.labels);
  if (fields.resources !== undefined) checkResources(fields.resources);
}

/** Wire body for `POST /v1/sandboxes`; throws `ValidationError` on an out-of-schema option. */
export function createBody(
  fields: CreateFields,
  mounts: readonly ResolvedMount[] = [],
): Record<string, unknown> {
  checkScalars(fields);
  return compact({
    name: fields.name,
    snapshot: fields.snapshot,
    resources: fields.resources === undefined ? undefined : resourcesPayload(fields.resources),
    env: fields.env,
    labels: fields.labels,
    network: fields.blockNetwork === undefined ? undefined : { block_all: fields.blockNetwork },
    auto_stop_minutes: fields.autoStopMinutes,
    auto_delete_minutes: fields.autoDeleteMinutes,
    public: fields.public,
    volumes: mounts.length === 0 ? undefined : mounts.map(mountPayload),
    egress_allowlist: fields.egressAllowlist === undefined ? undefined : [...fields.egressAllowlist],
    isolation: fields.isolation,
    inherit_resources: fields.inheritResources,
  });
}
