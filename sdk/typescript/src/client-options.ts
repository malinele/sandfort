/** Options and shared constants of `SandfortClient` (the class itself lives in `client.ts`). */

import type { CreateFields, VolumeMount } from "./create-body.js";
import { labelFilters } from "./models.js";
import type { Cursor } from "./pagination.js";
import type { CallOptions, ResilienceOptions } from "./resilience.js";
import type { PtySocketFactory } from "./pty.js";
import type { Query } from "./transport.js";
import type { FetchLike } from "./transport.js";
import { requirePositiveFinite } from "./validation.js";

export const DEFAULT_WAIT_TIMEOUT_S = 120;
export const DEFAULT_POLL_INTERVAL_S = 0.5;
/** Upper bound for one server-side long poll, as in the python sdk (the server caps at 60). */
export const MAX_LONG_POLL_S = 30;

export interface SandfortClientOptions extends ResilienceOptions {
  baseUrl: string;
  apiKey: string;
  fetch?: FetchLike;
  /** WebSocket factory for `connectPty` (default: the global `WebSocket`, Node 22+). */
  webSocket?: PtySocketFactory;
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

export function listQuery(options: ListSandboxesOptions): Query {
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

/** `waitTimeoutS` and `pollIntervalS`, when given, must be positive finite numbers. */
export function checkWaitOptions(options: { waitTimeoutS?: number; pollIntervalS?: number }): void {
  if (options.waitTimeoutS !== undefined) requirePositiveFinite(options.waitTimeoutS, "waitTimeoutS");
  if (options.pollIntervalS !== undefined) requirePositiveFinite(options.pollIntervalS, "pollIntervalS");
}
