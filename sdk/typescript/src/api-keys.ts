/**
 * API key administration (`client.apiKeys`), mirroring `sandfort_sdk.api_keys`. Every call
 * needs the `api_keys:admin` scope. The plaintext key is in the answer of `create` and nowhere
 * else; a key can only grant scopes its creator holds.
 */

import { InvalidResponseError, ValidationError } from "./errors.js";
import {
  asArray,
  asRecord,
  requiredString,
  requiredTimestamp,
  stringOrNull,
  timestampOrNull,
} from "./models.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { withHiddenSecret } from "./secret.js";
import type { Transport } from "./transport.js";
import { momentIso, requireInteger, requireNonBlank, requireStringList } from "./validation.js";

export const API_KEYS_PATH = "/v1/api-keys";
export const API_KEY_LIST_STATUSES = ["active", "revoked"] as const;
export type ApiKeyListStatus = (typeof API_KEY_LIST_STATUSES)[number];

/** Bounds of `CreateApiKeyRequest` in the OpenAPI spec. */
const MAX_KEY_LABELS = 8;
const MAX_KEY_SANDBOXES = 1000;
const DEFAULT_STATUS = "active"; // an older server omits the field
const KEY_MISSING =
  "the api key create answer has no 'key': the key was created; list and revoke it";

/** API key metadata; the secret and its hash are never part of it. */
export interface ApiKeyInfo {
  id: string;
  name: string;
  prefix: string;
  scopes: readonly string[];
  sandboxLabels: Record<string, string> | null;
  maxSandboxes: number | null;
  createdAt: Date;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  revokedAt: Date | null;
  createdBy: string | null;
  /**
   * `revoked` once `revokedAt` is set, else `expired` once `expiresAt` has passed, else
   * `active`. A plain string so that a value a newer server adds still loads as sent; a server
   * that predates the field leaves it at `active`.
   */
  status: string;
}

/** The create answer: the metadata plus the plaintext `key` (shown this once). */
export interface CreatedApiKey extends ApiKeyInfo {
  /** Not enumerable: it stays out of `JSON.stringify`, `Object.keys` and `console.log`. */
  readonly key: string;
}

/**
 * The revoke answer. `dependants` are the key's live descendants: with `cascade` true they
 * were just revoked, otherwise they are still alive and only a later revoke ends each one.
 */
export interface RevokedApiKey extends ApiKeyInfo {
  cascade: boolean;
  dependants: readonly ApiKeyInfo[];
}

export interface CreateApiKeyOptions extends CallOptions {
  /** Limits the key to sandboxes carrying all of these labels (at most 8). */
  sandboxLabels?: Record<string, string>;
  /** Caps the key's live sandboxes (1 to 1000); needs non-empty `sandboxLabels`. */
  maxSandboxes?: number;
  expiresAt?: Date;
}

export interface ListApiKeysOptions extends CallOptions {
  /** Only `active` (neither revoked nor expired) or only `revoked` keys; default: all. */
  status?: ApiKeyListStatus;
}

export interface RevokeApiKeyOptions extends CallOptions {
  /** Also revoke the key's live descendants (default false). */
  cascade?: boolean;
}

function labelsOrNull(value: unknown): Record<string, string> | null {
  if (value === undefined || value === null) return null;
  const raw = asRecord(value, "api key sandbox_labels");
  return Object.fromEntries(Object.entries(raw).map(([key, item]) => [key, String(item)]));
}

export function apiKeyFromPayload(data: unknown): ApiKeyInfo {
  const what = "api key";
  const raw = asRecord(data, what);
  const maxSandboxes = raw["max_sandboxes"];
  const status = raw["status"];
  return {
    id: requiredString(raw, "id", what),
    name: requiredString(raw, "name", what),
    prefix: requiredString(raw, "prefix", what),
    scopes: asArray(raw["scopes"], "api key scopes").map(String),
    sandboxLabels: labelsOrNull(raw["sandbox_labels"]),
    maxSandboxes: typeof maxSandboxes === "number" ? maxSandboxes : null,
    createdAt: requiredTimestamp(raw["created_at"], what),
    lastUsedAt: timestampOrNull(raw["last_used_at"], what),
    expiresAt: timestampOrNull(raw["expires_at"], what),
    revokedAt: timestampOrNull(raw["revoked_at"], what),
    createdBy: stringOrNull(raw["created_by"]),
    status: typeof status === "string" ? status : DEFAULT_STATUS,
  };
}

export function createdKeyFromPayload(data: unknown): CreatedApiKey {
  const raw = asRecord(data, "api key");
  if (typeof raw["key"] !== "string" || raw["key"] === "") {
    throw new InvalidResponseError(KEY_MISSING);
  }
  const key = raw["key"];
  return withHiddenSecret(apiKeyFromPayload(data), "key", key) as CreatedApiKey;
}

export function revokedKeyFromPayload(data: unknown): RevokedApiKey {
  const raw = asRecord(data, "api key");
  const dependants = raw["dependants"];
  return {
    ...apiKeyFromPayload(data),
    cascade: raw["cascade"] === true,
    dependants:
      dependants === undefined || dependants === null
        ? []
        : asArray(dependants, "api key dependants").map(apiKeyFromPayload),
  };
}

/** Wire body for `POST /v1/api-keys`; unset options are left out. */
export function apiKeyCreateBody(
  name: string,
  scopes: readonly string[],
  options: CreateApiKeyOptions,
): Record<string, unknown> {
  requireNonBlank(name, "name");
  requireStringList(scopes, "scopes");
  if (scopes.length === 0) throw new ValidationError("'scopes' must not be empty");
  const labels = options.sandboxLabels ?? {};
  const labelCount = Object.keys(labels).length;
  if (labelCount > MAX_KEY_LABELS) {
    throw new ValidationError(`sandboxLabels allows at most ${MAX_KEY_LABELS} entries`);
  }
  for (const [name, value] of Object.entries(labels)) {
    if (typeof value !== "string") {
      throw new ValidationError(`sandboxLabels '${name}' value must be a string`);
    }
  }
  const { maxSandboxes } = options;
  if (maxSandboxes !== undefined) {
    requireInteger(maxSandboxes, "maxSandboxes", 1, MAX_KEY_SANDBOXES);
    if (labelCount === 0) {
      throw new ValidationError("'maxSandboxes' needs a non-empty 'sandboxLabels'");
    }
  }
  return {
    name,
    scopes: [...scopes],
    ...(labelCount === 0 ? {} : { sandbox_labels: { ...labels } }),
    ...(maxSandboxes === undefined ? {} : { max_sandboxes: maxSandboxes }),
    ...(options.expiresAt === undefined
      ? {}
      : { expires_at: momentIso(options.expiresAt, "expiresAt") }),
  };
}

function keyPath(keyId: string): string {
  requireNonBlank(keyId, "keyId");
  return `${API_KEYS_PATH}/${encodeURIComponent(keyId)}`;
}

export class ApiKeys {
  readonly #transport: Transport;

  constructor(transport: Transport) {
    this.#transport = transport;
  }

  /**
   * Create a key; the plaintext is in `key` of the answer and cannot be read back. A create
   * is never resent after a failure, so a lost answer may leave a key you did not see: list
   * the keys before trying again.
   */
  async create(
    name: string,
    scopes: readonly string[],
    options: CreateApiKeyOptions = {},
  ): Promise<CreatedApiKey> {
    const reply = await this.#transport.request("POST", API_KEYS_PATH, {
      json: apiKeyCreateBody(name, scopes, options),
      ...callArgs(options),
    });
    return createdKeyFromPayload(reply);
  }

  async list(options: ListApiKeysOptions = {}): Promise<readonly ApiKeyInfo[]> {
    const { status } = options;
    if (status !== undefined && !API_KEY_LIST_STATUSES.includes(status)) {
      throw new ValidationError(
        `status must be one of ${API_KEY_LIST_STATUSES.join(", ")}; got ${JSON.stringify(status)}`,
      );
    }
    const reply = await this.#transport.request("GET", API_KEYS_PATH, {
      query: { status },
      ...callArgs(options),
    });
    return asArray(reply, "api keys").map(apiKeyFromPayload);
  }

  /** Revoke a key; repeating it answers the already revoked key. */
  async revoke(keyId: string, options: RevokeApiKeyOptions = {}): Promise<RevokedApiKey> {
    const path = keyPath(keyId);
    const reply = await this.#transport.request("DELETE", path, {
      query: { cascade: options.cascade === true ? true : undefined },
      ...callArgs(options),
    });
    return revokedKeyFromPayload(reply);
  }
}
