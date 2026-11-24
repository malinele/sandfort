/** `createSandbox`: validate, resolve volume names, POST, then optionally wait for `started`. */

import {
  DEFAULT_POLL_INTERVAL_S,
  DEFAULT_WAIT_TIMEOUT_S,
  checkWaitOptions,
  type CreateSandboxOptions,
} from "./client-options.js";
import { waitStarted } from "./client-waits.js";
import { createBody, resolveMounts } from "./create-body.js";
import { ValidationError } from "./errors.js";
import { sandboxFromPayload, type SandboxInfo } from "./models.js";
import { IDEMPOTENCY_HEADER, callArgs } from "./resilience.js";
import { SANDBOXES_PATH } from "./sandbox.js";
import type { Transport } from "./transport.js";
import { requireNonBlank } from "./validation.js";
import type { Volumes } from "./volumes.js";

/** Resolves volume names against ONE listing: the first name lists every volume, the rest reuse it. */
function volumeLookup(
  volumes: Volumes,
  signal: AbortSignal | undefined,
): (name: string) => Promise<string> {
  let listing: Promise<ReadonlyMap<string, readonly string[]>> | undefined;
  return async (name) => {
    listing ??= volumeIdsByName(volumes, signal);
    const ids = (await listing).get(name) ?? [];
    const [only, ...rest] = ids;
    if (only === undefined) throw new ValidationError(`no volume named '${name}'`);
    if (rest.length > 0) throw new ValidationError(`more than one volume is named '${name}'`);
    return only;
  };
}

async function volumeIdsByName(
  volumes: Volumes,
  signal: AbortSignal | undefined,
): Promise<ReadonlyMap<string, readonly string[]>> {
  const byName = new Map<string, string[]>();
  for await (const volume of volumes.listAll({ signal })) {
    byName.set(volume.name, [...(byName.get(volume.name) ?? []), volume.id]);
  }
  return byName;
}

/** The sandbox's `SandboxInfo`, `started` unless `options.wait` is false. */
export async function createSandboxInfo(
  transport: Transport,
  volumes: Volumes,
  deadlineMs: number | undefined,
  options: CreateSandboxOptions,
): Promise<SandboxInfo> {
  const key = options.idempotencyKey;
  if (key !== undefined) requireNonBlank(key, "idempotencyKey");
  checkWaitOptions(options);
  const mounts = await resolveMounts(options.volumes ?? [], volumeLookup(volumes, options.signal));
  const reply = await transport.request("POST", SANDBOXES_PATH, {
    json: createBody(options, mounts),
    ...callArgs(options),
    ...(key === undefined ? {} : { headers: { [IDEMPOTENCY_HEADER]: key } }),
  });
  const info = sandboxFromPayload(reply);
  if (!(options.wait ?? true)) return info;
  return waitStarted(
    transport,
    deadlineMs,
    info,
    options.waitTimeoutS ?? DEFAULT_WAIT_TIMEOUT_S,
    options.pollIntervalS ?? DEFAULT_POLL_INTERVAL_S,
    options.signal,
  );
}
