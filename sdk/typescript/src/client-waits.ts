/** Reading a sandbox or snapshot and waiting for it to settle: the polling behind `wait: true`. */

import { SandboxFailedError, SandboxTimeoutError } from "./errors.js";
import { sandboxFromPayload, type SandboxInfo } from "./models.js";
import { MAX_LONG_POLL_S } from "./client-options.js";
import { abortableSleep, callArgs, type CallOptions } from "./resilience.js";
import { sandboxPath } from "./sandbox.js";
import { SnapshotTimeoutError, isSnapshotReady, type SnapshotInfo, type Snapshots } from "./snapshots.js";
import type { Transport } from "./transport.js";

/** Added to a long poll's `timeout_s` to get the request timeout of that poll (as for exec). */
const LONG_POLL_REQUEST_MARGIN_MS = 10_000;
/** A long poll never outlasts the client's `deadlineMs` by design: it stops this early. */
const DEADLINE_MARGIN_S = 1;
const STATE_STARTED = "started";
const UNREACHABLE_STATES: ReadonlySet<string> = new Set(["error", "destroying", "destroyed"]);

function isReady(info: SandboxInfo): boolean {
  if (info.state === STATE_STARTED) return true;
  if (UNREACHABLE_STATES.has(info.state)) {
    const reason = info.errorReason ? `: ${info.errorReason}` : "";
    throw new SandboxFailedError(`sandbox ${info.id} is ${info.state}${reason}`, info.id, info.state);
  }
  return false;
}

function sleep(seconds: number, signal: AbortSignal | undefined): Promise<void> {
  return abortableSleep(seconds * 1000, signal);
}

/** Seconds the server may hold one poll: the wait left, capped, and inside any `deadlineMs`. */
function longPollS(remainingS: number, deadlineMs: number | undefined): number {
  const capped = Math.min(remainingS, MAX_LONG_POLL_S);
  if (deadlineMs === undefined) return capped;
  return Math.min(capped, Math.max(0, deadlineMs / 1000 - DEADLINE_MARGIN_S));
}

/** `GET` a sandbox; with `longPoll` the server holds the reply until it is `started`. */
export async function fetchSandbox(
  transport: Transport,
  sandboxId: string,
  call: CallOptions,
  longPoll?: number,
): Promise<SandboxInfo> {
  const poll =
    longPoll === undefined
      ? {}
      : {
          query: { wait_for: STATE_STARTED, timeout_s: longPoll },
          // The request must outlive the server-side hold, whatever `timeoutMs` is.
          minTimeoutMs: Math.ceil(longPoll * 1000) + LONG_POLL_REQUEST_MARGIN_MS,
        };
  const reply = await transport.request("GET", sandboxPath(sandboxId), { ...callArgs(call), ...poll });
  return sandboxFromPayload(reply);
}

export async function waitStarted(
  transport: Transport,
  deadlineMs: number | undefined,
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
    info = await fetchSandbox(transport, info.id, { signal }, longPollS(remainingS, deadlineMs));
    if (!isReady(info)) await sleep(pollIntervalS, signal);
  }
}

/** The snapshot route has no long poll, so this sleeps between plain reads. */
export async function waitSnapshotReady(
  snapshots: Snapshots,
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
    info = await snapshots.get(info.id, { signal });
  }
}
