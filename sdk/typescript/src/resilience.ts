/**
 * Per-request timeout, caller abort and bounded retries, shared by the JSON `Transport` and the
 * raw-body `BinaryChannel`.
 *
 * Retries are opt-out (`retries`, default 2) and narrow: only a 429 (not `QUOTA_EXCEEDED`, a
 * quota does not free itself) and a 503 with code `CAPACITY`, only for calls that are safe to
 * repeat (GET, HEAD, PUT, DELETE, or a POST carrying an `Idempotency-Key`). Each pause
 * honours `Retry-After`, capped at `MAX_RETRY_AFTER_S`, and all pauses of one call together
 * stay within `MAX_TOTAL_RETRY_WAIT_S`. Every other failure is final. An optional `deadlineMs`
 * bounds a whole call: every attempt and every pause together.
 */

import { RequestAbortedError, RequestTimeoutError, TransportError, ValidationError } from "./errors.js";
import { composeSignals, deadlineSignal } from "./signals.js";

export const DEFAULT_TIMEOUT_MS = 60_000;
export const DEFAULT_RETRIES = 2;
export const MAX_RETRIES = 10;
export const MAX_RETRY_AFTER_S = 30;
export const MAX_TOTAL_RETRY_WAIT_S = 60;
export const IDEMPOTENCY_HEADER = "Idempotency-Key";

const DEFAULT_RETRY_AFTER_S = 1;
const BACKOFF_FIRST_S = 0.5;
const BACKOFF_CAP_S = 8;
const IDEMPOTENT_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "PUT", "DELETE"]);
const CODE_QUOTA_EXCEEDED = "QUOTA_EXCEEDED";
const CODE_CAPACITY = "CAPACITY";

/**
 * Options every request of a call can carry. `timeoutMs`, `retries` and `deadlineMs` replace
 * the client-wide values of the same name for this call only; they are checked like the
 * client options (a `ValidationError` before anything is sent).
 */
export interface CallOptions {
  /** Abort this call; the call then rejects with `RequestAbortedError`. */
  signal?: AbortSignal | undefined;
  /** Per-request timeout of this call in milliseconds (`RequestTimeoutError` when it fires). */
  timeoutMs?: number | undefined;
  /**
   * Extra attempts of this call after a 429 or a 503 `CAPACITY` (0 turns retries off). Only
   * for GET/HEAD/PUT/DELETE or a POST with an idempotency key; any other POST is sent once.
   */
  retries?: number | undefined;
  /** Overall budget of this call in milliseconds, all attempts and pauses together. */
  deadlineMs?: number | undefined;
}

/** The four per-call fields of `call`, ready to spread into a request's options. */
export function callArgs(call: CallOptions): CallOptions {
  return {
    signal: call.signal,
    timeoutMs: call.timeoutMs,
    retries: call.retries,
    deadlineMs: call.deadlineMs,
  };
}

/** Sleep for `ms`, rejecting early when `signal` aborts. Replaceable for tests. */
export type SleepFn = (ms: number, signal?: AbortSignal) => Promise<void>;

export interface ResilienceOptions {
  /** Per-request timeout in milliseconds (default 60000). */
  timeoutMs?: number;
  /** Extra attempts after a 429 or a 503 `CAPACITY` (default 2; 0 turns retries off). */
  retries?: number;
  /** Overall budget of one call in milliseconds, all attempts and pauses together (default: none). */
  deadlineMs?: number;
  /** Pause implementation; the default is an abortable `setTimeout`. */
  sleep?: SleepFn;
}

export interface ResiliencePolicy {
  timeoutMs: number;
  retries: number;
  deadlineMs: number | undefined;
  sleep: SleepFn;
}

/** Why a response may be resent: its status, `error.code` and `Retry-After` header. */
export interface RetryHint {
  status: number;
  code: string | undefined;
  retryAfter: string | null;
}

/** What one attempt produced: the value to hand back, and whether it may be resent. */
export interface Attempt<T> {
  value: T;
  hint?: RetryHint | undefined;
}

export const abortableSleep: SleepFn = (ms, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(new RequestAbortedError("the request was aborted"));
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new RequestAbortedError("the request was aborted"));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });

export function resolvePolicy(options: ResilienceOptions = {}): ResiliencePolicy {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const retries = options.retries ?? DEFAULT_RETRIES;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
    throw new ValidationError("timeoutMs must be a positive whole number of milliseconds");
  }
  if (!Number.isInteger(retries) || retries < 0 || retries > MAX_RETRIES) {
    throw new ValidationError(`retries must be a whole number between 0 and ${MAX_RETRIES}`);
  }
  const deadlineMs = options.deadlineMs;
  if (deadlineMs !== undefined && (!Number.isInteger(deadlineMs) || deadlineMs < 1)) {
    throw new ValidationError("deadlineMs must be a positive whole number of milliseconds");
  }
  return { timeoutMs, retries, deadlineMs, sleep: options.sleep ?? abortableSleep };
}

/** The client policy with the per-call `timeoutMs`, `retries` and `deadlineMs` laid over it. */
export function withCallOptions(policy: ResiliencePolicy, call: CallOptions): ResiliencePolicy {
  const { timeoutMs, retries, deadlineMs } = call;
  if (timeoutMs === undefined && retries === undefined && deadlineMs === undefined) return policy;
  const inherited = deadlineMs ?? policy.deadlineMs;
  return resolvePolicy({
    timeoutMs: timeoutMs ?? policy.timeoutMs,
    retries: retries ?? policy.retries,
    sleep: policy.sleep,
    ...(inherited === undefined ? {} : { deadlineMs: inherited }),
  });
}

/** True when resending cannot do harm: an idempotent method, or a POST with an idempotency key. */
export function isRepeatable(method: string, headers: Readonly<Record<string, string>>): boolean {
  if (IDEMPOTENT_METHODS.has(method.toUpperCase())) return true;
  const keyed = Object.keys(headers).some((name) => name.toLowerCase() === IDEMPOTENCY_HEADER.toLowerCase());
  return method.toUpperCase() === "POST" && keyed;
}

const DELTA_SECONDS = /^\d+$/;
/** RFC 7231 IMF-fixdate, the only HTTP-date form a server should send. */
const IMF_FIXDATE =
  /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/**
 * Seconds from a `Retry-After` value: a non-negative whole number of seconds or an IMF-fixdate.
 * Anything else ("1.5", "-5", "+3", free text) is unusable and gives the 1 s default.
 */
export function parseRetryAfterS(value: string | null, now: number = Date.now()): number {
  if (value === null) return DEFAULT_RETRY_AFTER_S;
  const text = value.trim();
  if (DELTA_SECONDS.test(text)) return Number.parseInt(text, 10);
  if (!IMF_FIXDATE.test(text)) return DEFAULT_RETRY_AFTER_S;
  const date = Date.parse(text);
  if (Number.isNaN(date)) return DEFAULT_RETRY_AFTER_S;
  return Math.max(0, Math.ceil((date - now) / 1000));
}

/** The retry hint of a reply: only 429 and 503 can be retried, so only they parse the body. */
export function retryHint(status: number, text: string, headers: Headers): RetryHint | undefined {
  if (status !== 429 && status !== 503) return undefined;
  return { status, code: errorCode(text), retryAfter: headers.get("Retry-After") };
}

function errorCode(text: string): string | undefined {
  try {
    const body: unknown = JSON.parse(text);
    if (typeof body !== "object" || body === null) return undefined;
    const error = (body as Record<string, unknown>)["error"];
    if (typeof error !== "object" || error === null) return undefined;
    const code = (error as Record<string, unknown>)["code"];
    return typeof code === "string" ? code : undefined;
  } catch {
    return undefined;
  }
}

function clampRetryAfterS(seconds: number): number {
  return Math.min(Math.max(seconds, 0), MAX_RETRY_AFTER_S);
}

/** Seconds to wait before resending, or `undefined` when the reply is final. */
export function retryPauseS(
  hint: RetryHint | undefined,
  attempt: number,
  random: () => number = Math.random,
): number | undefined {
  if (hint === undefined) return undefined;
  if (hint.status === 429) {
    if (hint.code === CODE_QUOTA_EXCEEDED) return undefined;
    return clampRetryAfterS(parseRetryAfterS(hint.retryAfter));
  }
  if (hint.status !== 503 || hint.code !== CODE_CAPACITY) return undefined;
  const backoffS = Math.min(BACKOFF_FIRST_S * 2 ** attempt, BACKOFF_CAP_S);
  const own = backoffS * (0.5 + 0.5 * random());
  if (hint.retryAfter === null) return own;
  return Math.max(own, clampRetryAfterS(parseRetryAfterS(hint.retryAfter)));
}

export interface ResilientCall<T> {
  policy: ResiliencePolicy;
  method: string;
  path: string;
  headers: Readonly<Record<string, string>>;
  signal: AbortSignal | undefined;
  /** Raise the per-request timeout for a call the server may legitimately hold longer. */
  minTimeoutMs?: number | undefined;
  /** One attempt; `attemptSignal` fires on the timeout or the caller's abort. */
  run: (attemptSignal: AbortSignal) => Promise<Attempt<T>>;
}

function describeCause(cause: unknown): string {
  return cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause);
}

function requestTimeoutMs(call: ResilientCall<unknown>): number {
  return Math.max(call.policy.timeoutMs, call.minTimeoutMs ?? 0);
}

function failureFor(
  cause: unknown,
  call: ResilientCall<unknown>,
  timeout: AbortSignal,
  deadline: AbortSignal | undefined,
): TransportError {
  const where = `${call.method} ${call.path}`;
  if (call.signal?.aborted === true) return new RequestAbortedError(`${where} was aborted`, { cause });
  if (deadline?.aborted === true) {
    return new RequestTimeoutError(`${where} exceeded its deadline of ${call.policy.deadlineMs} ms`, {
      cause,
    });
  }
  if (timeout.aborted) {
    return new RequestTimeoutError(`${where} timed out after ${requestTimeoutMs(call)} ms`, { cause });
  }
  if (cause instanceof TransportError) return cause;
  return new TransportError(`${where} failed: ${describeCause(cause)}`, { cause });
}

/** Milliseconds left of the call's deadline, or `Infinity` when it has none. */
function remainingMs(policy: ResiliencePolicy, startedAt: number): number {
  return policy.deadlineMs === undefined ? Number.POSITIVE_INFINITY : policy.deadlineMs - (Date.now() - startedAt);
}

/** Run `call.run` with a timeout per attempt and the retry rules in the module comment. */
export async function withResilience<T>(call: ResilientCall<T>): Promise<T> {
  const { policy, signal } = call;
  const mayRetry = isRepeatable(call.method, call.headers);
  const startedAt = Date.now();
  const deadline = policy.deadlineMs === undefined ? undefined : deadlineSignal(policy.deadlineMs);
  const outer = [signal, deadline].filter((item): item is AbortSignal => item !== undefined);
  let waitedS = 0;
  for (let attempt = 0; ; attempt += 1) {
    const timeout = AbortSignal.timeout(requestTimeoutMs(call));
    const composed = composeSignals([...outer, timeout]);
    let outcome: Attempt<T>;
    try {
      if (signal?.aborted === true) throw new RequestAbortedError("the request was aborted");
      outcome = await call.run(composed.signal);
    } catch (cause) {
      throw failureFor(cause, call, timeout, deadline);
    } finally {
      composed.dispose();
    }
    const pauseS = mayRetry && attempt < policy.retries ? retryPauseS(outcome.hint, attempt) : undefined;
    if (pauseS === undefined || waitedS + pauseS > MAX_TOTAL_RETRY_WAIT_S) return outcome.value;
    if (pauseS * 1000 >= remainingMs(policy, startedAt)) return outcome.value;
    waitedS += pauseS;
    const pause = composeSignals(outer);
    try {
      await policy.sleep(pauseS * 1000, pause.signal);
    } catch (cause) {
      throw failureFor(cause, call, timeout, deadline);
    } finally {
      pause.dispose();
    }
  }
}
