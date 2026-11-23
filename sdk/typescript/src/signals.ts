/**
 * Compose abort signals. `AbortSignal.any` exists from Node 20.3, which `package.json` requires
 * (`engines`). The fallback below is only a courtesy for older runtimes and is NOT safe for
 * streams: its `dispose` detaches the inputs, and `withResilience` disposes once the response
 * head has arrived, so the per-request timeout would no longer bound the body of a stream.
 * That is why Node 20.0 to 20.2 are unsupported rather than patched around.
 */

export interface ComposedSignal {
  signal: AbortSignal;
  /** Drop the listeners this composition put on its inputs; safe to call more than once. */
  dispose: () => void;
}

function nativeAny(): ((signals: AbortSignal[]) => AbortSignal) | undefined {
  const candidate = (AbortSignal as { any?: (signals: AbortSignal[]) => AbortSignal }).any;
  return typeof candidate === "function" ? candidate.bind(AbortSignal) : undefined;
}

/** A signal that aborts, with the first reason, as soon as any of `signals` aborts. */
export function composeSignals(signals: readonly AbortSignal[]): ComposedSignal {
  const native = nativeAny();
  if (native !== undefined) return { signal: native([...signals]), dispose: () => undefined };
  const controller = new AbortController();
  const detached: Array<() => void> = [];
  const dispose = (): void => {
    for (const detach of detached.splice(0)) detach();
  };
  for (const input of signals) {
    if (input.aborted) {
      controller.abort(input.reason);
      dispose();
      break;
    }
    const onAbort = (): void => {
      controller.abort(input.reason);
      dispose();
    };
    input.addEventListener("abort", onAbort, { once: true });
    detached.push(() => input.removeEventListener("abort", onAbort));
  }
  return { signal: controller.signal, dispose };
}

/** The longest delay `setTimeout` takes; a longer deadline is clamped to it (about 24.8 days). */
const MAX_TIMER_MS = 2_147_483_647;

/** The abort reason of a call's `deadlineMs`, so a read that it cut can say "deadline". */
export class DeadlineExceeded extends Error {
  constructor(readonly deadlineMs: number) {
    super(`the deadline of ${deadlineMs} ms passed`);
    this.name = "DeadlineExceeded";
  }
}

/** A signal that aborts with a `DeadlineExceeded` after `ms`; its timer never keeps Node alive. */
export function deadlineSignal(ms: number): AbortSignal {
  const controller = new AbortController();
  const fire = (): void => controller.abort(new DeadlineExceeded(ms));
  const timer = setTimeout(fire, Math.min(ms, MAX_TIMER_MS));
  (timer as unknown as { unref?: () => void }).unref?.();
  return controller.signal;
}
