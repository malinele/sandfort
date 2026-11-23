/** The typed error for a body read that broke or was cut by the caller, timeout or deadline. */

import {
  RequestAbortedError,
  RequestTimeoutError,
  TransportError,
  withRequestId,
} from "./errors.js";
import { DeadlineExceeded } from "./signals.js";

/**
 * The composed abort signal a stream response was fetched under, so a body-read failure can
 * read its `reason` on runtimes whose rejection drops it (Node 20.x / Undici 5 rejects with a
 * bare `AbortError` instead of the deadline reason).
 */
const STREAM_SIGNALS = new WeakMap<Response, AbortSignal>();

export function rememberStreamSignal(response: Response, signal: AbortSignal): void {
  STREAM_SIGNALS.set(response, signal);
}

function deadlineReason(response: Response | undefined): DeadlineExceeded | undefined {
  const reason: unknown = response === undefined ? undefined : STREAM_SIGNALS.get(response)?.reason;
  return reason instanceof DeadlineExceeded ? reason : undefined;
}

/**
 * `subject` names the stream in the message ("the log stream"). The caller's abort wins over
 * a deadline, and a deadline (a `DeadlineExceeded` reason) is told apart from the per-request
 * timeout, so the message names what actually fired.
 */
export function streamReadFailure(
  subject: string,
  cause: unknown,
  signal: AbortSignal | undefined,
  requestId: string | null,
  response?: Response,
): TransportError {
  if (signal?.aborted === true) {
    return new RequestAbortedError(withRequestId(`${subject} was aborted`, requestId), { cause });
  }
  if (cause instanceof DeadlineExceeded) {
    const message = `${subject} exceeded its deadline of ${cause.deadlineMs} ms`;
    return new RequestTimeoutError(withRequestId(message, requestId), { cause });
  }
  if (cause instanceof Error && cause.name === "TimeoutError") {
    return new RequestTimeoutError(withRequestId(`${subject} timed out`, requestId), { cause });
  }
  if (cause instanceof Error && cause.name === "AbortError") {
    // The caller's signal was checked above, so an abort here can only come from the SDK's own
    // timeout or deadline controller. On Node 20.x / Undici 5 a body read cut by that controller
    // rejects with a DOMException named AbortError instead of the abort reason, so the reason is
    // recovered from the remembered stream signal to keep the deadline named in the message.
    const deadline = deadlineReason(response);
    if (deadline !== undefined) {
      const message = `${subject} exceeded its deadline of ${deadline.deadlineMs} ms`;
      return new RequestTimeoutError(withRequestId(message, requestId), { cause });
    }
    return new RequestTimeoutError(withRequestId(`${subject} timed out`, requestId), { cause });
  }
  const detail = cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause);
  const message = `reading ${subject} failed: ${detail}`;
  return new TransportError(withRequestId(message, requestId), { cause });
}
