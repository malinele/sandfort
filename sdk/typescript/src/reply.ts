/** Reply decoding shared by the JSON `Transport` and the raw-body `BinaryChannel`. */

import { errorFor, type ApiError } from "./errors.js";
import { parseRetryAfterS } from "./resilience.js";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** `undefined` when `text` is not JSON. */
export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** Seconds a `429` asks the caller to wait (`Retry-After`; 1 when absent or unusable). */
export function retryAfter(response: Response): number {
  return parseRetryAfterS(response.headers.get("Retry-After"));
}

/**
 * The typed error for a non-success reply. `body` is the whole parsed reply: its `error`
 * object is used when present, otherwise the code is `HTTP_<status>` and the message the
 * status text.
 */
export function replyError(body: unknown, response: Response): ApiError {
  const envelope = isRecord(body) ? body["error"] : undefined;
  const error: Record<string, unknown> = isRecord(envelope) ? envelope : {};
  const details = error["details"];
  return errorFor({
    code: optionalString(error["code"]) ?? `HTTP_${response.status}`,
    message: optionalString(error["message"]) ?? (response.statusText || "request failed"),
    status: response.status,
    details: isRecord(details) ? details : undefined,
    requestId: optionalString(error["request_id"]) ?? response.headers.get("x-request-id") ?? undefined,
    retryAfterS: retryAfter(response),
  });
}
