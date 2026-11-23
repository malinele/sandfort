/** Client-side argument checks; every failure is a `ValidationError` and nothing is sent. */

import { ValidationError } from "./errors.js";

export const MIN_EXEC_TIMEOUT_S = 1;
export const MAX_EXEC_TIMEOUT_S = 3600;

export function fail(message: string): never {
  throw new ValidationError(message);
}

function describeType(value: unknown): string {
  return value === null ? "null" : typeof value;
}

export function requireNonBlank(value: string, label: string): void {
  if (typeof value !== "string") fail(`${label} must be a string, got ${describeType(value)}`);
  if (value.trim() === "") fail(`${label} must not be empty`);
}

/** An integer in `[min, max]`; `label` names the option in the message. */
export function requireInteger(value: number, label: string, min: number, max: number): void {
  if (!Number.isInteger(value)) fail(`${label} must be a whole number, got ${String(value)}`);
  if (value < min || value > max) fail(`${label} must be between ${min} and ${max}`);
}

/** A server-side exec limit: whole seconds, as the API schema requires. */
export function requireTimeoutS(value: number, label = "timeoutS"): void {
  requireInteger(value, label, MIN_EXEC_TIMEOUT_S, MAX_EXEC_TIMEOUT_S);
}

/** A positive, finite number (seconds, usually); `label` names the option in the message. */
export function requirePositiveFinite(value: number, label: string): void {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    fail(`${label} must be a positive finite number, got ${String(value)}`);
  }
}

/** Characters Docker's bind syntax (`src:dst:mode,opt`) reads as separators, as the server does. */
const BIND_SYNTAX_CHARACTERS: Readonly<Record<string, string>> = {
  ":": "colon",
  ",": "comma",
  "\\": "backslash",
};

/**
 * The server's mount path character and absolute-path rules; the directory lists stay with the
 * server. The offending character is named and shown escaped, never raw.
 */
export function requireMountPath(path: string, label: string): void {
  for (const char of path) {
    const name = BIND_SYNTAX_CHARACTERS[char];
    if (name !== undefined) {
      fail(`${label} must not contain a ${name} (${JSON.stringify(char)}; docker bind syntax)`);
    }
  }
  if (!path.startsWith("/")) fail(`${label} must be an absolute path (start with '/')`);
}

/** An optional text filter: when given it must be a non-blank string. */
export function requireOptionalNonBlank(value: string | undefined, label: string): void {
  if (value !== undefined) requireNonBlank(value, label);
}

/** A point in time as ISO 8601 UTC (what the API's `from`/`to`/`expires_at` take). */
export function momentIso(value: Date, label: string): string {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    fail(`${label} must be a valid Date`);
  }
  return value.toISOString();
}

/** The `limit` of a list call: a whole number from 1 to 100 when given. */
export function requireListLimit(value: number | undefined): void {
  if (value !== undefined) requireInteger(value, "limit", 1, 100);
}

/** Every entry of `values` must be a non-blank string; a lone string is refused. */
export function requireStringList(values: readonly string[], label: string): void {
  if (!Array.isArray(values)) fail(`${label} must be an array of strings`);
  for (const value of values) requireNonBlank(value, `${label} entry`);
}
