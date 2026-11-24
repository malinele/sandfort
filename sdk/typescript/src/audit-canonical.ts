/**
 * The byte-exact forms the signed audit trailer depends on: Python's compact, sorted-key,
 * ASCII-only `json.dumps` (what the server signs) and the urlsafe base64 of keys and signatures.
 * Kept free of any other SDK code, as the python SDK keeps its copy free of server code.
 */

const MAX_DEPTH = 64;
const NON_ASCII_OR_DEL = /[\u007f-￿]/g;
const BASE64_FORM = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?$/;

/** A value the canonical form cannot reproduce byte for byte (the caller treats it as unsigned). */
export class CanonicalError extends Error {}

function hex4(unit: string): string {
  return `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`;
}

/** `json.dumps` of a string with `ensure_ascii=True`: DEL and every non-ASCII unit as `\uXXXX`. */
function quote(text: string): string {
  return JSON.stringify(text).replace(NON_ASCII_OR_DEL, hex4);
}

/** Order by code point, as python sorts keys (JS sorts by UTF-16 unit, which differs above U+FFFF). */
function compareCodePoints(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const x = a.codePointAt(i) ?? 0;
    const y = b.codePointAt(j) ?? 0;
    if (x !== y) return x < y ? -1 : 1;
    i += x > 0xffff ? 2 : 1;
    j += y > 0xffff ? 2 : 1;
  }
  if (i < a.length) return 1;
  return j < b.length ? -1 : 0;
}

function encode(value: unknown, depth: number): string {
  if (depth > MAX_DEPTH) throw new CanonicalError("nested too deeply");
  if (value === null) return "null";
  if (typeof value === "string") return quote(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    // Floats and integers beyond 2**53 would not print as python prints them.
    if (!Number.isSafeInteger(value)) throw new CanonicalError("number is not a safe integer");
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item: unknown) => encode(item, depth + 1)).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const parts = Object.keys(record)
      .sort(compareCodePoints)
      .map((key) => `${quote(key)}:${encode(record[key], depth + 1)}`);
    return `{${parts.join(",")}}`;
  }
  throw new CanonicalError("value is not JSON");
}

/** `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. */
export function canonicalJson(value: unknown): string {
  return encode(value, 0);
}

/**
 * Bytes of urlsafe base64 text (padding optional, whitespace around it ignored); `null` when the
 * text is not valid base64.
 */
export function decodeBase64Url(text: string): Uint8Array | null {
  const stripped = text.trim();
  const padded = stripped + "=".repeat((4 - (stripped.length % 4)) % 4);
  if (!BASE64_FORM.test(padded)) return null;
  return new Uint8Array(Buffer.from(padded, "base64url"));
}

/** The padded urlsafe base64 text of `raw`, as python's `urlsafe_b64encode` writes it. */
export function encodeBase64Url(raw: Uint8Array): string {
  return Buffer.from(raw).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}
