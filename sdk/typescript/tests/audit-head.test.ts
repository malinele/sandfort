import { describe, expect, it } from "vitest";
import { ValidationError, verifyHead } from "../src/index.js";
import { GOLDEN, chain, head, newSigner } from "./audit-trailer-helpers.js";

const line = (patch: Record<string, unknown>, base: string = GOLDEN.head): string =>
  JSON.stringify({ ...(JSON.parse(base) as object), ...patch });

describe("verifyHead against a head written by the server", () => {
  it("verifies the golden head, including non-ASCII filters and DEL in the rows' text", () => {
    const result = verifyHead(GOLDEN.head, GOLDEN.publicKey);

    expect(result).toEqual({
      ok: true,
      rowId: "evt_2",
      entryHash: `h02${"a".repeat(60)}`,
      publicKey: GOLDEN.publicKey,
      reason: null,
      signedAt: new Date("2026-11-11T04:52:33+00:00"),
    });
  });

  it("verifies the golden filtered head (sorted `filters`, `\\u00ef` escaped like python)", () => {
    expect(verifyHead(GOLDEN.filteredHead, GOLDEN.publicKey).ok).toBe(true);
  });

  it("accepts the key as standard base64, unpadded text or the 32 raw bytes", () => {
    const raw = new Uint8Array(Buffer.from(GOLDEN.publicKey, "base64url"));
    const standard = Buffer.from(raw).toString("base64");
    const unpadded = GOLDEN.publicKey.replace(/=+$/, "");

    for (const key of [standard, unpadded, raw, `  ${GOLDEN.publicKey}\n`]) {
      const result = verifyHead(GOLDEN.head, key);
      expect(result.ok).toBe(true);
      expect(result.publicKey).toBe(GOLDEN.publicKey);
    }
  });

  it("takes the head as an object as well as a line", () => {
    expect(verifyHead(JSON.parse(GOLDEN.head) as Record<string, unknown>, GOLDEN.publicKey).ok).toBe(true);
  });

  it("does not cover the hmac: changing it leaves the signature valid", () => {
    expect(verifyHead(line({ hmac: "f".repeat(64) }), GOLDEN.publicKey).ok).toBe(true);
  });
});

describe("verifyHead with an injected __proto__ member", () => {
  it("refuses a signed head that gained a top-level `__proto__` member", () => {
    const injected = GOLDEN.head.replace("{", '{"__proto__":{"x":1},');

    expect(Object.hasOwn(JSON.parse(injected) as object, "__proto__")).toBe(true);
    for (const input of [injected, JSON.parse(injected) as Record<string, unknown>]) {
      const result = verifyHead(input, GOLDEN.publicKey);

      expect(result.ok).toBe(false);
      expect(result.reason).toBe("signature");
    }
  });
});

describe("verifyHead refusals", () => {
  it.each([
    ["row_id", { row_id: "evt_9" }],
    ["hash", { hash: "other" }],
    ["signed_at", { signed_at: "2026-11-11T04:52:34+00:00" }],
    ["export_sha256", { export_sha256: "0".repeat(64) }],
    ["org_id", { org_id: "org_2" }],
    ["an added field", { extra: 1 }],
  ])("a tampered %s fails the signature", (_name, patch) => {
    const result = verifyHead(line(patch), GOLDEN.publicKey);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("signature");
  });

  it("a removed signed_at or binding breaks the signature", () => {
    const { signed_at: _a, ...noDate } = JSON.parse(GOLDEN.head) as Record<string, unknown>;
    const { row_count: _b, first_row_id: _c, export_sha256: _d, ...noBinding } = JSON.parse(
      GOLDEN.head,
    ) as Record<string, unknown>;

    expect(verifyHead(JSON.stringify(noDate), GOLDEN.publicKey).reason).toBe("signature");
    expect(verifyHead(JSON.stringify(noBinding), GOLDEN.publicKey).reason).toBe("signature");
  });

  it("reports an unsigned head (no signature or no alg)", () => {
    const { signature: _s, ...noSignature } = JSON.parse(GOLDEN.head) as Record<string, unknown>;
    const { alg: _a, ...noAlg } = JSON.parse(GOLDEN.head) as Record<string, unknown>;

    expect(verifyHead(JSON.stringify(noSignature), GOLDEN.publicKey).reason).toBe("unsigned");
    expect(verifyHead(JSON.stringify(noAlg), GOLDEN.publicKey).reason).toBe("unsigned");
    expect(verifyHead(line({ signature: "" }), GOLDEN.publicKey).reason).toBe("unsigned");
  });

  it("refuses another algorithm and a non-text or malformed signature as a bad signature", () => {
    expect(verifyHead(line({ alg: "rsa" }), GOLDEN.publicKey).reason).toBe("signature");
    expect(verifyHead(line({ signature: 5 }), GOLDEN.publicKey).reason).toBe("signature");
    expect(verifyHead(line({ signature: "!!" }), GOLDEN.publicKey).reason).toBe("signature");
    expect(verifyHead(line({ signature: "AAAA" }), GOLDEN.publicKey).reason).toBe("signature");
  });

  it("never trusts the key the line names: a forger's own key gives key_mismatch", () => {
    const forger = newSigner();
    const { lines } = chain(2);
    const forged = head(lines, forger);

    const result = verifyHead(forged, GOLDEN.publicKey);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("key_mismatch");
    expect(result.publicKey).toBe(GOLDEN.publicKey);
    expect(verifyHead(forged, forger.publicKey).ok).toBe(true);
  });

  it("treats a malformed named key as a mismatch and an absent one as a signature failure", () => {
    expect(verifyHead(line({ public_key: "not a key" }), GOLDEN.publicKey).reason).toBe("key_mismatch");
    expect(verifyHead(line({ public_key: "" }), GOLDEN.publicKey).reason).toBe("signature");
  });

  it("another trusted key fails the golden head as key_mismatch", () => {
    expect(verifyHead(GOLDEN.head, newSigner().publicKey).reason).toBe("key_mismatch");
  });
});

describe("verifyHead signed_at", () => {
  const signer = newSigner();
  const lines = chain(1).lines;
  const withDate = (signed_at: unknown): string => head(lines, signer, { signed_at });

  it("is undated when absent, naive, malformed, impossible or before 1970-01-02", () => {
    const cases: unknown[] = [
      undefined,
      "2026-11-11T04:00:00",
      "2026-11-11",
      "yesterday",
      "2026-02-31T04:00:00+00:00",
      "2026-11-11T24:00:00+00:00",
      "1970-01-01T12:00:00+00:00",
      7,
    ];
    for (const bad of cases) {
      const result = verifyHead(withDate(bad), signer.publicKey);

      expect(result.reason, String(bad)).toBe("undated");
      expect(result.signedAt).toBeNull();
    }
  });

  it("accepts Z, fractions and numeric offsets", () => {
    for (const ok of ["2026-11-11T04:00:00Z", "2026-11-11T04:00:00.123456+00:00", "2026-11-11T06:00:00+0200"]) {
      const result = verifyHead(withDate(ok), signer.publicKey);
      expect(result.ok, ok).toBe(true);
      expect(result.signedAt?.toISOString().slice(0, 16)).toBe("2026-11-11T04:00");
    }
  });

  it("refuses a head dated more than 5 minutes ahead and accepts 4 minutes ahead", () => {
    const iso = (offsetMs: number): string => new Date(Date.now() + offsetMs).toISOString().replace(/\.\d+Z$/, "+00:00");

    expect(verifyHead(withDate(iso(10 * 60_000)), signer.publicKey).reason).toBe("future_signed_at");
    expect(verifyHead(withDate(iso(4 * 60_000)), signer.publicKey).ok).toBe(true);
  });
});

describe("verifyHead input errors", () => {
  it.each([
    ["not JSON", "{nope"],
    ["a JSON array", "[1]"],
    ["a JSON string", '"x"'],
    ["another type", JSON.stringify({ type: "export_summary", rows: 1, filters: [] })],
    ["an empty row_id", line({ row_id: "" })],
    ["a missing hash", JSON.stringify({ type: "audit_head", row_id: "a" })],
    ["a partial binding", line({ row_count: undefined })],
    ["a bad digest length", line({ export_sha256: "ab" })],
    ["a negative count", line({ row_count: -1 })],
    ["a fractional count", line({ row_count: 1.5 })],
    ["an empty first_row_id", line({ first_row_id: "" })],
    ["filtered without filters", line({ filtered: true })],
    ["filtered false", line({ filtered: false, filters: {} })],
    ["non-text filter values", line({ filtered: true, filters: { outcome: 3 } })],
  ])("throws ValidationError for %s", (_name, input) => {
    expect(() => verifyHead(input, GOLDEN.publicKey)).toThrow(ValidationError);
  });

  it("survives a line nested very deeply without a stack overflow", () => {
    const deep = `{"type":"audit_head","row_id":"a","hash":"b","x":${"[".repeat(200_000)}${"]".repeat(200_000)}}`;

    expect(verifyHead(deep, GOLDEN.publicKey).reason).toBe("unsigned");
  });

  it("a head nested beyond the canonical limit fails the signature, not the process", () => {
    const nested = JSON.parse(`{"a":${"[".repeat(500)}${"]".repeat(500)}}`) as unknown;

    const result = verifyHead(line({ x: nested }), GOLDEN.publicKey);

    expect(result.reason).toBe("signature");
  });

  it.each([
    ["a key of the wrong length", "AAAA"],
    ["text that is not base64", "!!!!"],
    ["raw bytes of the wrong length", new Uint8Array(31)],
    ["an empty key", ""],
  ])("throws ValidationError for %s", (_name, key) => {
    expect(() => verifyHead(GOLDEN.head, key)).toThrow(ValidationError);
  });

  it("throws ValidationError when the key is missing", () => {
    expect(() => verifyHead(GOLDEN.head, undefined as never)).toThrow(/trusted public key is required/);
  });
});
