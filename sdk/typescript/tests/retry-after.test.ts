import { describe, expect, it } from "vitest";
import { parseRetryAfterS } from "../src/resilience.js";

const NOW = Date.parse("2026-11-11T10:00:00Z");

describe("Retry-After strictness", () => {
  it.each(["1.5", "-5", "+3", "soon", "", "5s", "0x10", "1e3"])(
    "uses the 1 s default for %j",
    (value) => {
      expect(parseRetryAfterS(value, NOW)).toBe(1);
    },
  );

  it("does not let Date.parse guess at date-looking junk", () => {
    expect(parseRetryAfterS("2026-11-11T10:00:09Z", NOW)).toBe(1);
    expect(parseRetryAfterS("Nov 11 2026 10:00:09", NOW)).toBe(1);
  });

  it("accepts whole seconds, with surrounding blanks", () => {
    expect(parseRetryAfterS("0", NOW)).toBe(0);
    expect(parseRetryAfterS(" 12 ", NOW)).toBe(12);
  });

  it("accepts an IMF-fixdate and clamps a past one to 0", () => {
    expect(parseRetryAfterS("Wed, 11 Nov 2026 10:00:09 GMT", NOW)).toBe(9);
    expect(parseRetryAfterS("Wed, 11 Nov 2026 09:59:00 GMT", NOW)).toBe(0);
  });
});
