import { describe, expect, it } from "vitest";
import { ApiError, NotFound, RateLimited, errorFor } from "../src/errors.js";

describe("errorFor", () => {
  it.each(["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"])(
    "treats the inherited name %s as an unknown code",
    (code) => {
      const error = errorFor({ code, message: "boom", status: 500 });

      expect(error).toBeInstanceOf(ApiError);
      expect(error.constructor).toBe(ApiError);
      expect(error.code).toBe(code);
      expect(error.message).toBe("boom");
    },
  );

  it("falls back to the status class when the code is an inherited name", () => {
    expect(errorFor({ code: "constructor", message: "m", status: 404 })).toBeInstanceOf(NotFound);
  });

  it("falls back to the generic error for a status that is an inherited name", () => {
    const error = errorFor({ code: undefined, message: "m", status: Number.NaN });

    expect(error.constructor).toBe(ApiError);
  });

  it("still maps known codes and statuses", () => {
    expect(errorFor({ code: "NOT_FOUND", message: "m", status: 400 })).toBeInstanceOf(NotFound);
    expect(errorFor({ code: undefined, message: "m", status: 429, retryAfterS: 3 })).toEqual(
      expect.objectContaining({ retryAfterS: 3 }),
    );
    expect(errorFor({ code: undefined, message: "m", status: 429 })).toBeInstanceOf(RateLimited);
  });
});
