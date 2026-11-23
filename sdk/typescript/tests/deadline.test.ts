import { describe, expect, it } from "vitest";
import { RateLimited, RequestAbortedError, RequestTimeoutError, ValidationError } from "../src/index.js";
import { clientFor, failure, hangUntilAborted, ok, recordingSleep, sandboxPayload } from "./helpers.js";

describe("deadlineMs", () => {
  it.each([0, -5, 1.5, Number.NaN])("rejects %s", (deadlineMs) => {
    expect(() => clientFor([], { deadlineMs })).toThrow(ValidationError);
  });

  it("cuts a call short before the per-request timeout", async () => {
    const { client } = clientFor([hangUntilAborted], { timeoutMs: 60_000, deadlineMs: 30 });

    const started = Date.now();
    const failed = client.getSandbox("sbx_1");

    await expect(failed).rejects.toBeInstanceOf(RequestTimeoutError);
    await expect(failed).rejects.toThrow(/deadline of 30 ms/);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("does not start a pause that would run past the deadline", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(429, "RATE_LIMITED", { "Retry-After": "20" }), ok(sandboxPayload())],
      { sleep, deadlineMs: 5_000 },
    );

    await expect(client.getSandbox("sbx_1")).rejects.toBeInstanceOf(RateLimited);
    expect(requests).toHaveLength(1);
    expect(pauses).toEqual([]);
  });

  it("still retries when the pause fits in the deadline", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(429, "RATE_LIMITED", { "Retry-After": "2" }), ok(sandboxPayload())],
      { sleep, deadlineMs: 60_000 },
    );

    await client.getSandbox("sbx_1");

    expect(requests).toHaveLength(2);
    expect(pauses).toEqual([2000]);
  });

  it("lets the caller's abort win over the deadline", async () => {
    const { client } = clientFor([hangUntilAborted], { deadlineMs: 60_000 });
    const controller = new AbortController();

    const pending = client.getSandbox("sbx_1", { signal: controller.signal });
    controller.abort();

    await expect(pending).rejects.toBeInstanceOf(RequestAbortedError);
  });
});
