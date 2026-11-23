import { describe, expect, it } from "vitest";
import {
  RateLimited,
  RequestAbortedError,
  RequestTimeoutError,
  ValidationError,
} from "../src/index.js";
import {
  clientFor,
  failure,
  hangUntilAborted,
  ok,
  recordingSleep,
  sandboxPayload,
} from "./helpers.js";

describe("per-call timeoutMs", () => {
  it("overrides a long client timeout and surfaces as RequestTimeoutError", async () => {
    const { client } = clientFor([hangUntilAborted], { timeoutMs: 60_000, retries: 0 });

    const started = Date.now();
    const failed = client.getSandbox("sbx_1", { timeoutMs: 20 });

    await expect(failed).rejects.toBeInstanceOf(RequestTimeoutError);
    await expect(failed).rejects.toThrow(/timed out after 20 ms/);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("leaves the client-wide value alone for the next call", async () => {
    const slow = async (): Promise<Response> => {
      await new Promise((resolve) => setTimeout(resolve, 60));
      return ok(sandboxPayload());
    };
    const { client } = clientFor([hangUntilAborted, slow], { timeoutMs: 5_000, retries: 0 });

    await expect(client.getSandbox("sbx_1", { timeoutMs: 10 })).rejects.toBeInstanceOf(
      RequestTimeoutError,
    );
    await expect(client.getSandbox("sbx_1")).resolves.toBeDefined();
  });

  it("applies to the new operations", async () => {
    const { client } = clientFor([hangUntilAborted], { retries: 0 });

    await expect(client.resetSandbox("sbx_1", { timeoutMs: 20 })).rejects.toBeInstanceOf(
      RequestTimeoutError,
    );
  });

  it("applies to session calls and file calls on a sandbox", async () => {
    const { client } = clientFor([ok(sandboxPayload()), hangUntilAborted, hangUntilAborted], {
      retries: 0,
    });
    const sandbox = await client.getSandbox("sbx_1");

    await expect(sandbox.listSessions({ timeoutMs: 20 })).rejects.toBeInstanceOf(
      RequestTimeoutError,
    );
    await expect(sandbox.fs.downloadFile("/x", { timeoutMs: 20 })).rejects.toBeInstanceOf(
      RequestTimeoutError,
    );
  });

  it("still reports a caller abort as RequestAbortedError", async () => {
    const controller = new AbortController();
    const { client } = clientFor([hangUntilAborted], { retries: 0 });

    const failed = client.getSandbox("sbx_1", { signal: controller.signal, timeoutMs: 60_000 });
    controller.abort();

    await expect(failed).rejects.toBeInstanceOf(RequestAbortedError);
  });

  it.each([0, -1, 1.5, Number.NaN])("rejects timeoutMs %s with ValidationError", async (value) => {
    const { client, requests } = clientFor([]);

    await expect(client.getSandbox("sbx_1", { timeoutMs: value })).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(requests).toHaveLength(0);
  });
});

describe("per-call retries", () => {
  it("turns retries off for one call although the client retries", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(429, "RATE_LIMITED", { "Retry-After": "1" }), ok(sandboxPayload())],
      { sleep, retries: 2 },
    );

    await expect(client.getSandbox("sbx_1", { retries: 0 })).rejects.toBeInstanceOf(RateLimited);
    expect(requests).toHaveLength(1);
    expect(pauses).toEqual([]);
  });

  it("turns retries on for one call although the client has them off", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(429, "RATE_LIMITED", { "Retry-After": "1" }), ok(sandboxPayload())],
      { sleep, retries: 0 },
    );

    const sandbox = await client.getSandbox("sbx_1", { retries: 1 });

    expect(sandbox.id).toBe("sbx_1");
    expect(requests).toHaveLength(2);
    expect(pauses).toEqual([1000]);
  });

  it.each([-1, 11, 1.5])("rejects retries %s with ValidationError", async (value) => {
    const { client } = clientFor([]);

    await expect(client.getSandbox("sbx_1", { retries: value })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });
});

describe("per-call deadlineMs", () => {
  it("cuts one call short while the client has no deadline", async () => {
    const { client } = clientFor([hangUntilAborted], { timeoutMs: 60_000, retries: 0 });

    const failed = client.getSandbox("sbx_1", { deadlineMs: 25 });

    await expect(failed).rejects.toBeInstanceOf(RequestTimeoutError);
    await expect(failed).rejects.toThrow(/deadline of 25 ms/);
  });

  it("replaces the client deadline for the call", async () => {
    const { client } = clientFor([ok(sandboxPayload())], { deadlineMs: 1 });

    await expect(client.getSandbox("sbx_1", { deadlineMs: 60_000 })).resolves.toBeDefined();
  });

  it("does not start a retry pause that would pass the per-call deadline", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(429, "RATE_LIMITED", { "Retry-After": "20" }), ok(sandboxPayload())],
      { sleep },
    );

    await expect(client.getSandbox("sbx_1", { deadlineMs: 5_000 })).rejects.toBeInstanceOf(
      RateLimited,
    );
    expect(requests).toHaveLength(1);
    expect(pauses).toEqual([]);
  });

  it.each([0, 1.5])("rejects deadlineMs %s with ValidationError", async (value) => {
    const { client } = clientFor([]);

    await expect(client.getSandbox("sbx_1", { deadlineMs: value })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });
});
