import { describe, expect, it } from "vitest";
import {
  ApiError,
  NotFound,
  RateLimited,
  RequestAbortedError,
  RequestTimeoutError,
  SandfortError,
  TransportError,
  ValidationError,
} from "../src/index.js";
import {
  DEFAULT_RETRIES,
  DEFAULT_TIMEOUT_MS,
  MAX_RETRY_AFTER_S,
  parseRetryAfterS,
  retryPauseS,
} from "../src/resilience.js";
import {
  at,
  clientFor,
  failure,
  hangUntilAborted,
  ok,
  recordingSleep,
  sandboxPayload,
} from "./helpers.js";

describe("defaults", () => {
  it("uses a 60 s timeout and 2 retries", () => {
    expect(DEFAULT_TIMEOUT_MS).toBe(60_000);
    expect(DEFAULT_RETRIES).toBe(2);
    expect(MAX_RETRY_AFTER_S).toBe(30);
  });

  it("gives every request an abort signal", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await client.getSandbox("sbx_1");

    expect(at(requests, 0).signal).toBeInstanceOf(AbortSignal);
  });

  it("rejects an invalid timeoutMs or retries with a ValidationError", () => {
    expect(() => clientFor([], { timeoutMs: 0 })).toThrow(ValidationError);
    expect(() => clientFor([], { timeoutMs: 1.5 })).toThrow(ValidationError);
    expect(() => clientFor([], { retries: -1 })).toThrow(ValidationError);
    expect(() => clientFor([], { retries: 11 })).toThrow(ValidationError);
  });
});

describe("timeout and abort", () => {
  it("times out a request that never answers, as RequestTimeoutError", async () => {
    const { client } = clientFor([hangUntilAborted], { timeoutMs: 20 });

    const error: unknown = await client.getSandbox("sbx_1").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(RequestTimeoutError);
    expect(error).toBeInstanceOf(TransportError);
    expect((error as Error).message).toContain("timed out after 20 ms");
  });

  it("does not retry a timeout", async () => {
    const { client, requests } = clientFor([hangUntilAborted, ok(sandboxPayload())], {
      timeoutMs: 20,
    });

    await expect(client.getSandbox("sbx_1")).rejects.toBeInstanceOf(RequestTimeoutError);
    expect(requests).toHaveLength(1);
  });

  it("aborts a call through the per-call signal", async () => {
    const { client } = clientFor([hangUntilAborted]);
    const controller = new AbortController();

    const pending = client.getSandbox("sbx_1", { signal: controller.signal });
    setTimeout(() => controller.abort(), 10);

    const error: unknown = await pending.catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RequestAbortedError);
    expect(error).toBeInstanceOf(SandfortError);
  });

  it("sends nothing when the signal is already aborted", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await expect(client.getSandbox("sbx_1", { signal: AbortSignal.abort() })).rejects.toBeInstanceOf(
      RequestAbortedError,
    );
    expect(requests).toHaveLength(0);
  });

  it("carries the per-call signal on list, create, exec and fs calls", async () => {
    const { client, requests } = clientFor([
      ok([]),
      ok(sandboxPayload()),
      ok({ exit_code: 0, stdout: "", stderr: "", timed_out: false, truncated: false, duration_ms: 1 }),
    ]);
    const controller = new AbortController();
    const { signal } = controller;

    await client.listSandboxes({ signal });
    const sandbox = await client.createSandbox({ signal, wait: false });
    await sandbox.processExec("true", { signal });
    controller.abort();

    expect(requests.map((r) => r.signal?.aborted)).toEqual([true, true, true]);
  });

  it("does not let the client timeout cut short an exec the server may hold longer", async () => {
    const slow = async (): Promise<Response> => {
      await new Promise((resolve) => setTimeout(resolve, 80));
      return ok({ exit_code: 0, stdout: "", stderr: "", timed_out: false, truncated: false, duration_ms: 1 });
    };
    const { client } = clientFor([ok(sandboxPayload()), slow], { timeoutMs: 20 });
    const sandbox = await client.getSandbox("sbx_1");

    const result = await sandbox.processExec("sleep 1", { timeoutS: 60 });

    expect(result.exitCode).toBe(0);
  });
});

describe("retries", () => {
  it("resends a GET after a 429 and honours Retry-After", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(429, "RATE_LIMITED", { "Retry-After": "3" }), ok(sandboxPayload())],
      { sleep },
    );

    const sandbox = await client.getSandbox("sbx_1");

    expect(sandbox.id).toBe("sbx_1");
    expect(requests).toHaveLength(2);
    expect(pauses).toEqual([3000]);
  });

  it("caps a long Retry-After at 30 s", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client } = clientFor(
      [failure(429, "RATE_LIMITED", { "Retry-After": "600" }), ok(sandboxPayload())],
      { sleep },
    );

    await client.getSandbox("sbx_1");

    expect(pauses).toEqual([30_000]);
  });

  it("resends after a 503 CAPACITY with jittered backoff, longer of that and Retry-After", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client } = clientFor(
      [failure(503, "CAPACITY"), failure(503, "CAPACITY", { "Retry-After": "5" }), ok(sandboxPayload())],
      { sleep },
    );

    await client.getSandbox("sbx_1");

    const [first, second] = pauses;
    expect(first).toBeGreaterThanOrEqual(250);
    expect(first).toBeLessThanOrEqual(500);
    expect(second).toBe(5000);
  });

  it("gives up after `retries` resends and throws the last error", async () => {
    const { sleep, pauses } = recordingSleep();
    const queue = [1, 2, 3].map(() => failure(429, "RATE_LIMITED", { "Retry-After": "1" }));
    const { client, requests } = clientFor(queue, { sleep });

    const error: unknown = await client.getSandbox("sbx_1").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(RateLimited);
    expect(requests).toHaveLength(3);
    expect(pauses).toEqual([1000, 1000]);
  });

  it("retries: 0 turns retries off", async () => {
    const { client, requests } = clientFor([failure(429, "RATE_LIMITED"), ok(sandboxPayload())], {
      retries: 0,
    });

    await expect(client.getSandbox("sbx_1")).rejects.toBeInstanceOf(RateLimited);
    expect(requests).toHaveLength(1);
  });

  it("bounds the total wait of one call", async () => {
    const { sleep, pauses } = recordingSleep();
    const queue = [1, 2, 3, 4, 5].map(() => failure(429, "RATE_LIMITED", { "Retry-After": "30" }));
    const { client, requests } = clientFor(queue, { sleep, retries: 10 });

    await expect(client.getSandbox("sbx_1")).rejects.toBeInstanceOf(RateLimited);

    expect(pauses).toEqual([30_000, 30_000]);
    expect(requests).toHaveLength(3);
  });

  it.each([
    ["a 429 QUOTA_EXCEEDED", failure(429, "QUOTA_EXCEEDED")],
    ["a 503 with another code", failure(503, "NODE_UNAVAILABLE")],
    ["a 500", failure(500, "INTERNAL")],
    ["a 404", failure(404, "NOT_FOUND")],
    ["a 409", failure(409, "CONFLICT")],
  ])("never retries %s", async (_label, response) => {
    const { sleep, pauses } = recordingSleep();
    const { client, requests } = clientFor([response, ok(sandboxPayload())], { sleep });

    await expect(client.getSandbox("sbx_1")).rejects.toBeInstanceOf(ApiError);
    expect(requests).toHaveLength(1);
    expect(pauses).toEqual([]);
  });

  it("never retries a network failure", async () => {
    const { client, requests } = clientFor([new TypeError("fetch failed"), ok(sandboxPayload())]);

    await expect(client.getSandbox("sbx_1")).rejects.toBeInstanceOf(TransportError);
    expect(requests).toHaveLength(1);
  });

  it("does not resend a POST without an idempotency key", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(503, "CAPACITY"), ok(sandboxPayload())],
      { sleep },
    );

    await expect(client.createSandbox({ wait: false })).rejects.toBeInstanceOf(ApiError);
    expect(requests).toHaveLength(1);
    expect(pauses).toEqual([]);
  });

  it("resends a create that carries an Idempotency-Key, with the same key", async () => {
    const { sleep } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(503, "CAPACITY"), ok(sandboxPayload("creating"))],
      { sleep },
    );

    const sandbox = await client.createSandbox({ idempotencyKey: "key-1", wait: false });

    expect(sandbox.id).toBe("sbx_1");
    expect(requests.map((r) => r.headers.get("Idempotency-Key"))).toEqual(["key-1", "key-1"]);
    expect(requests[1]?.body).toBe(requests[0]?.body);
  });

  it("rejects a blank idempotency key before sending", async () => {
    const { client, requests } = clientFor([]);

    await expect(client.createSandbox({ idempotencyKey: " " })).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("resends a DELETE (idempotent) after a 429", async () => {
    const { sleep } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(429, "RATE_LIMITED"), ok(sandboxPayload("destroying"))],
      { sleep },
    );

    await client.deleteSandbox("sbx_1");

    expect(requests.map((r) => r.method)).toEqual(["DELETE", "DELETE"]);
  });

  it("aborts during a Retry-After pause", async () => {
    const { client, requests } = clientFor([
      failure(429, "RATE_LIMITED", { "Retry-After": "30" }),
      ok(sandboxPayload()),
    ]);
    const controller = new AbortController();

    const pending = client.getSandbox("sbx_1", { signal: controller.signal });
    setTimeout(() => controller.abort(), 20);

    await expect(pending).rejects.toBeInstanceOf(RequestAbortedError);
    expect(requests).toHaveLength(1);
  });

  it("keeps a read-through error as NotFound, not a transport error", async () => {
    const { client } = clientFor([failure(404, "NOT_FOUND")]);

    await expect(client.getSandbox("sbx_1")).rejects.toBeInstanceOf(NotFound);
  });
});

describe("retries on the binary channel", () => {
  it("resends a download after a 503 CAPACITY and returns the bytes", async () => {
    const { sleep, pauses } = recordingSleep();
    const { client, requests } = clientFor(
      [ok(sandboxPayload()), failure(503, "CAPACITY", { "Retry-After": "2" }), new Response(new Uint8Array([1, 2, 3]))],
      { sleep },
    );
    const sandbox = await client.getSandbox("sbx_1");

    const bytes = await sandbox.fs.downloadFile("/a.bin");

    expect(Array.from(bytes)).toEqual([1, 2, 3]);
    expect(requests).toHaveLength(3);
    expect(pauses).toEqual([2000]);
  });

  it("resends an upload (PUT) after a 429 with the same body", async () => {
    const { sleep } = recordingSleep();
    const { client, requests } = clientFor(
      [ok(sandboxPayload()), failure(429, "RATE_LIMITED"), ok({ path: "/a", size_bytes: 3 })],
      { sleep },
    );
    const sandbox = await client.getSandbox("sbx_1");

    const result = await sandbox.fs.uploadFile("/a", new Uint8Array([1, 2, 3]));

    expect(result.sizeBytes).toBe(3);
    expect(requests.map((r) => r.method)).toEqual(["GET", "PUT", "PUT"]);
  });

  it("surfaces a non-retryable 429 error body intact", async () => {
    const { client } = clientFor([ok(sandboxPayload()), failure(429, "QUOTA_EXCEEDED", {}, "quota")]);
    const sandbox = await client.getSandbox("sbx_1");

    const error: unknown = await sandbox.fs.downloadFile("/a").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(RateLimited);
    expect((error as RateLimited).message).toBe("quota");
    expect((error as RateLimited).code).toBe("QUOTA_EXCEEDED");
  });

  it("times out a download that never answers", async () => {
    const { client } = clientFor([ok(sandboxPayload()), hangUntilAborted], { timeoutMs: 20 });
    const sandbox = await client.getSandbox("sbx_1");

    await expect(sandbox.fs.downloadFile("/a")).rejects.toBeInstanceOf(RequestTimeoutError);
  });
});

describe("Retry-After parsing", () => {
  it("reads delta-seconds, HTTP dates and falls back to 1 s", () => {
    const now = Date.parse("2026-11-11T10:00:00Z");

    expect(parseRetryAfterS("7")).toBe(7);
    expect(parseRetryAfterS("Wed, 11 Nov 2026 10:00:09 GMT", now)).toBe(9);
    expect(parseRetryAfterS("Wed, 11 Nov 2026 09:00:00 GMT", now)).toBe(0);
    expect(parseRetryAfterS("soon")).toBe(1);
    expect(parseRetryAfterS(null)).toBe(1);
  });

  it("computes pauses only for 429 and 503 CAPACITY", () => {
    expect(retryPauseS({ status: 429, code: "RATE_LIMITED", retryAfter: "4" }, 0)).toBe(4);
    expect(retryPauseS({ status: 503, code: "CAPACITY", retryAfter: null }, 1, () => 1)).toBe(1);
    expect(retryPauseS({ status: 503, code: "CAPACITY", retryAfter: null }, 20, () => 0)).toBe(4);
    expect(retryPauseS({ status: 503, code: "OTHER", retryAfter: null }, 0)).toBeUndefined();
    expect(retryPauseS(undefined, 0)).toBeUndefined();
  });
});
