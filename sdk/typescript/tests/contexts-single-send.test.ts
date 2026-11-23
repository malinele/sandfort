import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  RateLimited,
  RequestTimeoutError,
  type CodeContextEvent,
} from "../src/index.js";
import { clientFor, failure, ok, type Recorded } from "./helpers.js";
import { cellPayload, collect, frame } from "./contexts-helpers.js";

afterEach(() => vi.restoreAllMocks());

function capacity(): Response {
  return failure(503, "CAPACITY", { "retry-after": "1" });
}

function limited(): Response {
  return failure(429, "RATE_LIMITED", { "retry-after": "1" });
}

describe("a cell is never sent twice", () => {
  it("sends one request for run after a 429, though a second reply is queued", async () => {
    const { client, requests } = clientFor([limited(), ok(cellPayload())]);

    await expect(client.runInCodeContext("sbx_1", "ctx_a", "x += 1")).rejects.toBeInstanceOf(
      RateLimited,
    );
    expect(requests).toHaveLength(1);
  });

  it("sends one request for run after a 503 CAPACITY", async () => {
    const { client, requests } = clientFor([capacity(), ok(cellPayload())]);

    const error = await client.runInCodeContext("sbx_1", "ctx_a", "x += 1").catch((e) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("CAPACITY");
    expect(requests).toHaveLength(1);
  });

  it("sends one request for streamRun after a 429", async () => {
    const { client, requests } = clientFor([limited(), ok(cellPayload())]);

    const stream = collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"));

    await expect(stream).rejects.toBeInstanceOf(RateLimited);
    expect(requests).toHaveLength(1);
  });

  it("sends one request for streamRun after a 503 CAPACITY", async () => {
    const { client, requests } = clientFor([capacity(), ok(cellPayload())]);

    const error = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x")).catch((e) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("CAPACITY");
    expect(requests).toHaveLength(1);
  });

  it("does not sleep before giving up, since nothing is retried", async () => {
    const pauses: number[] = [];
    const sleep = (ms: number): Promise<void> => {
      pauses.push(ms);
      return Promise.resolve();
    };
    const { client } = clientFor([limited()], { sleep });

    const run = client.runInCodeContext("sbx_1", "ctx_a", "x");

    await expect(run).rejects.toBeInstanceOf(RateLimited);
    expect(pauses).toEqual([]);
  });
});

/** Spy on `AbortSignal.timeout`, remembering each requested delay and firing it at once. */
function recordTimeouts(): number[] {
  const delays: number[] = [];
  const real = AbortSignal.timeout.bind(AbortSignal);
  vi.spyOn(AbortSignal, "timeout").mockImplementation((ms: number) => {
    delays.push(ms);
    return real(2_000_000_000);
  });
  return delays;
}

describe("the request timeout of a run", () => {
  it("is timeoutS * 2000 + 10000 ms for run", async () => {
    const delays = recordTimeouts();
    const { client } = clientFor([ok(cellPayload())]);

    await client.runInCodeContext("sbx_1", "ctx_a", "1", { timeoutS: 100 });

    expect(delays).toEqual([210_000]);
  });

  it("is 130000 ms for run with the default 60 second cell limit", async () => {
    const delays = recordTimeouts();
    const { client } = clientFor([ok(cellPayload())]);

    await client.runInCodeContext("sbx_1", "ctx_a", "1");

    expect(delays).toEqual([130_000]);
  });

  it("is timeoutS * 2000 + 10000 ms for streamRun", async () => {
    const delays = recordTimeouts();
    const body = frame("result", cellPayload());
    const { client } = clientFor([sseOf(body)]);

    await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "1", { timeoutS: 100 }));

    expect(delays).toEqual([210_000]);
  });

  it("never lowers the client's own larger timeout", async () => {
    const delays = recordTimeouts();
    const { client } = clientFor([ok(cellPayload())], { timeoutMs: 500_000 });

    await client.runInCodeContext("sbx_1", "ctx_a", "1", { timeoutS: 5 });

    expect(delays).toEqual([500_000]);
  });
});

function sseOf(text: string): Response {
  return new Response(text, { status: 200, headers: { "content-type": "text/event-stream" } });
}

/** A stream whose head arrives at once and whose body then errors with the abort reason. */
function stallingBody(request: Recorded): Response {
  const signal = request.signal;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      const stop = (): void => controller.error(signal?.reason);
      if (signal?.aborted === true) stop();
      else signal?.addEventListener("abort", stop, { once: true });
    },
  });
  return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
}

describe("the timeout while the body is read", () => {
  it("surfaces RequestTimeoutError when the stream stalls after the response head", async () => {
    const real = AbortSignal.timeout.bind(AbortSignal);
    vi.spyOn(AbortSignal, "timeout").mockImplementation(() => real(40));
    const { client } = clientFor([stallingBody]);
    const seen: CodeContextEvent[] = [];

    const run = async (): Promise<void> => {
      for await (const event of client.streamCodeContextRun("sbx_1", "ctx_a", "x")) {
        seen.push(event);
      }
    };

    await expect(run()).rejects.toBeInstanceOf(RequestTimeoutError);
    expect(seen).toEqual([]);
  });
});
