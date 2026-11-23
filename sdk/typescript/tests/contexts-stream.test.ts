import { describe, expect, it } from "vitest";
import {
  InvalidResponseError,
  NotFound,
  RequestAbortedError,
  TransportError,
  ValidationError,
  type CellResult,
} from "../src/index.js";
import { at, clientFor, failure } from "./helpers.js";
import { BASE, cellPayload, collect, frame, sse } from "./contexts-helpers.js";

const STREAM_TYPE = { "content-type": "text/event-stream" };

describe("streamCodeContextRun", () => {
  it("yields the output chunks and ends with the cell result", async () => {
    const { client, requests } = clientFor([
      sse([
        frame("stdout", { data: "a\n" }),
        frame("stderr", { data: "warn\n" }),
        frame("result", cellPayload({ stdout: "a\n", stderr: "warn\n" })),
      ]),
    ]);

    const events = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "print('a')"));

    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe(`${BASE}/ctx_a/run/stream`);
    expect(at(requests, 0).headers.get("accept")).toBe("text/event-stream");
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({
      language: "python",
      code: "print('a')",
      timeout_s: 60,
    });
    expect(events.map((event) => event.type)).toEqual(["stdout", "stderr", "result"]);
    expect(events[0]).toEqual({ type: "stdout", data: "a\n" });
    expect(events[1]).toEqual({ type: "stderr", data: "warn\n" });
    const last = events[2];
    expect(last?.type === "result" && last.result.stdout).toBe("a\n");
    expect(last?.type === "result" && last.result.result).toBe("42");
  });

  it("decodes split frames, CRLF line ends, comments and unknown events", async () => {
    const whole = frame("stdout", { data: "x" }).replace(/\n/g, "\r\n");
    const { client } = clientFor([
      sse([
        ": keepalive\n\n",
        whole.slice(0, 7),
        whole.slice(7),
        "event: ping\ndata: {}\n\n",
        frame("result", cellPayload()),
      ]),
    ]);

    const events = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"));

    expect(events.map((event) => event.type)).toEqual(["stdout", "result"]);
  });

  it("keeps multi-byte characters that a chunk boundary splits", async () => {
    const bytes = new TextEncoder().encode(frame("stdout", { data: "héllo" }));
    const result = new TextEncoder().encode(frame("result", cellPayload()));
    const cut = 30;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes.slice(0, cut));
        controller.enqueue(bytes.slice(cut));
        controller.enqueue(result);
        controller.close();
      },
    });
    const { client } = clientFor([new Response(body, { status: 200, headers: STREAM_TYPE })]);

    const events = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"));

    expect(events[0]).toEqual({ type: "stdout", data: "héllo" });
  });

  it("stops reading after the result event", async () => {
    let cancelled = false;
    const { client } = clientFor([
      sse([frame("result", cellPayload()), frame("stdout", { data: "late" })], {
        onCancel: () => {
          cancelled = true;
        },
      }),
    ]);

    const events = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"));

    expect(events.map((event) => event.type)).toEqual(["result"]);
    expect(cancelled).toBe(true);
  });

  it("releases the response when the consumer stops early", async () => {
    let cancelled = false;
    const { client } = clientFor([
      sse([frame("stdout", { data: "1" }), frame("stdout", { data: "2" })], {
        onCancel: () => {
          cancelled = true;
        },
      }),
    ]);

    for await (const event of client.streamCodeContextRun("sbx_1", "ctx_a", "x")) {
      expect(event.type).toBe("stdout");
      break;
    }

    expect(cancelled).toBe(true);
  });

  it("raises the typed error of an error event", async () => {
    const { client } = clientFor([
      sse([
        frame("stdout", { data: "a" }),
        frame("error", { code: "NOT_FOUND", message: "context gone" }),
      ]),
    ]);
    const seen: string[] = [];

    const run = async (): Promise<void> => {
      for await (const event of client.streamCodeContextRun("sbx_1", "ctx_a", "x")) {
        seen.push(event.type);
      }
    };

    await expect(run()).rejects.toMatchObject({
      name: "NotFound",
      code: "NOT_FOUND",
      message: "context gone",
      status: 200,
    });
    expect(seen).toEqual(["stdout"]);
  });

  it("raises TransportError when the stream ends without a result", async () => {
    const { client } = clientFor([sse([frame("stdout", { data: "a" })])]);

    await expect(collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"))).rejects.toThrow(
      TransportError,
    );
  });

  it("raises InvalidResponseError for a malformed event", async () => {
    const { client } = clientFor([sse(["event: stdout\ndata: not json\n\n"])]);

    await expect(collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"))).rejects.toThrow(
      InvalidResponseError,
    );
  });

  it("raises the HTTP error of a failed start before any event", async () => {
    const { client } = clientFor([failure(404, "NOT_FOUND")]);

    await expect(collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"))).rejects.toThrow(
      NotFound,
    );
  });

  it("rejects bad arguments when called, before any request", () => {
    const { client, requests } = clientFor([]);

    expect(() => client.streamCodeContextRun("sbx_1", "ctx_a", "x", { timeoutS: 0 })).toThrow(
      ValidationError,
    );
    expect(() => client.streamCodeContextRun("sbx_1", "", "x")).toThrow(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("raises RequestAbortedError when the caller aborts mid-stream", async () => {
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(frame("stdout", { data: "a" })));
      },
    });
    const { client } = clientFor([new Response(body, { status: 200, headers: STREAM_TYPE })]);
    const controller = new AbortController();

    const run = async (): Promise<void> => {
      for await (const _event of client.streamCodeContextRun("sbx_1", "ctx_a", "x", {
        signal: controller.signal,
      })) {
        controller.abort();
      }
    };

    await expect(run()).rejects.toBeInstanceOf(RequestAbortedError);
  });
});

function withRequestId(response: Response, id: string): Response {
  const headers = new Headers(response.headers);
  headers.set("x-request-id", id);
  return new Response(response.body, { status: response.status, headers });
}

describe("streamCodeContextRun at the end of the stream", () => {
  it("delivers a final result event that has no trailing blank line", async () => {
    const resultJson = JSON.stringify(cellPayload());
    const { client } = clientFor([
      sse([frame("stdout", { data: "a" }), `event: result\ndata: ${resultJson}\n`]),
    ]);

    const events = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"));

    expect(events.map((event) => event.type)).toEqual(["stdout", "result"]);
  });

  it("still raises TransportError when the unfinished tail is not a result", async () => {
    const { client } = clientFor([sse(['event: stdout\ndata: {"data":"a"}'])]);

    const seen: string[] = [];
    const run = async (): Promise<void> => {
      for await (const event of client.streamCodeContextRun("sbx_1", "ctx_a", "x")) {
        seen.push(event.type);
      }
    };

    await expect(run()).rejects.toBeInstanceOf(TransportError);
    expect(seen).toEqual(["stdout"]);
  });
});

describe("streamCodeContextRun checks the reply type", () => {
  it.each([
    ["application/json", "application/json"],
    ["text/html; charset=utf-8", "text/html"],
  ])("raises InvalidResponseError for %s", async (header, named) => {
    const { client } = clientFor([
      new Response("{}", { status: 200, headers: { "content-type": header } }),
    ]);

    const error = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x")).catch(
      (e: unknown) => e,
    );

    expect(error).toBeInstanceOf(InvalidResponseError);
    expect((error as Error).message).toContain(named);
  });

  it("names a missing content type", async () => {
    const body = new ReadableStream<Uint8Array>({ start: (c) => c.close() });
    const { client } = clientFor([new Response(body, { status: 200 })]);

    await expect(collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"))).rejects.toThrow(
      /no content-type/i,
    );
  });

  it("accepts text/event-stream with parameters and any letter case", async () => {
    const reply = new Response(frame("result", cellPayload()), {
      status: 200,
      headers: { "content-type": "Text/Event-Stream; charset=utf-8" },
    });
    const { client } = clientFor([reply]);

    expect(await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"))).toHaveLength(1);
  });

  it("releases the body of a reply of the wrong type", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      },
    });
    const { client } = clientFor([
      new Response(body, { status: 200, headers: { "content-type": "text/plain" } }),
    ]);

    await expect(collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"))).rejects.toThrow(
      InvalidResponseError,
    );
    expect(cancelled).toBe(true);
  });
});

describe("streamCodeContextRun names the request id in its errors", () => {
  const REQUEST_ID = "req_abc123";

  it("for a stream that ends before the result", async () => {
    const stdout = sse([frame("stdout", { data: "a" })]);
    const { client } = clientFor([withRequestId(stdout, REQUEST_ID)]);

    await expect(collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"))).rejects.toThrow(
      new RegExp(`ended before the result.*${REQUEST_ID}`),
    );
  });

  it("for a malformed event", async () => {
    const { client } = clientFor([
      withRequestId(sse(["event: stdout\ndata: not json\n\n"]), REQUEST_ID),
    ]);

    await expect(collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x"))).rejects.toThrow(
      new RegExp(`not JSON.*${REQUEST_ID}`),
    );
  });

  it("for an overlong line", async () => {
    const huge = `data: ${"x".repeat(9 * 1024 * 1024)}`;
    const { client } = clientFor([withRequestId(sse([huge]), REQUEST_ID)]);

    const error = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x")).catch(
      (e: unknown) => e,
    );

    expect(error).toBeInstanceOf(InvalidResponseError);
    expect((error as Error).message).toContain(REQUEST_ID);
  });

  it("for a read that breaks", async () => {
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error("socket reset"));
      },
    });
    const reply = new Response(body, {
      status: 200,
      headers: { "content-type": "text/event-stream", "x-request-id": REQUEST_ID },
    });
    const { client } = clientFor([reply]);

    const error = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x")).catch(
      (e: unknown) => e,
    );

    expect(error).toBeInstanceOf(TransportError);
    expect((error as Error).message).toContain("socket reset");
    expect((error as Error).message).toContain(REQUEST_ID);
  });

  it("without a suffix when the reply has no request id", async () => {
    const { client } = clientFor([sse([frame("stdout", { data: "a" })])]);

    const error = await collect(client.streamCodeContextRun("sbx_1", "ctx_a", "x")).catch(
      (e: unknown) => e,
    );

    expect((error as Error).message).not.toMatch(/request/i);
  });
});
