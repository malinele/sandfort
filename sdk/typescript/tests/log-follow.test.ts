import { describe, expect, it } from "vitest";
import {
  InvalidResponseError,
  NotFound,
  RequestAbortedError,
  RequestTimeoutError,
  TransportError,
  ValidationError,
  type FollowLogEvent,
} from "../src/index.js";
import { at, clientFor, failure, ok, sandboxPayload, type Recorded } from "./helpers.js";
import { sse } from "./contexts-helpers.js";

const FOLLOW =
  "http://sf.test/v1/sandboxes/sbx_1/toolbox/process/sessions/s1/commands/c1/logs/follow";

function chunk(event: string, data: unknown, id?: number): string {
  const idLine = id === undefined ? "" : `id: ${id}\n`;
  return `${idLine}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

const out = (line: string, offset: number): string =>
  chunk("stdout", { stream: "stdout", offset, line }, offset + line.length);
const exit = (code: number | null = 0, id?: number): string =>
  chunk("exit", { exit_code: code, state: "exited", truncated: false }, id);

async function collect(events: AsyncIterable<FollowLogEvent>): Promise<FollowLogEvent[]> {
  const seen: FollowLogEvent[] = [];
  for await (const event of events) seen.push(event);
  return seen;
}

describe("followCommandLogs", () => {
  it("yields stdout and stderr chunks and ends after the exit event", async () => {
    const { client, requests } = clientFor([
      sse([
        ": keepalive\n\n",
        out("a\n", 0),
        chunk("stderr", { stream: "stderr", offset: 2, line: "warn\n" }, 7),
        exit(3),
        out("never seen\n", 7),
      ]),
    ]);

    const events = await collect(client.followCommandLogs("sbx_1", "s1", "c1"));

    expect(events).toEqual([
      { type: "stdout", offset: 0, nextOffset: 2, line: "a\n" },
      { type: "stderr", offset: 2, nextOffset: 7, line: "warn\n" },
      { type: "exit", exitCode: 3, state: "exited", truncated: false, nextOffset: null },
    ]);
    expect(at(requests, 0).method).toBe("GET");
    expect(at(requests, 0).url).toBe(FOLLOW);
    expect(at(requests, 0).headers.get("accept")).toBe("text/event-stream");
  });

  it("sends offset when given and handles a null exit code", async () => {
    const { client, requests } = clientFor([sse([exit(null)])]);

    const events = await collect(client.followCommandLogs("sbx_1", "s1", "c1", { offset: 42 }));

    expect(at(requests, 0).url).toBe(`${FOLLOW}?offset=42`);
    expect(events).toEqual([
      { type: "exit", exitCode: null, state: "exited", truncated: false, nextOffset: null },
    ]);
  });

  it("decodes frames split across chunks", async () => {
    const whole = out("hello\n", 0);
    const { client } = clientFor([sse([whole.slice(0, 9), whole.slice(9), exit()])]);

    const events = await collect(client.followCommandLogs("sbx_1", "s1", "c1"));

    expect(events.map((event) => event.type)).toEqual(["stdout", "exit"]);
  });

  it("is available on the Sandbox handle", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), sse([out("x", 0), exit()])]);
    const sandbox = await client.getSandbox("sbx_1");

    const events = await collect(sandbox.followCommandLogs("s1", "c1"));

    expect(events).toHaveLength(2);
    expect(at(requests, 1).url).toBe(FOLLOW);
  });

  it("rejects a negative or fractional offset and blank ids before any request", async () => {
    const { client, requests } = clientFor([]);

    const bad = [
      client.followCommandLogs("sbx_1", "s1", "c1", { offset: -1 }),
      client.followCommandLogs("sbx_1", "s1", "c1", { offset: 1.5 }),
      client.followCommandLogs("sbx_1", " ", "c1"),
      client.followCommandLogs("sbx_1", "s1", ""),
    ];
    for (const stream of bad) {
      await expect(stream.next()).rejects.toBeInstanceOf(ValidationError);
    }
    expect(requests).toHaveLength(0);
  });

  it("raises the typed error of a non-2xx reply on the first next()", async () => {
    const { client } = clientFor([failure(404, "NOT_FOUND")]);

    await expect(collect(client.followCommandLogs("sbx_1", "s1", "c1"))).rejects.toBeInstanceOf(
      NotFound,
    );
  });

  it("raises the typed error of an error event", async () => {
    const { client } = clientFor([
      sse([out("a", 0), chunk("error", { code: "NOT_FOUND", message: "gone" })]),
    ]);

    await expect(collect(client.followCommandLogs("sbx_1", "s1", "c1"))).rejects.toBeInstanceOf(
      NotFound,
    );
  });

  it("raises TransportError when the stream ends without an exit event", async () => {
    const { client } = clientFor([sse([out("a", 0)])]);

    await expect(collect(client.followCommandLogs("sbx_1", "s1", "c1"))).rejects.toBeInstanceOf(
      TransportError,
    );
  });

  it("raises InvalidResponseError for a log event without a line", async () => {
    const { client } = clientFor([sse([chunk("stdout", { stream: "stdout", offset: 0 })])]);

    await expect(collect(client.followCommandLogs("sbx_1", "s1", "c1"))).rejects.toBeInstanceOf(
      InvalidResponseError,
    );
  });

  it("closes the connection when the loop is left early", async () => {
    let cancelled = false;
    const { client } = clientFor([
      sse([out("a", 0), out("b", 1), exit()], { onCancel: () => (cancelled = true) }),
    ]);

    for await (const event of client.followCommandLogs("sbx_1", "s1", "c1")) {
      expect(event.type).toBe("stdout");
      break;
    }

    expect(cancelled).toBe(true);
  });

  it("raises RequestAbortedError when the caller aborts mid-stream", async () => {
    const controller = new AbortController();
    const { client } = clientFor([
      sse([out("a", 0)], {}),
    ]);
    const stream = client.followCommandLogs("sbx_1", "s1", "c1", { signal: controller.signal });

    await stream.next();
    controller.abort();

    await expect(stream.next()).rejects.toBeInstanceOf(RequestAbortedError);
  });

  it("a per-call timeoutMs bounds the whole stream as RequestTimeoutError", async () => {
    const encoder = new TextEncoder();
    // Like a real fetch body, the stream errors when the request's signal fires.
    const open = (request: Recorded): Response => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(out("a", 0)));
          request.signal?.addEventListener("abort", () => controller.error(request.signal?.reason));
        },
      });
      return new Response(body, { headers: { "content-type": "text/event-stream" } });
    };
    const { client } = clientFor([open], { timeoutMs: 60_000 });

    const stream = client.followCommandLogs("sbx_1", "s1", "c1", { timeoutMs: 30, retries: 0 });
    await stream.next();

    await expect(stream.next()).rejects.toBeInstanceOf(RequestTimeoutError);
  });
});
