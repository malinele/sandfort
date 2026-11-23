import { describe, expect, it } from "vitest";
import {
  InvalidResponseError,
  RequestTimeoutError,
  ValidationError,
  type FollowLogEvent,
} from "../src/index.js";
import { clientFor, ok, type Recorded } from "./helpers.js";
import { sse } from "./contexts-helpers.js";

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

async function drain(events: AsyncIterable<FollowLogEvent>): Promise<void> {
  for await (const event of events) void event;
}

describe("a deadline or timeout that fires on a follow stream", () => {
  it("says deadline, not timed out, when deadlineMs cut the stream", async () => {
    const { client } = clientFor([stallingBody], { deadlineMs: 30, retries: 0 });

    const run = drain(client.followCommandLogs("sbx_1", "s1", "c1"));

    await expect(run).rejects.toBeInstanceOf(RequestTimeoutError);
    await expect(run).rejects.toThrow(/exceeded its deadline of 30 ms/);
    await expect(run).rejects.not.toThrow(/timed out/);
  });

  it("says timed out when the per-call timeoutMs cut it", async () => {
    const { client } = clientFor([stallingBody], { retries: 0 });

    const run = drain(client.followCommandLogs("sbx_1", "s1", "c1", { timeoutMs: 30 }));

    await expect(run).rejects.toBeInstanceOf(RequestTimeoutError);
    await expect(run).rejects.toThrow(/timed out/);
  });
});

describe("an empty next_cursor", () => {
  it("is an InvalidResponseError, not a ValidationError from sending it back", async () => {
    const { client, requests } = clientFor([ok([], ""), ok([], null)]);

    const page = client.listSandboxes();

    await expect(page).rejects.toBeInstanceOf(InvalidResponseError);
    await expect(page).rejects.not.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(1);
  });

  it("stops a listAll walk with InvalidResponseError", async () => {
    const { client } = clientFor([ok([], "")]);

    const walk = (async (): Promise<void> => {
      for await (const sandbox of client.listSandboxesAll()) void sandbox;
    })();

    await expect(walk).rejects.toBeInstanceOf(InvalidResponseError);
  });
});

describe("content-type with parameters", () => {
  it("accepts text/event-stream with a charset on the log follow", async () => {
    const response = sse([
      'event: exit\ndata: {"exit_code":0,"state":"exited","truncated":false}\n\n',
    ]);
    const typed = new Response(response.body, {
      status: 200,
      headers: { "content-type": "Text/Event-Stream; charset=utf-8" },
    });
    const { client } = clientFor([typed]);

    const events: FollowLogEvent[] = [];
    for await (const event of client.followCommandLogs("sbx_1", "s1", "c1")) events.push(event);

    expect(events.map((event) => event.type)).toEqual(["exit"]);
  });
});

describe("label values", () => {
  const numeric = { team: 7 as unknown as string };

  it("must be strings when creating a sandbox, a volume or a key", async () => {
    const { client, requests } = clientFor([]);

    await expect(client.createSandbox({ labels: numeric })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(client.createVolume("v", { labels: numeric })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(
      client.apiKeys.create("k", ["sandboxes:read"], { sandboxLabels: numeric }),
    ).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });
});
