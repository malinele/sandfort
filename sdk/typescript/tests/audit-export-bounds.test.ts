import { describe, expect, it } from "vitest";
import { InvalidResponseError } from "../src/index.js";
import { MAX_EXPORT_LINE_CHARS } from "../src/audit-export.js";
import { clientFor } from "./helpers.js";

function body(chunks: (string | Uint8Array)[], onCancel?: () => void): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let next = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      const chunk = chunks[next];
      next += 1;
      if (chunk === undefined) controller.close();
      else controller.enqueue(typeof chunk === "string" ? encoder.encode(chunk) : chunk);
    },
    cancel() {
      onCancel?.();
    },
  });
}

function ndjson(
  chunks: (string | Uint8Array)[],
  options: { type?: string; onCancel?: () => void } = {},
): Response {
  const headers = { "content-type": options.type ?? "application/x-ndjson" };
  return new Response(body(chunks, options.onCancel), { status: 200, headers });
}

async function collect(lines: AsyncIterable<string>): Promise<string[]> {
  const out: string[] = [];
  for await (const line of lines) out.push(line);
  return out;
}

describe("audit.exportLines bounds", () => {
  it("refuses a line longer than 1 MiB without a newline", async () => {
    const piece = "x".repeat(256 * 1024);
    const { client } = clientFor([ndjson([piece, piece, piece, piece, piece])]);

    const run = collect(client.audit.exportLines());

    await expect(run).rejects.toBeInstanceOf(InvalidResponseError);
    await expect(run).rejects.toThrow(/longer than 1048576/);
  });

  it("accepts a line of exactly the cap, split across many chunks", async () => {
    const line = `${"y".repeat(MAX_EXPORT_LINE_CHARS - 1)}\n`;
    const chunks: string[] = [];
    for (let at = 0; at < line.length; at += 64 * 1024) chunks.push(line.slice(at, at + 64 * 1024));
    const { client } = clientFor([ndjson(chunks)]);

    expect(await collect(client.audit.exportLines())).toEqual([line]);
  });

  it("does not re-split the pending text: many tiny chunks of one line stay fast", async () => {
    const chunks = Array.from({ length: 50_000 }, () => "z");
    const { client } = clientFor([ndjson([...chunks, "\n"])]);

    const started = Date.now();
    const lines = await collect(client.audit.exportLines());

    expect(lines).toEqual([`${"z".repeat(50_000)}\n`]);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("maps invalid UTF-8 to InvalidResponseError", async () => {
    const { client } = clientFor([ndjson(["a\n", Uint8Array.of(0xff, 0xfe, 0x0a)])]);

    await expect(collect(client.audit.exportLines())).rejects.toBeInstanceOf(
      InvalidResponseError,
    );
  });

  it("maps a body that ends inside a multi-byte character to InvalidResponseError", async () => {
    const { client } = clientFor([ndjson([Uint8Array.of(0x61, 0xc5)])]);

    await expect(collect(client.audit.exportLines())).rejects.toBeInstanceOf(
      InvalidResponseError,
    );
  });

  it("cancels the body when the consumer breaks out of the loop", async () => {
    let cancelled = false;
    const { client } = clientFor([
      ndjson(["a\n", "b\n", "c\n"], { onCancel: () => (cancelled = true) }),
    ]);

    for await (const line of client.audit.exportLines()) {
      expect(line).toBe("a\n");
      break;
    }

    expect(cancelled).toBe(true);
  });

  it("accepts a content-type with a charset parameter", async () => {
    const { client } = clientFor([
      ndjson(["a\n"], { type: "Application/X-NDJSON; charset=utf-8" }),
    ]);

    expect(await collect(client.audit.exportLines())).toEqual(["a\n"]);
  });
});
