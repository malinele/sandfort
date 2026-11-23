import { describe, expect, it } from "vitest";
import {
  InvalidResponseError,
  InvalidState,
  RequestAbortedError,
  RequestTimeoutError,
  ValidationError,
} from "../src/index.js";
import { exportTar, SNAPSHOT_EXPORT_MIN_TIMEOUT_MS } from "../src/snapshot-export.js";
import type { Transport } from "../src/transport.js";
import { at, clientFor, failure, type Recorded } from "./helpers.js";

const TAR_TYPE = "application/x-tar";

/** A tar-like payload with non-ASCII and NUL bytes, to prove nothing is decoded on the way. */
function payload(): Uint8Array {
  const bytes = new Uint8Array(3000);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = (index * 7) % 256;
  bytes[0] = 0x00;
  bytes[1] = 0xff;
  bytes[2] = 0xc3;
  bytes[3] = 0x28;
  return bytes;
}

function body(chunks: Uint8Array[], onCancel?: () => void): ReadableStream<Uint8Array> {
  let next = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      const chunk = chunks[next];
      next += 1;
      if (chunk === undefined) controller.close();
      else controller.enqueue(chunk);
    },
    cancel() {
      onCancel?.();
    },
  });
}

function tar(
  chunks: Uint8Array[],
  options: { type?: string; onCancel?: () => void } = {},
): Response {
  const headers = {
    "content-type": options.type ?? TAR_TYPE,
    "x-request-id": "req_tar",
  };
  return new Response(body(chunks, options.onCancel), { status: 200, headers });
}

function split(bytes: Uint8Array, size: number): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  for (let from = 0; from < bytes.length; from += size) chunks.push(bytes.slice(from, from + size));
  return chunks;
}

async function collect(stream: AsyncIterable<Uint8Array>): Promise<Uint8Array[]> {
  const out: Uint8Array[] = [];
  for await (const chunk of stream) out.push(chunk);
  return out;
}

function join(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

describe("snapshot export", () => {
  it("streams the tar body in several chunks and reassembles it byte for byte", async () => {
    const original = payload();
    const { client, requests } = clientFor([tar(split(original, 700))]);

    const chunks = await collect(client.exportSnapshotStream("snap_1"));

    expect(chunks.length).toBeGreaterThan(1);
    expect(join(chunks)).toEqual(original);
    const sent = at(requests, 0);
    expect(sent.method).toBe("GET");
    expect(new URL(sent.url).pathname).toBe("/v1/snapshots/snap_1/export");
    expect(sent.headers.get("accept")).toBe(TAR_TYPE);
  });

  it("percent-encodes the snapshot id in the path", async () => {
    const { client, requests } = clientFor([tar([new Uint8Array([1])])]);

    await collect(client.exportSnapshotStream("a/b c"));

    expect(new URL(at(requests, 0).url).pathname).toBe("/v1/snapshots/a%2Fb%20c/export");
  });

  it("exportBytes equals the concatenated stream output", async () => {
    const original = payload();
    const { client } = clientFor([tar(split(original, 512)), tar(split(original, 512))]);

    const streamed = join(await collect(client.exportSnapshotStream("snap_1")));
    const bytes = await client.exportSnapshotBytes("snap_1");

    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toEqual(streamed);
    expect(bytes).toEqual(original);
  });

  it("returns an empty Uint8Array for a zero-length tar body", async () => {
    const { client } = clientFor([tar([])]);

    const bytes = await client.exportSnapshotBytes("snap_1");

    expect(bytes.length).toBe(0);
  });

  it("raises InvalidState with the request id when the snapshot is not ready", async () => {
    const { client } = clientFor([
      failure(409, "INVALID_STATE", { "x-request-id": "req_409" }, "snapshot is not ready"),
    ]);

    const run = client.exportSnapshotBytes("snap_1");

    await expect(run).rejects.toBeInstanceOf(InvalidState);
    const error: unknown = await run.catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "INVALID_STATE", status: 409, requestId: "req_409" });
  });

  it("refuses a 2xx reply of another content type and drops its body", async () => {
    let cancelled = false;
    const { client } = clientFor([
      tar([new Uint8Array([1, 2])], { type: "application/json", onCancel: () => (cancelled = true) }),
    ]);

    const run = collect(client.exportSnapshotStream("snap_1"));

    await expect(run).rejects.toBeInstanceOf(InvalidResponseError);
    await expect(run).rejects.toThrow(/content type|application\/x-tar/i);
    expect(cancelled).toBe(true);
  });

  it("a per-call timeoutMs bounds the whole stream as RequestTimeoutError", async () => {
    // Like a real fetch body, the stream errors when the request's signal fires.
    const open = (request: Recorded): Response => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array([1, 2, 3]));
          request.signal?.addEventListener("abort", () => controller.error(request.signal?.reason));
        },
      });
      return new Response(body, { headers: { "content-type": TAR_TYPE } });
    };
    const { client } = clientFor([open]);

    const stream = client.exportSnapshotStream("snap_1", { timeoutMs: 30, retries: 0 });
    await stream.next();

    await expect(collect(stream)).rejects.toBeInstanceOf(RequestTimeoutError);
  });

  it("raises InvalidResponseError with the request id when the reply has no body", async () => {
    const empty = new Response(null, {
      status: 200,
      headers: { "content-type": TAR_TYPE, "x-request-id": "req_nobody" },
    });
    const { client } = clientFor([empty]);

    const run = collect(client.exportSnapshotStream("snap_1"));

    await expect(run).rejects.toBeInstanceOf(InvalidResponseError);
    await expect(run).rejects.toThrow(/req_nobody/);
  });

  it("aborts mid-stream with RequestAbortedError and cancels the reader", async () => {
    const controller = new AbortController();
    let cancelled = false;
    const chunks = split(payload(), 100);
    const { client } = clientFor([tar(chunks, { onCancel: () => (cancelled = true) })]);

    const seen: Uint8Array[] = [];
    const run = (async (): Promise<void> => {
      for await (const chunk of client.exportSnapshotStream("snap_1", {
        signal: controller.signal,
      })) {
        seen.push(chunk);
        if (seen.length === 2) controller.abort();
      }
    })();

    await expect(run).rejects.toBeInstanceOf(RequestAbortedError);
    await expect(run).rejects.toThrow(/the snapshot export/);
    expect(cancelled).toBe(true);
  });

  it("cancels the reader when the consumer stops early", async () => {
    let cancelled = false;
    const { client } = clientFor([
      tar(split(payload(), 100), { onCancel: () => (cancelled = true) }),
    ]);

    for await (const _chunk of client.exportSnapshotStream("snap_1")) break;

    expect(cancelled).toBe(true);
  });

  it("rejects a blank snapshot id before any request is sent", async () => {
    const { client, requests } = clientFor([]);

    await expect(collect(client.exportSnapshotStream("  "))).rejects.toBeInstanceOf(ValidationError);
    await expect(client.exportSnapshotBytes("")).rejects.toThrow("'snapshotId' must not be empty");
    expect(requests).toHaveLength(0);
  });

  it("exports the 1 h whole-stream timeout floor as SNAPSHOT_EXPORT_MIN_TIMEOUT_MS", () => {
    expect(SNAPSHOT_EXPORT_MIN_TIMEOUT_MS).toBe(3_600_000);
  });

  it("floors the stream timeout at 1 h only while timeoutMs is unset", async () => {
    const floors: Array<number | undefined> = [];
    const stub = {
      openStream: (
        _method: string,
        _path: string,
        options: { minTimeoutMs?: number },
      ): Promise<Response> => {
        floors.push(options.minTimeoutMs);
        return Promise.resolve(new Response(body([]), { headers: { "content-type": TAR_TYPE } }));
      },
    } as unknown as Transport;

    await collect(exportTar(stub, "snap_1", {}));
    await collect(exportTar(stub, "snap_1", { timeoutMs: 5_000 }));

    expect(floors).toEqual([SNAPSHOT_EXPORT_MIN_TIMEOUT_MS, undefined]);
  });

  it("delegates through client.snapshots-backed methods to GET /export", async () => {
    const original = payload();
    const { client, requests } = clientFor([tar(split(original, 1000))]);

    const bytes = await client.exportSnapshotBytes("snap_9", { retries: 0 });

    expect(bytes).toEqual(original);
    expect(requests).toHaveLength(1);
    expect(new URL(at(requests, 0).url).pathname).toBe("/v1/snapshots/snap_9/export");
  });
});
