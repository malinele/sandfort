import { describe, expect, it } from "vitest";
import {
  InvalidResponseError,
  NotFound,
  SandfortClient,
  TransportError,
  type FetchLike,
  type Sandbox,
} from "../src/index.js";

interface Recorded {
  url: string;
  method: string;
  headers: Headers;
  body: unknown;
}

function stub(queue: Array<Response | Error>): { fetch: FetchLike; requests: Recorded[] } {
  const requests: Recorded[] = [];
  const fetch: FetchLike = async (input, init) => {
    requests.push({
      url: input,
      method: init.method ?? "GET",
      headers: new Headers(init.headers),
      body: init.body,
    });
    const next = queue.shift();
    if (next === undefined) throw new Error("no queued response");
    if (next instanceof Error) throw next;
    return next;
  };
  return { fetch, requests };
}

function ok(data: unknown): Response {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function bytesReply(bytes: number[], contentType = "application/octet-stream"): Response {
  return new Response(new Uint8Array(bytes), {
    status: 200,
    headers: { "content-type": contentType },
  });
}

const FS_URL = "http://sf.test/v1/sandboxes/sbx_1/toolbox/fs";

/** A started sandbox handle; its GET is request 0, the call under test is request 1. */
async function sandboxWith(
  replies: Array<Response | Error>,
): Promise<{ sandbox: Sandbox; requests: Recorded[] }> {
  const { fetch, requests } = stub([
    ok({ id: "sbx_1", name: "demo", state: "started" }),
    ...replies,
  ]);
  const client = new SandfortClient({ baseUrl: "http://sf.test", apiKey: "sf_key", fetch });
  return { sandbox: await client.getSandbox("sbx_1"), requests };
}

function at(requests: Recorded[], index: number): Recorded {
  const item = requests[index];
  if (item === undefined) throw new Error(`no request recorded at ${index}`);
  return item;
}

async function sentBytes(body: unknown): Promise<number[]> {
  if (body instanceof Uint8Array) return Array.from(body);
  if (body instanceof Blob) return Array.from(new Uint8Array(await body.arrayBuffer()));
  throw new Error("request body is not binary");
}

describe("uploadFile", () => {
  it("PUTs the raw bytes with path, overwrite, mode and size_bytes in the query", async () => {
    const { sandbox, requests } = await sandboxWith([ok({ path: "/w/a.bin", size_bytes: 3 })]);

    const result = await sandbox.fs.uploadFile("/w/a.bin", new Uint8Array([1, 2, 255]));

    const sent = at(requests, 1);
    expect(sent.method).toBe("PUT");
    expect(sent.url).toBe(
      `${FS_URL}/upload?path=%2Fw%2Fa.bin&overwrite=true&mode=644&size_bytes=3`,
    );
    expect(sent.headers.get("content-type")).toBe("application/octet-stream");
    expect(sent.headers.get("authorization")).toBe("Bearer sf_key");
    expect(await sentBytes(sent.body)).toEqual([1, 2, 255]);
    expect(result).toEqual({ path: "/w/a.bin", sizeBytes: 3 });
  });

  it("sends a Blob as is and passes overwrite and mode", async () => {
    const { sandbox, requests } = await sandboxWith([ok({ path: "/w/b", size_bytes: 2 })]);
    const blob = new Blob([new Uint8Array([7, 8])]);

    await sandbox.fs.uploadFile("/w/b", blob, { overwrite: false, mode: "600" });

    const sent = at(requests, 1);
    expect(sent.url).toBe(`${FS_URL}/upload?path=%2Fw%2Fb&overwrite=false&mode=600&size_bytes=2`);
    expect(await sentBytes(sent.body)).toEqual([7, 8]);
  });

  it("sends a copy, so later writes to the source do not change the body", async () => {
    const { sandbox, requests } = await sandboxWith([ok({ path: "/w/c", size_bytes: 2 })]);
    const source = new Uint8Array([1, 1]);

    await sandbox.fs.uploadFile("/w/c", source);
    source[0] = 9;

    expect(await sentBytes(at(requests, 1).body)).toEqual([1, 1]);
  });

  it("surfaces typed API errors from the upload envelope", async () => {
    const body = { success: false, error: { code: "NOT_FOUND", message: "no sandbox" } };
    const { sandbox } = await sandboxWith([new Response(JSON.stringify(body), { status: 404 })]);

    await expect(sandbox.fs.uploadFile("/w/a", new Uint8Array([1]))).rejects.toBeInstanceOf(
      NotFound,
    );
  });

  it("wraps network failures in TransportError", async () => {
    const { sandbox } = await sandboxWith([new TypeError("connection refused")]);

    await expect(sandbox.fs.uploadFile("/w/a", new Uint8Array([1]))).rejects.toBeInstanceOf(
      TransportError,
    );
  });
});

describe("downloadFile", () => {
  it("GETs the path and returns the bytes", async () => {
    const { sandbox, requests } = await sandboxWith([bytesReply([0, 255, 7])]);

    const bytes = await sandbox.fs.downloadFile("/w/a.bin");

    const sent = at(requests, 1);
    expect(sent.method).toBe("GET");
    expect(sent.url).toBe(`${FS_URL}/download?path=%2Fw%2Fa.bin`);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(Array.from(bytes)).toEqual([0, 255, 7]);
  });

  it("rejects a directory, which the server streams as tar", async () => {
    const { sandbox } = await sandboxWith([bytesReply([0], "application/x-tar")]);

    await expect(sandbox.fs.downloadFile("/w")).rejects.toBeInstanceOf(InvalidResponseError);
  });

  it("maps an error envelope to its typed error", async () => {
    const body = { success: false, error: { code: "NOT_FOUND", message: "no such file" } };
    const { sandbox } = await sandboxWith([new Response(JSON.stringify(body), { status: 404 })]);

    await expect(sandbox.fs.downloadFile("/nope")).rejects.toBeInstanceOf(NotFound);
  });
});

describe("listDir", () => {
  it("parses entries with names, kinds and timestamps", async () => {
    const { sandbox, requests } = await sandboxWith([
      ok({
        path: "/w",
        entries: [
          {
            name: "a.txt",
            path: "/w/a.txt",
            kind: "file",
            size_bytes: 3,
            mode: "644",
            modified_at: "2026-10-31T12:00:00+00:00",
          },
          { name: "src", path: "/w/src", kind: "dir", size_bytes: 0, mode: "755" },
        ],
      }),
    ]);

    const listing = await sandbox.fs.listDir("/w");

    expect(at(requests, 1).url).toBe(`${FS_URL}/list?path=%2Fw`);
    expect(listing.path).toBe("/w");
    expect(listing.entries.map((e) => [e.name, e.kind])).toEqual([
      ["a.txt", "file"],
      ["src", "dir"],
    ]);
    expect(listing.entries[0]).toEqual({
      name: "a.txt",
      path: "/w/a.txt",
      kind: "file",
      sizeBytes: 3,
      mode: "644",
      modifiedAt: new Date("2026-10-31T12:00:00Z"),
    });
    expect(listing.entries[1]?.modifiedAt).toBeNull();
  });

  it("lists the root by default", async () => {
    const { sandbox, requests } = await sandboxWith([ok({ path: "/", entries: [] })]);

    const listing = await sandbox.fs.listDir();

    expect(at(requests, 1).url).toBe(`${FS_URL}/list?path=%2F`);
    expect(listing.entries).toEqual([]);
  });

  it("rejects an entry without a kind", async () => {
    const { sandbox } = await sandboxWith([
      ok({ path: "/", entries: [{ name: "x", path: "/x", size_bytes: 0, mode: "644" }] }),
    ]);

    await expect(sandbox.fs.listDir()).rejects.toBeInstanceOf(InvalidResponseError);
  });
});

describe("mkdir, move and remove", () => {
  it("send the python facade's bodies with its defaults", async () => {
    const { sandbox, requests } = await sandboxWith([
      ok({ path: "/w/d", created: true }),
      ok({ source: "/a", destination: "/b" }),
      ok({ path: "/w/d", deleted: true }),
    ]);

    const made = await sandbox.fs.mkdir("/w/d");
    const moved = await sandbox.fs.move("/a", "/b");
    const removed = await sandbox.fs.remove("/w/d");

    expect(requests.slice(1).map((r) => `${r.method} ${r.url} ${String(r.body)}`)).toEqual([
      `POST ${FS_URL}/mkdir {"path":"/w/d","mode":"755","parents":true}`,
      `POST ${FS_URL}/move {"source":"/a","destination":"/b","overwrite":false}`,
      `POST ${FS_URL}/delete {"path":"/w/d","recursive":false}`,
    ]);
    expect(made).toEqual({ path: "/w/d", created: true });
    expect(moved).toEqual({ source: "/a", destination: "/b" });
    expect(removed).toEqual({ path: "/w/d", deleted: true });
  });

  it("pass explicit options through", async () => {
    const { sandbox, requests } = await sandboxWith([
      ok({ path: "/w/d", created: false }),
      ok({ source: "/a", destination: "/b" }),
      ok({ path: "/w/d", deleted: true }),
    ]);

    await sandbox.fs.mkdir("/w/d", { mode: "700", parents: false });
    await sandbox.fs.move("/a", "/b", { overwrite: true });
    await sandbox.fs.remove("/w/d", { recursive: true });

    expect(requests.slice(1).map((r) => r.body)).toEqual([
      '{"path":"/w/d","mode":"700","parents":false}',
      '{"source":"/a","destination":"/b","overwrite":true}',
      '{"path":"/w/d","recursive":true}',
    ]);
  });
});
