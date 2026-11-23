import { describe, expect, it } from "vitest";
import { Conflict, SandfortClient, SandfortError, type FetchLike } from "../src/index.js";
import { SnapshotFailedError, SnapshotTimeoutError } from "../src/snapshots.js";

interface Recorded {
  url: string;
  method: string;
  body: string | undefined;
}

function stub(queue: Response[]): { fetch: FetchLike; requests: Recorded[] } {
  const requests: Recorded[] = [];
  const fetch: FetchLike = async (input, init) => {
    requests.push({
      url: input,
      method: init.method ?? "GET",
      body: typeof init.body === "string" ? init.body : undefined,
    });
    const next = queue.shift();
    if (next === undefined) throw new Error("no queued response");
    return next;
  };
  return { fetch, requests };
}

function ok(data: unknown, nextCursor?: string): Response {
  const body =
    nextCursor === undefined
      ? { success: true, data }
      : { success: true, data, meta: { next_cursor: nextCursor } };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function snapshot(state: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "snap_1",
    name: "base",
    state,
    image_ref: "sandfort/snap_1:latest",
    layer_count: 4,
    created_at: "2026-10-31T12:00:00+00:00",
    digest: null,
    source_sandbox_id: "sbx_1",
    ...extra,
  };
}

function clientFor(queue: Response[]): { client: SandfortClient; requests: Recorded[] } {
  const { fetch, requests } = stub(queue);
  return {
    client: new SandfortClient({ baseUrl: "http://sf.test", apiKey: "sf_key", fetch }),
    requests,
  };
}

function at(requests: Recorded[], index: number): Recorded {
  const item = requests[index];
  if (item === undefined) throw new Error(`no request recorded at ${index}`);
  return item;
}

describe("createSnapshot", () => {
  it("posts the wire body and returns the pending snapshot without waiting", async () => {
    const { client, requests } = clientFor([ok(snapshot("pending"))]);

    const info = await client.createSnapshot("sbx_1", "base");

    const sent = at(requests, 0);
    expect(sent.method).toBe("POST");
    expect(sent.url).toBe("http://sf.test/v1/snapshots/from-sandbox");
    expect(sent.body).toBe('{"sandbox_id":"sbx_1","name":"base"}');
    expect(info.state).toBe("pending");
    expect(requests).toHaveLength(1);
  });

  it("polls getSnapshot until ready when wait is set", async () => {
    const { client, requests } = clientFor([
      ok(snapshot("pending")),
      ok(snapshot("pending")),
      ok(snapshot("ready", { digest: "sha256:abc" })),
    ]);

    const info = await client.createSnapshot("sbx_1", "base", { wait: true, pollIntervalS: 0.001 });

    expect(info.state).toBe("ready");
    expect(info.digest).toBe("sha256:abc");
    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      "POST http://sf.test/v1/snapshots/from-sandbox",
      "GET http://sf.test/v1/snapshots/snap_1",
      "GET http://sf.test/v1/snapshots/snap_1",
    ]);
  });

  it("throws SnapshotFailedError when the snapshot lands in error", async () => {
    const { client } = clientFor([ok(snapshot("pending")), ok(snapshot("error"))]);

    const error = await client
      .createSnapshot("sbx_1", "base", { wait: true, pollIntervalS: 0.001 })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(SnapshotFailedError);
    expect(error).toBeInstanceOf(SandfortError);
    expect((error as SnapshotFailedError).state).toBe("error");
    expect((error as SnapshotFailedError).snapshotId).toBe("snap_1");
  });

  it("throws SnapshotTimeoutError when the wait budget is spent", async () => {
    const { client } = clientFor(Array.from({ length: 200 }, () => ok(snapshot("pending"))));

    await expect(
      client.createSnapshot("sbx_1", "base", { wait: true, waitTimeoutS: 0.05, pollIntervalS: 0.01 }),
    ).rejects.toBeInstanceOf(SnapshotTimeoutError);
  });

  it("rejects a blank name before sending anything", async () => {
    const { client, requests } = clientFor([]);

    await expect(client.createSnapshot("sbx_1", "  ")).rejects.toThrow("must not be empty");
    expect(requests).toHaveLength(0);
  });

  it("maps the wire payload to camelCase fields", async () => {
    const { client } = clientFor([ok(snapshot("ready", { spec_hash: "h1", reused: true }))]);

    const info = await client.createSnapshot("sbx_1", "base");

    expect(info).toEqual({
      id: "snap_1",
      name: "base",
      state: "ready",
      imageRef: "sandfort/snap_1:latest",
      layerCount: 4,
      createdAt: new Date("2026-10-31T12:00:00Z"),
      digest: null,
      sourceSandboxId: "sbx_1",
      specHash: "h1",
      reused: true,
      labels: {},
      isolation: null,
    });
  });
});

describe("listSnapshots", () => {
  it("follows the cursor across pages", async () => {
    const { client, requests } = clientFor([
      ok([snapshot("ready"), snapshot("ready", { id: "snap_2" })], "c2"),
      ok([snapshot("pending", { id: "snap_3" })]),
    ]);

    const first = await client.listSnapshots({ limit: 2 });
    const second = await client.listSnapshots({
      limit: 2,
      ...(first.nextCursor === null ? {} : { cursor: first.nextCursor }),
    });

    expect(first.items.map((s) => s.id)).toEqual(["snap_1", "snap_2"]);
    expect(first.nextCursor).toBe("c2");
    expect(second.items.map((s) => s.id)).toEqual(["snap_3"]);
    expect(second.nextCursor).toBeNull();
    expect(requests.map((r) => r.url)).toEqual([
      "http://sf.test/v1/snapshots?limit=2",
      "http://sf.test/v1/snapshots?cursor=c2&limit=2",
    ]);
  });

  it("sends no query by default", async () => {
    const { client, requests } = clientFor([ok([])]);

    const page = await client.listSnapshots();

    expect(at(requests, 0).url).toBe("http://sf.test/v1/snapshots");
    expect(page.items).toEqual([]);
  });
});

describe("getSnapshot and deleteSnapshot", () => {
  it("use the matching method and an encoded path", async () => {
    const { client, requests } = clientFor([ok(snapshot("ready")), ok(snapshot("deleting"))]);

    await client.getSnapshot("snap_1");
    const deleted = await client.deleteSnapshot("a/b");

    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      "GET http://sf.test/v1/snapshots/snap_1",
      "DELETE http://sf.test/v1/snapshots/a%2Fb",
    ]);
    expect(deleted.state).toBe("deleting");
  });

  it("surfaces a 409 while a sandbox still uses the snapshot", async () => {
    const body = { success: false, error: { code: "CONFLICT", message: "in use" } };
    const { client } = clientFor([new Response(JSON.stringify(body), { status: 409 })]);

    await expect(client.deleteSnapshot("snap_1")).rejects.toBeInstanceOf(Conflict);
  });
});
