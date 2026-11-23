import { describe, expect, it } from "vitest";
import { Conflict, SandfortClient, type FetchLike } from "../src/index.js";

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
  return new Response(JSON.stringify(body), { status: 200 });
}

function volume(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "vol_1",
    name: "data",
    state: "ready",
    created_at: "2026-11-01T09:00:00+00:00",
    size_bytes: null,
    ...extra,
  };
}

function clientFor(queue: Response[]) {
  const { fetch, requests } = stub(queue);
  return {
    client: new SandfortClient({ baseUrl: "http://sf.test", apiKey: "sf_key", fetch }),
    requests,
  };
}

function first(requests: Recorded[]): Recorded {
  const item = requests[0];
  if (item === undefined) throw new Error("no request recorded");
  return item;
}

describe("volumes", () => {
  it("creates a volume with only the name on the wire", async () => {
    const { client, requests } = clientFor([ok(volume())]);

    const info = await client.createVolume("data");

    expect(first(requests)).toEqual({
      url: "http://sf.test/v1/volumes",
      method: "POST",
      body: '{"name":"data"}',
    });
    expect(info).toEqual({
      id: "vol_1",
      name: "data",
      state: "ready",
      createdAt: new Date("2026-11-01T09:00:00+00:00"),
      sizeBytes: null,
    });
  });

  it("rejects a blank name before any request", async () => {
    const { client, requests } = clientFor([]);

    await expect(client.createVolume("  ")).rejects.toThrow("'name' must not be empty");
    expect(requests).toHaveLength(0);
  });

  it("lists volumes with cursor and limit and returns the next cursor", async () => {
    const { client, requests } = clientFor([
      ok([volume(), volume({ id: "vol_2", size_bytes: 2048 })], "cur_2"),
    ]);

    const page = await client.listVolumes({ cursor: "cur_1", limit: 2 });

    expect(first(requests)).toEqual({
      url: "http://sf.test/v1/volumes?cursor=cur_1&limit=2",
      method: "GET",
      body: undefined,
    });
    expect(page.items.map((v) => v.id)).toEqual(["vol_1", "vol_2"]);
    expect(page.items[1]?.sizeBytes).toBe(2048);
    expect(page.nextCursor).toBe("cur_2");
  });

  it("lists with no query string by default", async () => {
    const { client, requests } = clientFor([ok([])]);

    const page = await client.listVolumes();

    expect(first(requests).url).toBe("http://sf.test/v1/volumes");
    expect(page).toEqual({ items: [], nextCursor: null });
  });

  it("gets and deletes by percent-encoded id", async () => {
    const { client, requests } = clientFor([ok(volume()), ok(volume({ state: "deleting" }))]);

    await client.getVolume("vol/1");
    const deleted = await client.deleteVolume("vol/1");

    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      "GET http://sf.test/v1/volumes/vol%2F1",
      "DELETE http://sf.test/v1/volumes/vol%2F1",
    ]);
    expect(requests.every((r) => r.body === undefined)).toBe(true);
    expect(deleted.state).toBe("deleting");
  });

  it("maps a 409 on delete to Conflict", async () => {
    const busy = new Response(
      JSON.stringify({ success: false, error: { code: "CONFLICT", message: "mounted" } }),
      { status: 409 },
    );
    const { client } = clientFor([busy]);

    await expect(client.deleteVolume("vol_1")).rejects.toBeInstanceOf(Conflict);
  });
});
