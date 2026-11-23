import { describe, expect, it } from "vitest";
import { InvalidResponseError } from "../src/index.js";
import { buildQuery } from "../src/transport.js";
import { at, clientFor, ok, sandboxPayload } from "./helpers.js";

function sbx(id: string): Record<string, unknown> {
  return sandboxPayload("started", { id });
}

function snapshot(id: string): Record<string, unknown> {
  return {
    id,
    name: id,
    state: "ready",
    image_ref: "img",
    layer_count: 1,
    created_at: "2026-11-01T09:00:00+00:00",
  };
}

function volume(id: string): Record<string, unknown> {
  return { id, name: id, state: "ready", created_at: "2026-11-01T09:00:00+00:00" };
}

async function collect<T>(iterator: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const item of iterator) out.push(item);
  return out;
}

describe("buildQuery", () => {
  it("drops null and undefined for any value and never throws", () => {
    const text = buildQuery({
      cursor: null,
      limit: undefined,
      label: null,
      state: "started",
      flag: false,
      labels: ["a=1", "b=2"],
    });

    expect(text).toBe("?state=started&flag=false&labels=a%3D1&labels=b%3D2");
    expect(buildQuery({ cursor: null })).toBe("");
  });
});

describe("cursor handling", () => {
  it("accepts page.nextCursor (string | null) straight back into list calls", async () => {
    const { client, requests } = clientFor([ok([sbx("a")], "c1"), ok([sbx("b")], null)]);

    const first = await client.listSandboxes({ limit: 1 });
    const second = await client.listSandboxes({ cursor: first.nextCursor, limit: 1 });
    const third = second.nextCursor;

    expect(first.nextCursor).toBe("c1");
    expect(at(requests, 1).url).toContain("cursor=c1");
    expect(third).toBeNull();
  });

  it("treats a null cursor as the first page for sandboxes, snapshots and volumes", async () => {
    const { client, requests } = clientFor([ok([]), ok([]), ok([])]);

    await client.listSandboxes({ cursor: null });
    await client.listSnapshots({ cursor: null });
    await client.listVolumes({ cursor: null });

    expect(requests.map((r) => r.url)).toEqual([
      "http://sf.test/v1/sandboxes",
      "http://sf.test/v1/snapshots",
      "http://sf.test/v1/volumes",
    ]);
  });
});

describe("listSandboxesAll", () => {
  it("follows next_cursor with the same filters on every page", async () => {
    const { client, requests } = clientFor([
      ok([sbx("a"), sbx("b")], "c1"),
      ok([sbx("c")], "c2"),
      ok([sbx("d")], null),
    ]);

    const items = await collect(
      client.listSandboxesAll({ state: "started", labels: { team: "x" }, order: "desc", limit: 2 }),
    );

    expect(items.map((s) => s.id)).toEqual(["a", "b", "c", "d"]);
    expect(requests.map((r) => r.url)).toEqual([
      "http://sf.test/v1/sandboxes?state=started&limit=2&label=team%3Dx&order=desc",
      "http://sf.test/v1/sandboxes?state=started&cursor=c1&limit=2&label=team%3Dx&order=desc",
      "http://sf.test/v1/sandboxes?state=started&cursor=c2&limit=2&label=team%3Dx&order=desc",
    ]);
  });

  it("is lazy: stopping early fetches no further page", async () => {
    const { client, requests } = clientFor([ok([sbx("a")], "c1"), ok([sbx("b")], null)]);

    for await (const item of client.listSandboxesAll()) {
      expect(item.id).toBe("a");
      break;
    }

    expect(requests).toHaveLength(1);
  });

  it("fails on a cursor the server repeats instead of looping forever", async () => {
    const { client } = clientFor([ok([sbx("a")], "same"), ok([sbx("b")], "same")]);

    await expect(collect(client.listSandboxesAll())).rejects.toBeInstanceOf(InvalidResponseError);
  });

  it("sends the stop_cause, include_destroyed and order filters", async () => {
    const { client, requests } = clientFor([ok([])]);

    await client.listSandboxes({ stopCause: "oom_killed", includeDestroyed: true, order: "asc" });

    expect(at(requests, 0).url).toBe(
      "http://sf.test/v1/sandboxes?stop_cause=oom_killed&include_destroyed=true&order=asc",
    );
  });
});

describe("listSnapshotsAll and listVolumesAll", () => {
  it("pages through snapshots", async () => {
    const { client, requests } = clientFor([ok([snapshot("s1")], "n1"), ok([snapshot("s2")], null)]);

    const items = await collect(client.listSnapshotsAll({ limit: 1 }));

    expect(items.map((s) => s.id)).toEqual(["s1", "s2"]);
    expect(at(requests, 1).url).toBe("http://sf.test/v1/snapshots?cursor=n1&limit=1");
  });

  it("pages through volumes, with the label filter on every page", async () => {
    const { client, requests } = clientFor([ok([volume("v1")], "n1"), ok([volume("v2")], null)]);

    const items = await collect(client.listVolumesAll({ labels: { env: "ci" } }));

    expect(items.map((v) => v.id)).toEqual(["v1", "v2"]);
    expect(requests.map((r) => r.url)).toEqual([
      "http://sf.test/v1/volumes?label=env%3Dci",
      "http://sf.test/v1/volumes?label=env%3Dci&cursor=n1",
    ]);
  });
});
