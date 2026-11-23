/** Round 75: `createSnapshot` passes the REST `labels` field through (TS round backlog item). */

import { describe, expect, it } from "vitest";
import { SandfortClient, ValidationError, type FetchLike } from "../src/index.js";
import { snapshotFromSandboxBody } from "../src/snapshots.js";

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

function ok(data: unknown): Response {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function snapshot(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "snap_1",
    name: "base",
    state: "pending",
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

describe("snapshotFromSandboxBody labels", () => {
  it("omits the labels key when none are given", () => {
    expect(snapshotFromSandboxBody("sbx_1", "base")).toEqual({
      sandbox_id: "sbx_1",
      name: "base",
    });
  });

  it("carries the given labels as a copy", () => {
    const labels = { round: "r75", owner: "partner1" };

    const body = snapshotFromSandboxBody("sbx_1", "base", labels);

    expect(body).toEqual({ sandbox_id: "sbx_1", name: "base", labels });
    expect(body["labels"]).not.toBe(labels);
  });

  it("rejects an empty label key", () => {
    expect(() => snapshotFromSandboxBody("sbx_1", "base", { " ": "x" })).toThrow(ValidationError);
  });

  it("rejects more than 32 labels", () => {
    const labels = Object.fromEntries(
      Array.from({ length: 33 }, (_, index) => [`k${index}`, "v"]),
    );

    expect(() => snapshotFromSandboxBody("sbx_1", "base", labels)).toThrow(ValidationError);
  });

  it("rejects a label value over 256 characters", () => {
    expect(() => snapshotFromSandboxBody("sbx_1", "base", { k: "v".repeat(257) })).toThrow(
      ValidationError,
    );
  });
});

describe("snapshot response field preservation", () => {
  it("keeps populated labels and isolation on the result", async () => {
    const { client } = clientFor([
      ok(snapshot({ labels: { round: "r75" }, isolation: "gvisor" })),
    ]);

    const info = await client.createSnapshot("sbx_1", "base");

    expect(info.labels).toEqual({ round: "r75" });
    expect(info.isolation).toBe("gvisor");
  });

  it("keeps an empty labels object", async () => {
    const { client } = clientFor([ok(snapshot({ labels: {} }))]);

    const info = await client.createSnapshot("sbx_1", "base");

    expect(info.labels).toEqual({});
  });

  it("defaults labels to empty and isolation to null when absent", async () => {
    const { client } = clientFor([ok(snapshot())]);

    const info = await client.createSnapshot("sbx_1", "base");

    expect(info.labels).toEqual({});
    expect(info.isolation).toBeNull();
  });

  it("preserves both fields on the get and list paths", async () => {
    const { client } = clientFor([
      ok(snapshot({ labels: { a: "1" }, isolation: null })),
      new Response(
        JSON.stringify({
          success: true,
          data: [snapshot({ labels: { b: "2" }, isolation: "container" })],
          meta: { next_cursor: null },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    ]);

    const got = await client.getSnapshot("snap_1");
    const page = await client.listSnapshots();

    expect(got.labels).toEqual({ a: "1" });
    expect(got.isolation).toBeNull();
    expect(page.items[0]?.labels).toEqual({ b: "2" });
    expect(page.items[0]?.isolation).toBe("container");
  });
});

describe("createSnapshot labels wire format", () => {
  it("sends labels in the from-sandbox body", async () => {
    const { client, requests } = clientFor([ok(snapshot({ labels: { round: "r75" } }))]);

    await client.createSnapshot("sbx_1", "base", { labels: { round: "r75" } });

    const sent = JSON.parse(requests[0]?.body ?? "{}") as Record<string, unknown>;
    expect(requests[0]?.url).toBe("http://sf.test/v1/snapshots/from-sandbox");
    expect(sent).toEqual({ sandbox_id: "sbx_1", name: "base", labels: { round: "r75" } });
  });

  it("keeps the body label-free when no labels are given", async () => {
    const { client, requests } = clientFor([ok(snapshot())]);

    await client.createSnapshot("sbx_1", "base");

    const sent = JSON.parse(requests[0]?.body ?? "{}") as Record<string, unknown>;
    expect(sent).toEqual({ sandbox_id: "sbx_1", name: "base" });
  });
});
