import { describe, expect, it } from "vitest";
import { SandfortClient, ValidationError, type FetchLike } from "../src/index.js";

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

function registered(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "snap_reg",
    name: "busybox:1.36",
    state: "ready",
    image_ref: "busybox@sha256:abc",
    layer_count: 1,
    created_at: "2026-11-18T17:00:00+00:00",
    digest: "sha256:abc",
    source_sandbox_id: null,
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

describe("registerSnapshot", () => {
  it("posts only the image when neither name nor labels are given", async () => {
    const { client, requests } = clientFor([ok(registered())]);

    const info = await client.registerSnapshot("busybox:1.36@sha256:abc");

    const sent = at(requests, 0);
    expect(sent.method).toBe("POST");
    expect(sent.url).toBe("http://sf.test/v1/snapshots");
    expect(sent.body).toBe('{"image":"busybox:1.36@sha256:abc"}');
    expect(info.id).toBe("snap_reg");
    expect(info.state).toBe("ready");
    expect(info.sourceSandboxId).toBeNull();
    expect(requests).toHaveLength(1);
  });

  it("sends name and labels when given", async () => {
    const { client, requests } = clientFor([ok(registered({ name: "f-fixture" }))]);

    await client.registerSnapshot("busybox:1.36@sha256:abc", {
      name: "f-fixture",
      labels: { round: "g", owner: "partner1" },
    });

    expect(at(requests, 0).body).toBe(
      '{"image":"busybox:1.36@sha256:abc","name":"f-fixture","labels":{"round":"g","owner":"partner1"}}',
    );
  });

  it("rejects a blank image before any request", async () => {
    const { client, requests } = clientFor([]);

    const error = await client.registerSnapshot("   ").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("rejects bad labels before any request", async () => {
    const { client, requests } = clientFor([]);

    const error = await client
      .registerSnapshot("busybox:1.36", { labels: { "": "x" } })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });
});
