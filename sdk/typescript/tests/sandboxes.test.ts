import { describe, expect, it } from "vitest";
import {
  NotFound,
  SandboxFailedError,
  SandboxTimeoutError,
  SandfortClient,
  type FetchLike,
} from "../src/index.js";

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

function sandbox(state: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { id: "sbx_1", name: "demo", state, ...extra };
}

function clientFor(queue: Response[]): { client: SandfortClient; requests: Recorded[] } {
  const { fetch, requests } = stub(queue);
  return { client: new SandfortClient({ baseUrl: "http://sf.test", apiKey: "sf_key", fetch }), requests };
}

function at(requests: Recorded[], index: number): Recorded {
  const item = requests[index];
  if (item === undefined) throw new Error(`no request recorded at ${index}`);
  return item;
}

describe("createSandbox", () => {
  it("sends the wire field names byte-exact", async () => {
    const { client, requests } = clientFor([ok(sandbox("started"))]);

    await client.createSandbox({
      name: "demo",
      snapshot: "snap_1",
      env: { A: "1" },
      labels: { k: "v" },
      blockNetwork: true,
      autoStopMinutes: 30,
    });

    const sent = at(requests, 0);
    expect(sent.method).toBe("POST");
    expect(sent.url).toBe("http://sf.test/v1/sandboxes");
    expect(sent.body).toBe(
      '{"name":"demo","snapshot":"snap_1","env":{"A":"1"},"labels":{"k":"v"},' +
        '"network":{"block_all":true},"auto_stop_minutes":30}',
    );
  });

  it("omits unset options and sends an empty object", async () => {
    const { client, requests } = clientFor([ok(sandbox("started"))]);

    await client.createSandbox();

    expect(at(requests, 0).body).toBe("{}");
  });

  it("maps the wire payload to camelCase fields", async () => {
    const { client } = clientFor([
      ok(
        sandbox("started", {
          resources: { cpu_millicores: 2000, memory_mib: 1024, disk_gib: 5 },
          env: { A: "1" },
          labels: { k: "v" },
          network: { block_all: true },
          public: true,
          auto_stop_minutes: 30,
          auto_delete_minutes: 60,
          error_reason: null,
          job_id: "job_1",
        }),
      ),
    ]);

    const info = await client.createSandbox();

    expect(info).toEqual({
      id: "sbx_1",
      name: "demo",
      state: "started",
      resources: { cpuMillicores: 2000, memoryMib: 1024, diskGib: 5 },
      env: { A: "1" },
      labels: { k: "v" },
      blockNetwork: true,
      public: true,
      autoStopMinutes: 30,
      autoDeleteMinutes: 60,
      errorReason: null,
      jobId: "job_1",
    });
  });

  it("does not poll when wait is false", async () => {
    const { client, requests } = clientFor([ok(sandbox("creating"))]);

    const info = await client.createSandbox({ wait: false });

    expect(info.state).toBe("creating");
    expect(requests).toHaveLength(1);
  });

  it("polls getSandbox until the sandbox is started", async () => {
    const { client, requests } = clientFor([
      ok(sandbox("creating")),
      ok(sandbox("starting")),
      ok(sandbox("started")),
    ]);

    const info = await client.createSandbox({ pollIntervalS: 0.001 });

    expect(info.state).toBe("started");
    expect(requests).toHaveLength(3);
    expect(at(requests, 1).method).toBe("GET");
    expect(at(requests, 1).url).toMatch(
      /^http:\/\/sf\.test\/v1\/sandboxes\/sbx_1\?wait_for=started&timeout_s=/,
    );
  });

  it("throws SandboxTimeoutError when the wait budget is spent", async () => {
    const { client } = clientFor(Array.from({ length: 200 }, () => ok(sandbox("creating"))));

    await expect(
      client.createSandbox({ waitTimeoutS: 0.05, pollIntervalS: 0.01 }),
    ).rejects.toBeInstanceOf(SandboxTimeoutError);
  });

  it("throws SandboxFailedError when the sandbox lands in error", async () => {
    const { client } = clientFor([
      ok(sandbox("creating")),
      ok(sandbox("error", { error_reason: "image pull failed" })),
    ]);

    const error = await client.createSandbox({ pollIntervalS: 0.001 }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(SandboxFailedError);
    expect((error as SandboxFailedError).state).toBe("error");
    expect((error as SandboxFailedError).message).toContain("image pull failed");
  });
});

describe("sandbox lifecycle calls", () => {
  it("getSandbox reads one sandbox", async () => {
    const { client, requests } = clientFor([ok(sandbox("stopped"))]);

    const info = await client.getSandbox("sbx_1");

    expect(info.state).toBe("stopped");
    expect(at(requests, 0).method).toBe("GET");
    expect(at(requests, 0).url).toBe("http://sf.test/v1/sandboxes/sbx_1");
  });

  it("start, stop and delete use the matching method and path", async () => {
    const { client, requests } = clientFor([
      ok(sandbox("starting")),
      ok(sandbox("stopping")),
      ok(sandbox("destroying")),
    ]);

    await client.startSandbox("sbx_1");
    await client.stopSandbox("sbx_1");
    await client.deleteSandbox("sbx_1");

    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      "POST http://sf.test/v1/sandboxes/sbx_1/start",
      "POST http://sf.test/v1/sandboxes/sbx_1/stop",
      "DELETE http://sf.test/v1/sandboxes/sbx_1",
    ]);
  });

  it("percent-encodes the sandbox id in the path", async () => {
    const { client, requests } = clientFor([ok(sandbox("started"))]);

    await client.getSandbox("a/b");

    expect(at(requests, 0).url).toBe("http://sf.test/v1/sandboxes/a%2Fb");
  });

  it("surfaces typed API errors", async () => {
    const body = { success: false, error: { code: "NOT_FOUND", message: "gone" } };
    const { client } = clientFor([new Response(JSON.stringify(body), { status: 404 })]);

    await expect(client.getSandbox("sbx_x")).rejects.toBeInstanceOf(NotFound);
  });
});

describe("listSandboxes", () => {
  it("passes filters, cursor and limit and returns the page", async () => {
    const { client, requests } = clientFor([
      ok([sandbox("started"), sandbox("started", { id: "sbx_2" })], "c2"),
    ]);

    const page = await client.listSandboxes({
      state: "started",
      labels: { a: "1" },
      cursor: "c1",
      limit: 2,
    });

    expect(at(requests, 0).url).toBe(
      "http://sf.test/v1/sandboxes?state=started&cursor=c1&limit=2&label=a%3D1",
    );
    expect(page.items.map((s) => s.id)).toEqual(["sbx_1", "sbx_2"]);
    expect(page.nextCursor).toBe("c2");
  });

  it("returns a null cursor on the last page and sends no query by default", async () => {
    const { client, requests } = clientFor([ok([])]);

    const page = await client.listSandboxes();

    expect(at(requests, 0).url).toBe("http://sf.test/v1/sandboxes");
    expect(page.items).toEqual([]);
    expect(page.nextCursor).toBeNull();
  });
});
