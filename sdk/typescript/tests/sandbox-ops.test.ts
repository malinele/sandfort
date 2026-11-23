import { describe, expect, it } from "vitest";
import { Conflict, NotFound, Sandbox, ValidationError } from "../src/index.js";
import { at, clientFor, failure, ok, sandboxPayload } from "./helpers.js";

const BASE = "http://sf.test/v1/sandboxes/sbx_1";

function created(data: unknown): Response {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 201,
    headers: { "content-type": "application/json" },
  });
}

const PREVIEW = {
  token: "pv_abc",
  url: "https://3000-pv_abc.preview.sf.test/",
  port: 3000,
  expires_at: "2026-11-11T10:00:00+00:00",
};

describe("updateSandbox", () => {
  it("PATCHes only the fields given and returns a Sandbox handle", async () => {
    const { client, requests } = clientFor([
      ok(sandboxPayload("started", { labels: { team: "a" }, auto_stop_minutes: 30 })),
    ]);

    const sandbox = await client.updateSandbox("sbx_1", {
      labels: { team: "a" },
      autoStopMinutes: 30,
      autoDeleteMinutes: -1,
      public: true,
    });

    expect(sandbox).toBeInstanceOf(Sandbox);
    expect(sandbox.labels).toEqual({ team: "a" });
    expect(sandbox.autoStopMinutes).toBe(30);
    expect(at(requests, 0).method).toBe("PATCH");
    expect(at(requests, 0).url).toBe(BASE);
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({
      labels: { team: "a" },
      auto_stop_minutes: 30,
      auto_delete_minutes: -1,
      public: true,
    });
  });

  it("sends labels: null to remove every label", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await client.updateSandbox("sbx_1", { labels: null });

    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({ labels: null });
  });

  it.each([
    [{}],
    [{ autoStopMinutes: 1.5 }],
    [{ autoStopMinutes: -2 }],
    [{ autoDeleteMinutes: 525_601 }],
    [{ labels: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, "v"])) }],
    [{ labels: { ["k".repeat(64)]: "v" } }],
    [{ labels: { k: "v".repeat(257) } }],
    [{ public: "yes" as unknown as boolean }],
  ])("rejects %j before any request", async (options) => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await expect(client.updateSandbox("sbx_1", options)).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("rejects a blank sandbox id", async () => {
    const { client } = clientFor([]);

    await expect(client.updateSandbox(" ", { public: false })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });

  it("is available on the Sandbox handle and returns the new record", async () => {
    const { client, requests } = clientFor([
      ok(sandboxPayload()),
      ok(sandboxPayload("started", { labels: { a: "b" } })),
    ]);
    const sandbox = await client.getSandbox("sbx_1");

    const updated = await sandbox.update({ labels: { a: "b" } });

    expect(updated).toBeInstanceOf(Sandbox);
    expect(updated.labels).toEqual({ a: "b" });
    expect(sandbox.labels).toEqual({});
    expect(at(requests, 1).url).toBe(BASE);
    expect(at(requests, 1).method).toBe("PATCH");
  });
});

describe("resetSandbox", () => {
  it("POSTs to /reset and returns the sandbox", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload("started"))]);

    const sandbox = await client.resetSandbox("sbx_1");

    expect(sandbox.state).toBe("started");
    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe(`${BASE}/reset`);
    expect(at(requests, 0).body).toBeUndefined();
  });

  it("raises Conflict for a state the server refuses", async () => {
    const { client } = clientFor([failure(409, "INVALID_STATE")]);

    await expect(client.resetSandbox("sbx_1")).rejects.toBeInstanceOf(Conflict);
  });

  it("is available on the Sandbox handle", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), ok(sandboxPayload())]);
    const sandbox = await client.getSandbox("sbx_1");

    const fresh = await sandbox.reset();

    expect(fresh).toBeInstanceOf(Sandbox);
    expect(at(requests, 1).url).toBe(`${BASE}/reset`);
  });
});

describe("resizeSandbox", () => {
  it("POSTs the resource fields given, in the wire names", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload("stopped"))]);

    const sandbox = await client.resizeSandbox("sbx_1", { cpuMillicores: 2000, memoryMib: 4096 });

    expect(sandbox.state).toBe("stopped");
    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe(`${BASE}/resize`);
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({
      cpu_millicores: 2000,
      memory_mib: 4096,
    });
  });

  it("passes the 409 of a sandbox that is not stopped through as Conflict", async () => {
    const { client, requests } = clientFor([failure(409, "INVALID_STATE")]);

    await expect(client.resizeSandbox("sbx_1", { diskGib: 20 })).rejects.toBeInstanceOf(Conflict);
    expect(requests).toHaveLength(1);
  });

  it.each([
    [{}],
    [{ cpuMillicores: 99 }],
    [{ cpuMillicores: 1_000_001 }],
    [{ memoryMib: 63 }],
    [{ memoryMib: 1.5 }],
    [{ diskGib: 0 }],
    [{ diskGib: 1_048_577 }],
  ])("rejects %j before any request", async (options) => {
    const { client, requests } = clientFor([]);

    await expect(client.resizeSandbox("sbx_1", options)).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("is available on the Sandbox handle", async () => {
    const stopped = sandboxPayload("stopped");
    const { client, requests } = clientFor([ok(stopped), ok(stopped)]);
    const sandbox = await client.getSandbox("sbx_1");

    const resized = await sandbox.resize({ diskGib: 20 });

    expect(resized).toBeInstanceOf(Sandbox);
    expect(JSON.parse(at(requests, 1).body ?? "")).toEqual({ disk_gib: 20 });
  });
});

describe("listIsolation", () => {
  it("GETs /v1/isolation and maps the tiers", async () => {
    const { client, requests } = clientFor([
      ok({ default: "container", available: ["container", "gvisor"] }),
    ]);

    const info = await client.listIsolation();

    expect(info).toEqual({ default: "container", available: ["container", "gvisor"] });
    expect(at(requests, 0).url).toBe("http://sf.test/v1/isolation");
    expect(at(requests, 0).method).toBe("GET");
  });

  it("is available on the Sandbox handle", async () => {
    const { client } = clientFor([
      ok(sandboxPayload()),
      ok({ default: "container", available: ["container"] }),
    ]);
    const sandbox = await client.getSandbox("sbx_1");

    expect((await sandbox.listIsolation()).available).toEqual(["container"]);
  });

  it("rejects a reply without the tiers", async () => {
    const { client } = clientFor([ok({ default: "container" })]);

    await expect(client.listIsolation()).rejects.toThrow(/isolation tiers/);
  });
});

describe("mintPreviewToken", () => {
  it("POSTs port and ttl and maps the 201 reply", async () => {
    const { client, requests } = clientFor([created(PREVIEW)]);

    const token = await client.mintPreviewToken("sbx_1", { port: 3000, ttlSeconds: 600 });

    expect(token.token).toBe("pv_abc");
    expect(token.url).toBe(PREVIEW.url);
    expect(token.port).toBe(3000);
    expect(token.expiresAt).toEqual(new Date("2026-11-11T10:00:00+00:00"));
    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe(`${BASE}/preview-tokens`);
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({ port: 3000, ttl_seconds: 600 });
  });

  it("leaves ttl_seconds out when it is not given (server default)", async () => {
    const { client, requests } = clientFor([created(PREVIEW)]);

    await client.mintPreviewToken("sbx_1", { port: 3000 });

    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({ port: 3000 });
  });

  it.each([
    [{ port: 1023 }],
    [{ port: 65_536 }],
    [{ port: 80.5 }],
    [{ port: 3000, ttlSeconds: 59 }],
    [{ port: 3000, ttlSeconds: 604_801 }],
  ])("rejects %j before any request", async (options) => {
    const { client, requests } = clientFor([]);

    await expect(client.mintPreviewToken("sbx_1", options)).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(requests).toHaveLength(0);
  });

  it("raises Conflict (no_container) for a sandbox that is not started", async () => {
    const { client } = clientFor([failure(409, "no_container")]);

    await expect(client.mintPreviewToken("sbx_1", { port: 3000 })).rejects.toBeInstanceOf(Conflict);
  });

  it("is available on the Sandbox handle", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), created(PREVIEW)]);
    const sandbox = await client.getSandbox("sbx_1");

    expect((await sandbox.mintPreviewToken({ port: 3000 })).token).toBe("pv_abc");
    expect(at(requests, 1).url).toBe(`${BASE}/preview-tokens`);
  });
});

describe("fs stat", () => {
  const ENTRY = {
    name: "main.py",
    path: "/tmp/main.py",
    kind: "file",
    size_bytes: 11,
    mode: "644",
    modified_at: "2026-11-11T09:00:00+00:00",
  };

  it("GETs fs/stat with the path and maps the entry", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), ok({ entry: ENTRY })]);
    const sandbox = await client.getSandbox("sbx_1");

    const entry = await sandbox.fs.stat("/tmp/main.py");

    expect(entry.kind).toBe("file");
    expect(entry.sizeBytes).toBe(11);
    expect(entry.modifiedAt).toEqual(new Date("2026-11-11T09:00:00+00:00"));
    expect(at(requests, 1).method).toBe("GET");
    expect(at(requests, 1).url).toBe(`${BASE}/toolbox/fs/stat?path=%2Ftmp%2Fmain.py`);
  });

  it("is on the client too and raises NotFound for a missing path", async () => {
    const { client } = clientFor([ok({ entry: ENTRY }), failure(404, "NOT_FOUND")]);

    expect((await client.statPath("sbx_1", "/tmp/main.py")).name).toBe("main.py");
    await expect(client.statPath("sbx_1", "/nope")).rejects.toBeInstanceOf(NotFound);
  });

  it("rejects a reply without the entry, and a blank path", async () => {
    const { client } = clientFor([ok({})]);

    await expect(client.statPath("sbx_1", "/x")).rejects.toThrow(/entry/);
    await expect(client.statPath("sbx_1", " ")).rejects.toBeInstanceOf(ValidationError);
  });
});
