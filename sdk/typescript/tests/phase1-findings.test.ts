/**
 * Regression tests for the design-partner phase 1 findings (2026-11-16): TS-001 (sandbox
 * handles drop response metadata), TS-002 (org facades ignore per-call resilience options)
 * and TS-004 (no header fallback for the request id of an error without an envelope id).
 */

import { describe, expect, it } from "vitest";
import { RateLimited, RequestTimeoutError, SandfortError } from "../src/index.js";
import { clientFor, failure, hangUntilAborted, ok, sandboxPayload } from "./helpers.js";

const PERIOD = {
  from: new Date("2026-11-01T00:00:00Z"),
  to: new Date("2026-11-16T00:00:00Z"),
};

const METADATA = {
  created_at: "2026-11-16T10:00:00Z",
  updated_at: "2026-11-16T10:05:00Z",
  stopped_at: "2026-11-16T10:10:00Z",
  stop_cause: "requested",
  isolation: "gvisor",
  volumes: [{ volume_id: "vol_1", mount_path: "/data", read_only: true }],
  egress_allowlist: ["example.com"],
};

describe("TS-001: sandbox handles keep response metadata", () => {
  it("exposes all seven optional fields on a fetched handle", async () => {
    const { client } = clientFor([ok(sandboxPayload("stopped", METADATA))]);

    const sandbox = await client.getSandbox("sbx_1");

    expect(sandbox.createdAt).toEqual(new Date("2026-11-16T10:00:00Z"));
    expect(sandbox.updatedAt).toEqual(new Date("2026-11-16T10:05:00Z"));
    expect(sandbox.stoppedAt).toEqual(new Date("2026-11-16T10:10:00Z"));
    expect(sandbox.stopCause).toBe("requested");
    expect(sandbox.isolation).toBe("gvisor");
    expect(sandbox.volumes).toEqual([{ volumeId: "vol_1", mountPath: "/data", readOnly: true }]);
    expect(sandbox.egressAllowlist).toEqual(["example.com"]);
  });

  it("serializes as its SandboxInfo: metadata keys in JSON, no toolbox keys", async () => {
    const { client } = clientFor([ok(sandboxPayload("stopped", METADATA))]);

    const sandbox = await client.getSandbox("sbx_1");
    const plain = JSON.parse(JSON.stringify(sandbox)) as Record<string, unknown>;

    expect(plain["isolation"]).toBe("gvisor");
    expect(plain["egressAllowlist"]).toEqual(["example.com"]);
    expect(plain["volumes"]).toEqual([{ volumeId: "vol_1", mountPath: "/data", readOnly: true }]);
    expect(Object.keys(sandbox)).not.toContain("fs");
    expect(Object.keys(sandbox)).not.toContain("git");
  });

  it("leaves the fields undefined and out of JSON when the server omits them", async () => {
    const { client } = clientFor([ok(sandboxPayload())]);

    const sandbox = await client.getSandbox("sbx_1");

    expect(sandbox.isolation).toBeUndefined();
    expect(sandbox.volumes).toBeUndefined();
    const plain = JSON.parse(JSON.stringify(sandbox)) as Record<string, unknown>;
    expect("isolation" in plain).toBe(false);
    expect("volumes" in plain).toBe(false);
  });

  it("keeps the fields on createSandbox and listSandboxes returns", async () => {
    const { client } = clientFor([
      ok(sandboxPayload("started", METADATA)),
      ok([sandboxPayload("started", METADATA)]),
    ]);

    const created = await client.createSandbox({ wait: false });
    const listed = await client.listSandboxes();

    expect(created.isolation).toBe("gvisor");
    expect(listed.items[0]?.egressAllowlist).toEqual(["example.com"]);
  });

  it("keeps the fields through update, reset and resize returns", async () => {
    const replies = [
      ok(sandboxPayload("started", METADATA)),
      ok(sandboxPayload("started", METADATA)),
      ok(sandboxPayload("stopped", METADATA)),
    ];
    const { client } = clientFor(replies);

    const updated = await client.updateSandbox("sbx_1", { labels: { a: "b" } });
    const reset = await client.resetSandbox("sbx_1");
    const resized = await client.resizeSandbox("sbx_1", { memoryMib: 512 });

    for (const sandbox of [updated, reset, resized]) {
      expect(sandbox.isolation).toBe("gvisor");
      expect(sandbox.egressAllowlist).toEqual(["example.com"]);
      expect(sandbox.createdAt).toEqual(new Date("2026-11-16T10:00:00Z"));
    }
  });
});

describe("TS-002: org facades honor per-call resilience options", () => {
  const throttled = (): Response => failure(429, "RATE_LIMITED", { "retry-after": "0" });

  interface CaseDef {
    name: string;
    run: (client: ReturnType<typeof clientFor>["client"]) => Promise<unknown>;
  }

  const calls: CaseDef[] = [
    { name: "webhooks.list", run: (c) => c.webhooks.list({ retries: 0 }) },
    { name: "apiKeys.list", run: (c) => c.apiKeys.list({ retries: 0 }) },
    { name: "audit.list", run: (c) => c.audit.list({ retries: 0 }).then((p) => p.items) },
    { name: "audit.verifyChain", run: (c) => c.audit.verifyChain({ retries: 0 }) },
    { name: "usage.get", run: (c) => c.usage.get({ ...PERIOD, retries: 0 }) },
  ];

  it.each(calls)("per-call retries: 0 wins over client retries for $name", async ({ run }) => {
    const { client, requests } = clientFor([throttled(), throttled(), throttled()], {
      retries: 2,
    });

    await expect(run(client)).rejects.toBeInstanceOf(RateLimited);
    expect(requests).toHaveLength(1);
  });

  it("per-call retries: 0 wins for audit.exportLines", async () => {
    const { client, requests } = clientFor([throttled(), throttled(), throttled()], {
      retries: 2,
    });

    const lines = client.audit.exportLines({ retries: 0 });
    await expect(lines.next()).rejects.toBeInstanceOf(RateLimited);
    expect(requests).toHaveLength(1);
  });

  const boundedCalls: CaseDef[] = [
    { name: "webhooks.list", run: (c) => c.webhooks.list({ timeoutMs: 20 }) },
    { name: "apiKeys.list", run: (c) => c.apiKeys.list({ timeoutMs: 20 }) },
    { name: "audit.list", run: (c) => c.audit.list({ timeoutMs: 20 }) },
    { name: "audit.verifyChain", run: (c) => c.audit.verifyChain({ timeoutMs: 20 }) },
    { name: "usage.get", run: (c) => c.usage.get({ ...PERIOD, timeoutMs: 20 }) },
  ];

  it.each(boundedCalls)("per-call timeoutMs caps a slow reply for $name", async ({ run }) => {
    const { client } = clientFor([hangUntilAborted], { timeoutMs: 60_000, retries: 0 });

    await expect(run(client)).rejects.toBeInstanceOf(RequestTimeoutError);
  });

  it("per-call timeoutMs caps the audit export head wait", async () => {
    const { client } = clientFor([hangUntilAborted], { timeoutMs: 60_000, retries: 0 });

    const lines = client.audit.exportLines({ timeoutMs: 20 });
    await expect(lines.next()).rejects.toBeInstanceOf(RequestTimeoutError);
  });

  it("per-call deadlineMs caps the audit export head wait", async () => {
    const { client } = clientFor([hangUntilAborted], { timeoutMs: 60_000, retries: 0 });

    const lines = client.audit.exportLines({ deadlineMs: 20 });
    await expect(lines.next()).rejects.toBeInstanceOf(RequestTimeoutError);
  });

  it("no facade passes a bare signal to the transport any more", async () => {
    const { readdir, readFile } = await import("node:fs/promises");
    const dir = new URL("../src/", import.meta.url);
    const names = (await readdir(dir)).filter((name: string) => name.endsWith(".ts"));

    for (const name of names) {
      const text = await readFile(new URL(name, dir), "utf8");
      // The resilience boundary itself (withCallOptions + raw signal) is the one place a
      // bare signal is correct: resilience.ts defines callArgs, the others call withResilience.
      if (name === "resilience.ts" || text.includes("withResilience(")) continue;
      expect(text, `${name} drops per-call options`).not.toMatch(
        /signal: (options|call|request)\.signal/,
      );
    }
  });
});

describe("TS-004: request id falls back to the reply header", () => {
  it("uses X-Request-ID when the error envelope has no request_id", async () => {
    const { client } = clientFor([
      failure(404, "NOT_FOUND", { "x-request-id": "req-header-1" }),
    ]);

    const error = await client.getSandbox("sbx_1").catch((cause: unknown) => cause);

    expect(error).toBeInstanceOf(SandfortError);
    expect((error as { requestId?: string }).requestId).toBe("req-header-1");
  });

  it("prefers the envelope request_id over the header", async () => {
    const body = {
      success: false,
      error: { code: "NOT_FOUND", message: "gone", request_id: "req-body-1" },
    };
    const reply = new Response(JSON.stringify(body), {
      status: 404,
      headers: { "content-type": "application/json", "x-request-id": "req-header-2" },
    });
    const { client } = clientFor([reply]);

    const error = await client.getSandbox("sbx_1").catch((cause: unknown) => cause);

    expect((error as { requestId?: string }).requestId).toBe("req-body-1");
  });
});
