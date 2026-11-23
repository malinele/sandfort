import { describe, expect, it } from "vitest";
import pkg from "../package.json";
import {
  PACKAGE_NAME,
  Sandbox,
  SandfortError,
  SnapshotFailedError,
  SnapshotTimeoutError,
  USER_AGENT,
  VERSION,
  ValidationError,
  buildInfo,
} from "../src/index.js";
import { at, clientFor, failure, ok, sandboxPayload } from "./helpers.js";

const SNAPSHOT = {
  id: "snap_1",
  name: "s",
  state: "pending",
  image_ref: "img",
  layer_count: 1,
  created_at: "2026-11-01T09:00:00+00:00",
};

describe("runtime exports", () => {
  it("exports SnapshotFailedError and SnapshotTimeoutError as values usable with instanceof", async () => {
    const { client } = clientFor([ok(SNAPSHOT), ok({ ...SNAPSHOT, state: "error" })]);

    const failed: unknown = await client
      .createSnapshot("sbx_1", "s", { wait: true, pollIntervalS: 0.001 })
      .catch((e: unknown) => e);

    expect(failed).toBeInstanceOf(SnapshotFailedError);
    expect(failed).toBeInstanceOf(SandfortError);
    expect((failed as SnapshotFailedError).snapshotId).toBe("snap_1");
  });

  it("raises SnapshotTimeoutError when the wait budget runs out", async () => {
    const { client } = clientFor([ok(SNAPSHOT), ok(SNAPSHOT), ok(SNAPSHOT)]);

    const timedOut: unknown = await client
      .createSnapshot("sbx_1", "s", { wait: true, waitTimeoutS: 0.01, pollIntervalS: 0.01 })
      .catch((e: unknown) => e);

    expect(timedOut).toBeInstanceOf(SnapshotTimeoutError);
  });

  it("exports the Sandbox class so handles pass instanceof", async () => {
    const { client } = clientFor([ok(sandboxPayload())]);

    expect(await client.getSandbox("sbx_1")).toBeInstanceOf(Sandbox);
  });
});

describe("client-side validation errors", () => {
  it("are ValidationError (a SandfortError), not plain Error, and send nothing", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), ok(sandboxPayload())]);
    const sandbox = await client.getSandbox("sbx_1");
    requests.length = 0;

    const failures: unknown[] = [
      await sandbox.git.commit("/w", " ").catch((e: unknown) => e),
      await sandbox.git.add("/w", []).catch((e: unknown) => e),
      await sandbox.git
        .push("/w", { credential: { username: "u", token: "t" } })
        .catch((e: unknown) => e),
      await sandbox.git
        .push("/w", { credential: { username: "", token: "t" }, remoteUrl: "https://x.test/r.git" })
        .catch((e: unknown) => e),
      await client.createVolume(" ").catch((e: unknown) => e),
      await client.createSnapshot("", "n").catch((e: unknown) => e),
      await sandbox.getCommandLogs("s", "c", { offset: -1 }).catch((e: unknown) => e),
      await sandbox.runInSession("s", "  ").catch((e: unknown) => e),
    ];

    for (const failure of failures) {
      expect(failure).toBeInstanceOf(ValidationError);
      expect(failure).toBeInstanceOf(SandfortError);
    }
    expect(requests).toHaveLength(0);
  });

  it("covers empty baseUrl and apiKey", () => {
    expect(() => clientFor([], { baseUrl: "" })).toThrow(ValidationError);
    expect(() => clientFor([], { apiKey: "" })).toThrow(ValidationError);
  });

  it("rejects a fractional or out-of-range timeoutS instead of sending it", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);
    const sandbox = await client.getSandbox("sbx_1");
    requests.length = 0;

    for (const timeoutS of [0.5, 0, 3601]) {
      await expect(sandbox.processExec("true", { timeoutS })).rejects.toBeInstanceOf(ValidationError);
      await expect(sandbox.codeRun("python", "1", { timeoutS })).rejects.toBeInstanceOf(
        ValidationError,
      );
      await expect(sandbox.runInSession("s", "true", { timeoutS })).rejects.toBeInstanceOf(
        ValidationError,
      );
    }
    expect(requests).toHaveLength(0);
  });
});

describe("version and build info", () => {
  it("VERSION equals the version in package.json", () => {
    expect(VERSION).toBe(pkg.version);
    expect(PACKAGE_NAME).toBe(pkg.name);
    expect(buildInfo()).toEqual({ name: pkg.name, version: pkg.version });
  });

  it("sends the version in a User-Agent header on JSON and binary requests", async () => {
    const { client, requests } = clientFor([
      ok(sandboxPayload()),
      new Response(new Uint8Array([1])),
    ]);
    const sandbox = await client.getSandbox("sbx_1");
    await sandbox.fs.downloadFile("/a");

    expect(USER_AGENT).toBe(`sandfort-sdk-typescript/${pkg.version}`);
    expect(at(requests, 0).headers.get("User-Agent")).toBe(USER_AGENT);
    expect(at(requests, 1).headers.get("User-Agent")).toBe(USER_AGENT);
  });
});

describe("client.status()", () => {
  it("reads GET /v1/status into a typed StatusInfo", async () => {
    const { client, requests } = clientFor([
      ok({
        status: "degraded",
        version: "0.1.0",
        build_sha: "abc123",
        image_sha: "abc123",
        build_matches_image: true,
        started_at: "2026-11-11T08:00:00+00:00",
        notice: { message: "maintenance", updated_at: "2026-11-11T09:00:00+00:00" },
      }),
    ]);

    const info = await client.status();

    expect(at(requests, 0).url).toBe("http://sf.test/v1/status");
    expect(at(requests, 0).method).toBe("GET");
    expect(info.status).toBe("degraded");
    expect(info.buildSha).toBe("abc123");
    expect(info.buildMatchesImage).toBe(true);
    expect(info.startedAt).toEqual(new Date("2026-11-11T08:00:00+00:00"));
    expect(info.notice).toEqual({
      message: "maintenance",
      updatedAt: new Date("2026-11-11T09:00:00+00:00"),
    });
  });

  it("handles unknown shas and no notice", async () => {
    const { client } = clientFor([
      ok({
        status: "ok",
        version: "0.1.0",
        build_sha: null,
        image_sha: null,
        build_matches_image: null,
        started_at: "2026-11-11T08:00:00+00:00",
        notice: null,
      }),
    ]);

    const info = await client.status();

    expect(info.buildSha).toBeNull();
    expect(info.buildMatchesImage).toBeNull();
    expect(info.notice).toBeNull();
  });

  it("retries a 503 CAPACITY like any GET", async () => {
    const { client, requests } = clientFor(
      [
        failure(503, "CAPACITY"),
        ok({ status: "ok", version: "1", started_at: "2026-11-11T08:00:00+00:00" }),
      ],
      { sleep: () => Promise.resolve() },
    );

    expect((await client.status()).status).toBe("ok");
    expect(requests).toHaveLength(2);
  });
});

describe("REST facades on the client", () => {
  it("exposes webhooks, apiKeys, audit and usage as stable read-only properties", () => {
    const { client } = clientFor([]);

    expect(client.webhooks).toBe(client.webhooks);
    expect(client.apiKeys).toBe(client.apiKeys);
    expect(client.audit).toBe(client.audit);
    expect(client.usage).toBe(client.usage);
    expect(() => {
      (client as unknown as Record<string, unknown>)["webhooks"] = 1;
    }).toThrow(TypeError);
  });
});
