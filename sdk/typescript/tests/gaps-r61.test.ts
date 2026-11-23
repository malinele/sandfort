import { describe, expect, it } from "vitest";
import { InvalidResponseError, ValidationError, type VolumeMountInfo } from "../src/index.js";
import { sandboxFromPayload } from "../src/models.js";
import { SnapshotTimeoutError } from "../src/snapshots.js";
import { volumeFromPayload, type VolumeCreateOptions } from "../src/volumes.js";
import { at, clientFor, ok, sandboxPayload } from "./helpers.js";
import { contextPayload, created } from "./contexts-helpers.js";

const CODE_RUN_URL = "http://sf.test/v1/sandboxes/sbx_1/toolbox/process/code-run";

function execReply(): Record<string, unknown> {
  return {
    exit_code: 0,
    stdout: "",
    stderr: "",
    timed_out: false,
    truncated: false,
    duration_ms: 1,
  };
}

function volumePayload(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "vol_1",
    name: "data",
    state: "ready",
    created_at: "2026-11-01T09:00:00+00:00",
    size_bytes: null,
    ...extra,
  };
}

function snapshotPayload(state: string): Record<string, unknown> {
  return {
    id: "snap_1",
    name: "base",
    state,
    image_ref: "sandfort/snap:1",
    layer_count: 1,
    created_at: "2026-11-01T09:00:00+00:00",
  };
}

describe("codeRun cwd", () => {
  it("sends cwd on the wire when given", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), ok(execReply())]);
    const sandbox = await client.getSandbox("sbx_1");

    await sandbox.codeRun("python", "print(1)", { cwd: "/work" });

    const sent = at(requests, 1);
    expect(sent.url).toBe(CODE_RUN_URL);
    expect(JSON.parse(sent.body ?? "{}")).toEqual({
      language: "python",
      code: "print(1)",
      cwd: "/work",
      timeout_s: 60,
    });
  });

  it("omits cwd when not given", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), ok(execReply())]);
    const sandbox = await client.getSandbox("sbx_1");

    await sandbox.codeRun("bash", "true");

    expect(JSON.parse(at(requests, 1).body ?? "{}")).not.toHaveProperty("cwd");
  });

  it.each([
    ["", "cwd must not be empty"],
    ["   ", "cwd must not be empty"],
  ])("rejects cwd %j locally without sending", async (cwd, message) => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);
    const sandbox = await client.getSandbox("sbx_1");

    const error = await sandbox.codeRun("python", "1", { cwd }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ValidationError);
    expect((error as Error).message).toContain(message);
    expect(requests).toHaveLength(1);
  });

  it("sends a relative cwd, as exec does: the API accepts any non-blank string", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), ok(execReply())]);
    const sandbox = await client.getSandbox("sbx_1");

    await sandbox.codeRun("python", "1", { cwd: "work/dir" });

    expect(JSON.parse(at(requests, 1).body ?? "{}")).toHaveProperty("cwd", "work/dir");
  });
});

describe("exec cwd", () => {
  it("sends a relative cwd", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), ok(execReply())]);
    const sandbox = await client.getSandbox("sbx_1");

    await sandbox.processExec("ls", { cwd: "work" });

    expect(JSON.parse(at(requests, 1).body ?? "{}")).toHaveProperty("cwd", "work");
  });

  it.each(["", "   "])("rejects blank cwd %j locally without sending", async (cwd) => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);
    const sandbox = await client.getSandbox("sbx_1");

    const error = await sandbox.processExec("ls", { cwd }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ValidationError);
    expect((error as Error).message).toContain("cwd must not be empty");
    expect(requests).toHaveLength(1);
  });
});

describe("createVolume labels", () => {
  it("sends labels with the name so listVolumes can filter on them", async () => {
    const created = volumePayload({ labels: { team: "a" } });
    const { client, requests } = clientFor([ok(created), ok([created], null)]);
    const options: VolumeCreateOptions = { labels: { team: "a" } };

    await client.createVolume("data", options);
    const page = await client.listVolumes({ labels: { team: "a" } });

    expect(JSON.parse(at(requests, 0).body ?? "{}")).toEqual({
      name: "data",
      labels: { team: "a" },
    });
    expect(at(requests, 1).url).toContain("label=team%3Da");
    expect(page.items.map((v) => v.id)).toEqual(["vol_1"]);
  });

  it("accepts an inline options literal in typed code", async () => {
    const { client, requests } = clientFor([ok(volumePayload({ labels: { team: "a" } }))]);

    await client.createVolume("data", { labels: { team: "a" } });

    expect(JSON.parse(at(requests, 0).body ?? "{}")).toEqual({
      name: "data",
      labels: { team: "a" },
    });
  });

  it("rejects a blank label key before sending", async () => {
    const { client, requests } = clientFor([]);

    for (const key of ["", "   "]) {
      const error = await client
        .createVolume("data", { labels: { [key]: "v" } })
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ValidationError);
      expect((error as Error).message).toContain("label key must not be empty");
    }
    expect(requests).toHaveLength(0);
  });

  it("keeps the name-only body when no labels are given", async () => {
    const { client, requests } = clientFor([ok(volumePayload())]);

    await client.createVolume("data");

    expect(at(requests, 0).body).toBe('{"name":"data"}');
  });

  it("rejects a label value longer than 256 characters before sending", async () => {
    const { client, requests } = clientFor([]);
    const options: VolumeCreateOptions = { labels: { k: "v".repeat(257) } };

    await expect(client.createVolume("data", options)).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("rejects more than 32 labels before sending", async () => {
    const { client, requests } = clientFor([]);
    const labels = Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, "v"]));
    const options: VolumeCreateOptions = { labels };

    await expect(client.createVolume("data", options)).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });
});

describe("SnapshotTimeoutError", () => {
  it("carries the snapshot id when the wait budget is spent", async () => {
    const replies = Array.from({ length: 200 }, () => ok(snapshotPayload("pending")));
    const { client } = clientFor(replies);

    const error = await client
      .createSnapshot("sbx_1", "base", { wait: true, waitTimeoutS: 0.05, pollIntervalS: 0.01 })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(SnapshotTimeoutError);
    expect((error as SnapshotTimeoutError).snapshotId).toBe("snap_1");
  });

  it("carries an id the message regex could not recover", async () => {
    const odd = { ...snapshotPayload("pending"), id: "snap one" };
    const { client } = clientFor(Array.from({ length: 200 }, () => ok(odd)));

    const error = await client
      .createSnapshot("sbx_1", "base", { wait: true, waitTimeoutS: 0.05, pollIntervalS: 0.01 })
      .catch((e: unknown) => e);

    expect((error as SnapshotTimeoutError).snapshotId).toBe("snap one");
  });

  it("takes an explicit snapshot id", () => {
    const error = new SnapshotTimeoutError("late", "snap_9");

    expect(error.snapshotId).toBe("snap_9");
    expect(error.message).toBe("late");
  });
});

describe("sandbox info extra fields", () => {
  it("maps timestamps, stop cause, isolation, volumes and egress allowlist", () => {
    const info = sandboxFromPayload(
      sandboxPayload("stopped", {
        created_at: "2026-11-01T09:00:00+00:00",
        updated_at: "2026-11-01T10:00:00+00:00",
        stopped_at: "2026-11-01T10:00:00+00:00",
        stop_cause: "auto_stop",
        isolation: "gvisor",
        volumes: [{ volume_id: "vol_1", mount_path: "/data", read_only: true }],
        egress_allowlist: ["pypi.org"],
      }),
    );

    expect(info.createdAt).toEqual(new Date("2026-11-01T09:00:00+00:00"));
    expect(info.updatedAt).toEqual(new Date("2026-11-01T10:00:00+00:00"));
    expect(info.stoppedAt).toEqual(new Date("2026-11-01T10:00:00+00:00"));
    expect(info.stopCause).toBe("auto_stop");
    expect(info.isolation).toBe("gvisor");
    expect(info.volumes).toEqual([{ volumeId: "vol_1", mountPath: "/data", readOnly: true }]);
    expect(info.egressAllowlist).toEqual(["pypi.org"]);
  });

  it("defaults read_only to false on a mount", () => {
    const info = sandboxFromPayload(
      sandboxPayload("started", { volumes: [{ volume_id: "vol_1", mount_path: "/data" }] }),
    );

    expect(info.volumes).toEqual([{ volumeId: "vol_1", mountPath: "/data", readOnly: false }]);
  });

  it("keeps null for nullable fields and leaves absent ones undefined", () => {
    const nulls = sandboxFromPayload(
      sandboxPayload("started", { stop_cause: null, stopped_at: null, egress_allowlist: null }),
    );
    const bare = sandboxFromPayload(sandboxPayload());

    expect(nulls.stopCause).toBeNull();
    expect(nulls.stoppedAt).toBeNull();
    expect(nulls.egressAllowlist).toBeNull();
    expect(bare.createdAt).toBeUndefined();
    expect(bare.volumes).toBeUndefined();
    expect(bare.isolation).toBeUndefined();
  });
});

describe("VolumeMountInfo", () => {
  it("names the type of a sandbox info volume", () => {
    const info = sandboxFromPayload(
      sandboxPayload("started", { volumes: [{ volume_id: "v", mount_path: "/d" }] }),
    );

    const mounts: readonly VolumeMountInfo[] = info.volumes ?? [];

    expect(mounts[0]?.volumeId).toBe("v");
  });
});

describe("volume info fields", () => {
  it("maps labels, maxBytes and overLimit", () => {
    const info = volumeFromPayload(
      volumePayload({ labels: { team: "a" }, max_bytes: 1024, over_limit: true }),
    );

    expect(info.labels).toEqual({ team: "a" });
    expect(info.maxBytes).toBe(1024);
    expect(info.overLimit).toBe(true);
  });

  it("keeps null for an unlimited volume", () => {
    const info = volumeFromPayload(volumePayload({ max_bytes: null, over_limit: false }));

    expect(info.maxBytes).toBeNull();
    expect(info.overLimit).toBe(false);
  });

  it("leaves the fields undefined for an older server", () => {
    const info = volumeFromPayload(volumePayload());

    expect(info.labels).toBeUndefined();
    expect(info.maxBytes).toBeUndefined();
    expect(info.overLimit).toBeUndefined();
  });

  it("rejects labels that are not an object", () => {
    expect(() => volumeFromPayload(volumePayload({ labels: ["x"] }))).toThrow(
      InvalidResponseError,
    );
  });
});

describe("malformed sandbox responses", () => {
  it("throws InvalidResponseError for a volumes entry that is not an object", () => {
    const payload = sandboxPayload("started", { volumes: ["vol_1"] });

    expect(() => sandboxFromPayload(payload)).toThrow(InvalidResponseError);
  });

  it("throws InvalidResponseError for a volumes field that is not a list", () => {
    const payload = sandboxPayload("started", { volumes: { volume_id: "v" } });

    expect(() => sandboxFromPayload(payload)).toThrow(InvalidResponseError);
  });

  it("throws InvalidResponseError for an invalid timestamp in a new field", () => {
    const payload = sandboxPayload("stopped", { stopped_at: "not-a-date" });

    expect(() => sandboxFromPayload(payload)).toThrow(InvalidResponseError);
  });

  it("throws InvalidResponseError for an isolation of the wrong type", () => {
    const payload = sandboxPayload("started", { isolation: 5 });

    expect(() => sandboxFromPayload(payload)).toThrow(InvalidResponseError);
  });
});

describe("sandbox label keys", () => {
  it("rejects a blank label key in createSandbox before sending", async () => {
    const { client, requests } = clientFor([]);

    const error = await client.createSandbox({ labels: { " ": "v" } }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });
});

describe("client.createCodeContext with a name", () => {
  it("returns { context, created: true } for a new kernel (201)", async () => {
    const { client } = clientFor([created(contextPayload({ name: "main" }))]);

    const result = await client.createCodeContext("sbx_1", { name: "main" });

    expect(result.created).toBe(true);
    expect(result.context.name).toBe("main");
  });

  it("returns created false when a live context was found (200)", async () => {
    const { client } = clientFor([ok(contextPayload({ name: "main" }))]);

    const result = await client.createCodeContext("sbx_1", { name: "main" });

    expect(result.created).toBe(false);
  });

  it("keeps returning the bare context without a name", async () => {
    const { client } = clientFor([created(contextPayload())]);

    const context = await client.createCodeContext("sbx_1");

    expect(context.id).toBe("ctx_0123456789abcdef");
    expect("created" in context).toBe(false);
  });
});
