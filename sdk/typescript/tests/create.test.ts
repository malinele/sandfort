import { describe, expect, it } from "vitest";
import { SandfortError, ValidationError, type CreateSandboxOptions } from "../src/index.js";
import { at, clientFor, ok, sandboxPayload } from "./helpers.js";

function volume(id: string, name: string): Record<string, unknown> {
  return { id, name, state: "ready", created_at: "2026-11-01T09:00:00+00:00" };
}

async function sentBody(options: CreateSandboxOptions): Promise<Record<string, unknown>> {
  const { client, requests } = clientFor([ok(sandboxPayload())]);
  await client.createSandbox(options);
  return JSON.parse(at(requests, 0).body ?? "null") as Record<string, unknown>;
}

describe("createSandbox option parity with the CreateSandboxRequest schema", () => {
  it("maps every camelCase option to the schema's snake_case field", async () => {
    const body = await sentBody({
      name: "demo",
      snapshot: "snap_1",
      isolation: "gvisor",
      resources: { cpuMillicores: 2000, memoryMib: 1024, diskGib: 10 },
      public: true,
      autoStopMinutes: 30,
      autoDeleteMinutes: 120,
      env: { A: "1" },
      labels: { k: "v" },
      blockNetwork: false,
      egressAllowlist: ["pypi.org"],
      volumes: [{ volumeId: "vol_1", mountPath: "/data", readOnly: true }],
    });

    expect(body).toEqual({
      name: "demo",
      snapshot: "snap_1",
      resources: { cpu_millicores: 2000, memory_mib: 1024, disk_gib: 10 },
      env: { A: "1" },
      labels: { k: "v" },
      network: { block_all: false },
      auto_stop_minutes: 30,
      auto_delete_minutes: 120,
      public: true,
      volumes: [{ volume_id: "vol_1", mount_path: "/data", read_only: true }],
      egress_allowlist: ["pypi.org"],
      isolation: "gvisor",
    });
  });

  it("omits unset options and sends read_only false by default", async () => {
    expect(await sentBody({})).toEqual({});
    const body = await sentBody({ volumes: [{ volumeId: "vol_1", mountPath: "/d" }] });
    expect(body["volumes"]).toEqual([{ volume_id: "vol_1", mount_path: "/d", read_only: false }]);
  });

  it("sends only the resource fields that were set", async () => {
    const body = await sentBody({ resources: { memoryMib: 256 } });
    expect(body["resources"]).toEqual({ memory_mib: 256 });
  });

  it("sends an empty egress allowlist (block-all) rather than dropping it", async () => {
    const body = await sentBody({ egressAllowlist: [] });
    expect(body["egress_allowlist"]).toEqual([]);
  });

  it("maps inheritResources to inherit_resources and omits it when unset", async () => {
    const body = await sentBody({ inheritResources: true, snapshot: "snap_1" });
    expect(body["inherit_resources"]).toBe(true);
    expect(await sentBody({ snapshot: "snap_1" })).not.toHaveProperty("inherit_resources");
  });

  it("looks a volume up by name when no id is given", async () => {
    const { client, requests } = clientFor([
      ok([volume("vol_a", "other")], "c1"),
      ok([volume("vol_b", "data")], null),
      ok(sandboxPayload()),
    ]);

    await client.createSandbox({ volumes: [{ volumeName: "data", mountPath: "/data" }] });

    expect(at(requests, 1).url).toBe("http://sf.test/v1/volumes?cursor=c1");
    expect(JSON.parse(at(requests, 2).body ?? "null")).toEqual({
      volumes: [{ volume_id: "vol_b", mount_path: "/data", read_only: false }],
    });
  });

  it("rejects an unknown or ambiguous volume name before creating anything", async () => {
    const missing = clientFor([ok([])]);
    await expect(
      missing.client.createSandbox({ volumes: [{ volumeName: "nope", mountPath: "/d" }] }),
    ).rejects.toThrow("no volume named 'nope'");
    expect(missing.requests).toHaveLength(1);

    const twice = clientFor([ok([volume("v1", "x"), volume("v2", "x")])]);
    await expect(
      twice.client.createSandbox({ volumes: [{ volumeName: "x", mountPath: "/d" }] }),
    ).rejects.toThrow("more than one volume");
  });
});

describe("createSandbox client-side validation", () => {
  const cases: [string, CreateSandboxOptions, string][] = [
    ["bad name", { name: "-bad" }, "name must be"],
    ["name too long", { name: "a".repeat(64) }, "name must be"],
    ["empty snapshot", { snapshot: "" }, "snapshot must not be empty"],
    ["unknown isolation", { isolation: "vm" as never }, "isolation must be one of"],
    ["cpu below minimum", { resources: { cpuMillicores: 50 } }, "resources.cpuMillicores"],
    ["fractional memory", { resources: { memoryMib: 100.5 } }, "whole number"],
    ["disk above maximum", { resources: { diskGib: 2_000_000 } }, "resources.diskGib"],
    ["autoStop below -1", { autoStopMinutes: -2 }, "autoStopMinutes"],
    ["autoDelete above max", { autoDeleteMinutes: 525_601 }, "autoDeleteMinutes"],
    ["too many labels", { labels: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, "v"])) }, "at most 32"],
    ["long label value", { labels: { k: "v".repeat(257) } }, "value is longer"],
    ["relative mount path", { volumes: [{ volumeId: "v", mountPath: "data" }] }, "absolute"],
    ["empty mount path", { volumes: [{ volumeId: "v", mountPath: "" }] }, "mountPath must not be empty"],
    [
      "volume with id and name",
      { volumes: [{ volumeId: "v", volumeName: "n", mountPath: "/d" } as never] },
      "exactly one of",
    ],
    [
      "more than 16 mounts",
      { volumes: Array.from({ length: 17 }, (_, i) => ({ volumeId: `v${i}`, mountPath: `/m${i}` })) },
      "at most 16",
    ],
  ];

  it.each(cases)("%s throws a ValidationError and sends nothing", async (_label, options, text) => {
    const { client, requests } = clientFor([]);

    const failure: unknown = await client.createSandbox(options).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(ValidationError);
    expect(failure).toBeInstanceOf(SandfortError);
    expect((failure as Error).message).toContain(text);
    expect(requests).toHaveLength(0);
  });
});
