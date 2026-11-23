import { describe, expect, it } from "vitest";
import specFile from "../../../openapi/sandfort.v1.json";
import {
  ISOLATION_TIERS,
  checkMounts,
  createBody,
  resolveMounts,
  type CreateFields,
  type VolumeMount,
} from "../src/create-body.js";

type Json = Record<string, unknown>;

function record(value: unknown, what: string): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${what} is not an object in the spec`);
  }
  return value as Json;
}

function schema(name: string): Json {
  const spec = record(specFile, "spec");
  const schemas = record(record(spec["components"], "components")["schemas"], "schemas");
  return record(schemas[name], name);
}

function property(owner: Json, name: string): Json {
  return record(record(owner["properties"], "properties")[name], name);
}

/** The first non-null branch of an `anyOf: [T, null]` property, or the property itself. */
function value(prop: Json): Json {
  const branches = prop["anyOf"];
  if (!Array.isArray(branches)) return prop;
  const real = branches.map((b) => record(b, "anyOf branch")).find((b) => b["type"] !== "null");
  if (real === undefined) throw new Error("anyOf has no non-null branch");
  return real;
}

function num(owner: Json, key: string): number {
  const found = owner[key];
  if (typeof found !== "number") throw new Error(`${key} is not a number in the spec`);
  return found;
}

function keys(owner: Json): string[] {
  return Object.keys(record(owner["properties"], "properties")).sort();
}

const CREATE = schema("CreateSandboxRequest");
const MOUNT = schema("VolumeMountSpec");
const RESOURCES = schema("ResourceSpecRequest");
const NETWORK = schema("NetworkPolicy");

const FULL: CreateFields = {
  name: "n",
  snapshot: "s",
  labels: { k: "v" },
  env: { A: "1" },
  blockNetwork: true,
  autoStopMinutes: 5,
  autoDeleteMinutes: 10,
  public: true,
  isolation: "gvisor",
  resources: { cpuMillicores: 500, memoryMib: 256, diskGib: 2 },
  egressAllowlist: ["pypi.org"],
};
const MOUNTS = [{ volumeId: "vol_1", mountPath: "/d", readOnly: true }] as const;

function body(fields: CreateFields = FULL): Json {
  return createBody(fields, MOUNTS.map((m) => ({ volumeId: m.volumeId, mountPath: m.mountPath, readOnly: m.readOnly })));
}

/** The call is accepted at `limit` and rejected one past it. */
function expectEdge(limit: number, accept: (n: number) => unknown, reject: (n: number) => unknown): void {
  expect(() => accept(limit)).not.toThrow();
  expect(() => reject(limit)).toThrow();
}

describe("create body keys match openapi/sandfort.v1.json", () => {
  it("sends exactly the CreateSandboxRequest properties when every option is set", () => {
    expect(Object.keys(body()).sort()).toEqual(keys(CREATE));
  });

  it("uses only ResourceSpecRequest, NetworkPolicy and VolumeMountSpec properties", () => {
    const sent = body();
    expect(Object.keys(record(sent["resources"], "resources")).sort()).toEqual(keys(RESOURCES));
    expect(Object.keys(record(sent["network"], "network")).sort()).toEqual(keys(NETWORK));
    const [mount] = sent["volumes"] as Json[];
    expect(Object.keys(record(mount, "mount")).sort()).toEqual(keys(MOUNT));
  });

  it("sends every required VolumeMountSpec property", () => {
    const [mount] = body()["volumes"] as Json[];
    for (const required of MOUNT["required"] as string[]) expect(mount).toHaveProperty(required);
  });

  it("omits unset options instead of sending nulls", () => {
    expect(createBody({})).toEqual({});
  });
});

describe("create enums and limits match the spec", () => {
  it("offers the isolation tiers of the schema", () => {
    const enumValues = value(property(CREATE, "isolation"))["enum"];
    expect([...ISOLATION_TIERS].sort()).toEqual([...(enumValues as string[])].sort());
  });

  it("applies the name pattern and length", () => {
    const name = value(property(CREATE, "name"));
    const pattern = new RegExp(String(name["pattern"]));
    for (const sample of ["ok", "a_b.c-d", "-bad", "_bad", "has space", ""]) {
      const accepted = (): unknown => createBody({ name: sample });
      if (pattern.test(sample) && sample.length >= 1) expect(accepted).not.toThrow();
      else expect(accepted).toThrow();
    }
    expectEdge(num(name, "maxLength"), (n) => createBody({ name: "a".repeat(n) }), (n) => createBody({ name: "a".repeat(n + 1) }));
  });

  it("applies the snapshot length (minLength 1 allows a lone space)", () => {
    const snapshot = value(property(CREATE, "snapshot"));
    expect(num(snapshot, "minLength")).toBe(1);
    expect(() => createBody({ snapshot: " " })).not.toThrow();
    expect(() => createBody({ snapshot: "" })).toThrow();
    expectEdge(num(snapshot, "maxLength"), (n) => createBody({ snapshot: "s".repeat(n) }), (n) => createBody({ snapshot: "s".repeat(n + 1) }));
  });

  it("applies the label count, key and value lengths", () => {
    const labels = property(CREATE, "labels");
    const valueLimit = num(record(labels["additionalProperties"], "labels value"), "maxLength");
    const keyLimit = num(record(labels["propertyNames"], "labels keys"), "maxLength");
    const countLimit = num(labels, "maxProperties");
    const many = (n: number): Record<string, string> => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, "v"]));
    expectEdge(countLimit, (n) => createBody({ labels: many(n) }), (n) => createBody({ labels: many(n + 1) }));
    expectEdge(valueLimit, (n) => createBody({ labels: { k: "v".repeat(n) } }), (n) => createBody({ labels: { k: "v".repeat(n + 1) } }));
    expectEdge(keyLimit, (n) => createBody({ labels: { ["k".repeat(n)]: "v" } }), (n) => createBody({ labels: { ["k".repeat(n + 1)]: "v" } }));
  });

  it("applies the auto-stop and auto-delete minute bounds", () => {
    for (const [field, option] of [
      ["auto_stop_minutes", "autoStopMinutes"],
      ["auto_delete_minutes", "autoDeleteMinutes"],
    ] as const) {
      const prop = property(CREATE, field);
      const make = (n: number): CreateFields => ({ [option]: n });
      const max = num(prop, "maximum");
      const min = num(prop, "minimum");
      expectEdge(max, (n) => createBody(make(n)), (n) => createBody(make(n + 1)));
      expectEdge(min, (n) => createBody(make(n)), (n) => createBody(make(n - 1)));
    }
  });

  it("applies the resource bounds", () => {
    for (const [field, option] of [
      ["cpu_millicores", "cpuMillicores"],
      ["memory_mib", "memoryMib"],
      ["disk_gib", "diskGib"],
    ] as const) {
      const prop = property(RESOURCES, field);
      const make = (n: number): CreateFields => ({ resources: { [option]: n } });
      expectEdge(num(prop, "maximum"), (n) => createBody(make(n)), (n) => createBody(make(n + 1)));
      expectEdge(num(prop, "minimum"), (n) => createBody(make(n)), (n) => createBody(make(n - 1)));
    }
  });

  it("applies the mount count, path and volume id limits", async () => {
    const mount = (i: number): VolumeMount => ({ volumeId: `v${i}`, mountPath: `/m${i}` });
    const maxItems = num(property(CREATE, "volumes"), "maxItems");
    expectEdge(maxItems, (n) => checkMounts(Array.from({ length: n }, (_, i) => mount(i))), (n) => checkMounts(Array.from({ length: n + 1 }, (_, i) => mount(i))));

    const pathLimit = num(property(MOUNT, "mount_path"), "maxLength");
    const path = (n: number): VolumeMount[] => [{ volumeId: "v", mountPath: `/${"p".repeat(n - 1)}` }];
    expectEdge(pathLimit, (n) => checkMounts(path(n)), (n) => checkMounts(path(n + 1)));

    const idLimit = num(property(MOUNT, "volume_id"), "maxLength");
    const resolve = (n: number): Promise<unknown> => resolveMounts([{ volumeId: "v".repeat(n), mountPath: "/d" }], async () => "x");
    await expect(resolve(idLimit)).resolves.toBeDefined();
    await expect(resolve(idLimit + 1)).rejects.toThrow();
  });
});
