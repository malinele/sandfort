import { describe, expect, it } from "vitest";
import { at, clientFor, ok, sandboxPayload } from "./helpers.js";

function volume(id: string, name: string): Record<string, unknown> {
  return { id, name, state: "ready", created_at: "2026-11-01T09:00:00+00:00" };
}

describe("volume name lookup", () => {
  it("lists volumes once for several named mounts of one create call", async () => {
    const { client, requests } = clientFor([
      ok([volume("vol_a", "data"), volume("vol_b", "models")], "c1"),
      ok([volume("vol_c", "scratch")], null),
      ok(sandboxPayload()),
    ]);

    await client.createSandbox({
      volumes: [
        { volumeName: "data", mountPath: "/data" },
        { volumeName: "models", mountPath: "/models", readOnly: true },
        { volumeName: "scratch", mountPath: "/tmp/s" },
      ],
    });

    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      "GET http://sf.test/v1/volumes",
      "GET http://sf.test/v1/volumes?cursor=c1",
      "POST http://sf.test/v1/sandboxes",
    ]);
    expect(JSON.parse(at(requests, 2).body ?? "null")).toEqual({
      volumes: [
        { volume_id: "vol_a", mount_path: "/data", read_only: false },
        { volume_id: "vol_b", mount_path: "/models", read_only: true },
        { volume_id: "vol_c", mount_path: "/tmp/s", read_only: false },
      ],
    });
  });

  it("does not list at all when every mount is given by id", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await client.createSandbox({ volumes: [{ volumeId: "vol_a", mountPath: "/data" }] });

    expect(requests).toHaveLength(1);
  });

  it("does not reuse a listing across create calls", async () => {
    const { client, requests } = clientFor([
      ok([volume("vol_a", "data")]),
      ok(sandboxPayload()),
      ok([volume("vol_a", "data")]),
      ok(sandboxPayload()),
    ]);
    const options = { volumes: [{ volumeName: "data", mountPath: "/data" }] };

    await client.createSandbox(options);
    await client.createSandbox(options);

    expect(requests.filter((r) => r.method === "GET")).toHaveLength(2);
  });
});
