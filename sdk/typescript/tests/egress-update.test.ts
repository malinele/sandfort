import { describe, expect, it } from "vitest";
import {
  Conflict,
  InvalidResponseError,
  InvalidState,
  ValidationError,
  ValidationFailed,
} from "../src/index.js";
import { at, clientFor, failure, ok, sandboxPayload } from "./helpers.js";

const BASE = "http://sf.test/v1/sandboxes/sbx_1";

function sentBody(requests: Parameters<typeof at>[0]): unknown {
  return JSON.parse(at(requests, 0).body ?? "");
}

describe("updateSandbox egressAllowlist", () => {
  it("sends the list as egress_allowlist next to the other options", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await client.updateSandbox("sbx_1", {
      egressAllowlist: ["pypi.org", "files.pythonhosted.org"],
      public: true,
    });

    expect(at(requests, 0).method).toBe("PATCH");
    expect(at(requests, 0).url).toBe(BASE);
    expect(sentBody(requests)).toEqual({
      egress_allowlist: ["pypi.org", "files.pythonhosted.org"],
      public: true,
    });
  });

  it("sends an explicit empty list, which refuses every connection", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await client.updateSandbox("sbx_1", { egressAllowlist: [] });

    expect(sentBody(requests)).toEqual({ egress_allowlist: [] });
  });

  it("leaves egress_allowlist out when the option is omitted", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await client.updateSandbox("sbx_1", { public: true });

    expect(sentBody(requests)).toEqual({ public: true });
  });

  it("accepts a readonly array and copies it", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);
    const hosts: readonly string[] = Object.freeze(["a.example"]);

    await client.updateSandbox("sbx_1", { egressAllowlist: hosts });

    expect(sentBody(requests)).toEqual({ egress_allowlist: ["a.example"] });
  });

  it("passes entries through unvalidated, the server checks them", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await client.updateSandbox("sbx_1", { egressAllowlist: ["*.example.com", "10.0.0.0/8"] });

    expect(sentBody(requests)).toEqual({ egress_allowlist: ["*.example.com", "10.0.0.0/8"] });
  });

  it.each([[null], ["pypi.org"], [{}]])(
    "rejects %j (no way to send null) before any request",
    async (value) => {
      const { client, requests } = clientFor([ok(sandboxPayload())]);

      await expect(
        client.updateSandbox("sbx_1", { egressAllowlist: value as unknown as string[] }),
      ).rejects.toBeInstanceOf(ValidationError);
      expect(requests).toHaveLength(0);
    },
  );

  it("counts egressAllowlist as a field, so [] alone is a valid update", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload())]);

    await expect(client.updateSandbox("sbx_1", { egressAllowlist: [] })).resolves.toBeDefined();
    expect(requests).toHaveLength(1);
  });

  it("names egressAllowlist in the 'at least one' message", async () => {
    const { client } = clientFor([]);

    await expect(client.updateSandbox("sbx_1", {})).rejects.toThrow(/egressAllowlist/);
  });

  it("is available on the Sandbox handle", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload()), ok(sandboxPayload())]);
    const sandbox = await client.getSandbox("sbx_1");

    await sandbox.update({ egressAllowlist: ["a.example"] });

    expect(JSON.parse(at(requests, 1).body ?? "")).toEqual({ egress_allowlist: ["a.example"] });
  });
});

describe("updateSandbox egress refusals", () => {
  it("maps 409 INVALID_STATE to InvalidState, a Conflict", async () => {
    const { client } = clientFor([failure(409, "INVALID_STATE", {}, "no allowlist to replace")]);

    const error = await client
      .updateSandbox("sbx_1", { egressAllowlist: ["a.example"] })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(InvalidState);
    expect(error).toBeInstanceOf(Conflict);
    expect(error).toMatchObject({ code: "INVALID_STATE", status: 409 });
  });

  it("keeps the 403 FORBIDDEN refusal as its own error", async () => {
    const forbidden = clientFor([failure(403, "FORBIDDEN")]);

    await expect(
      forbidden.client.updateSandbox("sbx_1", { egressAllowlist: ["a.example"] }),
    ).rejects.toMatchObject({ code: "FORBIDDEN", status: 403 });
  });

  it.each([
    ["UNPROCESSABLE", "Pypi.org"],
    ["VALIDATION_ERROR", "bad host"],
  ])("maps a 422 %s to ValidationFailed and keeps its code", async (code, entry) => {
    const { client } = clientFor([failure(422, code)]);

    const error = await client
      .updateSandbox("sbx_1", { egressAllowlist: [entry] })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ValidationFailed);
    expect(error).toMatchObject({ code, status: 422 });
  });
});

describe("sandbox egress fields", () => {
  it("reads egress_policy_generation and egress_allowlist", async () => {
    const { client } = clientFor([
      ok(
        sandboxPayload("started", { egress_policy_generation: 3, egress_allowlist: ["a.example"] }),
      ),
    ]);

    const sandbox = await client.getSandbox("sbx_1");

    expect(sandbox.egressPolicyGeneration).toBe(3);
    expect(sandbox.egressAllowlist).toEqual(["a.example"]);
  });

  it("reads an empty list as [] and a null list as null", async () => {
    const empty = clientFor([ok(sandboxPayload("started", { egress_allowlist: [] }))]);
    const none = clientFor([ok(sandboxPayload("started", { egress_allowlist: null }))]);

    expect((await empty.client.getSandbox("sbx_1")).egressAllowlist).toEqual([]);
    expect((await none.client.getSandbox("sbx_1")).egressAllowlist).toBeNull();
  });

  it.each([
    ["missing", {}],
    ["null", { egress_policy_generation: null }],
  ])("defaults the generation to 0 when it is %s", async (_name, extra) => {
    const { client } = clientFor([ok(sandboxPayload("started", extra))]);

    expect((await client.getSandbox("sbx_1")).egressPolicyGeneration).toBe(0);
  });

  it("keeps a generation of 0 as 0", async () => {
    const { client } = clientFor([ok(sandboxPayload("started", { egress_policy_generation: 0 }))]);

    expect((await client.getSandbox("sbx_1")).egressPolicyGeneration).toBe(0);
  });

  it.each([["2"], [true], [1.5], [[1]], [{}]])(
    "raises InvalidResponseError for a generation of %j",
    async (value) => {
      const { client } = clientFor([
        ok(sandboxPayload("started", { egress_policy_generation: value })),
      ]);

      await expect(client.getSandbox("sbx_1")).rejects.toBeInstanceOf(InvalidResponseError);
    },
  );

  it("ignores unknown response fields", async () => {
    const { client } = clientFor([
      ok(sandboxPayload("started", { egress_future_field: { x: 1 } })),
    ]);

    const sandbox = await client.getSandbox("sbx_1");

    expect(sandbox.egressPolicyGeneration).toBe(0);
  });

  it("carries the new generation on the handle update returns", async () => {
    const { client } = clientFor([
      ok(sandboxPayload("started", { egress_policy_generation: 2, egress_allowlist: [] })),
    ]);

    const updated = await client.updateSandbox("sbx_1", { egressAllowlist: [] });

    expect(updated.egressPolicyGeneration).toBe(2);
    expect(updated.egressAllowlist).toEqual([]);
  });
});
