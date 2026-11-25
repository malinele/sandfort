import { describe, expect, it } from "vitest";
import { SANDBOX_ERROR_CODES } from "../src/index.js";
import type { SandboxErrorCode } from "../src/index.js";
import { clientFor, ok, sandboxPayload } from "./helpers.js";

describe("SandboxInfo.errorCode", () => {
  it("reads a known code from error_code", async () => {
    const { client } = clientFor([
      ok(sandboxPayload("error", { error_reason: "proxy down", error_code: "egress_unavailable" })),
    ]);

    const sandbox = await client.getSandbox("sbx_1");

    expect(sandbox.errorCode).toBe("egress_unavailable");
    expect(sandbox.errorReason).toBe("proxy down");
  });

  it("is null when error_code is null", async () => {
    const { client } = clientFor([ok(sandboxPayload("started", { error_code: null }))]);

    expect((await client.getSandbox("sbx_1")).errorCode).toBeNull();
  });

  it("is null when error_code is missing", async () => {
    const { client } = clientFor([ok(sandboxPayload())]);

    expect((await client.getSandbox("sbx_1")).errorCode).toBeNull();
  });

  it("keeps an unknown string as given instead of throwing (open enum, like state)", async () => {
    const { client } = clientFor([ok(sandboxPayload("error", { error_code: "future_code" }))]);

    expect((await client.getSandbox("sbx_1")).errorCode).toBe("future_code");
  });

  it("is on the Sandbox handle next to errorReason", async () => {
    const { client } = clientFor([ok(sandboxPayload("error", { error_code: "node_lost" }))]);

    const sandbox = await client.getSandbox("sbx_1");

    expect(sandbox.errorCode).toBe("node_lost");
    expect(JSON.parse(JSON.stringify(sandbox))).toMatchObject({ errorCode: "node_lost" });
  });
});

describe("SANDBOX_ERROR_CODES", () => {
  it("lists the server codes in order, with egress_unavailable", () => {
    const code: SandboxErrorCode = "egress_unavailable";

    expect(SANDBOX_ERROR_CODES).toHaveLength(13);
    expect(SANDBOX_ERROR_CODES).toContain(code);
    expect(SANDBOX_ERROR_CODES[0]).toBe("image_not_found");
    expect(SANDBOX_ERROR_CODES[12]).toBe("internal");
  });
});
