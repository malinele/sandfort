import { describe, expect, it } from "vitest";
import { NotFound, RequestTimeoutError, TransportError } from "../src/index.js";
import { clientFor, hangUntilAborted, ok, sandboxPayload } from "./helpers.js";

function causeOf(error: unknown): unknown {
  return error instanceof Error ? error.cause : undefined;
}

describe("wrapped errors keep their cause", () => {
  it("wraps a network failure with the original error and message", async () => {
    const boom = new TypeError("fetch failed");
    const { client } = clientFor([boom], { retries: 0 });

    const error = await client.getSandbox("sbx_1").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(TransportError);
    expect((error as Error).message).toBe("GET /v1/sandboxes/sbx_1 failed: TypeError: fetch failed");
    expect(causeOf(error)).toBe(boom);
  });

  it("keeps the abort reason of a timeout as the cause", async () => {
    const { client } = clientFor([hangUntilAborted], { timeoutMs: 20, retries: 0 });

    const error = await client.getSandbox("sbx_1").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(RequestTimeoutError);
    expect(causeOf(error)).toBeDefined();
  });
});

describe("one reply decoder for both channels", () => {
  const body = { success: false, error: { code: "NOT_FOUND", message: "no such thing", request_id: "r1" } };

  it("maps an error envelope the same way on the JSON and the download route", async () => {
    const reply = (): Response => new Response(JSON.stringify(body), { status: 404 });
    const { client } = clientFor([ok(sandboxPayload()), reply(), reply()]);
    const sandbox = await client.getSandbox("sbx_1");

    const viaJson = await sandbox.listSessions().catch((e: unknown) => e);
    const viaBinary = await sandbox.fs.downloadFile("/x").catch((e: unknown) => e);

    for (const error of [viaJson, viaBinary]) {
      expect(error).toBeInstanceOf(NotFound);
      expect((error as NotFound).message).toBe("no such thing");
      expect((error as NotFound).requestId).toBe("r1");
    }
  });
});
