import { describe, expect, it } from "vitest";
import { ValidationError } from "../src/index.js";
import { at, clientFor, ok, sandboxPayload, type Recorded } from "./helpers.js";

const SLOW_MS = 150;

/** A long-poll answer that takes longer than the client's whole `timeoutMs`. */
async function slowStarted(_request: Recorded): Promise<Response> {
  await new Promise((resolve) => setTimeout(resolve, SLOW_MS));
  return ok(sandboxPayload("started"));
}

describe("wait long poll", () => {
  it("keeps the request alive past a tiny timeoutMs while the server holds the poll", async () => {
    const { client, requests } = clientFor(
      [ok(sandboxPayload("creating")), slowStarted],
      { timeoutMs: 50, retries: 0 },
    );

    const sandbox = await client.createSandbox({});

    expect(sandbox.state).toBe("started");
    expect(at(requests, 1).url).toContain("timeout_s=30");
  });

  it("asks the server for at most the wait budget that is left", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload("creating")), ok(sandboxPayload())]);

    await client.createSandbox({ waitTimeoutS: 5 });

    const match = /timeout_s=([\d.]+)/.exec(at(requests, 1).url);
    expect(Number(match?.[1])).toBeGreaterThan(4);
    expect(Number(match?.[1])).toBeLessThanOrEqual(5);
  });

  it("keeps the poll inside a client deadlineMs", async () => {
    const { client, requests } = clientFor([ok(sandboxPayload("creating")), ok(sandboxPayload())], {
      deadlineMs: 3_000,
    });

    await client.createSandbox({});

    expect(at(requests, 1).url).toContain("timeout_s=2");
  });
});

describe("wait option validation", () => {
  const bad: [string, Record<string, number>][] = [
    ["waitTimeoutS 0", { waitTimeoutS: 0 }],
    ["waitTimeoutS negative", { waitTimeoutS: -1 }],
    ["waitTimeoutS NaN", { waitTimeoutS: Number.NaN }],
    ["waitTimeoutS Infinity", { waitTimeoutS: Number.POSITIVE_INFINITY }],
    ["pollIntervalS 0", { pollIntervalS: 0 }],
    ["pollIntervalS negative", { pollIntervalS: -0.5 }],
    ["pollIntervalS NaN", { pollIntervalS: Number.NaN }],
  ];

  it.each(bad)("createSandbox rejects %s before sending anything", async (_name, options) => {
    const { client, requests } = clientFor([]);

    await expect(client.createSandbox(options)).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it.each(bad)("createSnapshot rejects %s before sending anything", async (_name, options) => {
    const { client, requests } = clientFor([]);

    await expect(client.createSnapshot("sbx_1", "s", { wait: true, ...options })).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(requests).toHaveLength(0);
  });

  it("accepts small positive fractions", async () => {
    const { client } = clientFor([ok(sandboxPayload())]);

    await expect(client.createSandbox({ waitTimeoutS: 0.5, pollIntervalS: 0.001 })).resolves.toBeDefined();
  });
});
