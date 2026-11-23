import { describe, expect, it } from "vitest";
import { ValidationError, type CreateSandboxOptions } from "../src/index.js";
import { at, clientFor, ok, sandboxPayload } from "./helpers.js";

const EMOJI = "\u{1F600}"; // one code point, two UTF-16 units

async function sentBody(options: CreateSandboxOptions): Promise<Record<string, unknown>> {
  const { client, requests } = clientFor([ok(sandboxPayload())]);
  await client.createSandbox(options);
  return JSON.parse(at(requests, 0).body ?? "null") as Record<string, unknown>;
}

describe("length limits count code points", () => {
  it("accepts a label value of 256 astral characters and rejects 257", async () => {
    const body = await sentBody({ labels: { k: EMOJI.repeat(256) } });
    expect(body["labels"]).toEqual({ k: EMOJI.repeat(256) });

    const { client, requests } = clientFor([]);
    await expect(client.createSandbox({ labels: { k: EMOJI.repeat(257) } })).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(requests).toHaveLength(0);
  });

  it("accepts a label key of 63 astral characters and rejects 64", async () => {
    await expect(sentBody({ labels: { [EMOJI.repeat(63)]: "v" } })).resolves.toBeDefined();

    const { client } = clientFor([]);
    await expect(client.createSandbox({ labels: { [EMOJI.repeat(64)]: "v" } })).rejects.toThrow(
      "label key",
    );
  });

  it("counts a snapshot reference in code points too", async () => {
    await expect(sentBody({ snapshot: EMOJI.repeat(512) })).resolves.toBeDefined();

    const { client } = clientFor([]);
    await expect(client.createSandbox({ snapshot: EMOJI.repeat(513) })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });
});

describe("snapshot minLength 1", () => {
  it("sends a whitespace-only snapshot as is; the schema only forbids an empty one", async () => {
    const body = await sentBody({ snapshot: " " });
    expect(body["snapshot"]).toBe(" ");
  });
});
