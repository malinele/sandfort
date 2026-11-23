import { describe, expect, it } from "vitest";
import { InvalidResponseError, ValidationError } from "../src/index.js";
import { clientFor, ok } from "./helpers.js";

const KEY_ANSWER = {
  id: "key_1",
  name: "ci",
  prefix: "sf_abc",
  scopes: ["sandboxes:read"],
  created_at: "2026-11-01T00:00:00Z",
  key: "sf_SECRET_PLAINTEXT",
};
const HOOK_ANSWER = {
  id: "wh_1",
  url: "https://hooks.example/in",
  event_types: ["*"],
  secret: "whsec_SECRET",
};
const PREVIEW_ANSWER = {
  token: "pv_SECRET_TOKEN",
  url: "https://p.example/x",
  port: 3000,
  expires_at: "2026-11-01T00:10:00Z",
};

type Holder = Record<string, unknown>;
type Inspect = (value: unknown, options?: { depth?: number; showHidden?: boolean }) => string;

// The package has no @types/node; `util.inspect` is what `console.log` prints with.
const { inspect } = (await import("node:util" as string)) as { inspect: Inspect };

async function created(): Promise<ReadonlyArray<readonly [string, Holder, string, string]>> {
  const { client } = clientFor([
    ok(KEY_ANSWER),
    ok(HOOK_ANSWER),
    ok(PREVIEW_ANSWER),
  ]);
  const key = await client.apiKeys.create("ci", ["sandboxes:read"]);
  const hook = await client.webhooks.create("https://hooks.example/in", ["*"]);
  const preview = await client.mintPreviewToken("sbx_1", { port: 3000 });
  return [
    ["api key", key as unknown as Holder, "key", KEY_ANSWER.key],
    ["webhook", hook as unknown as Holder, "secret", HOOK_ANSWER.secret],
    ["preview token", preview as unknown as Holder, "token", PREVIEW_ANSWER.token],
  ];
}

describe("one-time secrets", () => {
  it("are readable on the answer and absent from every other view", async () => {
    for (const [name, value, field, secret] of await created()) {
      expect(value[field], name).toBe(secret);
      expect(Object.keys(value), name).not.toContain(field);
      expect(JSON.stringify(value), name).not.toContain(secret);
      expect(inspect(value, { depth: 4 }), name).not.toContain(secret);
      expect(`${inspect(value)}`, name).not.toContain(secret);
    }
  });

  it("are not carried by a spread, Object.assign or structuredClone copy", async () => {
    for (const [name, value, field] of await created()) {
      const spread = { ...value };
      const assigned = Object.assign({}, value);
      const cloned = structuredClone(value);

      expect(spread[field], name).toBeUndefined();
      expect(assigned[field], name).toBeUndefined();
      expect(cloned[field], name).toBeUndefined();
    }
  });

  it("show only with showHidden, which is why they must be read at once", async () => {
    const [, key] = (await created())[0] ?? [];
    const shown = inspect(key, { showHidden: true });

    expect(shown).toContain("sf_SECRET_PLAINTEXT");
  });

  it("keep the preview url enumerable", async () => {
    const preview = (await created())[2]?.[1] as Holder;

    expect(Object.keys(preview)).toEqual(expect.arrayContaining(["url", "port", "expiresAt"]));
  });
});

describe("api key create", () => {
  it("says the key was created when the answer has no key", async () => {
    const { key: _omitted, ...withoutKey } = KEY_ANSWER;
    const { client } = clientFor([ok(withoutKey)]);

    const failed = client.apiKeys.create("ci", ["sandboxes:read"]);

    await expect(failed).rejects.toBeInstanceOf(InvalidResponseError);
    await expect(failed).rejects.toThrow(/the key was created; list and revoke it/);
  });

  it("refuses a label value that is not a string before sending", async () => {
    const { client, requests } = clientFor([]);

    const failed = client.apiKeys.create("ci", ["sandboxes:read"], {
      sandboxLabels: { team: 7 as unknown as string },
    });

    await expect(failed).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });
});
