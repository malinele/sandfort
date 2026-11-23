import { describe, expect, it } from "vitest";
import { ApiError, Forbidden, InvalidResponseError, ValidationError } from "../src/index.js";
import { at, clientFor, failure, ok } from "./helpers.js";

const KEY = {
  id: "key_1",
  name: "ci",
  prefix: "sf_abc",
  scopes: ["sandboxes:read"],
  sandbox_labels: null,
  max_sandboxes: null,
  created_at: "2026-11-01T09:00:00+00:00",
  last_used_at: null,
  expires_at: null,
  revoked_at: null,
  created_by: "key_0",
  status: "active",
};

describe("apiKeys.create", () => {
  it("posts the body and returns the plaintext key once", async () => {
    const { client, requests } = clientFor([ok({ ...KEY, key: "sf_plaintext" })]);

    const created = await client.apiKeys.create("ci", ["sandboxes:read"], {
      sandboxLabels: { team: "a" },
      maxSandboxes: 3,
      expiresAt: new Date("2027-01-01T00:00:00Z"),
    });

    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe("http://sf.test/v1/api-keys");
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({
      name: "ci",
      scopes: ["sandboxes:read"],
      sandbox_labels: { team: "a" },
      max_sandboxes: 3,
      expires_at: "2027-01-01T00:00:00.000Z",
    });
    expect(created.key).toBe("sf_plaintext");
    expect(created.id).toBe("key_1");
    expect(created.createdAt).toEqual(new Date("2026-11-01T09:00:00+00:00"));
    expect(created.status).toBe("active");
  });

  it("keeps the plaintext key out of JSON output", async () => {
    const { client } = clientFor([ok({ ...KEY, key: "sf_plaintext" })]);

    const created = await client.apiKeys.create("ci", ["a"]);

    expect(JSON.stringify(created)).not.toContain("sf_plaintext");
  });

  it("sends only name and scopes by default", async () => {
    const { client, requests } = clientFor([ok({ ...KEY, key: "k" })]);

    await client.apiKeys.create("ci", ["a"]);

    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({ name: "ci", scopes: ["a"] });
  });

  it("refuses bad arguments before sending", async () => {
    const { client, requests } = clientFor([]);
    const bad = [
      client.apiKeys.create(" ", ["a"]),
      client.apiKeys.create("ci", []),
      client.apiKeys.create("ci", ["a"], { maxSandboxes: 2 }),
      client.apiKeys.create("ci", ["a"], { sandboxLabels: { a: "b" }, maxSandboxes: 0 }),
      client.apiKeys.create("ci", ["a"], { expiresAt: new Date("nope") }),
      client.apiKeys.create("ci", [" "]),
    ];

    for (const call of bad) await expect(call).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("never resends a create after a 503 CAPACITY", async () => {
    const { client, requests } = clientFor([failure(503, "CAPACITY"), ok({ ...KEY, key: "k" })]);

    await expect(client.apiKeys.create("ci", ["a"])).rejects.toBeInstanceOf(ApiError);

    expect(requests).toHaveLength(1);
  });

  it("raises Forbidden for a key without the admin scope", async () => {
    const { client } = clientFor([failure(403, "FORBIDDEN")]);

    await expect(client.apiKeys.create("ci", ["a"])).rejects.toBeInstanceOf(Forbidden);
  });

  it("raises InvalidResponseError when the answer has no key", async () => {
    const { client } = clientFor([ok(KEY)]);

    await expect(client.apiKeys.create("ci", ["a"])).rejects.toBeInstanceOf(InvalidResponseError);
  });
});

describe("apiKeys.list", () => {
  it("lists keys without any secret and parses the optional fields", async () => {
    const full = {
      ...KEY,
      sandbox_labels: { team: "a" },
      max_sandboxes: 2,
      last_used_at: "2026-11-02T09:00:00+00:00",
      status: "expired",
    };
    const { client, requests } = clientFor([ok([KEY, full])]);

    const keys = await client.apiKeys.list();

    expect(at(requests, 0).method).toBe("GET");
    expect(new URL(at(requests, 0).url).search).toBe("");
    expect(keys).toHaveLength(2);
    expect(keys[1]?.sandboxLabels).toEqual({ team: "a" });
    expect(keys[1]?.maxSandboxes).toBe(2);
    expect(keys[1]?.lastUsedAt).toEqual(new Date("2026-11-02T09:00:00+00:00"));
    expect(keys[1]?.status).toBe("expired");
    expect(keys[0]?.sandboxLabels).toBeNull();
  });

  it("filters by status and defaults a missing status to active", async () => {
    const { status: _status, ...old } = KEY;
    const { client, requests } = clientFor([ok([old])]);

    const keys = await client.apiKeys.list({ status: "revoked" });

    expect(new URL(at(requests, 0).url).searchParams.get("status")).toBe("revoked");
    expect(keys[0]?.status).toBe("active");
  });

  it("refuses an unknown status", async () => {
    const { client } = clientFor([]);

    await expect(client.apiKeys.list({ status: "x" as never })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });
});

describe("apiKeys.revoke", () => {
  const revoked = { ...KEY, status: "revoked", revoked_at: "2026-11-03T09:00:00+00:00" };

  it("deletes the key and reports the dependants", async () => {
    const dependant = { ...KEY, id: "key_2" };
    const { client, requests } = clientFor([
      ok({ ...revoked, cascade: false, dependants: [dependant] }),
    ]);

    const result = await client.apiKeys.revoke("key_1");

    expect(at(requests, 0).method).toBe("DELETE");
    expect(at(requests, 0).url).toBe("http://sf.test/v1/api-keys/key_1");
    expect(result.status).toBe("revoked");
    expect(result.cascade).toBe(false);
    expect(result.dependants.map((d) => d.id)).toEqual(["key_2"]);
  });

  it("passes cascade as a query flag", async () => {
    const { client, requests } = clientFor([ok({ ...revoked, cascade: true, dependants: [] })]);

    const result = await client.apiKeys.revoke("key_1", { cascade: true });

    expect(new URL(at(requests, 0).url).searchParams.get("cascade")).toBe("true");
    expect(result.cascade).toBe(true);
  });

  it("treats missing dependants as none and rejects a blank id", async () => {
    const { client } = clientFor([ok(revoked)]);

    expect((await client.apiKeys.revoke("key_1")).dependants).toEqual([]);
    await expect(client.apiKeys.revoke("")).rejects.toBeInstanceOf(ValidationError);
  });
});
