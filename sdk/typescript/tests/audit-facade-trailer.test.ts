import { describe, expect, it } from "vitest";
import { ValidationError } from "../src/index.js";
import { GOLDEN } from "./audit-trailer-helpers.js";
import { at, clientFor, ok } from "./helpers.js";

const STATUS = {
  status: "ok",
  version: "0.1.0",
  started_at: "2026-11-11T08:00:00+00:00",
  audit_public_key: GOLDEN.publicKey,
  audit_key_fingerprint: "0123456789abcdef",
};

function ndjson(text: string): Response {
  return new Response(text, { status: 200, headers: { "content-type": "application/x-ndjson" } });
}

const EXPORT = `${GOLDEN.lines.join("")}${GOLDEN.head}\n`;

describe("status audit key fields", () => {
  it("reads audit_public_key and audit_key_fingerprint, null when absent", async () => {
    const { client } = clientFor([ok(STATUS), ok({ ...STATUS, audit_public_key: null, audit_key_fingerprint: undefined })]);

    const signed = await client.status();
    const unsigned = await client.status();

    expect(signed.auditPublicKey).toBe(GOLDEN.publicKey);
    expect(signed.auditKeyFingerprint).toBe("0123456789abcdef");
    expect(unsigned.auditPublicKey).toBeNull();
    expect(unsigned.auditKeyFingerprint).toBeNull();
  });
});

describe("client.audit.publicKey", () => {
  it("returns the published key from GET /v1/status", async () => {
    const { client, requests } = clientFor([ok(STATUS)]);

    expect(await client.audit.publicKey()).toBe(GOLDEN.publicKey);
    expect(at(requests, 0).url).toBe("http://sf.test/v1/status");
  });

  it("returns null for a missing or empty key", async () => {
    const { client } = clientFor([ok({ ...STATUS, audit_public_key: "" }), ok({ ...STATUS, audit_public_key: null })]);

    expect(await client.audit.publicKey()).toBeNull();
    expect(await client.audit.publicKey()).toBeNull();
  });
});

describe("client.audit.verifyHead", () => {
  it("makes no request for an explicit key", async () => {
    const { client, requests } = clientFor([]);

    const result = await client.audit.verifyHead(GOLDEN.head, GOLDEN.publicKey);

    expect(result.ok).toBe(true);
    expect(requests).toHaveLength(0);
  });

  it('reads the trust anchor from the status route for "status"', async () => {
    const { client, requests } = clientFor([ok(STATUS)]);

    const result = await client.audit.verifyHead(GOLDEN.head, "status");

    expect(result.ok).toBe(true);
    expect(requests).toHaveLength(1);
  });

  it('a bad line fails before any request even with "status"', async () => {
    const { client, requests } = clientFor([]);

    await expect(client.audit.verifyHead("{nope", "status")).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it('throws when "status" finds no published key', async () => {
    const { client } = clientFor([ok({ ...STATUS, audit_public_key: null })]);

    await expect(client.audit.verifyHead(GOLDEN.head, "status")).rejects.toThrow(/publishes no audit_public_key/);
  });

  it("a key the server publishes that is not the line's key gives key_mismatch", async () => {
    const other = Buffer.alloc(32, 7).toString("base64");
    const { client } = clientFor([ok({ ...STATUS, audit_public_key: other })]);

    expect((await client.audit.verifyHead(GOLDEN.head, "status")).reason).toBe("key_mismatch");
  });
});

describe("client.audit.verifyExport", () => {
  it("verifies a streamed export, reading the key from status after the file", async () => {
    const { client, requests } = clientFor([ndjson(EXPORT), ok(STATUS)]);

    const result = await client.audit.verifyExport(client.audit.exportLines(), "status");

    expect(result).toMatchObject({ ok: true, rows: 3, contentBound: true });
    expect(requests.map((r) => new URL(r.url).pathname)).toEqual([
      "/v1/audit-events/export",
      "/v1/status",
    ]);
  });

  it("detects a tampered stream", async () => {
    const tampered = EXPORT.replace("sandbox.create", "sandbox.destroy");
    const { client } = clientFor([ndjson(tampered)]);

    const result = await client.audit.verifyExport(client.audit.exportLines(), GOLDEN.publicKey);

    expect(result.reason).toBe("content_mismatch");
  });

  it("passes allowUnchained and previous through, and an explicit key makes no status request", async () => {
    const { client, requests } = clientFor([]);

    const result = await client.audit.verifyExport(EXPORT, GOLDEN.publicKey, {
      previous: GOLDEN.lines.slice(0, 2).join(""),
      allowUnchained: true,
    });

    expect(result).toMatchObject({ ok: true, previousRows: 2, newRows: 1 });
    expect(requests).toHaveLength(0);
  });
});
