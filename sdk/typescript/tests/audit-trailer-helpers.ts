import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { canonicalJson, encodeBase64Url } from "../src/audit-canonical.js";

/**
 * A real export written by the server's own code (`sign_head`, `ExportDigest`, `export_line`)
 * with the seed `bytes(range(32))`: three rows whose `actor` holds non-ASCII text and DEL, and a
 * head signed 2026-11-11T04:52:33+00:00. It pins the canonical form byte for byte.
 */
export const GOLDEN = {
  publicKey: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
  lines: [
    '{"action":"sandbox.create","actor":"\\u017e\\u0107\\u010d \\u00e9 \\ud83d\\ude00 \\u007f","hash":"h00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","id":"evt_0","occurred_at":"2026-11-11T04:00:00+00:00","org_id":"org_1","prev_hash":null}\n',
    '{"action":"sandbox.create","actor":"\\u017e\\u0107\\u010d \\u00e9 \\ud83d\\ude00 \\u007f","hash":"h01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","id":"evt_1","occurred_at":"2026-11-11T04:00:01+00:00","org_id":"org_1","prev_hash":"h00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n',
    '{"action":"sandbox.create","actor":"\\u017e\\u0107\\u010d \\u00e9 \\ud83d\\ude00 \\u007f","hash":"h02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","id":"evt_2","occurred_at":"2026-11-11T04:00:02+00:00","org_id":"org_1","prev_hash":"h01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n',
  ],
  head: '{"alg":"ed25519","export_sha256":"adf843f44dd4d2ba3c93ae20ab4787db697481490a27b60a3acfbe69228ef2e2","first_row_id":"evt_0","hash":"h02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hmac":"42765a694d73f590c639752ac62feff801d09b1a6f2cb5782bb3f48f1a892e7b","org_id":"org_1","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=","row_count":3,"row_id":"evt_2","signature":"LPxkLN6F0rxn0nRZVDeWs4nHIcVxgNxv1GBQL4i5nbWuTdsnkMDM_QpronUqER0_HUXSXQ7BT1VGiQ6uS0lrBw==","signed_at":"2026-11-11T04:52:33+00:00","type":"audit_head"}',
  /** The same export marked filtered (`outcome`, `request_id` with a non-ASCII value). */
  filteredHead:
    '{"alg":"ed25519","export_sha256":"adf843f44dd4d2ba3c93ae20ab4787db697481490a27b60a3acfbe69228ef2e2","filtered":true,"filters":{"outcome":"success","request_id":"r\\u00efd"},"first_row_id":"evt_0","hash":"h02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hmac":"fe8991486bae54de33ddd251700597f2d978edf4300ac48143891aaa5ba6274c","org_id":"org_1","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=","row_count":3,"row_id":"evt_2","signature":"iPNF2Zipc3A1dpL2AaCU1DNattnTImt3jMyMC9cGvxxW_ggRaRlD7OPKgx1Z-Gx4xsT9jujyZwokz2Bo5ciYAQ==","signed_at":"2026-11-11T04:52:33+00:00","type":"audit_head"}',
} as const;

export const ORG = "org_1";

export interface Signer {
  privateKey: KeyObject;
  /** Canonical urlsafe base64 of the raw public key. */
  publicKey: string;
}

export function newSigner(): Signer {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  return { privateKey, publicKey: encodeBase64Url(der.subarray(der.length - 32)) };
}

export function compact(record: unknown): string {
  return canonicalJson(record);
}

export function sha256Of(lines: readonly string[]): string {
  return createHash("sha256").update(lines.join(""), "utf8").digest("hex");
}

/** An event row line (with its `\n`) chained to `prev`. */
export function row(
  n: number,
  prev: string | null,
  extra: Record<string, unknown> = {},
): { line: string; hash: string } {
  const hash = `hash_${n}`;
  const record = {
    id: `evt_${n}`,
    occurred_at: "2026-11-11T04:00:00+00:00",
    org_id: ORG,
    action: "sandbox.create",
    prev_hash: prev,
    hash,
    ...extra,
  };
  return { line: `${compact(record)}\n`, hash };
}

/** `count` chained rows. */
export function chain(count: number): { lines: string[]; hashes: string[] } {
  const lines: string[] = [];
  const hashes: string[] = [];
  let prev: string | null = null;
  for (let n = 1; n <= count; n += 1) {
    const made = row(n, prev);
    lines.push(made.line);
    hashes.push(made.hash);
    prev = made.hash;
  }
  return { lines, hashes };
}

/** A head record over `lines`, signed with `signer` (override fields with `fields`). */
export function head(
  lines: readonly string[],
  signer: Signer,
  fields: Record<string, unknown> = {},
  options: { bind?: boolean; sign?: boolean } = {},
): string {
  const last = JSON.parse(lines[lines.length - 1] ?? "{}") as Record<string, string>;
  const first = JSON.parse(lines[0] ?? "{}") as Record<string, string>;
  const record: Record<string, unknown> = {
    type: "audit_head",
    org_id: ORG,
    row_id: last["id"],
    hash: last["hash"],
    alg: "ed25519",
    public_key: signer.publicKey,
    signed_at: "2026-11-11T04:00:00+00:00",
    hmac: "0".repeat(64),
    ...(options.bind === false
      ? {}
      : { row_count: lines.length, first_row_id: first["id"] ?? null, export_sha256: sha256Of(lines) }),
    ...fields,
  };
  for (const [name, value] of Object.entries(record)) {
    if (value === undefined) delete record[name];
  }
  const { signature: _s, hmac: _h, ...signed } = record;
  if (options.sign !== false) {
    record["signature"] = encodeBase64Url(sign(null, Buffer.from(compact(signed)), signer.privateKey));
  }
  return compact(record);
}

/** The signed head of a fresh chain, as `{ lines, head, signer }`. */
export function signedExport(count = 3, fields: Record<string, unknown> = {}) {
  const signer = newSigner();
  const { lines } = chain(count);
  return { signer, lines, head: head(lines, signer, fields) };
}

export function text(lines: readonly string[], trailer: string): string {
  return `${lines.join("")}${trailer}\n`;
}
