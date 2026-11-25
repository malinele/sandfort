import { describe, expect, it } from "vitest";
import { ValidationError, verifyExport } from "../src/index.js";
import {
  GOLDEN,
  ORG,
  chain,
  compact,
  head,
  newSigner,
  row,
  sha256Of,
  signedExport,
  text,
} from "./audit-trailer-helpers.js";

const goldenBody = text(GOLDEN.lines, GOLDEN.head);

describe("verifyExport against an export written by the server", () => {
  it("verifies the golden export as one text, as lines and as an async stream", async () => {
    async function* stream(): AsyncGenerator<string> {
      for (const line of goldenBody.split("\n")) yield `${line}\n`;
    }

    for (const source of [goldenBody, goldenBody.split("\n"), [...GOLDEN.lines, `${GOLDEN.head}\n`], stream()]) {
      const result = await verifyExport(source, GOLDEN.publicKey);

      expect(result).toMatchObject({
        ok: true,
        reason: null,
        rows: 3,
        unchained: 0,
        firstBreak: null,
        lastRowId: "evt_2",
        badLine: null,
        contentBound: true,
        filtered: false,
        previousRows: null,
        newRows: null,
        rowId: "evt_2",
        orgId: "org_1",
      });
    }
  });

  it("verifies the golden export under the filtered head and reports it filtered", async () => {
    const result = await verifyExport(text(GOLDEN.lines, GOLDEN.filteredHead), GOLDEN.publicKey);

    expect(result.ok).toBe(true);
    expect(result.filtered).toBe(true);
    expect(result.firstBreak).toBeNull();
  });

  it("catches an edited line that keeps its hash and prev_hash (content_mismatch)", async () => {
    const lines: string[] = [...GOLDEN.lines];
    lines[1] = (lines[1] as string).replace("sandbox.create", "sandbox.delete");

    const result = await verifyExport(text(lines, GOLDEN.head), GOLDEN.publicKey);

    expect(result.reason).toBe("content_mismatch");
  });

  it("counts CRLF as part of the bytes: a CRLF copy fails the digest", async () => {
    const crlf = goldenBody.replace(/\n/g, "\r\n");

    expect((await verifyExport(crlf, GOLDEN.publicKey)).reason).toBe("content_mismatch");
  });

  it("tolerates blank lines and trailing blank lines", async () => {
    const padded = `\n${GOLDEN.lines.join("\n")}\n\n${GOLDEN.head}\n\n\n`;

    expect((await verifyExport(padded, GOLDEN.publicKey)).ok).toBe(true);
  });

  it("reports the head's reason first when the head fails", async () => {
    const result = await verifyExport(goldenBody, newSigner().publicKey);

    expect(result.reason).toBe("key_mismatch");
    expect(result.ok).toBe(false);
  });
});

describe("verifyExport file checks (bound head)", () => {
  it("count_mismatch when rows are removed or added, before content_mismatch", async () => {
    const { signer, lines, head: trailer } = signedExport(3);
    const extra = row(4, "hash_3").line;

    expect((await verifyExport(text(lines.slice(0, 2), trailer), signer.publicKey)).reason).toBe("count_mismatch");
    expect((await verifyExport(text([...lines, extra], trailer), signer.publicKey)).reason).toBe("count_mismatch");
  });

  it("content_mismatch when two rows swap places", async () => {
    const { signer, lines, head: trailer } = signedExport(3);
    const swapped = [lines[0] as string, lines[2] as string, lines[1] as string];

    expect((await verifyExport(text(swapped, trailer), signer.publicKey)).reason).toBe("content_mismatch");
  });

  it("first_row_mismatch when the signed first id differs from the file's", async () => {
    const signer = newSigner();
    const { lines } = chain(3);
    const trailer = head(lines, signer, { first_row_id: "evt_other" });

    expect((await verifyExport(text(lines, trailer), signer.publicKey)).reason).toBe("first_row_mismatch");
  });

  it("an export with no rows under a head that binds zero rows is truncated (the head names a row)", async () => {
    const signer = newSigner();
    const { lines } = chain(1);
    const trailer = head(lines, signer, { row_count: 0, first_row_id: null, export_sha256: sha256Of([]) });

    const result = await verifyExport(`${trailer}\n`, signer.publicKey);

    expect(result.reason).toBe("truncated");
    expect(result.lastRowId).toBeNull();
  });
});

describe("verifyExport file checks (legacy head, no binding)", () => {
  const legacy = (lines: readonly string[], signer = newSigner(), fields: Record<string, unknown> = {}) => ({
    signer,
    trailer: head(lines, signer, fields, { bind: false }),
  });

  it("verifies a legacy head and reports contentBound false", async () => {
    const { lines } = chain(3);
    const { signer, trailer } = legacy(lines);

    const result = await verifyExport(text(lines, trailer), signer.publicKey);

    expect(result).toMatchObject({ ok: true, contentBound: false, rows: 3 });
  });

  it("truncated when the newest rows are cut, head_mismatch when the hash differs", async () => {
    const { lines } = chain(3);
    const { signer, trailer } = legacy(lines);
    const wrongHash = legacy(lines, signer, { hash: "forged" }).trailer;

    expect((await verifyExport(text(lines.slice(0, 2), trailer), signer.publicKey)).reason).toBe("truncated");
    expect((await verifyExport(text(lines, wrongHash), signer.publicKey)).reason).toBe("head_mismatch");
  });

  it("chain_break names the first row whose prev_hash does not match", async () => {
    const { lines } = chain(3);
    const broken = [lines[0] as string, row(2, "wrong").line, row(3, "hash_2").line];
    const { signer, trailer } = legacy(broken);

    const result = await verifyExport(text(broken, trailer), signer.publicKey);

    expect(result).toMatchObject({ ok: false, reason: "chain_break", firstBreak: "evt_2" });
  });

  it("does not check linkage for a filtered head (and reports no break)", async () => {
    const { lines } = chain(3);
    const gap = [lines[0] as string, row(3, "hash_2").line];
    const signer = newSigner();
    const trailer = head(gap, signer, { filtered: true, filters: { outcome: "denied" } });

    const result = await verifyExport(text(gap, trailer), signer.publicKey);

    expect(result).toMatchObject({ ok: true, filtered: true, firstBreak: null });
  });

  it("unchained_rows for rows without a hash, with badLine; allowUnchained counts them", async () => {
    const first = row(1, null, { hash: null });
    const second = row(2, null, { hash: null, prev_hash: null });
    const third = row(3, "hash_2");
    const lines = [first.line, second.line, third.line];
    const { signer, trailer } = legacy(lines);
    const body = text(lines, trailer);

    const strict = await verifyExport(body, signer.publicKey);
    const lenient = await verifyExport(body, signer.publicKey, { allowUnchained: true });

    expect(strict).toMatchObject({ ok: false, reason: "unchained_rows", badLine: 1, unchained: 2 });
    expect(lenient).toMatchObject({ ok: true, unchained: 2, rows: 1 });
  });

  it("a last row without a hash is head_mismatch even with allowUnchained", async () => {
    const { lines } = chain(2);
    const stripped = [lines[0] as string, row(2, "hash_1", { hash: null }).line];
    const signer = newSigner();
    const trailer = head(chain(2).lines, signer, {}, { bind: false });

    const result = await verifyExport(text(stripped, trailer), signer.publicKey, { allowUnchained: true });

    expect(result.reason).toBe("head_mismatch");
  });

  it("org_mismatch when a row belongs to another org, with its line", async () => {
    const { lines } = chain(3);
    const mixed = [lines[0] as string, row(2, "hash_1", { org_id: "org_2" }).line, lines[2] as string];
    const { signer, trailer } = legacy(mixed);

    const result = await verifyExport(text(mixed, trailer), signer.publicKey);

    expect(result).toMatchObject({ reason: "org_mismatch", badLine: 2 });
  });
});

describe("verifyExport malformed input", () => {
  const withBad = (bad: string) => {
    const signer = newSigner();
    const { lines } = chain(2);
    const trailer = head(lines, signer, {}, { bind: false });
    return { signer, body: `${lines[0]}${bad}\n${lines[1]}${trailer}\n` };
  };

  it.each([
    ["not JSON", "not json"],
    ["a JSON array", "[1]"],
    ["a row without id", compact({ occurred_at: "x", org_id: ORG, action: "a", hash: "h", prev_hash: null })],
    ["a row missing the prev_hash key", compact({ id: "e", occurred_at: "x", org_id: ORG, action: "a", hash: "h" })],
    ["a numeric hash", compact({ id: "e", occurred_at: "x", org_id: ORG, action: "a", hash: 5, prev_hash: null })],
    ["a line over 1 MiB", `{"id":"${"x".repeat(1024 * 1024)}"}`],
  ])("malformed_row for %s, naming line 2", async (_name, bad) => {
    const { signer, body } = withBad(bad);

    const result = await verifyExport(body, signer.publicKey);

    expect(result).toMatchObject({ ok: false, reason: "malformed_row", badLine: 2 });
  });

  it("misplaced_trailer for a head or summary line above the last line", async () => {
    const { signer, lines, head: trailer } = signedExport(2);
    const summary = compact({ type: "export_summary", rows: 0, filters: [] });

    for (const stray of [trailer, summary]) {
      const body = `${lines[0]}${stray}\n${lines[1]}${trailer}\n`;
      const result = await verifyExport(body, signer.publicKey);
      // A stray trailer is not an event line, so the binding still holds and the file check speaks.
      expect(result).toMatchObject({ ok: false, reason: "misplaced_trailer", badLine: 2 });
    }
  });

  it("no_trailer when the last line is a row, junk, or an extra row follows the head", async () => {
    const { signer, lines, head: trailer } = signedExport(2);

    const noHead = await verifyExport(lines.join(""), signer.publicKey);
    const junk = await verifyExport(`${lines.join("")}garbage\n`, signer.publicKey);
    const after = await verifyExport(`${lines.join("")}${trailer}\n${row(3, "hash_2").line}`, signer.publicKey);

    expect(noHead).toMatchObject({ ok: false, reason: "no_trailer", rowId: "", entryHash: "", rows: 2, badLine: 2 });
    expect(junk).toMatchObject({ reason: "no_trailer", badLine: 3 });
    expect(after).toMatchObject({ reason: "no_trailer", badLine: 4 });
  });

  it("still validates the key when there is no trailer", async () => {
    const { lines } = chain(1);

    await expect(verifyExport(lines.join(""), "bad")).rejects.toBeInstanceOf(ValidationError);
  });

  it("throws for an empty export, for a last export_summary and for junk without rows", async () => {
    const summary = `${compact({ type: "export_summary", rows: 0, filters: [] })}\n`;

    await expect(verifyExport("", GOLDEN.publicKey)).rejects.toThrow(/export is empty/);
    await expect(verifyExport("\n \n", GOLDEN.publicKey)).rejects.toThrow(/export is empty/);
    await expect(verifyExport(summary, GOLDEN.publicKey)).rejects.toBeInstanceOf(ValidationError);
    await expect(verifyExport(`${row(1, null).line}${summary}`, GOLDEN.publicKey)).rejects.toBeInstanceOf(ValidationError);
    await expect(verifyExport("junk\n", GOLDEN.publicKey)).rejects.toBeInstanceOf(ValidationError);
  });

  it("throws ValidationError for a malformed key even with a good file", async () => {
    await expect(verifyExport(goldenBody, "nope")).rejects.toBeInstanceOf(ValidationError);
  });
});

describe("verifyExport with previous", () => {
  it("accepts an earlier export as a byte prefix and counts the new rows", async () => {
    const signer = newSigner();
    const { lines } = chain(5);
    const earlier = text(lines.slice(0, 3), head(lines.slice(0, 3), signer));
    const later = text(lines, head(lines, signer));

    const result = await verifyExport(later, signer.publicKey, { previous: earlier });

    expect(result).toMatchObject({ ok: true, previousRows: 3, newRows: 2 });
  });

  it("accepts previous as lines, and an identical export adds no rows", async () => {
    const signer = newSigner();
    const { lines } = chain(3);
    const same = text(lines, head(lines, signer));

    const result = await verifyExport(same, signer.publicKey, { previous: same.split("\n") });

    expect(result).toMatchObject({ ok: true, previousRows: 3, newRows: 0 });
  });

  it("not_a_continuation when a line differs or the earlier export is longer", async () => {
    const signer = newSigner();
    const { lines } = chain(4);
    const later = text(lines, head(lines, signer));
    const edited = [...lines.slice(0, 2)];
    edited[1] = (edited[1] as string).replace("sandbox.create", "x");
    const longer = text(lines, head(lines, signer));
    const shorter = text(lines.slice(0, 3), head(lines.slice(0, 3), signer));

    const differs = await verifyExport(later, signer.publicKey, { previous: text(edited, "{}") });
    const tooLong = await verifyExport(shorter, signer.publicKey, { previous: longer });

    expect(differs).toMatchObject({ ok: false, reason: "not_a_continuation", previousRows: null });
    expect(tooLong.reason).toBe("not_a_continuation");
  });

  it("an empty previous is a prefix of anything", async () => {
    const { signer, lines, head: trailer } = signedExport(2);

    const result = await verifyExport(text(lines, trailer), signer.publicKey, { previous: "" });

    expect(result).toMatchObject({ ok: true, previousRows: 0, newRows: 2 });
  });
});

describe("verifyExport org binding", () => {
  /** A genuinely signed, content-bound export of `org`. */
  function exportOf(org: string, fields: Record<string, unknown> = {}) {
    const signer = newSigner();
    const lines: string[] = [];
    let prev: string | null = null;
    for (let n = 1; n <= 3; n += 1) {
      const made = row(n, prev, { org_id: org });
      lines.push(made.line);
      prev = made.hash;
    }
    return { signer, lines, trailer: head(lines, signer, { org_id: org, ...fields }) };
  }

  it("exposes the head's org_id, on the golden export too", async () => {
    const { signer, lines, trailer } = exportOf(ORG);

    expect((await verifyExport(text(lines, trailer), signer.publicKey)).orgId).toBe(ORG);
    expect((await verifyExport(goldenBody, GOLDEN.publicKey)).orgId).toBe("org_1");
  });

  it("accepts the expected org", async () => {
    const { signer, lines, trailer } = exportOf(ORG);

    const result = await verifyExport(text(lines, trailer), signer.publicKey, { expectedOrgId: ORG });

    expect(result).toMatchObject({ ok: true, reason: null, orgId: ORG });
  });

  it("refuses a genuine export of org_b presented as org_a, without file checks", async () => {
    const { signer, lines, trailer } = exportOf("org_b");

    const result = await verifyExport(text(lines, trailer), signer.publicKey, { expectedOrgId: "org_a" });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("expected_org_mismatch");
    expect(result.orgId).toBe("org_b");
    expect(result.badLine).toBeNull();
  });

  it("the head's reason wins over file problems when the expected org is wrong", async () => {
    const { signer, lines, trailer } = exportOf("org_b");

    const result = await verifyExport(text(lines.slice(1), trailer), signer.publicKey, { expectedOrgId: "org_a" });

    expect(result.reason).toBe("expected_org_mismatch");
  });

  it("a head without org_id fails closed with an expected org", async () => {
    const { signer, lines, trailer } = exportOf(ORG, { org_id: undefined });

    const plain = await verifyExport(text(lines, trailer), signer.publicKey);
    const expected = await verifyExport(text(lines, trailer), signer.publicKey, { expectedOrgId: ORG });

    expect(plain.orgId).toBeNull();
    expect(expected).toMatchObject({ ok: false, reason: "expected_org_mismatch", orgId: null });
  });

  it("throws ValidationError for an empty expectedOrgId", async () => {
    const { signer, lines, trailer } = exportOf(ORG);

    await expect(verifyExport(text(lines, trailer), signer.publicKey, { expectedOrgId: "" })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });

  it("an unsigned head keeps reason unsigned with an expected org", async () => {
    const signer = newSigner();
    const { lines } = chain(3);
    const trailer = head(lines, signer, { org_id: "org_b" }, { sign: false });

    const result = await verifyExport(text(lines, trailer), signer.publicKey, { expectedOrgId: "org_a" });

    expect(result).toMatchObject({ ok: false, reason: "unsigned", orgId: "org_b" });
  });

  it("an export without a trailer has no org id", async () => {
    const signer = newSigner();

    const result = await verifyExport(chain(2).lines.join(""), signer.publicKey);

    expect(result).toMatchObject({ ok: false, reason: "no_trailer", orgId: null });
  });

  it("the row-level org_mismatch reason is unchanged, with and without a matching expected org", async () => {
    const signer = newSigner();
    const first = row(1, null);
    const second = row(2, first.hash, { org_id: "org_x" });
    const third = row(3, second.hash);
    const lines = [first.line, second.line, third.line];
    const trailer = head(lines, signer);

    for (const options of [{}, { expectedOrgId: ORG }]) {
      const result = await verifyExport(text(lines, trailer), signer.publicKey, options);

      expect(result).toMatchObject({ ok: false, reason: "org_mismatch", badLine: 2, orgId: ORG });
    }
  });
});
