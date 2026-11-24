import { describe, expect, it } from "vitest";
import { verifyExport } from "../src/index.js";
import { signedExport, text } from "./audit-trailer-helpers.js";

/** An async source of lines that records whether its `finally` block ran. */
function tracked(lines: readonly string[]): { source: AsyncGenerator<string>; state: { closed: boolean } } {
  const state = { closed: false };
  async function* generate(): AsyncGenerator<string> {
    try {
      for (const line of lines) yield line;
    } finally {
      state.closed = true;
    }
  }
  return { source: generate(), state };
}

describe("verifyExport closes the `previous` source", () => {
  it("closes it right after a prefix mismatch, before the scan ends", async () => {
    const { signer, lines, head } = signedExport(5);
    const edited = lines.map((line, index) => (index === 1 ? line.replace("sandbox.create", "x") : line));
    const { source, state } = tracked(edited);

    const result = await verifyExport(text(lines, head), signer.publicKey, { previous: source });

    expect(result.reason).toBe("not_a_continuation");
    expect(state.closed).toBe(true);
  });

  it("closes it when the scan throws before it finishes", async () => {
    const { signer, lines } = signedExport(5);
    const { source, state } = tracked(lines);
    async function* failing(): AsyncGenerator<string> {
      for (const line of lines.slice(0, 3)) yield line;
      throw new Error("stream broke");
    }

    await expect(verifyExport(failing(), signer.publicKey, { previous: source })).rejects.toThrow("stream broke");

    expect(state.closed).toBe(true);
  });

  it("closes it when the earlier export is longer than the later one", async () => {
    const { signer, lines, head } = signedExport(5);
    const { source, state } = tracked(lines);
    const shorter = text(lines.slice(0, 3), head);

    const result = await verifyExport(shorter, signer.publicKey, { previous: source });

    expect(result.reason).not.toBeNull();
    expect(state.closed).toBe(true);
  });

  it("closes it after a passing check too", async () => {
    const { signer, lines, head } = signedExport(3);
    const { source, state } = tracked(lines);

    const result = await verifyExport(text(lines, head), signer.publicKey, { previous: source });

    expect(result.ok).toBe(true);
    expect(state.closed).toBe(true);
  });
});
