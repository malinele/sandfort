import { describe, expect, it, vi } from "vitest";
import { RequestTimeoutError, type Sandbox } from "../src/index.js";
import { clientFor, hangUntilAborted, ok, sandboxPayload, type Recorded } from "./helpers.js";

async function sandboxWith(
  reply: (request: Recorded) => Promise<Response>,
  clientOptions: { deadlineMs?: number } = {},
): Promise<Sandbox> {
  const { client } = clientFor([ok(sandboxPayload()), reply], { retries: 0, ...clientOptions });
  return client.getSandbox("sbx_1");
}

const calls: ReadonlyArray<readonly [string, (sandbox: Sandbox) => Promise<unknown>]> = [
  ["processExec", (sbx) => sbx.processExec("sleep 50", { timeoutMs: 20 })],
  ["codeRun", (sbx) => sbx.codeRun("python", "1", { timeoutMs: 20 })],
  ["runInSession", (sbx) => sbx.runInSession("s1", "sleep 50", { timeoutMs: 20 })],
  ["runInCodeContext", (sbx) => sbx.runInCodeContext("ctx_a", "1", { timeoutMs: 20 })],
  [
    "streamCodeContextRun",
    async (sbx) => {
      for await (const event of sbx.streamCodeContextRun("ctx_a", "1", { timeoutMs: 20 })) {
        void event;
      }
    },
  ],
];

describe("an explicit per-call timeoutMs wins over the long-run floor", () => {
  it.each(calls)("%s times out after timeoutMs, not after timeoutS + 10 s", async (_name, call) => {
    const sandbox = await sandboxWith(hangUntilAborted);

    const started = Date.now();
    const failed = call(sandbox);

    await expect(failed).rejects.toBeInstanceOf(RequestTimeoutError);
    await expect(failed).rejects.toThrow(/timed out after 20 ms/);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("still floors the timeout when the call sets none", async () => {
    const seen: number[] = [];
    const real = AbortSignal.timeout.bind(AbortSignal);
    const spy = vi.spyOn(AbortSignal, "timeout").mockImplementation((ms: number) => {
      seen.push(ms);
      return real(ms);
    });
    try {
      const { client } = clientFor([ok(sandboxPayload()), ok({ exit_code: 0, result: "" })], {
        timeoutMs: 1_000,
      });
      const sandbox = await client.getSandbox("sbx_1");
      await sandbox.processExec("ls", { timeoutS: 30 }).catch(() => undefined);
    } finally {
      spy.mockRestore();
    }

    expect(seen).toContain(40_000);
  });
});
