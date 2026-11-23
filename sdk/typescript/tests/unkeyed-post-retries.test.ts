import { describe, expect, it } from "vitest";
import { RateLimited, TransportError, type Sandbox } from "../src/index.js";
import { clientFor, failure, ok, sandboxPayload, type QueueItem } from "./helpers.js";

const RETRIES = { retries: 3 };

/** Every POST of the SDK that carries no idempotency key. */
const unkeyed: ReadonlyArray<readonly [string, (sandbox: Sandbox) => Promise<unknown>]> = [
  ["reset", (sbx) => sbx.reset(RETRIES)],
  ["processExec", (sbx) => sbx.processExec("ls", RETRIES)],
  ["codeRun", (sbx) => sbx.codeRun("python", "1", RETRIES)],
  ["runInSession", (sbx) => sbx.runInSession("s1", "ls", RETRIES)],
  ["mintPreviewToken", (sbx) => sbx.mintPreviewToken({ port: 3000, ...RETRIES })],
  ["runInCodeContext", (sbx) => sbx.runInCodeContext("ctx_a", "1", RETRIES)],
];

const answers: ReadonlyArray<readonly [string, () => QueueItem, unknown]> = [
  ["a 429", () => failure(429, "RATE_LIMITED", { "Retry-After": "1" }), RateLimited],
  ["a 503 CAPACITY", () => failure(503, "CAPACITY", { "Retry-After": "1" }), Error],
  ["a network error", () => new TypeError("fetch failed"), TransportError],
];

describe("a per-call retries above 0 never re-sends an unkeyed POST", () => {
  describe.each(unkeyed)("%s", (_name, call) => {
    it.each(answers)("after %s", async (_label, answer, errorType) => {
      const pauses: number[] = [];
      const sleep = (ms: number): Promise<void> => {
        pauses.push(ms);
        return Promise.resolve();
      };
      const { client, requests } = clientFor(
        [ok(sandboxPayload()), answer(), ok(sandboxPayload())],
        { sleep },
      );
      const sandbox = await client.getSandbox("sbx_1");

      await expect(call(sandbox)).rejects.toBeInstanceOf(errorType as typeof Error);

      expect(requests).toHaveLength(2);
      expect(pauses).toEqual([]);
    });
  });
});
