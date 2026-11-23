import { describe, expect, it } from "vitest";
import { RequestAbortedError, RequestTimeoutError } from "../src/index.js";
import { clientFor, ok, sandboxPayload, type Recorded } from "./helpers.js";

/** A 200 whose body sends one chunk, then stalls until the request signal aborts and errors. */
function stallingBody(request: Recorded): Response {
  const signal = request.signal;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]));
      signal?.addEventListener("abort", () => controller.error(signal.reason), { once: true });
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "content-type": "application/octet-stream" },
  });
}

describe("downloadFile body read", () => {
  it("maps a timeout during the body read to RequestTimeoutError", async () => {
    const { client } = await sandboxClient({ timeoutMs: 30, retries: 0 });
    const sandbox = await client.getSandbox("sbx_1");

    await expect(sandbox.fs.downloadFile("/w/big.bin")).rejects.toBeInstanceOf(RequestTimeoutError);
  });

  it("maps an abort in the middle of the stream to RequestAbortedError", async () => {
    const { client } = await sandboxClient({});
    const sandbox = await client.getSandbox("sbx_1");
    const controller = new AbortController();

    const pending = sandbox.fs.downloadFile("/w/big.bin", { signal: controller.signal });
    setTimeout(() => controller.abort(), 10);

    await expect(pending).rejects.toBeInstanceOf(RequestAbortedError);
  });
});

async function sandboxClient(options: { timeoutMs?: number; retries?: number }) {
  return clientFor([ok(sandboxPayload()), stallingBody], options);
}
