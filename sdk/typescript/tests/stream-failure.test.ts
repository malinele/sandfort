/**
 * Round 75 item C: `streamReadFailure` classification, including the Node 20.3 / Undici 5.22
 * shape where the SDK's own timeout surfaces as a `DOMException` named `AbortError` during a
 * body read (partner finding: expected `RequestTimeoutError`, got `TransportError`).
 */

import { describe, expect, it } from "vitest";
import { RequestAbortedError, RequestTimeoutError, TransportError } from "../src/errors.js";
import { SandfortClient, type FetchLike } from "../src/index.js";
import { DeadlineExceeded } from "../src/signals.js";
import { rememberStreamSignal, streamReadFailure } from "../src/stream-failure.js";

const SUBJECT = "the log stream";

function abortError(): DOMException {
  return new DOMException("The operation was aborted.", "AbortError");
}

describe("streamReadFailure", () => {
  it("prefers the caller's abort over everything else", () => {
    const controller = new AbortController();
    controller.abort();

    const error = streamReadFailure(SUBJECT, abortError(), controller.signal, "req_1");

    expect(error).toBeInstanceOf(RequestAbortedError);
  });

  it("classifies a DeadlineExceeded cause as a timeout", () => {
    const error = streamReadFailure(SUBJECT, new DeadlineExceeded(35), undefined, null);

    expect(error).toBeInstanceOf(RequestTimeoutError);
    expect(error.message).toContain("35");
  });

  it("classifies a TimeoutError-named cause as a timeout", () => {
    const cause = new DOMException("timed out", "TimeoutError");

    const error = streamReadFailure(SUBJECT, cause, undefined, null);

    expect(error).toBeInstanceOf(RequestTimeoutError);
  });

  it("classifies an AbortError without a caller abort as the SDK's own timer (Node 20.3 shape)", () => {
    const controller = new AbortController();

    const error = streamReadFailure(SUBJECT, abortError(), controller.signal, "req_2");

    expect(error).toBeInstanceOf(RequestTimeoutError);
    expect(error.message).toContain("req_2");
  });

  it("classifies an AbortError with no caller signal at all as a timeout", () => {
    const error = streamReadFailure(SUBJECT, abortError(), undefined, null);

    expect(error).toBeInstanceOf(RequestTimeoutError);
  });

  it("names the deadline when the remembered stream signal was cut by DeadlineExceeded", () => {
    const response = new Response("x");
    const controller = new AbortController();
    controller.abort(new DeadlineExceeded(35));
    rememberStreamSignal(response, controller.signal);

    const error = streamReadFailure(SUBJECT, abortError(), undefined, "req_3", response);

    expect(error).toBeInstanceOf(RequestTimeoutError);
    expect(error.message).toContain("deadline");
    expect(error.message).toContain("35");
  });

  it("stays a generic timeout when the remembered stream signal was cut by a plain abort", () => {
    const response = new Response("x");
    const controller = new AbortController();
    controller.abort(abortError());
    rememberStreamSignal(response, controller.signal);

    const error = streamReadFailure(SUBJECT, abortError(), undefined, null, response);

    expect(error).toBeInstanceOf(RequestTimeoutError);
    expect(error.message).not.toContain("deadline");
  });

  it("stays a generic timeout without a remembered response", () => {
    const error = streamReadFailure(SUBJECT, abortError(), undefined, null, new Response("x"));

    expect(error).toBeInstanceOf(RequestTimeoutError);
    expect(error.message).not.toContain("deadline");
  });

  it("keeps an unrelated failure a TransportError", () => {
    const error = streamReadFailure(SUBJECT, new TypeError("terminated"), undefined, null);

    expect(error).toBeInstanceOf(TransportError);
    expect(error).not.toBeInstanceOf(RequestTimeoutError);
    expect(error).not.toBeInstanceOf(RequestAbortedError);
  });
});

describe("deadline identity through the transport (Node 20 rejection shape)", () => {
  it("names the deadline when the body read rejects with a bare AbortError after deadlineMs", async () => {
    // The body never delivers a chunk; the pending read rejects with the Node 20 / Undici 5
    // shape (a bare AbortError DOMException) once the SDK's deadline controller fires.
    const body = new ReadableStream<Uint8Array>({
      pull(): Promise<void> {
        return new Promise((_resolve, reject) => {
          setTimeout(
            () => reject(new DOMException("The operation was aborted.", "AbortError")),
            80,
          );
        });
      },
    });
    const fetch: FetchLike = async () =>
      new Response(body, { status: 200, headers: { "content-type": "application/x-ndjson" } });
    const client = new SandfortClient({ baseUrl: "http://sf.test", apiKey: "sf_key", fetch });

    const run = (async () => {
      for await (const line of client.audit.exportLines({ deadlineMs: 30 })) void line;
    })();

    await expect(run).rejects.toBeInstanceOf(RequestTimeoutError);
    await expect(run).rejects.toThrow(/deadline of 30 ms/);
  });
});
