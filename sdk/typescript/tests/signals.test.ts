import { afterEach, describe, expect, it, vi } from "vitest";
import { RequestAbortedError, RequestTimeoutError } from "../src/index.js";
import { composeSignals } from "../src/signals.js";
import { clientFor, hangUntilAborted, ok, sandboxPayload } from "./helpers.js";

const original = Object.getOwnPropertyDescriptor(AbortSignal, "any");

function withoutAbortSignalAny(): void {
  Object.defineProperty(AbortSignal, "any", { value: undefined, configurable: true, writable: true });
}

afterEach(() => {
  if (original !== undefined) Object.defineProperty(AbortSignal, "any", original);
  vi.restoreAllMocks();
});

describe("composeSignals without AbortSignal.any", () => {
  it("really runs the fallback in this test", () => {
    withoutAbortSignalAny();
    expect((AbortSignal as { any?: unknown }).any).toBeUndefined();
  });

  it("aborts with the reason of the first input that aborts", () => {
    withoutAbortSignalAny();
    const first = new AbortController();
    const second = new AbortController();

    const composed = composeSignals([first.signal, second.signal]);
    expect(composed.signal.aborted).toBe(false);
    second.abort(new Error("second"));

    expect(composed.signal.aborted).toBe(true);
    expect((composed.signal.reason as Error).message).toBe("second");
  });

  it("is aborted at once when an input already is", () => {
    withoutAbortSignalAny();

    const composed = composeSignals([new AbortController().signal, AbortSignal.abort("gone")]);

    expect(composed.signal.aborted).toBe(true);
    expect(composed.signal.reason).toBe("gone");
  });

  it("removes its listeners on dispose and after firing", () => {
    withoutAbortSignalAny();
    const input = new AbortController();
    const added = vi.spyOn(input.signal, "addEventListener");
    const removed = vi.spyOn(input.signal, "removeEventListener");

    composeSignals([input.signal]).dispose();
    expect(added).toHaveBeenCalledTimes(1);
    expect(removed).toHaveBeenCalledTimes(1);

    const fired = composeSignals([input.signal]);
    input.abort();
    fired.dispose();
    expect(removed).toHaveBeenCalledTimes(2);
  });

  it("uses the native AbortSignal.any when it exists", () => {
    const composed = composeSignals([new AbortController().signal]);
    expect(composed.signal.aborted).toBe(false);
  });
});

describe("requests without AbortSignal.any", () => {
  it("still maps the caller's abort to RequestAbortedError", async () => {
    withoutAbortSignalAny();
    const { client } = clientFor([hangUntilAborted]);
    const controller = new AbortController();

    const pending = client.getSandbox("sbx_1", { signal: controller.signal });
    controller.abort();

    await expect(pending).rejects.toBeInstanceOf(RequestAbortedError);
  });

  it("still maps the per-request timeout to RequestTimeoutError", async () => {
    withoutAbortSignalAny();
    const { client } = clientFor([hangUntilAborted], { timeoutMs: 20, retries: 0 });

    await expect(client.getSandbox("sbx_1")).rejects.toBeInstanceOf(RequestTimeoutError);
  });

  it("leaves no listener on the caller's signal after a successful call", async () => {
    withoutAbortSignalAny();
    const { client } = clientFor([ok(sandboxPayload())]);
    const controller = new AbortController();
    const added = vi.spyOn(controller.signal, "addEventListener");
    const removed = vi.spyOn(controller.signal, "removeEventListener");

    await client.getSandbox("sbx_1", { signal: controller.signal });

    expect(added.mock.calls.length).toBeGreaterThan(0);
    expect(removed).toHaveBeenCalledTimes(added.mock.calls.length);
  });
});
