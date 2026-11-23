import { afterEach, describe, expect, it, vi } from "vitest";
import { RequestAbortedError } from "../src/index.js";
import { abortableSleep } from "../src/resilience.js";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("abortableSleep cleanup", () => {
  it("removes its abort listener once the timer fires", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const added = vi.spyOn(controller.signal, "addEventListener");
    const removed = vi.spyOn(controller.signal, "removeEventListener");

    const sleeping = abortableSleep(1_000, controller.signal);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(1_000);
    await sleeping;

    expect(added).toHaveBeenCalledTimes(1);
    expect(removed).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("clears its timer and rejects when the signal aborts", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();

    const sleeping = abortableSleep(60_000, controller.signal);
    const outcome = sleeping.catch((error: unknown) => error);
    controller.abort();

    expect(await outcome).toBeInstanceOf(RequestAbortedError);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("starts no timer and adds no listener for a signal that is already aborted", async () => {
    vi.useFakeTimers();
    const signal = AbortSignal.abort();
    const added = vi.spyOn(signal, "addEventListener");

    await expect(abortableSleep(1_000, signal)).rejects.toBeInstanceOf(RequestAbortedError);

    expect(added).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("sleeps without a signal and leaves no timer behind", async () => {
    vi.useFakeTimers();

    const sleeping = abortableSleep(500);
    await vi.advanceTimersByTimeAsync(500);

    await expect(sleeping).resolves.toBeUndefined();
    expect(vi.getTimerCount()).toBe(0);
  });
});
