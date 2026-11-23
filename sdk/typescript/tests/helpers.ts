import { SandfortClient, type FetchLike, type SandfortClientOptions } from "../src/index.js";

export interface Recorded {
  url: string;
  method: string;
  body: string | undefined;
  headers: Headers;
  signal: AbortSignal | undefined;
}

export type QueueItem = Response | Error | ((request: Recorded) => Response | Promise<Response>);

/** A fetch stub that answers from a queue and records every request. */
export function stub(queue: QueueItem[]): { fetch: FetchLike; requests: Recorded[] } {
  const requests: Recorded[] = [];
  const fetch: FetchLike = async (input, init) => {
    const recorded: Recorded = {
      url: input,
      method: init.method ?? "GET",
      body: typeof init.body === "string" ? init.body : undefined,
      headers: new Headers(init.headers),
      signal: init.signal ?? undefined,
    };
    requests.push(recorded);
    const next = queue.shift();
    if (next === undefined) throw new Error("no queued response");
    if (next instanceof Error) throw next;
    return typeof next === "function" ? next(recorded) : next;
  };
  return { fetch, requests };
}

export function ok(data: unknown, nextCursor?: string | null): Response {
  const body =
    nextCursor === undefined
      ? { success: true, data }
      : { success: true, data, meta: { next_cursor: nextCursor } };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

export function failure(
  status: number,
  code: string,
  headers: Record<string, string> = {},
  message = "boom",
): Response {
  const body = { success: false, error: { code, message } };
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export function sandboxPayload(
  state = "started",
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return { id: "sbx_1", name: "demo", state, ...extra };
}

export function clientFor(
  queue: QueueItem[],
  options: Partial<SandfortClientOptions> = {},
): { client: SandfortClient; requests: Recorded[] } {
  const { fetch, requests } = stub(queue);
  const client = new SandfortClient({
    baseUrl: "http://sf.test",
    apiKey: "sf_key",
    fetch,
    ...options,
  });
  return { client, requests };
}

export function at(requests: readonly Recorded[], index: number): Recorded {
  const item = requests[index];
  if (item === undefined) throw new Error(`no request recorded at ${index}`);
  return item;
}

/** A fetch answer that never arrives; it rejects with the abort reason when the request is aborted. */
export function hangUntilAborted(request: Recorded): Promise<Response> {
  return new Promise<Response>((_resolve, reject) => {
    const signal = request.signal;
    if (signal === undefined) return;
    const fail = (): void => reject(signal.reason);
    if (signal.aborted) fail();
    else signal.addEventListener("abort", fail, { once: true });
  });
}

/** A `sleep` option that records the requested pauses (in ms) and returns at once. */
export function recordingSleep(): { sleep: (ms: number) => Promise<void>; pauses: number[] } {
  const pauses: number[] = [];
  return {
    pauses,
    sleep: (ms: number): Promise<void> => {
      pauses.push(ms);
      return Promise.resolve();
    },
  };
}

/** The query string of a recorded request as a plain object (repeated keys keep the last). */
export function queryOf(request: Recorded): Record<string, string> {
  const out: Record<string, string> = {};
  new URL(request.url).searchParams.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}
