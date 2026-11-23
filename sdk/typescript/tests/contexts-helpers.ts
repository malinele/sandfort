import type { CodeContextEvent, Sandbox } from "../src/index.js";
import { clientFor, ok, sandboxPayload, type QueueItem, type Recorded } from "./helpers.js";

export const TOOLBOX = "http://sf.test/v1/sandboxes/sbx_1/toolbox/";
export const BASE = `${TOOLBOX}code-contexts`;


export function contextPayload(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { id: "ctx_0123456789abcdef", cwd: "/workspace", language: "python", ...extra };
}

export function cellPayload(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    exit_code: 0,
    stdout: "42\n",
    stderr: "",
    timed_out: false,
    truncated: false,
    duration_ms: 7,
    sandbox_stopped: false,
    stop_reason: null,
    result: "42",
    error: null,
    ...extra,
  };
}

export function created(data: unknown): Response {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 201,
    headers: { "content-type": "application/json" },
  });
}

export interface SseOptions {
  status?: number;
  onCancel?: () => void;
}

/** A server-sent-events answer that delivers `chunks` one by one. */
export function sse(chunks: readonly string[], options: SseOptions = {}): Response {
  const encoder = new TextEncoder();
  let next = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      const chunk = chunks[next];
      next += 1;
      if (chunk === undefined) controller.close();
      else controller.enqueue(encoder.encode(chunk));
    },
    cancel() {
      options.onCancel?.();
    },
  });
  return new Response(body, {
    status: options.status ?? 200,
    headers: { "content-type": "text/event-stream" },
  });
}

export function frame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

export async function started(
  replies: QueueItem[],
): Promise<{ sandbox: Sandbox; requests: Recorded[] }> {
  const { client, requests } = clientFor([ok(sandboxPayload()), ...replies]);
  return { sandbox: await client.getSandbox("sbx_1"), requests };
}

export async function collect(
  events: AsyncIterable<CodeContextEvent>,
): Promise<CodeContextEvent[]> {
  const seen: CodeContextEvent[] = [];
  for await (const event of events) seen.push(event);
  return seen;
}
