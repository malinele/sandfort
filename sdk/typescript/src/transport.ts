import { USER_AGENT } from "./version.js";
import { InvalidResponseError, ValidationError, withRequestId } from "./errors.js";
import { isRecord, parseJson, replyError } from "./reply.js";
import { rememberStreamSignal } from "./stream-failure.js";
import {
  resolvePolicy,
  retryHint,
  withCallOptions,
  withResilience,
  type CallOptions,
  type ResiliencePolicy,
  type ResilienceOptions,
} from "./resilience.js";

/** The subset of `fetch` the transport needs; `globalThis.fetch` satisfies it. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** `null` and `undefined` mean "not set" and never reach the url. */
export type QueryValue = string | number | boolean | readonly string[] | null | undefined;
export type Query = Readonly<Record<string, QueryValue>>;

export interface RequestOptions extends CallOptions {
  json?: unknown;
  query?: Query;
  /** Extra headers, e.g. `Idempotency-Key`. */
  headers?: Readonly<Record<string, string>>;
  /** Raise the timeout for this request above the client's `timeoutMs` (never lowers it). */
  minTimeoutMs?: number | undefined;
}

export interface Envelope {
  data: unknown;
  nextCursor: string | null;
  /** HTTP status of the reply (200 and 201 both carry a success envelope). */
  status: number;
}

export interface TransportOptions extends ResilienceOptions {
  baseUrl: string;
  apiKey: string;
  fetch?: FetchLike;
}

/** Serialize a query; unset (`null`/`undefined`) and unsupported values are dropped, never thrown on. */
export function buildQuery(query: Query | undefined): string {
  if (query === undefined) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) params.append(key, String(item));
    } else if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      params.append(key, String(value));
    }
  }
  const text = params.toString();
  return text === "" ? "" : `?${text}`;
}

/** The head of a stream reply: `text` is the whole body of a non-2xx one, else `undefined`. */
interface StreamHead {
  response: Response;
  text: string | undefined;
}

function parseEnvelope(body: unknown, response: Response): Envelope {
  if (isRecord(body) && "success" in body) {
    if (body["success"] === true) {
      const meta = body["meta"];
      const cursor = isRecord(meta) ? meta["next_cursor"] : undefined;
      if (cursor === "") {
        const message = "the reply has an empty 'next_cursor'";
        throw new InvalidResponseError(
          withRequestId(message, response.headers.get("x-request-id")),
        );
      }
      return {
        data: body["data"],
        nextCursor: typeof cursor === "string" ? cursor : null,
        status: response.status,
      };
    }
    throw replyError(body, response);
  }
  if (!response.ok) throw replyError(body, response);
  throw new InvalidResponseError("response is not a Sandfort envelope");
}

const EVENT_STREAM_TYPE = "text/event-stream";

/** A 2xx stream reply must have the media type asked for; any other is released and refused. */
function requireStreamType(response: Response, expected: string): void {
  const header = response.headers.get("content-type");
  const type = header?.split(";")[0]?.trim().toLowerCase() ?? "";
  if (type === expected) return;
  void response.body?.cancel().catch(() => undefined);
  const found = header === null ? "no content-type" : `content-type '${type}'`;
  const message = `expected a ${expected} reply, got ${found}`;
  throw new InvalidResponseError(withRequestId(message, response.headers.get("x-request-id")));
}

export class Transport {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly fetchImpl: FetchLike;
  private readonly policy: ResiliencePolicy;

  constructor(options: TransportOptions) {
    if (options.baseUrl === "") throw new ValidationError("baseUrl must not be empty");
    if (options.apiKey === "") throw new ValidationError("apiKey must not be empty");
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.policy = resolvePolicy(options);
  }

  /** Send a request and return the unwrapped `data` of the success envelope. */
  async request(method: string, path: string, options: RequestOptions = {}): Promise<unknown> {
    return (await this.requestEnvelope(method, path, options)).data;
  }

  /** Like `request`, but also returns `meta.next_cursor` for paginated routes. */
  async requestEnvelope(
    method: string,
    path: string,
    options: RequestOptions = {},
  ): Promise<Envelope> {
    const url = `${this.baseUrl}${path}${buildQuery(options.query)}`;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      Accept: "application/json",
      "User-Agent": USER_AGENT,
      ...options.headers,
    };
    const init: RequestInit = { method, headers };
    if (options.json !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.json);
    }
    const { response, text } = await withResilience({
      policy: withCallOptions(this.policy, options),
      method,
      path,
      headers,
      signal: options.signal,
      minTimeoutMs: options.minTimeoutMs,
      run: async (signal) => {
        const reply = await this.fetchImpl(url, { ...init, signal });
        const replyText = await reply.text();
        return {
          value: { response: reply, text: replyText },
          hint: retryHint(reply.status, replyText, reply.headers),
        };
      },
    });
    return parseEnvelope(parseJson(text), response);
  }

  /**
   * Send a request and hand back the live response of a server-sent-events route. Only the
   * wait for the response head runs inside the resilience wrapper; the per-call timeout
   * (raised to `minTimeoutMs`) keeps bounding the body while it is read. A non-2xx reply
   * is read in full and raised as its typed error. `mediaType` is the stream's content type:
   * it is sent as `Accept` and a 2xx reply of another type is refused.
   */
  async openStream(
    method: string,
    path: string,
    options: RequestOptions = {},
    mediaType: string = EVENT_STREAM_TYPE,
  ): Promise<Response> {
    const url = `${this.baseUrl}${path}${buildQuery(options.query)}`;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      Accept: mediaType,
      "User-Agent": USER_AGENT,
      ...options.headers,
    };
    const init: RequestInit = { method, headers };
    if (options.json !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.json);
    }
    const { response, text } = await withResilience<StreamHead>({
      policy: withCallOptions(this.policy, options),
      method,
      path,
      headers,
      signal: options.signal,
      minTimeoutMs: options.minTimeoutMs,
      run: async (signal) => {
        const reply = await this.fetchImpl(url, { ...init, signal });
        rememberStreamSignal(reply, signal);
        if (reply.ok) return { value: { response: reply, text: undefined } };
        const replyText = await reply.text();
        return {
          value: { response: reply, text: replyText },
          hint: retryHint(reply.status, replyText, reply.headers),
        };
      },
    });
    if (text !== undefined) throw replyError(parseJson(text), response);
    requireStreamType(response, mediaType);
    return response;
  }
}
