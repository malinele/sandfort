import { describe, expect, it } from "vitest";
import {
  ApiError,
  Conflict,
  Forbidden,
  InvalidResponseError,
  InvalidState,
  NotFound,
  RateLimited,
  SandfortError,
  TransportError,
  Unauthorized,
  ValidationFailed,
  type FetchLike,
} from "../src/index.js";
import { Transport } from "../src/transport.js";

interface Recorded {
  url: string;
  method: string;
  headers: Headers;
  body: string | undefined;
}

function stub(queue: Response[]): { fetch: FetchLike; requests: Recorded[] } {
  const requests: Recorded[] = [];
  const fetch: FetchLike = async (input, init) => {
    requests.push({
      url: input,
      method: init.method ?? "GET",
      headers: new Headers(init.headers),
      body: typeof init.body === "string" ? init.body : undefined,
    });
    const next = queue.shift();
    if (next === undefined) throw new Error("no queued response");
    return next;
  };
  return { fetch, requests };
}

function reply(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function errorEnvelope(code: string, message = "boom"): unknown {
  return {
    success: false,
    data: null,
    error: { code, message, details: { field: "name" }, request_id: "req_1" },
  };
}

/** Error-mapping tests turn retries off: a 429 or 503 on a GET would otherwise be resent. */
function transportFor(queue: Response[]): { transport: Transport; requests: Recorded[] } {
  const { fetch, requests } = stub(queue);
  const transport = new Transport({ baseUrl: "http://sf.test/", apiKey: "sf_key", fetch, retries: 0 });
  return { transport, requests };
}

function first(requests: Recorded[]): Recorded {
  const item = requests[0];
  if (item === undefined) throw new Error("no request recorded");
  return item;
}

describe("Transport requests", () => {
  it("sends the bearer header and a json body", async () => {
    const { transport, requests } = transportFor([reply(200, { success: true, data: { ok: 1 } })]);

    await transport.request("POST", "/v1/things", { json: { a: 1 } });

    const sent = first(requests);
    expect(sent.url).toBe("http://sf.test/v1/things");
    expect(sent.method).toBe("POST");
    expect(sent.headers.get("authorization")).toBe("Bearer sf_key");
    expect(sent.headers.get("content-type")).toBe("application/json");
    expect(sent.body).toBe('{"a":1}');
  });

  it("omits body and content type when there is no json", async () => {
    const { transport, requests } = transportFor([reply(200, { success: true, data: null })]);

    await transport.request("GET", "/v1/things");

    const sent = first(requests);
    expect(sent.body).toBeUndefined();
    expect(sent.headers.get("content-type")).toBeNull();
  });

  it("appends the query, repeating array values and skipping undefined", async () => {
    const { transport, requests } = transportFor([reply(200, { success: true, data: [] })]);

    await transport.request("GET", "/v1/things", {
      query: { state: "started", skip: undefined, label: ["a=1", "b=2"], limit: 5 },
    });

    expect(first(requests).url).toBe(
      "http://sf.test/v1/things?state=started&label=a%3D1&label=b%3D2&limit=5",
    );
  });

  it("unwraps the success envelope and returns its data", async () => {
    const { transport } = transportFor([reply(200, { success: true, data: { id: "x" } })]);

    await expect(transport.request("GET", "/v1/things/x")).resolves.toEqual({ id: "x" });
  });

  it("returns next_cursor from the envelope meta", async () => {
    const { transport } = transportFor([
      reply(200, { success: true, data: [], meta: { next_cursor: "c9" } }),
    ]);

    const envelope = await transport.requestEnvelope("GET", "/v1/things");

    expect(envelope.nextCursor).toBe("c9");
  });
});

describe("Transport errors", () => {
  const cases: ReadonlyArray<readonly [number, string, new (...args: never[]) => ApiError]> = [
    [400, "VALIDATION_ERROR", ValidationFailed],
    [401, "UNAUTHORIZED", Unauthorized],
    [403, "FORBIDDEN", Forbidden],
    [404, "NOT_FOUND", NotFound],
    [409, "CONFLICT", Conflict],
    [409, "INVALID_STATE", InvalidState],
    [422, "UNPROCESSABLE", ValidationFailed],
    [429, "RATE_LIMITED", RateLimited],
  ];

  it.each(cases)("maps %i %s to the matching subclass", async (status, code, cls) => {
    const { transport } = transportFor([reply(status, errorEnvelope(code))]);

    const error = await transport.request("GET", "/v1/x").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(cls);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toBeInstanceOf(SandfortError);
  });

  it("carries status, code, message, details and request id from the envelope", async () => {
    const { transport } = transportFor([reply(404, errorEnvelope("NOT_FOUND", "no such sandbox"))]);

    const error = await transport.request("GET", "/v1/x").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(NotFound);
    const api = error as ApiError;
    expect(api.status).toBe(404);
    expect(api.code).toBe("NOT_FOUND");
    expect(api.message).toBe("no such sandbox");
    expect(api.details).toEqual({ field: "name" });
    expect(api.requestId).toBe("req_1");
  });

  it("falls back to the status when the code is unknown", async () => {
    const { transport } = transportFor([reply(403, errorEnvelope("SOMETHING_NEW"))]);

    const error = await transport.request("GET", "/v1/x").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(Forbidden);
    expect((error as ApiError).code).toBe("SOMETHING_NEW");
  });

  it("uses a plain ApiError for an unknown code and status", async () => {
    const { transport } = transportFor([reply(503, errorEnvelope("CAPACITY"))]);

    const error = await transport.request("GET", "/v1/x").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).constructor).toBe(ApiError);
  });

  it("reads Retry-After into RateLimited", async () => {
    const { transport } = transportFor([
      reply(429, errorEnvelope("RATE_LIMITED"), { "Retry-After": "7" }),
    ]);

    const error = await transport.request("GET", "/v1/x").catch((e: unknown) => e);

    expect((error as RateLimited).retryAfterS).toBe(7);
  });

  it("maps a non-json error response by status", async () => {
    const { transport } = transportFor([new Response("<html>bad gateway</html>", { status: 404 })]);

    const error = await transport.request("GET", "/v1/x").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(NotFound);
    expect((error as ApiError).code).toBe("HTTP_404");
  });

  it("rejects a non-json success response", async () => {
    const { transport } = transportFor([new Response("plain text", { status: 200 })]);

    await expect(transport.request("GET", "/v1/x")).rejects.toBeInstanceOf(InvalidResponseError);
  });

  it("wraps network failures in TransportError", async () => {
    const failing: FetchLike = () => Promise.reject(new TypeError("fetch failed"));
    const transport = new Transport({ baseUrl: "http://sf.test", apiKey: "k", fetch: failing });

    await expect(transport.request("GET", "/v1/x")).rejects.toBeInstanceOf(TransportError);
  });
});
