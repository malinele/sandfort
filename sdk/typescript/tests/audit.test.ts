import { describe, expect, it } from "vitest";
import {
  InvalidResponseError,
  NotFound,
  RequestAbortedError,
  TransportError,
  ValidationError,
} from "../src/index.js";
import { at, clientFor, queryOf, failure, ok, recordingSleep, type QueueItem } from "./helpers.js";

const EVENT = {
  id: "aud_1",
  org_id: "org_1",
  actor_type: "api_key",
  actor_id: "key_1",
  action: "sandbox.create",
  target_type: "sandbox",
  target_id: "sbx_1",
  request_id: "req_1",
  outcome: "success",
  occurred_at: "2026-11-01T09:00:00+00:00",
  ip: "10.0.0.1",
  user_agent: "sdk",
  details: { image: "python" },
};

const VERIFY = {
  ok: false,
  checked: 7,
  first_id: "aud_1",
  last_id: "aud_7",
  last_hash: "h7",
  findings: [{ kind: "link_broken", event_id: "aud_4", detail: "prev_hash differs" }],
  findings_truncated: false,
  anchor_id: "aud_2",
  acknowledged_findings: 1,
};

const FROM = new Date("2026-11-01T00:00:00Z");
const TO = new Date("2026-11-02T00:00:00Z");

function ndjson(chunks: (string | Uint8Array)[], contentType = "application/x-ndjson"): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(typeof chunk === "string" ? encoder.encode(chunk) : chunk);
      }
      controller.close();
    },
  });
  return new Response(body, { status: 200, headers: { "content-type": contentType } });
}

async function collect<T>(lines: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const line of lines) out.push(line);
  return out;
}

describe("audit.list", () => {
  it("maps the filters to the query and parses the events", async () => {
    const { client, requests } = clientFor([ok([EVENT], "n1")]);

    const page = await client.audit.list({
      actorId: "key_1",
      action: "sandbox.create",
      targetId: "sbx_1",
      requestId: "req_1",
      outcome: "success",
      from: FROM,
      to: TO,
      order: "desc",
      cursor: "c0",
      limit: 25,
    });

    const url = new URL(at(requests, 0).url);
    expect(url.pathname).toBe("/v1/audit-events");
    expect(queryOf(at(requests, 0))).toEqual({
      actor_id: "key_1",
      action: "sandbox.create",
      target_id: "sbx_1",
      request_id: "req_1",
      outcome: "success",
      from: "2026-11-01T00:00:00.000Z",
      to: "2026-11-02T00:00:00.000Z",
      order: "desc",
      cursor: "c0",
      limit: "25",
    });
    expect(page.nextCursor).toBe("n1");
    expect(page.items[0]).toMatchObject({
      id: "aud_1",
      orgId: "org_1",
      actorType: "api_key",
      actorId: "key_1",
      action: "sandbox.create",
      targetType: "sandbox",
      targetId: "sbx_1",
      requestId: "req_1",
      outcome: "success",
      ip: "10.0.0.1",
      userAgent: "sdk",
      details: { image: "python" },
    });
    expect(page.items[0]?.occurredAt).toEqual(new Date("2026-11-01T09:00:00+00:00"));
  });

  it("sends no query by default and fills the optional fields with null", async () => {
    const minimal = {
      id: "a",
      org_id: "o",
      actor_type: "system",
      action: "x",
      occurred_at: "2026-11-01T09:00:00Z",
    };
    const { client, requests } = clientFor([ok([minimal], null)]);

    const page = await client.audit.list();

    expect(new URL(at(requests, 0).url).search).toBe("");
    expect(page.nextCursor).toBeNull();
    expect(page.items[0]).toMatchObject({ outcome: "success", actorId: null, details: {} });
  });

  it("refuses bad arguments before sending", async () => {
    const { client, requests } = clientFor([]);
    const bad = [
      client.audit.list({ order: "up" as never }),
      client.audit.list({ limit: 0 }),
      client.audit.list({ limit: 101 }),
      client.audit.list({ actorId: " " }),
      client.audit.list({ from: new Date("x") }),
      client.audit.list({ outcome: "" }),
    ];

    for (const call of bad) await expect(call).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("listAll follows the cursors with the same filters", async () => {
    const { client, requests } = clientFor([
      ok([EVENT], "c1"),
      ok([{ ...EVENT, id: "aud_2" }], null),
    ]);

    const ids: string[] = [];
    for await (const event of client.audit.listAll({ action: "sandbox.create", order: "desc" })) {
      ids.push(event.id);
    }

    expect(ids).toEqual(["aud_1", "aud_2"]);
    const second = new URL(at(requests, 1).url).searchParams;
    expect(second.get("cursor")).toBe("c1");
    expect(second.get("action")).toBe("sandbox.create");
    expect(second.get("order")).toBe("desc");
  });

  it("listAll refuses a repeated cursor", async () => {
    const { client } = clientFor([ok([EVENT], "c1"), ok([EVENT], "c1"), ok([EVENT], "c1")]);

    await expect(collect(client.audit.listAll())).rejects.toBeInstanceOf(InvalidResponseError);
  });
});

describe("audit.verifyChain", () => {
  it("returns the server-side verdict with its findings", async () => {
    const { client, requests } = clientFor([ok(VERIFY)]);

    const result = await client.audit.verifyChain({ fromId: "aud_2" });

    const url = new URL(at(requests, 0).url);
    expect(url.pathname).toBe("/v1/audit-events/verify");
    expect(url.searchParams.get("from_id")).toBe("aud_2");
    expect(result).toMatchObject({
      ok: false,
      checked: 7,
      firstId: "aud_1",
      lastId: "aud_7",
      lastHash: "h7",
      findingsTruncated: false,
      anchorId: "aud_2",
      acknowledgedFindings: 1,
      reanchoredBy: null,
      reanchor: null,
    });
    expect(result.findings).toEqual([
      { kind: "link_broken", eventId: "aud_4", detail: "prev_hash differs" },
    ]);
  });

  it("walks the whole chain without options and accepts an empty org", async () => {
    const empty = {
      ok: true,
      checked: 0,
      first_id: null,
      last_id: null,
      last_hash: null,
      findings: [],
      findings_truncated: false,
    };
    const { client, requests } = clientFor([ok(empty)]);

    const result = await client.audit.verifyChain();

    expect(new URL(at(requests, 0).url).search).toBe("");
    expect(result).toMatchObject({ ok: true, firstId: null, anchorId: null });
    expect(result.acknowledgedFindings).toBe(0);
  });

  it("parses a re-anchor and refuses a blank fromId", async () => {
    const anchor = {
      event_id: "aud_9",
      acknowledged_through: "aud_8",
      occurred_at: "2026-11-05T00:00:00Z",
      operator: "ops",
      reason_code: "restore",
      note: "after restore",
      findings: 3,
    };
    const { client } = clientFor([ok({ ...VERIFY, reanchor: anchor, reanchored_by: "aud_9" })]);

    const result = await client.audit.verifyChain();

    expect(result.reanchoredBy).toBe("aud_9");
    expect(result.reanchor).toMatchObject({
      eventId: "aud_9",
      acknowledgedThrough: "aud_8",
      operator: "ops",
      reasonCode: "restore",
      note: "after restore",
      findings: 3,
    });
    await expect(client.audit.verifyChain({ fromId: " " })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });
});

describe("audit.exportLines", () => {
  it("yields each line with its newline, whatever the chunking", async () => {
    const { client, requests } = clientFor([
      ndjson(['{"id":"a"}\n{"id', '":"b"}\n', '{"type":"audit_head"}']),
    ]);

    const lines = await collect(client.audit.exportLines({ outcome: "denied", from: FROM }));

    expect(lines).toEqual(['{"id":"a"}\n', '{"id":"b"}\n', '{"type":"audit_head"}']);
    const request = at(requests, 0);
    expect(new URL(request.url).pathname).toBe("/v1/audit-events/export");
    expect(new URL(request.url).searchParams.get("outcome")).toBe("denied");
    expect(new URL(request.url).searchParams.get("from")).toBe("2026-11-01T00:00:00.000Z");
    expect(request.headers.get("accept")).toBe("application/x-ndjson");
  });

  it("decodes a multi-byte character split across chunks", async () => {
    const bytes = new TextEncoder().encode('{"n":"Šđ"}\n');
    const cut = bytes.indexOf(0xc5) + 1;
    const { client } = clientFor([ndjson([bytes.slice(0, cut), bytes.slice(cut)])]);

    expect(await collect(client.audit.exportLines())).toEqual(['{"n":"Šđ"}\n']);
  });

  it("yields nothing for an empty body", async () => {
    const { client } = clientFor([ndjson([])]);

    expect(await collect(client.audit.exportLines())).toEqual([]);
  });

  it("checks the filters at once and sends the request on the first read", async () => {
    const { client, requests } = clientFor([ndjson(["x\n"])]);

    expect(() => client.audit.exportLines({ requestId: " " })).toThrow(ValidationError);
    expect(() => client.audit.exportLines({ to: new Date("x") })).toThrow(ValidationError);
    const lines = client.audit.exportLines();
    expect(requests).toHaveLength(0);
    await collect(lines);
    expect(requests).toHaveLength(1);
  });

  it("raises the typed error of a failed export", async () => {
    const { client } = clientFor([failure(404, "NOT_FOUND")]);

    await expect(collect(client.audit.exportLines())).rejects.toBeInstanceOf(NotFound);
  });

  it("retries the GET after a 429 before the stream opens", async () => {
    const { sleep } = recordingSleep();
    const queue: QueueItem[] = [failure(429, "RATE_LIMITED"), ndjson(["a\n"])];
    const { client, requests } = clientFor(queue, { sleep });

    expect(await collect(client.audit.exportLines())).toEqual(["a\n"]);
    expect(requests).toHaveLength(2);
  });

  it("refuses a reply that is not newline-delimited JSON", async () => {
    const { client } = clientFor([ndjson(["{}"], "text/html")]);

    await expect(collect(client.audit.exportLines())).rejects.toBeInstanceOf(
      InvalidResponseError,
    );
  });

  it("raises TransportError when the body breaks mid-stream", async () => {
    const broken = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("a\n"));
      },
      pull(controller) {
        controller.error(new Error("socket reset"));
      },
    });
    const response = new Response(broken, {
      status: 200,
      headers: { "content-type": "application/x-ndjson" },
    });
    const { client } = clientFor([response]);
    const seen: string[] = [];

    const outcome = (async (): Promise<void> => {
      for await (const line of client.audit.exportLines()) seen.push(line);
    })();

    await expect(outcome).rejects.toBeInstanceOf(TransportError);
    expect(seen).toEqual(["a\n"]);
  });

  it("stops with RequestAbortedError when the caller aborts mid-stream", async () => {
    const controller = new AbortController();
    const { client } = clientFor([ndjson(["a\n", "b\n"])]);
    const seen: string[] = [];

    const outcome = (async (): Promise<void> => {
      for await (const line of client.audit.exportLines({ signal: controller.signal })) {
        seen.push(line);
        controller.abort();
      }
    })();

    await expect(outcome).rejects.toBeInstanceOf(RequestAbortedError);
    expect(seen).toEqual(["a\n"]);
  });
});
