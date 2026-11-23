import { describe, expect, it } from "vitest";
import { ApiError, NotFound, ValidationError } from "../src/index.js";
import { at, clientFor, queryOf, failure, ok, recordingSleep } from "./helpers.js";

const ENDPOINT = {
  id: "wh_1",
  url: "https://hooks.test/in",
  enabled: true,
  event_types: ["sandbox.*"],
  failure_count: 0,
  created_at: "2026-11-01T09:00:00+00:00",
};

const DELIVERY = {
  id: "dlv_1",
  endpoint_id: "wh_1",
  event_id: "evt_1",
  event_type: "sandbox.started",
  state: "failed",
  attempts: 2,
  next_attempt_at: null,
  last_status: 503,
  last_error: "http 503",
  payload_sha256: "ab".repeat(32),
  attempt_history: [
    { kind: "attempt", attempted_at: "2026-11-01T09:01:00+00:00", status: 503, duration_ms: 12 },
    { kind: "redelivered", attempted_at: "2026-11-01T09:02:00+00:00", actor_id: "key_1" },
  ],
  created_at: "2026-11-01T09:00:00+00:00",
  updated_at: "2026-11-01T09:02:00+00:00",
};

describe("webhooks.create", () => {
  it("posts the url and event types and returns the secret once", async () => {
    const { client, requests } = clientFor([ok({ ...ENDPOINT, secret: "whsec_abc" })]);

    const endpoint = await client.webhooks.create(ENDPOINT.url, ["sandbox.*"], { enabled: false });

    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe("http://sf.test/v1/webhooks");
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({
      url: ENDPOINT.url,
      event_types: ["sandbox.*"],
      enabled: false,
    });
    expect(endpoint.id).toBe("wh_1");
    expect(endpoint.eventTypes).toEqual(["sandbox.*"]);
    expect(endpoint.createdAt).toEqual(new Date("2026-11-01T09:00:00+00:00"));
    expect(endpoint.secret).toBe("whsec_abc");
  });

  it("keeps the secret out of JSON and string output", async () => {
    const { client } = clientFor([ok({ ...ENDPOINT, secret: "whsec_abc" })]);

    const endpoint = await client.webhooks.create(ENDPOINT.url, ["*"]);

    expect(JSON.stringify(endpoint)).not.toContain("whsec_abc");
    expect(Object.keys(endpoint)).not.toContain("secret");
  });

  it("omits enabled unless given", async () => {
    const { client, requests } = clientFor([ok(ENDPOINT)]);

    const endpoint = await client.webhooks.create(ENDPOINT.url, []);

    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({ url: ENDPOINT.url, event_types: [] });
    expect(endpoint.secret).toBeUndefined();
  });

  it("rejects a blank url, a lone string and a blank event before sending", async () => {
    const { client, requests } = clientFor([]);

    await expect(client.webhooks.create(" ", ["*"])).rejects.toBeInstanceOf(ValidationError);
    await expect(client.webhooks.create("u", "sandbox.*" as never)).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(client.webhooks.create("u", [" "])).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("never resends a create after a 503 CAPACITY", async () => {
    const { client, requests } = clientFor([failure(503, "CAPACITY"), ok(ENDPOINT)]);

    await expect(client.webhooks.create(ENDPOINT.url, ["*"])).rejects.toBeInstanceOf(ApiError);

    expect(requests).toHaveLength(1);
  });
});

describe("webhooks list, get, update, delete", () => {
  it("lists endpoints and retries a GET after a 429", async () => {
    const { sleep } = recordingSleep();
    const { client, requests } = clientFor(
      [failure(429, "RATE_LIMITED", { "Retry-After": "1" }), ok([ENDPOINT])],
      { sleep },
    );

    const endpoints = await client.webhooks.list();

    expect(endpoints.map((e) => e.id)).toEqual(["wh_1"]);
    expect(requests).toHaveLength(2);
  });

  it("gets one endpoint with the id percent-encoded", async () => {
    const { client, requests } = clientFor([ok(ENDPOINT)]);

    await client.webhooks.get("wh/1");

    expect(at(requests, 0).url).toBe("http://sf.test/v1/webhooks/wh%2F1");
  });

  it("maps a 404 to NotFound", async () => {
    const { client } = clientFor([failure(404, "NOT_FOUND")]);

    await expect(client.webhooks.get("wh_x")).rejects.toBeInstanceOf(NotFound);
  });

  it("patches only the given fields", async () => {
    const { client, requests } = clientFor([ok({ ...ENDPOINT, enabled: false })]);

    const endpoint = await client.webhooks.update("wh_1", { enabled: false });

    expect(at(requests, 0).method).toBe("PATCH");
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({ enabled: false });
    expect(endpoint.enabled).toBe(false);
  });

  it("refuses an update with nothing to change", async () => {
    const { client, requests } = clientFor([]);

    await expect(client.webhooks.update("wh_1", {})).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("deletes an endpoint and returns it as it was", async () => {
    const { client, requests } = clientFor([ok(ENDPOINT)]);

    const endpoint = await client.webhooks.delete("wh_1");

    expect(at(requests, 0).method).toBe("DELETE");
    expect(endpoint.url).toBe(ENDPOINT.url);
  });

  it("rejects a blank endpoint id", async () => {
    const { client } = clientFor([]);

    await expect(client.webhooks.get("")).rejects.toBeInstanceOf(ValidationError);
  });
});

describe("webhooks deliveries", () => {
  it("lists a page with filters and a cursor", async () => {
    const { client, requests } = clientFor([ok([DELIVERY], "next1")]);

    const page = await client.webhooks.deliveries("wh_1", {
      eventType: "sandbox.started",
      state: "failed",
      cursor: "c0",
      limit: 10,
    });

    const url = new URL(at(requests, 0).url);
    expect(url.pathname).toBe("/v1/webhooks/wh_1/deliveries");
    expect(queryOf(at(requests, 0))).toEqual({
      event_type: "sandbox.started",
      state: "failed",
      cursor: "c0",
      limit: "10",
    });
    expect(page.nextCursor).toBe("next1");
    const [delivery] = page.items;
    expect(delivery?.state).toBe("failed");
    expect(delivery?.lastStatus).toBe(503);
    expect(delivery?.attemptHistory).toHaveLength(2);
    expect(delivery?.attemptHistory[1]?.kind).toBe("redelivered");
    expect(delivery?.attemptHistory[1]?.actorId).toBe("key_1");
    expect(delivery?.attemptHistory[0]?.durationMs).toBe(12);
    expect(delivery?.nextAttemptAt).toBeNull();
  });

  it("follows the cursors in deliveriesAll, including an empty filtered page", async () => {
    const { client, requests } = clientFor([
      ok([DELIVERY], "c1"),
      ok([], "c2"),
      ok([{ ...DELIVERY, id: "dlv_2" }], null),
    ]);

    const ids: string[] = [];
    for await (const item of client.webhooks.deliveriesAll("wh_1", { state: "failed" })) {
      ids.push(item.id);
    }

    expect(ids).toEqual(["dlv_1", "dlv_2"]);
    const cursors = requests.map((r) => new URL(r.url).searchParams.get("cursor"));
    expect(cursors).toEqual([null, "c1", "c2"]);
    expect(requests.every((r) => new URL(r.url).searchParams.get("state") === "failed")).toBe(
      true,
    );
  });

  it("refuses a bad state or limit before sending", async () => {
    const { client, requests } = clientFor([]);

    await expect(
      client.webhooks.deliveries("wh_1", { state: "bogus" as never }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(client.webhooks.deliveries("wh_1", { limit: 0 })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(client.webhooks.deliveries("wh_1", { limit: 101 })).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(requests).toHaveLength(0);
  });

  it("gets one delivery", async () => {
    const { client, requests } = clientFor([ok(DELIVERY)]);

    const delivery = await client.webhooks.getDelivery("wh_1", "dlv_1");

    expect(at(requests, 0).url).toBe("http://sf.test/v1/webhooks/wh_1/deliveries/dlv_1");
    expect(delivery.payloadSha256).toBe("ab".repeat(32));
  });

  it("requeues a delivery with a POST that is never resent", async () => {
    const { client, requests } = clientFor([failure(503, "CAPACITY"), ok(DELIVERY)]);

    await expect(client.webhooks.redeliver("wh_1", "dlv_1")).rejects.toBeInstanceOf(ApiError);

    expect(requests).toHaveLength(1);
    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe(
      "http://sf.test/v1/webhooks/wh_1/deliveries/dlv_1/redeliver",
    );
  });

  it("returns the requeued delivery", async () => {
    const { client } = clientFor([ok({ ...DELIVERY, state: "pending" })]);

    expect((await client.webhooks.redeliver("wh_1", "dlv_1")).state).toBe("pending");
  });
});
