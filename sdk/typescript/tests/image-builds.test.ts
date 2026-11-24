import { describe, expect, it } from "vitest";
import specFile from "../../../openapi/sandfort.v1.json";
import {
  Image,
  InvalidResponseError,
  NotFound,
  TransportError,
  ValidationError,
  ValidationFailed,
  type BuildLogEvent,
} from "../src/index.js";
import { frame, sse } from "./contexts-helpers.js";
import { at, clientFor, failure, ok } from "./helpers.js";

type Json = Record<string, unknown>;

const SPEC_PATH = "/v1/images/builds";
const LOGS_PATH = (id: string): string => `${SPEC_PATH}/${id}/logs`;

function record(value: unknown, what: string): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${what} is not an object in the spec`);
  }
  return value as Json;
}

const paths = record(record(specFile, "spec")["paths"], "paths");
const schemas = record(record(record(specFile, "spec")["components"], "components")["schemas"], "schemas");

function snapshot(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "snap_b1",
    name: "img-1",
    state: "pending",
    image_ref: "sandfort-snapshot:snap_b1",
    layer_count: 3,
    created_at: "2026-11-24T10:00:00+00:00",
    digest: null,
    source_sandbox_id: null,
    spec_hash: "abc123",
    reused: false,
    labels: {},
    ...extra,
  };
}

function accepted(data: unknown): Response {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 202,
    headers: { "content-type": "application/json" },
  });
}

function logFrame(line: string, index: number): string {
  return `id: ${index}\nevent: log\ndata: ${JSON.stringify({ line })}\n\n`;
}

async function collect(events: AsyncIterable<BuildLogEvent>): Promise<BuildLogEvent[]> {
  const seen: BuildLogEvent[] = [];
  for await (const event of events) seen.push(event);
  return seen;
}

describe("the OpenAPI spec still has the surface the SDK maps to", () => {
  it("declares POST /v1/images/builds and GET /v1/images/builds/{snapshot_id}/logs", () => {
    const build = record(record(paths[SPEC_PATH], "builds path")["post"], "post");
    const logs = record(
      record(paths[`${SPEC_PATH}/{snapshot_id}/logs`], "logs path")["get"],
      "get",
    );
    expect(build["operationId"]).toBe("build_image");
    expect(logs["operationId"]).toBe("stream_build_logs");
    expect(Object.keys(record(logs["responses"], "responses"))).toContain("200");
  });

  it("sends only keys BuildImageRequest allows, with spec required", () => {
    const request = record(schemas["BuildImageRequest"], "BuildImageRequest");
    const allowed = Object.keys(record(request["properties"], "properties"));
    expect(request["required"]).toEqual(["spec"]);
    expect(request["additionalProperties"]).toBe(false);
    expect(allowed.sort()).toEqual(["name", "spec"]);
  });

  it("reads every BuildImageResponse field the snapshot model uses", () => {
    const response = record(schemas["BuildImageResponse"], "BuildImageResponse");
    const fields = Object.keys(record(response["properties"], "properties"));
    for (const field of ["id", "name", "state", "image_ref", "layer_count", "spec_hash", "reused"]) {
      expect(fields).toContain(field);
    }
  });
});

describe("buildSnapshot", () => {
  it("posts the serialized Image under spec and parses the pending snapshot (202)", async () => {
    const { client, requests } = clientFor([accepted(snapshot())]);
    const image = Image.debianSlim().pipInstall("requests").workdir("/app");

    const info = await client.buildSnapshot(image);

    const sent = at(requests, 0);
    expect(sent.method).toBe("POST");
    expect(sent.url).toBe(`http://sf.test${SPEC_PATH}`);
    expect(sent.body).toBe(JSON.stringify({ spec: image.serialize() }));
    expect(info.id).toBe("snap_b1");
    expect(info.state).toBe("pending");
    expect(info.specHash).toBe("abc123");
    expect(info.reused).toBe(false);
    expect(requests).toHaveLength(1);
  });

  it("sends the name when given and leaves it out otherwise", async () => {
    const { client, requests } = clientFor([accepted(snapshot()), accepted(snapshot())]);
    const image = Image.fromImage("alpine:3.20");

    await client.buildSnapshot(image, { name: "my-image" });
    await client.buildSnapshot(image);

    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({
      spec: image.serialize(),
      name: "my-image",
    });
    expect(Object.keys(JSON.parse(at(requests, 1).body ?? "") as Json)).toEqual(["spec"]);
  });

  it("passes a raw wire-form spec through unchanged", async () => {
    const { client, requests } = clientFor([accepted(snapshot())]);
    const raw = { schema_version: "1", base_image: "alpine:3.20", pip_packages: ["x"] };

    await client.buildSnapshot(raw);

    expect(at(requests, 0).body).toBe(JSON.stringify({ spec: raw }));
  });

  it("reports a reused build (200, ready, reused true)", async () => {
    const { client } = clientFor([
      ok(snapshot({ state: "ready", reused: true, digest: "sha256:abc" })),
    ]);

    const info = await client.buildSnapshot(Image.debianSlim());

    expect(info.state).toBe("ready");
    expect(info.reused).toBe(true);
    expect(info.digest).toBe("sha256:abc");
  });

  it("raises ValidationFailed when the API refuses the spec (422)", async () => {
    const { client } = clientFor([failure(422, "VALIDATION_ERROR", {}, "bad spec")]);

    await expect(client.buildSnapshot(Image.debianSlim())).rejects.toBeInstanceOf(
      ValidationFailed,
    );
  });

  it("rejects a non-object spec before sending anything", async () => {
    const { client, requests } = clientFor([]);

    await expect(client.buildSnapshot(null as unknown as Image)).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(client.buildSnapshot([] as unknown as Image)).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(requests).toHaveLength(0);
  });

  it("raises InvalidResponseError when the answer is not a snapshot", async () => {
    const { client } = clientFor([accepted({ id: "snap_b1" })]);

    await expect(client.buildSnapshot(Image.debianSlim())).rejects.toBeInstanceOf(
      InvalidResponseError,
    );
  });
});

describe("followBuildLogs", () => {
  it("yields log lines then the final state event and stops", async () => {
    const { client, requests } = clientFor([
      sse([
        ": keepalive\n\n",
        logFrame("Step 1/3 : FROM python:3.12-slim", 0),
        logFrame("Step 2/3 : RUN pip install requests", 1),
        frame("state", { state: "ready", snapshot_id: "snap_b1", digest: "sha256:abc", reason: null }),
        logFrame("never seen", 2),
      ]),
    ]);

    const events = await collect(client.followBuildLogs("snap_b1"));

    expect(events).toEqual([
      { type: "log", line: "Step 1/3 : FROM python:3.12-slim", index: 0 },
      { type: "log", line: "Step 2/3 : RUN pip install requests", index: 1 },
      {
        type: "state",
        state: "ready",
        snapshotId: "snap_b1",
        digest: "sha256:abc",
        reason: null,
        succeeded: true,
      },
    ]);
    expect(at(requests, 0).method).toBe("GET");
    expect(at(requests, 0).url).toBe(`http://sf.test${LOGS_PATH("snap_b1")}`);
    expect(at(requests, 0).headers.get("accept")).toBe("text/event-stream");
  });

  it("marks a failed build as not succeeded and keeps the reason", async () => {
    const { client } = clientFor([
      sse([
        frame("state", { state: "error", snapshot_id: "snap_b1", digest: null, reason: "boom" }),
      ]),
    ]);

    const events = await collect(client.followBuildLogs("snap_b1"));

    expect(events).toEqual([
      {
        type: "state",
        state: "error",
        snapshotId: "snap_b1",
        digest: null,
        reason: "boom",
        succeeded: false,
      },
    ]);
  });

  it("leaves the index null for a log event without an id and ignores other event types", async () => {
    const { client } = clientFor([
      sse([
        frame("log", { line: "plain" }),
        frame("progress", { pct: 50 }),
        frame("state", { state: "ready" }),
      ]),
    ]);

    const events = await collect(client.followBuildLogs("snap_b1"));

    expect(events[0]).toEqual({ type: "log", line: "plain", index: null });
    expect(events[1]).toMatchObject({ type: "state", snapshotId: null, digest: null, reason: null });
    expect(events).toHaveLength(2);
  });

  it("decodes frames split across chunks", async () => {
    const whole = logFrame("hello", 0);
    const { client } = clientFor([
      sse([whole.slice(0, 11), whole.slice(11), frame("state", { state: "ready" })]),
    ]);

    const events = await collect(client.followBuildLogs("snap_b1"));

    expect(events[0]).toEqual({ type: "log", line: "hello", index: 0 });
  });

  it("raises TransportError when the stream ends before the state event", async () => {
    const { client } = clientFor([sse([logFrame("only line", 0)])]);

    const seen: BuildLogEvent[] = [];
    const run = (async () => {
      for await (const event of client.followBuildLogs("snap_b1")) seen.push(event);
    })();

    await expect(run).rejects.toBeInstanceOf(TransportError);
    await expect(run).rejects.toThrow(/before the final state event/);
    expect(seen).toEqual([{ type: "log", line: "only line", index: 0 }]);
  });

  it("raises InvalidResponseError for malformed events", async () => {
    const cases: string[] = [
      "event: log\ndata: not json\n\n",
      frame("log", { line: 5 }),
      frame("log", {}),
      frame("state", {}),
      `id: abc\n${frame("log", { line: "x" })}`,
    ];
    for (const chunk of cases) {
      const { client } = clientFor([sse([chunk])]);
      await expect(collect(client.followBuildLogs("snap_b1"))).rejects.toBeInstanceOf(
        InvalidResponseError,
      );
    }
  });

  it("encodes the snapshot id in the path", async () => {
    const { client, requests } = clientFor([sse([frame("state", { state: "ready" })])]);

    await collect(client.followBuildLogs("a/b c"));

    expect(at(requests, 0).url).toBe(`http://sf.test${SPEC_PATH}/a%2Fb%20c/logs`);
  });

  it("raises a blank id as ValidationError on the first read, before sending", async () => {
    const { client, requests } = clientFor([]);

    await expect(collect(client.followBuildLogs("  "))).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("raises the typed API error for a non-2xx answer (404)", async () => {
    const { client } = clientFor([failure(404, "NOT_FOUND")]);

    await expect(collect(client.followBuildLogs("snap_x"))).rejects.toBeInstanceOf(NotFound);
  });

  it("refuses a 2xx reply that is not an event stream", async () => {
    const { client } = clientFor([ok({})]);

    await expect(collect(client.followBuildLogs("snap_b1"))).rejects.toBeInstanceOf(
      InvalidResponseError,
    );
  });

  it("releases the response when the consumer stops early", async () => {
    let cancelled = false;
    const { client } = clientFor([
      sse([logFrame("a", 0), logFrame("b", 1), frame("state", { state: "ready" })], {
        onCancel: () => {
          cancelled = true;
        },
      }),
    ]);

    for await (const event of client.followBuildLogs("snap_b1")) {
      expect(event.type).toBe("log");
      break;
    }

    expect(cancelled).toBe(true);
  });

  it("stops with a RequestAbortedError-family error when the caller aborts", async () => {
    const controller = new AbortController();
    const { client } = clientFor([sse([logFrame("a", 0)])]);

    const run = (async () => {
      for await (const _event of client.followBuildLogs("snap_b1", { signal: controller.signal })) {
        controller.abort();
      }
    })();

    await expect(run).rejects.toBeInstanceOf(TransportError);
  });
});
