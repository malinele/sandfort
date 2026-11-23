import { describe, expect, it } from "vitest";
import {
  InvalidResponseError,
  SandfortClient,
  ValidationFailed,
  type FetchLike,
  type Sandbox,
} from "../src/index.js";

interface Recorded {
  url: string;
  method: string;
  body: string | undefined;
}

function stub(queue: Response[]): { fetch: FetchLike; requests: Recorded[] } {
  const requests: Recorded[] = [];
  const fetch: FetchLike = async (input, init) => {
    requests.push({
      url: input,
      method: init.method ?? "GET",
      body: typeof init.body === "string" ? init.body : undefined,
    });
    const next = queue.shift();
    if (next === undefined) throw new Error("no queued response");
    return next;
  };
  return { fetch, requests };
}

function ok(data: unknown): Response {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function execReply(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    exit_code: 0,
    stdout: "42\n",
    stderr: "",
    timed_out: false,
    truncated: false,
    duration_ms: 12,
    ...extra,
  };
}

const EXECUTE_URL = "http://sf.test/v1/sandboxes/sbx_1/toolbox/process/execute";
const CODE_RUN_URL = "http://sf.test/v1/sandboxes/sbx_1/toolbox/process/code-run";

/** A started sandbox handle; its GET is request 0, the call under test is request 1. */
async function sandboxWith(
  replies: Response[],
): Promise<{ sandbox: Sandbox; requests: Recorded[] }> {
  const { fetch, requests } = stub([
    ok({ id: "sbx_1", name: "demo", state: "started" }),
    ...replies,
  ]);
  const client = new SandfortClient({ baseUrl: "http://sf.test", apiKey: "sf_key", fetch });
  const sandbox = await client.getSandbox("sbx_1");
  return { sandbox, requests };
}

function at(requests: Recorded[], index: number): Recorded {
  const item = requests[index];
  if (item === undefined) throw new Error(`no request recorded at ${index}`);
  return item;
}

describe("processExec", () => {
  it("sends a command string as `command` with the default timeout", async () => {
    const { sandbox, requests } = await sandboxWith([ok(execReply())]);

    await sandbox.processExec("echo 42");

    const sent = at(requests, 1);
    expect(sent.method).toBe("POST");
    expect(sent.url).toBe(EXECUTE_URL);
    expect(sent.body).toBe('{"command":"echo 42","timeout_s":60}');
  });

  it("sends an array as `argv` with every option byte-exact", async () => {
    const { sandbox, requests } = await sandboxWith([ok(execReply())]);

    await sandbox.processExec(["ls", "-la", "/w"], {
      cwd: "/w",
      env: { A: "1" },
      timeoutS: 5,
      stdin: "in",
    });

    expect(at(requests, 1).body).toBe(
      '{"argv":["ls","-la","/w"],"cwd":"/w","env":{"A":"1"},"stdin":"in","timeout_s":5}',
    );
  });

  it("passes a custom timeout through as `timeout_s`", async () => {
    const { sandbox, requests } = await sandboxWith([ok(execReply())]);

    await sandbox.processExec("sleep 100", { timeoutS: 120 });

    expect(at(requests, 1).body).toBe('{"command":"sleep 100","timeout_s":120}');
  });

  it("unwraps the exec result into camelCase fields", async () => {
    const { sandbox } = await sandboxWith([
      ok(execReply({ exit_code: 3, stderr: "boom", timed_out: true, truncated: true })),
    ]);

    const result = await sandbox.processExec("false");

    expect(result).toEqual({
      exitCode: 3,
      stdout: "42\n",
      stderr: "boom",
      timedOut: true,
      truncated: true,
      durationMs: 12,
    });
  });

  it("rejects a result payload with a missing field", async () => {
    const { sandbox } = await sandboxWith([ok({ exit_code: 0, stdout: "" })]);

    await expect(sandbox.processExec("true")).rejects.toBeInstanceOf(InvalidResponseError);
  });

  it("surfaces typed API errors", async () => {
    const body = { success: false, error: { code: "VALIDATION_ERROR", message: "bad" } };
    const { sandbox } = await sandboxWith([new Response(JSON.stringify(body), { status: 422 })]);

    await expect(sandbox.processExec("x")).rejects.toBeInstanceOf(ValidationFailed);
  });
});

describe("codeRun", () => {
  it("sends language, code and the default timeout", async () => {
    const { sandbox, requests } = await sandboxWith([ok(execReply())]);

    const result = await sandbox.codeRun("python", "print(42)");

    const sent = at(requests, 1);
    expect(sent.method).toBe("POST");
    expect(sent.url).toBe(CODE_RUN_URL);
    expect(sent.body).toBe('{"language":"python","code":"print(42)","timeout_s":60}');
    expect(result.stdout).toBe("42\n");
  });

  it("sends argv, env and timeout_s byte-exact", async () => {
    const { sandbox, requests } = await sandboxWith([ok(execReply())]);

    await sandbox.codeRun("bash", "echo $1", { argv: ["a"], env: { K: "v" }, timeoutS: 9 });

    expect(at(requests, 1).body).toBe(
      '{"language":"bash","code":"echo $1","argv":["a"],"env":{"K":"v"},"timeout_s":9}',
    );
  });
});

describe("sandbox handle", () => {
  it("keeps only the record fields enumerable", async () => {
    const { sandbox } = await sandboxWith([]);

    expect(Object.keys(sandbox)).not.toContain("fs");
    expect(JSON.parse(JSON.stringify(sandbox))).toMatchObject({ id: "sbx_1", state: "started" });
  });

  it("percent-encodes the sandbox id in toolbox paths", async () => {
    const { fetch, requests } = stub([
      ok({ id: "a/b", name: "demo", state: "started" }),
      ok(execReply()),
    ]);
    const client = new SandfortClient({ baseUrl: "http://sf.test", apiKey: "sf_key", fetch });
    const sandbox = await client.getSandbox("a/b");

    await sandbox.processExec("true");

    expect(at(requests, 1).url).toBe(
      "http://sf.test/v1/sandboxes/a%2Fb/toolbox/process/execute",
    );
  });
});
