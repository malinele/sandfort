import { describe, expect, it } from "vitest";
import { InvalidResponseError, NotFound, SandfortClient, type FetchLike } from "../src/index.js";

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
  return new Response(JSON.stringify({ success: true, data }), { status: 200 });
}

const SANDBOX = { id: "sbx_1", name: "box", state: "started" };
const TOOLBOX = "http://sf.test/v1/sandboxes/sbx_1/toolbox/process/sessions";

function session(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "ses_1",
    sandbox_id: "sbx_1",
    cwd: "/work",
    env: { A: "1" },
    state: "active",
    created_at: "2026-11-01T10:00:00+00:00",
    ...extra,
  };
}

function command(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "cmd_1",
    session_id: "ses_1",
    state: "running",
    exit_code: null,
    stdout_bytes: 3,
    stderr_bytes: 0,
    created_at: "2026-11-01T10:00:01+00:00",
    finished_at: null,
    ...extra,
  };
}

async function handleFor(queue: Response[]) {
  const { fetch, requests } = stub([ok(SANDBOX), ...queue]);
  const client = new SandfortClient({ baseUrl: "http://sf.test", apiKey: "sf_key", fetch });
  const sandbox = await client.getSandbox("sbx_1");
  requests.length = 0;
  return { sandbox, requests };
}

function first(requests: Recorded[]): Recorded {
  const item = requests[0];
  if (item === undefined) throw new Error("no request recorded");
  return item;
}

describe("sessions", () => {
  it("creates a session with cwd and env, byte-exact body", async () => {
    const { sandbox, requests } = await handleFor([ok(session())]);

    const info = await sandbox.createSession({ cwd: "/work", env: { A: "1" } });

    expect(first(requests)).toEqual({
      url: TOOLBOX,
      method: "POST",
      body: '{"cwd":"/work","env":{"A":"1"}}',
    });
    expect(info.id).toBe("ses_1");
    expect(info.sandboxId).toBe("sbx_1");
    expect(info.cwd).toBe("/work");
    expect(info.env).toEqual({ A: "1" });
    expect(info.createdAt.toISOString()).toBe("2026-11-01T10:00:00.000Z");
  });

  it("omits unset create options", async () => {
    const { sandbox, requests } = await handleFor([ok(session({ cwd: null, env: null }))]);

    const info = await sandbox.createSession();

    expect(first(requests).body).toBe("{}");
    expect(info.cwd).toBeNull();
    expect(info.env).toEqual({});
  });

  it("lists sessions", async () => {
    const { sandbox, requests } = await handleFor([ok([session(), session({ id: "ses_2" })])]);

    const items = await sandbox.listSessions();

    expect(first(requests)).toEqual({ url: TOOLBOX, method: "GET", body: undefined });
    expect(items.map((s) => s.id)).toEqual(["ses_1", "ses_2"]);
  });

  it("runs a command synchronously with the default timeout and unwraps the exec result", async () => {
    const result = {
      exit_code: 0,
      stdout: "/work\n",
      stderr: "",
      timed_out: false,
      truncated: false,
      duration_ms: 12,
    };
    const { sandbox, requests } = await handleFor([ok({ mode: "sync", cwd: "/work", result })]);

    const out = await sandbox.runInSession("ses_1", "pwd");

    expect(first(requests)).toEqual({
      url: `${TOOLBOX}/ses_1/commands`,
      method: "POST",
      body: '{"command":"pwd","mode":"sync","timeout_s":60}',
    });
    expect(out).toEqual({
      exitCode: 0,
      stdout: "/work\n",
      stderr: "",
      timedOut: false,
      truncated: false,
      durationMs: 12,
    });
  });

  it("sends an explicit timeout and rejects blank commands before any request", async () => {
    const failed = {
      exit_code: 1,
      stdout: "",
      stderr: "e",
      timed_out: false,
      truncated: false,
      duration_ms: 1,
    };
    const { sandbox, requests } = await handleFor([ok({ mode: "sync", result: failed })]);

    await sandbox.runInSession("ses_1", "false", { timeoutS: 5 });
    expect(first(requests).body).toBe('{"command":"false","mode":"sync","timeout_s":5}');

    await expect(sandbox.runInSession("ses_1", "  ")).rejects.toThrow("must not be empty");
    expect(requests).toHaveLength(1);
  });

  it("rejects a sync reply without a result", async () => {
    const { sandbox } = await handleFor([ok({ mode: "sync" })]);

    await expect(sandbox.runInSession("ses_1", "ls")).rejects.toBeInstanceOf(InvalidResponseError);
  });

  it("starts an async command and returns its command info", async () => {
    const { sandbox, requests } = await handleFor([ok({ mode: "async", command: command() })]);

    const info = await sandbox.startCommand("ses_1", "sleep 5", { timeoutS: 30 });

    expect(first(requests).body).toBe('{"command":"sleep 5","mode":"async","timeout_s":30}');
    expect(info).toMatchObject({
      id: "cmd_1",
      sessionId: "ses_1",
      state: "running",
      exitCode: null,
    });
    expect(info.finishedAt).toBeNull();
  });

  it("gets command status and collected logs", async () => {
    const done = command({
      state: "exited",
      exit_code: 0,
      finished_at: "2026-11-01T10:00:05+00:00",
    });
    const logs = {
      events: [{ stream: "stdout", offset: 0, line: "hi\n" }],
      next_offset: 3,
      truncated: false,
      complete: true,
      state: "exited",
      exit_code: 0,
    };
    const { sandbox, requests } = await handleFor([ok(done), ok(logs)]);

    const info = await sandbox.getCommand("ses_1", "cmd_1");
    const page = await sandbox.getCommandLogs("ses_1", "cmd_1", { offset: 1, limit: 10 });

    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      `GET ${TOOLBOX}/ses_1/commands/cmd_1`,
      `GET ${TOOLBOX}/ses_1/commands/cmd_1/logs?offset=1&limit=10`,
    ]);
    expect(info.finishedAt?.toISOString()).toBe("2026-11-01T10:00:05.000Z");
    expect(page.events).toEqual([{ stream: "stdout", offset: 0, line: "hi\n" }]);
    expect(page).toMatchObject({ nextOffset: 3, complete: true, state: "exited", exitCode: 0 });
  });

  it("reads logs from offset 0 by default and rejects negative offsets", async () => {
    const empty = { events: [], next_offset: 0, truncated: false, complete: false };
    const { sandbox, requests } = await handleFor([ok(empty)]);

    const page = await sandbox.getCommandLogs("ses_1", "cmd_1");

    expect(first(requests).url).toBe(`${TOOLBOX}/ses_1/commands/cmd_1/logs?offset=0`);
    expect(page.state).toBeNull();
    await expect(sandbox.getCommandLogs("ses_1", "cmd_1", { offset: -1 })).rejects.toThrow(
      "offset must be >= 0",
    );
  });

  it("kills a command and percent-encodes ids", async () => {
    const { sandbox, requests } = await handleFor([ok(command({ state: "killed" }))]);

    const info = await sandbox.killCommand("a/b", "c d");

    expect(first(requests)).toEqual({
      url: `${TOOLBOX}/a%2Fb/commands/c%20d/kill`,
      method: "POST",
      body: undefined,
    });
    expect(info.state).toBe("killed");
  });

  it("maps an error envelope to a typed error", async () => {
    const missing = new Response(
      JSON.stringify({ success: false, error: { code: "NOT_FOUND", message: "no session" } }),
      { status: 404 },
    );
    const { sandbox } = await handleFor([missing]);

    await expect(sandbox.getSession("ses_x")).rejects.toBeInstanceOf(NotFound);
  });
});
