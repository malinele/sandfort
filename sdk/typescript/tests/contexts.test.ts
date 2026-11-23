import { describe, expect, it } from "vitest";
import {
  InvalidResponseError,
  NotFound,
  RequestAbortedError,
  ValidationError,
  type CellResult,
} from "../src/index.js";
import { at, clientFor, failure, hangUntilAborted, ok } from "./helpers.js";
import {
  BASE,
  TOOLBOX,
  cellPayload,
  collect,
  contextPayload,
  created,
  frame,
  sse,
  started,
} from "./contexts-helpers.js";

describe("createCodeContext", () => {
  it("posts the language, name and cwd and returns the context", async () => {
    const { client, requests } = clientFor([
      created(contextPayload({ name: "main", cwd: "/data" })),
    ]);

    const { context } = await client.createCodeContext("sbx_1", { name: "main", cwd: "/data" });

    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe(BASE);
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({
      language: "python",
      name: "main",
      cwd: "/data",
    });
    expect(context).toEqual({
      id: "ctx_0123456789abcdef",
      cwd: "/data",
      name: "main",
      language: "python",
    });
  });

  it("sends only the language for an unnamed context and reports name null", async () => {
    const { client, requests } = clientFor([created(contextPayload())]);

    const context = await client.createCodeContext("sbx_1");

    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({ language: "python" });
    expect(context.name).toBeNull();
  });

  it.each([
    ["an empty name", { name: "" }],
    ["a name that starts with a dash", { name: "-x" }],
    ["a name with a space", { name: "a b" }],
    ["a name longer than 63 characters", { name: "a".repeat(64) }],
    ["an unsupported language", { language: "node" as never }],
    ["a blank cwd", { cwd: " " }],
  ])("rejects %s before sending anything", async (_label, options) => {
    const { client, requests } = clientFor([]);

    await expect(client.createCodeContext("sbx_1", options)).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(requests).toHaveLength(0);
  });

  it("rejects a blank sandbox id", async () => {
    const { client, requests } = clientFor([]);

    await expect(client.createCodeContext(" ")).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("rejects a payload without an id", async () => {
    const { client } = clientFor([created({ cwd: "/workspace" })]);

    await expect(client.createCodeContext("sbx_1")).rejects.toBeInstanceOf(InvalidResponseError);
  });

  it("maps a missing sandbox to NotFound", async () => {
    const { client } = clientFor([failure(404, "NOT_FOUND")]);

    await expect(client.createCodeContext("sbx_1")).rejects.toBeInstanceOf(NotFound);
  });
});

describe("createCodeContext with a name", () => {
  it("returns { context, created: true } when the server starts a new kernel (201)", async () => {
    const { sandbox } = await started([created(contextPayload({ name: "main" }))]);

    const result = await sandbox.createCodeContext({ name: "main" });

    expect(result.created).toBe(true);
    expect(result.context.name).toBe("main");
  });

  it("returns created false when a live context of the name was found (200)", async () => {
    const { sandbox } = await started([ok(contextPayload({ name: "main" }))]);

    const result = await sandbox.createCodeContext({ name: "main" });

    expect(result.created).toBe(false);
  });

  it("keeps returning the bare context for an unnamed create", async () => {
    const { sandbox } = await started([created(contextPayload())]);

    const context = await sandbox.createCodeContext();

    expect(context.id).toBe("ctx_0123456789abcdef");
    expect("created" in context).toBe(false);
  });
});

describe("argument types are checked, not assumed", () => {
  it.each([
    ["a numeric cwd", { cwd: 5 as never }],
    ["a null cwd", { cwd: null as never }],
  ])("rejects %s with ValidationError", async (_label, options) => {
    const { client, requests } = clientFor([]);

    await expect(client.createCodeContext("sbx_1", options)).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(requests).toHaveLength(0);
  });

  it.each([5, null, undefined, {}])("rejects the context id %s", async (id) => {
    const { client, requests } = clientFor([]);

    await expect(client.runInCodeContext("sbx_1", id as never, "1")).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(client.deleteCodeContext("sbx_1", id as never)).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(() => client.streamCodeContextRun("sbx_1", id as never, "x")).toThrow(ValidationError);
    expect(requests).toHaveLength(0);
  });
});

describe("listCodeContexts", () => {
  it("lists the contexts, with name null where absent", async () => {
    const { client, requests } = clientFor([
      ok([contextPayload({ name: "main" }), contextPayload({ id: "ctx_b" })]),
    ]);

    const contexts = await client.listCodeContexts("sbx_1");

    expect(at(requests, 0).method).toBe("GET");
    expect(at(requests, 0).url).toBe(BASE);
    expect(contexts.map((item) => [item.id, item.name])).toEqual([
      ["ctx_0123456789abcdef", "main"],
      ["ctx_b", null],
    ]);
  });

  it("filters by name through the query", async () => {
    const { client, requests } = clientFor([ok([])]);

    await client.listCodeContexts("sbx_1", { name: "main" });

    expect(at(requests, 0).url).toBe(`${BASE}?name=main`);
  });

  it("rejects a payload that is not a list", async () => {
    const { client } = clientFor([ok(contextPayload())]);

    await expect(client.listCodeContexts("sbx_1")).rejects.toBeInstanceOf(InvalidResponseError);
  });
});

describe("ensureCodeContext", () => {
  it("reports created true when the server answers 201", async () => {
    const { client, requests } = clientFor([created(contextPayload({ name: "main" }))]);

    const ensured = await client.ensureCodeContext("sbx_1", "main");

    expect(ensured.created).toBe(true);
    expect(ensured.context.name).toBe("main");
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({ language: "python", name: "main" });
  });

  it("reports created false when a live context of the name was found (200)", async () => {
    const { client } = clientFor([ok(contextPayload({ name: "main", cwd: "/kept" }))]);

    const ensured = await client.ensureCodeContext("sbx_1", "main");

    expect(ensured.created).toBe(false);
    expect(ensured.context.cwd).toBe("/kept");
  });

  it("rejects a missing or invalid name locally", async () => {
    const { client, requests } = clientFor([]);

    await expect(client.ensureCodeContext("sbx_1", "")).rejects.toBeInstanceOf(ValidationError);
    await expect(client.ensureCodeContext("sbx_1", "no good")).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(requests).toHaveLength(0);
  });
});

describe("runInCodeContext", () => {
  it("posts the cell with the default timeout and maps the result", async () => {
    const { client, requests } = clientFor([ok(cellPayload())]);

    const cell: CellResult = await client.runInCodeContext("sbx_1", "ctx_a", "6 * 7");

    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe(`${BASE}/ctx_a/run`);
    expect(JSON.parse(at(requests, 0).body ?? "")).toEqual({
      language: "python",
      code: "6 * 7",
      timeout_s: 60,
    });
    expect(cell).toEqual({
      exitCode: 0,
      stdout: "42\n",
      stderr: "",
      timedOut: false,
      truncated: false,
      durationMs: 7,
      sandboxStopped: false,
      stopReason: null,
      result: "42",
      error: null,
    });
  });

  it("sends timeoutS and encodes the context id", async () => {
    const { client, requests } = clientFor([ok(cellPayload())]);

    await client.runInCodeContext("sbx_1", "a/b", "1", { timeoutS: 5 });

    expect(at(requests, 0).url).toBe(`${BASE}/a%2Fb/run`);
    expect(JSON.parse(at(requests, 0).body ?? "")["timeout_s"]).toBe(5);
  });

  it("maps a raised exception and a null result", async () => {
    const { client } = clientFor([
      ok(
        cellPayload({
          exit_code: 1,
          result: null,
          stderr: "Traceback...",
          error: { type: "ZeroDivisionError", message: "division by zero" },
        }),
      ),
    ]);

    const cell = await client.runInCodeContext("sbx_1", "ctx_a", "1/0");

    expect(cell.result).toBeNull();
    expect(cell.error).toEqual({ type: "ZeroDivisionError", message: "division by zero" });
  });

  it.each(["timeout", "queue_timeout", "output_limit", "context_lost", "sandbox_stopped"])(
    "passes the stop reason %s through",
    async (reason) => {
      const { client } = clientFor([
        ok(cellPayload({ stop_reason: reason, sandbox_stopped: reason === "sandbox_stopped" })),
      ]);

      const cell = await client.runInCodeContext("sbx_1", "ctx_a", "x");

      expect(cell.stopReason).toBe(reason);
      expect(cell.sandboxStopped).toBe(reason === "sandbox_stopped");
    },
  );

  it("defaults the optional outcome fields when the server leaves them out", async () => {
    const { client } = clientFor([
      ok({
        exit_code: 0,
        stdout: "",
        stderr: "",
        timed_out: false,
        truncated: false,
        duration_ms: 1,
      }),
    ]);

    const cell = await client.runInCodeContext("sbx_1", "ctx_a", "pass");

    expect(cell.stopReason).toBeNull();
    expect(cell.sandboxStopped).toBe(false);
    expect(cell.result).toBeNull();
    expect(cell.error).toBeNull();
  });

  it.each([0, 3601, 1.5, Number.NaN])("rejects timeoutS %s", async (timeoutS) => {
    const { client, requests } = clientFor([]);

    await expect(
      client.runInCodeContext("sbx_1", "ctx_a", "1", { timeoutS }),
    ).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("rejects a blank context id and a non-string code", async () => {
    const { client } = clientFor([]);

    await expect(client.runInCodeContext("sbx_1", "", "1")).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(
      client.runInCodeContext("sbx_1", "ctx_a", 1 as unknown as string),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it("rejects a result without stdout", async () => {
    const { client } = clientFor([ok({ exit_code: 0 })]);

    await expect(client.runInCodeContext("sbx_1", "ctx_a", "1")).rejects.toBeInstanceOf(
      InvalidResponseError,
    );
  });

  it("raises NotFound for a context that is gone", async () => {
    const { client } = clientFor([failure(404, "NOT_FOUND")]);

    await expect(client.runInCodeContext("sbx_1", "ctx_a", "1")).rejects.toBeInstanceOf(NotFound);
  });

  it("aborts with RequestAbortedError when the signal fires", async () => {
    const { client } = clientFor([hangUntilAborted]);
    const controller = new AbortController();

    const pending = client.runInCodeContext("sbx_1", "ctx_a", "while True: pass", {
      signal: controller.signal,
    });
    controller.abort();

    await expect(pending).rejects.toBeInstanceOf(RequestAbortedError);
  });
});

describe("interruptCodeContext", () => {
  it("posts to /interrupt and returns whether a kernel was signalled", async () => {
    const { client, requests } = clientFor([
      ok({ id: "ctx_a", interrupted: true }),
      ok({ id: "ctx_a", interrupted: false }),
    ]);

    expect(await client.interruptCodeContext("sbx_1", "ctx_a")).toBe(true);
    expect(await client.interruptCodeContext("sbx_1", "ctx_a")).toBe(false);
    expect(at(requests, 0).method).toBe("POST");
    expect(at(requests, 0).url).toBe(`${BASE}/ctx_a/interrupt`);
  });

  it("rejects a payload without a boolean interrupted", async () => {
    const { client } = clientFor([ok({ id: "ctx_a" })]);

    await expect(client.interruptCodeContext("sbx_1", "ctx_a")).rejects.toBeInstanceOf(
      InvalidResponseError,
    );
  });
});

describe("deleteCodeContext", () => {
  it("sends DELETE and resolves with nothing", async () => {
    const { client, requests } = clientFor([ok({ id: "ctx_a", deleted: true })]);

    await expect(client.deleteCodeContext("sbx_1", "ctx_a")).resolves.toBeUndefined();

    expect(at(requests, 0).method).toBe("DELETE");
    expect(at(requests, 0).url).toBe(`${BASE}/ctx_a`);
  });

  it("raises NotFound for a context that is gone", async () => {
    const { client } = clientFor([failure(404, "NOT_FOUND")]);

    await expect(client.deleteCodeContext("sbx_1", "ctx_a")).rejects.toBeInstanceOf(NotFound);
  });
});

describe("the same calls on a Sandbox", () => {
  it("creates, ensures, lists, runs, interrupts and deletes without a sandbox id", async () => {
    const { sandbox, requests } = await started([
      created(contextPayload()),
      created(contextPayload({ name: "main" })),
      ok([contextPayload()]),
      ok(cellPayload()),
      ok({ id: "ctx_a", interrupted: true }),
      ok({ id: "ctx_a", deleted: true }),
    ]);

    const context = await sandbox.createCodeContext();
    const ensured = await sandbox.ensureCodeContext("main");
    const listed = await sandbox.listCodeContexts();
    const cell = await sandbox.runInCodeContext("ctx_a", "6 * 7", { timeoutS: 9 });
    const interrupted = await sandbox.interruptCodeContext("ctx_a");
    await sandbox.deleteCodeContext("ctx_a");

    expect(context.id).toBe("ctx_0123456789abcdef");
    expect(ensured.created).toBe(true);
    expect(listed).toHaveLength(1);
    expect(cell.result).toBe("42");
    expect(interrupted).toBe(true);
    expect(requests.slice(1).map((r) => `${r.method} ${r.url.slice(TOOLBOX.length)}`)).toEqual([
      "POST code-contexts",
      "POST code-contexts",
      "GET code-contexts",
      "POST code-contexts/ctx_a/run",
      "POST code-contexts/ctx_a/interrupt",
      "DELETE code-contexts/ctx_a",
    ]);
    expect(JSON.parse(at(requests, 4).body ?? "")["timeout_s"]).toBe(9);
  });

  it("streams a run", async () => {
    const { sandbox, requests } = await started([
      sse([frame("stdout", { data: "hi\n" }), frame("result", cellPayload())]),
    ]);

    const events = await collect(sandbox.streamCodeContextRun("ctx_a", "print('hi')"));

    expect(at(requests, 1).url).toBe(`${BASE}/ctx_a/run/stream`);
    expect(events.map((event) => event.type)).toEqual(["stdout", "result"]);
  });
});
