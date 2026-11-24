import { afterEach, describe, expect, it, vi } from "vitest";
import { TransportError, Unauthorized, ValidationError } from "../src/index.js";
import type { PtySession, PtySocket } from "../src/index.js";
import { at, clientFor, ok } from "./helpers.js";

const PTY = {
  id: "pty_1",
  sandbox_id: "sbx_1",
  state: "open",
  rows: 24,
  cols: 80,
  created_at: "2026-11-24T06:00:00+00:00",
};
const TOKEN = { pty_id: "pty_1", token: "tok_secret_1", websocket_url: "ws://ignored/x" };

class FakeSocket implements PtySocket {
  binaryType = "blob";
  readonly url: string;
  readonly sent: (Uint8Array | string)[] = [];
  closedWith: { code: number | undefined; reason: string | undefined } | null = null;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: ((event: { code: number; reason: string }) => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(url: string) {
    this.url = url;
  }

  send(data: Uint8Array | string): void {
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    this.closedWith = { code, reason };
  }
}

/** Create a client whose pty dials FakeSocket, connect, and hand back both ends. */
async function connected(
  queue: Response[],
  options: Record<string, unknown> = {},
): Promise<{
  session: PtySession;
  socket: FakeSocket;
  requests: ReturnType<typeof clientFor>["requests"];
}> {
  const sockets: FakeSocket[] = [];
  const { client, requests } = clientFor(queue, {
    webSocket: (url: string) => {
      const socket = new FakeSocket(url);
      sockets.push(socket);
      return socket;
    },
    ...options,
  });
  const pending = client.connectPty("sbx_1");
  const socket = await dialed(sockets);
  socket.onopen?.();
  const session = await pending;
  return { session, socket, requests };
}

async function collect(session: PtySession): Promise<Uint8Array[]> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of session) chunks.push(chunk);
  return chunks;
}

/** Wait (bounded) until the client has dialed a socket. */
async function dialed(sockets: FakeSocket[]): Promise<FakeSocket> {
  for (let i = 0; i < 50 && sockets.length === 0; i++) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const socket = sockets[0];
  if (socket === undefined) throw new Error("no socket dialed");
  return socket;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("connectPty", () => {
  it("creates the pty and dials the connect URL built from baseUrl, with the token", async () => {
    const { socket, requests } = await connected([ok(TOKEN)]);

    const create = at(requests, 0);
    expect(`${create.method} ${create.url}`).toBe(
      "POST http://sf.test/v1/sandboxes/sbx_1/toolbox/pty",
    );
    expect(JSON.parse(create.body ?? "null")).toEqual({});
    expect(socket.url).toBe(
      "ws://sf.test/v1/sandboxes/sbx_1/toolbox/pty/pty_1/connect?token=tok_secret_1",
    );
    expect(socket.binaryType).toBe("arraybuffer");
  });

  it("dials wss for an https base URL", async () => {
    const { socket } = await connected([ok(TOKEN)], { baseUrl: "https://sf.test" });
    expect(socket.url.startsWith("wss://sf.test/")).toBe(true);
  });

  it("sends only the create options that were set, in snake_case", async () => {
    const sockets: FakeSocket[] = [];
    const { client, requests } = clientFor([ok(TOKEN)], {
      webSocket: (url: string) => {
        const socket = new FakeSocket(url);
        sockets.push(socket);
        return socket;
      },
    });
    const pending = client.connectPty("sbx_1", {
      rows: 40,
      cols: 120,
      argv: ["/bin/bash"],
      env: { TERM: "xterm" },
    });
    (await dialed(sockets)).onopen?.();
    await pending;

    expect(JSON.parse(at(requests, 0).body ?? "null")).toEqual({
      rows: 40,
      cols: 120,
      argv: ["/bin/bash"],
      env: { TERM: "xterm" },
    });
  });

  it("refuses to dial without a WebSocket implementation", async () => {
    vi.stubGlobal("WebSocket", undefined);
    const { client } = clientFor([ok(TOKEN)]);
    await expect(client.connectPty("sbx_1")).rejects.toBeInstanceOf(ValidationError);
  });
});

describe("PtySession", () => {
  it("forwards sent strings and bytes to the socket", async () => {
    const { session, socket } = await connected([ok(TOKEN)]);

    session.send("ls\n");
    session.send(new Uint8Array([3]));

    expect(socket.sent).toEqual(["ls\n", new Uint8Array([3])]);
  });

  it("yields binary frames as bytes and text frames as utf-8; exit close ends iteration", async () => {
    const { session, socket } = await connected([ok(TOKEN)]);

    socket.onmessage?.({ data: new Uint8Array([104, 105]).buffer });
    socket.onmessage?.({ data: "ok" });
    socket.onclose?.({ code: 4000, reason: "" });

    expect(await collect(session)).toEqual([
      new Uint8Array([104, 105]),
      new Uint8Array([111, 107]),
    ]);
    expect(session.exitCode).toBe(0);
  });

  it("maps a 4000+n close to that exit code and a 1000 close to null", async () => {
    const first = await connected([ok(TOKEN)]);
    first.socket.onclose?.({ code: 4042, reason: "" });
    await collect(first.session);
    expect(first.session.exitCode).toBe(42);

    const second = await connected([ok(TOKEN)]);
    second.socket.onclose?.({ code: 1000, reason: "" });
    await collect(second.session);
    expect(second.session.exitCode).toBeNull();
  });

  it("raises Unauthorized on a 4401 close, without the token in the message", async () => {
    const { session, socket } = await connected([ok(TOKEN)]);
    socket.onclose?.({ code: 4401, reason: "" });

    const error = await collect(session).catch((raised: unknown) => raised);
    expect(error).toBeInstanceOf(Unauthorized);
    expect(String(error)).not.toContain("tok_secret_1");
  });

  it("raises TransportError on an abnormal close, without the token in the message", async () => {
    const { session, socket } = await connected([ok(TOKEN)]);
    socket.onclose?.({ code: 1006, reason: "" });

    const error = await collect(session).catch((raised: unknown) => raised);
    expect(error).toBeInstanceOf(TransportError);
    expect(String(error)).not.toContain("tok_secret_1");
  });

  it("close() closes the socket", async () => {
    const { session, socket } = await connected([ok(TOKEN)]);
    session.close();
    expect(socket.closedWith).toEqual({ code: undefined, reason: undefined });
  });

  it("resize posts rows and cols for this pty", async () => {
    const { session, requests } = await connected([
      ok(TOKEN),
      ok({ ...PTY, rows: 50, cols: 132 }),
    ]);

    const info = await session.resize(50, 132);

    const resize = at(requests, 1);
    expect(`${resize.method} ${resize.url}`).toBe(
      "POST http://sf.test/v1/sandboxes/sbx_1/toolbox/pty/pty_1/resize",
    );
    expect(JSON.parse(resize.body ?? "null")).toEqual({ rows: 50, cols: 132 });
    expect(info.rows).toBe(50);
  });
});

describe("pty REST surface", () => {
  it("maps the wire payload to camelCase fields", async () => {
    const { client } = clientFor([ok(PTY)]);

    const info = await client.getPty("sbx_1", "pty_1");

    expect(info).toEqual({
      id: "pty_1",
      sandboxId: "sbx_1",
      state: "open",
      rows: 24,
      cols: 80,
      createdAt: new Date("2026-11-24T06:00:00Z"),
    });
  });

  it("lists, creates without connecting, and deletes over the matching routes", async () => {
    const { client, requests } = clientFor([
      ok([PTY]),
      ok(TOKEN),
      ok({ ...PTY, state: "closed" }),
    ]);

    const listed = await client.listPtys("sbx_1");
    const token = await client.createPty("sbx_1", { rows: 30 });
    const closed = await client.deletePty("sbx_1", "pty_1");

    expect(listed.map((pty) => pty.id)).toEqual(["pty_1"]);
    expect(JSON.parse(at(requests, 1).body ?? "null")).toEqual({ rows: 30 });
    expect(token).toEqual({
      ptyId: "pty_1",
      token: "tok_secret_1",
      websocketUrl: "ws://ignored/x",
    });
    expect(closed.state).toBe("closed");
    expect(requests.map((request) => `${request.method} ${request.url}`)).toEqual([
      "GET http://sf.test/v1/sandboxes/sbx_1/toolbox/pty",
      "POST http://sf.test/v1/sandboxes/sbx_1/toolbox/pty",
      "DELETE http://sf.test/v1/sandboxes/sbx_1/toolbox/pty/pty_1",
    ]);
  });
});
