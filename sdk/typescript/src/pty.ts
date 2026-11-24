/**
 * Interactive PTY: REST lifecycle plus a WebSocket session, mirroring `sandfort_sdk.pty`.
 *
 * The wire protocol (server: `src/sandfort/api/routes/toolbox/pty.py`): create over REST
 * answers a single-use connect token (60 s TTL); the WebSocket at
 * `.../toolbox/pty/{id}/connect?token=...` carries raw terminal bytes in both directions,
 * with no control frames in-band. Resize and close are REST calls. Server close codes:
 * 4401 token rejected, 4000+n process exited with code n, 1000 otherwise.
 */

import { TransportError, Unauthorized, ValidationError } from "./errors.js";
import { asRecord, requiredNumber, requiredString, requiredTimestamp } from "./models.js";
import { callArgs, type CallOptions } from "./resilience.js";
import type { Transport } from "./transport.js";

const CLOSE_NORMAL = 1000;
const CLOSE_UNAUTHORIZED = 4401;
const EXIT_CODE_BASE = 4000;
const EXIT_CODE_MAX = EXIT_CODE_BASE + 255;
const SIZE_MIN = 1;
const SIZE_MAX = 1000;

/** One terminal, as the REST routes report it. */
export interface PtyInfo {
  id: string;
  sandboxId: string;
  /** `"open"` or `"closed"`. */
  state: string;
  rows: number;
  cols: number;
  createdAt: Date;
}

/** The create response: a single-use connect token (60 s TTL, redeemed by the WebSocket). */
export interface PtyConnectToken {
  ptyId: string;
  token: string;
  websocketUrl: string;
}

export interface CreatePtyOptions extends CallOptions {
  /** Terminal size (server default 24x80; 1..1000 each). */
  rows?: number;
  cols?: number;
  /** Command to run (server default: a login shell). */
  argv?: readonly string[];
  env?: Record<string, string>;
}

/**
 * The browser-compatible subset of a WebSocket that the PTY session needs. The global
 * `WebSocket` of Node 22+ and of every browser satisfies it; on older Node pass a factory
 * (for example from the `ws` package) as the client's `webSocket` option.
 */
export interface PtySocket {
  binaryType: string;
  send(data: Uint8Array | string): void;
  close(code?: number, reason?: string): void;
  onopen: (() => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onclose: ((event: { code: number; reason: string }) => void) | null;
  onerror: (() => void) | null;
}

export type PtySocketFactory = (url: string) => PtySocket;

export function ptyFromPayload(data: unknown): PtyInfo {
  const what = "pty";
  const raw = asRecord(data, what);
  return {
    id: requiredString(raw, "id", what),
    sandboxId: requiredString(raw, "sandbox_id", what),
    state: requiredString(raw, "state", what),
    rows: requiredNumber(raw, "rows", what),
    cols: requiredNumber(raw, "cols", what),
    createdAt: requiredTimestamp(raw["created_at"], what),
  };
}

function tokenFromPayload(data: unknown): PtyConnectToken {
  const what = "pty connect token";
  const raw = asRecord(data, what);
  return {
    ptyId: requiredString(raw, "pty_id", what),
    token: requiredString(raw, "token", what),
    websocketUrl: requiredString(raw, "websocket_url", what),
  };
}

function checkSize(value: number | undefined, name: string): void {
  if (value === undefined) return;
  if (!Number.isInteger(value) || value < SIZE_MIN || value > SIZE_MAX) {
    throw new ValidationError(`${name} must be an integer in ${SIZE_MIN}..${SIZE_MAX}`);
  }
}

function createBody(options: CreatePtyOptions): Record<string, unknown> {
  checkSize(options.rows, "rows");
  checkSize(options.cols, "cols");
  const body: Record<string, unknown> = {};
  if (options.rows !== undefined) body["rows"] = options.rows;
  if (options.cols !== undefined) body["cols"] = options.cols;
  if (options.argv !== undefined) body["argv"] = [...options.argv];
  if (options.env !== undefined) body["env"] = options.env;
  return body;
}

/** Map the client's HTTP base URL to the ws(s) connect URL; the token rides as a query. */
export function ptyConnectUrl(
  baseUrl: string,
  sandboxId: string,
  ptyId: string,
  token: string,
): string {
  const base = baseUrl.replace(/\/+$/, "").replace(/^http/, "ws");
  const path = `/v1/sandboxes/${encodeURIComponent(sandboxId)}/toolbox/pty/${encodeURIComponent(ptyId)}/connect`;
  return `${base}${path}?token=${encodeURIComponent(token)}`;
}

/** The terminal process's exit code carried by a close frame, or null. */
function exitCodeFromClose(code: number | null): number | null {
  if (code === null || code < EXIT_CODE_BASE || code > EXIT_CODE_MAX) return null;
  return code - EXIT_CODE_BASE;
}

function closeError(code: number): Error | null {
  if (code === CLOSE_NORMAL || (code >= EXIT_CODE_BASE && code <= EXIT_CODE_MAX)) return null;
  if (code === CLOSE_UNAUTHORIZED) {
    return new Unauthorized("pty websocket rejected the connect token", {
      code: "UNAUTHORIZED",
    });
  }
  return new TransportError(`pty websocket closed abnormally (code ${code})`);
}

const EMPTY = new Uint8Array(0);

function frameBytes(data: unknown): Uint8Array {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (data instanceof Uint8Array) return data;
  return EMPTY;
}

type ResizeCall = (rows: number, cols: number, call: CallOptions) => Promise<PtyInfo>;

/**
 * A connected terminal: `send`, iterate output bytes, `resize`, `close`. Iteration ends
 * when the terminal ends (a normal or exit-code close); `exitCode` is set once closed.
 */
export class PtySession implements AsyncIterable<Uint8Array> {
  readonly id: string;
  readonly #socket: PtySocket;
  readonly #resizeCall: ResizeCall;
  readonly #frames: Uint8Array[] = [];
  #closeCode: number | null = null;
  #wake: (() => void) | null = null;

  constructor(ptyId: string, socket: PtySocket, resizeCall: ResizeCall) {
    this.id = ptyId;
    this.#socket = socket;
    this.#resizeCall = resizeCall;
    socket.onmessage = (event) => {
      this.#frames.push(frameBytes(event.data));
      this.#wake?.();
    };
    socket.onclose = (event) => {
      this.#closeCode = event.code;
      this.#wake?.();
    };
  }

  /** The terminal process's exit code once the connection closed; else `null`. */
  get exitCode(): number | null {
    return exitCodeFromClose(this.#closeCode);
  }

  /** Write keystrokes: a string is sent as a text frame, bytes as a binary frame. */
  send(data: Uint8Array | string): void {
    this.#socket.send(data);
  }

  resize(rows: number, cols: number, call: CallOptions = {}): Promise<PtyInfo> {
    return this.#resizeCall(rows, cols, call);
  }

  /** Close the socket; the terminal itself is torn down by `deletePty` or process exit. */
  close(): void {
    this.#socket.close();
  }

  async *[Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
    for (;;) {
      const frame = this.#frames.shift();
      if (frame !== undefined) {
        yield frame;
        continue;
      }
      if (this.#closeCode !== null) {
        const error = closeError(this.#closeCode);
        if (error !== null) throw error;
        return;
      }
      await new Promise<void>((resolve) => {
        this.#wake = resolve;
      });
      this.#wake = null;
    }
  }
}

/** PTY calls of one client; every method names the sandbox it works in. */
export class PtyChannel {
  readonly #transport: Transport;
  readonly #baseUrl: string;
  readonly #socketFactory: PtySocketFactory | undefined;

  constructor(
    transport: Transport,
    baseUrl: string,
    socketFactory: PtySocketFactory | undefined,
  ) {
    this.#transport = transport;
    this.#baseUrl = baseUrl;
    this.#socketFactory = socketFactory;
  }

  #path(sandboxId: string, suffix = ""): string {
    return `/v1/sandboxes/${encodeURIComponent(sandboxId)}/toolbox/pty${suffix}`;
  }

  async create(sandboxId: string, options: CreatePtyOptions = {}): Promise<PtyConnectToken> {
    const reply = await this.#transport.request("POST", this.#path(sandboxId), {
      json: createBody(options),
      ...callArgs(options),
    });
    return tokenFromPayload(reply);
  }

  async list(sandboxId: string, call: CallOptions = {}): Promise<PtyInfo[]> {
    const reply = await this.#transport.request("GET", this.#path(sandboxId), {
      ...callArgs(call),
    });
    if (!Array.isArray(reply)) throw new ValidationError("pty list is not an array");
    return reply.map(ptyFromPayload);
  }

  async get(sandboxId: string, ptyId: string, call: CallOptions = {}): Promise<PtyInfo> {
    const reply = await this.#transport.request(
      "GET",
      this.#path(sandboxId, `/${encodeURIComponent(ptyId)}`),
      { ...callArgs(call) },
    );
    return ptyFromPayload(reply);
  }

  async resize(
    sandboxId: string,
    ptyId: string,
    rows: number,
    cols: number,
    call: CallOptions = {},
  ): Promise<PtyInfo> {
    checkSize(rows, "rows");
    checkSize(cols, "cols");
    const reply = await this.#transport.request(
      "POST",
      this.#path(sandboxId, `/${encodeURIComponent(ptyId)}/resize`),
      { json: { rows, cols }, ...callArgs(call) },
    );
    return ptyFromPayload(reply);
  }

  async delete(sandboxId: string, ptyId: string, call: CallOptions = {}): Promise<PtyInfo> {
    const reply = await this.#transport.request(
      "DELETE",
      this.#path(sandboxId, `/${encodeURIComponent(ptyId)}`),
      { ...callArgs(call) },
    );
    return ptyFromPayload(reply);
  }

  #dial(url: string): PtySocket {
    if (this.#socketFactory !== undefined) return this.#socketFactory(url);
    const globalSocket = (globalThis as { WebSocket?: new (url: string) => PtySocket })
      .WebSocket;
    if (globalSocket === undefined) {
      throw new ValidationError(
        "no WebSocket implementation: pass the client option webSocket " +
          "(Node 22+ has a global WebSocket; on older Node use the ws package)",
      );
    }
    return new globalSocket(url);
  }

  /** Create a pty and attach to it. The returned session is live once this resolves. */
  async connect(sandboxId: string, options: CreatePtyOptions = {}): Promise<PtySession> {
    const created = await this.create(sandboxId, options);
    const url = ptyConnectUrl(this.#baseUrl, sandboxId, created.ptyId, created.token);
    const socket = this.#dial(url);
    socket.binaryType = "arraybuffer";
    const session = new PtySession(created.ptyId, socket, (rows, cols, call) =>
      this.resize(sandboxId, created.ptyId, rows, cols, call),
    );
    await new Promise<void>((resolve, reject) => {
      socket.onopen = () => resolve();
      socket.onerror = () => {
        reject(new TransportError("pty websocket connect failed"));
      };
    });
    return session;
  }
}
