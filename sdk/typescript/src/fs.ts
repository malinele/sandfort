/**
 * Filesystem toolbox: list, mkdir, move, remove and single-request file transfers, mirroring
 * `sandfort_sdk.fs.Fs`. Raw bodies travel as `Uint8Array` or `Blob` through `fetch`; JSON
 * calls reuse the shared `Transport`, raw ones go through `BinaryChannel`.
 */

import { USER_AGENT } from "./version.js";
import { InvalidResponseError, ValidationError } from "./errors.js";
import { isRecord, parseJson, replyError } from "./reply.js";
import {
  deleteResultFromPayload,
  dirListingFromPayload,
  mkdirResultFromPayload,
  moveResultFromPayload,
  uploadResultFromPayload,
  type DeleteResult,
  type DirListing,
  type FileEntry,
  type MkdirResult,
  type MoveResult,
  type UploadResult,
} from "./models.js";
import { statEntry } from "./sandbox-ops.js";
import {
  resolvePolicy,
  retryHint,
  callArgs,
  withCallOptions,
  withResilience,
  type CallOptions,
  type ResiliencePolicy,
} from "./resilience.js";
import {
  buildQuery,
  type FetchLike,
  type Query,
  type Transport,
  type TransportOptions,
} from "./transport.js";

export const TAR_MEDIA_TYPE = "application/x-tar";
const OCTET_STREAM = "application/octet-stream";
const JSON_MEDIA_TYPE = "application/json";
export const DEFAULT_FILE_MODE = "644";
export const DEFAULT_DIR_MODE = "755";

export type UploadData = Uint8Array | Blob;

export interface UploadOptions extends CallOptions {
  /** Replace an existing file (default true). */
  overwrite?: boolean;
  /** Octal permission string (default `"644"`). */
  mode?: string;
}

export interface MkdirOptions extends CallOptions {
  mode?: string;
  parents?: boolean;
}

export interface MoveOptions extends CallOptions {
  overwrite?: boolean;
}

export interface RemoveOptions extends CallOptions {
  recursive?: boolean;
}

interface BinaryRequest extends CallOptions {
  query: Query;
  accept: string;
  body?: BodyInit;
}

/** The `data` of a success envelope; any other reply becomes a typed error. */
function envelopeData(body: unknown, response: Response): unknown {
  if (isRecord(body) && body["success"] === true) return body["data"];
  if (isRecord(body) && "success" in body) throw replyError(body, response);
  if (!response.ok) throw replyError(body, response);
  throw new InvalidResponseError("response is not a Sandfort envelope");
}

/** Copy into a fresh buffer: a valid `BodyInit` that later caller writes cannot change. */
function toBody(data: UploadData): BodyInit {
  if (data instanceof Uint8Array) {
    const copy = new Uint8Array(data.byteLength);
    copy.set(data);
    return copy;
  }
  return data;
}

function byteSize(data: UploadData): number {
  return data instanceof Uint8Array ? data.byteLength : data.size;
}

function mediaType(response: Response): string {
  const header = response.headers.get("content-type") ?? "";
  return (header.split(";")[0] ?? "").trim().toLowerCase();
}

/** Raw-body requests (uploads and downloads) that the JSON `Transport` does not carry. */
export class BinaryChannel {
  readonly #baseUrl: string;
  readonly #apiKey: string;
  readonly #fetch: FetchLike;
  readonly #policy: ResiliencePolicy;

  constructor(options: TransportOptions) {
    if (options.baseUrl === "") throw new ValidationError("baseUrl must not be empty");
    if (options.apiKey === "") throw new ValidationError("apiKey must not be empty");
    this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#apiKey = options.apiKey;
    this.#fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.#policy = resolvePolicy(options);
  }

  /**
   * Send, then run `read` on the reply inside the same resilience wrapper, so a timeout or an
   * abort while the body streams in becomes `RequestTimeoutError` / `RequestAbortedError`.
   * `read` must return, not throw, for error statuses (a throw there would lose its type).
   */
  async send<T>(
    method: string,
    path: string,
    request: BinaryRequest,
    read: (response: Response) => Promise<T>,
  ): Promise<T> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.#apiKey}`,
      Accept: request.accept,
      "User-Agent": USER_AGENT,
    };
    const init: RequestInit = { method, headers };
    if (request.body !== undefined) {
      headers["Content-Type"] = OCTET_STREAM;
      init.body = request.body;
    }
    const url = `${this.#baseUrl}${path}${buildQuery(request.query)}`;
    return withResilience({
      policy: withCallOptions(this.#policy, request),
      method,
      path,
      headers,
      signal: request.signal,
      run: async (signal) => {
        const response = await this.#fetch(url, { ...init, signal });
        if (response.status !== 429 && response.status !== 503) {
          return { value: await read(response) };
        }
        // Error replies are small: read one to decide on a resend, then hand back an unread copy.
        const text = await response.text();
        const copy = new Response(text, response);
        return { value: await read(copy), hint: retryHint(response.status, text, response.headers) };
      },
    });
  }

  /** Send and unwrap the JSON envelope of the reply. */
  async sendForData(method: string, path: string, request: BinaryRequest): Promise<unknown> {
    const { response, text } = await this.send(method, path, request, async (reply) => ({
      response: reply,
      text: await reply.text(),
    }));
    return envelopeData(parseJson(text), response);
  }
}

/** What a download attempt read: an error body, a tar stream that was dropped, or the file. */
type DownloadReply =
  | { kind: "error"; response: Response; text: string }
  | { kind: "tar" }
  | { kind: "file"; bytes: Uint8Array };

async function readDownload(response: Response): Promise<DownloadReply> {
  if (!response.ok) return { kind: "error", response, text: await response.text() };
  if (mediaType(response) === TAR_MEDIA_TYPE) {
    await response.body?.cancel();
    return { kind: "tar" };
  }
  return { kind: "file", bytes: new Uint8Array(await response.arrayBuffer()) };
}

/** Filesystem calls of one sandbox; `toolboxPath` is `/v1/sandboxes/{id}/toolbox`. */
export class Fs {
  readonly #transport: Transport;
  readonly #binary: BinaryChannel;
  readonly #basePath: string;
  readonly #toolboxPath: string;

  constructor(transport: Transport, binary: BinaryChannel, toolboxPath: string) {
    this.#transport = transport;
    this.#binary = binary;
    this.#basePath = `${toolboxPath}/fs`;
    this.#toolboxPath = toolboxPath;
  }

  async listDir(path = "/", call: CallOptions = {}): Promise<DirListing> {
    const reply = await this.#transport.request("GET", this.#path("list"), {
      query: { path },
      ...callArgs(call),
    });
    return dirListingFromPayload(reply);
  }

  async mkdir(path: string, options: MkdirOptions = {}): Promise<MkdirResult> {
    const body = {
      path,
      mode: options.mode ?? DEFAULT_DIR_MODE,
      parents: options.parents ?? true,
    };
    const reply = await this.#transport.request("POST", this.#path("mkdir"), {
      json: body,
      ...callArgs(options),
    });
    return mkdirResultFromPayload(reply);
  }

  async move(source: string, destination: string, options: MoveOptions = {}): Promise<MoveResult> {
    const body = { source, destination, overwrite: options.overwrite ?? false };
    const reply = await this.#transport.request("POST", this.#path("move"), {
      json: body,
      ...callArgs(options),
    });
    return moveResultFromPayload(reply);
  }

  /** Delete a path (`POST .../fs/delete`); directories need `recursive: true`. */
  async remove(path: string, options: RemoveOptions = {}): Promise<DeleteResult> {
    const body = { path, recursive: options.recursive ?? false };
    const reply = await this.#transport.request("POST", this.#path("delete"), {
      json: body,
      ...callArgs(options),
    });
    return deleteResultFromPayload(reply);
  }

  /**
   * Upload `data` in one `PUT .../fs/upload` request: the raw bytes as the body and
   * `path`, `overwrite`, `mode` and `size_bytes` as query parameters, as the python sdk sends.
   */
  async uploadFile(
    path: string,
    data: UploadData,
    options: UploadOptions = {},
  ): Promise<UploadResult> {
    const query: Query = {
      path,
      overwrite: options.overwrite ?? true,
      mode: options.mode ?? DEFAULT_FILE_MODE,
      size_bytes: byteSize(data),
    };
    const reply = await this.#binary.sendForData("PUT", this.#path("upload"), {
      query,
      accept: JSON_MEDIA_TYPE,
      body: toBody(data),
      ...callArgs(options),
    });
    return uploadResultFromPayload(reply);
  }

  /** Download a whole file into memory; a directory path is rejected (it arrives as tar). */
  async downloadFile(path: string, call: CallOptions = {}): Promise<Uint8Array> {
    const route = this.#path("download");
    const reply = await this.#binary.send(
      "GET",
      route,
      { query: { path }, accept: "*/*", ...callArgs(call) },
      readDownload,
    );
    if (reply.kind === "error") throw replyError(parseJson(reply.text), reply.response);
    if (reply.kind === "tar") {
      throw new InvalidResponseError(`'${path}' is not a file: server sent '${TAR_MEDIA_TYPE}'`);
    }
    return reply.bytes;
  }

  #path(tail: string): string {
    return `${this.#basePath}/${tail}`;
  }

  /** The entry of a path (file, directory or symlink); `NotFound` when it does not exist. */
  stat(path: string, call: CallOptions = {}): Promise<FileEntry> {
    return statEntry(this.#transport, this.#toolboxPath, path, call);
  }
}
