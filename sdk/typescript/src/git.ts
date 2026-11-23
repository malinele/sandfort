/**
 * Git toolbox of one sandbox, mirroring `sandfort_sdk.git.Git`: clone, status, add, commit,
 * push and pull. The python facade has no `log`, and neither does the server, so none here.
 *
 * A `GitCredential` is passed per call and serialized only into that request's JSON body
 * (`credential: {username, token}`); it is never stored, and never put in a header or URL.
 */

import { ValidationError } from "./errors.js";
import { asArray, asRecord, compact, requiredString, stringOrNull } from "./models.js";
import { callArgs, type CallOptions } from "./resilience.js";
import type { Transport } from "./transport.js";

export const DEFAULT_REMOTE = "origin";

export interface GitCredential {
  username: string;
  token: string;
}

export interface GitFileStatus {
  path: string;
  index: string;
  worktree: string;
}

export interface GitStatus {
  branch: string | null;
  ahead: number;
  behind: number;
  files: readonly GitFileStatus[];
  /** True when no file is listed. */
  isClean: boolean;
}

/** Outcome of clone, add, push and pull; `output` is credential-scrubbed by the server. */
export interface GitResult {
  path: string;
  output: string;
}

export interface GitCommitResult {
  sha: string;
}

export interface GitCloneOptions extends CallOptions {
  branch?: string;
  depth?: number;
  credential?: GitCredential;
}

export interface GitCommitOptions extends CallOptions {
  authorName?: string;
  authorEmail?: string;
}

export interface GitSyncOptions extends CallOptions {
  /** Remote name (default `"origin"`). */
  remote?: string;
  branch?: string;
  credential?: GitCredential;
  /**
   * The http(s) url of the remote. Required together with `credential`: the server binds the
   * token to this host and pushes or pulls against this url, not against whatever url the
   * sandbox's own git config names for `remote`.
   */
  remoteUrl?: string;
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === "number" ? value : fallback;
}

function credentialPayload(credential: GitCredential): Record<string, string> {
  if (credential.username === "" || credential.token === "") {
    throw new ValidationError("git credential username and token must not be empty");
  }
  return { username: credential.username, token: credential.token };
}

/** Drop unset fields, then append `credential` last (python `_body`). */
function body(
  fields: Record<string, unknown>,
  credential: GitCredential | undefined,
): Record<string, unknown> {
  const out = compact(fields);
  return credential === undefined ? out : { ...out, credential: credentialPayload(credential) };
}

function syncBody(path: string, options: GitSyncOptions): Record<string, unknown> {
  if (options.credential !== undefined && options.remoteUrl === undefined) {
    throw new ValidationError("remoteUrl is required when a git credential is given");
  }
  return body(
    {
      path,
      remote: options.remote ?? DEFAULT_REMOTE,
      branch: options.branch,
      remote_url: options.remoteUrl,
    },
    options.credential,
  );
}

export function gitStatusFromPayload(data: unknown): GitStatus {
  const raw = asRecord(data, "git status");
  const files = asArray(raw["files"] ?? [], "git status files").map((item): GitFileStatus => {
    const what = "git file status";
    const entry = asRecord(item, what);
    return {
      path: requiredString(entry, "path", what),
      index: requiredString(entry, "index", what),
      worktree: requiredString(entry, "worktree", what),
    };
  });
  return {
    branch: stringOrNull(raw["branch"]),
    ahead: numberOr(raw["ahead"], 0),
    behind: numberOr(raw["behind"], 0),
    files,
    isClean: files.length === 0,
  };
}

export function gitResultFromPayload(data: unknown): GitResult {
  const raw = asRecord(data, "git result");
  const output = raw["output"];
  return {
    path: requiredString(raw, "path", "git result"),
    output: typeof output === "string" ? output : "",
  };
}

export function gitCommitFromPayload(data: unknown): GitCommitResult {
  return { sha: requiredString(asRecord(data, "git commit"), "sha", "git commit") };
}

/** Git calls of one sandbox; `toolboxPath` is `/v1/sandboxes/{id}/toolbox`. */
export class Git {
  readonly #transport: Transport;
  readonly #basePath: string;

  constructor(transport: Transport, toolboxPath: string) {
    this.#transport = transport;
    this.#basePath = `${toolboxPath}/git`;
  }

  async clone(url: string, path: string, options: GitCloneOptions = {}): Promise<GitResult> {
    const json = body(
      { url, path, branch: options.branch, depth: options.depth },
      options.credential,
    );
    return gitResultFromPayload(await this.#post("clone", json, options));
  }

  async status(path: string, call: CallOptions = {}): Promise<GitStatus> {
    const reply = await this.#transport.request("GET", `${this.#basePath}/status`, {
      query: { path },
      ...callArgs(call),
    });
    return gitStatusFromPayload(reply);
  }

  /** Stage `files` (a path or a list of paths; default `["."]`). */
  async add(
    path: string,
    files: string | readonly string[] = ["."],
    call: CallOptions = {},
  ): Promise<GitResult> {
    const names = typeof files === "string" ? [files] : [...files];
    if (names.length === 0) throw new ValidationError("files must not be empty");
    return gitResultFromPayload(await this.#post("add", { path, files: names }, call));
  }

  async commit(
    path: string,
    message: string,
    options: GitCommitOptions = {},
  ): Promise<GitCommitResult> {
    if (message.trim() === "") throw new ValidationError("commit message must not be empty");
    const json = body(
      { path, message, author_name: options.authorName, author_email: options.authorEmail },
      undefined,
    );
    return gitCommitFromPayload(await this.#post("commit", json, options));
  }

  async push(path: string, options: GitSyncOptions = {}): Promise<GitResult> {
    return gitResultFromPayload(await this.#post("push", syncBody(path, options), options));
  }

  async pull(path: string, options: GitSyncOptions = {}): Promise<GitResult> {
    return gitResultFromPayload(await this.#post("pull", syncBody(path, options), options));
  }

  #post(tail: string, json: Record<string, unknown>, call: CallOptions): Promise<unknown> {
    return this.#transport.request("POST", `${this.#basePath}/${tail}`, {
      json,
      ...callArgs(call),
    });
  }
}
