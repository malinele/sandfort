import { describe, expect, it } from "vitest";
import { SandfortClient, type FetchLike } from "../src/index.js";

interface Recorded {
  url: string;
  method: string;
  body: string | undefined;
  headers: Record<string, string>;
}

function stub(queue: Response[]): { fetch: FetchLike; requests: Recorded[] } {
  const requests: Recorded[] = [];
  const fetch: FetchLike = async (input, init) => {
    requests.push({
      url: input,
      method: init.method ?? "GET",
      body: typeof init.body === "string" ? init.body : undefined,
      headers: { ...(init.headers as Record<string, string>) },
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

const GIT = "http://sf.test/v1/sandboxes/sbx_1/toolbox/git";
const TOKEN = "ghp_secret_token";
const CREDENTIAL = { username: "octo", token: TOKEN };
const REMOTE_URL = "https://example.test/r.git";

async function handleFor(queue: Response[]) {
  const { fetch, requests } = stub([ok({ id: "sbx_1", name: "box", state: "started" }), ...queue]);
  const client = new SandfortClient({ baseUrl: "http://sf.test", apiKey: "sf_key", fetch });
  const sandbox = await client.getSandbox("sbx_1");
  requests.length = 0;
  return { git: sandbox.git, requests };
}

function first(requests: Recorded[]): Recorded {
  const item = requests[0];
  if (item === undefined) throw new Error("no request recorded");
  return item;
}

function leaksToken(request: Recorded): boolean {
  const headerText = Object.entries(request.headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
  return request.url.includes(TOKEN) || headerText.includes(TOKEN);
}

describe("git", () => {
  it("clones with the credential last in the body and nowhere else", async () => {
    const { git, requests } = await handleFor([ok({ path: "/work/repo", output: "Cloning" })]);

    const result = await git.clone("https://example.test/r.git", "/work/repo", {
      branch: "main",
      depth: 1,
      credential: CREDENTIAL,
    });

    const sent = first(requests);
    expect(sent.method).toBe("POST");
    expect(sent.url).toBe(`${GIT}/clone`);
    expect(sent.body).toBe(
      '{"url":"https://example.test/r.git","path":"/work/repo","branch":"main","depth":1,' +
        `"credential":{"username":"octo","token":"${TOKEN}"}}`,
    );
    expect(leaksToken(sent)).toBe(false);
    expect(result).toEqual({ path: "/work/repo", output: "Cloning" });
  });

  it("clones without a credential key and omits unset fields", async () => {
    const { git, requests } = await handleFor([ok({ path: "/w" })]);

    const result = await git.clone("https://example.test/r.git", "/w");

    expect(first(requests).body).toBe('{"url":"https://example.test/r.git","path":"/w"}');
    expect(result.output).toBe("");
  });

  it("reads status through a path query and unwraps files", async () => {
    const payload = {
      branch: "main",
      ahead: 1,
      behind: 0,
      files: [{ path: "a.txt", index: "A", worktree: " " }],
    };
    const { git, requests } = await handleFor([ok(payload), ok({ branch: null })]);

    const status = await git.status("/work/repo");
    const bare = await git.status("/work/repo");

    expect(first(requests)).toMatchObject({
      method: "GET",
      url: `${GIT}/status?path=%2Fwork%2Frepo`,
      body: undefined,
    });
    expect(status).toEqual({
      branch: "main",
      ahead: 1,
      behind: 0,
      files: [{ path: "a.txt", index: "A", worktree: " " }],
      isClean: false,
    });
    expect(bare).toEqual({ branch: null, ahead: 0, behind: 0, files: [], isClean: true });
  });

  it("adds '.' by default, accepts one path or a list, and rejects an empty list", async () => {
    const { git, requests } = await handleFor([
      ok({ path: "/w" }),
      ok({ path: "/w" }),
      ok({ path: "/w" }),
    ]);

    await git.add("/w");
    await git.add("/w", "a.txt");
    await git.add("/w", ["a.txt", "b.txt"]);

    expect(requests.map((r) => r.body)).toEqual([
      '{"path":"/w","files":["."]}',
      '{"path":"/w","files":["a.txt"]}',
      '{"path":"/w","files":["a.txt","b.txt"]}',
    ]);
    expect(requests.every((r) => r.url === `${GIT}/add`)).toBe(true);
    await expect(git.add("/w", [])).rejects.toThrow("files must not be empty");
  });

  it("commits with author fields as author_name and author_email", async () => {
    const { git, requests } = await handleFor([ok({ sha: "abc123" }), ok({ sha: "def456" })]);

    const full = await git.commit("/w", "msg", { authorName: "Ada", authorEmail: "ada@x.test" });
    const plain = await git.commit("/w", "msg2");

    expect(requests.map((r) => r.body)).toEqual([
      '{"path":"/w","message":"msg","author_name":"Ada","author_email":"ada@x.test"}',
      '{"path":"/w","message":"msg2"}',
    ]);
    expect(requests[0]?.url).toBe(`${GIT}/commit`);
    expect(full).toEqual({ sha: "abc123" });
    expect(plain.sha).toBe("def456");
    await expect(git.commit("/w", "   ")).rejects.toThrow("commit message must not be empty");
  });

  it("pushes and pulls with remote default origin and the credential in the body only", async () => {
    const { git, requests } = await handleFor([
      ok({ path: "/w", output: "pushed" }),
      ok({ path: "/w", output: "pulled" }),
      ok({ path: "/w" }),
    ]);

    const pushed = await git.push("/w", {
      branch: "main",
      credential: CREDENTIAL,
      remoteUrl: REMOTE_URL,
    });
    const pulled = await git.pull("/w", { remote: "upstream" });
    await git.push("/w");

    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      `POST ${GIT}/push`,
      `POST ${GIT}/pull`,
      `POST ${GIT}/push`,
    ]);
    expect(requests[0]?.body).toBe(
      `{"path":"/w","remote":"origin","branch":"main","remote_url":"${REMOTE_URL}","credential":{"username":"octo","token":"${TOKEN}"}}`,
    );
    expect(requests[1]?.body).toBe('{"path":"/w","remote":"upstream"}');
    expect(requests[2]?.body).toBe('{"path":"/w","remote":"origin"}');
    expect(requests.some((r) => leaksToken(r))).toBe(false);
    expect(pushed.output).toBe("pushed");
    expect(pulled.output).toBe("pulled");
  });

  it("rejects a credential without remoteUrl before any request", async () => {
    const { git, requests } = await handleFor([]);

    await expect(git.push("/w", { credential: CREDENTIAL })).rejects.toThrow(
      "remoteUrl is required when a git credential is given",
    );
    await expect(git.pull("/w", { credential: CREDENTIAL })).rejects.toThrow(
      "remoteUrl is required when a git credential is given",
    );
    expect(requests).toHaveLength(0);
  });

  it("rejects an empty credential field before any request", async () => {
    const { git, requests } = await handleFor([]);

    await expect(
      git.push("/w", { credential: { username: "", token: TOKEN }, remoteUrl: REMOTE_URL }),
    ).rejects.toThrow("username and token must not be empty");
    expect(requests).toHaveLength(0);
  });
});
