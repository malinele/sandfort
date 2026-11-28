import { describe, expect, it } from "vitest";
import { INSECURE_BASE_URL_WARNING, SandfortClient } from "../src/index.js";
import { insecureHost, warnIfInsecureBaseUrl } from "../src/insecure-url.js";
import { ok, sandboxPayload, stub } from "./helpers.js";

const KEY = "sf_env_key_do_not_print";
type Coded = Error & { code?: string };

const INSECURE: [string, string][] = [
  ["http://sandfort.test", "sandfort.test"],
  ["http://sandfort.test/", "sandfort.test"],
  ["HTTP://Sandfort.Test:8000", "sandfort.test"],
  ["http://10.0.0.5:8000", "10.0.0.5"],
  ["http://[2001:db8::1]:8000", "2001:db8::1"],
  ["http://user:pw@sandfort.test", "sandfort.test"],
  ["http://localhost.example", "localhost.example"],
];

const SAFE = [
  "https://sandfort.test",
  "https://10.0.0.5",
  "http://localhost:8000",
  "http://LOCALHOST",
  "http://localhost.:8000",
  "http://127.0.0.1:8000",
  "http://127.1.2.3",
  "http://[::1]:8000",
  "",
  "sandfort.test",
  "http://[::1",
];

const REMOTE = ["http://sandfort.test", "http://10.0.0.5:8000"];
const QUIET = ["https://sandfort.test", "http://127.0.0.1:8000", "http://localhost:8000"];

// process.emitWarning fires on process.nextTick, so wait one setImmediate before reading.
async function captureWarnings(build: () => unknown): Promise<Coded[]> {
  const seen: Coded[] = [];
  const listener = (warning: Error): void => {
    if (warning.name === INSECURE_BASE_URL_WARNING) seen.push(warning as Coded);
  };
  process.on("warning", listener);
  try {
    await build();
    await new Promise<void>((resolve) => setImmediate(resolve));
  } finally {
    process.off("warning", listener);
  }
  return seen;
}

describe("insecureHost", () => {
  it.each(INSECURE)("names the remote host of %s", (url, host) => {
    expect(insecureHost(url)).toBe(host);
  });

  it.each(SAFE)("is null for %j", (url) => {
    expect(insecureHost(url)).toBeNull();
  });
});

describe("client base url warning", () => {
  it.each(REMOTE)("warns once for %s, over several calls", async (baseUrl) => {
    const { fetch } = stub([ok(sandboxPayload())]);
    const found = await captureWarnings(async () => {
      const client = new SandfortClient({ baseUrl, apiKey: KEY, fetch });
      await client.getSandbox("sbx_1");
    });
    expect(found).toHaveLength(1);
    const w = found[0];
    expect(w?.name).toBe("InsecureBaseUrlWarning");
    expect(w?.code).toBe("SANDFORT_INSECURE_BASE_URL");
    expect(w?.message).toContain("clear text");
    expect(w?.message).not.toContain(KEY);
  });

  it("builds the exact message", async () => {
    const options = { baseUrl: "http://sandfort.test", apiKey: KEY, fetch: stub([]).fetch };
    const found = await captureWarnings(() => new SandfortClient(options));
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toBe(
      "baseUrl uses http:// for host 'sandfort.test', so the api key is sent in clear text. " +
        "Use https://, or filter InsecureBaseUrlWarning if the network is private and trusted.",
    );
  });

  it("warns once per client, so two clients give two warnings", async () => {
    const found = await captureWarnings(() => {
      const options = { baseUrl: "http://sandfort.test", apiKey: KEY, fetch: stub([]).fetch };
      return [new SandfortClient(options), new SandfortClient(options)];
    });
    expect(found).toHaveLength(2);
  });

  it.each(QUIET)("is quiet for %s", async (baseUrl) => {
    const found = await captureWarnings(
      () => new SandfortClient({ baseUrl, apiKey: KEY, fetch: stub([]).fetch }),
    );
    expect(found).toEqual([]);
  });

  it("names the host and never the userinfo", async () => {
    const found = await captureWarnings(() =>
      warnIfInsecureBaseUrl("http://user:pw@sandfort.test"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain("sandfort.test");
    expect(found[0]?.message).not.toContain("pw@");
    expect(found[0]?.message).not.toContain("user:");
  });

  it("exports the warning name from the package", () => {
    expect(INSECURE_BASE_URL_WARNING).toBe("InsecureBaseUrlWarning");
  });
});
