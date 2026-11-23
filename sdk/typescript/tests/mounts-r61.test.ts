import { describe, expect, it } from "vitest";
import { ValidationError } from "../src/index.js";
import { clientFor } from "./helpers.js";

async function refusal(mountPath: string): Promise<ValidationError> {
  const { client, requests } = clientFor([]);
  const error: unknown = await client
    .createSandbox({ volumes: [{ volumeId: "vol_1", mountPath }] })
    .then(
      () => undefined,
      (caught: unknown) => caught,
    );
  expect(requests).toHaveLength(0);
  expect(error).toBeInstanceOf(ValidationError);
  return error as ValidationError;
}

describe("mount path characters are refused locally", () => {
  it.each([
    [":", "colon", "/data:ro"],
    [",", "comma", "/data,rw"],
    ["\\", "backslash", "/data\\x"],
  ])("rejects %s and names the %s", async (char, name, path) => {
    const error = await refusal(path);
    expect(error.message).toContain(name);
    expect(error.message).toContain(JSON.stringify(char).slice(1, -1));
    expect(error.message).toContain("volumes[0].mountPath");
  });

  it("names the character even when the path is also relative", async () => {
    const error = await refusal("data:ro");
    expect(error.message).toContain("colon");
  });

  it("checks every mount of the list, with its index", async () => {
    const { client, requests } = clientFor([]);
    const volumes = [
      { volumeId: "vol_1", mountPath: "/ok" },
      { volumeId: "vol_2", mountPath: "/bad,path" },
    ];
    await expect(client.createSandbox({ volumes })).rejects.toThrow("volumes[1].mountPath");
    expect(requests).toHaveLength(0);
  });
});

describe("mount path must be absolute", () => {
  it.each(["data", "./data", "../data", "C/data"])("rejects %s", async (path) => {
    const error = await refusal(path);
    expect(error.message).toContain("absolute");
  });

  it("leaves the directory lists to the server", async () => {
    const { client, requests } = clientFor([]);
    await client.createSandbox({ volumes: [{ volumeId: "vol_1", mountPath: "/etc" }] }).catch(
      () => undefined,
    );
    expect(requests).toHaveLength(1);
  });
});
