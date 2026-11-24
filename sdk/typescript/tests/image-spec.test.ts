import { describe, expect, it } from "vitest";
import { Image, SandfortError, ValidationError } from "../src/index.js";

/**
 * Fixtures produced by the Python DSL (`sandfort_sdk.image.Image.serialize()` through
 * `json.dumps`, 2026-11-24) for the same inputs as the TypeScript calls below.
 */
const PY_FULL =
  '{"schema_version": "1", "base_image": "python:3.12-slim", "pip_packages": ["requests", "numpy"], ' +
  '"apt_packages": ["git"], "env": {"A": "1", "B": "2"}, "workdir": "/app", ' +
  '"files": [{"destination": "/app/x.txt", "content": "hi\\n"}]}';
const PY_MINIMAL =
  '{"schema_version": "1", "base_image": "python:3.12-slim", "pip_packages": [], ' +
  '"apt_packages": [], "env": {}, "workdir": null, "files": []}';
const PY_REPLACED =
  '{"schema_version": "1", "base_image": "alpine:3.20", "pip_packages": ["a", "b"], ' +
  '"apt_packages": [], "env": {}, "workdir": null, "files": [{"destination": "/g", "content": "2"}, ' +
  '{"destination": "/f", "content": "3"}]}';

/** Key order is part of the Python output, so compare the serialized text, not just values. */
function wire(image: Image): string {
  return JSON.stringify(image.serialize());
}

function pyWire(fixture: string): string {
  return JSON.stringify(JSON.parse(fixture));
}

describe("Image spec shape matches the Python DSL", () => {
  it("serializes the full builder chain to the Python wire form", () => {
    const image = Image.debianSlim()
      .pipInstall("requests", "numpy")
      .aptInstall("git")
      .env({ A: "1", B: "2" })
      .workdir("/app")
      .addFile("/app/x.txt", "hi\n");

    expect(wire(image)).toBe(pyWire(PY_FULL));
    expect(image.serialize()).toEqual(JSON.parse(PY_FULL));
  });

  it("serializes the bare debian slim base with empty lists and a null workdir", () => {
    expect(wire(Image.debianSlim())).toBe(pyWire(PY_MINIMAL));
  });

  it("flattens iterables, skips repeated packages and lets a later file replace an earlier one", () => {
    const image = Image.fromImage("alpine:3.20")
      .pipInstall(["a", "b"], "a")
      .addFile("/f", "1")
      .addFile("/g", "2")
      .addFile("/f", "3");

    expect(wire(image)).toBe(pyWire(PY_REPLACED));
  });

  it("uses the pinned python:3.12-slim base for debianSlim", () => {
    expect(Image.debianSlim().serialize().base_image).toBe("python:3.12-slim");
  });

  it("lets later env values win without moving the key", () => {
    const image = Image.debianSlim().env({ A: "1", B: "2" }).env({ A: "9", C: "3" });

    expect(JSON.stringify(image.serialize().env)).toBe('{"A":"9","B":"2","C":"3"}');
  });

  it("accepts an env call without values", () => {
    expect(Image.debianSlim().env().serialize().env).toEqual({});
  });
});

describe("Image is immutable", () => {
  it("returns a new image from every builder method and leaves the receiver unchanged", () => {
    const base = Image.debianSlim();
    const derived = base
      .pipInstall("x")
      .aptInstall("y")
      .env({ K: "v" })
      .workdir("/w")
      .addFile("/f", "c");

    expect(derived).not.toBe(base);
    expect(wire(base)).toBe(pyWire(PY_MINIMAL));
    expect(derived.serialize().pip_packages).toEqual(["x"]);
  });

  it("hands out a copy: changing a serialized spec does not change the image", () => {
    const image = Image.debianSlim().pipInstall("x");
    const first = image.serialize();
    first.pip_packages.push("evil");
    first.env["EVIL"] = "1";

    expect(image.serialize().pip_packages).toEqual(["x"]);
    expect(image.serialize().env).toEqual({});
  });
});

describe("Image rejects values that can never be valid", () => {
  const blank = ["", "   "];

  it.each(blank)("fromImage refuses the blank reference %j", (reference) => {
    expect(() => Image.fromImage(reference)).toThrow(ValidationError);
  });

  it.each(blank)("pipInstall and aptInstall refuse the blank package %j", (name) => {
    expect(() => Image.debianSlim().pipInstall(name)).toThrow(ValidationError);
    expect(() => Image.debianSlim().aptInstall(["ok", name])).toThrow(ValidationError);
  });

  it("refuses a blank file destination and non-string content", () => {
    expect(() => Image.debianSlim().addFile(" ", "x")).toThrow(ValidationError);
    expect(() => Image.debianSlim().addFile("/f", 1 as unknown as string)).toThrow(
      ValidationError,
    );
  });

  it("refuses a blank env name and a non-string env value", () => {
    expect(() => Image.debianSlim().env({ "": "x" })).toThrow(ValidationError);
    expect(() => Image.debianSlim().env({ A: 1 as unknown as string })).toThrow(ValidationError);
  });

  it("refuses a blank workdir", () => {
    expect(() => Image.debianSlim().workdir("")).toThrow(ValidationError);
  });

  it("raises errors that belong to the SDK error hierarchy", () => {
    expect(() => Image.fromImage("")).toThrow(SandfortError);
  });
});
