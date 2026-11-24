/**
 * Fluent, immutable image DSL, mirroring `sandfort_sdk.image`: every builder method returns a
 * new `Image`. `serialize()` produces exactly the image spec wire form (`schema_version` "1")
 * that `POST /v1/images/builds` takes under `spec`, key for key as the Python DSL does.
 * Structural limits and unsafe values are enforced by the server; the DSL only rejects values
 * that can never be valid (blank names).
 */

import { ValidationError } from "./errors.js";

const SCHEMA_VERSION = "1";
const DEBIAN_SLIM_BASE = "python:3.12-slim";

/** A file written into the image: `destination` path plus inline text `content`. */
export interface ImageFile {
  destination: string;
  content: string;
}

/** The image spec wire form, as `Image.serialize()` returns it. */
export interface ImageSpec {
  schema_version: "1";
  base_image: string;
  pip_packages: string[];
  apt_packages: string[];
  env: Record<string, string>;
  workdir: string | null;
  files: ImageFile[];
}

/** One package name, or an iterable of them (`pipInstall("a", "b")` and `pipInstall(["a", "b"])`). */
export type PackageArg = string | Iterable<string>;

function nonBlank(value: unknown, what: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new ValidationError(`${what} must be a non-empty string`);
  }
  return value;
}

function flatten(items: readonly PackageArg[], what: string): string[] {
  const flat: string[] = [];
  for (const item of items) {
    const group = typeof item === "string" ? [item] : Array.from(item);
    for (const name of group) flat.push(nonBlank(name, what));
  }
  return flat;
}

/** `added` appended in order, skipping names already present (re-adding is a no-op). */
function merged(existing: readonly string[], added: readonly string[]): string[] {
  return Array.from(new Set([...existing, ...added]));
}

interface ImageState {
  baseImage: string;
  pipPackages: readonly string[];
  aptPackages: readonly string[];
  environment: ReadonlyMap<string, string>;
  workingDir: string | null;
  files: readonly ImageFile[];
}

/** Declarative image spec; start with `Image.debianSlim()` or `Image.fromImage(reference)`. */
export class Image {
  readonly #state: ImageState;

  private constructor(state: ImageState) {
    this.#state = state;
  }

  /** Debian slim with Python 3.12 (the pinned `python:3.12-slim` base). */
  static debianSlim(): Image {
    return Image.fromImage(DEBIAN_SLIM_BASE);
  }

  /** Start from any registry image reference. */
  static fromImage(reference: string): Image {
    return new Image({
      baseImage: nonBlank(reference, "image reference"),
      pipPackages: [],
      aptPackages: [],
      environment: new Map(),
      workingDir: null,
      files: [],
    });
  }

  pipInstall(...packages: PackageArg[]): Image {
    const added = flatten(packages, "pip package");
    return this.#with({ pipPackages: merged(this.#state.pipPackages, added) });
  }

  aptInstall(...packages: PackageArg[]): Image {
    const added = flatten(packages, "apt package");
    return this.#with({ aptPackages: merged(this.#state.aptPackages, added) });
  }

  /** Write `content` to `destination`; a later file at the same path replaces it. */
  addFile(destination: string, content: string): Image {
    nonBlank(destination, "file destination");
    if (typeof content !== "string") throw new ValidationError("file content must be a string");
    const kept = this.#state.files.filter((item) => item.destination !== destination);
    return this.#with({ files: [...kept, { destination, content }] });
  }

  /** Set environment variables; later values win over earlier ones. */
  env(values: Readonly<Record<string, string>> = {}): Image {
    const next = new Map(this.#state.environment);
    for (const [name, value] of Object.entries(values)) {
      if (typeof value !== "string") {
        throw new ValidationError(`env value for '${name}' must be a string`);
      }
      next.set(nonBlank(name, "env name"), value);
    }
    return this.#with({ environment: next });
  }

  workdir(path: string): Image {
    return this.#with({ workingDir: nonBlank(path, "workdir") });
  }

  /** The image spec wire form accepted by `POST /v1/images/builds`; a fresh copy on every call. */
  serialize(): ImageSpec {
    const state = this.#state;
    return {
      schema_version: SCHEMA_VERSION,
      base_image: state.baseImage,
      pip_packages: [...state.pipPackages],
      apt_packages: [...state.aptPackages],
      env: Object.fromEntries(state.environment),
      workdir: state.workingDir,
      files: state.files.map((item) => ({ destination: item.destination, content: item.content })),
    };
  }

  #with(change: Partial<ImageState>): Image {
    return new Image({ ...this.#state, ...change });
  }
}
