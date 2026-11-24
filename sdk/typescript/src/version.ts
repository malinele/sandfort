/** SDK identity. `VERSION` is kept equal to `package.json`'s `version` by tests/surface.test.ts. */

export const VERSION = "0.2.0";
export const PACKAGE_NAME = "@sandfort/sdk";
/** Sent as the `User-Agent` of every request (ignored by browsers). */
export const USER_AGENT = `sandfort-sdk-typescript/${VERSION}`;

export interface BuildInfo {
  name: string;
  version: string;
}

/** Which SDK build this is (python: `sandfort_sdk.build_info()`, minus the wheel's commit stamp). */
export function buildInfo(): BuildInfo {
  return { name: PACKAGE_NAME, version: VERSION };
}
