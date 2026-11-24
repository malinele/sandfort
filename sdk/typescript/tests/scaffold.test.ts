import { describe, expect, it } from "vitest";
import * as sdk from "../src/index.js";

describe("export surface", () => {
  it("exposes the client, error classes and constants, and no internal helpers", () => {
    const names = Object.keys(sdk).sort();

    expect(names).toEqual(
      [
        "ApiError",
        "Conflict",
        "DEFAULT_POLL_INTERVAL_S",
        "DEFAULT_RETRIES",
        "DEFAULT_TIMEOUT_MS",
        "DEFAULT_WAIT_TIMEOUT_S",
        "Forbidden",
        "Image",
        "InvalidResponseError",
        "ISOLATION_TIERS",
        "InvalidState",
        "NotFound",
        "PACKAGE_NAME",
        "RateLimited",
        "Sandbox",
        "MAX_RETRIES",
        "MAX_RETRY_AFTER_S",
        "MAX_TOTAL_RETRY_WAIT_S",
        "RequestAbortedError",
        "RequestTimeoutError",
        "SandboxFailedError",
        "SandboxTimeoutError",
        "SandfortClient",
        "SandfortError",
        "SNAPSHOT_EXPORT_MIN_TIMEOUT_MS",
        "SnapshotFailedError",
        "SnapshotTimeoutError",
        "PtySession",
        "ptyConnectUrl",
        "verifyExport",
        "verifyHead",
        "TransportError",
        "USER_AGENT",
        "Unauthorized",
        "VERSION",
        "ValidationError",
        "ValidationFailed",
        "buildInfo",
      ].sort(),
    );
  });

  it("uses the python sdk defaults for the wait loop", () => {
    expect(sdk.DEFAULT_WAIT_TIMEOUT_S).toBe(120);
    expect(sdk.DEFAULT_POLL_INTERVAL_S).toBe(0.5);
  });
});
