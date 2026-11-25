/**
 * Why a sandbox settled in `error`, as `SandboxInfo.errorCode` reports it. The same 13 values,
 * in the same order, as `ERROR_CODES` in `src/sandfort/domain/sandbox.py` (a repo test keeps
 * them equal). Keep this array free of comments so that test can read it.
 */
export const SANDBOX_ERROR_CODES = [
  "image_not_found",
  "registry_unreachable",
  "registry_tls_error",
  "image_access_denied",
  "invalid_image_reference",
  "start_failed",
  "timeout",
  "reset_failed",
  "container_missing",
  "container_exited",
  "node_lost",
  "egress_unavailable",
  "internal",
] as const;

export type SandboxErrorCode = (typeof SANDBOX_ERROR_CODES)[number];
