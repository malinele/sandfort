# Changelog

Note: commit hashes in this file refer to the private pre-publication history and are kept as internal references; they do not resolve in the public repository. Some entries also reference internal paths (`.context/`, `marketing/pilot/`) that are not part of the public tree; the guides for public use are `docs/connect-guide.md` and `docs/beta-quickstart.md`.

All notable changes to the Sandfort product are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project intends to
use [Semantic Versioning](https://semver.org/spec/v2.0.0.html), but there are no published
releases yet.

This file is the source of truth for what the product actually does. Each entry is derived from the commit
history (`git log`) and verified in the code. The hash in parentheses is the commit that introduced the change. Dates are
commit dates; they are not release dates.

## [Unreleased]

The version in `pyproject.toml` and in the OpenAPI spec is `0.1.0`. Every build deployed to the hosted
beta carries the git tag `v0.1.0-beta.<runda>` on the exact commit. No document, including this
header, names the current tag: a file inside a tagged commit cannot name its own tag
and would always lag one deployment behind. The current build is read from `build_sha` in `GET /v1/status` and
compared with the commit of the newest tag `v0.1.0-beta.<runda>` (an annotated tag is resolved to its commit with
`^{commit}`); the release note `RELEASE.txt` in the delivery names the same tag and commit
(`docs/beta-terms.md`, section 5). An official `0.1.0` release does not exist and the release date is not
determined. Numbers (tests, commits, HTTP operations) are not kept in this header because they go stale quickly:
the test count is in `README.md` (Status section), and the HTTP operation count is computed from the exported spec
`openapi/sandfort.v1.json`.

Round headings in the "Fixes outside phases" section are worded relative to the previous tag ("after tag
`v0.1.0-beta.N-1`") and stay that way permanently, without later renaming once the round tag is delivered:
the heading is accurate both before and after deployment, so it never contradicts the deployment.

Convention for the hash of documentation entries: the "Documentation" entry of the newest round carries the description "(this
commit; the hash is recorded in the next round)", because a commit cannot name its own hash. The next
round replaces that description with the real hash from `git log`.

### Documentation and site (2026-11-10)

#### Changed
- **Landing and docs site**: `site/index.html` is the only version of the landing page; the numbers on it follow the spec and tests.
- **docs.sandfort.dev**: generated from `docs/beta-terms.md`, `docs/operations.md` and `marketing/pilot/beta-connect-guide.md` (`scripts/build_docs_site.py`, output in `site/docs/`), with the landing page style; `openapi.json` is a copy of the spec.
- **`/docs` and `/redoc` on the API**: dark theme aligned with the landing page (`src/sandfort/api/docs_theme.py`); CSP and SRI unchanged.
- Removed the comparison with competitors from the landing page; dead domains `*.lokalasistent.com` replaced with `sandfort.dev`.

#### Added
- **Landing, Governance**: animated display of the audit chain instead of a static terminal, CSS only (4261656). Five chained rows; `evt_1042` was rewritten from `request.denied` to `sandbox.start`, and `audit-verify` reports `hash_mismatch: recomputed hash differs` on that row and exits with 3. The text matches `admin_cli audit-verify` and `ChainFinding.render()`. With `prefers-reduced-motion`, the final state is shown.

#### Fixed
- **Landing script blocked by CSP**: The CSP of the `sandfort.dev` site (`landing.conf` in the `sandfort-static-nginx` ConfigMap) had no `script-src`, so the browser blocked the inline script: the tabs in the "Agent loop" section and the Hosted beta / Self-hosted switch did not respond, and the hero REPL did not animate. The script was moved to `site/landing.js`, `deploy/redeploy-beta.sh landing` now ships it too, and the landing CSP gets `script-src 'self'` (without `'unsafe-inline'`, same as docs). Commit ced4b7d.

### Fixes outside phases

#### Round 79 (after tag v0.1.0-beta.81; the Kubernetes kit names the published image)
- **feat(mcp): package the MCP server as sandfort-mcp (PyPI) with server.json for the MCP
  registry.** `mcp_server/pyproject.toml` builds the single module `sandfort_mcp` with the
  console script `sandfort-mcp`, and `mcp_server/README.md` is the long description. `server.json`
  in the repo root describes the stdio package for the registry. No tool or behaviour changed.
  (`mcp_server/pyproject.toml`, `server.json`, `tests/test_mcp_package_r78.py`; this commit;
  the hash is recorded in the next round)
- **feat(ts-sdk): signed audit trailer verification and nullable `imageRef` (0.2.0, BREAKING).**
  TypeScript SDK 0.2.0 changes `SnapshotInfo.imageRef` from `string` to `string | null`: the
  server answers `image_ref: null` to label-scoped API keys (`openapi/sandfort.v1.json`,
  `SnapshotResponse.image_ref`), and 0.1.x rejected that answer with `InvalidResponseError`, so
  every snapshot call failed for such a key. Code that reads `imageRef` as a string must handle
  `null`. It also adds verification of the signed `audit_head` trailer of an audit export, at
  parity with the Python SDK and with no new runtime dependency (`node:crypto`):
  `verifyHead(headLine, publicKey)` (Ed25519 over the head without `signature` and `hmac`,
  compact sorted-key ASCII JSON; the key in the line is only compared with the trust anchor;
  reasons `unsigned`, `signature`, `key_mismatch`, `undated`, `future_signed_at`) and
  `verifyExport(lines, publicKey, { allowUnchained?, previous? })` (content binding with row
  count, first row id and SHA-256, last row against the head, `prev_hash` linkage, rows without
  a hash, byte-prefix continuation). `client.audit.verifyHead`, `client.audit.verifyExport` and
  `client.audit.publicKey()` accept `"status"` as the key to read `audit_public_key` from
  `GET /v1/status`, and `client.status()` now returns `auditPublicKey` and
  `auditKeyFingerprint`. As in the Python SDK, the keyed row hashes and the head `hmac` are not
  recomputed, so only `client.audit.verifyChain()` proves the whole chain. Internally
  `src/client.ts` was split into `client-base.ts`, `client-options.ts`, `client-create.ts` and
  `client-waits.ts` (every source file is under 400 lines); no export changed. The stale
  `package-lock.json` version (0.1.7) was regenerated. The TypeScript SDK still has no members,
  SSO or SCIM client. (`sdk/typescript/src/audit-head.ts`, `sdk/typescript/src/audit-export-verify.ts`,
  `sdk/typescript/src/audit-scan.ts`, `sdk/typescript/src/snapshots.ts`,
  `sdk/typescript/tests/audit-head.test.ts`, `sdk/typescript/tests/audit-export-verify.test.ts`,
  `sdk/typescript/tests/snapshot-image-ref.test.ts`; this commit; the hash is recorded in the
  next round)
- **feat(ts-sdk): image builder (0.1.10).** TypeScript SDK 0.1.10 adds the declarative image
  builder of the Python SDK: an immutable `Image` DSL (`Image.debianSlim()`, `Image.fromImage`,
  `pipInstall`, `aptInstall`, `env`, `workdir`, `addFile`, `serialize()`; the spec JSON is
  checked against output of the Python DSL for the same inputs), `client.buildSnapshot(image,
  { name? })` (`POST /v1/images/builds`; a raw wire-form spec is also accepted) and
  `client.followBuildLogs(snapshotId)` (`GET /v1/images/builds/{snapshot_id}/logs`, yielding
  `log` events and the final `state` event). The TypeScript SDK still has no members, SSO or
  SCIM client and does not verify the signed audit trailer. (`sdk/typescript/src/image.ts`,
  `sdk/typescript/src/image-builds.ts`, `sdk/typescript/tests/image-spec.test.ts`,
  `sdk/typescript/tests/image-builds.test.ts`; this commit; the hash is recorded in the next
  round)
- **feat(ts-sdk): interactive PTY.** TypeScript SDK 0.1.9 adds the PTY client: `createPty`,
  `connectPty`, `listPtys`, `getPty`, `resizePty`, `deletePty` and a `PtySession`
  (async-iterate output bytes, `send`, REST `resize`, `exitCode` from the 4000+n close
  code; 4401 close raises `Unauthorized`). `connectPty` dials with the global `WebSocket`
  (Node 22+ or a browser) or a `webSocket` factory passed as a client option; the package
  keeps zero runtime dependencies. (`sdk/typescript/src/pty.ts`; this commit; the hash is
  recorded in the next round)
- **feat(sdk,cli,ts): `inherit_resources` reaches all three clients; snapshots expose their
  recorded resources.** The Python SDK gains keyword-only `inherit_resources: bool = False` on
  `create_sandbox` (sync and async; the key is sent only when True) and `SnapshotInfo.resources`
  (`Resources | None`) (05a51578). The CLI gains `sandbox create --inherit-resources`, and
  `sandfort snapshot` detail output prints `cpu_millicores`/`memory_mib`/`disk_gib` rows when
  recorded (2316fb37). The TypeScript SDK 0.1.8 gains `inheritResources` on `createSandbox`
  and `SnapshotInfo.resources` (`Resources | null`); the OpenAPI conformance test now covers
  the field (`sdk/typescript/src/create-body.ts`, `sdk/typescript/src/snapshots.ts`; this
  commit; the hash is recorded in the next round). Closes the "SDK/CLI/TypeScript parameters
  are follow-ups" note of the snapshot-resources entry below.
- **feat(preflight): a prod tier map with a blank runtime is refused unless explicitly
  acknowledged.** An explicit `SANDFORT_ISOLATION_RUNTIMES` entry like `container=` means the
  tier runs on whatever the daemon default runtime is; prod preflight now refuses that start
  and names the blank tiers, unless `SANDFORT_ALLOW_DEFAULT_RUNTIME_TIER=true` accepts it.
  The gvisor/microvm family check is also repeated in preflight for settings built in code.
  Legacy single-runtime mode (no tier map) is unchanged. New `tier runtimes` admin doctor row
  mirrors the gate; `deploy/node-setup.sh` and the runbook example now recommend
  `container=runc`. (`src/sandfort/preflight.py`, `src/sandfort/config.py`,
  `src/sandfort/admin_doctor_rows.py`, `src/sandfort/admin_doctor.py`; this commit; the hash
  is recorded in the next round)
- **feat(api): snapshots record the source sandbox's resources; creates can adopt them with
  `inherit_resources`.** A snapshot taken from a sandbox now stores the source's
  `cpu_millicores`, `memory_mib` and `disk_gib` (migration 0026; `SnapshotResponse` exposes
  them, null for registered or built images and for older rows). `POST /v1/sandboxes` gains an
  opt-in `inherit_resources: bool` flag: from a snapshot with recorded values, each resource
  field the request did not set explicitly is taken from the record (explicit fields win); the
  per-sandbox maximum is re-checked after the merge (422, no clamping), and a snapshot without
  recorded resources makes the flag a no-op. Default behavior is unchanged. SDK/CLI/TypeScript
  parameters are follow-ups. (`src/sandfort/services/snapshot_resources.py`,
  `src/sandfort/migrations/versions/r0026_snapshot_resources.py`; this commit; the hash is
  recorded in the next round)
- **feat(api): the per-org live-log-stream cap now covers command-log follow and build-log
  SSE.** The two remaining follow endpoints (`GET .../commands/{id}/logs/follow` and `GET
  /v1/snapshots/{id}/logs`) take a slot from the same `SANDFORT_MAX_LOG_STREAMS_PER_ORG` pool
  as container-log follow, so one cap bounds all live log streams of an org; the slot is held
  before the command or build lookup, over the cap the answer is 503 `CAPACITY` with
  `Retry-After: 30`, and the slot frees when the stream closes, including never-read bodies.
  (`src/sandfort/api/held_stream.py` `capped_body`,
  `src/sandfort/api/routes/toolbox/sessions.py`, `src/sandfort/api/routes/image_builds.py`;
  this commit; the hash is recorded in the next round)
- **feat(mcp): filesystem tools for the stdio MCP server.** Six new tools next to the
  existing eight: `list_directory` (at most 1000 entries, `truncated` flag), `stat_path`,
  `make_directory`, `delete_path` (`recursive` off by default), `upload_binary_file` and
  `download_binary_file` (base64; the 1 MiB limit of the text tools applies, checked before
  decoding on upload; base64 inflates the payload by about a third). Same error convention as
  the existing tools (`error: <message>`). (`mcp_server/sandfort_mcp.py`; this commit; the
  hash is recorded in the next round)
- **feat(api): per-org cap on live container-log follow streams.** `GET
  /v1/sandboxes/{id}/logs?follow=true` now takes a per-org slot
  (`SANDFORT_MAX_LOG_STREAMS_PER_ORG`, default 16, per process, `0` = no cap); over the cap
  the answer is 503 `CAPACITY` with `Retry-After: 30` and no audit row is written for the
  refused follow. The slot frees when the stream closes, including bodies the client never
  reads (`weakref.finalize` on the wrapped generator). Non-follow log reads take no slot;
  command-log follow and build-log SSE stay uncapped and remain on the roadmap. Terminals and
  async commands were already capped. (`src/sandfort/api/routes/sandbox_logs.py`,
  `src/sandfort/api/held_stream.py`, `src/sandfort/config.py`, `src/sandfort/api/wiring.py`;
  this commit; the hash is recorded in the next round)
- **feat(ops): optional bearer token for `GET /metrics`.** With `SANDFORT_METRICS_TOKEN` set
  (at least 32 printable ASCII characters), the endpoint requires `Authorization: Bearer
  <token>` — compared in constant time — and answers 401 with one fixed message on any
  failure, before touching the database; unset, `/metrics` stays open as before. The token is
  kept out of `repr(Settings)` and out of error texts, and the route stays outside the OpenAPI
  spec. Keep the endpoint cluster-internal either way: the token travels in clear text without
  TLS in front. (`src/sandfort/api/metrics_auth.py`, `src/sandfort/config.py`,
  `src/sandfort/api/app.py`; this commit; the hash is recorded in the next round)
- **feat(toolbox): post-exec death probe settles a sandbox killed right after an exit-0
  exec.** A background fork bomb lets an exec answer exit 0 and kills the container a moment
  later; the row kept saying `started` until the next exec or the periodic reconciler pass. On
  the `gvisor` and `microvm` tiers the exec route now schedules one best-effort probe task per
  sandbox that re-inspects the container 2, 6 and 15 seconds after the latest exec and settles
  a dead one through `Reconciler.mark_stopped_unexpectedly` (state `stopped`, stop cause
  `container_exited`, `sandbox.drift_detected` audit row, existing lifecycle event). A new exec
  extends the pending probe instead of adding a task; the probe never raises into the exec
  path and the reconciler pass stays the safety net. The exec response itself still reports
  exit 0 — the probe settles the row, it does not rewrite the answer.
  (`src/sandfort/api/death_probe.py`, `src/sandfort/api/routes/toolbox/process.py`; this
  commit; the hash is recorded in the next round)
- **feat(sdk,cli): sandbox resize in the Python SDK and the CLI.** `Sandbox.resize` and
  `AsyncSandbox.resize` (keyword-only `cpu_millicores`, `memory_mib`, `disk_gib`; at least one
  required, client-side bounds match the server schema) call `POST /v1/sandboxes/{id}/resize`
  and update the handle, mirroring `reset`; `sandfort sandbox resize <sandbox>
  --cpu-millicores/--memory-mib/--disk-gib` renders the updated sandbox and honours the global
  `--json`. Resize still applies to stopped sandboxes only (server rule, 409 otherwise); the
  TypeScript SDK already had it (checked 2026-11-16). (`sdk/python/src/sandfort_sdk/sandbox.py`,
  `sdk/python/src/sandfort_sdk/handles.py`, `cli/src/sandfort_cli/resize_cmd.py`; this commit;
  the hash is recorded in the next round)
- **feat(preflight): a prod start without an audit chain key is refused unless explicitly
  acknowledged.** Without `SANDFORT_AUDIT_CHAIN_KEY` the audit chain is an unkeyed SHA-256 that
  anyone who can write the database can rewrite consistently; until now prod only logged a
  warning. `check_preflight` now refuses that start; setting
  `SANDFORT_UNKEYED_AUDIT_CHAIN_ACKNOWLEDGED=true` (new `Settings` field) starts without a key.
  `Settings.from_env` still does not raise for a missing chain key — the gate lives in preflight,
  like the host-capacity gate. The admin doctor's `audit keys` row mirrors the gate: FAIL in prod
  with neither key and no acknowledgement, WARN when acknowledged; dev and test are unchanged.
  The hosted beta already sets a chain key, so it is unaffected. (`src/sandfort/preflight.py`,
  `src/sandfort/config.py`, `src/sandfort/admin_doctor_rows.py`; this commit; the hash is
  recorded in the next round)
- **chore(deploy): the Kubernetes kit and the runbook name the published image
  `ghcr.io/malinele/sandfort:v0.1.0-beta.81` instead of the `registry.example.com/sandfort:TAG`
  placeholder.** The repository and the GHCR package are public since tag `v0.1.0-beta.81`
  (anonymous pull verified 2026-11-23). Building from `deploy/Dockerfile` and pushing to your own
  registry remains supported, and is required for older tags, which have no published image.
  (`deploy/k8s/api.yaml`, `deploy/k8s/kustomization.yaml`, `deploy/k8s/README.md`,
  `docs/operations.md`; 740e20fa)
- **docs(recipes): agent tool loop — wiring a model's tool-use loop to a sandbox through the
  Python SDK.** `docs/recipes/agent-tool-loop.md` shows three tools (`run_command`,
  `write_file`, `read_file`) over `process_exec` and the fs API, driven by the Anthropic SDK
  tool runner; `examples/agent_tool_loop.py` runs the same loop with a scripted stand-in for
  the model, so it needs no model API key and exits non-zero on failure (ran locally against
  real Docker: `AGENT TOOL LOOP: PASS`, 3.9 s). (912053eb)
- **docs(recipes): OpenAI tool loop — the same three tools driven by a hand-written Chat
  Completions tool-calling loop.** `docs/recipes/openai-tool-loop.md` shows the `tools` JSON
  Schema definitions, executing `tool_calls` and appending `role: "tool"` results keyed by
  `tool_call_id`; `examples/openai_tool_loop.py` runs the loop with a scripted stand-in for the
  model, so it needs no `openai` package and no API key and exits non-zero on failure (ran
  locally against real Docker: `OPENAI TOOL LOOP: PASS`, 3.9 s). The OpenAI request and response
  side is not exercised by the example. (this commit; the hash is recorded in the next round)

#### Round 78 (after tag v0.1.0-beta.80; TypeScript SDK 0.1.7: snapshot export download)
- **feat(ts-sdk): snapshot export — download of the `docker save` tar from the TypeScript SDK.**
  `client.exportSnapshotStream(id)` streams the tar chunk by chunk (`GET /v1/snapshots/{id}/export`,
  `Accept: application/x-tar`), `client.exportSnapshotBytes(id)` returns the whole tar in memory;
  the server responds 409 (`InvalidState`) while the snapshot is not `ready`. The per-request timeout of the export
  has a lower bound `SNAPSHOT_EXPORT_MIN_TIMEOUT_MS` (1 h) on the whole stream, body included
  (an explicit `timeoutMs` replaces it; `deadlineMs` does not raise it); an empty `snapshotId` is a
  `ValidationError` before sending; abort (`AbortSignal`), a wrong 2xx content-type and a body without
  a stream are mapped to typed errors following the audit export pattern.
  (`sdk/typescript/src/snapshot-export.ts`, `snapshots.ts`, `client.ts`, `index.ts`; tests
  `tests/snapshot-export.test.ts`, TDD, manual mutants; package version 0.1.7)

#### Round 77 (after tag v0.1.0-beta.80; TypeScript SDK 0.1.6: snapshot registration)
- **feat(ts-sdk): `registerSnapshot` — registering a registry image as a snapshot from the
  TypeScript SDK.** `client.registerSnapshot(image, { name?, labels? })` and
  `client.snapshots.register(...)` send `POST /v1/snapshots` (body `{image, name?, labels?}`,
  same shape as Python `client.snapshots.register`); the server pulls the image and responds `ready`.
  An empty image and invalid labels are rejected before sending (`ValidationError`, same rules as
  volume labels). Snapshot export remains uncovered in the TS SDK (REST). (`sdk/typescript/src/snapshots.ts`,
  `client.ts`, `index.ts`; tests `tests/snapshot-register.test.ts`, TDD, 2 manual mutants
  killed; package version 0.1.6)

#### Round 76 (after tag v0.1.0-beta.79; snapshot export without `/.dockerenv`, design partner finding E-001 of 2026-11-18)
- **fix(export): the export tar filter also drops Docker's `/.dockerenv` marker (finding E-001,
  round E of snapshot export, closed PASS with an accepted LOW finding).** `docker export`
  materializes a zero-byte `/.dockerenv` even for a never-started container (reproduced
  outside the beta host on the pinned `busybox:1.36` digest), so the exported image carried
  a file the source image does not have. The filter `drop_reserve_file` was renamed to
  `drop_platform_members` and drops root-level platform members (`/.sandfort-reserve`
  and `/.dockerenv`); nested `opt/.dockerenv` and similar user files are kept.
  (`src/sandfort/drivers/docker/tar_filter.py`, `image_export.py`; tests
  `tests/test_snapshot_export_reserve.py` — new predicate `is_platform_member`, offline
  check of the exported tar's members and in the `@pytest.mark.docker` test)

#### Round 75 (after tag v0.1.0-beta.79; TypeScript SDK 0.1.2 and OpenAPI 200-reuse, findings of the live TS round 2026-11-17)
- **fix(sdk-ts): `createSnapshot` exposes the REST field `labels` (finding of phase 4 of the TS round).**
  `snapshotFromSandboxBody` and `Snapshots.createFromSandbox` accept optional `labels`
  (same limits and rules as volume labels, `checkLabels` from `volumes.ts`);
  `CreateSnapshotOptions.labels` passes them through, a body without `labels` stays unchanged.
  The new type `CreateFromSandboxOptions` is exported. Derived snapshots through the TS SDK are no
  longer necessarily `labels={}`. (`sdk/typescript/src/{snapshots,client,volumes,index}.ts`;
  tests `sdk/typescript/tests/snapshot-labels.test.ts`, 7 tests; 595 in total)
- **fix(openapi): the create code context operation also declares a 200 reuse response (finding of phase 3b
  of the TS round).** The route returns 200 with `created=false` for the name of a live context (c5495cd), but the
  spec declared only 201. The decorator now declares 200 with the same schema
  (`Envelope[CodeContextResponse]`) and a description of the reuse behavior; spec regenerated.
  (`src/sandfort/api/routes/toolbox/code_contexts.py`, `openapi/sandfort.v1.json`;
  test `tests/test_code_context_reuse_openapi_r75.py`)
- The package version `@sandfort/sdk` was raised to `0.1.2`. Both findings are from the phases of the live TS round
  of Design Partner 1 (2026-11-17, window 09:00–10:30 UTC, all phases PASS after gated
  resumption; close-out in the partner's records). The server was not changed. (7692fe6d)
- **fix(sdk-ts): `SnapshotInfo` keeps `labels` and `isolation` from the response (0.1.3; the partner's
  verification of 0.1.2, item A).** `snapshotFromPayload` built an object without `labels` and
  `isolation`, which the `SnapshotResponse` schema documents (and an empty `labels:{}` was lost; the defect
  also exists in the 0.1.1 decoder). Now: `labels` (default `{}`) and `isolation`
  (default `null`) are in the interface and are copied through the create/get/list/wait paths;
  `optionalLabels` exported from `volumes.ts`. Version `0.1.3`.
  (`sdk/typescript/src/{snapshots,volumes,version}.ts`; tests in
  `tests/snapshot-labels.test.ts`, 599 in total; this commit; the hash is recorded in the next round)
- **fix(sdk-ts): stream timeout classification on Node 20.x (0.1.4; partner's finding, item C).**
  On Node 20.3.0 / Undici 5.22.1, an abort of the stream body read by the SDK's timeout or
  deadline controller arrives as a `DOMException` named `AbortError`, so `followCommandLogs`,
  `streamCodeContextRun` and `audit.exportLines` returned `TransportError` instead of
  `RequestTimeoutError` (11 cases in the partner's suite; on Node 26 the error carries the name
  `TimeoutError` and was classified correctly). `streamReadFailure` now classifies
  `AbortError` without a caller abort as a timeout — the caller's signal is still checked
  first, so cancellation by the caller remains `RequestAbortedError`. Version `0.1.4`.
  (`sdk/typescript/src/stream-failure.ts`; tests `tests/stream-failure.test.ts`, 605 in total;
  this commit; the hash is recorded in the next round)
- **fix(sdk-ts): deadline identity in stream timeout messages on Node 20.x (0.1.5; partner's
  residual C finding).** The fix from 0.1.4 returned the correct class, but the generic message
  "timed out" even when the abort was caused by `deadlineMs` (4 cases with `assert.match(/deadline/)`):
  on Node 20.x / Undici 5 the rejection does not carry the abort reason. The transport now remembers the composite
  signal per Response (`rememberStreamSignal`, WeakMap), and `streamReadFailure` reads the
  `DeadlineExceeded` reason from it and names the deadline ("exceeded its deadline of N ms") in the
  `AbortError` branch too; the per-call timeout stays "timed out", caller cancellation
  stays `RequestAbortedError`. Version `0.1.5`.
  (`sdk/typescript/src/{stream-failure,transport,contexts,audit-export,sandbox-ops}.ts`;
  tests `tests/stream-failure.test.ts` incl. the end-to-end Node 20 shape, 609 in total;
  this commit; the hash is recorded in the next round)
- **fix(toolbox): honest kernel-state message for an inconclusive probe of a stuck cell.**
  A probe that times out, returns an unexpected exit code or raises `DriverError` (outcome `unknown`)
  no longer claims "was interrupted"; `stderr` ends with the new message `UNCONFIRMED_MESSAGE`
  ("the kernel state could not be confirmed, so the context was kept"). The outcome `alive` keeps
  the existing message, the context is kept in both cases. The strict-xfail test from 8bbf689 now passes.
  (`src/sandfort/toolbox/code_contexts.py`; tests r34/r35 updated in the same commit;
  this commit; the hash is recorded in the next round)
- **fix(audit): `quota.updated` rows carry the request id, IP and user agent.** `QuotaService` in
  wiring now gets `CorrelatedAuditRecorder` (like key events since 9571d1a), so
  `PUT /v1/org/quota` writes all three fields; a quota release outside a request (auto-stop,
  reconciler) still writes `null`, because there is no request. `docs/governance.md` no longer lists
  `quota.updated` as an exception. (`src/sandfort/api/wiring.py`; test in `tests/test_quota.py`;
  this commit; the hash is recorded in the next round)
- **feat(deploy): `partner-package.sh` assembles the partner delivery from a signed release dir.**
  It verifies the existing `SHA256SUMS(.sig)`, copies additional files (e.g. the spec export), extends
  and re-signs the manifest with the same key/namespace, self-verifies and creates
  `<dir>-<partner>.zip` with a hash for the delivery message — replaces the manual steps done per
  delivery (4× in round 75). (`deploy/partner-package.sh`; smoke tests with and without additional
  files; this commit; the hash is recorded in the next round)
- **docs(onboarding): one-page quickstart for the hosted beta.**
  `marketing/pilot/beta-quickstart.md` (delivery verification, installation, first sandbox;
  a summary of the connect guide, the guide remains the authority) is published as `quickstart.html` on
  the docs site, with an entry in the navigation and in the sitemap; the top of the connect guide points to it.
  `deploy/redeploy-beta.sh` ships the new key in the `sandfort-docs` ConfigMap.
  (`scripts/build_docs_site.py`, `scripts/docs_theme.py`, `tests/test_docs_site_build.py`;
  this commit; the hash is recorded in the next round)

#### Round 74 (after tag v0.1.0-beta.79; TypeScript SDK 0.1.1, design partner findings TS-001/TS-002/TS-004)
- **fix(sdk-ts): the `Sandbox` handle no longer loses seven response fields (TS-001).** The constructor
  of the `Sandbox` class did not assign `createdAt`, `updatedAt`, `stoppedAt`, `stopCause`,
  `isolation`, `volumes` and `egressAllowlist`, which `models.ts` already parses, so through create,
  get, list, update, reset and resize they were `undefined` and did not exist in the handle declaration.
  They are now assigned and declared. (`sdk/typescript/src/sandbox.ts`)
- **fix(sdk-ts): org facades honor per-call resilience options (TS-002).** `webhooks`,
  `apiKeys`, `audit.list`, `audit.verifyChain`, `usage` and `audit.exportLines` passed only
  `signal` to the transport, so the per-call `timeoutMs`, `deadlineMs` and `retries` were silently
  ignored (the README promised them). Now everything goes through `callArgs`. `ExportRequest` no longer
  redefines `timeoutMs` as a lower bound: an explicit `timeoutMs` limits the whole stream, as
  everywhere. (`sdk/typescript/src/{webhooks,api-keys,audit,usage,audit-export}.ts`)
- **fix(sdk-ts): request id from the `X-Request-ID` header when the error envelope has no `request_id`
  (TS-004).** `replyError` now falls back to the response header; the envelope id still takes
  precedence. (`sdk/typescript/src/reply.ts`)
- The package version `@sandfort/sdk` was raised to `0.1.1`; the README was aligned with `engines`
  (`node >=20.3`). Regression tests for the findings: `sdk/typescript/tests/phase1-findings.test.ts`
  (16 tests; 583 in total). The findings are from the offline package-contract check by Design Partner 1
  on the signed tarball, 2026-11-16; the server was not changed. (aa7579c1)

#### Round 73 (after tag v0.1.0-beta.77; SF78-001)
- **fix(volumes): orphaned `sf-vxfer` helpers of interrupted transfers no longer block recovery
  of the volume.** A restore killed in the middle of extraction (SIGKILL) leaves a helper container
  (`sf-vxfer-<hex>`, state Created, never started) that references the volume, so recovery at
  startup (`recover_interrupted_restores` → `clear_volume`), the "repair" restore and deletion of the volume
  after a killed export got 409 (volume is in use) until the helper is removed manually.
  Now `clear_volume`, `restore_volume` and `DockerDriver.remove_volume` remove, before working on the volume,
  every helper that mounts it (`volume_helper.remove_orphan_helpers`, without an age
  condition; every removal is logged at WARNING; never raises). The helper is never started, so
  state and age do not distinguish a live transfer from a dead one: transfers in progress are tracked by a
  (client, volume) in-process counter (`helper_container` increments it before anything that is created
  on the daemon and decrements it in `finally`), so helpers of transfers in progress are never cleaned (deletion
  during a live export still gives 409). The 6 h prune also skips volumes with a transfer in
  progress, so a long (>6 h) live export is not harmed by a concurrent transfer. Limitation: the counter
  sees only its own process, so one API process per host with volumes applies (another process on the
  same daemon could lose live transfers; `docs/operations.md`).
  (`src/sandfort/drivers/docker/volume_helper.py`,
  `src/sandfort/drivers/docker/volume_transfer.py`, `src/sandfort/drivers/docker/driver.py`,
  `docs/operations.md`, `tests/test_volume_orphan_helper_r73.py`; this commit)

#### Round 72 (after tag v0.1.0-beta.77; test hooks for the agreed fault window)
- **Two new fault-injection flags** (`SANDFORT_FAULT_INJECTION`; both are automatically shown
  in the `GET /v1/status` notice through the existing `fault_notice`, which gives the partner independent proof
  that they are active): `restore_extract_hold` freezes the restore upload in the Docker driver only after the
  first assembled part of the tar has been handed to the daemon (works for small archives too, before the end of the body), so a kill
  of the process is guaranteed to land after extraction has started; a cancelled request still cleans up properly
  (the existing cleanup). `volume_recovery_clear_fail` makes recovery at startup not empty
  any marked volume (the driver is not even called, markers remain, no audit records), which
  tests the 409 `restore_unrecovered` branch for export and mounting and recovery by a new
  restore; in-request paths are untouched. Both flags do nothing when they are not set.
  (`src/sandfort/config.py`, `src/sandfort/drivers/docker/volume_transfer.py`,
  `src/sandfort/services/volume_restore_recovery.py`, `tests/test_fault_flags_r72.py`;
  this commit)

#### Round 71 (after tag v0.1.0-beta.76)
- **Restore recovery after a process crash: after recovery the volume is empty or complete,
  never partial.** Restore now writes a persistent marker `volumes.restoring_since` (migration
  `0025`) after the first decompressed chunk and before the driver empties the volume and starts
  extraction; the marker is cleared on success and in the existing shielded cleanup (only if the
  emptying succeeded — a volume that could not be emptied keeps the marker). At API process
  start (roles `api` and `all`, before the first request; not `worker`) every volume with a
  dangling marker is emptied through the driver `clear_volume`, the marker is removed and an audit
  record is written (`volume.restore`, outcome error, actor `system`, `details.reason` `recovered_after_crash`,
  `details.volume_emptied`); a `DriverError` leaves the marker for the next start, a vanished provider
  volume only has its marker removed. While a volume carries a dangling marker, export and mounting into a new
  sandbox are refused with 409 `CONFLICT`, `details.reason` `restore_unrecovered`; a new restore of the same
  volume remains allowed (it replaces the content and marks again). Recovery clears the marker with a
  compare-and-clear query (`UPDATE ... WHERE restoring_since = :observed`), so it never deletes the
  marker of a newer restore. Limits: the marker does not record the process — one API process per host with
  volumes (documented); an interruption BEFORE the first decompressed chunk still leaves the old
  content untouched (no marker is written). Covers a finding from the audit partner's fault window
  2026-11-14 (a post-extraction hard kill could leave partial content).
  (`src/sandfort/services/volume_transfer.py`, `src/sandfort/services/volume_restore_recovery.py`,
  `src/sandfort/api/app.py`, `tests/test_volume_restore_marker_r71.py`; this commit)

#### Round 70 (after tag v0.1.0-beta.76; operational edge fix, no code change)
- **Public API edge: pre-body 413 and visibility of the transfer limit (INCONCLUSIVE pair from
  beta.74):** the live ingress `api.sandfort.dev` did not have `proxy-request-buffering: "off"`, so
  nginx waited for the whole body before passing even the headers to the server. A request with `Content-Length`
  above the server limit but below the edge backstop (256 MiB + 1, below `proxy-body-size:
  512m`) hung without any response (measured: 12 s until the client timeout), even though the server
  refuses before the body (`api/routes/volumes.py` `_refuse_declared_oversize`, fs `MAX_UPLOAD_BYTES`).
  The same buffering serialized parallel restores at the edge, so the transfer slots
  (`services/transfer_slots.py`, 2 per org / 8 per process) did not overlap on the server side and the limit
  could not be observed from outside. The annotation was added to the live edge on 2026-11-14; the same probe
  now gets a server response in ~0.2 s. The runbook (`.context/deployment.md` §API edge body limit)
  now lists three required settings and records the live state; the example `deploy/k8s/ingress.yaml`
  (which already has the annotation) got a comment on why it is load-bearing. Server code and spec
  unchanged; the server was not restarted.

#### Round 69 (fix after the beta.75 retest)
- **SF75-001, network phrases in the body of a 401/403 response:** a registry that RESPONDED with 401/403 with a
  body that mentions network words (`unauthorized: dial tcp: lookup backend.invalid: no such
  host`) returned a retryable `registry_unreachable`, because the "hard transport wins" guard
  scanned the whole text. Now transport is looked for only in the daemon's own words BEFORE the registry echo
  (`unauthorized:` / `denied:`): the response body is registry data and keeps
  `image_access_denied`, while a token fetch that could not dial is still
  `registry_unreachable` (`src/sandfort/drivers/docker/images.py`,
  `tests/test_pull_body_network_text_r69.py`; two earlier tests that encoded the old rule
  were rewritten so that transport is in the daemon prefix). The documented precedence in
  operations and the guide has been extended with the same rule.

#### Round 68 (fixes after tag `v0.1.0-beta.74`)
- **SF74-001, duplicates in the restore archive:** `duplicate_entry` is now raised for EVERY later member
  whose normalized path equals the path of an earlier member (file, directory and symlink, in any
  combination; `./a` and `a` are the same path), not only for a member on the path of an earlier
  symlink. Two regular files with the same name no longer return 200 with the second overwriting the
  first: 422 `forbidden_entry` with `details.violation` `duplicate_entry`, the existing contract empties the volume
  (`details.volume_emptied` `true`). The set of seen paths is bounded by
  `MAX_MEMBERS`. Change: `src/sandfort/drivers/docker/tar_policy.py`; tests:
  `tests/test_tar_duplicates_r68.py`.
- **SF74-002, answered 401/403 with TLS text in the body:** `unauthorized: x509: certificate has
  expired` (401) returned `registry_tls_error`, and `denied: x509: certificate has expired` (403)
  `image_not_found`. Cause of 401: the registry body arrives after the error code, so only the weak marker
  `unauthorized: ` (checked AFTER the TLS check) saw the refusal. Cause of 403: moby wraps every
  registry `DENIED` response in the sentence "pull access denied for ..., repository does
  not exist or may require 'docker login': denied: <message>", and `clean_message` replaces it with
  the phrase `the image could not be pulled`; the not-found family branch was decided first and never
  read the registry body. Fix in `src/sandfort/drivers/docker/images.py`: (1) a sentence followed
  by `denied: <message>` that is not the standard Docker Hub message ("requested access to the resource
  is denied") nor GHCR's bare `denied` is no longer not-found (standard repos stay
  `image_not_found`, so a private and a nonexistent Hub repository are still indistinguishable); (2)
  the registry `unauthorized: <message>` / `denied: <message>` (as the whole text, at the start of a line
  or after a colon) is `image_access_denied` before the TLS, throttle and 5xx checks, except when the text
  shows a hard transport failure (dial, lookup, timeout, refused, EOF). A real TLS failure
  (x509 in the handshake, HTTPS-to-HTTP) stays `registry_tls_error`. The order is described in
  `docs/operations.md` and the guide; tests: `tests/test_pull_denial_precedence_r68.py`.
- **SF74-003, OpenAPI for volume transfer:** `GET /v1/volumes/{id}/export` in the spec returns 200
  `application/gzip` (binary) instead of `application/json`; `POST /v1/volumes/{id}/restore` has a
  required `requestBody` `application/gzip` (binary), 413 with the described causes and no 415
  (the body is not JSON). The declarations are in `src/sandfort/api/openapi_volumes.py`; the spec was re-exported;
  tests: `tests/test_openapi_volume_transfer_r68.py`.
- **SF74-004, two phases of restore:** the guide and `docs/operations.md` now distinguish a refusal before the
  start of extraction (volume untouched, no `volume_emptied` key; this includes a gzip error
  visible in the first decoded block, up to 1 MiB, for example a bad CRC in a small archive) from a failure after the
  start (volume empty, `volume_emptied` `true`; bad CRC in a larger archive, tar-level refusals,
  duplicates). The early refusal is intentionally kept; API behavior was not changed, because
  `volume_emptied: false` already means "emptying did not succeed" and must not be overloaded. Tests:
  `tests/test_volume_restore_phases_r68.py`.

#### Round 67
- **Signed self-host bundle for a design partner without repo access:** the new
  `deploy/release-bundle.sh <tag> <wheels-dir> [out-dir]` builds `sandfort-selfhost-<tag>.tar.gz` from the
  output of `deploy/release-wheels.sh`. Contents: three wheels, `SHA256SUMS` + `SHA256SUMS.sig`,
  `release-allowed-signers`, `RELEASE.txt` (extended with the recipe for the bundle), `deploy/host-setup.sh`,
  `deploy/node-setup.sh`, `deploy/seccomp.json`, `deploy/selfhost/{Dockerfile,compose.yml,
  sandfort.env.example}` and `INSTALL.md`. The script writes `BUNDLE-SHA256SUMS` over all other
  files and signs it with the same key (`SANDFORT_RELEASE_KEY`), principal
  `release@sandfort.dev` and namespace `sandfort-release`, so the partner verifies one signature for the
  whole bundle. Before packaging it checks the wheel signature, that the `HEAD` commit is the one from `RELEASE.txt` and
  that `deploy/` is clean (`SANDFORT_BUNDLE_UNSAFE=1` skips those two checks, for tests only); after
  packaging it unpacks the tarball and verifies the signature and sums again.
- **`deploy/selfhost/`:** the `Dockerfile` installs the SERVER WHEEL from the bundle root
  (`COPY sandfort-[0-9]*.whl`, no source build, user uid 10001, the same `EXPOSE` and
  `sandfort-server` as `deploy/Dockerfile`; migrations go through `python -m sandfort.admin_cli
  migrate`, because `alembic.ini` is not in the bundle and the migrations are in the wheel). `compose.yml` is adapted
  from `compose.prod.yml` (API + Postgres 16, Docker socket, seccomp mounted from the bundle, optional
  notice mount, the build context is the bundle root). `sandfort.env.example` has every required
  `SANDFORT_` variable with a comment and empty secrets. Deviation: compose reads
  `sandfort.env` (a copy of the example), not the example itself, so the example stays as it was signed.
- **`deploy/selfhost/INSTALL.md`:** host requirements as on the beta (Ubuntu 24.04, Docker Engine,
  `/var/lib/docker` on XFS with `pquota`, overlay2, gVisor, optional Kata, Postgres 16), bundle verification
  (`ssh-keygen -Y verify -n sandfort-release`), `node-setup.sh --check`, compose, migrate and
  bootstrap, smoke test, upgrade and rollback, the chapter "Snapshot recovery through a registry"
  (export, `docker load`, tag, push, register by digest, hash comparison) and the sequence for a
  disabled webhook endpoint (PATCH `enabled=true` resets the counter, then redeliver; redeliver on a
  disabled endpoint is 409).
- Documentation: `docs/release.md` describes the bundle; `marketing/pilot/partner-install-guide.md`
  no longer assumes a checkout (wheels instead of `pip install -e`) and points to the bundle for the
  soak. `pyyaml` was added to the `dev` dependencies (a test parses compose). The spec was not regenerated, the API does not
  change. Tests: `tests/test_release_bundle_r67.py` (no Docker, a fake wheels directory and an
  ed25519 key from tmp).
- **Volume export and restore (design partner request):** `GET /v1/volumes/{id}/export` (scope
  `volumes:read`) returns the files of the volume as a gzip tar (`application/gzip`, `Content-Disposition`
  `<name>.tar.gz`), and `POST /v1/volumes/{id}/restore` (scope `volumes:write`) replaces the content of the volume
  from a gzip tar sent as the request body (at most 256 MiB compressed). Both are audited as
  `volume.export` (row before the first byte, name only) and `volume.restore` (bytes or failure reason and
  `volume_emptied`). The Docker driver reads and writes through a helper container that is only created, never
  started (network `none`, `cap_drop=ALL`, `no-new-privileges`, volume at `/volume-data`, `ro,nocopy`
  for export and `rw,nocopy` for restore, always force-removed; leftover helpers older than 6 h are removed
  by the label `sandfort.volume_transfer`); the files are copied by the Docker daemon (`get_archive`/`put_archive`).
  A volume that was not created by the platform (without the label `sandfort.managed`) is never mounted.
  The protocol `VolumeTransferDriver` (`export_volume`, `restore_volume`, `clear_volume`) is implemented by
  `DockerDriver` and `FakeDriver`; another driver answers 409 `CONFLICT` with `reason` `unsupported_mode`.
- **Restore semantics (headline): empties first, then unpacks, not atomic.** The volume is emptied
  (removed and created again with the same name, driver, options and labels), then the archive is unpacked;
  every failure after the start leaves the volume EMPTY and the response says so (`details.volume_emptied`):
  an invalid, interrupted or oversized tar, a refused member, a dropped connection. A body that is not gzip, is empty
  or has no data is refused with 422 before emptying (volume untouched). 409 `in_use` while any
  sandbox that is not deleted mounts the volume, 409 `restore_in_progress` for a second restore in the same
  process. Quotas: compressed body up to 256 MiB (413 before reading the body for a larger `Content-Length`),
  decompressed bytes are counted and must fit in `SANDFORT_VOLUME_MAX_BYTES` when set (413,
  volume empty); the org quota is NOT checked. Known race: a sandbox created right after the
  mount check can mount the volume in the middle of a restore.
- **Archive policy on restore (`drivers/docker/tar_policy.py`):** regular files, directories
  and symbolic links with a relative target inside the volume are allowed; mode (including setuid, setgid
  and sticky, safe because every sandbox runs with `no-new-privileges`), uid, gid and time are kept as
  written, extended attributes are not. The server builds a NEW tar from the approved headers. Everything else is 422
  `UNPROCESSABLE` with `details.reason` `forbidden_entry`, `details.violation` (`path_traversal`,
  `absolute_path`, `invalid_name`, `invalid_link_target`, `hardlink`, `symlink_absolute`, `symlink_escape`,
  `symlink_through`, `duplicate_entry`, `special_file`, `unsupported_entry`, `header_too_large`,
  `too_many_entries`), `details.entry` and `volume_emptied`.
  Limitation of the round: export is a faithful read without policy, so a volume with an absolute symbolic link
  (e.g. `bin/python -> /usr/bin/python3` in a venv) or a hard link exports successfully, but restoring that
  archive is refused with a 422 that names the member. `FakeDriver` now REFUSES forbidden members (same
  policy) instead of silently dropping them. Export has no checksum: a truncated body cannot be
  recognized by the client without `gzip -t`; exporting a volume that a sandbox is still writing is not a point-in-time snapshot.
- **Hardening after the security review (same round):** (1) pax/GNU headers larger than 1 MiB
  (`MAX_EXTENDED_HEADER_BYTES`) are refused after reading about 1 MiB (`header_too_large`; `tarfile` would
  hold them entirely in memory: a 400 MiB header consumed 888 MiB), the limit applies to every individual
  read of the parsed stream, so even the pax `size` does not bypass it. (2) A control character (and NUL) in a name or link target
  is refused (`invalid_name`, `invalid_link_target`; targets longer than 4096 bytes too), every
  rebuilt header is parsed back and the name, target and type must be identical to the checked ones (the daemon
  reads C strings, so a NUL in `linkpath` must not create a link that escapes); user and group names are
  not carried over. (3) Decompression is always limited to 64 times the compressed size (`EXPANSION_RATIO`,
  never below 16 MiB, `EXPANSION_FLOOR_BYTES`; the basis is `Content-Length` or the bytes received so far)
  in addition to `SANDFORT_VOLUME_MAX_BYTES`: 413 with `details.max_expansion_ratio`, volume empty; previously, without
  the limit, a 256 MiB gzip of zeros would write about 256 GiB. (4) At most 100000 members per archive
  (`too_many_entries`; this also bounds the set of symbolic links). (5) Concurrent transfers:
  `SANDFORT_MAX_VOLUME_TRANSFERS_PER_ORG` (2) and `SANDFORT_MAX_VOLUME_TRANSFERS` (8), 0 = no limit;
  export holds the slot until the stream is closed, restore for its duration; over the limit 409 `CONFLICT` with
  `reason` `org_transfer_limit` or `transfer_limit` (`services/transfer_slots.py`). (6) Cleanup of
  leftover helper containers removes only a container with the name `sf-vxfer-*`, without the `sandfort.sandbox_id` and
  `sandfort.managed` labels and with a readable old timestamp (a label from a sandbox image is not enough).
  (7) At most 1000 gzip members in the body (`MAX_GZIP_MEMBERS`; more is 422): a flood of empty 20-byte
  members consumes CPU without output that the ratio would limit; decompression yields to the event loop
  per received chunk (`anyio.lowlevel.checkpoint`).
  Tests: `tests/test_tar_policy_hardening_r67.py`, `tests/test_volume_transfer_limits_r67.py` and additions to
  `tests/test_docker_volume_transfer_r67.py`.
- **Python SDK and CLI:** `client.volumes.export(volume_id, path)` (streams to a file, deletes the
  partial file on failure, returns the bytes) and `client.volumes.restore(volume_id, source)` (path, bytes or
  binary file object; larger than 256 MiB is refused locally; the body is never sent again after a
  dropped connection; returns `VolumeRestore`), sync and async; `sandfort volume export <id|name> -o <file>` and
  `sandfort volume restore <id|name> <file>`, `--json` as with `snapshot export`. The helper functions for
  writing the stream are in `_download.py` (shared with snapshot export). The TypeScript SDK remains a subset without this.
  Along the way: `upload_limit_error` and `MIB` were moved to `sandfort.errors` for `lint-imports`
  (`toolbox.fs_range` re-exports them).
- **Documentation** (this commit; the hash is recorded in the next round): `docs/operations.md` (section "Volume export and restore": table of semantics and
  policy with sources, examples), the guide (section in "Volumes"), the operation description in OpenAPI; the spec and
  `site/docs` regenerated. Tests: `tests/test_volume_transfer_r67.py`, `tests/test_tar_policy_r67.py`,
  `tests/test_volume_restore_policy_r67.py`, `tests/test_docker_volume_transfer_unit_r67.py`,
  `tests/test_docker_volume_clear_unit_r67.py`, `tests/test_docker_volume_transfer_r67.py` (docker),
  `tests/test_sdk_volume_transfer_r67.py`, `tests/test_cli_volume_transfer_r67.py`.
- **Error taxonomy on image pull (design partner request):** HTTP 429 (Docker Hub
  "toomanyrequests: You have reached your pull rate limit") and HTTP 5xx ("received unexpected HTTP
  status: 503 Service Unavailable", containerd "unexpected status from ... request to ...: 503")
  become `registry_unreachable` (retry after a pause), instead of `start_failed`. A TLS validation error
  (`x509:`, "certificate", "http response to https client") gets the new code
  `registry_tls_error`, which is NOT retried: the fix is trust or registry configuration, not the
  network (previously it went to `registry_unreachable` with the instruction "retry after a pause"). The new type
  `DriverRegistryTlsError` is a direct descendant of `DriverError`, intentionally not `DriverRegistryUnreachable`,
  so a loop that catches "unreachable" does not retry the TLS error. `error_reason` is a fixed sentence
  built only from the reference; daemon text goes only to the `debug` log. "EOF" and "TLS handshake
  timeout" remain `registry_unreachable` (network condition, not validation). The order in
  `classify_known_pull_failure`: not-found family and the sentence about a refused pull, then
  unparsable reference, then registry response 401/403 (wins over TLS, 429/5xx and transport), then TLS
  validation, then 429/5xx and transport, then anchored refusal phrases, then weak network markers. The markers
  are anchored (never bare words, because the daemon echoes text chosen by the tenant): "certificate" only
  as a whole word outside the path, host and tag, "x509:" only as the Go sentence "x509: <sentence>",
  "toomanyrequests:" only as a docker code, and the containerd status only immediately after the request URL. The same
  TLS class also covers "tls: first record does not look like a TLS handshake" (plain-HTTP registry).
  A CPU architecture mismatch comes out as `image_not_found`: Docker picks the platform from the manifest
  list and reports not-found when none matches, and the marker "no matching manifest" classifies that
  regardless of HTTP status (actual text from Docker Engine 29.8.2, 2026-11-13, covered by a test);
  that is Sandfort's mapping of the daemon response, not a registry response.
  `ERROR_CODES`, `IMAGE_PULL_ERROR_CODES`, the SDK `ErrorCode` and `ERROR_CODE_REGISTRY_TLS_ERROR`
  (parity is covered by a test), the `error_code` description in the OpenAPI spec (regenerated),
  `docs/operations.md`, the integration guide and the SDK README were updated. The TypeScript SDK does not carry the
  code list. Tests: `tests/test_pull_taxonomy_r67.py`.

#### Round 66
- **Resize keeps the root file system files (S1, reported by the first external design partner):**
  `POST /v1/sandboxes/{id}/resize` deleted all files from the root file system on all
  isolation tiers, because the start after resize created a new container from the original image
  (`/tmp/m` and `/root/m` disappeared after stop, resize, start; a plain stop/start kept them).
  Now the start after resize commits the stopped container to a temporary local image
  `sf-resize-<id malim slovima>`, creates a new container (same hardening, labels, volumes, new
  resources, disk quota) from that image and removes the image, also when creation fails (best effort, `debug`
  log). The image carries the label `sandfort.resize_image`; a container created from it inherits it, so the
  Docker driver on `destroy` also removes the image that remained as its base (only if it has
  no name, so a snapshot committed from such a container is never a target). Works on runc, runsc and
  kata, because commit works on every stopped container. A failed commit leaves the old
  container untouched. `reset` was not changed and still deletes everything. Protocols:
  `commit_container(..., labels=)` and `remove_image(..., force=)`. Note: what was written before
  resize becomes part of the image the new container starts from, so it does not count toward the `disk_gib` of its
  writable layer. Tests: `tests/test_resize_keeps_files_r66.py`,
  `tests/test_docker_resize_image_unit_r66.py`, `tests/test_docker_resize_r66.py` (docker).
  Documentation: guide (resize section and OOM tip), operation description in OpenAPI,
  `docs/isolation-tiers.md`; spec and `site/docs` regenerated.
- **A second resize of the same sandbox works (regression of the first S1 fix, found by a partner on the beta):**
  the first fix force-removed the image `sf-resize-<id>` right after a successful `create`, even though the
  newly created (not started) container still referenced it. On classic overlay2, `rmi -f` of an image
  referenced only by stopped containers DELETES the image record (Docker Desktop with the containerd
  store only removes the tag, so the local docker test did not see the error), so the commit of the next
  resize found `No such image: sha256:...` and `POST /start` returned 404. Now: (1) the tag
  `sf-resize-<id>` stays while the sandbox lives; the next resize commits to the same tag, and after a successful
  `create` it removes the PREVIOUS image by id on a best-effort basis if it differs (`debug` log); a failed
  `create` still removes the newly made commit; (2) the Docker driver on `destroy` (with
  `remove_volumes`, i.e. the end of the sandbox, not a container replacement during resize) after removing
  the container also force-removes the tag `sf-resize-<id>` (also after a reset, when the container no longer has
  the marker); (3) a failure of the commit/container replacement at start is `500 INTERNAL` with the message "resize
  could not prepare the sandbox's container; try again or contact the operator", the cause stays in
  the server log, never again 404 for a sandbox that exists (the row is untouched, the start can be repeated as soon as
  the cause goes away); `DriverUnsupported` stays 501. (4) `FakeDriver` models overlay2
  (`overlay2_images=True` by default): force-removing an image used only by stopped
  containers DELETES the image, so a later commit of such a container raises the same "No such image";
  `overlay2_images=False` is the containerd mode. Tests: second and third resize, destroy deletes the tag,
  failed commit then repeated start, fake model in `tests/test_resize_keeps_files_r66.py`, unit
  tests of tag removal in `tests/test_docker_resize_image_unit_r66.py`, docker test with a tag
  that exists while the sandbox lives and disappears after deletion in `tests/test_docker_resize_r66.py`.
  Guide: the hosted beta CAN set limits per org (partners now have them), `null` means
  unlimited (it used to say all limits are `null`); `site/docs` regenerated.
- **Recovery after an interruption in the middle of a container replacement + a controlled hook for fault injection
  (agreed fault-injection test with the design partner):** (1) when `create` after `destroy` fails,
  the temporary image `sf-resize-<id>` is no longer removed (the only copy of the sandbox files), a
  `warning` is logged that the data lives in the image until the next successful start; a failed `destroy` still removes
  the fresh commit because the old container is alive. (2) `_recreate_if_resized`: when the container does not exist
  (`DriverNotFound` on inspect), and the image `sf-resize-<id>` exists (`image_exists` from
  `ImageRegistryDriver`, already in the protocol, fake and docker driver), start creates a container from that image
  with the row's current resources and writes a new `driver_ref`, so a repeated start after an interruption really
  works; without the image the old behavior remains (start itself reports the missing container). (3) The new
  setting `fault_injection` (`SANDFORT_FAULT_INJECTION`, comma-separated, by default
  empty): `resize_commit_fail` raises `DriverError` instead of the commit (nothing is touched),
  `resize_create_fail` instead of `create` after the commit and destroy; both give the existing
  `500 INTERNAL`. An unknown name is a load-time error. Safeguards: a warning in the log at start,
  `GET /v1/status` `notice.message` carries `fault injection active: <vrednosti>` and without
  `status_notice_file` (appended to the file text), `doctor` has a row `fault injection` that is
  `FAIL` while the setting is set. Documented in `docs/operations.md` (hook never in
  production). Tests: `tests/test_resize_fault_injection_r66.py`, modified
  `tests/test_resize_keeps_files_r66.py` (a failed create keeps the image), docker recovery case in
  `tests/test_docker_resize_r66.py`.
- **Webhook URL: a transient DNS failure is no longer "host does not resolve" (S2, first external partner):**
  `POST /v1/webhooks` with `https://example.com/audit` answered 422 after 5,17 s because the SSRF
  check reported resolver errors (timeout, SERVFAIL, `EAI_AGAIN`, other `OSError`) as permanent
  "does not resolve". Now resolver responses are separated: NXDOMAIN/NoData (`EAI_NONAME`,
  `EAI_NODATA`, empty response) stays 422 `UNPROCESSABLE` with `details.reason` `not_resolved`;
  a transient failure is retried once after 0,5 s, and a second failure answers 503 `DNS_UNAVAILABLE`
  (`details.reason` `dns_unavailable`, `Retry-After: 2`, message "could not verify the webhook host:
  DNS lookup failed; try again") and creates nothing. The same applies to `PATCH` with a new URL. A single
  lookup is limited to 2,5 s, so the check takes at most 5,5 s. The audit row of a rejected call carries
  `reason` (`not_resolved` / `dns_unavailable`); delivery classifies both as `dns`. Spec, guide,
  `docs/operations.md` (error table) and `docs/governance.md` updated.

#### Round 65: fs and drivers (lane c)
- **`HEAD /download` answers the same as `GET` (contract):** under `/proc`, `/sys` and `/dev` `HEAD` no longer
  answers from `stat` (200, or 416 `bytes */0` with `Range`), but queries the archive like `GET`, so the
  response is 404 when `GET` gives it. The error body of `HEAD` and `GET` for a nonexistent path is the same
  (`no such path`, `details.path`), so `Content-Length` is the same too.
- **OpenAPI (contract):** the description of `GET` and `HEAD` on `/download` lists 409 `CONFLICT` for a symlink; the description
  of `GET` states that `If-Range` is compared with a weak ETag, which deviates from RFC 9110 (kept because
  it enables resuming downloads); the same note in `sdk/python/README.md`.
- **Docker driver:** `.sf-exec-*.pid` and `.sf-pty-*.pid` from earlier runs remain in `/tmp` when
  stopping the sandbox kills the wrapper (a stopped container does not run exec), so
  `DockerDriver.start` removes them after start (detached, best effort, `debug` log when the container
  is gone).
- **`audit verify-head` / `verify_export`:** the line count is checked before the SHA-256 content, so
  removed or added rows give `count_mismatch`, and a modified or moved row (same count)
  gives `content_mismatch`. Previously the digest, which covers all lines, always gave `content_mismatch`
  and `count_mismatch` was unreachable. The reason text and documentation follow the new order.

#### Round 64 (after the tag `v0.1.0-beta.68`)
Items were committed to main after the tag `v0.1.0-beta.68`, by group: API and snapshots, toolbox
and driver, CLI and SDKs, deploy, documentation and site. Each is derived from the titles in
`git log v0.1.0-beta.68..HEAD`. Items the operator sees are marked with "(operator)", and changes
to the contract with "(contract)". Earlier short items about the same changes (shared volumes, 413 and `Range`) from
the round 62/63 section are merged here.

**Operator duties in this round (operator):**
- **Redeploy `api`** (24d602d, 66623ac): `deploy/redeploy-beta.sh api` applies two migrations,
  `0023` (`shared_volume_labels` on the API key) and `0024` (column `labels` on snapshots, server
  default `{}`). Both only add a column; existing rows get an empty set. The same redeploy ships 413 before
  the body, `Range` and `HEAD` on download and the new rules for snapshots below.
- **Redeploy `docs` and `landing`** (9f6dea7, 42f0c7f, a73e5d9): the CSP in `docs.conf` and `landing.conf`
  no longer lists font hosts (`fonts.googleapis.com`, `fonts.gstatic.com`); the pages use
  system fonts. The new releases page reads the current tag from git, and `/404` responds with status 404.
  The docs site is rebuilt (`scripts/build_docs_site.py`).

1) API and snapshots:
- **Upload over the limit** (4b3b4b0): rejected before reading the body with 413 and names the limit.
  Download accepts a single `Range`, and `HEAD` of the same path is in the spec (details in "Contract changes").
- **Labels on snapshots** (66623ac, e695718): `register` and creation from a sandbox accept
  `labels`, the list accepts a repeatable filter `label=k=v`, and a key restricted by labels gets its scope
  merged into the labels of every snapshot it creates. A snapshot with labels is visible to such a key
  when its labels contain the scope or when the source sandbox is in the scope. `snapshot.register` and
  `snapshot.create` carry the stored labels in the audit details.
- **Deleting a shared snapshot** (e695718): a key restricted by labels deletes a snapshot only if it
  reaches it through labels or through the source sandbox; registered and built snapshots without
  labels give 403.
- **Shared volume set** (55e85b4): a key with `shared_volume_labels` cannot create a volume
  whose labels contain all of its shared labels (403 `FORBIDDEN`). Before that, a single student
  key could place a volume next to the teacher's dataset. The name stays unique per
  org, so claiming the name still succeeds.
- **`labels` columns** (e695718): `SnapshotRow.labels` and `VolumeRow.labels` get the server default
  `{}`, same as the migrations. `volume.create` in the audit carries `name`, `labels` and `max_bytes` (c5035e0).

2) Toolbox and driver:
- **Pid files** (c760227, 0ce21ba): the exec pid file is deleted on every exit (EXIT trap), and the pid
  file of a PTY session when the session closes.
- **Code context** (223c778): the sentences about the output limit and sandbox death say "cell", and
  a sandbox killed due to memory adds that the context and its variables are gone (`start`, then
  `ensure` again). `\r` flushes part of the stream. `interrupt` reports `interrupted: false` when no
  cell is running.
- **Git without the binary** (aa537f7): `git` calls in an image without git give 409 `CONFLICT` with
  `details.reason` `git_missing` and a message suggesting an image that has it (`python:3.12`).

3) CLI and SDKs:
- **`ExecResult.ok`** (76d7391): true only for exit 0, without `stop_reason`, without a timeout and without
  truncated output (same for `CellResult.ok`). A run stopped because of `output_limit` could previously
  be `ok` with exit 0.
- **Profile** (76d7391): the profile is stored under `$XDG_CONFIG_HOME/sandfort` when that variable is
  an absolute path (`SANDFORT_CONFIG_DIR` takes precedence).
- **`cp`** (8f0e644, 3ebf3a7): `cp -r` skips links that leave the tree (a warning on stderr
  and "skipped N symlinks" in the summary, `skipped`, `directories` and `symlinks` in `--json`) instead of
  aborting; upload creates files owned by root; a clear error for a nonexistent local file.
  Errors the CLI finds before sending exit with 2 (contract).
- **Command sessions** (3ebf3a7): `sandfort cmd sessions` and `sandfort cmd rm-session`, and
  `cmd start --follow --close` deletes the new session when the command finishes.
- **Other in the CLI** (3ebf3a7, 8f0e644, c5035e0): `volume get` and `volume rm` work by name; the hint for
  exit 127 only when the command is actually missing, with the original quotes; `--mount` errors name
  the option; wider label columns; `login` names the key source in errors (`--key-stdin`, file,
  environment); a profile readable by others gives a single warning with a `chmod` command; class names
  of exceptions become plain words; the sanitizer masks the host after ASCII symbols and CJK or full-width
  separators; U+FFFC counts as a blank character.
- **Narrow terminals** (f542b9d): `key list` and `audit list` fit in a narrow terminal, columns that
  disappear are listed on stderr, and ids are not cut.
- **Audit CLI** (842e3ad): `export` without a final line exits with 3 with a warning; edge cases of
  `--output`; local check of `audit list`; a single JSON document on error; an empty `--previous` is
  rejected; `verify-head -` reads stdin; hint for CRLF and BOM; repeated options are rejected (exit 2).
- **SDK** (8f0e644): exception `ReadOnlyPath` (subclass of `Conflict`) for 409 `READ_ONLY_PATH`.
  `client.snapshots` accepts `labels=` on `register` and `create_from_sandbox` and on `list` and `iter`.

4) Deploy: see "Operator duties" (9f6dea7, 42f0c7f, a73e5d9).

5) Documentation and site:
- **Landing** (42f0c7f, a3505f2): current numbers and release state, a single wording for the benchmark,
  a working example of the agent loop, no third-party fonts; the comment in the example says what `ok` means.
- **README and guide** (c309514, aa537f7, 223c778): the README points users of the hosted beta to the guide;
  the guide gets a section on the default image, `python:3.12` for git, corrected times in the section on
  contexts and a scriptable `login`.
- **Docs site** (9f6dea7, a73e5d9, 410a821, dda51b1, 2f11303): system fonts, clean URLs in
  navigation, footer and the 404 page, releases page from git, a note about the path on the
  security page; the site was regenerated after every guide change.
- **OpenAPI** (38cd852, e402561, 2f11303): the spec describes `Range`, `HEAD`, 413 and the fields `labels` and
  `shared_volume_labels`.
- **Guide and CHANGELOG** (this commit; the hash is recorded in the next round): quotas (`client.quota.get()`,
  `sandfort quota`, `org:read`), a recipe for idempotent grading, `cp` exit codes, command
  sessions, `READ_ONLY_PATH` for upload, mkdir, deletion and move, disk measurement, `login
  --key-stdin`, snapshot labels, `ExecResult.ok`, audit CLI and narrow tables.

**Contract changes (contract):**
- **Upload over the limit is 413** (4b3b4b0): an upload of more than 256 MiB (268435456 bytes) is rejected
  before reading the body with 413 `PAYLOAD_TOO_LARGE`, regardless of whether the size is in `size_bytes` or in
  `Content-Length`. The message is `upload limit is 256 MiB (268435456 bytes); this upload is N bytes`,
  and `details` is `{limit_bytes, size_bytes}` (previously 422 only after the body was received).
- **Download accepts `Range`, `HEAD` is in the spec** (4b3b4b0, 38cd852): `GET .../toolbox/fs/download`
  of a file responds with `Accept-Ranges: bytes` and accepts a single `Range`: 206 with `Content-Range` and
  the `Content-Length` of the range, 416 `RANGE_NOT_SATISFIABLE` with `Content-Range: bytes */<size>`; multiple
  ranges, another unit or a bad value are ignored and the response is 200. The tar of a directory responds
  with `Accept-Ranges: none`. `HEAD` of the same path returns the same statuses and headers without a body and is now in
  the exported spec (89 operations in 68 paths).
- **Shared volumes for keys with a label scope (`shared_volume_labels`)** (24d602d, 55e85b4,
  e402561): `POST /v1/api-keys` accepts the optional field `shared_volume_labels` (a map of labels, the same
  restrictions as `sandbox_labels`, requires `sandbox_labels`); key responses return it (`null`
  when not set). A key with a scope can, besides its own volumes, list and get volumes whose
  labels contain all those pairs and mount them only read-only; a read-write mount is 403 that names
  the rule, and modifying and deleting such a volume remain impossible. The key that sets it must have
  `api_keys:admin`, and a creator with a label scope may share only labels it can itself reach.
  Migration `0023`; SDK `create_api_key(..., shared_volume_labels=...)`; CLI
  `sandfort key create --shared-volume-label k=v` (repeatable); guide: course example. A key with
  `shared_volume_labels` cannot create a volume whose labels contain all of its shared labels
  (403 `FORBIDDEN`), so that it does not publish into the common set; the match is a subset, so shared
  data should be marked with a label that private volumes do not carry (guide).
- **Labels on snapshots** (66623ac, 2f11303): `POST /v1/snapshots` and `POST /v1/snapshots/from-sandbox`
  accept `labels` (the same rules and limits as volume labels); the snapshot object has `labels`.
  `GET /v1/snapshots` accepts a repeatable `label=k=v`, every pair must match, the same key twice
  with different values is 422, and the cursor is bound to the filter. A key restricted by labels gets its
  scope merged into the labels. Migration `0024`; SDK `labels=` and CLI `snapshot create|register -l k=v`,
  `snapshot list -l k=v`.
- **Deleting a shared snapshot is 403** (e695718): a key restricted by labels does not delete a snapshot that
  no scope owns (registered or built without labels): 403 "snapshot <id> is shared
  across the org; only a key without sandbox_labels can delete it".
- **Publishing to the shared set is 403** (55e85b4): `POST /v1/volumes` with a key with `shared_volume_labels`
  and labels that contain all of its shared labels.
- **`READ_ONLY_PATH` (409)** applies to upload, mkdir, deletion and move on a read-only mount;
  the SDK raises it as `ReadOnlyPath` (8f0e644).
- **CLI exit codes** (3ebf3a7, 842e3ad): errors `cp` finds on the client before sending
  (missing local file, relative remote path, unusable destination) exit with 2, not
  with 125. `audit export` without a final line (`audit_head` or `export_summary`) exits with 3.
  A repeated single-value option of `audit` commands is a usage error (2).
- **Command sessions** (3ebf3a7): `DELETE .../process/sessions/{sid}` (round 62/63) now has the CLI
  `cmd rm-session`, and `cmd sessions` lists it.
- **Context `interrupt`** (223c778): `interrupted` is `true` only when a cell was running; without
  a cell it is `false`.
- **Git without the binary** (aa537f7): 409 `CONFLICT` with `details.reason` `git_missing`
  (previously `operation_failed` with the message `git <akcija> failed: ...`).
- **`ExecResult.ok`** (76d7391): see above; `ok` is not a response field, the SDK computes it.

#### Round 62/63 (after tag `v0.1.0-beta.67`)
Items were committed to main after tag `v0.1.0-beta.67`, grouped by: audit, API and parsing,
toolbox and driver, CLI and SDKs, deploy, documentation and site. Each is derived from the title in
`git log v0.1.0-beta.67..HEAD`. This section merges the earlier fragments "Round 62 (in progress)"
and "Round 63 (in progress)" and two daily sections from 2026-11-11. Items the operator sees are marked
with "(operator)", and contract changes with "(contract)". The audit chain is tamper-evident (it proves
a modification, it does not prevent it).

**Operator obligations in this round (operator):**
- **Redeploy `api`** (42554e5, d092bd3): `deploy/redeploy-beta.sh api` now builds and re-creates
  the egress proxy as well. Previously the proxy ran for days from the old image because the step re-created
  only `api`, so the proxy fix did not reach the beta. After the redeploy, check the proxy's
  startup line `egress allowed ports:` (the script checks it itself). The `egress` target does
  only that part, and `rollback` restores the proxy too. The new proxy rejects CONNECT to ports that are not
  allowed.
- **Docs ConfigMap split** (5df1618): the docs site is split into two ConfigMaps to fit under the
  Kubernetes size limit. The first `docs` deploy after this round patches the Deployment
  (`scripts/docs_volume_patch.py` builds the JSON patch); an already patched Deployment is left untouched.
- **Two audit keys**: `SANDFORT_AUDIT_CHAIN_KEY` and `SANDFORT_AUDIT_SIGNING_KEY` are set
  together (rule from round 61). Only then do signed exports exist and `GET /v1/status`
  publishes `audit_public_key` and `audit_key_fingerprint`. Record the fingerprint out of band.
- **Disk metering** (5f4dbcd): disk usage is credited for the whole started time, closed at
  stop and delete, and cut to the period like vCPU (`docs/operations.md`).

1) Audit:
- **The signed head binds the export content** (90b1784, d7715ea). The `audit_head` head at the end of the
  REST export, `audit-export` and `GET /v1/audit-events/export` carries `row_count`, `first_row_id`
  and `export_sha256` (SHA-256 over the exact bytes of each event line with the trailing `\n`, without
  the trailer; computed while streaming in constant memory). The fields are covered by the Ed25519
  signature and the HMAC; older heads without them are still readable.
- **Every non-empty export is signed** (90b1784). An export with `to` before the newest row binds the
  last exported row; an export with `request_id` or `outcome` carries `filtered: true` and
  `filters`, and the adjacent-row linkage check is skipped. `export_summary` remains only for an
  empty export or a server without a chain key.
- **`verify-head` and `verify_export`** (90b1784) also check the content: `content_mismatch`,
  `count_mismatch` and `first_row_mismatch` right after the signature, `org_mismatch` for the `org_id` of each
  row, `future_signed_at` (`signed_at` more than 5 minutes ahead; before 1970-01-02 it is `undated`),
  `malformed_row` for a row without `hash`, `prev_hash`, `occurred_at`, `org_id` or `action`. The new
  option `--previous <file>` (SDK `previous=`) requires the lines of the earlier export to be an exact prefix
  (`not_a_continuation`) and reports the number of new rows. The public key is read from `/v1/status` without
  credentials, `--public-key` also accepts standard base64, and success prints what was proven.
- **Key fingerprint in status** (d0af033): `audit_key_fingerprint` (16 hex characters) is `null`
  exactly when `audit_public_key` is `null`. Capacity rejections are merged by key and minute.
- **Secrets in paths** (d092bd3): an API key, session token, webhooks secret or opaque
  token pasted into the request path is written to the audit row as `<redacted>`, because a chain row
  cannot be deleted.

2) API and parsing:
- **Request body** (398d547): a repeated JSON object key, nesting over 64 levels and an integer
  with more than 64 digits give 422 `VALIDATION_ERROR`; a body that is not JSON gives 415. Strict
  `?cascade=`. Idempotency compares the canonical body; code-run honors `Idempotency-Key`.
- **OpenAPI** (9f9766b, 8987fc8, 371c38a): nullability is an OpenAPI 3.1 type union,
  `Idempotency-Key` has bounds 1 to 255, inline `fs/download` has a schema, volume and
  snapshot `state` are enums, the reasons `name_taken` and `result_unavailable` are in the spec, response
  headers are declared. Code-run and session creation are listed as idempotent.
- **Scoped key quota** (efd3fdd): `GET /v1/org/quota` for a key scoped by labels
  returns `scope` with the labels, the key's limit, the sandbox count and the remaining count.
  `client.quota` and `sandfort quota` are new.

3) Toolbox and driver:
- **Command sessions** (215f3fc): `DELETE .../process/sessions/{sid}`; `Idempotency-Key` on
  session creation; 202 in the spec for async commands; the stop sentence in the log follows the
  cause (`requested`, `auto_stop`, unknown; `oom_killed` and `container_exited` remain).
- **Command log** (68e7df2): GET log and the SSE stream cut the log into one event per line
  (the terminator stays, a line over 64 KiB is cut into chunks), an unfinished tail waits for continuation;
  the event `id` is the byte offset where the next line starts, so resuming with `Last-Event-ID` or
  `?offset=` goes exactly after the last delivered line.
- **Writing to pseudo-file systems** (dc9da2d): upload, mkdir and move under `/proc`, `/sys` and `/dev`
  are rejected with 422 instead of a false success; upload checks that the file was actually written.
- **Read-only** (d092bd3): write, mkdir, rm and mv on a read-only mount give 409
  `READ_ONLY_PATH`.
- **`oom_killed`** (9461157): a kill due to memory is reported as `oom_killed` where the
  driver sees it (container tier); other tiers still report `container_exited`.

4) CLI and SDKs:
- **Python SDK and CLI** (b4dbf64): `stop_cause` and full command status; `idempotency_key` on
  exec and `sandfort exec --idempotency-key`; the command list is sent as `argv`.
- **CLI login** (888affe, 5f614f7): `login` reads `--key-file`, `SANDFORT_API_KEY` and
  `SANDFORT_API_KEY_FILE` before prompting, the key from stdin (`--key-stdin`); revocation asks for confirmation;
  unnamed keys are shown. `volume rm` works by name (d092bd3); the host sanitizer
  recognizes full-width separators.
- **`audit list`** (33249ed, 35bc806): newest first (`--order newest|oldest`, `asc` and `desc`
  remain aliases), columns STATUS, ERROR and PATH, exact label values from spaces.
- **TypeScript SDK** (24ca3b0, d20065d, fe60042): facades for webhooks, API keys, audit and
  usage; update, reset, resize, isolation, preview tokens, stat and log following;
  log following resumes from `nextOffset`; bounded export reader; an explicit per-call timeout wins.

5) Deploy: see "Operator obligations" (5df1618, 42554e5).

6) Documentation and site:
- **Guide and documents** (7bec200, eb71d78, e3a6308, 4544815): `SANDFORT_BASE_URL` in
  examples, audit growth and archiving, shorter sentences, a single CLI install path, disk
  measurement rule, usage report, wording about gVisor seccomp.
- **Docs site** (bbe4020, f3ff85e, 1d046b6, cd122f5, 5f1e80e): clean canonical and sitemap URLs,
  accessible API page without JavaScript, contrast, named anchors, copy buttons; tests
  count the actual blocks and all spec operations.
- **CHANGELOG and guide** (a03bddb). The round 62/63 section,
  the `verify-head` reasons table and the 422/415 responses in the guide.

**Contract changes (contract):**
- **400 to 422 and 415**: the `GET /v1/sandboxes` label filter with a bad pair is 422 with
  `details.errors` (previously 400 with empty `details`). A body that is not JSON is 415
  `UNSUPPORTED_MEDIA_TYPE` (previously 422); nesting over 64 levels and an integer over 64 digits are
  422 (previously 400 `HTTP_400`). `expires_at` in the past when creating a key is 422.
- **A repeated JSON object key** at any depth is 422 (`duplicate key`).
- **Strict `?cascade=`**: only `true` or `false`; `yes`, `on`, `1`, `TRUE` and empty are 422.
- **Idempotency**: compares the canonical validated body, not the raw bytes (records with the old
  hash are recognized); code-run and session creation honor `Idempotency-Key`; an empty key or one
  longer than 255 characters, and a header sent twice with different values, is 422.
  `in_progress` 409 has no `Retry-After`.
- **Signed heads on every export**, with `row_count`, `first_row_id`, `export_sha256` and
  `filtered`. The `verify-head` reasons in order of checking (all give exit 3, exit 2 only when the
  check cannot be performed): `unsigned`, `key_mismatch`, `signature`, `undated`,
  `future_signed_at`, `content_mismatch`, `count_mismatch`, `first_row_mismatch`,
  `malformed_row`, `misplaced_trailer`, `org_mismatch`, `truncated`, `head_mismatch`,
  `chain_break`, `unchained_rows`, `not_a_continuation`, `no_trailer`. The option `--previous`.
- **`GET /v1/status`** has `audit_key_fingerprint`.
- **`GET /v1/org/quota`**: the field `scope` (`null` for an org-wide key).
- **`GET /v1/org/usage`**: an unknown `group_by` value is 422 `VALIDATION_ERROR`; `label:KEY`
  may have at most 63 characters and passes the label key rule; a comma (multiple groupings) is 422
  (e9c2f59).
- **One content rule** (e9c2f59) for label values and keys (sandbox creation, PATCH,
  volume, `sandbox_labels` of a key), env keys and values, `cwd` for exec, code-run, sessions and
  contexts, `egress_allowlist` items and the API key name: C0/C1 control characters and
  DEL are rejected (TAB only in env values, newline nowhere), bidi controls and isolates, invisible format
  characters (BOM, ZWSP, tag characters), U+2028/U+2029, private use and noncharacters; label keys
  and egress hosts must not contain a space; the message names the field and `U+XXXX`, never the raw character.
  `mount_path` additionally rejects fake slashes, colons and commas, a three-dot segment
  and `/var/run/docker.sock` and `/run/docker.sock`.
- **Upload, mkdir and move** under `/proc`, `/sys` and `/dev` are rejected (422); writes on a read-only
  mount give 409 `READ_ONLY_PATH`.
- **`oom_killed`** is a possible stop reason value where the driver sees it.
- **Command log**: one event per line, `id` is the offset of the next line.
- **Sessions**: `DELETE .../sessions/{sid}` returns the session with state `closed`; async session
  commands respond 202.
- **OpenAPI 3.1**: nullable fields are type unions, volume and snapshot `state` are enums.
  Renamed schemas from round 61 that were not recorded: `CommandStatus` to `CommandInfo`,
  `LogPageResponse` to `LogPageInfo`, `SessionExecResponse` to `SessionExecInfo`.
- **`details.reason`**: `name_taken` (duplicate name) and `result_unavailable`
  (`IDEMPOTENCY_RESULT_UNAVAILABLE`).

#### Round 61 (after tag `v0.1.0-beta.66`)
Items were committed to main after tag `v0.1.0-beta.66`, grouped by: webhooks hotfix, audit,
key configuration, API, CLI, SDKs, release, documentation. Each is derived from the title
in `git log v0.1.0-beta.66..HEAD`. Items the operator sees are marked with "(operator)", and
contract changes with "(contract)". The audit chain is tamper-evident (it proves a modification, it does not prevent it).

**Hotfix in `v0.1.0-beta.66`.** The webhooks dispatcher reads the delivery history through a metered
repository (99e249a); the fix is already in `v0.1.0-beta.66`. After five minutes the CLI prints
a note about a stuck dispatcher when deliveries stay `pending` without attempts (f85391c,
e813198).

**Operator obligations in this round (operator):**
- **Two audit keys** (daace93, 9e2fa7c): `SANDFORT_AUDIT_CHAIN_KEY` (at least 32 bytes) and
  `SANDFORT_AUDIT_SIGNING_KEY` (Ed25519) are set together. A signing key without a chain
  key refuses to start in `prod` (in dev and test environments it only warns). Without both keys the chain
  is an unkeyed hash and the export is unsigned.
- **Kubernetes** (this commit): `deploy/k8s/api.yaml` reads both keys from the secret
  `sandfort-secrets` as `optional: true`; a cluster without them still starts. Set the keys in the
  secret and then restart the API pod.
- **Regenerated spec** (3aba224): `openapi/sandfort.v1.json` (87 operations on 68 paths) and the
  docs site regenerated for round 61; it is regenerated again after documentation changes.
- **Doctor row `audit keys`** (daace93, 9e2fa7c): `admin_cli doctor` reports PASS when the heads
  are signed (with the public key fingerprint), WARN when the chain is keyed but unsigned or without both
  keys, FAIL only where startup actually refuses the configuration.

1) Audit:
- **Export is verified against the signed head** (4f0ecbd, 3b659bc, 3d5974f, 778e561).
  `sandfort audit verify-head <file>` does not check only the trailer signature: the last row must be
  the row the head names with the same hash, each `prev_hash` must be the hash of the previous row, and
  each row must have a hash. `signed_at` is displayed. Checks go in order: signature, bad row,
  wrong trailer position, last row, hash, chain break, rows without a hash.
- **Failure reasons** (exit 3): `unsigned`, `signature`, `key_mismatch`, `undated`,
  `truncated` (the last row is not the row from the head), `head_mismatch`, `chain_break` (`first_break`
  names the row), `malformed_row` (not a JSON object, bad UTF-8, nested too deeply or longer than
  1 MiB), `misplaced_trailer` (`audit_head` or `export_summary` is not the last line),
  `unchained_rows` (a row without a hash) and `no_trailer` (rows exist, and the last line is not a
  usable `audit_head`). The option `--allow-unchained` accepts rows that nobody chained.
- **Exit 2** is only for unusable input: a file that does not exist or cannot be read, an empty file,
  a file without a single valid row and trailer, a trailer that does not parse or an invalid
  `--public-key` (32 bytes, urlsafe base64). A server without `audit_public_key` and without `--public-key`
  also gives 2. `--head-only` checks only the signature.
- **Client-side check boundary**: it binds only the last row and the linkage of adjacent rows. Only the
  server-side check (`sandfort audit verify`, admin `audit-verify`) proves the whole chain.
- **An unkeyed newest row remains an alarm** (8e75c9c): with the chain key set, a chain whose
  newest row is unkeyed is a finding regardless of the flag; either the key was turned on after the
  last event, or keyed rows were deleted. Compare with an earlier export (`--head`).
  The operator output is polished.
- **Public key in status** (daace93): `audit_public_key` on `GET /v1/status` is published only
  when both the signing and chain keys are set; otherwise it is `null`.

2) API:
- **Exec `Idempotency-Key`** (811fb5a, 5300b8d, 694fdf9). The header on synchronous exec:
  the same key and body return the first response with `Idempotent-Replayed: true` and the audit
  `sandbox.exec.replay`; the command is not executed again. The key has 1 to 255 characters, belongs to the API
  key and the sandbox and is valid for 24 hours. The same key with a different body gives 422. An outcome
  interrupted by a stop, delete or reset of the sandbox is not stored, nor is a failed attempt. A response
  with more than 256 KiB of output (or truncated output) is not stored: a repeated call gives 409
  `IDEMPOTENCY_RESULT_UNAVAILABLE`. A reset or new start changes the generation, so the command
  is executed anew.
- **Label filter conflict** (b1b22c1, 1773133). A label key given twice with different
  values gives 422 on both list routes (sandboxes and volumes); the message is bounded and escaped.
- **Duplicate name** (805de3f, 6a6f704). A duplicate volume or snapshot name says that the name
  exists, without guessing about a missing organization; the conflict carries the reason `NAME_TAKEN`, and a
  missing organization has its own reason.
- **Command state on stop** (4326616, 225820e). A command interrupted by a sandbox stop reads
  `killed` without an exit code, with `stop_cause` `sandbox_stopped`. The cause is kept only in the
  process memory: after a server restart the command is `killed`, and `stop_cause` is `null`.
- **Git identity** (8f60617, 80c1216). A commit without a git identity returns a clear error with a
  named field, not raw git text; detection is pinned to the C locale.

3) CLI:
- **Mounting** (02edab7, 155e59c, 43a1634, 872a7f1). The parser names the rejected character, mode
  errors (`ro` or `rw`) are named as modes, and volumes are mounted by name. Help and the form text
  mention volumes; one constant for `--mount`.
- **Tables and hints** (65eb310, e6c0146, ef256eb, 169c157). The status and date columns are never
  dropped on narrow terminals; truncation is grapheme-safe; the volume table shows size
  and limit as JSON, raw bytes in the list and rounded before choosing the unit. The hints
  `CAPACITY` and Retry-After are honest.
- **`cp`, `exec`** (068486d, e5af1f3, e813198). Client errors in `cp` exit with 2, and `cp -r`
  into a read-only mount reports an honest message with the request id. `exec` prints a note about
  built-in commands and a hint for exit 126.
- **`SANDFORT_API_KEY_FILE`** (21576d3, c017e54). The key is read from a file; it is masked like any
  key; file edge cases are covered. The SDK user agent carries the installed version.
- **`sandfort usage`** (15d5c65, 103281c). A new command and the SDK facade `client.usage`
  (sync and async); the cursor requires an explicit period; pagination and totals are hardened.
- **Webhooks command** (f85391c). The `update` flags are mutually exclusive; a 404 with the argument
  in the wrong order suggests the `whk_` form.

4) SDKs:
- **`ExecResult.request_id`** (e5af1f3): the exec result carries the request id of the response.
- **TypeScript code context** (a960887, 19c93c4, 400fe75). Stateful code context:
  create, ensure, run, stream, interrupt and delete. `codeRun` honors `cwd`; `createVolume` accepts
  labels in typed code; `VolumeMountInfo` is exported; the information fields for volume and
  sandbox are more complete; a named `createCodeContext` reports that it was created; the snapshot id is in
  the timeout error.
- **TypeScript robustness** (872a7f1, f384283): mount paths are validated locally;
  SSE decoding is bounded, the error code lookup is safe, the stream timeout applies on every
  Node 20; the package requires Node >= 20.3.

5) Release and documentation:
- **Server wheel in the release** (c0d9d5f): the signed release also ships the server wheel
  (`deploy/release-wheels.sh`, `docs/release.md`).
- **Docs site** (073e942): relative redirects (without an `http://` step); a trailing slash is
  redirected to the clean URL.
- **Admin and ops** (30c0fc9): isolation gate refusal without a traceback; bootstrap names the org
  and the key; quiet message before the first key row.
- **Documentation** (06fd743, 3793813): signed export in the governance and runbook pages,
  guide notes (pending deliveries, sessions, memory, exec idempotency), TypeScript code
  context, usage and verify-head in the positioning documents.
- **CHANGELOG** (this commit; the hash is recorded in the next round). Round 61 section.

**Contract changes (contract):**
- **`verify-head` exit codes**: 0 when all checks pass, 3 when any fails (including
  the new reasons `truncated`, `head_mismatch`, `chain_break`, `malformed_row`,
  `misplaced_trailer`, `unchained_rows` and `no_trailer`), 2 only for unusable input.
  An export without a usable trailer or with a row after the trailer now fails with 3.
- **Label filter**: a key given twice with different values is a 422 on sandbox and
  volume lists (the request is rejected instead of picking one value).
- **`audit_public_key` in `GET /v1/status`** is non-`null` only when both the
  signing and chain keys are set.
- **Command information** has a `stop_cause` field (`sandbox_stopped` or `null`).
- **`ExecResult.request_id`** is a new field in the Python SDK.
- **TypeScript**: `createVolume` accepts label options, `VolumeMountInfo` is exported, and
  `engines` requires Node >= 20.3 (previously >= 20).

#### Round 60 (after tag `v0.1.0-beta.64`)
Items were committed to main after tag `v0.1.0-beta.64`, by group: usage and API, CLI,
signed audit export head, audit of rejected requests, webhooks, sanitizer and volumes,
documentation. Each is derived from the titles in `git log v0.1.0-beta.64..HEAD`. Items the
operator sees are marked with "(operator)", and contract changes with "(contract)".

**Operator obligations in this round (operator):**
- **`SANDFORT_AUDIT_SIGNING_KEY` (optional)** (1fd5ce2, 69334ac): Ed25519 private key, raw
  base64 or PEM. Without it the export head remains an HMAC head only, and `audit_public_key` on
  `GET /v1/status` is `null`. An invalid key rejects the configuration at startup.
- **Migration `r0022`** (91876e0): adds the columns `event_type`, `payload_sha256`, `last_error`
  and `attempt_history` to `webhook_deliveries`. Existing rows get `NULL` and an empty history.
  It runs with the usual `migrate` before the new version starts.

**Contract changes (contract):**
- **`verify_head` requires a public key** (b64d1ad, 4b53ec1, ab33eb5). In the SDK `public_key` has no
  default value: a call without it is a `TypeError`. The key is always known to the caller (a key
  that the row itself names is never accepted) or the text `"status"`, which reads `audit_public_key`
  from `GET /v1/status`. `AsyncAudit.verify_head` is now a coroutine (`await`), because `"status"`
  sends a request; with an explicit key there is no request. `HeadVerification.anchored` was removed
  (it was always true), and `signed_at` follows directly after `reason`.
- **The webhook delivery response has new fields** (4fa9532). `event_type`, `last_error`,
  `payload_sha256` and `attempt_history` were added. Earlier releases did not have them; rows before
  migration `r0022` return `null` and an empty history, respectively.

1) Usage and API:
- **Usage by label scope** (093d422). A key restricted by labels (`sandbox_labels`) in
  `GET /v1/org/usage` sees only its own sandboxes: in the totals, in the per-sandbox groups and
  in the per-label groups.
- **Typed grouped response** (093d422). `group_by` returns a list of `UsageGroup`:
  `group_key`, `group_value`, `totals` and, for `group_by=sandbox`, `name` and `labels`. Pagination
  goes through `cursor` and `limit`; the cursor is valid only with the same `from`, `to`, `group_by` and key scope.
- **Mount paths** (028b042). `mount_path` rejects the colon, comma and backslash
  (Docker bind syntax), system binary trees and files managed by Docker.
  The message names the character class or segment.

2) CLI:
- **Strict mount parser** (028b042, 3d512b2). An empty path is a usage error, not a
  silent default; the same characters as on the server are rejected before the request.
- **`create --wait` deletes the failed sandbox** (a91d2f9). A sandbox in state `error` or
  `start_failed` is deleted unless `--keep-on-failure` is given; the message names the command
  `sandbox rm` when the sandbox is kept.
- **`cp -r` into a read-only mount** (a91d2f9, 3d512b2). The display is the same as when copying
  a single file: 409 `READ_ONLY_PATH`, "nothing was written".

3) Signed audit export head:
- **Ed25519 head** (1fd5ce2, 69334ac). The `audit_head` trailer carries `alg`, `public_key`,
  `signature` and `signed_at`; the signature covers `signed_at`. The signer is read only from settings.
  The public key is `audit_public_key` on `GET /v1/status`.
- **SDK** (b64d1ad, 4b53ec1, ab33eb5). `client.audit.verify_head(line, public_key)` and
  `client.audit.public_key()` (sync and async). `ok=False` with reason `unsigned`, `signature`,
  `key_mismatch` or `undated`.
- **CLI and admin** (ef21d81). `sandfort audit verify-head <file> [--public-key KEY]`: exit 0
  when the signature is valid, 3 when it is not, 2 when the file, trailer or key is unusable. On
  `audit export` stderr lists the key fingerprint. `audit-verify --head FILE --public-key KEY`
  reports an unsigned head or a bad signature as a `head_invalid` finding.
- **Old heads** (862df0b, ab33eb5). Signed heads from releases `v0.1.0-beta.60` through
  `v0.1.0-beta.64` have no `signed_at`: they parse, but verification reports `ok=False` with
  reason `undated`, even when the signature is valid.

4) Audit of rejected requests:
- **Capacity refusals** (e62e1e1). A refused create and start write `sandbox.create_refused`
  and `sandbox.start_refused`.
- **Rejected responses are not success** (c845959). A rejected response is recorded as `denied` or
  `error`, never as `success`; redeliver writes `webhook.redelivered`.
- **One row per refusal** (bcb3da7, 862df0b). A rejected request writes one row; the upload audit
  is recorded before the driver call.

5) Webhooks:
- **Delivery details** (91876e0, 4fa9532). Event type, attempt history (the newest 6,
  oldest first), last error (up to 200 characters) and `payload_sha256` (hash of the signed
  body, not the body). The dispatcher records every attempt.
- **Redeliver** (d66db6a, 862df0b). Only `failed` and `disabled` deliveries; the attempt count goes to
  0, the state to `pending`, the history is kept with a `redelivered` entry with the actor, and
  `next_attempt_at` stays `null` until the dispatcher writes the time.
- **Filters and cursor** (4fa9532). The delivery list accepts `event_type` and `state`; the cursor is bound
  to the endpoint and filters. Rows before `r0022` do not match the `event_type` filter until the
  dispatcher fills them in.
- **SDK facade** (86865e5). `client.webhooks`: create, list, get, update, delete, deliveries,
  iter_deliveries, get_delivery and redeliver, sync and async.
- **CLI `webhook` group** (6e675f6). `create`, `list`, `get`, `update`, `rm`, `deliveries`
  (with `--event-type`, `--state`, `--all` and `--show`) and `redeliver`. The signing secret
  is printed only with `--json --show-secret`.

6) Sanitizer and volumes:
- **Sanitizer** (b46e5a7, 69e829e). Punctuation and whitespace of all scripts count as
  host separators; IPv6 hosts in brackets, with a port and fragment, are masked too.
- **Volume labels** (f0231ef). Empty label values are allowed; label errors are
  usage errors; `volume list --label KEY=VALUE` filters. The create audit carries `read_only`.

7) Documentation and site:
- **Governance page** (7bdc412). Published and linked from the security page;
  `/api` serves the API reference, and `/api/` redirects to the root (fd110e8).
- **Guide** (1c4eb1b). Audit rows and CLI commands, naming rules, a recipe for webhooks.
- **Release page** (1c4eb1b). Signing key fingerprint.
- **Spec and site output** (09bd937, 4278373). Regenerated OpenAPI spec and docs site.
- **CHANGELOG and guide** (68ebf93). Round 60 section,
  the "Webhooks from the CLI" subsection and `audit verify-head` in the guide.

#### Round 59 (after tag `v0.1.0-beta.61`)
Items were committed to main after tag `v0.1.0-beta.61`, by group: incident and docs site,
API and volumes, SDK, CLI and admin, release, TypeScript SDK, documentation. Each is derived from
the titles in `git log v0.1.0-beta.61..HEAD`. Items the operator sees are marked with
"(operator)".

**Incident on the beta.** After a bare run of the `host-setup` script, sandboxes with an egress allowlist
were unreachable: the script did not derive the egress proxy endpoint. The fix is in group 1 (9a56667).

**Operator obligations in this round (operator):**
- **`SF_EGRESS_PROXY` at host setup** (9a56667): `deploy/host-setup.sh` derives the egress
  proxy endpoint from the env file or from the egress gateway and rejects the loopback default.
  If the endpoint cannot be derived, set `SF_EGRESS_PROXY` explicitly before running.
  The reminder after redeploy now carries `SF_EGRESS_PROXY`.
- **`SANDFORT_VOLUME_MAX_BYTES` (optional)** (c834145): soft limit on volume size.
  Without this setting there is no limit.
- **`prod` preflight** (765e6bd, 58e9168): configuration blockers are collected in a single pass
  and the preflight is applied at server start; see group 3.

1) Incident and docs site:
- **Deriving the egress proxy endpoint** (9a56667). `host-setup` reads the env file or the egress
  gateway; the loopback default is rejected; the redeploy reminder carries
  `SF_EGRESS_PROXY`.
- **Light scheme for the docs site** (29f83e8, 62c0999). The scheme follows `prefers-color-scheme`; the API
  page stays dark (`always-dark`); the navigation background and zebra rows follow the scheme.
- **Not-found page, robots and sitemap** (fb73f6d, 1fbee7c). Links on the not-found page are
  root-absolute (no `base` element); fonts are allowed in the docs site CSP; the API
  page has a dark `theme-color`. Deploy keys and tests were added.
- **Nginx configuration in the repository** (f12f70e). Static configuration with clean docs
  URLs and a not-found page; a new `nginx` target for redeploy.
- **Release page on the docs site** (574e1ab). See group 4.
- **Docs site output** (21f700e). Regenerated with the light scheme, not-found page, robots and
  sitemap.

2) API and volumes:
- **Soft volume size limit** (c834145). `SANDFORT_VOLUME_MAX_BYTES`: `over_limit` in
  responses; a read-write mount over the limit is rejected with `VOLUME_OVER_LIMIT`.
- **Read-only in the sandbox view** (dd44a76). `read_only` is in the mount view; upload to a
  read-only mount answers `READ_ONLY_PATH`.
- **Downloads** (dd44a76). Download responses carry `Content-Length` and `ETag`.
- **Capacity details** (dd44a76). The capacity details response does not contain the total values
  of the host.
- **Scratch volumes for image paths** (5f97253). Volume paths declared in the image
  get labeled per-sandbox scratch volumes instead of anonymous ones; `image_mounts` is in the
  sandbox view.
- **`mount_path` validation** (764b682). Visible text, normalized path, no system
  directories.
- **One form of reserved label** (764b682). Message without the "Value error" prefix; limits for the
  API key label.
- **Query guards on the remaining routes** (08145c1). Single-valued and known query parameters.
  The `in_use` conflict on volumes does not reveal sandbox IDs outside the scope.
- **Audit export trailer** (0b2f001). The REST audit export carries a signed head or a digest as a
  trailer; a repeated cascade value in the query answers 422.

3) SDK, CLI and admin:
- **SDK audit facade** (1027135, 63c7165). `audit` on `Client` and `AsyncClient` (list, iter,
  verify, export); strict payload validation, deeply frozen `details`.
- **CLI `audit` group** (fc53e21, 05029b0). `list`, `verify` and `export` over the SDK facade; list
  and export stream.
- **Volume labels and read-only mount in the SDK and CLI** (9d4a0cb). Labels on volumes;
  `VOLUME:PATH:ro` mounting; `read_only` in sandbox views.
- **CLI hints** (65c9035, 05029b0). Hint for exit 127; `exec` hint with an explicit
  shell; the download error names the remote reference; fix for absolute paths in the
  `cp` usage message; tilde paths in `cp`.
- **Sanitizer** (d039bbb). Masks the host after CJK sentence punctuation and `host:port#fragment`
  after a key-like separator.
- **`admin revoke-key`** (d8aac0f, 9a3ac9d). Revokes any key from the host; the 403 response and
  the `create-key` help name the fix for the platform admin; the error repeats only the key prefix;
  empty selectors are rejected.
- **`prod` preflight** (765e6bd, 58e9168). Collects configuration blockers in a single pass and
  prints them without a traceback; the gate names the egress override; the preflight is applied in the
  `serve` lifespan, the egress hint only in `prod`, findings are logged once.
- **`admin doctor`, parity with start gates** (1ed490c, 9a3ac9d). Rows for all gates, root
  on a shared kernel, host capacity, preflight details, a driver row and a final
  verdict line (also in JSON output).

4) Release:
- **Tag version in the image** (574e1ab). The image carries the baked-in tag version; allowed signers and
  fingerprint sit alongside the wheels; release page on the docs site.

5) TypeScript SDK (`sdk/typescript/`):
- **Tests** (7b4831d, 337ae34). Git push and pull tests follow the `remoteUrl` contract; the
  `create` body is checked against the OpenAPI schema; `abortableSleep` cleanup.
- **Pagination** (3df3515). Zero cursors, auto-pagination helpers, list filters.
- **`createSandbox` options** (a649410). Parity with `CreateSandboxRequest`.
- **Timeout, abort and retry** (7506e07). Per-request timeout, abort signal, bounded retry.
- **`deadlineMs`** (1e2a3d2). Total budget for attempts and pauses between retries.
- **Exports and status** (ffabcca, ea4c2d3). Runtime exports, `ValidationError`, `status()`, version
  stamp; internal helpers are not exported, `MAX_RETRIES` is exported.
- **Fixes after review** (78c052f, dafb447, d8b59c5, dbea6a6, 69d76ba, 1f8b2ab, 1c7b5b3,
  64bcf3b). The download body is read inside the resilience wrapper; `Retry-After` accepts only whole
  seconds or IMF-fixdate; fallback without `AbortSignal.any`; one list pass per `create` for
  named volumes; long wait polls follow the request timeout with option validation; label
  and snapshot lengths in code points; shared response decoding, `cause` on
  wrapped errors; shipping `LICENSE`, SPDX license identifier, no unresolvable source maps.
- **README** (4b261ea, 7f164b8, be3718e). Rewritten for the new options, pagination and retry; without
  internal jargon; the `VERSION` comment points to `tests/surface.test.ts`.

6) Documentation and spec:
- **Guide** (6cdb53e). Quick-start box for the CLI, key from the environment, wheel versions
  derived from the tag, release signature; a section on volumes.
- **Spec and site output** (d90b362). Regenerated OpenAPI spec and docs site for round 59.
- **CHANGELOG** (138c591). Round 59 section.

#### Round 58 (after tag `v0.1.0-beta.59`)
Items were committed to main after tag `v0.1.0-beta.59`, by group: persona findings, audit
of isolation, release engineering, documentation and site. Each is derived from the titles in
`git log v0.1.0-beta.59..HEAD`. Items the operator sees are marked with "(operator)", and changes
that break existing calls with "(BREAKING)".

**Isolation audit (2026-11-10).** The isolation audit (opus) produced 0 CRITICAL, 5 HIGH, 6 MEDIUM and
9 LOW findings. All were resolved in this round; the items are in group 2.

**Changes that break existing calls (BREAKING):**
- **Git push and pull with a credential require `remote_url`** (772555e, cd02319). The token is bound to
  the URL supplied by the caller; a call with a credential and without `remote_url` no longer passes. TypeScript
  SDK requires `remoteUrl` with a git credential.
- **Mounting a volume requires volume scopes** (b07bc7b, 1e87787). A key without the matching
  scope cannot mount a volume; a key bound to a label mounts only its own volumes.
- **Label bounds** (ea2c856, 86f5939). Sandbox labels have bounds and are rejected with a plain
  message; `null` labels are documented.
- **Key revocation no longer cascades by default** (cb27626, 69ac1da, 9aee657). The cascade is
  explicit, with a preview of dependent keys (the SDK and CLI give a hint about dependent keys);
  keys created by another key are limited by the creator's expiry.

**Operator obligations in `prod` (operator):**
- **Host capacity** (63de6be): the host capacity gate is a new required setting.
- **Egress probe** (f46517e, 0508104): the canary probe replaces the confirmation flag; the confirmation becomes
  an explicit override.
- **Egress settings** (ba9c03a, 5b3f2ce, 8d68d27): token expiry, allowed registries and the network
  of the build are read from settings.
- **Key for the keyed audit chain** (56b8f8d): the HMAC chain requires a key.

1) Persona findings:
- **CLI option `--stop-cause` and SDK argument `stop_cause`** (3b518d2, f0af6dc). Hints for the stop
  cause; the list help wraps normally.
- **Repeated options and parameters** (3b518d2, e312df4). A repeated single-value list option in
  the CLI is a usage error; a repeated single-value query parameter is a 422 on every route.
- **Cursors** (69d2593, d141f36). The cursor carries the resource and filter on every list route; the rejection
  names the filter fields that differ.
- **422 shape for the label filter** (879ed23). All label filter rejections share the same shape
  of the `details` item.
- **Invalid UTF-8 in the body** (1503088). A JSON body with invalid UTF-8 gets the standard 422 response.
- **Sanitizer** (36e4025, a4618ce). Finds the host after separators and CJK punctuation;
  credential masking is limited to uncut text; truncated credentials after a noisy
  prefix with encoded or Unicode colons are dropped.
- **Messages and hints** (030ecac, f0af6dc). Singular for byte, wording for control characters,
  message for the profile key.

2) Isolation audit:
- **Empty egress allowlist = block-all** (7184968, b22d93a). An empty list blocks the entire network and
  is described in the help.
- **Host guard on the allowlist bridge** (1d37123, 5f00e8f). Interface checks, honest resume
  messages, return forward limited by ports, derivation of the proxy port.
- **Git credentials bound to the caller's URL** (772555e). See BREAKING.
- **Build runtime and root-on-runc gate** (4ce3994, 14d9e01, 423fd3e). `prod` requires a build
  runtime and the Docker driver; builds are limited; `prod` rejects root on `runc` without remap;
  minimum `runc` version; tier family validation.
- **Egress probe as a gate** (f46517e, 0508104). The probe does not fail startup, has a timeout, a positive
  control and cleanup.
- **Fixed bridge names** (00e62e0, b22d93a). The bridge name warning is given once, with
  operator overrides; the k8s kit has no preset egress confirmation.
- **Egress proxy** (70ac88a, 9b706f0, ba9c03a, 5b3f2ce, 4d1d645). Rejected CIDRs and
  interface enumeration, allowed ports, a per-sandbox connection cap, global and pre-auth
  caps, idle timeout, bounded token expiry, legacy tokens accepted across the upgrade, expiry
  derived from the auto-delete horizon, re-mint on reset; start does not re-mint (documented).
- **Volume labels and scopes** (86f5939, 1e87787, b07bc7b, 636b604). Labels on volumes with
  a filter; scope on get and delete; safe filter keys.
- **Read-only mount** (1e87787, 5b3f2ce). Read-only mounting reaches the driver.
- **Docker client without the operator's logins and allowed registries** (d891c2f, 8d68d27). The policy
  of allowed registries also applies in builds; doctor shows the registries and the build network.
- **Preview cookie `__Host-`** (4aba826). Secure cookie with the host prefix.
- **Keys bound to the creator and explicit cascade** (9aee657, cb27626, 69ac1da). See
  BREAKING.
- **Per-org log budget** (19ee5ec, 7d23f01). Command log budget per org; sessions
  write logs under their own org, `org_id` is required.
- **Keyed HMAC audit chain and signed export head** (56b8f8d, fe3a68e). Acceptance
  of unsigned rows; an unsigned tail is a finding when the key is set; byte comparison.
- **Operator policy** (63de6be). Enforced `block network`, default
  org quotas, host capacity gate, host-wide admission lock.
- **`admin doctor` command** (87d358e). Checks the host and settings against the `prod` gate.

3) Release engineering:
- **Release script** (8a4a4f0). The script in the repository builds a wheel with SSH-signed sums,
  allowed signers and a release guide.
- **Version from the git tag** (6abcdb6). `setuptools-scm` (form `0.1.0bN`); build info reports
  the installed version.
- **Image on GHCR** (a9dfefd). CI builds and publishes the API image on the release tag.
- **BUILD_SHA in the image** (8ba4ab2, cb0e78e). The image carries a baked-in build sha and labels; the status route
  reports `image_sha` and `build_matches_image`.
- **Deploy by image** (8ba4ab2). Deploy by image reference with a check of the revision label and a target
  for rollback.
- **Node-setup for gVisor** (868fce4, 5c8aa59). Installation from a per-architecture tarball with
  helper binaries; the hash is pinned, with an explicit escape for unpinned.

4) Documentation and site:
- **Security and isolation pages published** (ca0a77d, aaa29ed): links to the published
  pages, softer wording for `microvm`, key and expiry, build gate, volume labels,
  log budget.
- **Release page** (c6cf37c): versions from tags, image provenance, rollback.
- **Operations additions** (634b8e0): doctor, host script flags, egress settings, production
  gate, policy settings.
- **K8s and compose kits** (4527fca, 6e780c2): follow the egress probe, root-on-runc gate, capacity
  of the host and the keyed audit chain; egress design and a deploy note.
- **Spec and site output** (4279e1d, d6ee7a4, 7c24ccb): regenerated OpenAPI spec (volume labels,
  read-only mount, label bounds, cascade) and docs site output; tests follow the behavior of the round
  (c74f968).

#### Round 57 (after tag `v0.1.0-beta.57`)
Items were committed to main after commit 8952716, by group: CLI and SDK, sanitizer, API,
docs site and deploy, documentation. Each one is derived from `git log 8952716..HEAD`. Items that
the operator sees are marked with "(operator)".

**Incident 2026-11-10.** The previous deploy script (`deploy/redeploy-beta.sh`) restarted
the API container on the old image, while the status route already showed the new sha: it did not
build the image, so `SANDFORT_BUILD_SHA` wrote the new commit onto the old image. As a result,
`v0.1.0-beta.55` and `v0.1.0-beta.56` actually ran server code from `v0.1.0-beta.54`, although
`build_sha` in `GET /v1/status` showed the new commit. Fixed in 8952716 (outside the scope of this
round): the script now builds the image, runs migrations and compares the `paths` of the live OpenAPI spec with
the committed `openapi/sandfort.v1.json`; if they differ, the deploy aborts with an error. Until then,
`build_sha` must not be taken as proof of the code that is running.

CLI and SDK:
- **Option `--stop-cause` for the list and SDK argument `stop_cause`** (cd0a8c8, 054bfc4). The CLI list
  of sandboxes accepts a filter by stop cause only as the `--stop-cause` option (there is no positional
  argument: `sandbox list requested` is an unexpected extra argument); the SDK takes a named
  argument `stop_cause`; the list help is more readable. Shared list
  parameters in the SDK carry `stop_cause`, the list help has no orphaned line, and the causes in the CLI are tied to
  the literal from the SDK.
- **Hints and messages** (70a3870, 801714a, 2671313). New hints for a character, invisible characters and
  bytes that do not decode; a message for a name consisting only of escape sequences; a profile
  key with surrounding spaces is rejected; keys consisting only of invisible characters from
  older profiles; singular in the file count. The empty name check agrees with the sanitizer on
  interrupted sequences, and the test expectations follow the hints for the character and the code point.
- **Escape sequences** (01b5271). Short ESC sequences and C1 CSI with parameters count as
  an empty name; C1 CSI with a final byte is empty.

Sanitizer (`cli/src/sandfort_cli/`):
- **Hosts and punctuation** (9215d59). The sanitizer handles IDNA dots and Unicode punctuation
  in hosts, a space after the @ sign and closing brackets after numeric fragments.
- **Performance** (88a282d). The backward host search converts only the tail of the string; helper functions for
  hosts are in their own module (`sanitise_hosts.py`); docstrings state the trade-offs.

API:
- **Repeated query parameters** (af5dea1, a49fcc9). A repeated `stop_cause` or `state` is a 422;
  after a49fcc9 the same applies to every single-value list parameter that is repeated.
- **Label filter and cursor** (9d533b4). Label filter rejections have a single 422 shape; the cursor
  is bound to the filter under which it was issued.
- **`max_bytes` and preview token** (47edaf3). One message for the `max_bytes` limit; the preview token
  requires a running sandbox.

Docs site and deploy:
- **(operator) `security` and `isolation-tiers` pages published** (086d6ab, 9e6052a). The docs
  site now publishes both pages, with cards; the footer is built from the page list; the dead
  link to the governance page was removed; the build test covers all pages.
- **(operator) Deploy script ships the new pages** (9e6052a). `deploy/redeploy-beta.sh`
  includes `security` and `isolation-tiers` in the docs site delivery.

Documentation (0440796, f6f68ec, 337b718, 903a16b, 120bd5c): the guide describes bytes in `cp`,
CLI usage errors, the `--stop-cause` option (without a positional argument) and the 422 for a repeated
query; seccomp under `runsc` is stated more precisely, with the seccomp profile of the API pod and caveats in the tier
table (f6f68ec, 903a16b); sanitizer rules for hosts in any script, numeric
fragments, bare credential and trade-offs (337b718); an aligned sentence about isolation and
wording for `runsc`,
`api_key` error shapes, `stop_cause` in the list summary, links to published pages and the rule
for an empty user in a credential (120bd5c). Regeneration of the docs site output: e56dd01.

#### Round 56 (after tag `v0.1.0-beta.55`)
Items were committed to main after tag `v0.1.0-beta.55`, in commit order: validation
of requests (01eb734), `stop_cause` surfaces on the server (6664319), CLI usability (8d36ba7), `cp`
(de21bdf), spec regeneration (0480996), sanitizer (dc09c4e) and two documentation items
(a50372f, 1415d9f). Each one is derived from the diff of the listed commit.

Changes the operator sees:
- **Audit rows for automatic stop and delete have `actor_type` `system`** (6664319). The row
  `sandbox.auto_stopped`, which is written by the idle timer, previously carried `actor_type` `api_key`;
  it now carries `system` when there is no `actor_id`. The same change (helper function `record` in the service
  for jobs, `src/sandfort/services/sandbox_jobs.py`) also applies to `sandbox.auto_deleted`: that row
  now says `system` as well. Older rows are not changed.
- **New list filter `stop_cause`** (6664319; spec 0480996). `GET /v1/sandboxes?stop_cause=<vrednost>`
  takes a single value (`requested`, `auto_stop`, `container_exited`, `oom_killed`, `unknown`);
  an unknown value is a 422. It combines with `state`, `label`, `order` and `cursor`. The parameter is in
  `openapi/sandfort.v1.json` as an enum.
- **Spec regenerated** (0480996): a mechanical export of the application, without manual edits; the diff adds only
  the query parameter `stop_cause`. The fields from 01eb734 that do not accept JSON `true`/`false` as a number
  did not change the exported spec.

Changes clients see:
- **Request validation** (01eb734). A label key consisting only of spaces and invisible
  format characters is rejected. The fields `port` and `ttl_seconds` (preview) and `timeout_s` (sessions and code
  contexts) do not accept JSON `true`/`false` as a number. Inline `max_bytes` when downloading a file
  accepts only digits, at least 1 and at most the default handler limit; larger or differently
  written values are 422.
- **`stop_cause` in 409** (6664319). A 409 `CONFLICT` response with reason `no_container` (exec and
  other toolbox calls on a sandbox without a container) carries `details.stop_cause` while the sandbox is `stopping` or `stopped`, along with
  `details.state`; the value is the one shown by the sandbox object, so it is `unknown` when the cause is
  unknown (a row without a cause). In other states, including `destroying` and `destroyed`, the key is
  omitted (cf329f1). An invalid label filter in the list is a 422 (`UNPROCESSABLE`).
- **CLI** (8d36ba7). `sandfort key create --help` lists the scope names; the hint with a 409 on exec
  ends with "stopped because: <cause>" when the server knows the cause; `--wait-timeout` gives the same hints
  as integer options; the message about a corrupted profile reads `api_key in <putanja> <problem>`;
  label keys in tables are sanitized; a repeated label key is a usage error, not a silent
  last-wins.
- **`sandfort cp` reports the bytes of the copied files** (de21bdf), not the archive size.
- **Sanitizer** (dc09c4e): masks hosts with non-ASCII letters before the query (`café?token=...` is
  masked as `what?x=1`), short numeric fragments remain (only ASCII digits, at most six, e.g.
  `feature#12`; if a scheme (`://`) precedes the anchor, at most three digits remain, so a verification
  link with a six-digit code is masked), and a bare userinfo (`user:secret@host:8443`, also with an empty user) is masked.
  SOS inside credentials was already removed before (`cli/src/sandfort_cli/sanitise.py`), so this is not
  a new behavior change.
- **Documentation** (a50372f, 1415d9f): only
  `marketing/pilot/beta-connect-guide.md`, `docs/operations.md`, `docs/security.md`,
  `docs/isolation-tiers.md` and `CHANGELOG.md`, no code changes. Guide: the response to the WebSocket
  handshake (422 for a rejected path or query, 400 from the edge for NUL), 409 `CONFLICT` "modified
  concurrently", `stop_cause` filter and an audit query for repeated exits, description of the isolation tiers.
  Security: section 1 describes three tiers and the tier map; section 2 lists
  `SANDFORT_ENFORCE_DISK_QUOTA`. Operations: audit row `system`, `stop_cause` filter, names
  of CLI variables.
- **Review fixes** (in commit order). Code: cf329f1 (409 `no_container` reports the visible
  `stop_cause`), dd0d796 (`stop_cause` filter in SQL; a label key made only of spaces is rejected),
  0955754 (module for text checks; letters that look empty count as invisible; dead
  branch for the displayed name removed), db77289 (test: `max_bytes` over the limit gives 422 on
  file download), 4a71164 (`cp` tests count file bytes; a report hint with every
  profile key error), dd2e8b1 (CLI modules for numbers and escapes; hint for the underscore;
  docstring of the pair parser; merged label cleanup), b267353 (sanitizer: the host string accepts
  combining marks; the numeric fragment exception is limited by space, punctuation and scheme),
  4ebf3e0 (sanitizer: restricted pattern for a bare credential; an empty user requires a port, a host with
  a dot or in brackets; coverage of break characters). Documentation: eb4d713 (corrected
  CHANGELOG for round 56, more precise `auto_deleted`, drift filter and `no_container` in operations),
  32990c0 (guide without first-person notes, WebSocket wording per observation on the beta, filter
  for drift, `no_container` and `expected_version` details, a paragraph on the CLI hint, seccomp per set,
  c3f84b4 (seccomp per deployment set, tier settings in the checklist,
  capabilities on all three tiers, simpler isolation wording).

#### Round 55 (after tag `v0.1.0-beta.54`)
All items were committed to main after merge commit `81d1241` (round 54), in the order of the
commits: one documentation item for decision D2 (a971c60), two driver commits (a96410f and the
fix 6304aa7), one commit for deployment scripts (4de92ed) and a documentation item that
corrects the documents after the code (1b04004). Each is derived from the diff of the named commit.
`openapi/sandfort.v1.json` is not changed.

Changes the operator sees (server startup behavior and node scripts):
- **The production gate is active on compose** (4de92ed). `deploy/compose.prod.yml` has until now
  set `SANDFORT_ENV: prod`, and the server does not read that variable; the production switch is
  `SANDFORT_ENVIRONMENT`. The old variable was ignored, so the compose deployment ran
  without production checks. The file now sets `SANDFORT_ENVIRONMENT: prod`, so as of this release
  the isolation check at startup, the egress rules acknowledgement (`SANDFORT_EGRESS_ACKNOWLEDGED`),
  the mandatory `SANDFORT_WEBHOOK_SECRET_KEY` and https-only webhooks apply. A compose host that
  previously started without them refuses to start until that is met. The Kubernetes kit already set
  `SANDFORT_ENVIRONMENT` and is not changed here.
- **The finding about the daemon default runtime is a warning everywhere** (a96410f, 6304aa7). When `docker
  info` reports a default runtime that no tier uses (a tier mapped to an empty runtime
  counts as the default), the server writes a warning to the log at startup: "default runtime ...
  is not among the configured sandbox runtimes ...; tenant image builds run on it (advisory only:
  logged as a warning, never refuses startup until a separate require flag exists)". It never
  refuses startup, in neither `prod` nor `dev`.
- **The user-namespace remap finding** (a96410f, 6304aa7): "user-namespace remapping: not active
  on the daemon (userns-remap in daemon.json); container root maps to host root except for tiers that
  opt out per container". In `prod` it refuses startup only with `SANDFORT_REQUIRE_USERNS_REMAP=true`; without
  that it is written as a warning ("isolation advisory (does not refuse startup)") on every
  startup. Outside `prod` it is written as a tolerated finding. If `docker info` does not list `name=userns`,
  remap is considered not active.

#### Decision D2 and documentation before code
- **Documentation: decision D2** (a971c60): only `.context/decisions.md`, `docs/architecture.md`,
  `docs/security.md`, `docs/operations.md` and `docs/isolation-tiers.md`, no code changes. The decision on
  isolating the Docker socket: image builds do not run on bare runc, `docker0` is filtered, the `container`
  tier is explicitly mapped to runc when the daemon runtime is gVisor, remap with an exception for
  Kata, authorization plugin, then node agent. The text was written before the code and claimed that the settings,
  opt-out and flags do not exist yet; the item "Documentation: D2 after code" below corrects that.

#### Driver and settings
- **Driver: cgroup parent, per-tier userns and daemon facts** (a96410f): three new
  settings in `src/sandfort/config.py`.
  - `SANDFORT_CGROUP_PARENT` (empty by default): the cgroup parent of every sandbox container;
    empty leaves Docker's default.
  - `SANDFORT_USERNS_HOST_TIERS` (default `microvm`): a comma-separated list of tiers whose
    containers are created with `userns_mode="host"`, because Kata does not work in a remapped namespace.
    Spaces and capital letters are ignored, duplicates are merged, an unknown tier is an error when loading
    the settings. An empty (set) value removes the exception for all tiers.
  - `SANDFORT_REQUIRE_USERNS_REMAP` (off by default): in `prod` it refuses startup without remap.
  - The capabilities report (`DockerCapabilities`) gets three fields from `docker info`: `userns_remap`
    (`name=userns` among `SecurityOptions`), `default_runtime` and `cgroup_driver`.
  - Legacy single-runtime mode: when `SANDFORT_CONTAINER_RUNTIME` is a Kata runtime without a tier
    map, Kata is on the `container` tier, which is not in the default exception list. On a remapped
    daemon, set `SANDFORT_USERNS_HOST_TIERS=container`.
- **Driver: findings reach the startup gate, warnings, slice name check** (6304aa7):
  - `isolation_gaps` now passes the settings along, so the remap finding really enters the gate; previously
    the findings from a96410f did not reach `check_isolation`.
  - The default runtime finding is separated into advisory findings (`advisory_findings`) that are
    only logged; the finding text now says it is advisory.
  - `SANDFORT_CGROUP_PARENT` must be a systemd slice name: letters, digits, `_`, `.`, `@`, `:`, `-`,
    ending in `.slice`, without `/`, without `..`, without spaces and control characters. Previously only
    a space was checked. Any other value fails loading of the settings.

#### Deployment scripts
- **Deploy: node flags, `docker0`, production variable name** (4de92ed):
  - `deploy/node-setup.sh`: new optional flags `--default-runtime-runsc`, `--userns-remap`,
    `--live-restore` (they merge `default-runtime`, `userns-remap` and `live-restore` into `daemon.json`;
    the first two require a Docker restart) and `--with-slice` (creates and enables `sandfort.slice`). The smoke
    test for `kata` runs with `--userns=host` when remap is active. `--check` and the final report
    print the default runtime, the remap state and the live-restore state. `--rollback` does not remove the slice
    (nor the installed binaries).
  - `deploy/host-setup.sh`: the default bridge `docker0` (variable `SF_DEFAULT_BRIDGE_IFACE`),
    on which image builds run, enters the same two iptables hooks (egress and host guard) as
    `sf-net`, for IPv4 and IPv6.
  - `deploy/compose.prod.yml`: `SANDFORT_ENV` replaced with `SANDFORT_ENVIRONMENT` (see the first
    item above).

#### Documentation after code
- **Documentation: D2 after code** (1b04004): only
  `docs/architecture.md`, `docs/security.md`, `docs/operations.md`, `docs/isolation-tiers.md`,
  `.context/decisions.md`, `CHANGELOG.md` and `marketing/pilot/beta-connect-guide.md`, no code
  changes.
  - Paragraphs that claimed the driver does not set the userns mode, that no setting feeds the
    cgroup parent, that the self-check does not read userns and that opt-out does not exist are replaced with the state
    from the code: three settings with names, default values and validation, per-tier opt-out, daemon
    facts, the texts of both findings and the gate rules.
  - `docs/operations.md`: the `node-setup.sh` flags, `docker0` in `host-setup.sh`, a note on the
    legacy single-runtime mode, the expectation that the `microvm` tier check passes and
    two-step enabling (deploy with the flag off, check the warnings and one
    sandbox per tier, then enable), and a correction of the compose variable description.
  - `.context/decisions.md`: the consequences of decision D2 list commits a96410f, 4de92ed and 6304aa7.
  - `CHANGELOG.md`: this round and the real hash (318e3f2) of the previous documentation item of round 54.
  - Guide: one paragraph in the "Isolation tiers" section saying that the hosted beta moves to gVisor for
    image builds and enables remap, without a date and without a claim of stronger isolation than the microVM
    services.

#### Round 54 (after tag `v0.1.0-beta.53`)
All items were committed to main after commit `14dd64f` (round 53), in commit order:
one documentation accuracy fix, five server fixes, six CLI fixes, the `stop_cause` feature
(four commits: server, spec and SDK model, CLI, SDK types) and two documentation items (a037e1f and
318e3f2). Each is derived from the diff of the named commit. The spec
`openapi/sandfort.v1.json` was regenerated only in 8bd0ad9; ebbbb97 changes route descriptions and limits, but
does not touch the spec (see its item).

Changes that scripts can see:
- The sandbox object (REST, `SandboxInfo` in the Python SDK and the `--json` output of the CLI) has two new
  fields that can be `null`: `stop_cause` (the reason for stopping, `null` except in the states `stopping` and
  `stopped`) and `stopped_at` (the time of stopping, `null` except in the state `stopped`) (8bd0ad9).
  Existing fields do not change.
- The database schema gets the column `sandboxes.stop_cause` (migration `0020`, nullable `Text`, no
  backfill). Before starting the new version, `alembic upgrade head` is run (0aef00c). A sandbox
  stopped before the migration shows `stop_cause` as `unknown`.
- The payload of `sandbox.*` events (webhook) has the key `stop_cause` next to `reason` and `error_code`; except in
  `sandbox.stopped` the value is `null` (8bd0ad9). The audit rows `sandbox.stop`,
  `sandbox.auto_stopped` and `sandbox.drift_detected` (with `stopped_unexpectedly`) have
  `details.stop_cause` (0aef00c).
- `GET /v1/sandboxes/{id}/logs?since=` with the value `nan`, `inf` or `-inf` responds with 422 and the type
  `finite_number` and the message "Input should be a finite number of seconds"; status 422 and `loc`
  `["query", "since"]` are as before (479bfc7).
- `POST /v1/org/members` with a `display_name` that is empty after trimming spaces, has a control
  character or contains only spaces and invisible format characters responds with 422 `VALIDATION_ERROR`; previously
  only the length limit of 1 to 255 applied (479bfc7).
- The filter by labels (`labels` on list routes, `--label`) no longer breaks the whole query when a
  sandbox row stores NUL or a lone surrogate in labels: such a row is omitted from the filter results
  (0f977f2). New administrator rule for the repair: `repair-labels`.
- A request with JSON `true` or `false` on any numeric body field responds with 422
  `VALIDATION_ERROR` with the type `number_not_bool`; the rule now also applies to `max_sandboxes` of a key,
  `size_bytes` and `max_bytes` (fs), `depth` (git clone), `timeout_s` (exec and code-run) and `rows` and
  `cols` (PTY create and resize) (ebbbb97).
- `PUT .../toolbox/fs/upload` with `size_bytes` in the query that is not a plain string of decimal digits
  (`10.0`, ` 10 `, `+10`, `1e1`) responds with 422 and the type `int_parsing`; previously the looser parsing read
  `10.0` and ` 10 ` as 10. The limit is `0` to `MAX_UPLOAD_BYTES` (268435456) (ebbbb97).
- `GET /v1/audit-events` with both `from` and `to`, where `to` is not after `from`, responds with 422
  `UNPROCESSABLE` with the message "`to` must be after `from`" (same as export); previously it responded
  with an empty list (ebbbb97).
- A URL path with invalid UTF-8 or an encoded lone surrogate (`%FF`, `%ED%A0%80`)
  is rejected before routing with 422 (`loc` `["path"]`, types `invalid_utf8` and `surrogate_in_string`);
  previously it was decoded with U+FFFD and routed. A WebSocket handshake with such a path or query gets
  the same 422 response when the server supports the ASGI extension `websocket.http.response`, otherwise it is closed
  before accepting as before (ebbbb97).
- CLI `sandbox create --mount` with an invalid value (no colon, empty volume id or path,
  a value of only invisible or control characters) is a usage error with exit 2;
  previously it exited with 1 (15d3c1f). The value is checked before the other options and before login.
- The CLI rejects locally (usage error, exit 2, no request) empty or only invisible or
  control values of the options `--scope` (`key create`), `--snapshot` and `--egress` (`sandbox create`),
  `--state` (`sandbox list`), `--cwd` (`exec`), `--session` (`cmd start`), `--name` (`snapshot
  build`) and `--output` (`snapshot export`); a name of only control characters is now empty, like a name
  of only invisible characters (15d3c1f).
- CLI `exec <sandbox> -t 5 ls` (an exec option after the sandbox name) is a usage error with exit 2 and
  a hint, instead of `-t` becoming the command; a program whose name starts with a dash goes after `--`
  (15d3c1f, narrowed in 0a5780b).
- Addition to `repair-labels`: a valid key always keeps its name, and the server writes a warning to the log when the
  label filter skips rows (9624b2e, 0822a62).
- CLI: a profile whose `api_key` field is present but is not a JSON string or is empty gives a usage
  error (exit 2) with the profile name instead of `not logged in` (fccbcad).
- CLI: the REASON column in `sandbox list` shows `stop_cause` when the sandbox has neither `error_code` nor
  `error_reason`; the field display has new rows `labels`, `stop_cause` and `stopped_at` (abcd019,
  fb46163).

- **Documentation: removed claims about unimplemented fs and git operations, recounting of the API,
  corrected statuses and facts about competitors** (82b3c14): documentation only, no code changes;
  changes in `README.md`, `context/icp-personas.md`, `context/metrics-snapshot.md`,
  `context/positioning.md`, `docs/architecture.md`, `docs/egress-allowlist-design.md` and
  `docs/scim-design.md`.
  - `README.md`: the feature list names `reset`, egress allowlist, warm pool, snapshot export, SCIM
    Users and code contexts; fs without permissions, search, find and replace, git without branch and checkout
    (described as nonexistent); `PATCH` and `DELETE` on `/v1/org/members`; the TypeScript SDK as a subset.
  - `docs/architecture.md`: the toolbox routes table has the marks "NOT IMPLEMENTED (design only)" and
    a note on the implementation state; the design documents for egress allowlist and SCIM get a section
    "Implementation status" (2026-11-10).
  - `context/metrics-snapshot.md`: 86 HTTP operations across 67 paths (counted 2026-11-10, HEAD
    14dd64f); `context/positioning.md` and `context/icp-personas.md`: corrected facts about
    competitors and statuses.
  - The header of `context/metrics-snapshot.md` got a sentence about the recount twice in this commit;
    that is corrected in the documentation item of this round.
- **Server: label filters survive a lone surrogate in the database; administrator command for
  repair** (0f977f2): changes in `src/sandfort/admin_cli.py` and
  `src/sandfort/db/repositories/sandboxes.py`, new `tests/test_sandbox_labels_r54.py`.
  - `label_match()` builds the filter condition so that a `CASE` singles out rows whose raw label JSON contains a
    `\u` escape that Postgres cannot convert to text (NUL or a lone surrogate from the time before the guard from
    round 53); for such a row the extraction by key (`->>`) is not evaluated, the row does not match the
    filter, and the query is not interrupted. The same applies to counting in the scope of a key with labels
    (`count_in_scope`). The regular expression is the same for Postgres (`~`) and SQLite (`REGEXP`); a valid pair of
    surrogates (emoji) and an escaped backslash are not matched.
  - `sandfort-admin repair-labels [--org ORG_ID] [--dry-run]` (in code
    `python -m sandfort.admin_cli repair-labels`): replaces lone surrogates and NUL in stored
    labels (keys and values) with U+FFFD, in all states including `destroyed` and standby
    rows. `--org` limits it to one org (an unknown id is an error, exit 1), `--dry-run`
    only reports rows. It prints the id of each changed sandbox, then `repaired labels of N
    sandbox row(s)` (`would repair ...` with `--dry-run`). A key that the repair changes and that collides
    with another key gets an additional U+FFFD; a valid key that the repair does not change always keeps
    its name, regardless of order (fix in 9624b2e; the original sentence "a key that collides after the
    repair gets an additional U+FFFD" held only partially). Only `labels` and `version` are changed; audit rows are neither read nor written, so the
    audit chain stays identical, and the repair is not recorded in the audit.
  - Changed files: `src/sandfort/admin_cli.py`, `src/sandfort/db/repositories/sandboxes.py`,
    `tests/test_sandbox_labels_r54.py` (new).
- **Feature: `stop_cause`, the reason a sandbox stopped** (four commits: 0aef00c,
  8bd0ad9, abcd019, 9e69291). Values: `requested`, `auto_stop`, `container_exited`, `oom_killed`
  (reserved, no path sets it) and `unknown` (never stored; the API shows it instead of
  `null` for a `stopping` or `stopped` row without a cause).
  - **Server: `stop_cause` is recorded on every stop path; migration 0020** (0aef00c):
    changes in `src/sandfort/domain/sandbox.py`, `db/models/sandboxes.py`,
    `db/repositories/sandboxes.py`, `services/sandboxes.py`, `services/sandbox_jobs.py`,
    `workers/autostop.py` and `workers/reconciler.py`, new migration
    `src/sandfort/migrations/versions/r0020_sandbox_stop_cause.py`, new
    `tests/test_stop_cause_r54.py`.
    - Three paths set the cause in the same write that triggers the stop: `SandboxService.stop`
      (`requested`), `AutoStopScanner` (`auto_stop`) and the reconciler when it finds an exited container
      (`container_exited`; the same applies when exec sees that the container died, because both paths go through
      `mark_stopped_unexpectedly`). Reset, lost node, operator and quota do not set a cause.
    - A successful start clears the cause (`Lifecycle`, `stop_cause=None`). A second stop request does not
      overwrite it: stop on a `stopped` sandbox is a no-op, on a `stopping` one it is 409 `INVALID_STATE`, and
      reset of a stopped sandbox keeps the cause.
    - `visible_stop_cause()` and `visible_stopped_at()` determine what the API shows: the cause only in the states `stopping` and
      `stopped` (`unknown` when the row is `NULL`), `stopped_at` only in `stopped`.
    - Migration `0020` adds the nullable `Text` column `stop_cause`, without backfill; the downgrade
      removes it.
    - Audit: `sandbox.stop` has `details.stop_cause` `requested`, `sandbox.auto_stopped` has
      `auto_stop` next to `auto_stop_minutes` and `idle_seconds`, `sandbox.drift_detected` with
      `stopped_unexpectedly` has `container_exited`.
    - Changed files: those listed above, plus `tests/test_stop_cause_r54.py` (new).
  - **API and SDK model: `stop_cause` and `stopped_at` in the sandbox response, webhooks and model;
    regenerated spec** (8bd0ad9): changes in `src/sandfort/api/schemas/sandboxes.py`,
    `src/sandfort/services/events.py`, `openapi/sandfort.v1.json` and
    `sdk/python/src/sandfort_sdk/models.py`, new `tests/test_api_stop_cause_r54.py`, addition in
    `tests/test_cli_error_code_r34.py`.
    - `SandboxResponse` has `stop_cause` (string or `null`) and `stopped_at` (date and time with
      zone or `null`); the field descriptions in the spec state the rules.
    - `EventingSandboxRepository` puts `stop_cause` in the payload of every sandbox event next to
      `reason` and `error_code`.
    - `SandboxInfo.stopped_at` (`datetime | None`) and `SandboxInfo.stop_cause` (`str | None`) are
      added at the end of the model, so the order of earlier fields stays the same; both are `None` against a server
      that does not send them.
  - **CLI: `stop_cause` and `stopped_at` in the field display; REASON fallback in the list** (abcd019): changes in
    `cli/src/sandfort_cli/output.py`, new `tests/test_cli_stop_cause_r54.py`.
    - `sandbox_fields()` adds the rows `stop_cause` and `stopped_at` (ISO 8601) after `error_code`,
      only when the server sends a value; the `--json` object has both fields.
    - `error_cell()`: without `error_code` and without `error_reason` the REASON column shows
      `stop_cause` (empty if it is absent too).
  - **SDK: typed stop causes and handle properties** (9e69291): changes in
    `sdk/python/src/sandfort_sdk/__init__.py`, `handles.py` and `sdk/python/README.md`, new
    `sdk/python/src/sandfort_sdk/stop_causes.py` and `tests/test_sdk_stop_cause_r54.py`.
    - The constants `SANDBOX_STOP_CAUSE_REQUESTED`, `SANDBOX_STOP_CAUSE_AUTO_STOP`,
      `SANDBOX_STOP_CAUSE_CONTAINER_EXITED`, `SANDBOX_STOP_CAUSE_OOM_KILLED` and
      `SANDBOX_STOP_CAUSE_UNKNOWN`, the type `StopCause` (a `Literal` of five values) and the guard
      `is_known_stop_cause(value)` are exported from `sandfort_sdk`. The attribute stays `str | None`, so that a
      cause added by a newer server does not break an older SDK. The names are not `STOP_*` so as not to collide with
      `STOP_REASON_*`.
    - The sandbox handle has the read-only properties `stop_cause` and `stopped_at`.
- **Server: empty or invisible member display names are 422; finite-number message for `since`
  in logs** (479bfc7): changes in `src/sandfort/api/routes/sandbox_logs.py` and
  `src/sandfort/api/schemas/users.py`, new `tests/test_api_limits_r54.py`.
  - `check_display_name()` on `CreateMemberRequest.display_name`: an empty name (after trimming
    spaces) is 422 with the message "must not be blank"; a control character and a name made only of spaces and
    invisible format characters (category Cf) is 422 with the message "must contain a visible
    character, not only whitespace and invisible format characters". Visible script of any
    alphabet remains allowed.
  - `since` in `GET /v1/sandboxes/{id}/logs`: `_reject_non_finite()` rejects `nan` and infinity before the
    limits, with the type `finite_number` and the message "Input should be a finite number of seconds".
    The limits (`minimum`, `exclusiveMaximum`) remain in the published schema.
  - Changed files: `src/sandfort/api/routes/sandbox_logs.py`,
    `src/sandfort/api/schemas/users.py`, `tests/test_api_limits_r54.py` (new).
- **CLI: sanitizer stage order: true key tail length, query and fragment masks before
  sequence removal, context in the comparison display, idempotence** (13e3e9a): changes in
  `cli/src/sandfort_cli/sanitise.py`, addition in `tests/test_cli_r48.py`, new
  `tests/test_cli_r54b.py`. Found by two security testers.
  - A key of true length (60 characters) with one hidden character at any position is masked entirely,
    both the own key and a token shaped like a key; the tolerant passes run before the plain shape pass
    and over the display that will be seen, and the key mask is repeated between sequence removal and
    flattening. A lone surrogate counts as a hidden character.
  - The query and fragment masks run before terminal sequence removal: a sequence that eats the `?`,
    the colon of `://` or the `#` does not leave a value unmasked. A sequence whose body has `@` and `#` or
    `?` in a password with a space cannot turn its body into text that reveals the rest of the password
    (`_display_sequences()`, `_apply_edits()`).
  - The URL context for the query and fragment is checked on the comparison display (a joiner or
    combining character before `?` does not hide it), and hosts with non-ASCII characters (`bücher.example`,
    `пример.рф`, `例子.测试:8080`) count as hosts (`URLISH_HOST_RE` uses `\w`).
  - A whitespace inside a query or fragment value that is not a plain space (tab, line break, `\x0b`,
    `\x0c`, `\x85`, ` `, ` `, `　`) does not end the value (`WORD_ACROSS_BREAKS_RE`);
    only a plain space ends it.
  - A fragment after a host without a scheme (`host.test#x`, `host.test:8080#x`, `localhost#x`, `[::1]:8080#x`,
    the path `/v1/x#x`) is masked like a query; `issue #123` and `C#` remain. The old `FRAGMENT_RE` was
    removed.
  - `flatten_text()` first removes control characters that are not whitespace, so flattening twice gives
    the same as once; every stage is idempotent (property check on a random corpus), and after the
    whole flow no ESC, C1 control or lone surrogate remains.
  - Changed files: `cli/src/sandfort_cli/sanitise.py`, `tests/test_cli_r48.py`,
    `tests/test_cli_r54b.py` (new).
- **CLI: label key collision suffix on the changed key, cell cutting at the grapheme boundary and
  the `labels` row in the field display** (fb46163): changes in `cli/src/sandfort_cli/output.py`, new
  `tests/test_cli_r54c.py`.
  - `clean_key_names()`: when sanitizing makes two keys of one object equal, the key that
    stayed unchanged keeps its exact name (even if it looks like `a#2`), and the key that sanitizing
    changed gets the cleaned name if it is free, otherwise the suffix `#<n>` with the lowest free number
    from 2. A key with a hidden character cannot take the name of a real key, regardless of the order
    in which the server sent them.
  - `truncate_cell()` cuts at a grapheme cluster boundary (UAX #29, `cut_at_cluster()`): never half
    of an emoji sequence, a base letter without its combining characters, a lone regional indicator or a
    conjunct cut at the virama. A cell can be a few characters shorter than 32.
  - The field display has a `labels` row: each label as `key=value` in its own row, `-` when there are none,
    sanitized as a cell but without cutting (`labels_lines()`, `print_fields(..., folded=...)`); in a
    narrow terminal the row wraps.
  - Changed files: `cli/src/sandfort_cli/output.py`, `tests/test_cli_r54c.py` (new).
- **CLI: a wrongly typed key in the profile is a usage error with the profile name** (fccbcad):
  changes in `cli/src/sandfort_cli/config.py`, new `tests/test_cli_r54d.py`.
  - `stored_api_key()`: an `api_key` field that is present and is not a JSON string (number, `null`, list,
    object, boolean) or is an empty string gives `BadParameter` (exit 2) with
    `api_key in <profile path>` and a fixed message (`is not a string ...`, `is empty ...`), and the
    value is not printed. An absent field is still `not logged in`. The variable
    `SANDFORT_API_KEY` takes precedence, so a damaged key in the profile applies only without it.
  - Changed files: `cli/src/sandfort_cli/config.py`, `tests/test_cli_r54d.py` (new).
- **Server: label guard warning and a repair edge case** (9624b2e): changes in
  `src/sandfort/admin_cli.py` and `src/sandfort/db/repositories/sandboxes.py`, additions in
  `tests/test_sandbox_labels_r54.py` and a stale statement in `tests/test_api_strings_r53.py`.
  - `repaired_labels()`: a valid key (without NUL and lone surrogate) keeps its name wherever it
    stands in the map; only a key the repair changed gets an additional U+FFFD while it collides with an already
    written or valid key. The earlier code checked that only against already written
    keys, so a valid key could lose its name because of ordering.
  - `unreadable_labels()` extracts the guard predicate; `list` (`_page`) and `count_in_scope` with a filter by
    labels write the warning `label filter skipped N row(s) of org ORG with unreadable labels;
    run sandfort-admin repair-labels --org ORG` when the guard omits rows.
- **Server: the label guard diagnostic is rate limited** (0822a62): change in
  `src/sandfort/db/repositories/sandboxes.py`, extended `tests/test_sandbox_labels_r54.py`.
  - The counting of omitted rows (`COUNT` with the guard regular expression over the label text of the
    org) from 9624b2e ran on every query with a filter. It now runs at most once per
    org per `UNREADABLE_CHECK_INTERVAL_S` (600 s) per process; the time is written before the query,
    so a slow or failed query does not repeat on the next request. The map `_unreadable_checked_at` holds
    one number for each org that has ever run a query with a filter. The clock is a module attribute
    (`_monotonic`) so tests can move it. Because of this the warning is no longer conditioned on the
    logging level.
- **CLI: a name of only control characters is empty, empty option values are rejected locally,
  an invalid `--mount` is a usage error, a hint for an exec option in the wrong place and for
  ASCII digits** (15d3c1f): changes in `cli/src/sandfort_cli/output.py`, `sandboxes.py`, `exec_cmd.py`,
  `cmd_cmd.py`, `keys.py` and `snapshot.py`, new `tests/test_cli_r54n.py`.
  - `is_blank_char()` and `is_blank()`: a character is blank if it is whitespace, invisible or control (C0, DEL,
    C1, including the single-byte CSI). `reject_empty_name()` uses `is_blank()`, so "must not be
    empty" also applies to a name of only control characters. `reject_empty_option()` and
    `reject_empty_options()` apply the same to an option value and to each value of a repeatable
    option; `None` (option not given) passes.
  - Applied to: `--scope` (`key create`), `--snapshot` and `--egress` (`sandbox create`),
    `--state` (`sandbox list`), `--cwd` (`exec`), `--session` (`cmd start`), `--name` (`snapshot
    build`) and `--output` (`snapshot export`; `-o` is now text with `metavar` `PATH` because typer turns an empty
    string into `.`). The key of a `KEY=VALUE` pair (`--env`, `--label`) made only of invisible or
    control characters is a usage error; an empty pair value remains allowed.
  - `parse_mount()`: an empty value is "must not be empty", and a value without a colon or with an empty
    id or path is `BadParameter` `invalid mount ...; expected VOLUME_ID:PATH` with
    `param_hint` `--mount`, exit 2. Previously this was a `CliError` with exit 1. The call is moved
    ahead of the other `sandbox create` checks and outside `cli_errors()`.
  - `reject_misplaced_option()` in `exec`: if the first word of the command looks like an exec option of its own, a
    usage error (exit 2) says `... came after the sandbox name; exec options go before it: sandfort
    exec OPCIJA ... <sandbox> -- <command> (to run a command that starts with a dash, put it
    after --)`. A word after `--` is the command and is not checked.
  - `whole_number_hints()`: with a whole-number error, besides "surrounding whitespace is not allowed",
    the hint `only plain ASCII digits are accepted` when the value contains an invisible or control
    character (except whitespace), a non-ASCII digit or a plus sign.
- **CLI: the key is masked before the credential masks in the pass before sequence removal; sanitizer
  stages module; decision on the unterminated string introducer** (31489a6): changes in
  `cli/src/sandfort_cli/sanitise.py`, new `cli/src/sandfort_cli/sanitise_stages.py`, a stale statement
  in `tests/test_cli_r50b.py`, new `tests/test_cli_r54o.py`.
  - The pass before terminal sequence removal now runs `mask_credentials(mask_key(raw, ...))`,
    previously `mask_key(mask_credentials(raw), ...)`. Reason: a `?` or `#` that a malicious sequence
    inserted into the caller's key made the query or fragment mask swallow the word from that mark, so
    the key mask never saw the whole key.
  - The mask helper functions (text displays, edit machinery, query and fragment stages) moved to
    `sanitise_stages.py` (458 lines; `sanitise.py` goes from 1052 to 705 lines) and
    `sanitise.py` re-exports them through `__all__`, so import paths stay the same.
  - The decision on the unterminated string introducer (APC, OSC, DCS, PM, SOS) is recorded in the module
    documentation: such a sequence in text swallows the rest of the text in the display. These are the rules of the terminal itself
    and a safe choice; what follows the introducer is never displayed. So `bad sf_test<ESC>_key_do_not_print
    now` gives `bad ***`; the test in `tests/test_cli_r50b.py` is adjusted, with a check that the key stays
    fully masked.
  - A tradeoff also recorded and accepted: the fragment mask looks only for a URL-like context, not a scheme, so
    even ordinary words with a dot or path and `#` (`v1.2.3#build`, `README.md#install`) are masked as
    `#***`.
- **CLI: exact match of the exec option, stale claims about `--mount`, wrapping of the SDK README**
  (0a5780b): changes in `cli/src/sandfort_cli/exec_cmd.py`, `sdk/python/README.md`,
  `tests/test_cli_phase3.py`, `tests/test_cli_r50.py` and `tests/test_cli_r54n.py`.
  - `matched_option()`: a word counts as an exec option only if it is the exact option name, a long name
    with `=VALUE` or a short name followed only by ASCII digits (`-t5`). Any other word with a dash
    (`-tool`, `-input`) is a program name; in 15d3c1f the match was wider (any word that starts with a
    short name).
  - Stale statements about `--mount` in tests aligned with exit 2; in `sdk/python/README.md` only the
    paragraph about handle properties was rewrapped (same content).
- **Server: guard in the path position, no boolean values on the other numeric fields, strict
  `size_bytes`, order of the period in the audit list** (ebbbb97): changes in
  `src/sandfort/api/text_guard.py`, `routes/audit.py`, `routes/toolbox/fs.py`,
  `schemas/common.py`, `api_keys.py`, `toolbox_fs.py`, `toolbox_git.py`, `toolbox_process.py` and
  `toolbox_pty.py`, new `tests/test_api_strings_r54.py`.
  - `text_guard.py`: when the server passes `raw_path`, the raw path bytes are decoded as strict
    UTF-8 before routing (`_raw_path_problem()`); invalid UTF-8 gives `invalid_utf8`, an encoded
    lone surrogate `surrogate_in_string`, both 422 with `loc` `["path"]`. Previously the path arrived
    decoded with U+FFFD. The query is not counted in `raw_path`. A WebSocket handshake that the guard rejects
    gets the same 422 response if the scope has the extension `websocket.http.response`, otherwise it is closed
    before accepting with code 1008.
  - `NoBool[...]` (`schemas/common.py`, `reject_bool()`) is added to `max_sandboxes` (key creation),
    `size_bytes` and `max_bytes` (fs), `depth` (git clone), `timeout_s` (`ExecuteRequest` and
    `CodeRunRequest`) and `rows` and `cols` (PTY create and resize); error type `number_not_bool`, message
    "Input should be a number, not a boolean". `ge` and `le` remain `minimum` and `maximum` in the schema.
  - `size_bytes` in the upload query (`SizeBytesQuery`): the `BeforeValidator` `_strict_digits()` rejects everything
    except plain decimal digits (type `int_parsing`, message "Input should be a non-negative
    integer written as plain digits"), limit `0` to `MAX_UPLOAD_BYTES`. The declared size goes into the
    tar header.
  - `_check_period()` is shared by `GET /v1/audit-events` and export: both `from` and `to` with a `to` that is not after
    `from` give 422 `UNPROCESSABLE` ("`to` must be after `from`"); the list previously returned an empty
    page.
  - The commit does not change `openapi/sandfort.v1.json`: the published spec does not yet contain the new rules in
    the description of the `size_bytes` parameter and in the description of the audit route (the text "plain decimal digits" was checked, it is not
    in the spec). Regeneration of the spec was deferred to a later round.
- **Documentation: contract of round 54** (a037e1f): only
  `CHANGELOG.md`, `marketing/pilot/beta-connect-guide.md`, `docs/operations.md`,
  `docs/architecture.md` and `context/metrics-snapshot.md`, no code changes.
  - `docs/operations.md`: the section "Sandbox `stop_cause` values" after the `error_code` table (value,
    meaning, who sets it, what the script does; `null` except in `stopping` and `stopped`, `unknown`
    before migration 0020, cleared on start, reset, lost node, operator and quota do not set a
    cause; audit rows and the webhook `sandbox.stopped` carry it), a `stop_cause` row in the table "Sandbox
    stopped or died" and a paragraph about migration `0020`.
  - `docs/architecture.md`: the `sandboxes` row in the data model table gets `error_code` and
    `stop_cause`.
  - Guide: the section "Why a sandbox stopped" (fields `stop_cause` and `stopped_at`, a table of values,
    SDK constants, handle properties), field display rows and the REASON fallback, a table in the list; the sanitizer
    stages from round 54, the key collision suffix, grapheme cutting, a wrong key in the
    profile; 422 for empty or invisible member display names, the `finite_number` message for
    `since`, label filters and `repair-labels` with the options `--org` and `--dry-run`; a NUL in the URL path
    is rejected by the edge proxy with a plain 400 before the application (422 JSON applies to the query and body), and
    invalid UTF-8 in the path is decoded with U+FFFD instead of being rejected; a sentence in the CI section
    that points to the note on labels; the contract of the typed `state` on `NoContainer` and `NotFound`
    in the code contexts section (the earlier text that `NotFound` has no `state` was stale since
    7935b4c).
  - `context/metrics-snapshot.md`: the recount sentence in the header stated once.
  - `CHANGELOG.md`: this round and the real hash (14dd64f) of the previous documentation item.
- **Documentation: addition to the log and guide of round 54** (318e3f2): only `CHANGELOG.md` and `marketing/pilot/beta-connect-guide.md`, no code changes.
  - `CHANGELOG.md`: items for 15d3c1f, 9624b2e, 31489a6, 0a5780b, 0822a62 and ebbbb97, new items in
    "Changes that scripts can see", a corrected sentence about key collision in `repair-labels`,
    corrected numbers in the round header and the real hash (a037e1f) of the previous documentation item.
  - Guide: exit 2 for an invalid `--mount`, the rule on empty option values, the dash `--` before the
    program name and the hint for an exec option after the sandbox name, the path guard (422 for
    invalid UTF-8 or an encoded surrogate), `number_not_bool` on all numeric fields, strict
    `size_bytes`, 422 for the audit list period, the label guard warning and the `repair-labels` correction.

#### Round 53 (after tag `v0.1.0-beta.52`)
All items were committed to main after commit `00a21c8` (round 52), in commit order:
six server fixes, five CLI fixes (one with the SDK), two test commits and documentation.
Each was derived from the diff of the named commit. The spec `openapi/sandfort.v1.json` was regenerated
only in a2a862b; the other server commits do not change it.

Changes that scripts can see (status and exit code):
- `sandfort cp` with the wrong shape of endpoints (neither or both arguments in the form
  `<sandbox>:<path>`) exits with 2 instead of 125 (779bd2d). An empty local or remote path
  also exits with 2; other `cp` errors keep 125.
- `GET /v1/org/usage` with `to` that is not after `from` responds 422 with code `UNPROCESSABLE` instead of
  400 `VALIDATION_ERROR` (e5b6c93).
- The error line text for a sandbox name that matches no sandbox starts with `NOT_FOUND:`
  (779bd2d); `--json` is unchanged.
- A request with NUL or a lone surrogate in the path, query or JSON body responds 422 instead of 500
  or silently stored text (fcc7727).
- `POST /v1/api-keys` with `sandbox_labels` whose key consists only of invisible characters or contains a
  control character responds 422 `VALIDATION_ERROR`, the same as a sandbox label key (61e9804).

- **Server: upper bound on git clone depth and check of the declared upload size**
  (a2a862b): changes in `src/sandfort/api/routes/toolbox/fs.py`,
  `src/sandfort/api/schemas/toolbox_git.py` and `openapi/sandfort.v1.json`, new
  `tests/test_api_limits_r53.py`.
  - `depth` in the git clone body has an upper bound `MAX_CLONE_DEPTH` = 1000000 (the lower bound 1 is
    unchanged); a larger value is 422 `VALIDATION_ERROR`. The field description in the spec states the range.
  - `PUT .../toolbox/fs/upload`: a `size_bytes` that differs from the `Content-Length` header
    is rejected before the body is read with 422 `UNPROCESSABLE` (`details` has `declared_bytes` and
    `received_bytes`), so nothing is written. The description of the `size_bytes` parameter in the spec states
    the rule.
  - Changed files: `src/sandfort/api/routes/toolbox/fs.py`,
    `src/sandfort/api/schemas/toolbox_git.py`, `openapi/sandfort.v1.json`,
    `tests/test_api_limits_r53.py` (new).
- **CLI: shared sanitizer on the volume, snapshot, key, members, preview and cmd displays**
  (caf1ccf): changes in `cli/src/sandfort_cli/volume.py`, `snapshot.py`, `keys.py`, `members.py` and
  `cmd_cmd.py`, new `tests/test_cli_r53e.py`.
  - Tables, field displays and `--json` objects for snapshot, volume, key and members, the lines of `cmd start`
    and `cmd kill`, and the `preview` output go through the same sanitizer as the sandbox displays
    (`shown()`, `clean_strings()`, `caller_key()`). Previously these displays were not covered.
  - Exceptions: the one-time secret of `key create` (the `key` field in `--json` and the line in text) stays
    byte-for-byte as the server returned it; the preview token (`preview`) is not changed: `token` in `--json`
    is exactly the value from the server, and the URL is sanitized with the token put back in place
    (`preview_url()`).
  - The snapshot build log lines went through the sanitizer in this commit; 3bdf371 moves them
    to the program output policy.
  - Changed files: `cli/src/sandfort_cli/cmd_cmd.py`, `keys.py`, `members.py`, `snapshot.py`,
    `volume.py`, `tests/test_cli_r53e.py` (new).
- **Server: boolean values on numeric fields are 422; the order of the usage period responds as
  export** (e5b6c93): changes in `src/sandfort/api/routes/usage.py`, `schemas/orgs.py` and
  `schemas/sandboxes.py`, new `tests/test_api_limits_r53q.py`.
  - JSON `true` and `false` on numeric fields of the quota body (`max_vcpus`, `max_memory_mib`,
    `max_disk_gib`, `max_sandboxes`) and of the sandbox body (`cpu_millicores`, `memory_mib`, `disk_gib`,
    `auto_stop_minutes`, `auto_delete_minutes` on create, update and resize) are rejected
    with 422 and error type `number_not_bool`; previously lax conversion read them as 1 and 0.
    The helper type `NoBool` wraps the whole type, so `minimum` and `maximum` stay in the published schema.
  - `GET /v1/org/usage` with `to` that is not after `from` responds 422 `UNPROCESSABLE` with the message
    "`to` must be after `from`", like `audit-events/export`; previously 400 `VALIDATION_ERROR` with the
    message "the period end must be after its start".
  - Changed files: `src/sandfort/api/routes/usage.py`, `src/sandfort/api/schemas/orgs.py`,
    `src/sandfort/api/schemas/sandboxes.py`, `tests/test_api_limits_r53q.py` (new).
- **CLI: decoding of the login prompt, key length limit, names made of invisible characters,
  message for whitespace in integers and the full list of allowed values** (a834cda): changes in
  `cli/src/sandfort_cli/config.py`, `output.py` and `sandboxes.py`, new `tests/test_cli_r53c.py`.
  - A key longer than `MAX_API_KEY_CHARS` = 512 characters (without surrounding whitespace) is a usage error,
    exit 2: `is too long (an api key is at most 512 characters)`; it applies to `login` and to every
    configured key (`check_configured_key()`).
  - The hidden prompt `Api key` whose input is not valid UTF-8 gives the same usage error as a
    malformed key (`is malformed ...`), exit 2, without a traceback.
  - `reject_empty_name()` treats a name made up only of whitespace and invisible characters (zero-width
    space, joiners, bidi marks and other default-ignorable code points) as empty.
  - An integer error with surrounding whitespace ends with `; surrounding whitespace is not
    allowed`, because the printed value flattens the whitespace and would look like an ordinary number.
  - The validation message in the text line has a limit `MAX_VALIDATION_MESSAGE_CHARS` = 600
    instead of 120 per pair, and the server validation message is cut at 600 instead of 300, so a list of
    twelve allowed scopes (about 200 characters) is printed in full. `--json` is cut as before.
  - Changed files: `cli/src/sandfort_cli/config.py`, `cli/src/sandfort_cli/output.py`,
    `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli_r53c.py` (new).
- **CLI: `cp` with empty and invalid paths, clean errors for recursive download, prefix
  for a missed name and port range in the `preview` help** (779bd2d): changes in
  `cli/src/sandfort_cli/cp_cmd.py`, `cp_dir.py`, `refs.py` and `cmd_cmd.py`, new
  `tests/test_cli_r53p.py`.
  - `check_arguments()`: the wrong shape of endpoints is a `UsageError` with exit 2 (previously
    `CliError` with exit 125); an empty local path is a usage error (`must not be empty`,
    names `<source>` or `<destination>`). Everything is checked before any request.
  - Recursive download: an empty remote path (`EMPTY_REMOTE_MESSAGE`) and a destination that is a
    file (or whose nearest existing parent is a file, `destination <path> is not a directory`)
    are rejected before the request (`check_download_source()`, `dir_destination_problem()`); a file that appears in the meantime gives the same clean error from
    `make_destination()`, not the operating system text. `existing_ancestor()` was moved from
    `cp_cmd.py` to `cp_dir.py`.
  - A sandbox name that matches no sandbox: the text line starts with `NOT_FOUND:`
    as for a missed id (`name_miss_message()`); under `--json` the message has no prefix and everything else
    is the same.
  - The `preview` help states the port range 1024 to 65535.
  - Changed files: `cli/src/sandfort_cli/cp_cmd.py`, `cli/src/sandfort_cli/cp_dir.py`,
    `cli/src/sandfort_cli/refs.py`, `cli/src/sandfort_cli/cmd_cmd.py`, `tests/test_cli_r53p.py`
    (new).
- **Server: lone surrogates and NUL never give 500; tolerant JSON output and one input guard**
  (fcc7727): changes in `src/sandfort/api/app.py`, `errors.py`, `routes/sandboxes.py`,
  `routes/scim.py`, `routes/toolbox/fs.py`, `routes/usage.py`, `wiring.py` and
  `proxy/terminal.py`, new `src/sandfort/api/safe_json.py`, `src/sandfort/api/text_guard.py` and
  `tests/test_api_strings_r53.py`.
  - `TextGuardMiddleware` (`text_guard.py`) rejects, before any route, a request whose path, name or
    query parameter value (strict UTF-8 after percent-decoding) or any string in the
    JSON body (object keys included, at any depth) contains NUL or a lone UTF-16
    surrogate. The response is 422 `VALIDATION_ERROR` with `details.errors` (`type`, `loc`, `msg`; types
    `nul_in_string`, `surrogate_in_string`, `invalid_utf8`); the text is not repeated in the response.
    The body is inspected when `Content-Type` is missing or is JSON; the upload body is not read.
    The `stdin` field of the `process/execute` route may carry NUL (a lone surrogate is rejected there too).
    The guard runs before authentication and before the route, so the rejection is not recorded in the audit.
  - `SafeJSONResponse` (`safe_json.py`) is the default response class of the application; a lone
    surrogate in stored text is returned as U+FFFD instead of 500. The stored value is not changed.
    Routes that built `JSONResponse` by hand (`sandboxes`, `scim`, `toolbox/fs`, `usage`,
    `errors`, `wiring`, `proxy/terminal`) use the new class.
  - Other changes in `app.py`, `errors.py` and `wiring.py` are reformatting only.
  - Changed files: `src/sandfort/api/app.py`, `errors.py`, `routes/sandboxes.py`,
    `routes/scim.py`, `routes/toolbox/fs.py`, `routes/usage.py`, `wiring.py`,
    `proxy/terminal.py`, `safe_json.py` (new), `text_guard.py` (new),
    `tests/test_api_strings_r53.py` (new).
- **CLI: empty remote `cp` path, preview token by parameter name, faithful build log line and
  outdated assertions from rounds 37 to 53** (3bdf371): changes in `cli/src/sandfort_cli/cmd_cmd.py`,
  `cp_cmd.py` and `snapshot.py`, new `tests/test_cli_r53v.py`.
  - `cp`: an empty (whitespace-only) remote path is a usage error, exit 2, before the request.
  - `preview`: the token is looked up in the URL by the parameter name `sandfort_preview_token` (`TOKEN_PARAM`),
    not by comparing values. An ordinary token is put back in place in the URL; other query values stay
    masked. When the URL cannot carry the token, text mode prints `token: <token>` after the
    URL. A token with control characters is not printed in text (a note on stderr points to
    `--json`); `--json` has the exact value.
  - Snapshot build log lines are program output: only dangerous terminal sequences are removed
    (`strip_dangerous_terminal()`, the same as in the `exec` relay), nothing is masked, flattened
    or cut, so indentation stays.
  - Outdated assertions in `tests/test_cli.py`, `test_cli_r37.py`, `test_cli_r50d.py`,
    `test_cli_r50f.py`, `test_cli_r51h.py`, `test_cli_r53p.py`, `test_cli_rm_create.py` and
    `test_usage.py` were updated to the behavior of rounds 37 to 53.
  - Changed files: `cli/src/sandfort_cli/cmd_cmd.py`, `cli/src/sandfort_cli/cp_cmd.py`,
    `cli/src/sandfort_cli/snapshot.py`, `tests/test_cli.py`, `tests/test_cli_r37.py`,
    `tests/test_cli_r50d.py`, `tests/test_cli_r50f.py`, `tests/test_cli_r51h.py`,
    `tests/test_cli_r53p.py`, `tests/test_cli_rm_create.py`, `tests/test_usage.py`,
    `tests/test_cli_r53v.py` (new).
- **Server: bounded body traversal with a depth limit, parsing off the event loop, SSE resistant
  to surrogates and a guard for websocket** (ffdffa4): changes in `src/sandfort/api/text_guard.py` and
  `src/sandfort/api/sse.py`, additions in `tests/test_api_strings_r53.py`.
  - The JSON body traversal uses a stack of iterators and a single mutable path, so memory follows
    depth and not the number of elements; it stops after `MAX_FINDINGS` = 10 findings. A body nested deeper than
    `MAX_DEPTH` = 64 levels is 422 with type `nesting_too_deep` and `loc` `["body"]` (a body nested
    exactly 64 levels is traversed). The body is parsed only if it contains a `\u` escape or a NUL byte; this
    also applies to the depth check.
  - A body larger than `OFFLOAD_BYTES` = 64 KiB is parsed and traversed in a worker thread, so it does not
    block the event loop.
  - `format_event()` in `sse.py` replaces a lone surrogate with U+FFFD, so the stream does not break after the start of
    the response.
  - A websocket handshake with NUL or a surrogate in the path or query is closed with code 1008.
  - Changed files: `src/sandfort/api/text_guard.py`, `src/sandfort/api/sse.py`,
    `tests/test_api_strings_r53.py`.
- **CLI and SDK: actual characters in text details, name sanitized before insertion and typed
  "context gone" state** (7935b4c): changes in `cli/src/sandfort_cli/output.py`, `refs.py` and
  `sdk/python/src/sandfort_sdk/exceptions.py`, new `tests/test_cli_r53x.py`.
  - `details` that is not a string is printed in the text line as compact JSON with actual
    characters (`ensure_ascii=False`), not as `\uXXXX`; a lone surrogate stays escaped because it cannot
    be written to the terminal.
  - `name_miss_message()` sanitizes the typed name before inserting it into the template: a lone ESC no longer
    swallows the closing quote and part of the template in a later pass.
  - SDK: `NotFound.state` is a typed field (`str | None`, default `None`), and
    `CONTEXT_GONE_ERRORS` is of type `tuple[type[NoContainer | NotFound], ...]`, so
    `except CONTEXT_GONE_ERRORS as exc` can read `exc.state` under strict type checking.
    Behavior does not change.
  - Changed files: `cli/src/sandfort_cli/output.py`, `cli/src/sandfort_cli/refs.py`,
    `sdk/python/src/sandfort_sdk/exceptions.py`, `tests/test_cli_r53x.py` (new).
- **Server: key names and label keys must be visible; reset of the new line of the stream**
  (124309c): changes in `src/sandfort/api/schemas/api_keys.py`, `schemas/sandboxes.py` and
  `routes/toolbox/code_contexts.py`, new `tests/test_api_names_r53.py`.
  - The API key name (`CreateApiKeyRequest`) and every label key on sandbox create and update
    (`check_visible_text()`, `check_label_keys()`) are rejected with 422 `VALIDATION_ERROR` if they
    contain a control character (category Cc, including tab and newline) or if they consist only of
    invisible format characters (category Cf). A joiner between visible characters (emoji sequences) and
    non-ASCII scripts stay allowed. Label values are not checked.
  - `code_contexts.py`: `_end_gone_line()` adds a newline at the end of stderr when it ends with the
    "cell is gone" line, so every line after a delete, reset or stop ends the same way,
    in the result and in the stream.
  - Changed files: `src/sandfort/api/schemas/api_keys.py`,
    `src/sandfort/api/schemas/sandboxes.py`, `src/sandfort/api/routes/toolbox/code_contexts.py`,
    `tests/test_api_names_r53.py` (new).
- **Test: build log lines follow the program output policy** (a8cc0a2): only
  `tests/test_cli_r53e.py`, no code change; the test from caf1ccf adjusted to the behavior from 3bdf371.
- **Server: byte prefilter of the guard, own limiter and check of label keys when creating an
  API key** (61e9804): changes in `src/sandfort/api/text_guard.py` and
  `src/sandfort/api/schemas/api_keys.py`, new tests in `tests/test_api_names_r53.py` and
  `tests/test_api_strings_r53.py`.
  - Before every parse, `needs_parse()` looks at the byte level only for what the guard can
    reject (`SUSPECT_BYTES`): a NUL byte, a `\u` escape for NUL or for a code point from the surrogate range,
    or a UTF-8 encoded surrogate. A body without that is not parsed, however large it is. A body with
    any `\u` escape and more than `MAX_DEPTH` (64) opening brackets (the depth upper bound)
    is still parsed, so the depth rule (422 `nesting_too_deep`) applies to such bodies. Every other
    body, however deep, is parsed by the framework as before.
  - Parsing of bodies above `OFFLOAD_BYTES` (64 KiB) runs on a thread of its own `GUARD_LIMITER`
    (`GUARD_WORKERS` = 4), not from the shared default thread pool used by the routes.
  - A websocket handshake with NUL or a lone surrogate in the path or query is closed before
    accept; a comment in the code states that the close code is only advisory, because the server turns a close
    before accept into a handshake rejection (HTTP 403), so the client does not see 1008.
  - `CreateApiKeyRequest.sandbox_labels` goes through `check_label_keys()`: a label key made only of
    invisible characters or with a control character is 422 `VALIDATION_ERROR`, and nothing is stored.
  - Changed files: `src/sandfort/api/text_guard.py`, `src/sandfort/api/schemas/api_keys.py`,
    `tests/test_api_names_r53.py`, `tests/test_api_strings_r53.py`.
- **Test: the text details expectation shows actual non-ASCII characters** (8aab497):
  only `tests/test_cli_r50f.py`, no code change; `json.dumps(..., ensure_ascii=False)` in the
  compact form comparison, so the test matches the display from 7935b4c.
- **Documentation: round 53 contract** (ef8bb32): only
  `marketing/pilot/beta-connect-guide.md` and `CHANGELOG.md`, no code change.
  - Guide, sanitizer: the snapshot, volume, key and members displays, `preview`, `cmd start` and `cmd kill`
    are covered (the sentence saying they are not was removed); exact exceptions: the one-time secret of `key create`
    and the preview token, and snapshot build log lines under the program output policy.
  - Guide, CLI: a name made of invisible characters is empty; `cp` empty paths and the wrong shape of
    endpoints are usage errors (exit 2), other `cp` errors 125; the `NOT_FOUND:` prefix in the
    text for a missed name; the message about whitespace around an integer; `login` rejects an overlong key
    (512) and prompt input that is not UTF-8; validation messages up to 600 characters; actual characters in
    text details.
  - Guide, server: NUL and a lone surrogate (path, query, keys and values of the JSON body) are 422
    with a location, except NUL in `stdin`; depth limit 64; U+FFFD for stored surrogates in JSON and
    streams; boolean values rejected on numeric fields; visible key names and label
    keys; usage `to` not after `from` is 422 `UNPROCESSABLE`; upper bound of clone `depth`;
    a mismatch of `size_bytes` and `Content-Length` is 422 `UNPROCESSABLE`.
  - Guide, CI: next to the snippet with the label filter, one sentence pointing to the note about labels
    and saying that a filter with the raw value still matches.
  - `CHANGELOG.md`: this round and the real hash (00a21c8) of the previous documentation item.
- **Documentation: final addition to round 53** (14dd64f): only
  `marketing/pilot/beta-connect-guide.md` and `CHANGELOG.md`, no code change.
  - Guide, request text guard: the body is parsed only when the raw bytes contain a NUL byte or a
    `\u` escape for NUL or a surrogate; the depth rule applies to those bodies; every other body is parsed by the
    framework (a too-deep body on a route that reads a JSON body is 400 `HTTP_400`); own small thread
    limit; rejected websocket handshake (the client sees a rejected handshake, not a close code);
    label keys when creating an API key (422).
  - `CHANGELOG.md`: items for 61e9804 and 8aab497 and the real hash (ef8bb32) of the previous
    documentation item.

#### Round 52 (after tag `v0.1.0-beta.51`)
All items were committed to main after commit `e508830` (round 51), in commit order: two
server fixes, two CLI fixes, documentation and two post-review fixes (one
server, one CLI). Each is derived from the diff of the named
commit. The spec `openapi/sandfort.v1.json` was regenerated in 6e67de0 and de3e27f (7af1f4b does not
change it); the new
`tests/test_api_limits_r52.py` (de3e27f) has the test `test_committed_openapi_spec_matches_a_fresh_render`
which ties the committed spec to a fresh render of the schema.
- **Server: the request `resources` rejects unknown fields; stale claims from round 30** (6e67de0):
  changes in `src/sandfort/api/schemas/sandboxes.py`, `openapi/sandfort.v1.json`,
  `tests/test_cli_r30.py`, `tests/test_cli_r30o.py` and `tests/test_cli_rm_create.py`.
  - `ResourceSpecRequest` (the `resources` body on create) has `extra="forbid"` like every other
    request model: an unknown field is a 422 that names it, not a silently dropped value. The spec gets
    `additionalProperties: false` for that schema.
  - Three older CLI tests were adapted to the behavior introduced by rounds 50 and 51: successful json output
    collapses whitespace (`error_reason` without a trailing space), a value without control sequences
    (`boom red end`, `demo`) and a single json document `{"error": ..., "processed": [...]}` on
    partial failure of `sandbox rm`. There is no CLI code change in this commit.
  - Changed files: `src/sandfort/api/schemas/sandboxes.py`, `openapi/sandfort.v1.json`,
    `tests/test_cli_r30.py`, `tests/test_cli_r30o.py`, `tests/test_cli_rm_create.py`.
- **Server: 422 instead of 500 for `since` in logs, the `max_vcpus` quota and the `from`/`to` edges in audit**
  (de3e27f): changes in `src/sandfort/api/routes/sandbox_logs.py`, `routes/audit.py`,
  `schemas/orgs.py` and `openapi/sandfort.v1.json`, new `tests/test_api_limits_r52.py`.
  - `GET /v1/sandboxes/{id}/logs?since=` has an exclusive upper bound `SINCE_LIMIT_S` =
    253402300800 (10000-01-01T00:00:00Z): `datetime` does not go beyond year 9999, so a larger epoch
    overflowed the conversion and the response was 500. It is now 422 with `loc` `["query", "since"]`
    (`1e300` and `inf` as well); the largest value that converts is accepted.
  - `max_vcpus` in the org quota body (`QuotaLimitsBody`) has an upper bound
    `MAX_QUOTA_VCPUS` = 1000 (`MAX_CPU_MILLICORES // 1000`, a test checks that it matches the
    per-sandbox limit) and `allow_inf_nan=False`: `Infinity`, `-Infinity`, `NaN` and a literal such as
    `1e309` that parses to infinity are 422 instead of 500. The values `0.5` and 1000 are stored and
    read back.
  - `from` and `to` on `GET /v1/audit-events` and `/export` go through an `AfterValidator` (`_utc_bound()`):
    a value with a zone that falls outside the range of years 1 to 9999 when converted to UTC
    (`9999-12-31T23:00:00-23:00`, `0001-01-01T00:00:00+23:00`) is a 422 with `loc` `["query", "from"]`
    or `["query", "to"]` and the message `datetime is out of range once converted to UTC`; previously
    an `OverflowError` produced 500. A value without a zone is still read as UTC; `export` still
    rejects a `to` that is not after `from` (422 `UNPROCESSABLE`). The helper `_utc()` was moved above the
    routes and `_bounded_verifier()` was reformatted without a behavior change.
  - `openapi/sandfort.v1.json` was regenerated: `maximum: 1000.0` for `max_vcpus` and
    `exclusiveMaximum: 253402300800` for `since`.
  - Changed files: `src/sandfort/api/routes/sandbox_logs.py`, `src/sandfort/api/routes/audit.py`,
    `src/sandfort/api/schemas/orgs.py`, `openapi/sandfort.v1.json`,
    `tests/test_api_limits_r52.py` (new).
- **CLI: empty arguments are usage errors everywhere, without a traceback** (ddb3897): changes in
  `cli/src/sandfort_cli/cmd_cmd.py`, `keys.py`, `members.py`, `sandboxes.py` and `snapshot.py`, new
  `tests/test_cli_r52c.py`.
  - An empty or whitespace-only reference, name or id is a usage error (`must not be empty`,
    exit 2) before any request, on commands that did not previously check this: the name of `sandbox
    create`; the reference of `sandbox get`, `stop`, `start`, `reset` and every reference of `sandbox rm`;
    the sandbox of `cmd start` and `preview`; the sandbox, session and command (`reject_empty_ids()`) of `cmd logs`
    and `cmd kill`; the name of `key create` and every id of `key revoke`; the display name of `members add`; the image
    and `--name` of `snapshot register` and the id of `snapshot export`.
  - Repeated metavars became constants (`NAME_METAVAR`, `KEY_ID_METAVAR`,
    `DISPLAY_NAME_METAVAR`, `IMAGE_METAVAR`, `SESSION_METAVAR`, `COMMAND_METAVAR`); the message
    text does not change.
  - Changed files: `cli/src/sandfort_cli/cmd_cmd.py`, `cli/src/sandfort_cli/keys.py`,
    `cli/src/sandfort_cli/members.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `cli/src/sandfort_cli/snapshot.py`, `tests/test_cli_r52c.py` (new).
- **CLI: one validation line, notes for truncated collections and refinements for cp, preview, login and the
  integer parser** (abbc30c): changes in `cli/src/sandfort_cli/cmd_cmd.py`, `cp_cmd.py`,
  `output.py` and `sandboxes.py`, new `tests/test_cli_r52g.py`.
  - The text validation error line writes the list of `location: message` pairs once
    (`api_error_text()`, `validation_head()`): the server message repeats the first pair and ends with
    `(and N more)`, so the CLI keeps only the base of the message (`request validation failed`) and after it
    prints the pairs (at most five, then `and N more`); other `details` keys go in parentheses. A message
    that does not repeat the location of the first pair stays whole. Nothing is changed under `--json`.
  - A truncated collection in text no longer prints the raw pair `<key>_beyond_cap`: the note `and N
    more` goes inside the closed parenthesis of the value (`_entry_text()`), and for a truncated `details` itself after
    the pairs. `relay_mapping()` returns the retained entries separately from the counter (`RelayedEntry`,
    `RelayedMapping`); the json shape with the adjacent field is the same.
  - `preview` checks the port range 1024 to 65535 (`MIN_PREVIEW_PORT`, the range from
    `MintPreviewTokenRequest.port` in the spec); previously the lower bound was 1.
  - `login` rejects an invalid API key before sending and before saving (`check_configured_key()` in
    `reject_bad_login_input()`): usage error, exit 2, the key is not printed.
  - The integer parser (`parse_whole_number()`) accepts only ASCII digits with an optional leading minus
    (`WHOLE_NUMBER_RE`); `+5`, spaces around the number, `1_000` and digits of other scripts are rejected even though
    `int()` accepts them. A number over the digit limit of `int()` also gives the same usage error.
  - `cp`: a download whose parent path is a file reports `destination <path> is not a
    directory` (`existing_ancestor()`), and a remote directory without `-r` reports `<path> is a
    directory; use -r for directories` instead of the SDK response error (`InvalidResponseError` with
    `use download_dir`; other such errors still propagate).
  - Changed files: `cli/src/sandfort_cli/cmd_cmd.py`, `cli/src/sandfort_cli/cp_cmd.py`,
    `cli/src/sandfort_cli/output.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `tests/test_cli_r52g.py` (new).
- **Documentation: round 52 error contract, 422 limits and a note for CI** (3f5b6d4): only `marketing/pilot/beta-connect-guide.md` and `CHANGELOG.md`, no
  code change.
  - Guide, error contract: three inputs that now give 422 instead of 500 (`since` in logs,
    the quota `max_vcpus` including non-finite values, `from`/`to` at the edge of the range) with
    documented limits; the upper bounds of the org quota next to the other limits; the list
    `details.errors` (`type`, `loc`, `msg`) belongs only to the code `VALIDATION_ERROR`, and the list `names`
    remains only for environment variable names and reserved label names; one sentence about
    an integer literal longer than the parser limit (status 400, code `HTTP_400`, message `There was
    an error parsing the body`): derived from reading the code (body handling in FastAPI and
    `src/sandfort/api/errors.py`), not run and has no dedicated test in the repository.
  - Guide, CLI: empty arguments are usage errors on all commands from round 52, one validation line,
    `and N more` in text for truncated collections, `login` rejects an invalid key before
    saving, the `preview` port range 1024 to 65535, only ASCII digits for integers, `cp` messages.
  - Guide, note for CI: json successful output masks query-like values in labels and collapses
    whitespace, so a label written through the CLI does not come back identical through the CLI; the SDK returns the stored value
    unchanged (store the URL without a query or read through the SDK).
  - Guide, wording fix: color sequences in forwarded program output reach the screen only
    when stdout is a terminal (`typer.echo` strips them from redirected output). The second requested
    fix (control characters in usage errors as visible escape sequences) was not written:
    the code strips them (`sanitise_usage_error()`, `echo_value()`), so the guide still says
    that they are stripped.
  - `CHANGELOG.md`: this round and the real hash (e508830) of the previous documentation item.
- **Server: `from` and `to` on the usage report share the bound with the audit routes** (7af1f4b): changes
  in `src/sandfort/api/routes/audit.py` and `routes/usage.py`, additions in `tests/test_api_limits_r52.py`.
  - `GET /v1/org/usage` accepted `from` and `to` without a bound: a value with a zone that falls outside the range of years 1 to 9999
    when converted to UTC was not covered by the check from de3e27f. It is now 422
    with `loc` `["query", "from"]` or `["query", "to"]`, as on the audit routes.
  - `audit.py` exposes the required variants `RequiredFrom` and `RequiredTo` (the same `AfterValidator`
    `_utc_bound`); `usage.py` uses them, so its own helper `_utc()` was removed. A value without a
    zone is still read as UTC, and a `to` that is not after `from` is still 422 (`the period end must
    be after its start`). The spec was not changed.
  - Changed files: `src/sandfort/api/routes/audit.py`, `src/sandfort/api/routes/usage.py`,
    `tests/test_api_limits_r52.py`.
- **CLI: empty sandbox references on `exec`, `snapshot create`, `cp` and `shell`, help text for
  `login` and stale claims from rounds 48 to 51** (d8c308f): changes in
  `cli/src/sandfort_cli/exec_cmd.py`, `snapshot.py`, `cp_cmd.py`, `shell_cmd.py` and `sandboxes.py`,
  new `tests/test_cli_r52i.py`.
  - An empty or whitespace-only sandbox reference is a usage error (`must not be empty`, exit 2)
    before any request and without a traceback, using the same helper `reject_empty_name()` as in ddb3897:
    `exec`; the sandbox argument of `snapshot create` (previously only the name was checked); the remote part of the
    path in `cp` (both sides); `shell`, where the check comes before the interactive terminal check. With
    this, every sandbox reference in the CLI is covered. An empty `cp` reference `:/path` is a
    local path (the rule is as in scp), so the whitespace-only check applies.
  - The help text for `login` also lists the rejection of an invalid API key (a space inside the key, a
    control character or a non-ASCII character) as a usage error.
  - Older claims in `tests/test_cli_r48.py`, `test_cli_r50d.py`, `test_cli_r51d.py` and
    `test_cli_r51h.py` were updated to the behavior of rounds 50 to 52 (ten changed lines in
    four modules; the task counted them as fifteen): the `preview` port range 1024 to 65535 (message text
    and the valid port example), port 8080 instead of 80 in the `--ttl` cases so that
    `--ttl` is what is checked, the truncated list text `and N more` instead of the raw `<key>_beyond_cap` (json
    keeps the adjacent field), and a test key without spaces because `login` now rejects a key with a
    space before any request. The intent of the tests is unchanged.
  - Changed files: `cli/src/sandfort_cli/exec_cmd.py`, `cli/src/sandfort_cli/snapshot.py`,
    `cli/src/sandfort_cli/cp_cmd.py`, `cli/src/sandfort_cli/shell_cmd.py`,
    `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli_r48.py`, `tests/test_cli_r50d.py`,
    `tests/test_cli_r51d.py`, `tests/test_cli_r51h.py`, `tests/test_cli_r52i.py` (new).
- **Documentation: final round 52 fixes** (00a21c8):
  only `marketing/pilot/beta-connect-guide.md` and `CHANGELOG.md`, no code change.
  - Guide: the sentence about empty arguments names exactly which commands are covered (including
    `exec`, `snapshot create`, `cp` and `shell`); the statement about 422 at the date edge also covers the `from`/`to` of
    the usage report; one sentence saying that the `and N more` note at the end of the outer list
    also counts entries cut from the inner lists.
  - `CHANGELOG.md`: fixed the command name (`members add`) and wrote the real hash (3f5b6d4)
    of the previous documentation item.

#### Round 51 (after tag `v0.1.0-beta.50`)
All items were committed to main after commit `a70e5b0` (round 50), in commit order:
four CLI fixes, one server fix, documentation and two post-review fixes (one
server, one CLI). Each is derived from the diff of the named
commit. The spec `openapi/sandfort.v1.json` was regenerated in e1984e3 (ca863a3 did not
change it); the same commit adds a test that ties the committed spec to a fresh render of the schema.
- **CLI: clean errors for an oversized timeout, bad copy targets, empty names and invalid
  keys** (3d77fac): changes in `cli/src/sandfort_cli/config.py`, `cp_cmd.py`, `exec_cmd.py`,
  `output.py`, `snapshot.py` and `volume.py`, new `tests/test_cli_r51.py`.
  - `exec --timeout` has an upper bound of 3600 s (`MAX_TIMEOUT_S`, the default server limit
    `SANDFORT_MAX_EXEC_TIMEOUT_S`): a larger value is the usage error `must be a whole number from 1
    to 3600`, exit 2, before sending. If the socket still cannot accept the value (`OverflowError`),
    the CLI reports `timeout is too large; pass -t/--timeout from 1 to 3600`.
  - `cp` without `-r` checks the local download destination before the first request (`check_download()`):
    a directory that does not exist or is not writable gives a CLI error (`destination directory <path>
    does not exist`, or `is not writable`). A write error after the download has started
    reports `cannot write <target>: <reason>` and deletes the temporary file.
  - An empty or whitespace-only name is a usage error (`must not be empty`, exit 2) before any
    request (`reject_empty_name()`, first applied to `snapshot create` and `volume create`).
  - A configured API key that cannot go into the `Authorization` header (a space inside the key,
    a control or non-ASCII character) is a usage error, exit 2 (`check_configured_key()`). The message
    names only the source (`SANDFORT_API_KEY` or `api_key in <profile path>`); the key is not printed.
  - A response body that is nested too deeply or cannot be parsed is treated as a response without a server
    envelope (`install_body_guards()`): `HTTP_<status>` for an error, otherwise
    `InvalidResponseError`, never a traceback. A `details` that is not an object (a string or a list) is kept
    and printed as `details=<value>` (`details_text()`).
  - Changed files: `cli/src/sandfort_cli/config.py`, `cli/src/sandfort_cli/cp_cmd.py`,
    `cli/src/sandfort_cli/exec_cmd.py`, `cli/src/sandfort_cli/output.py`,
    `cli/src/sandfort_cli/snapshot.py`, `cli/src/sandfort_cli/volume.py`,
    `tests/test_cli_r51.py` (new).
- **CLI: tail checks in the matching view, masking between phases, the class of default-ignorable
  characters and gentler stripping in the display** (fbdf979): changes in
  `cli/src/sandfort_cli/sanitise.py`, new `tests/test_cli_r51b.py`.
  - Query masking (`?k=***`) requires a url context (`mask_queries()`): a scheme or `//`, a path,
    a host with a dot, a host with a port or brackets, or ASCII text (or nothing) before the `?` followed
    by `key=`. A question mark in prose (a word, CJK or Thai text) is left untouched.
  - The matching view uses the Unicode property `Default_Ignorable_Code_Point` (assigned and unassigned
    code points, `DEFAULT_IGNORABLE`) together with the categories Cf, Mn and Me and explicit lists. The view
    also skips spaces and delimiters inside terminal sequences.
  - The display strips only truly invisible format characters. Format characters that draw something
    stay (`DISPLAY_KEPT_FORMAT`): Arabic number and end-of-ayah signs (U+0600 to U+0605, U+06DD, U+0890,
    U+0891, U+08E2), the Syriac abbreviation mark (U+070F), Kaithi number signs and the layout controls
    of Egyptian hieroglyphs. A valid emoji tag sequence (black flag, two to eight tag letters or
    digits, cancel tag; `TAG_FLAG_SEQUENCE_RE`) keeps its tag characters, any other tag character
    is stripped. The filler list also covers the unassigned block of specials (U+FFF0 to
    U+FFFB) and unassigned tag-block ranges.
  - Tail discarding looks for the last token in the matching view, so a character or joiner between
    two slashes does not save the url. Discarding is limited to 256 characters
    (`MAX_TAIL_TOKEN_CHARS`): long text without spaces and with two dots keeps a cleaned beginning.
  - The copy for key masking decodes percent sequences up to four rounds (`%255F` is `%5F` after
    one, `_` after two rounds) and masks on the original range (`decode_mapped()`); a partial
    key at the cut is also recognized when encoded multiple times.
  - A terminal string sequence (OSC, DCS, SOS, PM, APC) that never terminates swallows the rest of the
    text; the text before it is treated as cut off (`strip_terminal()`). The credential, query and fragment
    masks run before whitespace collapsing (`mask_credentials()`).
  - Changed files: `cli/src/sandfort_cli/sanitise.py`, `tests/test_cli_r51b.py` (new).
- **CLI: successful output is sanitized, and `exec` strips dangerous terminal sequences** (3db903b):
  changes in `cli/src/sandfort_cli/exec_cmd.py`, `output.py` and `sandboxes.py`, new
  `tests/test_cli_r51c.py`.
  - Successful output of sandbox commands goes through the sanitizer (`shown()`, `clean_strings()`): the table
    (`sandbox list`), the field display (a single sandbox), the `--json` sandbox object (every string and every
    key; numbers, booleans and `null` keep their type, a level deeper than 32 becomes `…`, keys that
    collide get the suffix `#<n>`), `sandbox isolation` and the id printed by `sandbox rm`. Values
    are cut only at the raw limit of 2000 characters; labels and the failure reason in the table are still cut at 32.
    The snapshot, volume, key and member displays are not covered.
  - `InvalidResponseError` messages quote the bad value with `repr`; every quoted literal is
    turned back into the string it represents, sanitized and rewritten (`clean_repr_literals()`), so a key
    split by an escape byte does not pass as plain text.
  - `exec` forwards the program's stdout and stderr through `strip_dangerous_terminal()`: it strips
    OSC (including the clipboard write), DCS, SOS, PM and APC, in 7-bit and 8-bit form; a sequence without
    an end runs to the next `ESC` or to the end of the text. Everything else, including CSI, stays as the
    program wrote it, and nothing is masked. `shell` was not changed: `write_output` writes the bytes
    of the remote terminal without filtering.
  - Changed files: `cli/src/sandfort_cli/exec_cmd.py`, `cli/src/sandfort_cli/output.py`,
    `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli_r51c.py` (new).
- **CLI: metavar everywhere, rejection of empty ids, a single json document and clean truncated collections**
  (46c30ad): changes in `cli/src/sandfort_cli/cmd_cmd.py`, `cp_cmd.py`, `members.py`, `output.py`,
  `sandboxes.py`, `shell_cmd.py`, `snapshot.py` and `volume.py`, new `tests/test_cli_r51d.py`.
  - Positional arguments of all remaining commands are written in angle brackets (`<source>`,
    `<destination>`, `<snapshot-id>`, `<volume-id>`, `<user-id>`, `<email>`, `<image>`,
    `<spec-file>` and others), and integer options have the metavar `INTEGER`. The `sandbox create` options
    (`--auto-stop`, `--auto-delete`, `--cpu-millicores`, `--memory-mib`, `--disk-gib`),
    `cmd start --timeout` (1 to 3600) and `preview --ttl` (60 to 604800) are accepted as text and
    go through `parse_whole_number()`, so the error has the same message as the others. A negative integer
    as a positional argument of `preview` reaches the check instead of being an unknown option
    (`accepts_negative_numbers`).
  - An empty id is a usage error (`must not be empty`, exit 2) before the request: the snapshot and
    volume id, the email and the user id (`reject_empty_name()`).
  - A truncated collection stays clean (`relay_value()`): a list or map over 50 entries is cut to 50
    with no marker entry inside. The count of discarded entries is the adjacent field `<key>_beyond_cap` next to the truncated
    value in `details`, or `details_beyond_cap` in the error object when `details` itself is truncated; the text
    line says `and N more`. This changes the `{"…": "<n> more"}` marker from round 50.
  - The list of validation errors (`details.errors`) in the text line is written as readable pairs
    `location: message`, at most five, then `and N more` (`validation_summary()`); the location is joined
    with dots. Under `--json` the list is unchanged.
  - A partial failure of `sandbox rm` under `--json` gives a single document `{"error": {...}, "processed":
    [...]}` instead of two (`extras` in `cli_errors()` and `ref_errors()`); the key `processed` exists only
    when something was processed.
  - The fragment mask does not eat the closing parenthesis that typer writes in the message `unexpected extra
    argument (<value>)`.
  - Changed files: `cli/src/sandfort_cli/cmd_cmd.py`, `cli/src/sandfort_cli/cp_cmd.py`,
    `cli/src/sandfort_cli/members.py`, `cli/src/sandfort_cli/output.py`,
    `cli/src/sandfort_cli/sandboxes.py`, `cli/src/sandfort_cli/shell_cmd.py`,
    `cli/src/sandfort_cli/snapshot.py`, `cli/src/sandfort_cli/volume.py`,
    `tests/test_cli_r51d.py` (new).
- **Server: upper bounds of sandbox integer fields give 422 instead of 500** (ca863a3): changes in
  `src/sandfort/api/schemas/sandboxes.py`, new `tests/test_api_limits_r51.py`.
  - A value from 2**31 upward reached the database and the response was 500 `INTERNAL`. It is now 422
    `VALIDATION_ERROR`, and `details.errors` names the field in `loc`.
  - New schema bounds (above the configurable per-sandbox maximums, which the service still enforces):
    `auto_stop_minutes` and `auto_delete_minutes` up to 525600 on create and update (the lower bound -1
    stays); `cpu_millicores` up to 1000000, `memory_mib` up to 16777216 and `disk_gib` up to 1048576 on
    create (`resources`, new class `ResourceSpecRequest`) and resize.
  - The OpenAPI spec was not regenerated in this commit; it was regenerated in the next server fix
    (e1984e3, see below), which also ties it to a fresh render with a test.
  - Changed files: `src/sandfort/api/schemas/sandboxes.py`, `tests/test_api_limits_r51.py`
    (new).
- **Documentation: round 51 sanitizer, error contract and integer field limits**
  (a24649e): only `marketing/pilot/beta-connect-guide.md` and
  `CHANGELOG.md`, no code change.
  - Guide: the sanitizer section describes sanitized successful output of sandbox commands, a display
    that keeps visible format characters and valid emoji tag sequences, a matching view by the property
    `Default_Ignorable_Code_Point`, query masking only with a url context and the forwarding rule for
    `exec` (dangerous sequences stripped, program content unmasked) and `shell` (no filtering).
  - Guide: the error contract describes clean truncated collections with the adjacent field `_beyond_cap`,
    readable location and message pairs for validation in text, a single json document on partial
    failure of `sandbox rm`, empty ids as usage errors and the upper bound of `exec --timeout`.
  - Guide: a recommendation that scripts read `key_status`, one sentence about the request id on errors
    outside `login` (from the server envelope, `null` when the request was not sent or the response is not an envelope)
    and the new upper bounds of integer fields with a 422 response.
  - `CHANGELOG.md`: this round and the real hash (c328e95) of the previous documentation item.
- **Server: org quota bounds, a regenerated spec and a test that ties it to the schema**
  (e1984e3): changes in `src/sandfort/api/schemas/orgs.py`, `openapi/sandfort.v1.json` and
  `tests/test_api_limits_r51.py`.
  - The org quota body (`QuotaLimitsBody`) has upper bounds like the sandbox fields:
    `max_memory_mib` up to 16777216, `max_disk_gib` up to 1048576 and `max_sandboxes` up to 1000000
    (`MAX_QUOTA_MEMORY_MIB`, `MAX_QUOTA_DISK_GIB`, `MAX_QUOTA_SANDBOXES`; the first two reuse the
    constants from `schemas/sandboxes.py`). A larger value is 422 instead of 500.
  - `openapi/sandfort.v1.json` was regenerated: it contains the new `maximum` values (`auto_stop_minutes`,
    `auto_delete_minutes`, `cpu_millicores`, `memory_mib`, `disk_gib`, quotas) and the new schema
    `ResourceSpecRequest`, which `resources` references on create. This makes the
    previous state from the ca863a3 item, in which the committed spec lagged behind the schema, outdated.
  - The new test `test_committed_openapi_spec_matches_a_fresh_render` compares the committed spec with a fresh
    render (`render_spec(build_document())`); a stale spec fails the test with the instruction
    `python -m sandfort.api.openapi`.
  - Changed files: `src/sandfort/api/schemas/orgs.py`, `openapi/sandfort.v1.json`,
    `tests/test_api_limits_r51.py`.
- **CLI: carried request id on a name miss, filtered `cmd logs` and post-review cleanups**
  (b55cb2b): changes in `cli/src/sandfort_cli/cmd_cmd.py`, `config.py`, `output.py`, `refs.py`,
  `sandboxes.py`, `sanitise.py`, `snapshot.py` and `volume.py`, new `tests/test_cli_r51h.py`, plus
  fixes to `tests/test_cli_r48.py`, `tests/test_cli_r50.py`, `tests/test_cli_r50d.py` and
  `tests/test_cli_r50f.py`.
  - Stale claims in tests: `test_cli_r50d.py` expects the message `from 1 to 3600` for
    `exec --timeout`; `test_cli_r50.py` and `test_cli_r50f.py` check clean truncated collections
    (`relay_value()`, the adjacent field `_beyond_cap`, no marker entry) instead of the old marker;
    `test_cli_r48.py` gets hostile shapes for passes added after round 48 (percent sequences,
    query context, string sequences without an end, combining characters).
  - A sandbox name miss carries the request id: `SandboxNameNotFound` takes `request_id` from the SDK's
    `NotFound` (the id of the last list response in which the name was searched), so it is carried by the json error
    (`request_id`) and by the tail of the text line. Test: `test_a_name_miss_carries_the_request_id_of_the_list_reply`.
  - `cmd logs` (following and paging) passes program output through the same filter as `exec`
    (`echo_event()` calls `strip_dangerous_terminal()`): OSC (including the clipboard write), DCS,
    SOS, PM and APC are stripped, the rest stays. `shell` is still unfiltered.
  - The parenthesis in the fragment mask belongs to the sanitizer: `FRAGMENT_RE` is now defined in
    `sanitise.py` and excludes the closing parenthesis from the fragment, so it stays in the message; `output.py` no longer replaces
    a module attribute (`FRAGMENT_KEEPING_PAREN_RE` and the replacement in
    `install_angle_arguments()` were removed), so sanitization does not depend on import order.
  - LOW cleanups: the empty-name hint is `<name>` (`reject_empty_name()` in `snapshot create` and
    `volume create`); a json error body whose `details` is not an object keeps the error type of the actual status
    (`raw_details_error()` instead of `raw_details_conflict()`: 404 `NOT_FOUND` is `NotFound`, 503
    `ServiceUnavailable`, 409 `Conflict`); truncation inside a nested list counts toward the discarded count
    (`_relay_list()`); `sandbox rm --json` prints the processed refs even after an unexpected exception
    (`finally` in `rm`); dead code for collections removed from `clean_value()` (now scalar only; collections
    are walked by `relay_value()`).
  - Changed files: `cli/src/sandfort_cli/cmd_cmd.py`, `cli/src/sandfort_cli/config.py`,
    `cli/src/sandfort_cli/output.py`, `cli/src/sandfort_cli/refs.py`,
    `cli/src/sandfort_cli/sandboxes.py`, `cli/src/sandfort_cli/sanitise.py`,
    `cli/src/sandfort_cli/snapshot.py`, `cli/src/sandfort_cli/volume.py`,
    `tests/test_cli_r51h.py` (new), `tests/test_cli_r48.py`, `tests/test_cli_r50.py`,
    `tests/test_cli_r50d.py`, `tests/test_cli_r50f.py`.
- **Documentation: round 51 review leftovers** (e508830):
  only `marketing/pilot/beta-connect-guide.md` and `CHANGELOG.md`, no code change.
  - `CHANGELOG.md`: the round header and the ca863a3 item no longer claim that the spec lags behind the schema; new
    items for e1984e3 and b55cb2b; the real hash (a24649e) of the previous documentation item.
  - Guide: the sentence about the request id on a name miss describes the actual mechanism (the id of the last
    list response, not the error envelope); `cmd logs` strips dangerous terminal sequences like
    `exec`, while `shell` carries raw bytes deliberately; one sentence about the contract of json successful output
    (whitespace is collapsed, query-like values in labels are masked).

#### Round 50 (after tag `v0.1.0-beta.49`)
All items were committed to main after commit `24a2b39` (round 49), in commit order:
five CLI fixes and two documentation items. Each is derived from the diff of the named commit.
There is no spec regeneration in this round.
- **CLI: sanitiser as a shared module, applied to every command and to typer text errors**
  (dba3a42): new `cli/src/sandfort_cli/sanitise.py`, changes in `cli/src/sandfort_cli/main.py`,
  `cli/src/sandfort_cli/output.py` and `cli/src/sandfort_cli/sandboxes.py`, new `tests/test_cli_r50.py`.
  - The sanitiser's text helpers were moved from `sandboxes.py` to `sanitise.py`; `output.py`
    uses them for all commands, not only for login.
  - The text error line (`describe_error()`) and the json error object (`error_payload()`)
    clean everything the server said: the code (up to 100 characters), the message, `details` (keys and values,
    at most 50 entries, depth up to 4 levels), the request id (up to 128 characters) and the fields of the failed sandbox
    (`sandbox_id`, `state`, `error_reason`, `error_code`). Hint lines go through the same
    sanitiser.
  - The CLI's own messages go through a lighter pass (`scrub_local()`): control characters are removed
    and the key is masked; the text is cut to 2000 characters.
  - Text usage errors printed by typer itself (`unexpected extra argument`, `No such
    command`, `No such option`) go through the same sanitiser before printing (`sanitise_usage_error()`):
    a key given by mistake is masked, control characters are removed, the message is cut to 600 characters.
  - Changed files: `cli/src/sandfort_cli/sanitise.py` (new), `cli/src/sandfort_cli/main.py`,
    `cli/src/sandfort_cli/output.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `tests/test_cli_r50.py` (new).
  - Server messages in the shared error display (text line and json object) are cut to
    the default transport limit of 300 characters and reduced to a single line (whitespace is collapsed) from
    this first commit of round 50. The higher limit of 600 characters applies only to transport errors and
    the failed sandbox message.
- **CLI: masking before stripping, a single class of invisible characters and a cut exception tied to
  the path** (4a534b2): changes in `cli/src/sandfort_cli/sanitise.py`, new `tests/test_cli_r50b.py`.
  - The key and userinfo are masked before terminal control sequences are removed, not only after
    it, and they look through invisible and control characters (`_tolerant_sub()`): an escape byte in front of
    the marker or key no longer hides the secret or eats its first character.
  - A single definition of an invisible character (`is_invisible()`) serves removal and every match
    of the key and userinfo: Unicode categories Cf, Mn and Me plus code points that the categories miss
    (soft hyphen, Hangul fillers, blank braille, variation selectors, tag characters).
    `FORMAT_CHARS_RE` was replaced.
  - The cut exception for a token with a full authority applies only up to the last slash: a
    credential pair (colon) in the last path segment is discarded, while a long path without a
    colon stays whole.
  - Changed files: `cli/src/sandfort_cli/sanitise.py`, `tests/test_cli_r50b.py` (new).
- **CLI: the configured url rejects control characters, strips userinfo, and the check at creation never
  gives a traceback** (c9c390d): changes in `cli/src/sandfort_cli/config.py` and
  `cli/src/sandfort_cli/sandboxes.py`, new `tests/test_cli_r50c.py`.
  - A configured base url with a control character anywhere (userinfo, path, query) is rejected as
    `a control character in the url` (usage error).
  - Userinfo in the configured url (`SANDFORT_BASE_URL` or `base_url` from the profile) is stripped before
    the client is built (`strip_userinfo()`), because it would replace the API key with a Basic header;
    in text mode a note goes to stderr: `note: userinfo was removed from the configured
    base url (...)`; under `--json` there is none. Bearer authorization with the API key remains.
  - The "not logged in" error comes before any url check. A `base_url` field in the profile that
    exists but is not a usable string is a malformed profile (`read_profile()`,
    `stored_base_url()`), which is not the same as a logged-out user.
  - The name check the SDK performs during `sandbox create` does not print a traceback (`quiet_name_check()`):
    the transport error record is discarded (create itself reports the same error cleanly), for the other
    records only the traceback is removed.
  - Changed files: `cli/src/sandfort_cli/config.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `tests/test_cli_r50c.py` (new).
- **CLI: unified parser messages, angle brackets in the usage line and a "not found" code for a
  missed name** (ebf0922): changes in `cli/src/sandfort_cli/cmd_cmd.py`, `exec_cmd.py`, `keys.py` and
  `sandboxes.py`, new `tests/test_cli_r50d.py`.
  - `exec --timeout`, `key create --max-sandboxes` and the port of the `preview` command are accepted as text and
    converted in `parse_whole_number()`: a value that is not a whole number or is out of range gives the same
    usage error (`Invalid value for <opcija>: must be a whole number ..., got '<vrednost>'`,
    exit 2, the same wording under `--json` too); the port has a range of 1 to 65535.
  - Positional arguments in the usage line are written in angle brackets (`<sandbox>`, `<argv>...`,
    `<port>`, `<session-id>`, `<command-id>`, `<key-id>...`, `<name>`), not in curly ones.
  - A sandbox name that matches no live sandbox is reported under `--json` with the code `NOT_FOUND`
    (like a nonexistent id) with `"source": "client"` (`ref_errors()`); the text line and the exit code
    stay the same. It applies to `sandbox get`, `stop`, `start`, `reset`, `rm`, `exec`, `preview` and
    `cmd start`, `logs`, `kill`. An ambiguous name stays `CLI_ERROR`. (The `source` field was later
    removed, see the 72aed61 item below.)
  - Changed files: `cli/src/sandfort_cli/cmd_cmd.py`, `cli/src/sandfort_cli/exec_cmd.py`,
    `cli/src/sandfort_cli/keys.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `tests/test_cli_r50d.py` (new).
- **CLI: the display keeps marks of real languages, `source` dropped from name misses, unified
  wrappers** (72aed61): changes in `cli/src/sandfort_cli/cp_cmd.py`, `output.py`, `sandboxes.py`,
  `sanitise.py`, `shell_cmd.py` and `snapshot.py`, new `tests/test_cli_r50f.py`.
  - The removal of invisible characters from displayed text was narrowed to the format category (Cf) and
    an explicit list of fillers (`is_hidden_in_display()`, `DISPLAY_FILLERS`). The mark
    categories (Mn, Me), zero-width joiners and variation selectors stay in the output, because they carry the meaning
    of Thai, Devanagari, Hebrew niqqud marks, Arabic harakat, decomposed accents
    and emoji sequences. Those marks serve only in the internal view used for matching (`is_invisible()`,
    `MATCH_ONLY_INVISIBLE`), so a key or userinfo interrupted by marks is still found and masked.
    After the display stripping, the credential and fragment masks go once more through the view for
    matching.
  - A name miss (`NOT_FOUND` under `--json`) no longer has the field `"source": "client"`: the name lookup
    (a list or get call) did reach the server, while `"source": "client"` means that no request
    of the failed step reached it.
  - The `ref_errors()` wrapper was extended to the remaining three commands: `snapshot create`, `cp` and `shell`
    now give the same `NOT_FOUND` code for a missed name.
  - One depth rule for `details` in both modes: the text line (`describe_details()`) and the json
    object go through the same `clean_value()`; the map that is passed in is level 0.
  - Truncation markers: a map or list cut at the limit of 50 entries ends with a marker
    (`{"…": "<n> more"}`, or `"… <n> more"` respectively), so the total count stays at the limit. Two keys
    that sanitise to the same text are both kept, the second gets the suffix `#<n>`.
  - Metavar subclass: `AngleArgument` (`output.py`) replaces the earlier patching of a method of the class
    `TyperArgument` for the whole process; typer's class stays untouched, and the installation is idempotent.
  - Logger name test: `tests/test_cli_r50f.py` checks that the SDK logger that the quiet name check
    silences at creation exists under the name `NAME_CHECK_LOGGER` and that the filter adds and removes only
    that logger.
  - Updated expectations: `tests/test_cli.py`, `tests/test_cli_r37.py`, `tests/test_cli_r48b.py` and
    `tests/test_cli_r50b.py` were adapted to the new behaviour.
  - Changed files: `cli/src/sandfort_cli/cp_cmd.py`, `cli/src/sandfort_cli/output.py`,
    `cli/src/sandfort_cli/sandboxes.py`, `cli/src/sandfort_cli/sanitise.py`,
    `cli/src/sandfort_cli/shell_cmd.py`, `cli/src/sandfort_cli/snapshot.py`, `tests/test_cli.py`,
    `tests/test_cli_r37.py`, `tests/test_cli_r48b.py`, `tests/test_cli_r50b.py`,
    `tests/test_cli_r50f.py` (new).
- **Documentation: extent of the sanitiser, status 400/422, notes on the url and names** (e9313b6): only `marketing/pilot/beta-connect-guide.md` and `CHANGELOG.md`, no
  code changes.
  - Guide: the sentence that limited the sanitiser to login, probes and usage errors was replaced
    with an accurate one: the sanitiser applies to text coming from the server on every command and to typer
    text errors. The rules for invisible characters, masking before stripping and
    the path-bound cut exception were extended.
  - Guide: a 403 whose body is not a server envelope intentionally does not take over the `x-request-id` added by
    the proxy (it is not a server id).
  - Guide: the REST API section separates three validation responses: the label filter (400,
    `VALIDATION_ERROR`, empty `details`), body and query type (422, `VALIDATION_ERROR`,
    `details.errors`) and a bad environment variable name (422, `UNPROCESSABLE`, names in
    `details.names`). A missed sandbox name gets `NOT_FOUND` with `"source": "client"`.
  - Guide: without an API key the "not logged in" error comes before the url check; userinfo in
    the configured url is stripped with a note, bearer stays; unified parser messages and angle
    brackets in the usage line.
  - `CHANGELOG.md`: round 49 received the real hash of the documentation item (24a2b39).
- **Documentation: round 50 review leftovers** (c328e95): only
  `marketing/pilot/beta-connect-guide.md` and `CHANGELOG.md`, no code changes.
  - Guide: the server message in the shared error display is cut to the default transport limit of
    300 characters, not 600; the higher limit applies only to transport errors and the failed sandbox message.
  - Guide: the section on invisible characters now distinguishes the display (format only and the list of fillers) from
    the internal view used for matching (mark categories); marks of real languages stay in the output.
  - Guide: a name miss (`NOT_FOUND`) has no `"source"`, and it also covers `snapshot create`, `cp` and
    `shell`; the sentence that excluded them was removed.
  - `CHANGELOG.md`: the item for 72aed61, the line about the server message in the shared display, the wrapping of a long
    line in the round 49 item and the real hash (e9313b6) of the previous documentation item.

#### Round 49 (after tag `v0.1.0-beta.48`)
All items were committed to main after commit `23fe610` (round 48), in commit order: four
CLI fixes and documentation. Each is derived from the diff of the named commit. There is no spec regeneration
in this round.
- **CLI: the configured base url is checked as at login, never a traceback** (9ba375c):
  changes in `cli/src/sandfort_cli/config.py` and `cli/src/sandfort_cli/sandboxes.py`, new
  `tests/test_cli_r49.py`.
  - `SANDFORT_BASE_URL` and `base_url` from the profile go through the same structural checks as `login`
    (scheme, host, port, whitespace or brackets in the host, a url that local parsers reject) in the new
    function `check_configured_url()`, before the client is built. An unusable url gives the same
    single usage error (exit 2; under `--json` one `USAGE_ERROR` object) instead of a
    traceback. The error names the source: `SANDFORT_BASE_URL` or `base_url in <putanja profila>`.
  - The checks shared by login and configuration were moved to `reject_unusable_url()`; `perform_login`
    calls them from there, so login behaviour does not change.
  - Changed files: `cli/src/sandfort_cli/config.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `tests/test_cli_r49.py` (new).
- **CLI: the sanitiser steps share the same notion of whitespace and key; nested bodies and long echoes
  handled** (dd29975): changes in `cli/src/sandfort_cli/sandboxes.py`, new `tests/test_cli_r49b.py`.
  - Discarding the tail after stripping: when the text is cut, the tail (a partial API key or a token with
    a colon or `//`) is examined only after control and invisible characters are removed, so inserted
    characters cannot hide them. A token is delimited only by a plain space; a token whose last url
    has a full authority (closed with `/`, `?` or `#`, for example a long path) stays.
  - Whitespace classes: every whitespace other than the plain one (tab, line breaks, vertical tab, form feed,
    separator controls, next-line, non-breaking and other Unicode spaces, line and
    paragraph separators) does not end userinfo in the first masking pass, and is later collapsed to a single space.
    Control characters that are not whitespace are removed (`HIDDEN_CONTROLS_RE`).
  - Key masking in the decoded copy: the own key is masked even when written as any
    mix of literal and percent-encoded characters, in both cases of hexadecimal digits
    (`key_pattern()`); a partial key at the cut is also recognised in percent-encoded form
    (`decoded_key_tail()`).
  - Foreign key-shaped tokens: every token `sf_` + at least 16 key characters in the relayed text
    is masked, not only the key from the call; a tail `sf_` with up to 15 characters at the cut is discarded.
  - Nested bodies: a response nested so deeply that the parser gives up (`RecursionError`) is treated
    as a body that is not json (not a status document, no error envelope), not as a traceback.
    The request id of the error envelope is read from the error itself, then from the envelope's `meta`, then from the
    `x-request-id` header.
  - Long echoes: a url longer than 2000 characters whose echo would be empty is shown only as `…`.
    The new local check `reject_long_host()` rejects a host longer than 253 characters (reason "the host is
    longer than 253 characters", usage error, exit 2).
  - Changed files: `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli_r49b.py` (new).
- **CLI: a single message for `--wait-timeout`, an upper bound on value echo, `--max-sandboxes`
  without a label and a clean array of scopes** (20adea2): changes in `cli/src/sandfort_cli/sandboxes.py`,
  `cli/src/sandfort_cli/keys.py` and `cli/pyproject.toml`, new `tests/test_cli_r49c.py`.
  - `--wait-timeout` (`sandbox create` and `sandbox start`) is accepted as text and converted in
    `parse_wait_timeout()`: a value that is not a number gets the same usage error (exit 2, also under
    `--json`) as `nan`, `inf`, zero and a negative number. Three messages: "requires --wait", "must be a
    finite number greater than 0" and both together.
  - A value the user typed (`--label`, `--env`, `--expires-at`) that the usage error message
    repeats is cut separately to 120 characters (`echo_value()`), so the reason after it survives
    the limit on the whole message.
  - `key create --max-sandboxes` without any `--label` is a usage error (exit 2, option
    `--label`, message "at least one KEY=VALUE is required with --max-sandboxes"); previously a client
    error with exit 1.
  - The remainder of scopes beyond the limit of 20 is no longer an "and N more" entry in the array: `missing_scopes`
    is a clean array of names, and the count is in the new numeric field `missing_scopes_beyond_cap` (in a login success
    with a `limited-scope` key, in the `details` of the `--require-verified` error). The text line
    of scopes ends with ", and N more".
  - `cli/pyproject.toml`: dependency `typer<0.28` (the help layout and the usage error style were tested
    on the 0.27 line). `tests/test_cli_r48.py` was adapted to the new field; it is only the first of six older
    test modules adapted to intended behaviour changes in this round, the other five are in f436e12
    below.
  - Changed files: `cli/pyproject.toml`, `cli/src/sandfort_cli/keys.py`,
    `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli_r48.py`, `tests/test_cli_r49c.py` (new).
- **Documentation: family of malformed urls, error code on a failed probe, round 49 changes
  and the placeholder convention** (eaa80ff): documentation only, no code changes.
  - `marketing/pilot/beta-connect-guide.md`: the sentence saying that a url found only by the status probe
    is a "client error with exit 1" is outdated; a url with an unclosed IPv6 bracket is a usage
    error (exit 2) with the reason `malformed brackets in the host`. The list of reasons was extended
    with the other reasons from the code (host longer than 253 characters, whitespace or a control character in the host, a url that
    cannot be parsed). The table row for a failed status probe no longer mentions an unusable url.
  - Same guide: a failed status probe carries the client code `CLI_ERROR` with empty `details` (no
    `server_code` field); the example in the advice on the placement of `--json` always names the same command, which is now
    stated; all changes from 9ba375c, dd29975 and 20adea2 listed above are documented.
  - `docs/operations.md`: the note on paths also explains the difference between `.context/` and `context/`, and
    the placeholder convention (angle brackets or a plain word as in the CLI help; curly braces only
    in REST paths from the OpenAPI document) is recorded in the same note. There were no items with curly
    braces in command lines in the runbook; in REST paths they remain.
  - `CHANGELOG.md`: round 48 received the real hash of the documentation item (24ce96a).
- **CLI: bounded key-shape mask, recursion guard, typer upper bound in the root and
  adapted assertions** (f436e12): changes in `cli/src/sandfort_cli/config.py`,
  `cli/src/sandfort_cli/sandboxes.py` and the root `pyproject.toml`, five older test modules.
  - Left boundary of the key-shape mask: `KEY_SHAPE_RE` does not start after a letter or digit, so a longer
    identifier that merely contains the prefix `sf_` in the middle stays untouched. A token that does not follow
    an alphanumeric character (start of text, `=`, `(`, `_`, `-`) is still masked. New tests
    are in `tests/test_cli_r47.py`.
  - `load_profile()` also catches `RecursionError`: a profile file nested so deeply that the parser
    gives up is treated as an unreadable profile (client error, exit 1, message "profile
    <path> is unreadable; run 'sandfort login' again"), not as a traceback. The new test is in
    `tests/test_cli_r47.py`.
  - The help of the `login` command and the result description (`login_payload()`) mention `missing_scopes_beyond_cap`:
    the number of missing scopes the server named beyond the transport limit, `0` when there are none.
  - Root `pyproject.toml`: dependency `typer<0.28`, the same upper bound as in
    `cli/pyproject.toml` from 20adea2; previously it was unbounded in the root.
  - The earlier claim in the 20adea2 item that only `tests/test_cli_r48.py` was adapted was correct
    at the time, but incomplete: this commit adapts five more older modules to the intended
    behaviour changes of this round, so the total is six. `tests/test_cli_keys_r31.py` and
    `tests/test_cli_r37.py`: `key create --max-sandboxes` without `--label` is a usage error (exit
    2, the message names `--label`), and an unusable base url from the environment gives a usage error
    (exit 2) with the variable name. `tests/test_cli_r45.py`, `tests/test_cli_r46.py` and
    `tests/test_cli_r47.py`: the expected json objects contain `"missing_scopes_beyond_cap": 0`.
  - Changed files: `cli/src/sandfort_cli/config.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `pyproject.toml`, `tests/test_cli_keys_r31.py`, `tests/test_cli_r37.py`,
    `tests/test_cli_r45.py`, `tests/test_cli_r46.py`, `tests/test_cli_r47.py`.
- **Documentation: correction of the round 49 item on changed test modules** (24a2b39): only
  `CHANGELOG.md`, no code changes. The 20adea2 item now says that `tests/test_cli_r48.py` is the first of
  six adapted modules; the literal `ovaj commit` from the eaa80ff documentation item was replaced with
  its hash.

#### Round 48 (after tag `v0.1.0-beta.47`)
All items were committed to main after commit `69f53d6` (round 47), in commit order: CLI
sanitizer, CLI usage and documentation. Each is derived from the diff of the named commit.
There is no spec regeneration in this round.
- **CLI: linear-time sanitizer with bounded input, upper bound for scopes and
  `server_code` in `--require-verified` details** (347d7ae): changes in
  `cli/src/sandfort_cli/sandboxes.py`, new tests in `tests/test_cli_r48.py`.
  - The raw text is cut to 2000 characters before any rule runs, so the running time
    does not depend on what the server sends; the userinfo patterns use lookbehind and possessive
    quantifiers. A fragment at the cut that is only the beginning of an api key is dropped, and text cut
    this way always ends with `…`.
  - Userinfo is removed before control sequences are removed as well (a control character in a password cannot
    hide the rest of the url). The api key is masked in url-encoded forms too. Unicode tag characters
    (U+E0000 to U+E007F) are removed as invisible.
  - The reason for a failed status probe and the url repeated in messages now pass through the same
    sanitizer (previously only url masking). The url in a message is cut separately to 200 characters, the usage
    error message to 600 (previously 300), so the reason after the url survives.
  - At most 20 names of missing scopes are carried over from the response, the rest is a single entry
    `and N more`.
  - A negative port counts as out of range. In the `details` of the `--require-verified` error, the field
    `server_code` was added when the server envelope sent a code (a 403 without an envelope has none); the value is
    sanitized.
  - Changed files: `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli_r48.py` (new).
- **CLI: hint in strict mode, single usage error for an invalid url, label and
  `--expires-at`** (1f4eb30): changes in `cli/src/sandfort_cli/main.py`, `sandboxes.py` and `keys.py`,
  new `tests/test_cli_r48b.py`.
  - Strict mode (`--require-verified`): the hint never offers `--verify-key` or `--no-verify`; it says
    "retry" or check the base url, then "or drop --require-verified if saving without the key
    check is acceptable". A failed status probe says "check the url and retry".
  - An `--expires-at` that is not ISO 8601 or has no time zone, and a `--label`/`--env` that is not
    `KEY=VALUE`, are now usage errors (exit 2, option name in the message) instead of a client error with
    exit 1. The check runs before any request and before the profile is read (`key create`, `sandbox create`,
    `sandbox list`).
  - Every url rejected locally at login (unsupported scheme, no host including `http://` and
    `https:///`, a port that is not a number such as `invalid port`, port out of range) is one family: the same
    wording, usage error with exit 2. The port is checked before the `--no-verify` branch, so an
    inconsistency cannot be saved even without the check. An empty port (`host:`) is accepted.
  - Calling a command group without a command under the global `--json` prints one json object
    `USAGE_ERROR` (exit 2) without help text; text mode still shows help. A misplaced `--json` (after the command)
    gets the addition "--json is a global option and belongs before
    the command, for example: sandfort --json sandbox list".
  - `--wait-timeout` without `--wait` and with an invalid value gives one message: "requires --wait,
    and must be a finite number greater than 0".
  - Changed files: `cli/src/sandfort_cli/main.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `cli/src/sandfort_cli/keys.py`, `tests/test_cli_r47.py`, `tests/test_cli_r48.py`,
    `tests/test_cli_r48b.py` (new).
- **Documentation: usage errors and sanitizer from round 48, paragraph on the login error code, link to the
  guide, note on paths** (24ce96a): documentation
  only, no code changes.
  - `marketing/pilot/beta-connect-guide.md`: one sentence that on a failed key check the
    `error.code` is always `CLI_ERROR`, and the server code is read from `error.details.server_code`; in the
    sanitizer, "masked" for userinfo was replaced with "removed" (userinfo is removed without a marker), and
    the tradeoff says that even a host with a dot without a port and path does not trigger the rule for bare userinfo;
    `--json` is described as a global option that goes BEFORE the command, with an example; all
    changes from 347d7ae and 1f4eb30 listed above are documented.
  - `docs/beta-terms.md`: the guide path in plain text was replaced with a link to the published page
    https://docs.sandfort.dev/guide.html.
  - `docs/operations.md`: a note at the top that paths such as `deploy/k8s/` are paths in the repository,
    not links on the documentation site.
  - `CHANGELOG.md`: round 47 got items for 69f53d6 and 6a5b392 (the real hash of the documentation item
    98b6dfb is already recorded).
- **Test: robust pairing of the kernel interrupt process under load** (0babb81): changes only in
  `tests/test_code_context_interrupt.py`, no change to product code.
  - The new helper `ready_sleeper()` starts a sleeper process and waits for its `ready` signal (up to 30 s,
    `select` on stdout) before the test sends SIGINT. Under load, a SIGINT that arrives while a fresh interpreter
    is still importing modules can swallow the startup code, so the process never finishes;
    the handshake rules this out.
  - Two tests of the interrupt script (`..._signals_the_process_whose_cmdline_names_the_directory` and
    `..._writes_the_target_before_signalling`) use `ready_sleeper()` instead of `sleeper()`.
  - Changed files: `tests/test_code_context_interrupt.py`.
- **CLI: structural local url check on every path, dropping a cut token,
  masking of the url-encoded own key and of whitespace in the password, hint about `--json` only when json
  mode is not enabled** (1999436): changes in `cli/src/sandfort_cli/main.py` and
  `cli/src/sandfort_cli/sandboxes.py`; updated assertions in `tests/test_cli_r37.py`,
  `tests/test_cli_r45.py`, `tests/test_cli_r46.py`, `tests/test_cli_r48.py` and
  `tests/test_cli_r48b.py`. Complements the items 347d7ae and 1f4eb30 above (does not change them).
  - The new check `reject_malformed_url` runs before the `--no-verify` branch, so even an unsaved login
    (`--no-verify`) rejects a structurally invalid url. It rejects a space or control character in the host,
    brackets that do not enclose the whole host (an unclosed IPv6 bracket, text after it) and every url that the
    local parsers reject (`urlsplit` and `httpx.URL`, the one used by requests). The reason is a fixed
    phrase, because the parser message can quote parts of the url. Thus the whole family of locally rejected
    urls from item 1f4eb30 (scheme, host, port) covers this case as well: the same wording, usage
    error with exit 2, nothing is sent or saved. The helper `url_authority()` was extracted, which
    is shared by the host, port and structure checks.
  - Cut token: when the raw text is cut to 2000 characters, the last token (up to a
    space) that contains a colon is also dropped. A url cut inside the userinfo no longer has an `@` by which it could be
    recognized, so the part of the password before the cut would otherwise be printed (`drop_partial_url()`). Tab, carriage
    return and newline do not end a token. This complements the dropping of a partial api key from
    347d7ae.
  - Masking of the own key also covers fully percent-encoded forms (`_ - . ~` are encoded too,
    which standard encoding leaves alone, as is the form in which every byte is encoded), each
    with uppercase and lowercase hexadecimal letters (`key_forms()`).
  - Whitespace in the password: the first userinfo masking pass on the raw text (before flattening
    whitespace) allows tab, carriage return and newline inside the userinfo of a url, with or without a
    scheme (`mask_raw_userinfo()`), so a line break in the password cannot split a url into an unmasked
    prefix of the password and the host.
  - The hint about the placement of `--json` (`add_json_placement_hint`) is added only when json mode is not already
    enabled: with a leading `--json` the claim "belongs before the command" would be wrong. The message of the
    json usage error object does not change in this case; the text error frame keeps the hint.
  - Test: the sanitizer time budget in `tests/test_cli_r48.py` was raised from 0.5 s to 1 s (the bounded
    work takes milliseconds; the limit is wider so that a slow CI runner does not cause a flaky test), and the test was
    renamed to `..._finishes_within_the_budget`. New tests cover the structural check,
    the cut token, encoded key forms, whitespace in the password and the hint about `--json`; assertions in the modules
    r37, r45, r46, r48 and r48b were adjusted to the single usage error and the new behavior.
    `tests/test_code_context_interrupt.py` got only a comment about the diagnosis of the earlier instability
    (SIGINT arrives before the new interpreter installs the default handler).
  - Changed files: `cli/src/sandfort_cli/main.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `tests/test_cli_r37.py`, `tests/test_cli_r45.py`, `tests/test_cli_r46.py`,
    `tests/test_cli_r48.py`, `tests/test_cli_r48b.py`, `tests/test_code_context_interrupt.py`.
- **Test: assertions for key creation from round 31 expect the usage error exit code** (b0cc9bc):
  changes only in `tests/test_cli_keys_r31.py`, no change to product code.
  - `key create ... --expires-at` without a time zone is now asserted as exit 2 (usage error from
    1f4eb30), not exit 1; the message still contains "timezone". The case `--max-sandboxes` without
    `sandbox_labels` remains exit 1 (client error).
  - An assertion was added for `--json`: stderr is empty, `error.code` is `USAGE_ERROR`, `error.source`
    is `client`, and the message contains "timezone". The request is still not sent (0 calls of the route).
  - Changed files: `tests/test_cli_keys_r31.py`.

#### Round 47 (after tag `v0.1.0-beta.46`)
All items were committed to main after commit `468c6cc` (round 46), in commit order: CLI
login and documentation. Each is derived from the diff of the named commit. There is no spec regeneration in this
round.
- **CLI: shared sanitizer of text relayed from the server, option `--require-verified`, json usage errors
  across the whole CLI and earlier rejection of an invalid port** (5e56c1c): changes in
  `cli/src/sandfort_cli/sandboxes.py` and `cli/src/sandfort_cli/main.py`, new tests in
  `tests/test_cli_r47.py`.
  - Text that the CLI relays from the server (the build value in the status line, code, message, request id and
    scope names from the key check response), the reason for a failed key check request, the url
    in messages about an invalid url and the usage error message pass through the same sanitizer, in
    both text and json mode: the key the user supplied is masked (`***`) wherever it appears,
    userinfo is masked even without a scheme (`//user:password@host`, `user:password@host`), query values and
    fragment are masked, terminal escape and control sequences (OSC, CSI, other escape sequences,
    backspace, newlines) and invisible format characters (zero-width, bidi controls) are removed,
    runs of whitespace become a single space, and the field is cut to 300 characters with an ellipsis (`…`).
    A build value that is empty after that is shown as `build unreported`. The reason for a failed
    status probe keeps only the earlier url masking.
  - New option `login --require-verified` (strict mode for bootstrap scripts): it implies the key check
    and succeeds only when the check is answered with 2xx. A 403 with a server envelope (`limited-scope`)
    and a 403 without an envelope (`not-checked`) now end with exit code 1 and nothing is saved (the existing
    profile stays); the json error object carries `key_status`, `missing_scopes` (when the
    server names them) and `request_id` (when it sent one) in `details`. It cannot be combined with `--no-verify`
    (usage error, exit 2); with `--verify-key` it is allowed and changes nothing.
  - The json object of a successful login: a `limited-scope` key adds `missing_scopes` and `request_id`
    (`null` when the server did not send it); the new field `userinfo_removed: true` exists only when
    userinfo was removed from the saved url. The text success line for a 403 without an envelope reads
    `Profile saved to <path>; the api key was not verified` instead of `Logged in; ...`.
  - An empty `--api-key`, an empty `--base-url` and an unsupported scheme (a url that does not start with `http://` or
    `https://`) are now usage errors with exit code 2 (previously a client error with exit 1).
  - A port outside the range 1-65535 (including 0) is caught in advance, before any request, as "is not a
    valid url (port out of range 1-65535); nothing was sent" (`"source": "client"`, exit 1);
    a port that is not a number remains at the probe.
  - With the global option `--json` given before the command, a usage error anywhere in the CLI (bad
    option value, missing argument) is printed as a single json object (`USAGE_ERROR`,
    `"source": "client"`, exit 2) instead of the framed usage box. Text mode keeps the frame,
    and a group called without arguments still shows help.
  - Changed files: `cli/src/sandfort_cli/main.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `tests/test_cli_r47.py` (new).
- **CLI: rule for bare userinfo adapted to email addresses** (0653fe2): change in
  `cli/src/sandfort_cli/sandboxes.py`, updated tests and two new regression tests.
  - `BARE_USERINFO_RE` masks `user:password@host` without a scheme only when it looks like a url authority, i.e. when
    the host is followed by a port or path (`user:pw@host.internal:8443`, `user:pw@host.internal/path`).
    The scheme-relative form (`//user:password@host`) is still always masked. Ordinary email addresses
    and label-email pairs in relayed server text (`mailto:support@example.com`,
    `contact:ops@example.com`, `help@example.com`) remain unchanged.
  - Tradeoff: a fully bare `user:password@plainword`, without a port and without a path, is deliberately no longer
    masked because it is indistinguishable from a label followed by an email address.
  - Five older checks updated: in `tests/test_cli.py`, `tests/test_cli_r44.py` and
    `tests/test_cli_r46.py` an invalid or empty `--base-url` and `--api-key` expect exit code 2
    (usage error) instead of 1; in `tests/test_cli_r45.py` and `tests/test_cli_r46.py` the json object of a
    `limited-scope` key also expects the fields `missing_scopes` (`[]`) and `request_id`. In
    `tests/test_cli_r47.py` the bare userinfo examples got a port so that they stay masked.
  - Two new regression tests in `tests/test_cli_r47.py`: an error that is not a usage error does not
    become `USAGE_ERROR` under `--json` (`--require-verified` after a 403 gives `CLI_ERROR`, exit 1,
    nothing is saved), and an ordinary email address in a relayed server message survives the sanitizer in
    text and in json mode. Alongside them, parametrized checks were added that email forms do not
    change and that the userinfo of authority forms is still masked.
  - Changed files: `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli.py`,
    `tests/test_cli_r44.py`, `tests/test_cli_r45.py`, `tests/test_cli_r46.py`,
    `tests/test_cli_r47.py`.
- **Documentation: corrected paragraph on the userinfo note, `--require-verified`, sanitization, json
  fields and usage errors, path markers** (98b6dfb): documentation
  only, no code changes.
  - `CHANGELOG.md`: the round 46 item for the documentation commit got the real hash (44654c3).
  - `marketing/pilot/beta-connect-guide.md`, `login`: the paragraph on userinfo was rewritten according to the behavior of the
    CLI. The note `note: userinfo was removed from the saved base url (...)` is printed only on a
    successful login whose url carried userinfo (in json mode this is the field `userinfo_removed`);
    a url with an empty host after removal is rejected without a note. The previous wording linked
    the note to a rejected url, which the CLI does not do. An overlong line was wrapped.
  - Guide, same section: documented the behavior from 5e56c1c (sanitization of relayed text, json
    fields `missing_scopes`, `request_id` and `userinfo_removed`, semantics of `--require-verified`, exit 2
    for an empty key or url and an unsupported scheme, early rejection of an out-of-range port, json usage errors
    across the whole CLI); the outcome table was extended with the column "With `--require-verified`".
  - Guide: the visible label of the link to the beta terms is no longer a repo path (`docs/beta-terms.md`) but
    "beta terms"; a note was added that a path in `backtick`s that is not a link (e.g.
    `openapi/sandfort.v1.json`) denotes a file in the maintainer's repository, not a url of the documentation
    site, and the same marker accompanies individual mentions of that path. The guide has no
    cross-references to the runbook.
- **Test: login checks from round 37 expect the usage error exit code** (69f53d6): tests only
  (`tests/test_cli_r37.py`), no code changes. An invalid `--base-url` and an empty `--api-key` at
  login expect exit 2 and the code `USAGE_ERROR` instead of a client error with exit 1.
- **Documentation: sanitizer tradeoff for email addresses and an item for post-review fixes**
  (6a5b392): documentation only, no code changes. `CHANGELOG.md` got an item for 0653fe2 and the real
  hash (98b6dfb) for the documentation item of this round; `marketing/pilot/beta-connect-guide.md`
  describes the rule for bare userinfo and the tradeoff for a bare `user:password@plainword`.

#### Round 46 (after tag `v0.1.0-beta.45`)
All items were committed to main after commit `8d69f4d` (round 45), in commit order: test,
CLI login, documentation and fixes after review. Each is derived from the diff of the named commit. There is no spec regeneration in
this round.
- **Test: json checks for `login` expect the `key_verified` field** (656e111): tests only
  (`tests/test_cli.py`, `tests/test_cli_r44.py`), no code changes.
- **CLI: `login --verify-key` carries the server error, the `key_status` field and a saved profile without
  userinfo** (ea8b60b): changes in `cli/src/sandfort_cli/sandboxes.py`.
  - The key check reads the response body: the body is the "server's" only if it is a JSON object with
    `"success": false`. For a 403 with that envelope, the line remains "key probably valid, but
    lacks the scope to read sandboxes" and adds the scope names from `details.missing_scopes` and
    the request id when present. A 403 without the envelope (proxy, login page) no longer claims the key
    is valid: it prints `api key: NOT verified; the 403 answer (...) did not come from the server's API`,
    the profile is saved, and the fields are `key_verified: false` and `key_status: "not-checked"`.
  - Errors for 401 and other statuses name the server's code, message and request id when the envelope
    parses; 3xx gets a redirect hint, 5xx gets a hint to retry or to
    log in without the option. In json mode the error object carries `details` with `server_code` and
    `request_id`.
  - New json field `key_status` with three values: `verified`, `limited-scope`, `not-checked`.
    The older field `key_verified` (`true`, `"limited-scope"`, `false`) remains for compatibility.
  - Userinfo (`user:password@`) is also removed from the url saved to the profile, with the note `note:
    userinfo was removed from the saved base url (...)`; the same url that was checked is saved.
  - Masking: the fragment in the printed url becomes `#***`. The `http`/`https` scheme in any
    letter case is accepted and saved in lowercase. A url that cannot be used (disallowed url
    or unsupported scheme) gives the message "is not a valid url ... nothing was sent".
  - In json mode `login` asks no questions: a missing `--base-url` or `--api-key` gives a single
    object `{"error": {...}}` with `code` `USAGE_ERROR` and exit code 2. In text mode
    the value is still requested by prompt.
  - Changed files: `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli_r46.py` (new).
- **Documentation: `--verify-key` outcome table, new `login` behavior, absolute link to the beta terms
  and default values of the key list** (44654c3):
  documentation only, no code changes.
  - `CHANGELOG.md`: the round 45 item for the documentation commit received the real hash (8d69f4d).
  - `marketing/pilot/beta-connect-guide.md`, `login`: compact table of key check outcomes (response,
    whether the profile is saved, exit code, json fields) for 2xx, 403 with envelope, 403 without envelope, 401,
    other status, failed request, `--no-verify` and the default flow; the prose remains, the table carries
    the matrix.
  - Guide, same section: documented the behavior from ea8b60b (userinfo removed from the saved
    url with a note, the `key_status` field and the older `key_verified`, fragment masking, scheme regardless of
    letter case, json usage error object when the key is missing); the paragraph on
    credentials in the url was rewritten because "saved as entered" no longer holds.
  - Guide: relative links to `docs/beta-terms.md` (path `../../`) replaced with the absolute
    `https://docs.sandfort.dev/beta-terms.html`, because the relative path does not resolve on the
    documentation site where the guide is published.
  - Guide, "Managing API keys": one sentence says the defaults differ
    (the SDK method and the HTTP list return all keys, while `sandfort key list` hides revoked ones without
    `--all`), so the two statements do not read as a contradiction.
- **CLI: fixes after the round 46 review — userinfo masking in carried reasons, fragment only
  in url context, retry hints on 408/429 and rejection of an empty host** (c243703): changes
  in `cli/src/sandfort_cli/sandboxes.py`.
  - Userinfo (`user:password@`) is now masked anywhere in text carried in an error message
    (the reason from a transport error or a server message), not only at the start of a url; the pattern stops at
    a space, so it does not swallow surrounding words.
  - The fragment is masked (`#***`) only when it follows a url-like token (`://` earlier in the same word);
    a marker such as `issue #123` in a message is left untouched.
  - The hint "retry or login without --verify-key" that applied to 5xx now also applies to 408 and 429 on
    the key check; other statuses still get a hint to check the base url.
  - A url whose host is empty after userinfo removal (`http://user@`, `http://:80`) is rejected before
    any request as "is not a valid url (no host); nothing was sent", as a client error
    (`"source": "client"`). An IPv6 host in square brackets counts as a host; an invalid one gives
    the probe message "not a valid url".
  - Tests: seven older checks updated for the new fields and the new wording — six expect
    `key_status` in the json output (`tests/test_cli.py`, `tests/test_cli_r44.py`,
    `tests/test_cli_r45.py`; the 403 check now sends the server's envelope because without it the outcome is not
    `limited-scope`), and one expects "is not a valid url" instead of "did not answer the status
    endpoint" for an unclosed IPv6 bracket. Additionally, one call in `tests/test_cli_r44.py` was only
    reformatted. New cases are in `tests/test_cli_r46.py`.
  - Changed files: `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli.py`,
    `tests/test_cli_r44.py`, `tests/test_cli_r45.py`, `tests/test_cli_r46.py`.

#### Round 45 (after tag `v0.1.0-beta.44`)
All items were committed to main after commit `1d9d865` (round 44), in commit order: CLI
login and documentation. Each is derived from the diff of the named commit. There is no spec regeneration in this
round.
- **CLI: `sandfort login --verify-key`, a clean error for an invalid url, probe without userinfo and
  masked query values** (0262b29): the new `--verify-key` option sends, after the status check,
  one authenticated `GET /v1/sandboxes?limit=1` with the key being saved. A 2xx response prints
  `api key: verified (HTTP <code> on GET /v1/sandboxes)`; 403 saves the profile with a note that the key
  is valid but lacks the scope to read sandboxes; 401 saves nothing (the existing profile remains) and
  ends with exit code 1; any other status or a failed request also saves nothing.
  The option must not be combined with `--no-verify` (usage error). Without `--verify-key` a successful
  `login` prints an extra line `api key: NOT verified (...)`, because the status check does not prove
  that the key is valid. A url that `urlsplit` cannot parse (for example an unclosed IPv6
  bracket) now gives a clean `login` error instead of an exception, and nothing is saved. The status check
  request and the key check request are sent without the `user:password@` part of the url (no derived Basic
  header); `redact_userinfo` was replaced by the function `redact_url`, which besides userinfo also masks
  query parameter values (`k=***`) in the url printed in lines and errors, including
  the reason text. The url is still saved as entered (with whitespace and trailing slash trimmed).
  Changed files: `cli/src/sandfort_cli/sandboxes.py`, test `tests/test_cli_r45.py` (new).
- **Documentation: `--verify-key`, the exact meaning of "build unreported", `SANDFORT_CONFIG_DIR`,
  a warning about credentials in the url and the SDK key list filter**
  (a63080b): documentation only, no code changes.
  - `CHANGELOG.md`: the round 44 item for the documentation commit received the real hash (ee55d31).
  - `marketing/pilot/beta-connect-guide.md`, CLI section (`login`): described the
    `--verify-key` option (one authenticated call to list sandboxes after the status check; 403 saves
    the profile with a note about the limited scope; 401 saves nothing) and that without the option a successful `login` does not
    prove the key is valid, in line with the new `api key: NOT verified` line.
  - Guide, same section: a warning not to put credentials in the base url itself; the probe removes
    `user:password@` before every request and masks query values in printed urls, but the url
    is saved to the profile as entered (`redact_url`, `validate_base_url`).
  - Guide, paragraph on the build: "build unreported" refers to a `build_sha` value that is
    `null` (or empty or non-text); a response that is valid JSON but has no
    `build_sha` key is rejected as a document that is not a status (`probe_server`).
  - Guide, paragraph on profiles: `SANDFORT_CONFIG_DIR` is a supported way for the CLI to use a different profile directory
    (parallel accounts, test environments); default `~/.config/sandfort`, file
    `profile.json` (`cli/src/sandfort_cli/config.py`).
  - Guide, "Managing API keys": a sentence saying that `list_api_keys(status=...)` in the Python SDK accepts the same
    filter as the HTTP endpoint and the CLI, so revoked keys can also be listed from code.
- **CLI: the key check preserves the query from the base url, softer text for 403, earlier error for the option combination
  and the `key_verified` field in json output** (a4ccf87): `GET /v1/sandboxes?limit=1` with
  `--verify-key` now merges `limit=1` with the query already in the base url (`copy_merge_params`),
  instead of replacing it. A 403 response no longer claims the key is valid: the line reads
  `api key: the server answered 403 (HTTP 403 on GET /v1/sandboxes); the key is probably valid but
  lacks the sandbox read scope`, because the same response can also be returned by a proxy in front of the server; the profile is
  still saved. The errors `httpx.UnsupportedProtocol` and `httpx.InvalidURL` are now classified as
  a request that was never sent (`request_never_sent`, list `NEVER_SENT_ERRORS`), along with
  `ConnectError` and `ConnectTimeout`. The combination of `--verify-key` with `--no-verify` is rejected in the
  callback of both options, which are now `is_eager`, so the usage error (exit code
  2) arrives before any prompt for the url or key. A successful `login` in json mode returns the object
  `{"profile": ..., "key_verified": ...}`: `key_verified` is `true` after a confirmed key (2xx),
  the string `"limited-scope"` after a 403 response and `false` when the key was not checked (without
  `--verify-key`). Changed files: `cli/src/sandfort_cli/sandboxes.py`,
  `tests/test_cli_r45.py`.
- **Documentation: text for 403, paragraph on credentials in the url and the `key_verified` field**
  (8d69f4d): documentation only, no code changes.
  - `CHANGELOG.md`: the round 45 item for the documentation commit received the real hash (a63080b); added
    an item for a4ccf87.
  - `marketing/pilot/beta-connect-guide.md`, `login --verify-key`: the 403 item aligned with
    the softer CLI text from a4ccf87 (the server answered 403, the key is probably valid but lacks the scope
    to read sandboxes; the same response looks identical when returned by a proxy).
  - Guide, same section: documented the `key_verified` field in the json output of a successful `login`
    (`true`, `"limited-scope"`, `false`); the sentence about the `{"profile": ...}` object replaced with an exact
    description of both fields.
  - Guide, paragraph on credentials in the url: the sentence about the `exec` options (`--cwd`, `--timeout`, `-i`)
    split into its own paragraph, because it belonged to a different topic, and an overlong line was wrapped; no
    change of facts.

#### Round 44 (after tag `v0.1.0-beta.43`)
All items were committed to main after commit `0c40778` (round 43), in commit order: CLI
login and documentation. Each is derived from the diff of the named commit. There is no spec regeneration in this
round.
- **CLI: `sandfort login` checks `GET /v1/status` before saving the profile** (43f27bc): one
  unauthenticated `GET` to `<base-url>/v1/status` (timeout 5 s, no redirect following). A
  2xx response with a JSON object whose `data` field carries the key `build_sha` saves the profile and prints the line
  `server <base-url>: build <first 12 characters of build_sha>`, or `build unreported` when
  `build_sha` is empty or is not text. A connection error, a non-2xx response and a body that is not
  a status document save nothing (the existing profile remains) and end with exit code 1;
  the message names the url and suggests `--no-verify`. The new `--no-verify` option saves the profile without a request and
  prints `server <base-url>: not checked (--no-verify)`. Input is validated before the request (an invalid
  url or an empty key sends nothing), and with the global `--json` stdout remains the object
  `{"profile": ...}` without the build line. Behavior change: `login` against a server that does not respond no longer
  succeeds silently. Changed files: `cli/src/sandfort_cli/sandboxes.py`, test
  `tests/test_cli_r44.py` (new) and the existing `tests/test_cli.py`.
- **Documentation: correct recovery example, `status` query, key list visibility and login**
  (ee55d31; later additions to the same section in 1d9d865): documentation only, no code changes.
  - `CHANGELOG.md`: an outdated sentence in the round 43 item (the guide supposedly says that handle `start` does not
    accept `wait`) was replaced with a correct one; added a convention about the hash of a documentation item in the header.
  - `marketing/pilot/beta-connect-guide.md`, recovery after `sandbox_stopped`: the code block uses
    `sbx.start(wait=True, wait_timeout_s=60)`, like the sentence below it.
  - Guide, "Managing API keys": a sentence refers to the repeated query parameter rule (the
    last value applies) from the section on unknown query parameters.
  - Guide, "Managing API keys": a key with a label scope sees in the list only keys whose label scope
    contains all of its pairs (`ApiKeyAdminService.list_keys`, `src/sandfort/services/api_key_admin.py`
    and `matches` in `src/sandfort/auth/label_scope.py`); a key without labels, for example the bootstrap admin,
    is therefore not on such a list.
  - Guide, CLI section: described the check at `login` (status endpoint, build line,
    `--no-verify`) per 43f27bc.
- **CLI: hermetic `login` tests, userinfo removal from messages and a redirect hint**
  (f4bcef7): three existing `login` tests in `tests/test_cli.py` now pass `--no-verify`, so
  they do not depend on the status check (they send no request). The new `redact_userinfo` removes the
  `user:password@` part from the url in the check error (and in the reason text) and in the line
  `server <base-url>: ...` that `login` prints, so the password from the url does not reach stderr or
  the JSON error; the url is still saved as entered. A 3xx response on the check now gives the message
  "redirects are not followed" with a suggestion to use the final url as the base url (for example https),
  or `--no-verify`; other failures keep the earlier hint. Changed files:
  `cli/src/sandfort_cli/sandboxes.py`, `tests/test_cli.py`, `tests/test_cli_r44.py` (two new
  tests).

#### Round 43 (after tag `v0.1.0-beta.42`)
All items were committed to main after commit `626bfa9` (round 42), in commit order:
SDK start parity, CLI and SDK addition, infrastructure (retirement of the auxiliary domain) and documentation.
Each is derived from the diff of the named commit. There is no spec regeneration in this round.
- **SDK: `AsyncClient.start` gets `wait`, `wait_timeout_s` and `poll_interval_s` like `Client.start`,
  and an unusable timeout is rejected before the request** (1e65710): `await client.start(sandbox_id, wait=True,
  wait_timeout_s=...)` blocks until the sandbox reports `started`, with the same single timeout as in the synchronous
  client. With `wait=True`, a `wait_timeout_s` that is not a finite number greater than 0 raises `ValueError`
  before any request, in both `start` and `create_sandbox` (sync and async); without `wait` the timeout is not
  checked or used. A start request that exceeds the timeout raises `SandboxTimeoutError` with
  `sandbox_id` and `state` `None` (the start may complete on the server); a wait that times out carries
  the last seen state. Behavior change: a wait timeout of 0 or less (or a number that is not finite)
  on `create_sandbox` and `start` now raises `ValueError` before any request, whereas 0 and negative
  values previously came out as a false timeout after the POST. Changed files:
  `sdk/python/src/sandfort_sdk/` (`client.py`, `async_client.py`, `handles.py` with the shared
  timeout check `check_wait_budget`), test `tests/test_sdk_r43_start_parity.py` (new).
- **CLI and SDK: finite `--wait-timeout` and the `status` option on the key list** (42b2fb8): the CLI rejects
  a `--wait-timeout` that is not a finite number greater than 0 (usage error). `Client.list_api_keys` and
  `AsyncClient.list_api_keys` accept `status` (`"active"` or `"revoked"`) and send it to the server as
  a filter; any other value raises `ValueError` before the request, and without `status` no query is sent.
  `sandfort key list --status active|revoked` requests a subset from the server and replaces the default
  hiding of revoked keys (`--all` remains). An invalid value is a usage error. Changed
  files: `sdk/python/src/sandfort_sdk/` (`client.py`, `async_client.py`),
  `cli/src/sandfort_cli/` (`keys.py`, `sandboxes.py`), test `tests/test_cli_r43.py` (new).
- **Infrastructure: the auxiliary domain `*.sandfort.lokalasistent.com` was retired** (no commit in
  the repository; owner's decision): the hosts are no longer served. The beta is served only on `sandfort.dev`
  (`api.sandfort.dev`, `docs.sandfort.dev`, `sandfort.dev`, `*.preview.sandfort.dev`). The domain was
  auxiliary; the invite-only beta and all partners already use `sandfort.dev`. The 30-day notice period from round
  42 thereby ceased to apply. Documentation from this round names only `sandfort.dev`; earlier items
  of this file remain as history.
- **SDK: `Sandbox.start` and `AsyncSandbox.start` (handle) pass `wait` through** (78f60ac): a fix
  after review. `sbx.start(wait=True, wait_timeout_s=..., poll_interval_s=...)` passes
  the arguments to `Client.start` (or `AsyncClient.start`) through the handle's transport, so the same
  single timeout, the same `SandboxTimeoutError` and `SandboxFailedError`, and the same `ValueError` for an unusable
  timeout before the request apply; without `wait` the handle sends a single start request as before, and `info` is replaced
  with the response. Four timeout-check tests were adapted to use a real timeout instead of a
  replaced one. Changed files: `sdk/python/src/sandfort_sdk/sandbox.py`, tests
  `tests/test_sdk.py` (modified), `tests/test_sdk_r43_start_parity.py` (extended).
- **Documentation: only `sandfort.dev`, recovery after `sandbox_stopped`, repeated query parameter and key
  list** (5402c8d, additions in 0c40778): documentation only, no code changes.
  - `docs/beta-terms.md` and `marketing/pilot/beta-connect-guide.md`: transitional sentences about the old
    hosts and the 30-day notice for them were replaced with a single sentence that the beta is served only on
    `sandfort.dev`. The terms keep the general commitment that an endpoint change gets at least 30 days'
    notice via status notices and the support address.
  - Guide, section "Recovering after `sandbox_stopped`": a one-line restart
    `client.start(sandbox_id, wait=True, wait_timeout_s=...)` (the same on `AsyncClient`); a start that
    exceeds the timeout raises `SandboxTimeoutError`, and when the request itself times out, `state` is `None` and the start
    may complete on the server, so `get()` is checked if certainty is needed. (The original
    sentence that `Sandbox.start()` (handle) does not accept `wait` was replaced in 0c40778 with a description of the pass-through
    introduced by 78f60ac.) Alongside `sandbox start --wait` it is stated that on the
    hosted beta the start response is already `started`, so `--wait` is a safeguard for slower backends.
  - Guide: a repeated declared query parameter (e.g. `status` twice) is not an error, the last
    value applies; the unfiltered key list has no pagination and grows with revoked keys, so
    scripts should use `status=active`; SDK `list_api_keys(status=...)` and
    `sandfort key list --status` replace the claim that the SDK does not filter.

#### Round 42 (after tag `v0.1.0-beta.41`)
All items were committed to main after commit `c211ba4` (round 41), in commit order:
CLI `sandbox start --wait`, `status` filter on the API key list, spec regeneration,
documentation, a `start --wait` fix after review, and guide documentation. Each is derived from the diff of the named commit.
- **CLI: `sandfort sandbox start` gets `--wait` and `--wait-timeout` like `sandbox create`**
  (e13cdf7): with `--wait` the command, after the start request, waits for the sandbox to reach `started`, and
  `--wait-timeout` (seconds, must be > 0, default as in the SDK) limits the wait; one
  deadline, computed just before the start request, applies to both steps. Without `--wait` the behavior is unchanged.
  The description of the `--wait-timeout` option is extracted into a shared constant used by both `create` and `start`.
  Changed files: `cli/src/sandfort_cli/sandboxes.py`, test `tests/test_cli_r42.py` (new).
- **API: the API key list accepts a `status` filter (`active` or `revoked`)** (f559920):
  `GET /v1/api-keys?status=active` returns keys that are neither revoked nor expired, and
  `status=revoked` only revoked ones; without the parameter all keys are returned, including revoked and
  expired ones. Any other value gives 422. Filtering is done on the same `status` field carried by
  each response row, at the same moment. Changed files: `src/sandfort/api/routes/api_keys.py`,
  test `tests/test_api_keys.py`.
- **OpenAPI: spec regenerated after the `status` filter** (0801d3c): `openapi/sandfort.v1.json` gets
  a `status` query option on `GET /v1/api-keys`, an operation description, and a 422 response. The number of HTTP operations
  does not change.
- **Documentation: `sandfort --json version`, transition from old hosts, and the key recipe**
  (7c92bc3): documentation only, no code changes.
  - `marketing/pilot/beta-connect-guide.md`: alongside the installation check, the command
    `sandfort version` is described (CLI and SDK build, no network call); the JSON form is
    `sandfort --json version`, because the global flag goes before the subcommand, and
    `sandfort version --json` is a usage error. The JSON carries the full commit, the text line the first 12
    characters.
  - `docs/beta-terms.md` and `marketing/pilot/beta-connect-guide.md`: the transition sentence about the old
    hosts `*.sandfort.lokalasistent.com` is extended: both names serve the same organization, keys
    and audit log (one backend behind two names), and the old hosts get at least 30 days of
    notice through the status notice and the support address before being retired.
  - `docs/operations.md` (new key recipe): the call to list keys uses
    `?status=active`, and the instruction for `OLD_KEY_ID` stays on matching `name`/`prefix`, with
    "the active list" instead of the condition "status is not `revoked`".
  - `CHANGELOG.md`: the rule on round headings no longer requires renaming after the tag; corrected
    the description of round 41 (`sandfort --json version`).
- **CLI and SDK: `start --wait` uses the public SDK wait, and the deadline also covers the POST itself** (fc4c2b0,
  fix after review of commit e13cdf7): `Client.start(sandbox_id, wait=False,
  wait_timeout_s=None, poll_interval_s=...)` with `wait=True` blocks until the sandbox reports
  `started`; one deadline, computed just before the POST, limits the whole call. A timeout of the start request
  raises `SandboxTimeoutError` with the sandbox name (the start may complete on the server), and a sandbox
  that ends in `error` raises `SandboxFailedError` and is preserved. Without `wait` a single
  request is sent as before. CLI `_start` calls this method instead of the private `_wait_started` and `_fetch`.
  Changed files: `sdk/python/src/sandfort_sdk/client.py`, `cli/src/sandfort_cli/sandboxes.py`,
  tests `tests/test_sdk_r42_start_wait.py` (new) and `tests/test_cli_r42.py`.
- **Documentation: the partner guide teaches `sandbox start --wait` and the `status` filter on the key list**
  (626bfa9): documentation only, no code changes.
  `marketing/pilot/beta-connect-guide.md`: in the CLI section, the `sandbox start` description lists `--wait`
  and `--wait-timeout SECONDS` as in `create` (one deadline for the request and the wait; without `--wait` the command
  returns immediately) and an example; the section on key management states that
  `GET /v1/api-keys?status=active` (or `revoked`) filters the list and that any other value gives 422.

#### Round 41 (after tag `v0.1.0-beta.40`)
All items were committed to main after tag `v0.1.0-beta.40` (`94d4dc3`), in commit order:
documentation about the domain, the new CLI command `version` and its fix after review. Each is
derived from the diff of the named commit. The heading stays in the form "after tag" even when the tag of the round
is shipped.
- **Documentation: the hosted beta moved to the `sandfort.dev` domain** (ed9bc2f): documentation
  only, no code changes. An infrastructure change, not a product change: the API now answers at
  `https://api.sandfort.dev`, the documentation site at `https://docs.sandfort.dev`, the product site
  at `https://sandfort.dev`, and the sandbox preview URL addresses at
  `https://<port>-<sandbox-id>.preview.sandfort.dev`. The old hosts `*.sandfort.lokalasistent.com`
  run in parallel until further notice, so existing configurations keep working; new settings
  must use `sandfort.dev`. The addresses were replaced in `docs/beta-terms.md`,
  `docs/operations.md` (example `SANDFORT_URL`), `marketing/pilot/beta-connect-guide.md`,
  `sdk/typescript/README.md` and `media/presentations/pitch-deck-web.html`.
  - `docs/beta-terms.md` and `marketing/pilot/beta-connect-guide.md`: one transition sentence at
    the place where the base URL of the API is first introduced.
  - `marketing/pilot/beta-connect-guide.md`: the installation guide says that
    `sandfort_sdk.build_info()` prints the commit and tag of the wheel and that the one-line check comes down
    to comparing `build_info().commit` with `client.status().build_sha`; every beta wheel carries
    version `0.1.0`, so upgrading an existing venv requires `pip install --force-reinstall` (or
    a new venv), and `pip list` does not distinguish builds, while `build_info()` does.
- **CLI: the new `sandfort version` command prints the build identity of the CLI and SDK** (ff9a3c5):
  for each component (`cli`, `sdk`) a line is printed with the component name, the version from the metadata
  of the installed package (`unknown` when the metadata does not exist), and the commit and tag when the wheel carries
  the build resource; when the commit and tag are `None`, `unknown` and `untagged` are printed. The third line
  points to `GET /v1/status` (`build_sha`) for the server identity. When called as `sandfort --json version`
  (the global flag goes before the subcommand; `sandfort version --json` is a usage error)
  the command prints one object with the keys `cli` and `sdk`. The command makes no network call. The CLI package
  gets its own `build_info` module modeled on the SDK pattern from round 40: it reads the optional package
  resource `_build_info.json`, and the CLI wheel ships it when the release tool writes it (from
  `v0.1.0-beta.41`); the source checkout has no such resource. Changed files:
  `cli/src/sandfort_cli/build_info.py` (new), `cli/src/sandfort_cli/main.py`,
  `cli/pyproject.toml` (`artifacts` for the resource), test `tests/test_cli_version_r41.py` (new).
- **CLI: `sandfort version` also works with an SDK without `build_info`, with two tightened tests**
  (689be80): the dependency of the CLI on the SDK is not tied to a version, so an older
  SDK wheel without `sandfort_sdk.build_info` may be installed next to the CLI. In that case the command now
  reports all build fields for `sdk` as `None` (`unknown`, `untagged`) instead of failing;
  the SDK version is still read from the package metadata. Tests: the help check requires exactly one
  `version` line with the command description (previously it was enough for the word to appear anywhere in the output), and
  the exception in the missing-metadata test uses `importlib.metadata.PackageNotFoundError`
  instead of a re-export from the module; the new test `test_old_sdk_without_build_info_still_prints_version`
  covers plain and `--json` output. Changed files: `cli/src/sandfort_cli/main.py`,
  `tests/test_cli_version_r41.py`.

#### Round 40 (in the deployed tag `v0.1.0-beta.40`)
All items were committed to main after tag `v0.1.0-beta.39` (`0995a15`), and are part of build
`v0.1.0-beta.40` (`94d4dc3`, deployed 2026-11-09 10:00 UTC). Each is derived from the diff of
the named commit. Commits after `94d4dc3` are not in that tag (see round 41).
- **SDK: `sandfort_sdk.build_info()` returns the commit, tag and build time of the wheel** (f62f767): the new
  module `sdk/python/src/sandfort_sdk/build_info.py` reads the optional package resource
  `_build_info.json` that the release tool writes into the package directory immediately before building
  the wheel and removes after it. `build_info()` returns `BuildInfo(commit, tag, built_at)`; all three
  fields are `None` for a source checkout without that file, when the file is not readable or is not
  valid JSON, and for a key that is missing or is not a string. `build_info` and `BuildInfo` are
  exported from `sandfort_sdk`. `sdk/python/pyproject.toml` gets three lines; test
  `tests/test_sdk_build_info_r40.py`. The wheel from tag `v0.1.0-beta.40` is the first to carry this
  capability.
- **Documentation: comparison from wheels only, `build_info()`, create-key DELETE through a header file
  and mounting of the status notice** (46f52d9): documentation only,
  no code changes.
  - `docs/beta-terms.md` (section 5): a partner without a repository checkout compares `build_sha`
    from `GET /v1/status` with the commit from the release note `RELEASE.txt` shipped with the wheels
    (the instructions with `git rev-parse <tag>^{commit}` remain for readers with a checkout); from
    `v0.1.0-beta.40` the SDK itself reports the build through `sandfort_sdk.build_info()`.
  - `docs/operations.md`, create-key: the `DELETE` example uses `-H @header.txt` instead of
    `$(cat new.key)` in argv, in line with its own warning; the instruction for `OLD_KEY_ID` also requires
    that the `status` of the key is different from `revoked` (the key list includes revoked keys,
    multiple rows may have the same name, and deleting an already revoked key is 200 with no effect and
    leaves the real old key active).
  - `docs/operations.md`, status notice: the bind mount is a DIRECTORY
    `/home/sandfort/sandfort-notice` mounted read-only at `/etc/sandfort/notice`, so
    replacing a file inside it (editor, `sed -i`) is safe and the container sees the new inode; added
    idioms for writing (`echo`) and deleting (`:`); the generic example path aligned with
    the documented path in the container.

#### Round 39 (in the deployed tag `v0.1.0-beta.39`)
All items were committed to main after tag `v0.1.0-beta.38` (`3e87c6e`), and are part of build
`v0.1.0-beta.39` (`0995a15`, deployed 2026-11-09 09:22 UTC). Each is derived from the diff of
the named commit. Commits after `0995a15` are not in that tag (see round 40).
- **Cell execution stream: stderr from the first of two driver lines is held back, so
  the final sentence decides every outcome** (efcc597): on a streamed cell run, stderr is
  sent as it arrives up to the first of two lines that the run may rephrase: the line about
  the death of the sandbox and the sentence about the driver execution deadline ("the command was stopped after ...",
  with the seconds of the execution deadline and advice to allow more time). From that line on, stderr is
  held back, and the sentence from the final response arrives as the last stderr chunk, immediately before
  the `result` event. Therefore the streamed stderr equals the `stderr` of the result both in the outcome
  `context_lost` (hard kill, the kernel ignored the interrupt) and in the outcome of an interrupted context
  that is retained; a consumer that reads only chunks no longer sees the wrong sentence "allow more
  time" with the seconds of the execution deadline instead of the cell limit. Change to code and tests
  (`src/sandfort/toolbox/code_context_stream.py`; tests `tests/test_code_context_stream_r34.py`,
  `tests/test_named_contexts_r35.py`).
- **Documentation: no document names the current tag anymore; exit code 137 without
  a stop, redaction of its own digest, the location of the notice on the beta VM, and create-key**
  (449336d): documentation only, no code changes.
  - `docs/beta-terms.md` (section 5) and the header of this file: the sentences "current tag" and
    "previous tag" were deleted. A file inside the tagged commit cannot name its own tag, so
    each such sentence lagged one deployment behind (the same defect three rounds in a row).
    The rule that replaces them: the deployed build is read from `build_sha` in `GET /v1/status`, must
    equal the commit of the latest tag `v0.1.0-beta.<runda>` (an annotated tag is reduced with
    `^{commit}`), and `RELEASE.txt` in the delivery names the same tag and commit. The heading of round 38 now
    states the tag in which it was shipped (`v0.1.0-beta.38`, `3e87c6e`, deployed 2026-11-09 08:21 UTC).
  - `marketing/pilot/beta-connect-guide.md`: row 137 in the `exec` exit code table also covers
    killing of the process itself (`sandbox_stopped: false`, `stop_reason` `killed`), not only
    stopping of the sandbox; the paragraph on build log redaction states an exception to "your lines remain
    unchanged": `sha256:<64 hex>` from your own line (for example a pinned digest in the value of
    `ENV`) is replaced for keys with a label scope, except when it follows `=` or a word character.
  - `docs/operations.md`: status notice on the compose VM (the file
    `/home/sandfort/sandfort-notice/notice.txt` on the VM, mounted read-only into the `api`
    container at `/etc/sandfort/notice/notice.txt`, `SANDFORT_STATUS_NOTICE_FILE` in the beta compose
    overlay, which is an operator tool outside the repository; the production compose file deliberately has
    no such wiring); create-key: choosing `OLD_KEY_ID`, the definition of `SANDFORT_URL` and a warning that
    `$(cat new.key)` in argv is briefly visible in the process list on a shared host; the runbook heading
    no longer says "(Kubernetes)" because the document covers compose as well (`docs/beta-terms.md`,
    `marketing/pilot/beta-connect-guide.md`, `docs/operations.md`, `CHANGELOG.md`).

#### Round 38 (in the deployed tag `v0.1.0-beta.38`)
All items were committed to main after tag `v0.1.0-beta.37` (`e06722e`), and are part of build
`v0.1.0-beta.38` (`3e87c6e`, deployed 2026-11-09 08:21 UTC). Each is derived from the diff of
the named commit. Commits after `3e87c6e` are not in that tag (see round 39).
- **CI: Typer help stays plain text under `GITHUB_ACTIONS`, so the unit job is green again**
  (19bbefb): GitHub Actions sets `GITHUB_ACTIONS` (some runners also `FORCE_COLOR` or
  `PY_COLORS`), so `typer.rich_utils` turns on `FORCE_TERMINAL` and every `--help` and every usage error
  is drawn with ANSI codes and boxes. CLI tests check the plain text that a user without
  a tty sees. The shared pytest configuration module gets an `autouse` fixture with
  session scope that turns off `FORCE_TERMINAL` in `typer.rich_utils`. Tests only, no change to
  product code (`tests/conftest.py`).
- **CLI `exec`: the hint about a stopped sandbox starts on its own line when the remote stderr
  has no trailing newline** (5f12624): the sentence about the stop arrives without `\n` at the end, so
  the line "sandfort: the sandbox has stopped; start it again with: sandfort sandbox start <id>"
  was glued onto it. Now the CLI in text mode first closes the open stderr line, then
  prints the hint; stderr that already ends with a newline does not get an empty line, and when
  the timeout and the stop happen at the same time, the line is closed only once. With `--json` the output is
  unchanged. The exit code stays 137 (code 124 changes the exit code only when the command timed out and
  its remote exit code is 0; otherwise the remote code is passed through) (`cli/src/sandfort_cli/exec_cmd.py`;
  test `tests/test_cli.py`).
- **Build log for a key with a label scope: redaction also applies to "Removed intermediate container
  <12 hex>"** (fdb5abd): the live classic builder prints the past tense (" ---> Removed intermediate
  container <id>"), and the redaction from 225eae1 covered only "Removing". Now the 12 hexadecimal
  characters after both forms are replaced with the text "the built image", in log lines and in the `reason`
  of the final `state` event, regardless of letter case. A key without a label scope sees the lines
  unchanged, and hexadecimal text outside the anchors stays unchanged. The route description in the code lists
  both forms (`src/sandfort/api/routes/image_builds.py`; test
  `tests/test_image_build_scope_r35.py`).
- **OpenAPI: spec regenerated after the redaction description change** (3e1b457): mechanical regeneration,
  one line. The description of the route `GET /v1/images/builds/{snapshot_id}/logs` now lists "Removing
  intermediate container" and "Removed intermediate container" (`openapi/sandfort.v1.json`).
- **A streamed cell interrupted by delete or reset sends its "gone" line as the last
  stderr part, so the streamed stderr equals `result.stderr` in every ending** (d05c512):
  previously the leftover part of stderr was sent only when the channel had held the driver's death line. A delete
  or reset whose container disappeared without that line, as well as the sentence added by a timeout, did not
  reach the stream. Now, before the `result` event, the whole remaining part of stderr from the final
  response is sent. When the final stderr does not begin with the already sent text, nothing is sent (`result`
  carries the whole stderr) and a warning is logged. The helper function `_send_held` was renamed to
  `_send_stderr_tail` (`src/sandfort/toolbox/code_context_stream.py`; test
  `tests/test_named_contexts_r35.py`).
- **Documentation: stop reasons in the runbook, a notice step during upgrade,
  key handover in create-key, the 422 exception in the audit, and advice about a pool of sandboxes in the SDK**
  (3d89ec2): documentation only, no code changes.
  - `docs/operations.md`: the `sandbox_stopped` row in the reasons table covers a stop (by the caller
    or auto-stop) and death (resource limit or end of the main process); the new table "Sandbox stopped
    or died" distinguishes the two cases by the sentence in stderr, by the sandbox row (`error_code` is
    `null` after a stop, `container_exited` after death) and by the audit log (`sandbox.stop` for
    the key that stopped it, or `sandbox.drift_detected` with outcome `error`); a streamed
    cell interrupted by a stop ends with a plain `result` event, and `error` is reserved
    for driver errors. The deploy notice (waiting at least two minutes) is the first step
    of the upgrade, with a note that the notice automation lives outside the repository. `kubectl`
    commands apply to Kubernetes; the hosted beta runs under docker compose. For create-key,
    revoking the old key through the API with the new key was added (the admin CLI has no command for
    revocation), deleting the key file after handover, and the reverse order when the old key has leaked.
  - `docs/governance.md`: a 422 for a request body that is not valid JSON does not write a
    `request.denied` row (the body is rejected before the key is resolved); every other 422 after
    a valid key writes it.
  - `sdk/python/README.md`: parallel cells on a single sandbox share one kernel host, so for
    parallel work a pool of sandboxes should be used (`docs/operations.md`, `docs/governance.md`,
    `sdk/python/README.md`).
- **Documentation: pointers to the deployed `v0.1.0-beta.37`, the `exec` exit code table,
  builds across the scope boundary, and wording on redaction** (59de84c): documentation only, no change
  to code.
  - `CHANGELOG.md`: the header lists `v0.1.0-beta.37` (`e06722e`, deployed 2026-11-09 06:52 UTC)
    and says that the deployed build is read from `build_sha` in `GET /v1/status`; this round is separate
    from round 37, and the 225eae1 item notes that the "Removed" form was added only in fdb5abd.
  - `docs/beta-terms.md`: audit events on the beta are not deleted by retention (the setting is not
    set); they remain until the organization's data is deleted; build logs show the build steps,
    including `ENV` values, to every key of the organization, so an image spec must not carry
    secrets; section 5 lists `v0.1.0-beta.37` and `build_sha`, and names the release note `RELEASE.txt`.
  - `marketing/pilot/beta-connect-guide.md`: the `exec` exit code table gets row 137
    (a stop, auto-stop or limit interrupts the command; `sandbox_stopped: true`) and a more precise
    row 125, with a note that `cp` uses the same convention; a description of the hint about a stopped
    sandbox, the difference between a stop and death by `stop_reason`, a build by a key with a label scope
    (build names, logs and jobs are visible to all keys of the organization; the same specification
    returns someone else's build with `reused: true`), the "Removed intermediate container" form, equality
    of streamed stderr and `result.stderr`, auto-stop that does not wait for a command or cell, and the
    422 exception in the audit. The notes "arrives with the next beta tag" for round 37 items were removed because they are
    in beta.37 (`docs/beta-terms.md`, `marketing/pilot/beta-connect-guide.md`, `CHANGELOG.md`).
  - Fixes after the review of round 38 (documentation only): the guide (section 1) and the round 37 item
    now say that the release note is the file `RELEASE.txt`, which on beta.37 lists the commit and build time,
    and from `v0.1.0-beta.38` also the tag (as `docs/beta-terms.md`, section 5); in the item for
    5f12624 code 124 changes the exit code only when the command timed out and its remote exit code is 0,
    and otherwise the remote code is passed through (`cli/src/sandfort_cli/exec_cmd.py`, `CHANGELOG.md`,
    `marketing/pilot/beta-connect-guide.md`).

#### Round 37: actor in `sandbox.failed`, stop wording, cursor, SDK and CLI (in the deployed tag `v0.1.0-beta.37`)
All items were committed to main after the tag `v0.1.0-beta.36` (`41af222`), and are part of the build
`v0.1.0-beta.37` (`e06722e`, deployed 2026-11-09 06:52 UTC). Each one is derived from the diff of
the named commit. The exported `openapi/sandfort.v1.json` was regenerated in bb33b54 (description of the
stop reason).
- **Audit: `sandbox.failed` carries the actor that requested the operation; `sandbox.drift_detected` rows
  have the outcome `error`**: in the inline (job-less) flow the failure path did not receive an actor, so the row
  was written as `system`. Now the actor is read from the latest audit row `sandbox.create` or
  `sandbox.start` of the same sandbox (that row is written in the transaction of the request itself); without such a row
  the actor is still `system`. The `sandbox.drift_detected` rows written by the reconciler now have the
  outcome `error` (978ea62, `src/sandfort/services/sandbox_jobs.py`,
  `src/sandfort/workers/reconciler.py`; test `tests/test_sandbox_failed_audit_r36.py`).
- **A stopped sandbox is reported as stopped on `exec`, `code_run` and `run_stream`**:
  when the caller or auto-stop stops the sandbox while a command or cell is running, the response has
  `stop_reason` `sandbox_stopped`, and stderr no longer carries the sentence about death under a resource limit.
  For `exec` and `code_run` the sentence is "the sandbox was stopped while the command was running;
  start it again"; for a cell of a named context (run and run_stream) "the sandbox was stopped
  while the cell was running; the context is gone, create or ensure a new one". Death under a limit
  keeps its sentence about the resource limit, and delete and reset still take precedence
  (`sandbox_deleted`, `sandbox_reset`). A stop on request is not "reconciled" and does not trigger the
  reconciler. The description of the `sandbox_stopped` reason in OpenAPI was updated: the sandbox was stopped
  (caller or auto-stop) or died (resource limit or the main process exited); stderr
  says which (2bd92d1, `src/sandfort/api/routes/toolbox/process.py`, `src/sandfort/api/openapi.py`,
  `src/sandfort/drivers/docker/exec.py`; tests `tests/test_exec_timeout_text_r36.py`,
  `tests/test_named_contexts_r35.py`). Streamed run: stderr is sent up to the driver's line about death,
  and the rest is sent as the final response words it, right before the `result`
  event, so the joined streamed stderr equals the stderr from `result`. A stop in the middle of a
  streamed run ends with a plain `result` event with `stop_reason` `sandbox_stopped`,
  not an `error` event, so the SDK raises nothing. This changes the item "Named contexts: stop in the middle
  of a cell" from round 36, which listed an `error` event for the streamed run. The `error` event remains
  for server errors; a driver error that the run could not turn into a result is still sent as an
  `error` event.
- **An invalid or empty `cursor` returns 422**: instead of 400, a `cursor` that cannot be decoded or
  is empty is answered with 422 with the code `VALIDATION_ERROR`, the message "invalid cursor: query.cursor" and
  one `details.errors` entry (`type` `value_error`, `loc` `["query", "cursor"]`, `msg`
  "invalid cursor") (909f4a2, `src/sandfort/api/pagination.py`; tests
  `tests/test_unknown_query_params_r36.py`, `tests/test_api_sandboxes.py`).
- **The ReDoc logo host is allowed only on `/redoc`**: `/docs` has `img-src 'self' data:` without a
  remote source, and `/redoc` has the same set plus `https://cdn.redoc.ly`. Previously (bfdd08d) both
  pages allowed that host (909f4a2, `src/sandfort/api/security_headers.py`,
  `src/sandfort/api/docs_pages.py`; tests `tests/test_security_headers_r31.py`,
  `tests/test_docs_pages_r33.py`).
- **Build log lines do not carry the snapshot tag or the image id for keys with a label scope**: in the stream
  `GET /v1/images/builds/{snapshot_id}/logs` each line for such a caller replaces
  `sandfort-snapshot:<tag>` and every run of 12 or more hexadecimal characters with the text "the built
  image". A key without a label scope sees the lines unchanged (ad49300,
  `src/sandfort/api/routes/image_builds.py`; test `tests/test_image_build_scope_r35.py`). The rule
  "every run of 12 or more hexadecimal characters" was replaced by a narrower one in d35b63f (see below).
- **SDK: the streamed result keeps `stop_reason` and `timed_out` from the `result` event**: the last
  `CellResult` from `run_stream` (sync and async) carries `stop_reason`, `timed_out` and `sandbox_stopped`
  as the result of `run`; a stop gives `"sandbox_stopped"`, a normal end `None`. The commit
  adds tests and a description in `sdk/python/README.md` (03fb37f, `tests/test_sdk_r37.py`).
- **SDK: `SandboxFailedError` and `SandboxDestroyedError` can be pickled and copied**: `__init__` has
  only keyword arguments, so the default reconstruction did not work. `__reduce__` returns the
  exception by state, with all attributes; this also applies to subclasses (cfa473c,
  `sdk/python/src/sandfort_sdk/exceptions.py`; test `tests/test_sdk_r37.py`).
- **SDK and CLI: request id with every displayed error** (a982b57):
  - `str(ApiError)` is the `message` with the suffix " (request id <id>)" when `request_id` is set;
    `str(SandboxFailedError)` is the message, then the code in square brackets, then the same suffix; the id is
    stated once, even when the caller already added it to `message`.
  - The `Sandbox` handle (sync and async) has a read-only property `request_id`: the `x-request-id`
    of the create response when the handle was returned by `create_sandbox`; `None` for a handle from `get`,
    `list_sandboxes` or an action, or when the response did not have that header.
  - A create whose response is already in the `error` state raises `SandboxFailedError` with the `request_id`
    of the create response (sync and async, with and without deletion after failure). CLI `sandbox create` without
    `--wait` whose response is in the `error` state passes `Sandbox.request_id` to the same error.
  - CLI: the text error line for an API error and `SandboxFailedError` ends with the request id,
    once; `sandbox create` no longer adds the id to `message` (the helper function `mention_request_id` was
    removed in 65e2c7d). With `--json`, `error.request_id` is the exception's id (`null` when it has none), and
    `error.source` is `"client"` for an error that was never sent to the server (the meaning was tightened in
    65e2c7d, see below). Previously `request_id` for errors that are not `ApiError` was always `null`
    (`cli/src/sandfort_cli/output.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `sdk/python/src/sandfort_sdk/`; tests `tests/test_cli_r37.py`, `tests/test_sdk_r37.py`).

- **Named context: the stop wording is chosen from the sandbox row, so an OOM-killed container
  is no longer "stopped"** (d35b63f): `run` and `run_stream` cells previously appended the stop sentence for every container
  that was no longer running. Now the module `toolbox/code_contexts.py`
  leaves a container that is not running with the driver's line about death (a resource limit was exceeded or
  the main process exited), and the route reads the sandbox row: the sentence "the sandbox was stopped while
  the cell was running; the context is gone, create or ensure a new one" is given only to a stop
  requested by the caller or auto-stop (a row without `error_code`). Every other death, including a
  container killed because of memory (OOM), keeps the driver's line about the limit, and a vanished container
  keeps its sentence "the sandbox container is gone". `stop_reason`, exit 137 and `sandbox_stopped`
  stay the same; only the sentence in stderr changes. The same applies to the streamed run (the same
  sentence goes before the `result` event) (`src/sandfort/api/routes/toolbox/process.py`,
  `src/sandfort/api/routes/toolbox/code_contexts.py`, `src/sandfort/toolbox/code_contexts.py`;
  tests `tests/test_named_contexts_r35.py`).
- **Build log for a key with a label scope: the replacement touches only the builder's own lines and the final
  reason** (d35b63f): in the stream `GET /v1/images/builds/{snapshot_id}/logs` the replacement with the text "the built
  image" is applied only to the forms the builder itself prints: the internal tag `sandfort-snapshot:<id>`, the id
  after "Successfully built", the digest `sha256:<64 hexadecimal characters>` (any letter case,
  not when it follows `=` or a letter or digit) and the image name after "writing image". The same replacement applies to
  `reason` in the final `state` event, whose `digest` is still `null`. Output that belongs to the
  tenant, for example git SHA values or `--hash=sha256:...` in pip output, stays unchanged
  (previously every run of 12 or more hexadecimal characters was affected). A key without a label
  scope sees everything unchanged. The route description in the code states the same (`src/sandfort/api/routes/image_builds.py`;
  test `tests/test_image_build_scope_r35.py`).
- **CLI: `"source": "client"` means that no request reached the server; transport errors
  carry the request id in the text; an unused helper function was removed** (65e2c7d):
  - `error.source` is `"client"` when no request of that step reached the server: a failed
    connect (`TransportError` caused by `httpx.ConnectError`), a timeout before sending, an ambiguous local
    sandbox name (`AmbiguousSandboxName`, decided locally) and a CLI error for wrong input.
    The ambiguous name was excluded from "client" in df85b1e (see below): the name is looked up in the list response, so
    the request reached the server.
    A CLI error behind which stands an SDK error that reached the server (for example `NotFound` when the name
    is not in the list response) no longer has `"client"`. Without `"source"` the request may have reached the server.
    The description was added to the help of the `sandfort sandbox` group.
  - The text error line for every exception that has a `request_id`, including transport
    errors, ends with "(request id <id>)", once.
  - The helper function `mention_request_id` and its test were removed; `sandbox create` has not
    called it since a982b57 (`cli/src/sandfort_cli/output.py`, `cli/src/sandfort_cli/sandboxes.py`;
    tests `tests/test_cli_r37.py`, `tests/test_sdk_r36.py`).
- **Build log for a key with a label scope: the replacement also applies to the ids of the classic builder itself**
  (225eae1): in addition to the forms from d35b63f, a caller with a label scope now gets, instead of 12 hexadecimal
  characters, the same text "the built image" on the lines " ---> <12 hex>", "Running in <12 hex>"
  and "Removing/Removed intermediate container <12 hex>" (the step id, the id of the step's container and the id of the same
  container on removal; the form "Removed" was added only in fdb5abd, round 38). The replacement applies to log lines and to the `reason` of the final `state` event.
  Hexadecimal text of other forms stays unchanged (a bare hexadecimal id, git SHA,
  `--hash=sha256:...` and `sha256=...` in step output). A key without a label scope sees the lines
  unchanged. The route description in OpenAPI states the same (`src/sandfort/api/routes/image_builds.py`;
  test `tests/test_image_build_scope_r35.py`).
- **A streamed cell run chooses the stop wording from the sandbox row even when the driver reports an error;
  a cell interrupted by delete or reset has a line that names the cell** (225eae1):
  - When a streamed run ends with a driver error that means the sandbox is no longer running, the `error`
    event chooses the message like the path with a result: a vanished container gets "the sandbox container
    is gone"; a container that is not running gets the stop sentence ("the sandbox was stopped
    while the cell was running; ...") only when the sandbox row shows a stop requested by the
    caller or auto-stop (a row without `error_code`); every other death keeps the driver's line
    about death. A row that is missing or cannot be read counts as having no such stop
    (the error is logged), so the driver's line stays. The code (409 conflict) and `stop_reason`
    `sandbox_stopped` stay the same; only `message` changes. Previously this `error` event for a
    container that is not running always carried the stop sentence.
  - A cell (`run` and `run_stream`) interrupted by delete or reset of the sandbox now gets a line
    that names the cell: "the sandbox was deleted while the cell was running", and "the sandbox
    was reset while the cell was running; the context is gone, create or ensure a new one", respectively.
    `stop_reason` (`sandbox_deleted`, `sandbox_reset`), exit 137 and `sandbox_stopped` stay the same.
    Previously the cell carried the command line ("... while running this command").
  - The line "the sandbox container is gone" appears once: when the cell result already carries it,
    the reason from the sandbox row does not add a second line
    (`src/sandfort/api/routes/toolbox/code_contexts.py`,
    `src/sandfort/api/routes/toolbox/process.py`, `src/sandfort/toolbox/code_context_stream.py`,
    `src/sandfort/toolbox/code_contexts.py`; test `tests/test_named_contexts_r35.py`).
- **CLI: `"source": "client"` only for input errors detected before any request of the step is sent;
  explanation in the help of the root and every command group** (df85b1e):
  - `CliError` has an explicit `client` flag; `error.source` is `"client"` when it is set
    (and no SDK error in the cause chain reached the server) or when the connect failed or the
    timeout was before sending. The flag is carried by: a wrong base URL, an empty key, "not logged in",
    an unreadable or invalid profile, stdin that is not valid UTF-8 for `exec`, a missing
    interactive terminal for `shell` (checked before the first request), and by the same rule invalid
    `--mount`, `--env` and `--label` pairs, `--expires-at`, `key create` arguments that the SDK rejects
    before sending, an unreadable or invalid spec file for build, and a local source or empty remote
    path for `cp` (now checked before opening the client).
  - A CLI error raised after a server response has no `"source"`: a build log without a final state,
    a build that the server reported as failed, a command without a reported result, an unpack
    that failed or timed out in the sandbox, an unsafe path in the archive. An ambiguous sandbox name
    also has no `"source"`, because it is found in the list response; this changes the item 65e2c7d above, where
    it was "client". If `shell` finds stdin replaced only after the earlier check, the requests are already
    sent, so that error has no `"source"`.
  - The explanation of the flag is in the help of the root command and every group (`sandbox`, `snapshot`, `volume`,
    `members`, `key`, `cmd`) and of the commands `login`, `preview`, `exec`, `cp`, `shell`; previously only in the group
    `sandfort sandbox` (`cli/src/sandfort_cli/output.py`, `cli/src/sandfort_cli/config.py`,
    `cli/src/sandfort_cli/exec_cmd.py`, `cli/src/sandfort_cli/shell_cmd.py`,
    `cli/src/sandfort_cli/main.py`, `cli/src/sandfort_cli/sandboxes.py`,
    `cli/src/sandfort_cli/cp_cmd.py`, `cli/src/sandfort_cli/keys.py`,
    `cli/src/sandfort_cli/snapshot.py`; tests `tests/test_cli_r37.py`, `tests/test_cli.py`,
    `tests/test_cli_cp_dir.py`, `tests/test_cli_phase3.py`, `tests/test_cli_r36.py`).
- **`cp`: the `"source": "client"` flag only on the check before the request that looks up the sandbox; streamed
  cell: lines for delete and reset also on the driver-error path; the anchors of build log redaction
  pinned by a test** (0345499):
  - `sandfort cp`: the check of the local source and of an empty remote path that runs before the request for
    looking up the sandbox (`check_upload`, `_copy`) still raises an error with the flag `"source": "client"`.
    The repeated checks after the sandbox lookup (`upload` for a single file and `_remote_dest` for a
    directory) raise the same message without the flag, because the requests have already been sent.
  - Streamed cell (`run_stream`): when the driver reports an error that means the sandbox is no longer running,
    the message of the `error` event is chosen from the sandbox row as in the result of a non-streamed cell. If the row
    shows delete or reset, the message is the line that names the cell ("the sandbox was deleted while
    the cell was running", and "the sandbox was reset while the cell was running; the context is
    gone, create or ensure a new one", respectively); the stop sentence only for a stop requested by the
    caller or auto-stop; in every other case (and when the row cannot be read) the
    driver's line about death stays. The code (409 conflict) and `stop_reason` `sandbox_stopped` stay the same;
    only `message` changes. Previously delete and reset on this path got the driver's line.
    `StopCheck` now returns the reason from the row (`sandbox_deleted`, `sandbox_reset`, `sandbox_stopped` or
    `None`) instead of `bool`, and `stream_run` takes a map of reasons to lines (`CELL_GONE_MESSAGES`).
  - The test of classic builder build log redaction pins all three anchors (`---> <id>`,
    `---> Running in <id>`, `Removing intermediate container <id>`): words of 12 hexadecimal
    characters outside the anchors stay unchanged, both the bare word and the same word in a `RUN echo` line of the step. There is
    no change to the redaction code
    (`cli/src/sandfort_cli/cp_cmd.py`, `cli/src/sandfort_cli/cp_dir.py`,
    `src/sandfort/api/routes/toolbox/code_contexts.py`,
    `src/sandfort/toolbox/code_context_stream.py`; tests `tests/test_cli_r37.py`,
    `tests/test_cli_cp_dir.py`, `tests/test_named_contexts_r35.py`,
    `tests/test_image_build_scope_r35.py`).

#### Support contact, precise beta terms and round 36 corrections (2026-11-08, documentation only)
Operator decisions of 2026-11-08, recorded as facts. No code changes. This entry supplements
the next one ("Hosted beta terms"), in which support is still listed as "the maintainer from the README".
- **Support**: the contact for design partners is `office@polygon.rs`; the target response time is the next
  business day (Monday–Friday, CET), best effort; the report includes the `request_id`. The address is in
  `docs/beta-terms.md` (section 3), in the guide (section 6 and the places that said "ask the
  maintainer") and in `README.md` ("Maintainer and support", without referring to the git log).
- **Data** (`docs/beta-terms.md`, section 4): nothing survives sandbox deletion, and for a
  stopped sandbox there is no guarantee that it can be started again after a host change; a stopped
  sandbox keeps its files and environment values until deleted. `auto_delete_minutes` defaults to
  "never" (`-1`), so it (and `auto_stop_minutes`) should be set on every sandbox you do not want to
  keep. Audit events are deleted together with the organization's data on request, so
  export them first (`GET /v1/audit-events/export`).
- **Releases** (`docs/beta-terms.md`, section 5): wheels ship with `SHA256SUMS` and a text
  release note `RELEASE.txt` that lists the commit and build time, and from `v0.1.0-beta.38` the tag
  (a correction in round 38, see the entry for 59de84c); verification:
  `shasum -a 256 -c SHA256SUMS`. The same is in the guide (section 1).
- **Guide** (`marketing/pilot/beta-connect-guide.md`): a create without `--wait` / with `wait=False` that
  ends in the `error` state still counts toward the key's `max_sandboxes` until it is deleted (with a description
  of the limitation); during a planned deploy the API is unavailable for less than a minute, and the SDK's back-off
  (about 1.5 s in total with the default 2 retries) does not cover it, so wait for the notice to disappear
  (`GET /v1/status`) or repeat the calls yourself for up to 60 s; auto-stop (`auto_stop_minutes`) is
  counted from the last toolbox request and fires even while a cell or command is running, so cells
  longer than the window are killed (`stop_reason` `sandbox_stopped`); routes without filters (get-by-id for
  snapshot, volume, job, webhook, session, command and PTY, snapshot export, build log stream)
  accept unknown query parameters, while lists and routes with filters respond with 422
  (`GET /v1/sandboxes/{id}` is among them); the `request_id` in the CLI's JSON error for a create without
  `--wait` is `null` (the CLI does not read the `x-request-id` of the create response).
- **Runbook** (`docs/operations.md`): the deploy notice steps include the two-minute wait that
  the deploy script performs (`NOTICE_LEAD_S`, default 120); the `create-key` section has a call on
  the VM (`docker compose ... exec -T api python -m sandfort.admin_cli create-key ...`), `umask 077`
  before redirection and `chmod 600`, a check of the new key before revoking the old one, and a note that the
  replacement key is org-wide (platform-admin only with `--platform-admin`).
- **Known issues** (`.context/known-issues.md`): the support rows are closed; three new active
  rows (in progress): `sandbox.failed` shows the actor as `system`, the stop text for a stopped
  sandbox on exec/code_run, and build log lines that name the snapshot tag for keys with
  `sandbox_labels`. The fixes are committed to main (978ea62, 2bd92d1, ad49300), but are not in
  the deployed tag `v0.1.0-beta.36`.

#### Hosted beta terms (2026-11-08, documentation only)
Operator decisions of 2026-11-08, recorded as facts in the new `docs/beta-terms.md` (six
sections). No code changes.
- **Price**: the hosted beta is free for the whole beta period; paid plans come after the beta, when
  the market is understood. Prices are not stated.
- **Availability**: no availability guarantee (one VM, one region), best effort. A planned
  deploy is announced through a status notice (`notice` in the `GET /v1/status` response) at least two
  minutes before the API restart; the restart takes less than a minute, running sandboxes keep
  running; the build is identified by `build_sha` in the same response.
- **Support**: the contact for design partners is the maintainer from `README.md` (new section "Maintainer
  and support"); the target response time is the next business day (Monday–Friday, CET), best effort;
  the report includes the `request_id` from the error response.
- **Data**: sandboxes are ephemeral; snapshots and volumes last until deleted; organization
  data is deleted on request within five business days; audit events are exported
  (`GET /v1/audit-events/export`) and the chain is verified (`GET /v1/audit-events/verify`).
- **Releases**: every deployed build carries a tag `v0.1.0-beta.<runda>` on the exact commit (as of 2026-11-08:
  `v0.1.0-beta.36` = `41af222`; the previous `v0.1.0-beta.35` = `0d66b53` stays in the history); the container image is not published, the API is built from the tagged commit
  (compose on the host); the SDK and CLI are shipped as wheels built from the same tag.
- **Isolation**: `gvisor` is the default beta tier (`SANDFORT_DEFAULT_ISOLATION=gvisor` in
  `deploy/node-setup.sh` and `deploy/k8s/configmap.yaml`); the `microvm` tier (Kata Containers) exists
  for evaluation. The Firecracker driver is still a skeleton and is not a tier (`docs/isolation-tiers.md`).
- `marketing/pilot/beta-connect-guide.md`: a "Beta terms" row at the top; section 6, instead of "Contact the
  maintainer directly", gives the response target and a link; the "Beta limits" and "Status and
  incidents" sections are aligned (announcement at least two minutes before the restart). `README.md`: section "Maintainer
  and support".

#### Round 36: create-key, sandbox.failed, strict query parameters, SDK and CLI
Each entry is derived from the code and commits of round 36 (after docs commit 0d66b53). The exported
`openapi/sandfort.v1.json` was regenerated in 6d250a6 (descriptions and `null` for the `image_ref` and `digest` of the
snapshot). The `create-key` entry previously stood under round 35; the commit is from round 36.
- **Admin CLI: `create-key` issues a new org-wide key for an existing organization**:
  `python -m sandfort.admin_cli create-key --org-slug <slug>` (or `--org-id`, exactly one of
  the two; `--name`, default `admin`) creates a key with the full set of scopes, without a label
  scope, sandbox limit or expiry. The key is not platform-admin unless `--platform-admin` is given.
  It uses the same generator, HMAC with a pepper and repository as `create-org`. It writes
  an `api_key.created` audit event (actor `sandfort-admin`) in the same transaction; the details carry
  the name, prefix and scopes, not the key. The plaintext key goes to stdout once, with the same two
  stderr hints as `create-org`; an unknown organization gives "error: unknown organisation
  <slug>" and exit 1. Recovery of a lost key: issue a new one, then revoke the old one
  (`docs/operations.md`, section "Recovering a lost API key"). Tests:
  `tests/test_admin_cli_create_key_r35.py` (b6fca90, `src/sandfort/admin_cli.py`).
- **Audit: `sandbox.failed` row for a failed create or start**: when a driver error moves a sandbox
  to `error` during the create or start step, the same transaction writes the audit row `sandbox.failed`
  (outcome `error`, target type `sandbox`, the target is the sandbox id). `details` carries `phase` (`create` or
  `start`), and the sandbox's `error_code` and `error_reason`. The actor is the API key that requested
  the operation when known, otherwise the system. The state change and the audit row are written together or
  not at all. It is not written by reset (its failure stays `sandbox.reset_failed`) nor by the reconciler
  (stays `sandbox.drift_detected`). Before this, the failure was visible only in the state and
  the sandbox's `error_reason`, with no audit row (fdac2e6, `src/sandfort/services/sandbox_jobs.py`; test
  `tests/test_sandbox_failed_audit_r36.py`).
- **An unknown query parameter gives 422 on every list route**: as the audit routes do since round 35,
  now also `GET /v1/sandboxes`, `/v1/isolation`, `/v1/snapshots`, `/v1/volumes`, `/v1/api-keys`,
  `/v1/webhooks`, `/v1/webhooks/{id}/deliveries`, `/v1/nodes`, `/v1/jobs` and `/v1/org/usage`
  respond with 422 with the code `VALIDATION_ERROR` and one `details.errors` entry for each
  unknown parameter (`type` `extra_forbidden`, `loc` `["query", ime]`, `msg`; the value is not
  returned). The allowed set is read from the route's own signature, so `cursor`, `limit` and `order` apply only
  where the route declares them. The check comes after authentication: an unauthenticated call still
  gets 401 or 403. A misspelled filter no longer gives an unfiltered 200 (93553f5,
  `src/sandfort/api/query_guard.py`; test `tests/test_unknown_query_params_r36.py`).
- **Snapshot: `image_ref` and `digest` are not returned to a key with a label scope**: both fields are
  `null` for such a caller, like `source_sandbox_id`, because `image_ref` carries the host and path
  of the operator's registry. A key without a label scope sees them. `image_ref` is therefore in the response schema
  `string` or `null` (31d44d6, `src/sandfort/api/schemas/snapshots.py`; test
  `tests/test_scoped_internals_r35.py`).
- **Named contexts: a stop in the middle of a cell is reported as a stop, not as a limit**: when a sandbox
  is stopped (caller stop, auto-stop) or its container disappears while a cell is running, the run responds with
  `stop_reason` `sandbox_stopped`, `exit_code` 137, `timed_out` false and `sandbox_stopped` true.
  Stderr then says "the sandbox was stopped while the cell was running; the context is gone,
  create or ensure a new one" (or "the sandbox container is gone; ..." when the container does not
  exist), and the driver's lines about the deadline expiring and about resource overrun are removed. Previously the
  run stayed reported as `timeout` or as death due to a limit. A streamed run sends the same
  reason: the `error` event carries `stop_reason` `sandbox_stopped` (the code is the one of the 409 conflict).
  Other driver failures remain a generic internal error (1153b74,
  `src/sandfort/toolbox/code_contexts.py`, `src/sandfort/toolbox/code_context_stream.py`; test
  `tests/test_named_contexts_r35.py`).
- **`/docs` and `/redoc` pages: the CSP allows the ReDoc logo host**: `img-src` is now
  `'self' data: https://cdn.redoc.ly`, the only remote image source; nothing else changed
  (bfdd08d, `src/sandfort/api/security_headers.py`).
- **SDK: error code in `str()`, `SandboxDestroyedError`, the `created` flag, `request_id` on
  stream errors, `CONTEXT_GONE_ERRORS`, `details` `None`** (73348c4, 5ffe7e5,
  `sdk/python/src/sandfort_sdk/`; test `tests/test_sdk_r36.py`):
  - `str(SandboxFailedError)` is the message plus ` [<error_code>]` when the code is set; the message without
    the code is `exc.message` (and `args[0]`). The CLI shows the code once.
  - `SandboxDestroyedError` (a subclass of `SandboxFailedError`) is raised when the sandbox is `destroyed`,
    for example on a repeated create with `idempotency_key` after deletion. `state` is
    `"destroyed"`, `error_code` is `None` unless the record keeps a code from before the deletion.
  - `code_contexts.ensure(...)` and the named `create(...)` return a handle with a read-only
    `created`: `True` when the call started the kernel (server 201), `False` when it found a live
    one (server 200). `create()` without a name is always `True`, a context from `list()` is `False`.
    A named create is not resent on 429 (raises `RateLimited`). Superseded: named
    create and ensure again keep the retry after 429 (b3c0d97, see below).
  - `TransportError` and `InvalidResponseError` from the cell execution stream carry `request_id`
    (the stream response's `x-request-id`, `None` when absent).
  - `CONTEXT_GONE_ERRORS = (NoContainer, NotFound)`, exported from the package root, for a single `except`
    around a call on a context whose kernel is gone.
  - `ApiError.details` is `None` only for a stream `error` event without `details`; an error response
    without `details` still gives `{}`. Superseded: `details` is always a dict, and `has_details` distinguishes
    "no details" (76b1bf4, see below).
- **The execution timeout message is on a separate line and does not name the parameter**: the stderr of a command
  stopped at the deadline now ends with the sentence "the command was stopped after N s (timeout);
  allow more time, up to 3600 s", instead of "... pass a larger timeout_s (up to 3600) to allow more
  time". Clients name this setting differently (`timeout_s`, `-t/--timeout`), so the text does not
  name the parameter. When the captured stderr is not empty and does not end with a newline, a newline is added before the
  sentence, in both plain and streamed execution. Older entries of this file that
  quote the old sentence describe the behavior at that time (82cbb2c,
  `src/sandfort/drivers/docker/exec.py`; tests `tests/test_exec_timeout_text_r36.py`,
  `tests/test_docker_exec_unit.py`).
- **CLI: `delete` alias for `snapshot rm` and `volume rm`, exit 1 with a hint for a create in the
  `error` state**: `sandfort snapshot delete` and `sandfort volume delete` are hidden commands with the same
  behavior as `rm` (`sandbox delete` already existed). `sandfort sandbox create` without `--wait`
  whose response is already in the `error` state now prints the error with the code and a hint ("the sandbox was
  kept; repeat the create with --wait to have it deleted on failure, or delete it with:
  sandfort sandbox rm <id>") and exits with 1; with `--json` the error object with `error.hint` goes to
  stdout. The sandbox is not deleted (53c2a99, `cli/src/sandfort_cli/sandboxes.py`,
  `cli/src/sandfort_cli/snapshot.py`, `cli/src/sandfort_cli/volume.py`; test
  `tests/test_cli_r36.py`).

##### Fixes after the round 36 review (unreleased)
Each entry is derived from the diff of the commit named, after docs commit 5912b42.
- **Image build: responses do not return `image_ref` and `digest` to a key with a label scope**: the response to
  the build request (`build_response`) takes `image_ref`, `digest` and `source_sandbox_id` from the same
  place as `/v1/snapshots`, so they are `null` for such a caller. The final `state` event of the build
  log also carries `digest` `null` for it. A key without a label scope sees them (34c8658,
  `src/sandfort/api/routes/image_builds.py`, `src/sandfort/api/schemas/image_builds.py`; test
  `tests/test_image_build_scope_r35.py`).
- **An unknown query parameter gives 422 on the remaining GET routes too, with a drift test**: the check
  (`KnownQuery`) is now also on `GET /v1/org/members`, `/v1/org/scim-tokens`, `/v1/org/quota` and
  `/v1/org/quota/recount` and on the sandbox toolbox list routes: directory listing (`toolbox/fs`),
  git status, lists of PTYs, sessions and code contexts. The drift test fails when a new `GET` route has no
  check or is not on the exceptions list with a reason. SCIM resource routes under `/scim/v2/` (for example
  `/Users`) remain RFC-lenient and accept RFC 7644 parameters (`filter`, `startIndex`,
  `count`) (db971c2, `src/sandfort/api/routes/`; test `tests/test_unknown_query_params_r36.py`).
- **Admin `create-key`: audit `details` follow the shape of the API event**: the `api_key.created` written by
  `create-key` carries `name`, `prefix`, `scopes`, `sandbox_labels` (`null`), `max_sandboxes`
  (`null`) and `expires_at` (`null`), like the event from the API. The `is_platform_admin` field is no longer
  in `details` (ec1af5b, `src/sandfort/admin_cli.py`).
- **SDK and CLI: `SnapshotInfo.image_ref` and `digest` are optional, the CLI shows `-`**: both fields are
  `str | None` (`None` for a key with a label scope). The CLI prints `-` instead of the hidden `image_ref`
  or `digest` in the `snapshot list` table (IMAGE column), in the fields of a single snapshot and in the
  "build ... ready" line when there is neither `digest` nor `image_ref` (76b1bf4,
  `sdk/python/src/sandfort_sdk/snapshots.py`, `cli/src/sandfort_cli/snapshot.py`).
- **SDK: `ApiError.details` is always a dict, `has_details` for a stream error**: `details` is `{}` when
  the server sent none, never `None`; `has_details` is `True` only when the server sent
  a non-empty `details` object. A stream `error` event without `details` gives `{}` and `has_details`
  `False`. The earlier statement "`details` is `None`" for such an event is superseded (76b1bf4,
  `sdk/python/src/sandfort_sdk/exceptions.py`, `code_contexts.py`).
- **The CLI strips only the code suffix from the failure message**: ` [<error_code>]` is removed only when
  it is at the end of the message, before the optional ` (request id ...)`; the same token inside the text
  (the sandbox's `error_reason`) stays (76b1bf4, `cli/src/sandfort_cli/output.py`,
  `plain_message`).
- **The `str()` of a failure keeps the request id**: `str(SandboxFailedError)` is the text from `args[0]` plus
  ` [<error_code>]`, inserted before the trailing ` (request id ...)`. The CLI writes the request id into
  `args[0]` and `message` (`mention_request_id`), so `str()` shows the code and the request id (76b1bf4,
  `sdk/python/src/sandfort_sdk/exceptions.py`, `cli/src/sandfort_cli/sandboxes.py`).
- **SDK: named create and ensure of code contexts keep the retry after 429**: the call
  goes through the plain `request`, so it is resent after a 429 `RATE_LIMITED` like any other.
  `created` is still determined from the status (200 found, anything else new) (b3c0d97,
  `sdk/python/src/sandfort_sdk/code_contexts.py`, `_transport.py`).

##### Latest fixes of round 36 (unreleased)
Each item is derived from the diff of the listed commit, after docs commit 403d2d4.
- **Audit: `api_key.created` carries `is_platform_admin` again**: the `details` of the event
  `api_key.created` contains `is_platform_admin`, both when the key is created by `create-key` (the value is
  `true` only for a platform-admin key issued by the admin CLI with `--platform-admin`) and when it is created by
  `ApiKeyAdminService` (the value of the key record). Replaced: the earlier statement that the field is "no longer in
  `details`" describes the behavior up to this commit (a7149c6, `src/sandfort/admin_cli.py`,
  `src/sandfort/services/api_key_admin.py`; test `tests/test_admin_cli_create_key_r35.py`).
- **Unknown query parameter gives 422 on `GET /v1/sandboxes/{id}`, sandbox logs and
  `fs/stat`, `fs/download` too; the drift test forbids an exception for a route with query parameters**:
  the check (`KnownQuery`) now sits on `GET /v1/sandboxes/{id}` (parameters `wait_for` and
  `timeout_s`), on the sandbox logs route (`GET /v1/sandboxes/{id}/logs`) and on the toolbox routes
  `fs/stat` and `fs/download`. A misspelled `wait_for` or `timeout_s` therefore gives 422, not a
  response without waiting. The drift test (`test_allowlisted_routes_declare_no_query_parameter`) fails
  when a route on the exception list declares any query parameter. The only allowed exception
  is the two session command routes (`.../commands/{command_id}/logs` and `.../logs/follow`), which
  declare query parameters but have no check yet (`PENDING_SESSIONS_GUARD`; a second test fails
  as soon as someone guards them). Replaced: the routes `GET /v1/sandboxes/{id}`, sandbox logs, `fs/stat` and
  `fs/download` were previously on the exception list as reads by id or streams (c3ccf82,
  `src/sandfort/api/routes/sandboxes.py`, `sandbox_logs.py`, `toolbox/fs.py`; test
  `tests/test_unknown_query_params_r36.py`).
- **CLI: the failure message is built from the message without the code, without a stripping heuristic**: `plain_message`
  was removed. The failure line and `error.message` in `--json` take `exc.message`, which never
  contains the code; the code is added only in `str()` and in the text line, once. The text the sandbox itself
  carries (`error_reason`) is not changed, even when it ends with a token such as `[timeout]`. Replaced:
  the item "CLI strips only the code suffix from the failure message" describes the behavior up to this commit.
  In the SDK, `SandboxFailedError.__str__` now starts from `message`, not from `args[0]` (f4394b5,
  `cli/src/sandfort_cli/output.py`, `sdk/python/src/sandfort_sdk/exceptions.py`; test
  `tests/test_cli_r36.py`).
- **CLI: the `snapshot build` summary for a key with a label scope names the snapshot id**: when
  `digest` and `image_ref` are hidden, the line "build <id> ready" prints the snapshot id instead of `-`
  (`build snap_... ready (reused): snap_...`) (f4394b5, `cli/src/sandfort_cli/snapshot.py`; test
  `tests/test_cli_r36.py`).

##### Last fixes of round 36 (unreleased)
Each item is derived from the diff of the listed commit, after docs commit de30898.
- **Unknown query parameter gives 422 on the command-log routes (list and follow) too; the drift test no longer
  has a pending exception**: the check (`KnownQuery`) now sits on
  `GET /v1/sandboxes/{sandbox_id}/toolbox/process/sessions/{session_id}/commands/{command_id}/logs`
  (parameters `offset` and `limit`) and on `.../logs/follow` (parameter `offset`). A misspelled
  `offset` therefore gives 422, not a 200 that replays the log from the start. The `Last-Event-ID` header
  on the follow route is not affected: the check reads only the keys of the query string. The set
  `PENDING_SESSIONS_GUARD` and the test that held it were deleted, so the drift test
  (`test_allowlisted_routes_declare_no_query_parameter`) allows no exception for a route
  that declares a query parameter. Replaced: the item "Unknown query parameter gives 422 on
  `GET /v1/sandboxes/{id}`, sandbox logs and `fs/stat`, `fs/download` too" names those two
  command-log routes as the only allowed exception; that held up to this commit (dac583c,
  `src/sandfort/api/routes/toolbox/sessions.py`; test `tests/test_unknown_query_params_r36.py`).
- **CLI: `error.message` in `--json` output has no "(request id ...)" suffix**: `sandbox create`
  adds the request id to the failure text (`mention_request_id`) only when `--json` is not enabled. With
  `--json` the failure is raised unchanged, so `error.message` does not end with the suffix, and the same id is carried by a
  separate field `error.request_id`. The text line is unchanged and still ends with
  `(request id <id>)`. Replaced: the item "`str()` of the failure keeps the request id" applies to the
  text path; in `--json` mode the CLI does not write the request id into `args[0]` or `message`
  (9370a83, `cli/src/sandfort_cli/sandboxes.py`; test `tests/test_cli_r36.py`).

#### Round 35: audit filters, stricter requests, named contexts, new error codes
Each item is derived from the code and commits of round 35 (after docs commit 4b1e222). The exported
`openapi/sandfort.v1.json` is regenerated every round (936c252).
- **Image build: registry text does not reach the tenant**: the build error is no longer written to the log or
  to the exception as the daemon returned it. A failed pull of the base image (the first `FROM` in
  the Dockerfile) is classified as a pull: a refused or unreachable registry gives the same fixed
  sentence as pull, with the prefix "image build failed: " and in the same error type
  (`DriverAccessDenied`, `DriverRegistryUnreachable`). A failed build step (message "returned a
  non-zero code") gives "image build failed: a build step exited with a non-zero code", and every
  other error gives "image build failed: the Docker daemon could not complete the build". The last
  line of the build log equals the exception message; the daemon text (may name the host identity)
  goes only to the debug log. Note: these two fixed sentences do not point to the build log, the code does not do that
  (0d60831, `src/sandfort/drivers/docker/build.py`, `tests/test_image_build_errors_r35.py`).
- **Pull: "denied" at the start of a registry response is a refusal**: a response that starts with the word
  `denied` (or has a line that starts that way, e.g. ECR "denied: User: ... is not authorized") gives
  `image_access_denied`. The phrase "denied by ..." is not one (0d60831,
  `src/sandfort/drivers/docker/images.py`).
- **Pull: an unclassified error always says "could not pull <reference>"**: the message is fixed,
  without daemon text (previously it kept the cleaned message, and only text with an AWS ARN was
  replaced). The error keeps its type (timeout stays timeout, conflict stays conflict); only the
  fixed disk-full message stays as it is (0d60831, `src/sandfort/drivers/docker/images.py`).
- **Create: an invalid reference has the same form as in the pull path**: create with a reference
  the daemon cannot parse gives the same message as pull, "invalid image reference <reference>:
  invalid reference format", instead of the raw daemon message (0d60831,
  `src/sandfort/drivers/docker/containers.py`).
- **Pull: certificate errors, HTTPS mismatches and EOF are `registry_unreachable`**: texts with
  `x509:`, "certificate", "http response to https client" and `EOF` are treated as a network failure
  (the registry did not respond), so they give `registry_unreachable` (0d60831,
  `src/sandfort/drivers/docker/images.py`).
- **SDK exports `ApiKeyStatus`**: `from sandfort_sdk import ApiKeyStatus`; `DEFAULT_STATUS` in
  `api_keys.py` is typed with that `Literal`. `ApiKeyInfo.status` stays a plain `str`, so that a
  value added by a newer server is still loaded as sent (93522d7,
  `sdk/python/src/sandfort_sdk/__init__.py`, `api_keys.py`).
- **SDK: `ApiKeyInfo.status`**: `ApiKeyInfo` (and `CreatedApiKey`) carries a `status` field with
  the value the server computes at response time (`active`, `expired` or `revoked`);
  `from_payload` reads it, and a response without the field (older server) is loaded as `active`.
  `ApiKeyStatus` is a `Literal` of those three values in `sdk/python/src/sandfort_sdk/api_keys.py`.
  Limit: against an older server `status` is always `active`, so `revoked_at`
  and `expires_at` must be read there. Tests: `tests/test_sdk_api_key_status_r35.py`.
- **Audit: `request_id` and `outcome` filters, an unknown parameter is 422**: `GET /v1/audit-events`
  accepts `request_id` (exact match with the `X-Request-ID` of the request that wrote the row) and
  `outcome` (`success`, `denied` or `error`) alongside the existing `actor_id`, `action`, `target_id`, `from`, `to`,
  `order`, `cursor` and `limit`; filters are combined with AND. `GET /v1/audit-events/export` accepts
  `from`, `to`, `request_id` and `outcome`, and `GET /v1/audit-events/verify` only `from_id`. Every
  other query parameter on these three routes responds with a 422 that names it and lists the accepted ones
  (previously a typo such as `?requestid=` returned an unfiltered 200). The check runs after the check of the
  key and scope, so an unauthorized call still gets 401/403 (965782c,
  `src/sandfort/api/routes/audit.py`, `src/sandfort/db/repositories/audit.py`).
- **Request body rejects unknown fields (422)**: request body models derive from the shared base
  `RequestModel` (`extra="forbid"`), so an unknown field gives 422 `VALIDATION_ERROR` that names it,
  instead of being silently dropped. This applies to models in the schemas for sandboxes (update, resize,
  volume mounting), snapshots, image build, orgs, SSO, users, volumes, webhooks
  and toolbox (fs, git, process, PTY, sessions); key create and sandbox create already did this.
  A body that is not valid JSON gets `loc` of only `["body"]` (previously pydantic added the character
  position as a second element) (4be9773, `src/sandfort/api/schemas/common.py`,
  `src/sandfort/api/errors.py`).
- **Internal ids are not returned to a key with a label scope**: in the sandbox response `node_id` and
  `job_id` are `null` for a key with `sandbox_labels`, and in the snapshot response `source_sandbox_id` is
  `null` (the source may be a sandbox outside its scope). A key without labels sees the values as
  before (da31b5a, `src/sandfort/api/schemas/sandboxes.py`, `snapshots.py`).
- **`GET /v1/nodes`: `running_sandboxes` counts only the caller's sandboxes**: the field is the number of started
  sandboxes of the caller's org on that node, not the load of the whole host. Node rows are still
  platform-wide, the route still requires `org:read` and a key without labels, and returns only counts.
  The route is still outside the exported spec (`_IN_SCHEMA = False`) (da31b5a,
  `src/sandfort/api/routes/nodes.py`, `src/sandfort/api/schemas/nodes.py`).
- **API key has a `status` field**: the create, list and revoke responses carry `status`: `revoked` as soon as
  `revoked_at` is set, otherwise `expired` when `expires_at` is equal to or earlier than the response time,
  otherwise `active`. The server computes it on every response; `revoked` wins over `expired`
  (100d088, `src/sandfort/api/schemas/api_keys.py`). SDK `ApiKeyInfo` gets the field
  `status` in the item "SDK: `ApiKeyInfo.status`" above; CLI `key list` already computes the same status.
- **Audit re-anchor: operator and reason code, `reanchor` object in verify**: `audit-reanchor`
  accepts the options `--operator TEXT` (1 to 255 characters) and `--reason-code`
  (`incident_acknowledged`, `migration` or `other`); they are given together or not at all (otherwise an error and
  exit 1), and they are written into the details of the event `audit.chain_reanchored` as `operator` and
  `reason_code`, alongside `note`. `GET /v1/audit-events/verify` gets a `reanchor` object with the fields
  `event_id`, `operator`, `reason_code`, `acknowledged_through`, `findings`, `note` and
  `occurred_at`; it is omitted until there is a re-anchor, and `operator` and `reason_code` are `null` for
  older events without them (100d088, `src/sandfort/admin_cli.py`,
  `src/sandfort/services/audit_chain.py`, `src/sandfort/api/schemas/audit.py`).
- **Documentation pages respond to HEAD**: `/docs`, `/redoc` and `/docs/init.js` accept GET and
  HEAD; HEAD returns the status and headers of the GET response, without a body, for availability checks (52f1cd8,
  `src/sandfort/api/docs_pages.py`).
- **New `error_code` for image pull errors**: `registry_unreachable` (the network to the registry
  failed, the image may exist; retrying makes sense), `image_access_denied` (the registry
  responded and refused the pull, e.g. `unauthorized` or `denied:`; do not retry) and
  `invalid_image_reference` (the daemon cannot parse the reference, "invalid reference format"; do not
  retry). The code is chosen by the driver exception type (`DriverRegistryUnreachable`,
  `DriverAccessDenied`, `DriverInvalidReference`), never by the message text. The daemon text
  "pull access denied ... may require 'docker login'" still gives `image_not_found`. Limit:
  SDK `ErrorCode` and `is_known_error_code` do not know these three codes, so `SandboxInfo.error_code`
  carries them as a plain string (a00c406, `src/sandfort/drivers/docker/images.py`,
  `src/sandfort/services/sandbox_jobs.py`, `src/sandfort/domain/sandbox.py`).
- **SDK: typed error codes and `error_code` on the handle**: `ErrorCode` (Literal),
  the constants `ERROR_CODE_*` and `is_known_error_code(value)` are exported from `sandfort_sdk`;
  `SandboxInfo.error_code` stays `str | None`. The sandbox handle has the property `error_code`
  (the same as `sbx.info.error_code`). `ErrorCode` lists the eight earlier codes, without the three new ones from the
  previous item (f80d6aa, `sdk/python/src/sandfort_sdk/error_codes.py`, `handles.py`).
- **Named code contexts and SDK `ensure`**: `POST .../code-contexts` optionally accepts `name`
  (character rules as for sandbox names), unique among the live contexts of a sandbox. Create with
  the name of a live context returns that context with 200 instead of a new one (201); `cwd` is then not compared.
  `GET .../code-contexts?name=` returns only the context of that name (an empty list if there is none), and
  `name` is omitted from the response for an unnamed context. Named creates of the same sandbox and
  name wait for each other on a lock in that process (up to 30 s, then 409 `in_progress`). SDK:
  `code_contexts.ensure(name, language=, cwd=)` (and async), `create(..., name=, language=)` and
  `ctx.name`. State is not restored: after stop/start the same call starts a new, empty context
  of the same name (c5495cd, `src/sandfort/api/routes/toolbox/code_contexts.py`,
  `src/sandfort/toolbox/code_contexts.py`, `sdk/python/src/sandfort_sdk/code_contexts.py`).
- **More honest message when a kernel is hard-killed**: when a run of a stuck cell removes the context
  after the exec deadline, stderr instead of the driver's line about the exec deadline (cell limit plus a 5 s margin)
  carries "the cell exceeded its N s limit and the kernel did not stop when interrupted; its state
  is lost", with the limit of the cell itself (c5495cd, `src/sandfort/toolbox/code_contexts.py`).
- **A repeated create with the same `Idempotency-Key` returns the current state**: the replay returns the stored
  status code, but the current view of the sandbox, not the stored body; a sandbox deleted in the meantime
  is returned as state `destroyed`. If the row no longer exists, the stored body is returned. The key is valid
  for one day (24 h) from storage; after that it is forgotten and the request creates a new sandbox. The replay carries
  the header `Idempotent-Replayed: true`. Same commit: the `error` event in a `run_stream` stream carries
  the `x-request-id` of the stream response and its HTTP status (200), so the exception has `request_id` and
  `status_code` (`details` stays `None`) (88a424d, `src/sandfort/api/routes/sandboxes.py`,
  `sdk/python/src/sandfort_sdk/code_contexts.py`).
- **CLI: `snapshot` row, `error_code` in the error line, text for an `exec` timeout**: commands that
  print a single sandbox add a `snapshot` row (image id or reference, `-` when there is none; the table
  `sandbox list` is not changed). The error of a failed start reads "sandbox <id> is error [<error_code>]:
  ..." when the code exists. An `exec` timeout prints "error: command timed out; allow more time with
  -t/--timeout SECONDS, which goes before the sandbox reference: sandfort exec -t 60 <sandbox> --
  <command>" and first breaks the line if stderr did not end with a newline (52866ea,
  `cli/src/sandfort_cli/output.py`, `exec_cmd.py`).

#### Round 35: fixes after review
Each item is derived from the code and commits after docs commit b0d3c80. The items above stay as
written for their commits; this round changes what they describe where stated.
- **Image pull error classification compares registry responses by structure**: before comparison,
  every echo of the requested reference (and its repository paths) is removed from the daemon text, so a
  reference that contains "forbidden" (e.g. `acme/forbidden-fruit`) no longer gives a refusal. A refusal is
  recognized only by anchored phrases (`: denied:`, `denied: requested access`, `unauthorized: `,
  `status: 401`, `status: 403`, `pull access denied`, or text that ends with
  `: unauthorized`), not bare words. A network failure (dial, lookup, timeout, refused) is decided before
  a refusal, because a registry that did not respond could not have refused the pull (2e7476d,
  `src/sandfort/drivers/docker/images.py`).
- **`error_reason` for a refused or invalid image is a fixed sentence**: for `image_access_denied`
  the tenant sees "the registry refused to pull <reference>; check the image name and the registry
  access", and for `invalid_image_reference` "invalid image reference <reference>" (with
  ": invalid reference format" when the daemon said so). The daemon text, which may quote the
  host identity (e.g. the role ARN and account number in an ECR refusal), goes to the server log at debug
  level. Other errors keep their cleaned message (2e7476d,
  `src/sandfort/services/sandbox_jobs.py`, function `failure_reason`).
- **Named contexts: a transient read error does not create a duplicate name**: if the live contexts
  cannot be read (driver error), create fails instead of starting a new context. The scope
  of uniqueness is stated: it holds per API process; two creates of the same name racing between
  processes can both succeed (there is no persisted constraint). The 200 response for an existing name carries
  the `cwd` of the existing context, and the `cwd` from the request is ignored (20bd72c,
  `src/sandfort/api/routes/toolbox/code_contexts.py`).
- **The code context run body, the preview token body and the SCIM token body reject unknown fields**:
  `CodeContextRunRequest`, `MintPreviewTokenRequest` and `CreateScimTokenRequest` derive from
  `RequestModel` (`extra="forbid"`), so an unknown field gives 422 `VALIDATION_ERROR` that names it
  (20bd72c, d5631a9, `src/sandfort/api/routes/toolbox/code_contexts.py`,
  `sandbox_preview.py`, `scim_tokens.py`). Limit: the "wider search" from the message of commit d5631a9
  was not checked model by model.
- **SDK `ErrorCode` lists `registry_unreachable`, `image_access_denied` and
  `invalid_image_reference`**: `ErrorCode` and `KNOWN_ERROR_CODES` now have all eleven codes,
  the constants `ERROR_CODE_REGISTRY_UNREACHABLE`, `ERROR_CODE_IMAGE_ACCESS_DENIED` and
  `ERROR_CODE_INVALID_IMAGE_REFERENCE` exist, and `is_known_error_code()` returns `True` for these three
  codes. Retrying makes sense for `registry_unreachable` and `timeout`; for `image_access_denied` and
  `invalid_image_reference` it does not, until the reference or access changes. This corrects the limit from
  the item "New `error_code` for image pull errors" above (c980737,
  `sdk/python/src/sandfort_sdk/error_codes.py`). SDK `ApiKeyInfo` gets the field `status` in the
  item "SDK: `ApiKeyInfo.status`" above. The same commit unifies the server list `ERROR_CODES` (from the commit title; not
  checked in the code).
- **Image pull errors carry a fixed message on every path**: the pull classifier in the
  Docker driver (`classify_pull_failure`) now gives every recognized error a fixed message
  built from the reference the tenant sent, and the daemon text (may name the host identity,
  e.g. the AWS role ARN in an ECR refusal) goes only to the debug log: `DriverAccessDenied` is "the registry
  refused to pull <reference>; check the image name and the registry access",
  `DriverInvalidReference` is "invalid image reference <reference>" (with ": invalid reference
  format" when the daemon said so), and `DriverNotFound` is "no such image or snapshot:
  <reference>". Previously only `failure_reason` built the fixed message when creating a sandbox; now
  the driver itself builds it, so `failure_reason` returns the exception message. The same message arrives when creating a
  sandbox, on reset (the row's `error_reason` and the audit field `error` for `sandbox.reset_failed` are
  `failure_reason`, previously the raw driver message) and when registering a snapshot
  (`POST /v1/snapshots`, test `tests/test_snapshot_pull_denied_r35.py`). An unclassified pull
  error keeps its type and cleaned message, except when the text names the host identity (ARN):
  then it becomes a plain `DriverError` "could not pull <reference>". Limit: a reference fragment
  that contains `/`, `:` or `@` is removed from the text before comparison with the markers; a bare word
  (a reference called `denied`) stays in the text. The resize path was not separately checked in the diff
  of the commit (285d599, `src/sandfort/drivers/docker/images.py`,
  `src/sandfort/services/sandbox_jobs.py`, `src/sandfort/services/sandbox_reset.py`).
- **Containerd 401/403 texts, the bare word "denied" and "no basic auth credentials" are
  `image_access_denied`**: text that only a registry that responded can give (the word pair
  `401 Unauthorized` or `403 Forbidden`, a final `: denied` at the end of the text or line, and ECR's
  "no basic auth credentials") is classified as `DriverAccessDenied` before the check of network
  errors. The marker "failed to authorize" was added among the refusal phrases, but stays behind the transport
  check, because the same prefix is also carried by a failed token fetch (dial). The other refusal phrases
  (`: denied:`, `unauthorized: `, `status: 401`, `status: 403`) still lose to a transport error
  (285d599, `src/sandfort/drivers/docker/images.py`, tests
  `tests/test_docker_pull_classification_r35.py`).
- **SDK: the root package exports three image pull codes**: `ERROR_CODE_IMAGE_ACCESS_DENIED`,
  `ERROR_CODE_INVALID_IMAGE_REFERENCE` and `ERROR_CODE_REGISTRY_UNREACHABLE` are imported directly from
  `sandfort_sdk` and are in `__all__` (the other eight `ERROR_CODE_*` constants already were)
  (761db29, `sdk/python/src/sandfort_sdk/__init__.py`).
- **Audit 422 for an unknown query parameter does not return `input`**: each entry in `details.errors`
  carries only `type` (`extra_forbidden`), `loc` (`["query", <ime>]`) and `msg`; the value the
  caller sent is not returned (previously the entry also had `input`). The shape is the same as in
  request body validation (13274c9, `src/sandfort/api/routes/audit.py`,
  `tests/test_audit_filters_r35.py`).
- **Removed the dead constant `COUNT_PAGE_SIZE` from `src/sandfort/api/routes/nodes.py`**: the counts
  for `GET /v1/nodes` come from a single grouped query, so the constant was not used; the test
  that patched it was also removed. The route's behavior does not change. The same commit corrects the docstring of
  `sandbox_response`: `node_id` is hidden from a key with a label scope, and `job_id` is reserved and
  always `null` for every caller (13274c9, `tests/test_scoped_internals_r35.py`).
- **`job_id` is a reserved field and is always `null`**: the field description in the sandbox schema says "Reserved.
  Currently always null for every caller, org-wide and label-scoped keys alike; do not rely on
  it." The code sets `job_id=None` for every caller (c980737,
  `src/sandfort/api/schemas/sandboxes.py`). This corrects the earlier item about a key with a label scope,
  according to which a key without labels sees `job_id` "as before".
- **CLI: the `exec` timeout hint quotes the reference and respects the current `-t`**: the sandbox reference is quoted
  in the suggested command through `shlex.quote`. The suggested `-t` is twice the one that was
  in effect (60 s when `-t` is not given), at most 3600 s. When `-t` is already 3600 s or more, the message
  instead says that the command did not finish within the maximum of 3600 s and points to
  `sandfort cmd start <ref> -- <command>` (08eb485, `cli/src/sandfort_cli/exec_cmd.py`).
- **API key status follows the server clock**: `status` is computed in `key_status(key, now)` from the
  time the call takes from the application clock, the same one with which authentication compares `expires_at`,
  not from the system clock (07a4682, `src/sandfort/api/schemas/api_keys.py`).
- **Unknown query parameter in the audit routes: `VALIDATION_ERROR` with `loc` `["query", ime]`**:
  the 422 response has the code `VALIDATION_ERROR` and one `details.errors` entry per unknown parameter, with
  the fields `type` (`extra_forbidden`), `loc` (`["query", "<ime>"]`), `msg` ("Extra inputs are not
  permitted") and `input` (the passed value); the message names the parameters and lists the accepted ones
  (1be42d7, `src/sandfort/api/routes/audit.py`).
- **The `audit_events` table gets an index on `(org_id, request_id)` (migration r0019)**: the index
  `ix_audit_events_org_id_request_id` serves the `request_id` filter; without it the search scans the whole
  audit chain of the org. The migration is revision `0019` (after `0018`), `downgrade()` drops it
  (1be42d7, `src/sandfort/migrations/versions/r0019_audit_request_id_index.py`).
- **`GET /v1/nodes`: the number of running sandboxes per org from a single grouped query**:
  `running_counts(org_id)` runs a single `GROUP BY node_id` query over started sandboxes, with
  the org filter when given; the route calls it once (e376bb3,
  `src/sandfort/db/repositories/nodes.py`, `src/sandfort/api/routes/nodes.py`). The same commit, according to
  its title, shows a dash in the console for a sandbox without a node; this was not checked in the code.
- **Image build responses do not return `source_sandbox_id` to a key with a label scope**: the field
  `source_sandbox_id` in the build response is taken from `snapshot_response`, so it is `null` for a key with
  `sandbox_labels`, as on `/v1/snapshots` (72cad5d, `src/sandfort/api/schemas/image_builds.py`).

#### Round 35: fixes after the fourth review
Each item is derived from the code and the commits after docs commit daed314 (070a017 and bc871e4).
Items above remain as written for their commits; this round changes what they describe where it
is stated.
- **Image build: an error that arrives as a daemon HTTP error is classified like the one from the stream**: an error
  from the build call (daemon HTTP error or `requests` library error) goes through the same
  classification as an `error` entry from the progress stream, so it gives the same fixed sentences: rejected or
  unavailable base image registry, "image build failed: a build step exited with a non-zero
  code" or "image build failed: the Docker daemon could not complete the build". The last line
  of the build log equals the exception message on this path too (070a017,
  `src/sandfort/drivers/docker/build.py`, `tests/test_image_build_errors_r35.py`).
- **Image build: the BuildKit step sentence is recognized, and the step sentence keeps the exit code**:
  besides the classic message "returned a non-zero code", BuildKit's "did not complete
  successfully" is recognized too, so the command text (which belongs to the tenant) cannot be read as a pull error.
  When the daemon states "exit code: N", the sentence reads "image build failed: a build step exited with a
  non-zero code (exit code N)"; only the digits are carried over, no other daemon text (070a017,
  `src/sandfort/drivers/docker/build.py`). This changes the item "Image build: the registry text does not reach
  the tenant" above, where the step sentence has no suffix.
- **Pull: "context deadline exceeded" and a client timer expiry are `registry_unreachable`**:
  the texts "context deadline exceeded" and "client.timeout exceeded while awaiting headers" were added
  to the network markers, so they are treated as a network failure toward the registry (the registry did not respond), not as an
  unclassified error (070a017, `src/sandfort/drivers/docker/images.py`,
  `tests/test_docker_pull_classification_r35.py`).
- **An unclassified daemon error gives a fixed sentence, and the details go to the server log**: an error
  from the Docker daemon or the `requests` library that is not classified (not a not found, conflict, full
  disk, or pull rejection) now has the message "the sandbox runtime reported an error; the
  details are in the server log". That sentence is the `message` of the 502 `DRIVER_ERROR` response and
  the sandbox's `error_reason`, likewise. The sanitized daemon text, which may name host paths,
  sockets, and runtime internals, is logged at `WARNING` level together with the operation name and
  reference. Classified errors keep their message, and text that the
  pull classifier recognizes is passed to it unchanged (it still gives its own fixed sentences). Invariant
  in `failure_reason`: no driver error message is rewritten because each one is safe for
  the tenant (bc871e4, `src/sandfort/drivers/docker/client.py`,
  `src/sandfort/services/sandbox_jobs.py`, `tests/test_generic_driver_error_text_r35.py`).
- **The Docker driver log reader and the firecracker agent client also use fixed messages**: a failure of the
  container log stream gives "the container log stream failed; the details are in the server log", and
  the exception goes to the server log (`WARNING`). The firecracker agent client gives "the microVM agent
  reported an error; the details are in the server log (status N)" when the agent responds with a status
  outside 2xx, and "the microVM agent request failed; the details are in the server log" when the request does not
  succeed at the transport level; the agent text, or the exception, goes to the log (`WARNING`). The Firecracker driver is
  still a skeleton and is not offered (bc871e4, `src/sandfort/drivers/docker/logs.py`,
  `src/sandfort/drivers/firecracker/agent_client.py`).

#### Round 35: fixes after the fifth review
Each item is derived from the code and the commit after docs commit 24246b5 (17129e6). Items above
remain as written for their commits; this round changes what they describe where it is stated.
- **Daemon text travels outside the message (`daemon_text`), so every unclassified driver message is
  a fixed sentence on every operation**: `DriverError` got the attribute `daemon_text`. The message
  (`message`, likewise `str(exc)`) is the only text the tenant may see; `daemon_text` is
  the backend's own explanation, serves only classifiers and the server log, and never enters
  the API response. An unclassified error from the daemon or the `requests` library has the message "the sandbox
  runtime reported an error; the details are in the server log" on every driver operation, not
  only on image pull. The pull and build paths classify from that text (via
  `classification_text`: `daemon_text` when it exists, otherwise `message`) the same as before, so
  `image_not_found`, `registry_unreachable`, `image_access_denied`, and `invalid_image_reference`
  stay as they were. Previously the text that the pull classifier recognizes stayed in the error
  message; that no longer applies (17129e6, `src/sandfort/drivers/errors.py`,
  `src/sandfort/drivers/docker/client.py`, `src/sandfort/drivers/docker/images.py`,
  `tests/test_generic_driver_error_text_r35.py`).
- **Image build: an HTTP error gives the same sentences as a stream error**: an error from the build
  call itself reads `daemon_text` (otherwise the sanitized message) and goes through the same classification as an entry
  `error` from the progress stream: a 404 pull rejection gives the rejection sentence, a failed step gives
  "image build failed: a build step exited with a non-zero code" with the exit code, and the BuildKit
  sentence "did not complete successfully" gives the same step sentence. The exit code is read from
  both the classic message ("returned a non-zero code: N") and the BuildKit one ("exit code: N"); the
  last match applies, because the command text that precedes it belongs to the tenant and may contain the same
  phrase. Only the digits are carried over (17129e6, `src/sandfort/drivers/docker/build.py`).
- **The warning log names the operation, the reference, and the job ids, and truncates the daemon text**: the
  `WARNING`-level line (logger `sandfort.drivers.docker.client`) reads `docker <operation> failed
  (ref=<ref>, sandfort.org_id=<id>, sandfort.sandbox_id=<id>): <text>`. `<operation>` is the name of the
  operation as the caller specifies it (for example `container.create`, `exec.start`, `image.pull`,
  `volume.create`); the org and sandbox ids come from the job being executed and are omitted
  when the error occurs outside a job. `<text>` is the sanitized daemon text truncated to 500 characters, because
  an OCI error can repeat the command line (17129e6, `src/sandfort/drivers/docker/client.py`).
  This changes the item "An unclassified daemon error gives a fixed sentence" above, where the line carries
  only the operation and the reference.
- **The Firecracker driver no longer forwards the agent validation text**: a malformed `vm` from the agent's
  response gives the message "the sandbox agent returned a malformed vm; details are in the server log";
  the validation error text, which may quote agent internals, goes to the server log (`WARNING`)
  and to `daemon_text`. The Firecracker driver is still a skeleton and is not offered (17129e6,
  `src/sandfort/drivers/firecracker/driver.py`).
- **Cleanup during image export no longer logs false warnings**: image export checks whether the
  error is "not found" using a pure mapping (`map_driver_error`), which does not write a log, so "not found" during
  cleanup no longer leaves a `WARNING` line (17129e6,
  `src/sandfort/drivers/docker/image_export.py`).

#### Round 35: fixes after the eighth review
Each item is derived from the code and the commit after docs commit b578da8 (596ec72). Items below
remain as written for their commits; this round changes what they describe where it is stated.
- **"Not found" for a container keeps the phrase `No such container:`, and the exec-gone list accepts only
  a hexadecimal id, the replacement word, or a plain word**: a "not found" error for a container that is
  named by a short (12 or more hexadecimal characters) or full (64) daemon id keeps
  the message `No such container: the sandbox container`; the id is still replaced by the replacement word, but the sanitizer
  no longer deletes the phrase `No such container: ` before it (previously the text became "No such the
  sandbox container", did not pass the allowed-phrases list, and the tenant got "the object does
  not exist"). The exec id in the "No such exec instance" (exec-gone) allowed-phrases list accepts
  only a hexadecimal id, the replacement word "the sandbox container", or a plain word of letters, digits,
  dots, underscores, and hyphens; previously it accepted any token without spaces, `/`, and quotes.
  Text such as `No such exec instance: ab/cd` or `No such exec instance: $(x)` therefore gives the fixed
  sentence "the object does not exist", and the daemon text goes to `daemon_text` (596ec72,
  `src/sandfort/drivers/docker/client.py`, `tests/test_generic_driver_error_text_r35.py`).

#### Round 35: fixes after the seventh review
Each item is derived from the code and the commit after docs commit 53f488d (30d0dbc). Items below
remain as written for their commits; this round changes what they describe where it is stated.
- **The container reference sanitizer is case-insensitive**: the pattern that replaces the container id
  in the daemon text with the words "the sandbox container" now also matches a capital initial
  letter, so moby's text `Container <id> is not running` becomes "the sandbox
  container is not running" after sanitizing and keeps the phrase `is not running` (30d0dbc,
  `src/sandfort/drivers/docker/client.py`, `tests/test_generic_driver_error_text_r35.py`).
- **The "No such exec instance" allowed-phrases list accepts the sanitized id**: the exec id has 64
  hexadecimal characters, so sanitizing changes it to "the sandbox container". The variants `'<id>' found in
  daemon` and `: <id>` therefore accept that replacement text too (besides an id without `/`, spaces, and
  quotes), so a real id from the daemon keeps the marker "No such exec instance" instead of the fixed
  sentence (30d0dbc, `src/sandfort/drivers/docker/client.py`).
- **The exec module and the toolbox process route read the driver error's classification text**: the
  `exec` module recognizes a vanished execution (`No such exec instance`), and the toolbox process route a dead
  container (`is not running`) from the driver error's `classification_text`, not from the message the
  tenant sees. `classification_text` is the daemon text when it exists, otherwise the message; therefore the fixed
  sentences the tenant sees cannot break the recognition (30d0dbc,
  `src/sandfort/drivers/docker/exec.py`, `src/sandfort/api/routes/toolbox/process.py`,
  `tests/test_docker_exec_unit.py`).
- **`UnknownDriver` is restored from `pickle`**: the class gets `__reduce__`, which builds it from
  the constructor arguments (the driver name and the list of known drivers), because the base class
  passes the message and `ref`, which does not match the constructor signature (30d0dbc,
  `src/sandfort/drivers/registry.py`).

#### Round 35: fixes after the sixth review
Each item is derived from the code and the commit after docs commit 08fbd73 (ac1db76). Items above
remain as written for their commits; this round changes what they describe where it is stated.
- **"Not found" and "conflict" messages carry only allowed daemon phrases, otherwise a fixed sentence**:
  a "not found" or "conflict" (HTTP 409) error keeps the sanitized daemon text in the message only when
  the entire text matches one of the phrases that name the tenant's own objects (the comparison is
  case-insensitive): `No such container: <ime>`, `No such image: <referenca>`,
  `No such volume: <ime>`, `No such exec instance` (optionally with `'<id>' found in daemon` or
  `: <id>`), `<kontejner> is not running`, `container name "/<ime>" is already in use`,
  `removal of <kontejner> is already in progress`, and `<kontejner> is paused`. `<kontejner>` is
  "the sandbox container" (the container id is replaced by those words during sanitizing) or `container
  <ime>`; `is not running` also accepts a bare name. Any other text gives the fixed sentence
  "the object does not exist" (not found) or "the operation conflicts with the current
  state" (conflict), and the daemon text goes to `daemon_text`. A full-disk conflict keeps its own
  fixed sentence (ac1db76, `src/sandfort/drivers/docker/client.py`,
  `tests/test_generic_driver_error_text_r35.py`).
- **The pull-rejection sentence gives "not found" only on pull and build**: the Docker
  Hub sentence "the image could not be pulled" maps to `DriverNotFound` with its own text only for
  the `image.pull` and `image.build` operations. On every other operation the same sentence gives
  "the object does not exist", and the text goes to `daemon_text` (ac1db76,
  `src/sandfort/drivers/docker/client.py`).
- **Image build: 404 "No such image" gives "no such image or snapshot"**: an error from the build
  call itself keeps the type `DriverNotFound`. When it does not recognize a build step sentence, the message is
  "image build failed: no such image or snapshot: <reference>", and the daemon text (which may
  name host paths) does not enter the message (ac1db76, `src/sandfort/drivers/docker/build.py`,
  `tests/test_image_build_errors_r35.py`).
- **Pull and build errors are logged at `INFO` level, other operations at `WARNING`**: the
  `docker <operation> failed (...)` line from the item above has level `INFO` for `image.pull` and `image.build`
  (the tenant determines how many of them fail, and the classifiers already log the outcome), and level `WARNING` for all
  other operations. The content of the line is unchanged (ac1db76,
  `src/sandfort/drivers/docker/client.py`).
- **Driver errors do not carry daemon text when serialized**: `DriverError` defines
  `__reduce__`, which keeps only the type, the message, and `ref`; `daemon_text` is omitted, so an error
  that went through `pickle` or copying comes back without it (ac1db76,
  `src/sandfort/drivers/errors.py`).

#### Round 34: follow-up fixes and additions
Dates are commit dates (2026-11-07).
- **SDK: `run_stream` on the code context and `OutputChunk`**: `ctx.run_stream(code, timeout_s=60)`
  (sync) and `await ctx.run_stream(...)` (async) return an event stream: `OutputChunk` (`stream` is
  `"stdout"` or `"stderr"`, `data` is text) for each output event, then as the last item
  the same `CellResult` that `run` returns. Errors before the stream starts (`NotFound`, `NoContainer`,
  `ValidationFailed`) are raised by the `run_stream` call itself; a stream that ends without a result raises
  `TransportError`. The stream is closed with `close()` / `with` (async: `aclose()` / `async with`).
  `OutputChunk`, `CellStream`, and `AsyncCellStream` are exported from `sandfort_sdk`. The SDK sends
  `POST /v1/sandboxes/{id}/toolbox/code-contexts/{context_id}/run/stream` with
  `Accept: text/event-stream` and waits at most `2 * timeout_s` for a read. This commit changes only the SDK
  and its tests use a fake transport. **Correction:** the server has that route since d43eec1
  (`stream_code_context_run` in `src/sandfort/api/routes/toolbox/code_contexts.py`): it responds with
  `text/event-stream` with `stdout` and `stderr` events, then one final `result` event
  (or an `error` event if an error occurs after the stream starts), and 83dd69e records it in
  `openapi/sandfort.v1.json` (27f3931,
  `sdk/python/src/sandfort_sdk/code_contexts.py`, `_transport.py`, `__init__.py`).
- **The run's private directory is not visible in the `__main__` module's representation**: user code
  runs in the `__main__` module whose `repr` is `<module '__main__' from 'main.py'>`, so messages such as
  "Can't get attribute 'M' on <module '__main__' ...>" from `pickle` do not reveal the path
  `/tmp/.sandfort-run-<random>/`. The module's `__file__` still holds the real script path
  (b620c4d, `src/sandfort/toolbox/code_run.py`).
- **Audit routes reject a key with a label scope**: `GET /v1/audit-events`,
  `GET /v1/audit-events/export` and `GET /v1/audit-events/verify` respond with 403
  ("audit events are org-wide; use an API key without sandbox labels") when the key has
  `sandbox_labels`, even if it holds the `audit:read` scope. Reason: audit events belong to the whole
  org, and a label scope limits only sandboxes. To read the audit, use a key without
  labels. The same commit adds an `order` argument to `AuditRepository.list` in the port, with no change in
  behavior (41f9d3e, `src/sandfort/api/routes/audit.py`,
  `src/sandfort/db/repositories/ports.py`).
- **A slow or failed kernel query does not remove a healthy code context**: when a run of a stuck cell
  times out at the exec deadline, the kernel query has three outcomes. The context is removed only when the query ends with
  "no live kernel" (exit 1) or when the interrupted kernel does not report that the cell is done. A query
  that timed out, returned another exit code, or raised `DriverError`, as well as a removal that did not
  succeed, leave the context; the run then reports `timeout` (stderr: "the cell did not return in
  time and was interrupted; the context was kept"), not `context_lost`. `context_lost` means
  that the context was actually removed (792a988, `src/sandfort/toolbox/code_contexts.py`).
- **The SDK waits for `Retry-After` on 503**: a 503 with a `Retry-After` header waits at least that long
  (at most 30 s, `RETRY_AFTER_CAP_S`), or its own jitter back-off if that is longer; a 503 without
  the header keeps only the back-off. Only calls that are safe to repeat are retried,
  as before. The comment on `STOP_REASON_CONTEXT_LOST` says that a run with that reason still has exit
  code 124 and `timed_out` true (d6435d8, `sdk/python/src/sandfort_sdk/_requests.py`,
  `sdk/python/src/sandfort_sdk/stop_reasons.py`).
- **The terminal limit reports 30 s**: a 503 `CAPACITY` due to the limit on live terminals per
  org carries `Retry-After: 30` (instead of 5) and the message "the org already has N live terminals;
  a slot frees when a terminal closes", because the slot is freed only when a terminal closes.
  Other 503 `CAPACITY` responses stay at `Retry-After: 5` (d6435d8, `src/sandfort/toolbox/pty.py`).
- **CLI: `key list` shows the expiry date again, and the JSON carries the status**: the table has the column
  `EXPIRES` after `STATUS` (UTC, `YYYY-MM-DD HH:MM`, `-` for a key that does not expire). Rows
  `--json` get a `status` field (`active`, `expired`, or `revoked`, the same value as in
  the table); `expires_at` stays ISO 8601 (77461d4, `cli/src/sandfort_cli/keys.py`).
- **Documentation pages do not load third-party images**: the CSP of the documentation pages has
  `img-src 'self' data:` instead of `img-src 'self' data: https:` (657726d,
  `src/sandfort/api/security_headers.py`).
- **Audit: an operator re-anchor acknowledges historical chain breaks**: new admin command
  `audit-reanchor --org ORG_ID --note TEXT` (a note of 1 to 1000 characters is required). It runs a full
  verify of that org; if there are unacknowledged findings, it adds one chain event
  `audit.chain_reanchored` (actor `platform_admin` / `sandfort-admin`, in the details
  `acknowledged_through`, `findings`, and `note`) and prints its id; with no findings it writes nothing.
  Findings on rows up to `acknowledged_through` are reported by verify separately as acknowledged and no longer
  fail verify. No row is changed or removed, all findings remain in the history and in
  `audit-export`, and a later break (after that row, in the re-anchor event itself, or after it)
  still fails verify. `GET /v1/audit-events/verify` gets the fields `acknowledged_findings`
  (the number acknowledged) and `reanchored_by` (the id of the last re-anchor event); both are omitted from
  the response while they are 0 and `null` respectively, and `findings` lists only unacknowledged findings. `audit-verify`
  on success prints "ok: N audit rows verified (M acknowledged finding(s))" (d96b196,
  `src/sandfort/admin_cli.py`, `src/sandfort/services/audit_chain.py`,
  `src/sandfort/api/routes/audit.py`, `src/sandfort/api/schemas/audit.py`).
- **The sandbox object records its source: the `snapshot` field**: the sandbox response (`SandboxResponse`) has
  a `snapshot` field: the snapshot id (`snap_...`) or the image reference from the create request. The name
  of your org's snapshot is stored as its id; an image reference (or a name that does not
  match any visible snapshot) is stored as given. Creating without
  `snapshot` leaves `null`, and sandboxes created before the migration also have `null`. The value is
  set at creation and does not change later. Migration `0017` adds a nullable column
  `sandboxes.snapshot` without a backfill. The SDK field `SandboxInfo.snapshot` (and `sbx.snapshot`) already
  read this field and stayed `None` because the server did not send it (8c0593a,
  `src/sandfort/api/schemas/sandboxes.py`,
  `src/sandfort/migrations/versions/r0017_sandbox_snapshot.py`; test
  `tests/test_sandbox_snapshot_field_r34.py`).
- **Sandbox object: `error_code` alongside `error_reason`**: the sandbox response gets `error_code`,
  a machine-readable code alongside the `error_reason` text; `null` when there is no error and for errors recorded
  before the migration. The code is chosen by exception type or kind of deviation, never by message text.
  Values: `image_not_found` (the driver did not find the image or snapshot at creation),
  `start_failed` (another driver error at creation or start), `timeout` (a driver operation
  exceeded the deadline), `reset_failed` (the driver failed during a reset, after removing
  the old container), `container_missing` (reconciler: the container of a started sandbox has vanished
  or exists but was never started), `container_exited` (reconciler: the container exited;
  the sandbox is `stopped` and can be started again), `node_lost` (reserved: no path
  sets it yet), and `internal` (everything else). `error_code` is set and cleared together with
  `error_reason`; a successful start clears it. Sandbox events carry `error_code` alongside `reason` in
  the payload. Migration `0018` adds a nullable column `sandboxes.error_code` without a backfill.
  SDK: `SandboxInfo.error_code` (`None` with no error or when the server does not send the field) and
  `SandboxFailedError.error_code`, which is also carried when `create_sandbox` deletes the sandbox
  (34ded76, `src/sandfort/domain/sandbox.py`, `src/sandfort/api/schemas/sandboxes.py`,
  `src/sandfort/migrations/versions/r0018_sandbox_error_code.py`,
  `sdk/python/src/sandfort_sdk/models.py`, `exceptions.py`; test
  `tests/test_sandbox_error_code_r34.py`). Limits: the handle (`sbx`) has no `error_code` property,
  it is read as `sbx.info.error_code`; errors recorded before migration `0018` stay with
  `error_code` `null`. (Correction in round 35: the SDK handle now has an `error_code` property, see
  the item on typed codes.)
- **The CLI shows `error_code`**: commands that print a single sandbox add an `error_code` row when
  the code is set, the REASON column in `sandbox list` shows `<error_code>: <error_reason>`, and
  `--json` carries `error_code` in the sandbox object and in the `SANDBOX_FAILED` error. In the SDK,
  `SandboxInfo.error_code` was moved to the end of the class so the positional order of the other fields stays the same
  (70eef66, `cli/src/sandfort_cli/output.py`, `sdk/python/src/sandfort_sdk/models.py`).
- **The `sandbox.error` event**: a sandbox that moves to the `error` state publishes one
  `sandbox.error` event through the same outbox as `sandbox.started`, `sandbox.stopped`, and `sandbox.deleted`;
  the payload carries `sandbox_id`, `state`, `reason`, and `error_code`. The type existed in `EventType`, but
  no path published it before (599814c, `src/sandfort/services/events.py`).
- **`snapshot` is not returned to a key with a label scope**: a key with `sandbox_labels` gets
  `snapshot: null` in the sandbox response, because the source may be a snapshot outside its scope. A key
  without labels sees the value as before. The same commit treats "manifest unknown" as an unknown
  reference on pull (fb8459c, `src/sandfort/api/schemas/sandboxes.py`,
  `src/sandfort/drivers/docker/images.py`).
- **SDK: an `error` event in the `run_stream` stream raises the matching exception**: the server sends an `error`
  event instead of `result` when the run fails mid-stream. The SDK now raises it from the iteration as an `ApiError`
  subclass for the event's `code` (a plain `ApiError` for an unknown code), instead of `TransportError`;
  it carries only `code` and `message`. An event whose data is not JSON, or whose `code` or `message` is not a
  string, raises `InvalidResponseError`. `TransportError` remains only for a stream that ends without an
  `error` event and without a `result` (793a07c, `sdk/python/src/sandfort_sdk/code_contexts.py`; test
  `tests/test_sdk_context_stream_error_r34.py`).
- **A cancelled streamed run finishes the cell interrupt**: when the helper function
  `_run_until_disconnect` is itself cancelled (the client left), its exec is cancelled and awaited, shielded
  from further cancellation, so the cell interrupt and the release of the context lock are done when the
  function returns. Previously the exec was only cancelled, without waiting. The same commit also wanted a more honest
  message for a kernel state that cannot be confirmed, but that message **is not implemented**:
  stderr still says "the context was kept", and the test for the new message is marked `xfail`
  (8bbf689, `src/sandfort/api/routes/toolbox/process.py`; test `tests/test_stream_cancel_r34.py`).
- **Audit verify: bounded memory; only a row with actor `platform_admin` is a re-anchor**:
  `GET /v1/audit-events/verify` first looks for the last valid re-anchor (pages of 100, from
  the newest), then walks the chain and keeps at most 100 unacknowledged findings (`MAX_FINDINGS`); it only counts the
  rest, and `findings_truncated` is computed from that total. Acknowledged findings are only counted. When
  walking from the anchor, the last re-anchor on the anchor row or after it applies. An event with the action
  `audit.chain_reanchored` acknowledges findings only if it was written with the actor type `platform_admin`
  (which only `audit-reanchor` does); the same row with another actor type acknowledges nothing, both in the API and
  in the admin commands. Limit: `audit-verify` and `audit-reanchor` still use the verifier without
  bounds and hold all findings in memory (c42eab2, `src/sandfort/services/audit_chain.py`,
  `src/sandfort/api/routes/audit.py`; test `tests/test_audit_reanchor_bounds_r34.py`).
- **Streamed exec gives the same result as plain exec on every driver**: the timeout line
  (stderr "... (timeout); pass a larger timeout_s ..."; the sentence was changed in round 36, see "Timeout message" in Round 36) is now printed by the `exec_stream` of the Docker
  driver, before the `ExitEvent`, and no longer by `exec_run` and `stream_exec` each separately, so all
  stream consumers see it and the result of a streamed run equals the one from `driver.exec`. `FakeDriver` and
  the Firecracker skeleton pass `sandbox_stopped` into `ExitEvent` (cfca89c,
  `src/sandfort/drivers/docker/exec.py`, `src/sandfort/drivers/fake.py`,
  `src/sandfort/drivers/firecracker/driver.py`, `src/sandfort/toolbox/code_context_stream.py`;
  test `tests/test_exec_stream_parity_r34.py`).

#### Round 33: follow-up fixes and additions
Dates are commit dates (2026-11-07).
- **SDK: `SortOrder`, `SandboxTimeoutError.deleted` and `updated_at` on the handle**: `SortOrder`
  (`Literal["asc", "desc"]`) is exported from `sandfort_sdk` and types `order` in `list_sandboxes` and
  `iter_sandboxes` (sync and async). `SandboxTimeoutError.deleted` is `True` exactly when the cleanup
  after a create timeout deleted the sandbox that this call made (the message then says "was deleted"
  and `sandbox_id` names it), otherwise `False`, so an adapter does not have to read the message. A sandbox handle
  has the `updated_at` property (same as `info.updated_at`; `None` until the server sends the time) (ab9980a,
  `sdk/python/src/sandfort_sdk/__init__.py`, `_requests.py`, `exceptions.py`, `handles.py`).
- **A removed stuck context reports `stop_reason` `context_lost`**: when the run's exec deadline
  (`timeout_s` plus 5 s) expires, a cell stuck in native code does not respond to the interrupt even
  after 2 s, and the kernel is stopped and the context removed, the run responds with `context_lost` (previously
  `timeout`). `exit_code` 124 and `timed_out` stay, and `stderr` says the context was stopped.
  A kernel that responds to the interrupt keeps the context and the run stays `timeout`. A later run on
  the removed context responds with 404 (239d4e9, `src/sandfort/toolbox/code_contexts.py`,
  `src/sandfort/api/schemas/toolbox_process.py`,
  `src/sandfort/api/routes/toolbox/code_contexts.py`).
- **The audit event list accepts `order`**: `GET /v1/audit-events?order=asc|desc`. The default is
  `asc` (oldest first); `desc` gives newest first. The order is by id, which follows creation
  time; `next_cursor` continues in the chosen order, so every request sends the same `order`
  (7cdfb86, `src/sandfort/api/routes/audit.py`, `src/sandfort/db/repositories/audit.py`).
- **503 `CAPACITY` carries `Retry-After`**: 5 s by default (`DEFAULT_CAPACITY_RETRY_AFTER_S`). The SDK
  does not wait for it on 503: the pause before resending is the same as for any 503, and the value arrives in
  `retry_after_s` of the `CapacityExceeded` exception (7cdfb86, `src/sandfort/errors.py`,
  `src/sandfort/api/errors.py`).
- **`created_by` is visible only to keys without a label scope**: `POST`, `GET` and `DELETE` responses
  on `/v1/api-keys` return `created_by` `null` to a caller limited to sandbox labels, because the
  id would reveal the key that created it (7cdfb86, `src/sandfort/api/routes/api_keys.py`,
  `src/sandfort/api/schemas/api_keys.py`).
- **Message for invalid JSON**: a body that is not valid JSON gives 422 with the message "request body is
  not valid JSON", without the internal position index (`body.1`) (7cdfb86,
  `src/sandfort/api/errors.py`).
- **CLI: tables and `sandbox delete`**: `sandfort key list` has a STATUS column (`active`, `expired`
  or `revoked`), condensed scopes (the first two names, then "+N more") and no EXPIRES AT and
  REVOKED AT columns; `--json` stays the full object. The `sandbox list` table has a CREATED column (UTC,
  `YYYY-MM-DD HH:MM:SS`). `sandfort sandbox delete` is a hidden alias for `sandbox rm` (same
  arguments, options and output). With `--json`, the create timeout error (`SandboxTimeoutError`) carries in
  `error.details` `sandbox_id` (when known) and `deleted` (e869e66,
  `cli/src/sandfort_cli/keys.py`, `output.py`, `sandboxes.py`).
- **`/docs` and `/redoc` pages with Subresource Integrity and no inline script**: every bundle from
  `cdn.jsdelivr.net` has `integrity` (sha384) and `crossorigin`; Swagger UI is started by a script from
  the same origin (`/docs/init.js`), so no page has an inline script. The pages' CSP:
  `script-src 'self' https://cdn.jsdelivr.net`, `'unsafe-inline'` only in `style-src`, and Google
  Fonts are no longer allowed. The pages and the script are not in the OpenAPI document and do not require
  authentication (b2df569, `src/sandfort/api/docs_pages.py`, `security_headers.py`).

#### Round 32: follow-up fixes and additions
Dates are commit dates (2026-11-07).
- **CLI `--json` sandbox output carries times**: `created_at` and `updated_at` are ISO 8601 strings, and
  `print_json` has a fallback serializer for `datetime`. Commands that print a single sandbox
  (`sandbox create`, `get`, `start`, `stop`, `reset`) list both times in the field output too when
  the server sends them (380be27, `cli/src/sandfort_cli/output.py`).
- **`sandfort key list` prints full ids and hides revoked keys**: the ID column is never
  truncated, so the id can be copied into `key revoke`. Revoked keys are not shown (not in `--json` either)
  except with the new `--all` option (`-a`). The SDK `list_api_keys()` does not filter (380be27,
  `cli/src/sandfort_cli/keys.py`).
- **SDK `SandboxInfo.updated_at`**: the field is `None` until the server sends the time; `created_at` on
  the handle stays as it was (380be27, `sdk/python/src/sandfort_sdk/models.py`).
- **Sandbox list order in the SDK and CLI**: `list_sandboxes(order=...)` and
  `iter_sandboxes(order=...)` (sync and async) accept `"asc"` or `"desc"` (newest first) and send
  it only when set; `iter_sandboxes` sends the same `order` on every page. CLI:
  `sandfort sandbox list --order asc|desc`. Any other value gives 422 from the server (b582bc7,
  `sdk/python/src/sandfort_sdk/client.py`, `async_client.py`, `cli/src/sandfort_cli/sandboxes.py`).
- **The create timeout message says whether the cleanup deleted the sandbox**: if it deleted it,
  `SandboxTimeoutError` states "the sandbox it made (sbx_...) was deleted, so nothing is left
  behind" and carries `sandbox_id`; otherwise it says the create may still finish on the server (b582bc7,
  `sdk/python/src/sandfort_sdk/handles.py`, `_create_cleanup.py`).
- **Persistent context: the context cwd is first on `sys.path`, and the hint for `spawn` goes to
  `stderr` too**: a module file in the context working directory is imported as in `code_run`, and the private
  kernel directory is no longer on the path. The hint about `spawn`/`forkserver` children, which ends
  `error.message`, is also written as the last line of `stderr` (d019083,
  `src/sandfort/toolbox/code_context_kernel.py`).
- **401 for a revoked or expired key leaves an audit record**: `request.denied` in the chain of the
  key's org, with `reason` `revoked` or `expired` in the details, at most one per key in 60 s per
  server process (bounded in-memory map). Unknown, malformed and wrong-secret keys are not
  recorded because the org is not known (e915a65, `src/sandfort/auth/authenticate.py`,
  `src/sandfort/api/errors.py`; `docs/governance.md`).
- **`/docs` and `/redoc` load pinned versions from `cdn.jsdelivr.net` and have a CSP**: Swagger UI
  `swagger-ui-dist@5.17.14`, Redoc `redoc@2.2.0`, the page sends its own
  `Content-Security-Policy`, and the favicon is a `data:` URI (no favicon from another host). The pages
  still load the pinned Swagger UI or ReDoc bundle from `cdn.jsdelivr.net`, and ReDoc loads
  Google Fonts; the page CSP allows all of this (a90478f, `src/sandfort/api/app.py`,
  `security_headers.py`).
- **`HEAD /v1/status` responds 200**: status and headers as for `GET`, including content length,
  without a body; not in the OpenAPI document (a90478f, `src/sandfort/api/routes/health.py`).
- **An empty `from_id` on `GET /v1/audit-events/verify` gives 422** (a90478f,
  `src/sandfort/api/routes/audit.py`).
- **Stopping a persistent context at the output limit reports `exit_code` 137**, regardless of which stream
  exceeded it (a90478f, `src/sandfort/api/schemas/toolbox_process.py`).
- **One description of a cell stuck in native code in the OpenAPI operation descriptions**: the own `timeout_s`
  of the cell, the interrupt, then the exec deadline expiring (`timeout_s` plus 5 s) and only after a 2 s delay
  the context removal; the queue behind the cell; an interrupt never removes the context, and `DELETE`
  removes it immediately (8767ce0, `src/sandfort/api/routes/toolbox/code_contexts.py`).
- **`NotFound` on `get` by name carries the `request_id`** of the last list page it searched
  (df9be27, `sdk/python/src/sandfort_sdk/_requests.py`, `client.py`, `async_client.py`).
- **Static sites (the docs site and the landing page) send security headers**: `nosniff`,
  `X-Frame-Options`, `Referrer-Policy` and CSP, and their 404 pages do not carry the nginx version. The same
  applies to `/metrics` and `/console` on the API host, which are routed to the landing server. Other
  error pages made by the shared hosting proxy may still show its
  defaults. The hosting configuration is not in this repository, so for this item
  there is no commit or test in it.

#### Round 31: follow-up fixes and additions
- **The snapshot export sanitizer test builds its own "leaky" image with a raw `docker commit`**:
  a test-only fix, with no change to server behavior (a4ff361,
  `tests/test_snapshot_export_sanitize.py`). (2026-11-06)
- **A toolbox call on a deleted sandbox says it was deleted**: for the states `destroying` and
  `destroyed` the toolbox guard responds 409 `no_container` with the message "the sandbox was deleted;
  create a new one" and `details.state`, instead of the generic message "sandbox is destroyed; toolbox calls
  require a started sandbox" (238cd17, `src/sandfort/toolbox/guards.py`). (2026-11-06)
- **Sandbox objects carry `created_at` and `updated_at`**: both fields are UTC times with an offset
  (ISO 8601). `created_at` does not change, `updated_at` moves forward on every change to the record, for
  example a state change. Therefore the cleanup after a create timeout in the SDK now works on this server
  (previously the server did not send `created_at`, so the cleanup always left the sandbox); the warning for
  a sandbox without `created_at` now says how to delete it manually (f9db65e,
  `src/sandfort/api/schemas/sandboxes.py`, `sdk/python/src/sandfort_sdk/_create_cleanup.py`).
  The full guarantee remains `idempotency_key`. (2026-11-06)
- **Persistent Python context: cell output is buffered, the limit notice goes on its own line, and
  a `spawn`/`forkserver` hang gets a hint**: the kernel collects the writes of each stream and
  sends them as one frame at 64 KiB, every 50 ms and at the end of the cell, so a loop with many
  small `print` calls does not cost one frame per line. The output limit notice starts on
  its own line in `stderr`. A cell that times out or is interrupted while children started with
  `spawn` or `forkserver` are alive gets a line "hint: ..." in `error.message` with instructions for
  `multiprocessing.get_context("fork")`. The hang only gets an explanation, it does not go away
  (1a8b3c0, `src/sandfort/toolbox/code_context_kernel.py`, `code_contexts.py`). (2026-11-06)
- **The sandbox list accepts `order=desc`**: `GET /v1/sandboxes?order=desc` returns the newest sandbox
  first, the default is `asc` (oldest first). `next_cursor` continues in the chosen order, so
  all pages are requested with the same `order`. The SDK and CLI do not expose it yet (1e92ba0,
  `src/sandfort/api/routes/sandboxes.py`). (2026-11-06)
- **Audit verify from an anchor**: `GET /v1/audit-events/verify?from_id=<id>` starts the walk from that
  row. The anchor's hash is recomputed, every later row is checked as in a full walk, and the response
  carries `anchor_id`. It proves the chain from the anchor onward, not the history before it, and does not compare the link
  of the anchor with the previous row. An unknown id or an id from another org gives 404. The `from` and
  `to` filters of the event list already exist (175ec2a, `src/sandfort/api/routes/audit.py`,
  `src/sandfort/services/audit_chain.py`). (2026-11-06)
- **Security headers and the scope of node data**: every API response carries
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`, and
  JSON and empty responses also carry `Content-Security-Policy: default-src 'none'; frame-ancestors
  'none'`; HTML pages that the application serves itself keep their own policy, and a header
  that a route already sets is not overwritten. The middleware builds the 500 response itself when an exception reaches
  it before the first byte. `GET /v1/nodes` rejects a key with sandbox labels with 403, because it counts
  the sandboxes of all tenants on the host (7960ffd, `src/sandfort/api/security_headers.py`,
  `src/sandfort/api/routes/nodes.py`). (2026-11-06)
- **SDK: typed conflicts, `get_sandbox` and request id on a failed create**: 409 is chosen by
  `details.reason`: `NameTaken` (`name_taken`) and `NoContainer` (`no_container`, attribute `state`)
  are subclasses of `Conflict`, so `except Conflict` catches both, and other 409s stay a plain `Conflict`.
  `client.get_sandbox(ref)` is the same call as `client.get(ref)` (sync and async).
  `SandboxFailedError` carries `request_id` (the `x-request-id` header of the response that showed
  the failure), and `sandfort sandbox create --json` repeats it as `error.request_id` (d950865,
  `sdk/python/src/sandfort_sdk/exceptions.py`, `cli/src/sandfort_cli/sandboxes.py`).
  (2026-11-06)
- **CLI: `sandfort key create`, `key list` and `key revoke`**: key creation (`--scope`,
  `--label`, `--max-sandboxes`, `--expires-at`) prints the secret once to stdout, and a warning to
  stderr. `key list` shows metadata, including revoked keys; `key revoke` accepts
  multiple ids and `--if-exists`. The global `--json` prints the whole structure. All three commands require
  scope `api_keys:admin` (e05f7fb, `cli/src/sandfort_cli/keys.py`). (2026-11-06)
- **Creating a sandbox by snapshot name**: the `snapshot` field in `POST /v1/sandboxes` accepts a snapshot
  id, an org snapshot name or an image reference. An org snapshot name takes
  precedence over an image of the same name, and a value that matches no snapshot stays
  an image reference. State and label scope checks apply as when creating by id (d9769e4,
  `src/sandfort/services/sandboxes.py`). (2026-11-06)
- **Persistent Python context operation descriptions in OpenAPI**: the create, list, delete,
  interrupt and run routes have a description (scope, `result` and `error`, `queue_timeout`, `context_lost`,
  context loss on reset, stop and delete) (fef86c0,
  `src/sandfort/api/routes/toolbox/code_contexts.py`). (2026-11-06)

#### Round 30: follow-up fixes
- **Snapshot export: the tar filter copies each byte a bounded number of times and detects a truncated
  stream**: the filter that drops `/.sandfort-reserve` from the export copies each input byte at most
  twice on the way to `tarfile`, and clears the archive member list after each member, so memory does not
  grow with the number of files. The input must end with the end-of-archive marker: a stream cut at the boundary
  of a header, in the middle of a header or on garbage raises `tarfile.ReadError` instead of ending silently
  (5c970aa, `src/sandfort/drivers/docker/tar_filter.py`). (2026-11-06)
- **Audit: the client IP comes from the address reported by uvicorn, and header values are
  bounded**: `ip` in the audit row is the address from the ASGI scope. The application no longer reads `X-Forwarded-For`
  itself (the caller could spoof it); uvicorn applies it only when the peer is in
  `SANDFORT_FORWARDED_ALLOW_IPS`. An address longer than 45 characters (the column width) is written as `null`,
  and a `User-Agent` longer than 512 characters is truncated to 512. It replaces the 2026-11-03 item that
  named the first entry from `X-Forwarded-For` (5dae517, `src/sandfort/api/middleware/request_id.py`).
  (2026-11-06)
- **`X-Content-Type-Options: nosniff` on 500 responses too**: an unhandled exception produces a response
  built by Starlette `ServerErrorMiddleware`, outside `SecurityHeadersMiddleware`, so that middleware
  did not see it. The error handlers now set the header themselves on each of their responses, including
  500 (5dae517, `src/sandfort/api/errors.py`). It supplements the 2026-11-06 item (c374dc6) that
  named every response. (2026-11-06)
- **Persistent Python context: each cell has its own name in the traceback**: cells are named `<cell-N>`
  (counter per kernel), so a function defined in an earlier cell shows its own source line
  when a later cell calls it. The source is kept for the last 100 cells, older ones are deleted.
  A syntax error still names `<cell>` (5dae517, `src/sandfort/toolbox/code_context_kernel.py`).
  (2026-11-06)
- **SDK: cleanup after a create timeout deletes only the sandbox that this call made**: with
  `wait=True`, `delete_on_failure` and `name`, the client looks up the name once before the POST (that lookup is not
  counted in `wait_timeout_s`). After a POST that was sent times out, it tries once to delete the sandbox
  under that name, and only if the name was free before the call and the `created_at` of that sandbox is
  no earlier than the moment before the POST (with 60 s of tolerance for clock difference). A name that already belonged
  to a live sandbox, an older sandbox or a sandbox without `created_at` stay, and the warning names its
  id. When the timeout occurred before the request left the client
  (`RequestTimedOut.request_sent` is `False`), nothing is deleted (0b1fd99,
  `sdk/python/src/sandfort_sdk/_create_cleanup.py`). (2026-11-06)
- **SDK: 429 `RATE_LIMITED` is retried safely, and a blocking create has a single deadline**: 429
  `RATE_LIMITED` is retried only when the body can be sent again (JSON, bytes or no body).
  An upload from a file object is a read-once stream: after `RATE_LIMITED` it is not sent again
  and `RateLimited` is raised immediately. With `wait=True`, a single deadline of `wait_timeout_s`, started just before
  the create request, bounds the whole blocking create: the POST (its timeout is the remaining time),
  the pauses before resending and the wait for `started`. A pause that would pass the deadline is not taken; instead
  an error is raised. It replaces the read timeout of `wait_timeout_s` plus 5 s from item 73f6fcc (0b1fd99,
  `sdk/python/src/sandfort_sdk/_requests.py`, `_transport.py`, `client.py`). (2026-11-06)
- **CLI: `sandbox list` shows labels and reasons literally**: table cells and the title are `Text`,
  not a string, so `[red]x[/red]` or `[/x]` in a label or reason is data, not markup. In
  the `LABELS` and `REASON` columns, runs of whitespace (newlines, tabs) become a single space, and other
  C0 and C1 control characters (including ESC) are dropped before truncation to 32 characters (01cd0d8,
  `cli/src/sandfort_cli/output.py`). (2026-11-06)
- **Persistent Python context: interrupt edge cases**: (1) SIGINT is blocked from the end of the code of the
  cell until the response is sent, so a late interrupt does not hit the cleanup and the response is not lost. (2) Each run
  has a cell number that the kernel checks: an interrupt due to cancellation, disconnect, `output_limit` or
  exec timeout names its own cell and never stops the cell of the next run; an interrupt that
  arrives before the kernel started the cell makes the kernel skip it (the run ends as
  an interrupted cell). (3) The `interrupt` route and `ctx.interrupt()` do not name a cell and interrupt the one that
  is currently running. (4) An interrupt reaches only Python code: a cell stuck in native code may
  keep running, and the next run then queues behind it until that cell's timeout expires. The earlier
  claim that the next run does not queue behind an interrupted cell holds only for a cell that finishes within
  the 2 s wait. (5) The run's `stdout` is limited to 1 MiB minus 64 KiB to leave room for `result`
  and `error`; `result`, the error type and message are truncated to 4096 characters with `... [truncated]`
  (the printed `repr` in `stdout` stays whole). (6) The pid from the pid file is trusted only when
  `/proc/<pid>/cmdline` has `<dir>/kernel.py` as an argument (e6f96e2,
  `src/sandfort/toolbox/code_context_kernel.py`, `code_contexts.py`,
  `src/sandfort/api/routes/toolbox/code_contexts.py`). (2026-11-06)

#### CLI
- **`sandbox list` shows labels and the error reason, and `--wait-timeout` also limits the blocking
  create**: the table has the columns `LABELS` (`key=value` pairs) and `REASON` (the `error_reason`
  of a sandbox in state `error`); a cell longer than 32 characters ends with three dots. The `--json` error
  `SANDBOX_FAILED` carries `sandbox_id`, `state`, `error_reason`, `deleted`, and `request_id`.
  `sandbox create --wait --wait-timeout S` now also limits the create request itself through the SDK (read
  timeout of S seconds plus 5; replaced by a single deadline, see "Round 30"), which on the hosted beta
  returns a response only when the sandbox is started
  (fcf8f56, `cli/src/sandfort_cli/output.py`, `sandboxes.py`; 73f6fcc). (2026-11-06)
- **`sandbox rm` and `sandbox create` for CI scripts**: `sandbox rm REF [REF ...]` deletes in order and
  prints only the id of each deleted sandbox (`--json`: an object for one ref, a list for several);
  `--if-exists` skips a nonexistent name, an id with a `NOT_FOUND` response, or an already destroyed sandbox with
  a note on stderr, while other errors (ambiguous name, auth, network, 5xx) still fail.
  `sandbox create --wait --wait-timeout SECONDS` passes the wait deadline to the SDK (without `--wait` it is
  a usage error), and `--keep-on-failure` passes `delete_on_failure=False`
  (`cli/src/sandfort_cli/sandboxes.py`, `refs.py`).

#### Security
- **`X-Content-Type-Options: nosniff` on every API response**: `SecurityHeadersMiddleware`
  (`src/sandfort/api/security_headers.py`) adds the header at the start of every HTTP response, including
  JSON, error responses, and a streamed response (e.g. a snapshot export); the body is not
  touched. The console and the web terminal page already had it (c374dc6, `tests/test_r30e_messages.py`).
  The 500 response for an unhandled exception is built by Starlette outside that middleware; it is covered by 5dae517
  (see "Round 30"). (2026-11-06)
- **Audit: API key events carry request context, and quota denials are recorded**:
  `api_key.created` and `api_key.revoked` now write the request id, client IP, and user agent (the route
  passes a correlated recorder to the key service); previously those fields were `null`. A rejected
  request with 429 and the code `QUOTA_EXCEEDED` (org quota or the key's `max_sandboxes`) is written
  as `request.denied` with outcome `denied`; 429 `RATE_LIMITED` is still not recorded, so that a retry
  loop does not fill the chain (9571d1a, `src/sandfort/api/errors.py`,
  `src/sandfort/api/routes/api_keys.py`). Remaining: `docs/governance.md` still states the old description for
  keys. (2026-11-06)
- **A snapshot from a sandbox does not carry the sandbox's env values**: `commit_container` now, before the commit,
  reads the container and its base image and passes the commit a `conf` whose `Env` is the image's base `Env`
  unchanged, plus `KEY=` (empty value) for each key the sandbox added; a key that
  the sandbox overwrote (e.g. `PATH`) gets its base value back (`src/sandfort/drivers/docker/images.py`,
  `commit_env.py`). Previously the saved image carried the container's whole `Env`: user env
  values (the API masks them as `***`) and variables the platform injects (the egress proxy URL
  with a signed token), so `env` in a sandbox created from the snapshot printed the secrets
  of the source sandbox. Limit: a Docker commit can empty a key but not remove it, so keys
  remain with an empty value. Snapshots created before this change can still carry env
  values; if the source sandbox had secrets in `env`, the snapshots should be deleted or created again.
  The export route had already cleaned `Env` earlier. (5fa64d8, 2026-11-06)
- **Image references and scope of label-scoped keys**: a user image reference that is an image ID
  (`sha256:<hex>`, bare or short hex) or names the reserved repository `sandfort-snapshot`
  or `moby-dangling` is rejected with 422 when creating a sandbox, for the `base_image` of an image build, and when
  registering a snapshot (`check_user_image_reference`, `src/sandfort/images/dockerfile.py`)
  (c4ad194, c6ee3dd, 9a46b00). Previously Docker resolved such a reference against the host's local
  image store, so a caller who knows the digest of another org's snapshot, or guesses
  short ids, could start a sandbox from someone else's committed snapshot. A snapshot is now fetched only by
  snapshot id. Deployed to the hosted beta 2026-11-05; audit of the beta database: no sandbox was ever
  created from an image ID or from a `moby-dangling` reference, and no sandbox runs from
  another org's snapshot (this checks only existing snapshots; deleted snapshot rows are
  removed, so older history cannot be verified). Keys with a scope by labels: every
  toolbox route under a sandbox id checks the scope through a guard at the router level (80fad83); a key with
  `api_keys:admin` lists and revokes only keys within its own scope (e308c00); a snapshot committed
  from a sandbox is visible and usable only if the source sandbox is in scope, and a destroyed source is still
  evaluated by its labels (c4ad194); build logs and jobs follow the same rules, build and
  snapshot jobs require `snapshots:read`, and the build spec is not returned to a caller with a scope; the check
  of whether a snapshot is in use sees all of the org's sandboxes; idempotency keys apply per API
  key (9bd888e, 9a46b00). Open: sandbox names are unique per org, so a create
  with a name used by an out-of-scope sandbox responds 409 and reveals that the name exists. Documentation:
  `docs/governance.md` (new section "Image reference policy"), the beta connect guide.
  (2026-11-04/05)

#### Added
- **Persistent Python context: cell interrupt**: `POST
  /v1/sandboxes/{id}/toolbox/code-contexts/{context_id}/interrupt` (scope `toolbox:use`, audit
  `toolbox.code_contexts.interrupt`) sends SIGINT to the kernel: a running cell raises `KeyboardInterrupt`
  (a cell error, the state remains), between cells it does nothing; the response `interrupted` is `false`
  when the context has no live kernel. A run whose client has gone away (dropped connection or cancelled task) and a run
  that hit the output limit (`output_limit`) interrupt their cell before the next
  run starts, so nothing queues behind a cell that nobody is waiting for (1dd3da9,
  `src/sandfort/api/routes/toolbox/code_contexts.py`). Limits of the interrupt (a cell in native code,
  an interrupt without a named cell through the route) are described in the item "interrupt edge cases" in
  "Round 30". Remaining: the committed `openapi/sandfort.v1.json`
  does not yet contain the `interrupt` route. (2026-11-06)
- **Persistent Python context: run outcomes**: the run response carries `result` (the `repr` of the final expression) and
  `error` (`{"type", "message"}` of the exception the cell raised), and `stop_reason` gets two
  values for contexts only: `queue_timeout` (the run waited for another run of the same context longer than
  its `timeout_s`, exit 124, `timed_out` true, the context remains) and `context_lost` (the kernel
  died or closed the connection in the middle of a run, or the context was deleted in the middle of a run) (5a5d364,
  `src/sandfort/toolbox/code_contexts.py`, `src/sandfort/api/schemas/toolbox_process.py`).
  (2026-11-06).
- **SDK: `RATE_LIMITED` is retried for all methods, typed exceptions, bounded blocking
  create, `with` on handles**: a 429 with the code `RATE_LIMITED` is retried for every method (also
  for `POST` without a key, `PUT`, and `PATCH`), because the server did not process the request; `QUOTA_EXCEEDED` is still
  never retried. New exceptions `IdempotencyMismatch` (422) and `ServiceUnavailable` (every
  503; `CapacityExceeded` is a subclass for `CAPACITY`; both have `retry_after_s`); all derived from
  `SandfortSDKError`. `create_sandbox(wait=True)` honors `wait_timeout_s` even when the server holds create
  open until start: the read timeout is `wait_timeout_s` plus 5 s, and expiry raises `SandboxTimeoutError`
  (create may still finish on the server; with `idempotency_key` the same call returns the sandbox, and with
  `delete_on_failure` and `name` the client tries once to delete the sandbox by name). Replaced in
  0b1fd99: a single deadline for the whole create, and deletion by name only for a sandbox that this call created
  (see "Round 30"). `Sandbox` and
  `AsyncSandbox` are context managers that delete the sandbox on exit (a sandbox that has already gone away
  is ignored) (73f6fcc, `sdk/python/src/sandfort_sdk/handles.py`, `_requests.py`, `exceptions.py`).
  (2026-11-06)
- **SDK: context interrupt, `CellResult`, `StopReason`**: `ctx.interrupt()` (sync and async) returns
  `True` when an interrupt was sent to the kernel, `False` when there is no live kernel. `ctx.run(...)` returns `CellResult`:
  all `ExecResult` fields plus `result` and `error` (`CellError` with `type` and `message`). The module
  `sandfort_sdk.stop_reasons` exposes a `StopReason` literal with all values, including
  `queue_timeout` and `context_lost`. `CodeContext` and `AsyncCodeContext` are context managers that
  delete the kernel on exit (a context that has already gone away is ignored) (f1c052e,
  `sdk/python/src/sandfort_sdk/code_contexts.py`, `stop_reasons.py`). (2026-11-06)
- **Rounds 21-26: `stop_reason`, sandbox reset, `code_run` in the working directory, default
  network block, OpenAPI, and operational documentation**: the result of `process/execute` and
  `process/code-run` has a `stop_reason` field (`timeout`, `output_limit`, `sandbox_stopped`,
  `killed`, or `null` on normal exit); it is derived only from result flags, never from the text
  of the output, and `killed` means SIGKILL (exit 137), including OOM kill. A command stopped at
  `timeout_s` now writes "the command was stopped after N s (timeout)" to stderr (exit 124), and the SDK
  sandbox handle exposes `auto_stop_minutes` and `auto_delete_minutes` (63b3d72). `POST
  /v1/sandboxes/{id}/reset` (SDK `sbx.reset()`, CLI `sandfort sandbox reset`) replaces the container
  of the sandbox with a new one from the same image and the same specification: id, name, labels, resources, env, network
  policy, isolation tier, mounted volumes, and auto timers remain, and everything written to the old
  container is lost. It is allowed from `started` and `stopped` (the state stays the same), and returns 409 in
  other states, while a snapshot is in progress, and when the lifecycle runs as jobs; audit records `sandbox.reset`
  and `sandbox.reset_failed` (975b76f). Reset resilience: a concurrent stop or reconcile does not leave
  an orphan container (409 with the new state), and a driver failure after the old container is removed
  moves the sandbox to `error` with a reason (6be6470); the reconciler skips drift repair only
  for a sandbox with a recent `sandbox.reset` audit event (db7bb93). `code_run` writes the script as
  `main.<extension>` into a private per-call directory under `/tmp`, which is deleted after the call
  (7202c31), and it runs in the sandbox's working directory, so relative paths see the user's
  files; the optional `cwd` field (SDK `sbx.process.code_run(..., cwd=...)`) changes it. The traceback therefore
  shows an absolute path whose file name is `main` plus the language suffix, and the directory changes
  (b58a0ff). `SANDFORT_DEFAULT_BLOCK_NETWORK` (default `false`): a create without a network
  policy gets `block_all`; an explicit `true` or `false` in the request wins, and an egress allowlist (even
  an empty one) keeps its own rules (a5b9390). CLI `sandbox create` accepts `--block-network` and
  `--no-block-network` (b58a0ff). The OpenAPI spec declares error responses (400, 401, 403, 404,
  409, 422, 429, 500), binary operations (upload, download), and SSE operations, has clean
  `operationId`s, and the live spec is equal to the exported one (a55b858); the committed spec was regenerated
  (a5708a2, 714452f) and now has 78 HTTP operations in 60 paths. Fixes: `uvicorn` is a core
  dependency, so a plain install can start the server (2dec3b7), and the audit append on Postgres takes
  `FOR NO KEY UPDATE` only on the org row, which removes a deadlock that under load
  gave 500 on exec (cb01b30, 15d451f). Deploy and operations: a Kubernetes kit for a single
  host-networked sandbox node with a prod configmap, seccomp, probes, NetworkPolicy,
  Ingress, and alerts (65a0310), `deploy/node-setup.sh` prepares Docker storage, gVisor, and
  optional Kata (53166aa), `docs/operations.md` gets topology, upgrade and rollback, backup
  of node data, monitoring, and sizing, and `SECURITY.md` is added to the repo root (4871ea2).
  Documentation: a new recipe `docs/recipes/run-code-button.md` for a "Run code" button for students,
  the beta connect guide gets a section "REST API", `stop_reason`, reset, and instructions for a grader/eval
  harness, and `docs/governance.md` clarifies the encryption of webhook secrets
  (`SANDFORT_WEBHOOK_SECRET_KEY`, required in `prod`) and records reset and
  `SANDFORT_DEFAULT_BLOCK_NETWORK`. Open: there is no published container image, and multi-node
  Kubernetes is not a supported topology by default (see `.context/known-issues.md`).
  (2026-11-05)
- **SDK: `sbx.process.start(command, ...)`**: starts a background command in one call (a new
  session, or an existing one via `session_id=`) and returns a handle with `info()`, `logs()`, `follow()`,
  `kill()`, and `wait()`; leaving `with` / `async with` kills the command if it is still running (e8bab35,
  `sdk/python/src/sandfort_sdk/background.py`). It replaces `create_session` +
  `execute_session_command(run_async=True)` + `kill_command`; without `timeout_s` the default
  budget of 60 s applies. Documented for `AsyncClient`: cleanup after cancellation is guaranteed only
  when the client is closed (`async with AsyncClient(...)` or `await client.aclose()`); a bare
  `asyncio.run` that never closes the client can still leave a cancelled create behind. On the hosted
  beta the create request itself returns only when the sandbox is started, so `wait_timeout_s` does not limit
  create; `asyncio.wait_for(...)` is for that, and cleanup works with it (since 73f6fcc and 0b1fd99
  `create_sandbox(wait=True)` has a single deadline `wait_timeout_s` for the whole blocking create, see
  "Round 30"; `asyncio.wait_for(...)` remains for your own deadline). (2026-11-04)
- **API keys bound to labels, a cancellation-safe SDK, and exec interruption when the
  client disappears**: `POST /v1/api-keys` accepts an optional `sandbox_labels` (`{key: value}`, at most 8
  pairs; names with the prefix `sandfort.` are reserved) (1a5f1d0, 3ecdda8). A key with that scope
  sees and modifies only sandboxes whose labels contain all those pairs: the others respond 404 (existence
  is not revealed), the list is filtered, a create through the key adds the pairs to the labels (a label that
  contradicts the scope is 403 "this API key is limited to sandboxes labelled k=v"), and a label change
  that takes the sandbox out of scope is 403. A key with a scope can create only keys whose scope
  contains all of its pairs (403 with `excess_labels`). Snapshots, volumes, keys, usage, and
  audit remain at the org level, workers are not bound by the scope, and forwarded (multi-node)
  requests carry the caller's credential and are checked on the target node. The SDK and CLI do not manage
  API keys: a key with a scope is created through the REST API. The earlier limitation "scopes apply
  per action, not per sandbox" in `docs/governance.md` has been replaced by this description.
  `AsyncClient.create_sandbox(..., delete_on_cancel=True)` (default): when a task that is waiting
  is cancelled during the create request or while waiting for `started`, the sandbox is deleted in the background (5ab9bca);
  `aclose()` and leaving `async with` wait at most 10 s for those deletions (a5dcef0).
  `delete_on_cancel=False` leaves the sandbox, but a create cancelled mid-request then cannot
  report its id. `SandboxTimeoutError` now carries `sandbox_id` and `state`; `SandboxFailedError`
  carries `sandbox_id`, `state`, and `error_reason`, and the sandbox stays in the `error` state until it is deleted.
  A synchronous exec (`process/execute` and `process/code-run`) is cancelled, and its process tree
  killed, when the client disconnects (the server checks every 0,5 s) (a2384a9). Asynchronous commands in
  a session keep running when the log follower is interrupted; they are stopped with `kill_command`.
  Documentation (`docs/governance.md`, `marketing/pilot/beta-connect-guide.md`) updated:
  the exact canonical form of an audit row with a reference verifier (API key and quota events
  currently do not record IP, user agent, or request id), `link_broken` findings affect only 3 of 5
  evaluation orgs of the beta, 409 `CONFLICT` messages differ only by message, `exec -i`
  accepts only UTF-8 text, `cp` reports archive bytes, and a closed PTY can remain in the list
  while the limit of 8 counts live terminals. (2026-11-04)
- **Governance reference (`docs/governance.md`)**: new documentation for platform and compliance
  reviewers, verified against the code. It covers 12 API key scopes with endpoints per scope (and
  routes without a scope: `/healthz`, `/readyz`, `/metrics`, `/console`, SSO exchange, and the PTY websocket
  is authenticated with a one-time token), rate limit (`SANDFORT_RATE_LIMIT_ENABLED`,
  `SANDFORT_RATE_LIMIT_REFILL_PER_S`, `SANDFORT_RATE_LIMIT_BURST`, 429 `RATE_LIMITED` with
  `Retry-After`), audit (what is recorded and redacted, `request.denied`, hash chain, `audit-verify`,
  `audit-export`, `GET /v1/audit-events/verify` and `/export`, `SANDFORT_AUDIT_RETENTION_DAYS`),
  metering (disk is sampled, not allocated), webhooks (13 event types, Standard Webhooks signature,
  6 attempts, SSRF rules), data retention and deletion, telemetry, and isolation tiers.
  The limitations are stated in the same text: scopes apply per action, not per sandbox or label (for
  binding per sandbox a gateway in front of the API is needed), audit digests for `args` and `stdin` have no salt,
  `/metrics` has no authentication, and the web terminal loads xterm from a public CDN. The connect guide for
  the beta links to that reference, gives a list of scopes instead of advice about a "narrower key", and records the findings
  of round 12 (`/.sandfort-reserve` is not touched, upload over an existing file on `microvm`,
  times for malicious submissions, classification order). (2026-11-04)
- **Per-sandbox disk size outside the `prod` environment and gVisor `/tmp` in the root file system**:
  `SANDFORT_ENFORCE_DISK_QUOTA=true` turns on enforcement of `disk_gib` outside the `prod` environment as well
  (ee34447). If enforcement is requested and the host does not support it (no XFS project quota), the server
  refuses to start instead of silently continuing without a limit (6620ebb). The hosted beta now runs
  on overlay2 over XFS with project quota and has `SANDFORT_ENFORCE_DISK_QUOTA=true`, so
  `disk_gib` is enforced on all three tiers: with `disk_gib=1` a write of 1,5 GiB stops at 1 GiB (1073676288
  bytes; `dd` exits with 1, "no space left"), both in `/tmp` and in `/root`, on `container`, `gvisor`, and
  `microvm`, and the sandbox keeps running (verified on the beta, 2026-11-04). gVisor sandboxes no longer
  have a separate volume on `/tmp`: before every gVisor start Sandfort places an empty marker
  `/tmp/.sandfort-keep`, so gVisor keeps `/tmp` in the root file system. Therefore `/tmp` is covered by
  the disk quota and is included in snapshots on all tiers, and file upload and download under `/tmp` work.
  The marker is not deleted: if `/tmp` is empty at start, gVisor mounts a private in-memory `/tmp`
  that file transfer does not see. gVisor sandboxes created before 2026-11-04 keep the old `/tmp`
  volume until deletion. Self-hosted installations without XFS project quota remain unchanged.
  (ee34447, 6620ebb, e0501cb, 2026-11-04)
- **Dead `microvm`, network without DNS, and isolation tier on the snapshot**: a sandbox on the `microvm` tier
  that dies reports a clean stop message and `sandbox_stopped` instead of a Rust backtrace, even when
  Docker only shows that the container stopped (detection goes by Docker's state, not by the text
  of the error; this also applies to `gvisor`). Sandboxes with `block_network=True` no longer expose the DNS configuration
  of the host: name lookups fail immediately on every tier. A snapshot now records the isolation tier of the sandbox
  it was created from (new `isolation` field on the snapshot, migration 0014), and a sandbox created from
  it without an explicit `isolation` gets the same tier; an explicit `isolation` takes precedence.
  If the recorded tier is not available, creation is rejected with 422 that lists the available tiers.
  Snapshots from a public image or an image spec have no recorded tier. The documentation of the `microvm` tier
  was corrected after a second evaluation on the beta: creation to started takes about 4 s (six measurements
  3,70-3,96 s, median 3,84 s), and about 8-9 s with `block_network=True`; exceeding memory kills
  the program (OOM, exit 137), and the sandbox keeps running; a fork bomb can stop the whole `microvm`.
  (bda761c, 816517d, a916880, 2026-11-04)
- **`microvm` tier enabled on the hosted beta**: `GET /v1/isolation` returns the available tiers
  `container`, `gvisor`, and `microvm`, and the default remains `gvisor`. `microvm` uses Kata
  Containers 4.3.1 (Rust runtime, QEMU) on the KVM of the beta VM (nested virtualization); each
  sandbox has its own guest kernel (it reported 6.18.56, not the host's 6.8). Measured once on the beta:
  creation to started about 4 s (six measurements 3,70-3,96 s, median 3,84 s; start 3,7 s), and about
  8-9 s with `block_network=True` (the other tiers are well under a second). DNS for `microvm`
  goes through the same public resolvers as `gvisor`. On a network with an allowlist a DNS lookup now immediately
  fails on `gvisor` and `microvm` (fail-fast); on the `container` tier names are still resolved through
  the Docker resolver, which is a DNS side channel and is stated in `docs/isolation-tiers.md`. The result
  of exec now carries `sandbox_stopped` (REST field, SDK `ExecResult.sandbox_stopped`; the CLI prints
  a hint to start the sandbox again): true when the sandbox of the command stopped (exceeding a limit
  on `gvisor`). When the command output reaches the limit of 1 MiB, the command is stopped, the result
  has `truncated=true`, and stderr says "the command was stopped because its output exceeded the
  limit of 1048576 bytes". `no_proxy` keys are hidden from the sandbox response. Limitations:
  the per-sandbox disk size is not enforced on the beta (storage has no project quota); the `container` tier
  shares the host kernel; gVisor is a user-space kernel, not a hardware boundary; the Firecracker
  driver is still a skeleton and is not offered. (870a42f, 213dd6d, 2026-11-04)
- **Isolation tiers per sandbox**: isolation is chosen at creation from three tiers, `container`,
  `gvisor`, and `microvm`. Create accepts an optional `isolation` field (omitted means the default
  tier of the deployment), every sandbox response carries `isolation`, and `GET /v1/isolation` returns
  `{"default": ..., "available": [...]}`; a tier that is not available gives 422 with a list of the available ones.
  The deployment maps tiers to Docker runtimes through `SANDFORT_ISOLATION_RUNTIMES` (e.g.
  `container=,gvisor=runsc,microvm=kata`) and selects the default through `SANDFORT_DEFAULT_ISOLATION`.
  SDK and CLI: `isolation=` in `create_sandbox`, `client.isolation()`, `sandfort sandbox create
  --isolation` and `sandfort sandbox isolation`. gVisor fixes: a host-backed volume on `/tmp`
  (file upload and download and `code_run` work under `runsc`), DNS works through `SANDFORT_GVISOR_DNS`
  (ab5db24), and a sandbox that exceeds its limits reports a clean message with exit code 137. A sandbox
  whose container exits on its own now becomes `stopped` and can be started, instead of `error` (4a2866c);
  it is detected within a few seconds through docker exit events (a31a0f3) and through exec.
  The measured overhead of gVisor and the behavior under limits are documented in `docs/isolation-tiers.md`
  (4854d5a): create, exec, CPU-bound work, and file transfer are approximately the same as on `container`, and
  spawn- and small-file-heavy operations are, in our measurements, about 3x to about 9x slower (more for
  fork-heavy shell loops). Limitations: `microvm` (Kata Containers) has meanwhile been enabled on
  the beta (see the item above); gVisor is a user-space kernel, not a hardware boundary; the `container` tier shares the kernel
  of the host. (2026-11-04)
- **Connect guide v6**: aligned with the shipped CLI and with beta facts that the persona
  evaluators found missing — Python 3.12+ as an explicit prerequisite; all new CLI flags
  (`--auto-stop`/`--auto-delete`/`--env`/`--label`/sizing/`--egress`/`--mount`/`--block-network`,
  `snapshot create --wait`, `sandbox list --state/--label`); env variables for agents/CI; `error`
  state and "no such image or snapshot" for a bad reference; a note that the beta runs `runc` (without gVisor);
  that `audit-verify`/`audit-export` are an admin CLI and not an API; that SSO/SCIM are not enabled on the beta; and
  the removal of a dead link to the "security page". (2026-11-03)
- **CLI `sandbox list` filters and `--block-network`**: `sandfort sandbox list` now accepts `--state`
  and `--label KEY=VALUE` (repeatable), so the list does not have to show all `destroyed` tombstone rows;
  `sandfort sandbox create` gets `--block-network` (blocks all outbound traffic). CLI messages about
  errors now also show structured `details` (e.g. the per-sandbox maximum from 422, or the field that
  failed validation), which were previously available only through raw REST. A finding from the persona verification
  round (4 of 5). (2026-11-03)
- **Create-time knobs in the CLI**: `sandfort sandbox create` now exposes `--auto-stop`,
  `--auto-delete` (minutes; negative = never, zero = delete immediately after stop),
  `--env`/`-e` and `--label`/`-l` (both `KEY=VALUE`, repeatable) and `--cpu-millicores`/`--memory-mib`/
  `--disk-gib` (resources; ones not given fall back to SDK defaults). `sandfort snapshot create`
  gets `--wait`, which blocks until the snapshot is ready. Previously these parameters existed
  only in the Python SDK, so a CI user could not set an auto-delete backstop from the command
  line. A finding of the CI/CD evaluation. (2026-11-03)
- **Egress allowlist in the CLI and TypeScript SDK**: `sandfort sandbox create --egress <host>`
  (repeatable) and `egressAllowlist` in TS `createSandbox`. Previously this main network
  restriction was available only through REST and the Python SDK. A finding of an external Node evaluation.
  (2026-11-03)

#### Fixed
- **Sandbox reset no longer ends in `error`**: the reset saves the reference of the new container on the row
  before it starts it, so in that window the row pointed to a container in the `created` state that
  the reconciler reads as "created, never started" and moves the sandbox to `error`. The reconciler now
  skips such a row while any `sandbox.reset` event exists for it within the last
  `RESET_SETTLE_S` (60 s), regardless of `driver_ref`; a crash between the saved reference and the start
  is resolved by the first pass after that window (72be987, `src/sandfort/workers/reconciler.py`).
  (2026-11-06)
- **Clearer messages**: the message for a stopped sandbox reads "the sandbox stopped while running
  this command (a resource limit was hit or its main process ended); start it again" and no longer
  attributes the death only to memory (`SANDBOX_DIED_MESSAGE`, `src/sandfort/drivers/docker/exec.py`).
  409 `no_container` carries `details.state` and a message per state: for `stopped` "sandbox has no container
  instance; start it first", for `destroying` and `destroyed` "the sandbox was deleted; create a new
  one" (`no_container_message`, `src/sandfort/errors.py`); the toolbox guard for a sandbox that is not
  started still writes "sandbox is <state>; toolbox calls require a started sandbox", so the client
  branches on `details.state`, not on the message. An image pull failure names both causes: "could not
  pull <ref>: the registry did not answer (a transient network problem, or a registry host that
  does not exist); check the name, then try again", without the resolver address. The traceback of a cell
  of a persistent context now also shows the source code line (`linecache` entry of the kernel). The description
  of the export route says that the tar does not carry the repository and that `docker load` prints the image id, so it has to be
  tagged manually (c374dc6, `tests/test_r30e_messages.py`). (2026-11-06)
- **Snapshot export does not carry the platform reserve file**: the tar returned by `GET
  /v1/snapshots/{id}/export` is filtered member by member (without buffering the whole tar) and omits
  `/.sandfort-reserve`, a file that means nothing outside Sandfort; other members keep their name, mode,
  owner and time (f7378e6, `src/sandfort/drivers/docker/tar_filter.py`,
  `image_export.py`). (2026-11-06)
- **Round 29: per-key sandbox limit, snapshot export, persistent Python context, endpoint
  status, SDK additions**: (1) `POST /v1/api-keys` accepts `max_sandboxes` (1 to 1000, requires a non-empty
  `sandbox_labels`); a sandbox create with a key that already holds that many live sandboxes in its scope
  answers 429 `QUOTA_EXCEEDED` with `details.limit` `key_max_sandboxes` (`details.max`,
  `details.current`). Counting happens in the transaction that writes the row, under the quota lock. A key with
  a limit can create only keys with a limit that is not larger than its own (403). It does not
  replace the org quota (d98cfa5, `src/sandfort/services/sandboxes.py`,
  `src/sandfort/services/api_key_admin.py`, migration `r0016_api_key_max_sandboxes.py`).
  (2) `GET /v1/snapshots/{id}/export` sends a `ready` snapshot as a tar (`docker save`, scope
  `snapshots:read`); other states answer 409 `INVALID_STATE`, and a driver without export 409
  `CONFLICT` with the reason `unsupported_mode`. The export is recorded in the audit as `snapshot.exported` before
  the transfer starts. The tar carries only the file system and the safe image configuration, without a repository and tag, so
  `docker load` prints the image id; registering a snapshot
  on another server always pulls from the registry and rejects the reserved repository, so the image has to be
  renamed and pushed to a registry the target server can pull from (c4747ec,
  `src/sandfort/api/routes/snapshots.py`). (3) `start()` starts a sandbox whose container died while the
  row still said `started` (43dbc61). (4) Public `GET /v1/status` (no key): `status` (`ok` or
  `degraded`), `version`, `build_sha` (`SANDFORT_BUILD_SHA`), `started_at` and `notice` from the file
  `SANDFORT_STATUS_NOTICE_FILE`, which is read on every request (at most 2 KiB; the prefix `degraded:`
  sets the status); 503 is documented in the spec (c05a30d, `src/sandfort/api/routes/health.py`).
  (5) Persistent Python code contexts: `.../toolbox/code-contexts` (create, list, delete, `run`).
  Variables, imports and loaded data survive between runs; the value of the final expression is
  printed; a cell exceeding `timeout_s` reports `timed_out` (124), and the state remains. The state is lost on
  stop, reset and delete of the sandbox and when a cell kills the kernel; Python only, the image requires `python3`.
  `code_run` is still a new process (5aa1a8c, `src/sandfort/toolbox/code_contexts.py`). (6)
  The Python traceback from `code_run` names `main.py` instead of the private run directory; other
  languages still show the directory (e61bc9c, `src/sandfort/toolbox/code_run.py`). (7)
  `sandbox_deleted` and `sandbox_reset` are also named when the exec ends with a bare SIGKILL exit (5214b20), and
  the deferral after a reset applies to every recent container reset of the row, with `sandbox_reset` reported
  before the row moves (118b170). (8) The exported `openapi/sandfort.v1.json` is regenerated
  (list `include_destroyed`, stop reasons, error glossary) (0b09531). (9) Python SDK and CLI:
  retries with jitter (a random pause between half and the whole of the backoff time, at most 8 s),
  `Retry-After` as seconds or an HTTP date, 429 `QUOTA_EXCEEDED` is not retried, 409 `in_progress`
  is retried for POST with `Idempotency-Key`; `include_destroyed` on `list_sandboxes` and
  `iter_sandboxes` (CLI `sandbox list --all` again shows destroyed sandboxes); `client.get(ime)`
  with `AmbiguousSandboxName`; `create_sandbox(delete_on_failure=True)` deletes a sandbox in the `error` state
  before it raises `SandboxFailedError`; `client.export_snapshot` and `sandfort snapshot export`;
  `client.status()`; `create_api_key`, `list_api_keys`, `revoke_api_key`; `sbx.code_contexts`
  (c989b1b, `sdk/python/src/sandfort_sdk/`, `cli/src/sandfort_cli/snapshot.py`). Documentation:
  the beta guide is self-contained (the scope table and the rule descriptions that previously pointed to
  the governance reference, a recipe for the "Run code" button inside the guide, a hardening recipe for a grader with
  `setpriv`, snapshot export, code contexts, status and problem reporting), `docs/operations.md`
  (request id format, "Status notice", "Snapshot export"), `docs/recipes/run-code-button.md`,
  `.context/known-issues.md` (closed items: per-key limit, snapshot export, interpreter
  state, status endpoint).
- **Round 28: deferral after reset by `previous_driver_ref`, accurate exec stop reasons,
  list without destroyed sandboxes, 422 for unknown fields, SDK retries and idempotent create,
  error glossary**: (1) The audit record `sandbox.reset` carries `previous_driver_ref` (the container that
  the reset removes), and the reconciler and the exec death path defer the sandbox only while the row still points to
  that container (or `driver_ref` is empty, or the record predates the key). A sandbox that dies right
  after a reset (a fork bomb in the fresh container) is now moved to `stopped` immediately, instead of the sandbox remaining about
  a minute (the `RESET_SETTLE_S` window of 60 s) in `started` (df4b1f2,
  `src/sandfort/workers/reconciler.py`, `src/sandfort/services/sandbox_reset.py`). (2) New
  `stop_reason` values `sandbox_deleted` and `sandbox_reset`: when exec returns `sandbox_stopped`, the route again
  reads the row, so a sandbox that another caller deleted or reset gets its own reason and
  stderr line ("the sandbox was deleted/reset while running this command"), and the row is not treated
  as an unexpected death; `exit_code` stays 137 and `sandbox_stopped` stays true. The timeout line
  now reads "the command was stopped after N s (timeout); pass a larger timeout_s (up to 3600) to
  allow more time" (the sentence at the time; it was changed in round 36, see Round 36) (f871381, `src/sandfort/api/routes/toolbox/process.py`,
  `src/sandfort/api/schemas/toolbox_process.py`). (3) `GET /v1/sandboxes` without a `state` filter
  hides `destroyed` sandboxes; `include_destroyed=true` or `state=destroyed` shows them.
  `CreateSandboxRequest` and `CreateApiKeyRequest` reject unknown fields with 422 (for example
  `max_sandboxes` on a key is no longer silently ignored) (ff4f8f0). (4) Python SDK: `Client` and
  `AsyncClient` accept `max_retries` (default 2, `0` disables); GET, HEAD, DELETE and POST with
  `Idempotency-Key` are retried on 429 (after `Retry-After`, at most 30 s), 503 and a transport
  error (0,5 s, 1 s, 2 s ..., at most 8 s); other requests and streams are not retried.
  `create_sandbox(idempotency_key=...)` sends `Idempotency-Key` (a7ce00b,
  `sdk/python/src/sandfort_sdk/client.py`, `_requests.py`). (5) The glossary of errors, reasons for 409 and
  `stop_reason` values is in the `info.description` of the OpenAPI document and in `docs/operations.md`
  ("Client-facing errors") (54b82cf). Documentation: the beta guide (reset as recovery for the grader,
  hidden tests in a separate sandbox, the data analysis path, list, retries, the new
  `stop_reason`, API key management, data egress without snapshot export, links to the
  governance reference replaced), the pilot pitch (isolation tiers on the beta, numbers from
  `context/metrics-snapshot.md`), README and `context/positioning.md` (number of tests and operations),
  `.context/known-issues.md`. Open: there is no limit on the number of sandboxes per key or per label,
  a snapshot cannot be exported, there is no interpreter state between `code_run` calls, the beta has no
  status page or version endpoint; SDK `list_sandboxes` has no `include_destroyed`, so CLI
  `sandbox list --all` no longer shows destroyed sandboxes.
- **Round 27: reasons for 409 CONFLICT, a separate 422 for untagged images, snapshot of a sandbox in the
  `error` state, known limitations**: (1) Every response with the code `CONFLICT` carries `error.details.reason`,
  a stable string, so the client does not have to parse the message text (4ac4558, `src/sandfort/errors.py`).
  Values: `name_taken`, `already_exists`, `concurrent_update`, `no_container`, `in_progress`,
  `in_use`, `closed`, `operation_failed`, `changed_during_reset`, `unsupported_mode`, `disk_full`,
  `runtime_conflict` and the fallback `conflict`. A driver conflict becomes `disk_full` or
  `runtime_conflict`. `INVALID_STATE` (also status 409) is a separate code and has no `reason`. (2) A reference
  to an untagged image (`moby-dangling`) gets its own 422 message ("untagged images (moby-dangling)
  are not accepted; pass an image name such as python:3.12-slim"); previously it got the message about
  the reserved repository `sandfort-snapshot`, which was misleading (272f9f2). (3) A sandbox in the
  `error` state whose container still exists can be saved into a snapshot (272f9f2,
  `src/sandfort/services/snapshots.py`): the commit works on a container that is not running, so the data
  of a sandbox with a full disk is recovered by creating a new sandbox from the snapshot with a larger
  `disk_gib`. The cause does not change: start needs free blocks in the layer with the quota, and the reserve
  `/.sandfort-reserve` is in the file system of the sandbox itself; a sandbox in `error` still cannot be
  started. If the container is already gone, the snapshot fails. (4) Documented open limitations
  (no code change): microvm create with `block_network=True` takes about 5 s longer (on the hosted
  beta 2026-11-05: about 3,9 s with network, 8,6 to 9,0 s with `block_network`; gvisor about 0,35 to 0,47 s in
  both cases), because the Kata runtime-rs shim in Docker network mode `none` does not find an interface and waits for its own
  rescan timeout of about 5 s; the workaround was not applied, because an internal bridge network would give the sandbox
  an interface and weaken the guarantee that there is no network. Sandbox names are unique per org and across
  the boundaries of keys with labels, so a key with labels learns that a name exists outside its scope (without an id
  and data); the recommendation is to not set a name or to prefix it by scope. Updated are
  `.context/known-issues.md`, `docs/isolation-tiers.md` and the beta guide.
- **Rounds 12 and 13: audit chain fork on Postgres, disk measurement, upload, CLI and PTY exit code**:
  (1) Under parallel load on Postgres, concurrent writes of audit events for the same org
  read the same chain head and both linked to it, so the chain forked. `GET
  /v1/audit-events/verify` on the evaluation orgs of the hosted beta reported 93 findings
  `link_broken` (27, 51 and 15 in 3 of 5 orgs) and no `hash_mismatch`: no event was
  modified. Writes are now serialized per org with a Postgres advisory transaction lock; after
  the fix, 40 parallel audited requests added 40 events with no new findings (6fe71aa). SQLite
  installations were not affected. Existing breaks remain in the chain (the audit trail is not rewritten) and
  verify still reports them; all of them predate the fix. (2) `GET /v1/audit-events/export` (NDJSON
  with `prev_hash` and `hash`) and `GET /v1/audit-events/verify` are in the OpenAPI spec (fc4077e, 85ade9b,
  97052f7). (3) Disk is measured: the Docker driver reports the size of the writable layer, so `disk_gib_seconds`
  is no longer always 0 (92ce691). `GET /v1/org/usage?group_by=sandbox|label:<key>` groups consumption by
  sandbox or by label (afca6c3). (4) A failed upload to a full disk deletes its partial file, an upload
  above the limit is rejected based on `Content-Length` before the body is sent, and exec no longer leaves pid
  files in `/tmp` (5be56d1). (5) CLI: `cp -r` on download unpacks the contents of a directory and
  accepts a trailing slash on the path; all commands on a sandbox give a start hint and exit 125;
  `cmd logs --follow` exits with 137 or 124 respectively, with a message for killed and timed-out commands; `preview`
  warns about a stopped sandbox (be74622). (6) `sandfort shell` and the PTY session in the SDK report
  the exit code of the remote shell (websocket close code 4000 + n; SDK `PtySession.exit_code`) (94019b2).
  (7) `SANDFORT_WEBHOOK_REQUIRE_HTTPS` rejects `http` URLs (it is enabled in `prod`), and `prod` refuses
  to start without `SANDFORT_WEBHOOK_SECRET_KEY`; the beta now sets both, so webhook URLs on the beta
  must use https (3ba0fc0). (8) A plain timeout no longer exceeds `timeout_s` by about 3 s on
  `gvisor` and `microvm`: `timeout_s=3` returned a response after 3,2 s (d46e442). (2026-11-04)
- **Round 11: interactive shell behind TLS, CLI additions, restart of a full disk, death instead of timeout**:
  (1) PTY behind a proxy that terminates TLS: the new setting `SANDFORT_FORWARDED_ALLOW_IPS` (default
  `127.0.0.1`; proxy addresses separated by commas, or `*`) tells uvicorn the addresses it may trust
  for the `X-Forwarded-Proto` and `X-Forwarded-For` headers, so websocket URLs get `wss` instead of
  `ws`; the SDK additionally changes a plain ws URL to wss when the base URL is https on the same host. On the hosted
  beta, `sandfort shell <sandbox>` and `sbx.pty.create()` work (PTY over https ran `echo` and
  returned the output) (272d151). (2) `sandfort exec -i` forwards the CLI stdin to the command; without `-i` stdin from
  a pipe is not sent and the CLI prints "sandfort: stdin is not forwarded to the command; pass -i to send
  it". A leading `--` before the command is accepted, and exec on a stopped sandbox ends with the hint "start
  it with: sandfort sandbox start <sandbox>". `sandfort sandbox list` hides `destroyed` sandboxes,
  `--all` shows them (b6af272). (3) `sandfort cp -r` copies directories in both directions; the contents
  of the directory are unpacked into the target path (created if it does not exist), the sandbox needs to have `tar`,
  and the archive is subject to the upload limit of 256 MiB (9f07a47). (4) `sandfort cmd start`, `cmd logs
  [--follow]` and `cmd kill` start, follow and stop background commands (with `--follow` the CLI exits
  with the exit code of the command); `sandfort preview <sandbox> <port>` prints the preview URL, and the SDK gets
  `sbx.preview(port)` which returns `PreviewInfo` (url, token, expiry) (8f38a00). (5) A sandbox
  written to until ENOSPC with 0 free bytes now restarts with its data on all three tiers
  (verified on `gvisor`, `microvm` and `container`); the reserve `/.sandfort-reserve` is emptied in place
  (truncate), so stop, start and snapshot of a full sandbox work. The file still must not be deleted: whoever
  deletes or truncates it loses protection until the next start, which recreates it (203370a). (6) Upload to
  a path that is already a directory answers with 409 Conflict "is a directory: <path>; upload to a file
  path inside it" (previously `gvisor` replaced the directory with a file). When a sandbox dies before or at
  the deadline, the result is exit 137 with `sandbox_stopped` true, not a timeout (124); in the evaluation 26
  of 29 `microvm` python fork bombs returned exit 137 within 6,1-12,7 s, and 3 returned 124 with an already
  dead sandbox. `timeout_s` is a budget, not an exact cutoff (a command with `timeout_s=10` returned after
  about 13 s). A classic bash fork bomb usually returns exit 0 in about 1 s on `gvisor` and `microvm`, and
  the NEXT exec reports `sandbox_stopped` (after up to about 5 s on `microvm`) (5243f36). The hosted beta was
  unavailable on 2026-11-04 from 15:08 to 15:46 (the host killed the QEMU of the VM for exceeding the limit
  of memory during parallel heavy tests, and the recreated VM came up without a network); fixed
  at the operations level, without a code change: QEMU has 2 GiB of memory headroom above the guest, and the MAC address of the VM
  is fixed. The beta is still a single VM (6 vCPU, 24 GiB RAM) for all evaluators, so at most
  about 3 concurrent heavy sandboxes are requested. (272d151, b6af272, 9f07a47, 8f38a00, 203370a, 5243f36,
  2026-11-04)
- **Full disk, dead sandbox and deletion after a crash (round 10, verified on the hosted beta at
  commit 6a4bcd8)**: (1) after an exec that returns `sandbox_stopped=true` the sandbox is already in the
  `stopped` state when the response arrives (the server settles the state first), so `start()` and a new exec work immediately without
  waiting; with `gvisor` and `bytearray(3<<30)`: exit 137, `sandbox_stopped` true, state `stopped`,
  start, then `echo alive` exits with 0 (e230999). The same commit removes a stray stderr from exec on a
  full disk: the write fails with "No space left on device", and exec keeps working. (2) Upload to a full
  sandbox answers with HTTP 409 CONFLICT and the message "the sandbox disk is full (no space left on
  device): delete files in the sandbox or create it with a larger disk_gib", without host paths
  (efe4a97). (3) Death detection on `microvm`: the state is checked up to 3 s after a suspicious exit or
  timeout (c2db53c), and exec on a dead `runsc`/`kata` container returns a response in about 2 s
  instead of only at the deadline (6a4bcd8). Python and bash fork bombs with `timeout_s=60`, 4 of 4 runs:
  exit 137, `sandbox_stopped` true, `timed_out` false, response after 6-10 s (previously often exit 124
  only at the full deadline, or 255, with `sandbox_stopped` false). Remaining limitation: a command that
  starts a fork bomb in the background and exits immediately can return exit 0 before the sandbox dies; the next
  exec then reports `sandbox_stopped`. (4) Deleting a sandbox right after a crash no longer fails with
  "modified concurrently": the server retries the deletion on a concurrent version change (2473299).
  (5) A sandbox filled to 100% can be stopped, started and saved into a snapshot (verified on `gvisor`
  and `microvm`; a snapshot of a full `microvm` sandbox returned all files into a new sandbox with
  `disk_gib=3`). The quota is `disk_gib` plus 32 MiB, and Sandfort holds a file `/.sandfort-reserve` of 16 MiB
  which it empties before every stop and fills after every start; `df` therefore shows about 32 MiB more than
  `disk_gib` (1.1G for `disk_gib=1`). The file is not deleted: without it a sandbox filled to 100% may not
  be able to start (it is recreated on the next start) (1924027). For untrusted code: one sandbox
  per submission, and treat `sandbox_stopped`, exit 137 and a failed next exec as a failure.
  (e230999, efe4a97, c2db53c, 2473299, 1924027, 6a4bcd8, 2026-11-04)
- **Upload to a nonexistent directory gives a clear message**: when the parent directory does not exist,
  upload now returns "no such directory: <parent>; create it first" instead of a docker message that
  called the nonexistent directory "file" and mentioned "container". Finding of the persona verification round
  (4 evaluators). (2026-11-03)
- **A failed image/snapshot pull gives a clean message (also on the create path)**: if the reference cannot
  be pulled (it does not exist or requires `docker login`), the sandbox moves to `error` with the reason
  "no such image or snapshot: <reference>" instead of raw docker text that leaked the backend
  (e.g. "pull access denied ... 'docker login'"). The original fix covered only the separate pull
  helpers; the create path pulls the image inline in `create_container` when container create throws
  image-not-found, so the raw error still leaked there — now that path is clean too, with a backstop in
  `clean_message` that removes the "docker login" phrase from any docker message. It also covers the name
  of a snapshot passed instead of an id. Finding of the persona verification round (Tomoko/Oskar). (2026-11-03)
- **Clearer error messages at the client boundary**: a sandbox name conflict now reads "a
  sandbox with this name already exists in this organization; choose a different name or delete
  the existing one" instead of the confusing "id or name already exists, or its org does not exist". In
  addition, messages from the docker driver redact the container identifier (64-hex and the short form after
  the word "container") into "the sandbox container", so an upload to a nonexistent path no longer leaks
  the internal docker id to the client. Findings of the junior and technical evaluations. (2026-11-03)
- **An errored sandbox no longer reserves its name**: the partial unique index over
  `(org_id, name)` now excludes the `error` state too, not only `destroyed` (migration `0012`). Previously,
  if creation fell into `error`, the user could not create a new sandbox with the same name until they
  deleted the failed one. Finding of the junior evaluation. (2026-11-03)
- **Deleting an errored sandbox no longer collides with a live namesake**: since `0012` allows a live and
  an errored sandbox to share a name, deleting the errored one (which passes through `destroying`) failed with 409
  "sandbox name already exists in this org" because `destroying` was still in the index. Migration `0013`
  also excludes `destroying` from the index, so a sandbox on its way out does not reserve the name against a live one.
  Finding of the persona verification round. (2026-11-03)
- **Lifecycle calls are idempotent on the target state**: deleting an already deleted sandbox,
  stopping an already stopped one and starting an already started one are now a no-op that returns the current
  sandbox, instead of 409 "illegal transition". A repeated (retry) call after success no longer looks
  like an error. Truly impossible transitions still return an error. Finding of the external SRE evaluation.
  (2026-11-03)
- **Auto-delete with a delay now works**: a stopped sandbox with a positive
  `auto_delete_minutes` is deleted when it has been stopped for at least that many minutes (measured from `stopped_at`);
  previously auto-delete triggered only for the value 0 (immediately), so "delete N minutes after stop"
  was unimplemented and forgotten sandboxes remained. `-1` still means never. Finding
  of the external SRE evaluation. (2026-11-03)
- **The quota is checked and reserved on `start` too, not only on `create`**: previously a stopped
  sandbox released its reservation, and a repeated `start` did not request it again, so the quota could
  be bypassed with a stop/start cycle (more started sandboxes than the limit). Now a `start` that would
  exceed the quota returns 429 and the sandbox stays stopped; the reservation is in the same transaction as
  the start intent. Finding of the external FinOps evaluation. (2026-11-03)
- **Audit also records rejections of authenticated requests**: when a key authenticates successfully but
  the request is rejected (403 due to scope, or 404/409/422), an audit record with the `denied`
  outcome is written to the org chain (method, path, status and code in the details), best-effort — never changes
  the response to the client. Previously only successes were recorded, so a key that only hits rejections was
  invisible. Finding of the external security evaluation. (2026-11-03)
- **Audit records carry the client `ip` and `user_agent`**: middleware now threads the client address
  (the first entry from `X-Forwarded-For` behind a reverse proxy, otherwise the ASGI client) and the user-agent into the audit
  row, as it already does with `request_id`. Previously both were null. Finding of the external beta evaluation.
  The address source was replaced in 5dae517: only the address reported by uvicorn (see "Round 30").
  (2026-11-03)
- **MCP server: `list_sandboxes` returns only live sandboxes** (without `destroyed`/`deleting`); added
  `mcp_server/requirements.txt` which declares the `mcp>=2` dependency (previously undeclared). Findings
  of the external beta evaluation. (2026-11-03)
- **A snapshot source cannot be deleted while the commit is in progress**: deleting a sandbox that is the source
  of a snapshot in progress (`pending`) now returns 409 with a clear message, instead of the snapshot silently falling
  into `error` without a reason. Finding of the external beta evaluation (reproduced 3/3). (2026-11-03)
- **`websockets` added to the runtime dependencies**: `sandfort.proxy.app` imports it unconditionally
  (through `api/wiring.py`), and it was declared only in the dev dependencies, so the production
  image from `deploy/Dockerfile` failed on import at startup. Discovered during the first deploy
  of the hosted beta. (2026-11-03)
- **The image CMD runs `sandfort-server` instead of bare uvicorn**: the earlier CMD bypassed
  `main()`, the only path that serves the API and the preview proxy in the same loop, so the proxy in
  the production image never started even with `SANDFORT_PROXY_ENABLED=true`.
  Discovered while setting up preview URLs on the hosted beta. (2026-11-03)
- **New setting `SANDFORT_PUBLIC_PREVIEW_URL`**: the public origin on which previews are
  served behind TLS termination (e.g. an https origin without a port); the minted preview URL takes the scheme
  and port from it, the host remains the generated one. Empty = previous behavior (http + local
  proxy port). It is validated that the host is exactly the preview domain. Without this the `url` field
  of the response was unusable behind the ingress. (2026-11-03)
- **The name of a deleted sandbox can be reused**: name uniqueness per org
  now applies only among non-destroyed sandboxes (partial unique index, migration r0011);
  previously the name stayed reserved forever, so even our own quickstart failed on the second
  run with 409. Finding of the external beta evaluation. (2026-11-03)
- **Docker errors to the client without an internal URL**: the mapping of driver errors now uses
  the daemon's explanation (or cleaned text), so messages no longer contain the internal docker API
  URL. Finding of the external beta evaluation. (2026-11-03)
- **The OpenAPI spec documents authentication, errors and the egress field**: added
  an `ApiKeyBearer` security scheme at the document level, the standard error envelope described
  structure, and the `egress_allowlist` field on sandbox create is no longer hidden from the
  exported specification. Spec regenerated. Findings of the external beta evaluation. (2026-11-03)
- **SDK: `egress_allowlist` on create and `wait` for snapshot**: creating a sandbox through
  the Python SDK now accepts a list of allowed hosts (the server always accepted the field), and
  `create_from_sandbox` can wait for the `ready` state instead of returning `pending` without
  help. Findings of the external beta evaluation. (2026-11-03)
- **The minted preview URL contains a token**: the `url` field of the response now also carries
  `?sandfort_preview_token=...` (the parameter name is imported from the proxy constant), so the link is
  immediately usable; previously it returned 401 and the use of the token was not documented —
  the external evaluator guessed the parameter name. (2026-11-03)
- **Preview hosts without an underscore**: the generated label is now `<port>-sbx-<telo id-ja>`
  (a hyphen instead of the underscore from the id) because an underscore is not valid in a DNS label, so strict
  TLS clients (Python `ssl`) rejected wildcard matching with a valid certificate.
  The parser also accepts the old form with an underscore; the frozen seed tests are untouched. (2026-11-03)

### Phase 11: Docker driver lanes (2026-11-02)

#### Changed
- **Two lanes for docker calls, one thread budget**: long-running operations (log following,
  archive upload/download, exec output and terminal reads, pull, commit, build, flatten)
  go through the bulk lane (`SANDFORT_DOCKER_BULK_THREADS`, default 48, clamped below
  the total limit), so a parked log follow or a slow pull can no longer starve short
  calls (create, start, stop, inspect) on the total lane
  (`SANDFORT_DOCKER_THREAD_LIMIT`, 64). A starvation test pins this (red on the old
  routing). Benchmark with no regression: create p50 107 ms before and after (conditions in
  `context/metrics-snapshot.md`).
- **Cancellation contract**: a cancelled await never leaves a live thread unobserved — the token
  stays held until the thread returns, and a failure after cancellation is logged once; the number of threads
  can no longer exceed the limit through native cancel.
- **Clean driver shutdown**: idempotent `aclose` kills live terminals, drains the lanes and
  closes the docker-py client; lifespan shuts down in order workers → driver → engine; docker-py pool
  widened to the total thread limit (no dropped connections above 10). Event-loop
  responsiveness under a slow call is pinned by a test.

### Phase 10: SCIM provisioning (2026-11-02)

#### Added
- **SCIM 2.0 provisioning (subset for user lifecycle)**: `/scim/v2` routes for Users — list with
  `userName eq` filter and startIndex/count pagination, get, create, replace, patch (three
  shapes sent by Okta and Entra, including string-boolean), delete and deactivation
  (`active: false` removes the membership; the user row and audit history remain); ServiceProviderConfig,
  ResourceTypes and Schemas discovery documents state the limits honestly (no groups, bulk,
  etag; one filter shape). Every mutation goes through the existing user admin service, so
  last-admin protection, role ceiling and audit apply unchanged. Enabled with
  `SANDFORT_SCIM_ENABLED`; `SANDFORT_SCIM_DEFAULT_ROLE` (default `viewer`).
- **Per-org SCIM bearer tokens**: the org admin mints and revokes them through management routes; only
  the hash is stored (like API keys), plaintext is shown once, they are valid exclusively on SCIM
  paths (401 on the rest of the API) and carry a role ceiling that cannot exceed the minter's role;
  at most 5 active per organization; `externalId` is stored on the membership (migration `0010`).
- **Gate 10** (`examples/gate10.py`): plays Okta/Entra sequences against a live server —
  discovery, filter miss/hit, create, all three patch shapes, deactivation, re-create
  with the same ID, delete, last-admin rejection in the SCIM error shape, revoked token
  immediately 401. Passed locally 2026-11-02. SCIM routes are outside the exported OpenAPI spec
  (policy recorded in `docs/scim-design.md`).

### Phase 9: Cross-node toolbox routing (2026-11-02)

#### Added
- **Cross-node toolbox routing**: a toolbox request (exec, async commands with SSE logs, fs,
  git, sessions, interactive PTY over websocket) that arrives at a node that does not hold the sandbox
  is forwarded exactly once over HTTP to the owning node, authenticated with a short-lived
  HMAC route token (`sfr_`, 30 s, canonical re-encoded verification); the owner executes
  the same routes with the same authentication, quotas and audit. Configuration:
  `SANDFORT_NODE_INTERNAL_URL` (address the node advertises in its heartbeat),
  `SANDFORT_ROUTING_SECRET` (shared secret, min 32 characters; empty = routing disabled,
  behavior identical to before), `SANDFORT_ROUTING_TIMEOUT_S` (default 5 s for
  connect/write/pool; read unlimited). A forwarding failure returns the standard envelope
  `503 NODE_UNAVAILABLE` with `Retry-After` and a reason (`stale`, `no_address`, `unreachable`,
  `timeout`, `rejected`, `misrouted`). The hop is unencrypted: a private network is a documented
  requirement (runbook). Design: `docs/cross-node-routing-design.md`.
- **Gate 9** (`examples/gate9.py`): two real processes with role `all` (alpha and beta) over one
  database and real Docker; exec, file round-trip, git commit, followed SSE logs and terminal
  (echo + resize) all through alpha for a beta sandbox; shutting down beta yields `503 NODE_UNAVAILABLE`.
  Passed locally 2026-11-02.
- **Node internal address**: column `internal_url` on `nodes` (migration `0009`), advertised
  in every heartbeat, `route_for_sandbox` lookup; `GET /v1/nodes` shows it.

### Phase 8: Beyond parity (2026-11-01, in progress)

#### Security
- **Per-org limits for terminals and async commands**: cap on live terminals (default 8) and
  running async commands (16) per organization, reaping of terminals that never connected after
  the connect token expires, and purging of expired tokens from memory on every mint.
- **Concurrent webhook delivery**: semaphore of 8 in flight, at most 2 per endpoint with per-endpoint
  ordering preserved, round-robin per organization across the batch, and url vetting under the same
  timeout regime as the request itself - a slow tenant no longer blocks the others.
- **Webhook secrets encrypted in the database**: Fernet envelope with a marker prefix (legacy plaintext
  rows work without migration, new writes are encrypted), `SANDFORT_WEBHOOK_SECRET_KEY` required in the
  prod environment; the repository docstring now describes the actual behavior.

#### Added
- **Gate 8** (`examples/gate8.py`): egress allowlist proven live - a sandbox with an allowlist of
  example.com receives proxy variables with its own token, https to the allowed host passes
  through the CONNECT tunnel, a disallowed host is rejected with 403, a wrong credential with 407. Passed
  locally 2026-11-02. The host chain is a linux-only step from the runbook (not performed on macOS).
- **Egress allowlist, slice 3b - driver and host**: a dedicated egress bridge network (ensure like the
  main one), build_host_config selects it when the spec carries an allowlist (block_all still wins with
  none), the host chain in the deploy script lets through only the proxy address and established replies,
  runbook section for the proxy process and settings.
- **Egress allowlist, slice 3a - service wiring**: `SANDFORT_EGRESS_PROXY_ADDRESS` and
  `SANDFORT_EGRESS_SECRET` (min 32 characters); create with an allowlist without a configured proxy
  is rejected (fail-closed), and with the configuration the spec environment gets four standard proxy
  variables with a signed token as userinfo and no-proxy for loopback.
- **Egress allowlist, slice 2 - CONNECT proxy** (`src/sandfort/egress/`): asyncio proxy per
  node; the credential is a signed token (sandbox id + allowlist, HMAC like session tokens),
  every resolved address passes the same SSRF check as webhooks, fail-closed on everything else;
  decisions are logged without credentials.
- **Egress allowlist, slice 1 - model and validation**: `egress_allowlist` on the create command,
  the sandbox and the API response (hostname rules from the design, leading dot = subdomains, cap through
  `SANDFORT_EGRESS_ALLOWLIST_MAX_ENTRIES`, contradiction with block_all rejected); migration
  r0008; sandboxes with an allowlist bypass the warm pool.
- **Egress allowlist design** (`docs/egress-allowlist-design.md`): decision for per-sandbox
  network allowlists - forward proxy with per-sandbox credentials, fail-closed; alternatives
  (host firewall rules, DNS filter) rejected with rationale; delivery in 4 slices.
- **Web console** (`GET /console`): a single self-contained read-only page on the API - sandboxes,
  nodes and audit trail with a 5 s refresh; the API key lives only in page memory, CSP
  allows only self connections, no external assets and no browser storage (tests
  pin this). Verified live in a browser 2026-11-01.
- **Gate 7** (`examples/gate7.py`): two processes as nodes alpha and beta on the same daemon -
  placement distributed 6 sandboxes 3:3, each node executed only its own jobs, everything cleanly
  destroyed. Passed locally 2026-11-01. Multi-node requires `SANDFORT_SANDBOX_JOBS_ENABLED=1`
  (inline lifecycle bypasses placement) - recorded in the runbook.
- **Nodes API**: `GET /v1/nodes` (org:read) - registry state with running counts and a staleness
  flag.
- **Placement and node affinity** (scheduler slice 2): create picks the least loaded active node
  with a fresh heartbeat and free capacity (empty registry = local node, behavior
  unchanged); job lease, autostop, reconciler and GC work exclusively on their own node's resources.
- **Node registry** (scheduler slice 1): `nodes` table with heartbeat and capacity
  (`SANDFORT_NODE_ID`, default `local`; `SANDFORT_NODE_MAX_SANDBOXES`), `node_id` on
  sandboxes and jobs (migration r0007); the default keeps single-host behavior unchanged.
- **TypeScript SDK extended to parity**: exec sessions and async commands, volumes and git operations
  (credential per call, never stored) on the same client; the whole agent workflow now exists in
  both SDKs.
- **Reproducible benchmark** (`examples/benchmark.py`): create/exec/delete p50 and p95 with measurement
  conditions in the final json; passed locally 2026-11-01 (create p50 107 ms, exec p50 18 ms on
  macOS arm64 / Docker 29.8.2 - a single local measurement, not an SLO).
- **MCP server** (`mcp_server/sandfort_mcp.py`): sandbox operations as MCP tools over stdio
  transport (create, run_code, run_command, upload and download text files, list, delete,
  snapshot) - every MCP client gets sandboxes without SDK integration; instructions in the runbook.
- **Warm pool** (`SANDFORT_WARM_POOL_SIZE`, default 0 = disabled): a lazy pool of standby
  sandboxes per (org, snapshot, resources); create of the same spec without custom env/mounts atomically
  takes over an already started sandbox, refill goes through the existing job queue; standby reserves quota,
  is excluded from listing and auto-stop.

### Phase 7: Path to sales (2026-10-31, in progress)

#### Security
- **Quota is a platform operation (medium, decision)**: `PUT /v1/org/quota` now requires a
  platform-admin principal - a tenant can no longer lift, on its own, the limits that protect other
  tenants on the same host; reads unchanged.
- **Abuse limits (medium)**: rate-limit buckets are keyed per user (all sessions share the
  bucket) with LRU purging of the map; SSO exchange got a per-IP limiter before authentication; a new
  body-limit middleware rejects JSON bodies over `SANDFORT_MAX_REQUEST_BODY_BYTES` (default
  16 MiB) with an exception for upload routes.
- **Seccomp profile moved to an allowlist base (medium)**: `deploy/seccomp.json` is now the moby
  v28.3.3 default (deny by default) minus the syscalls Sandfort explicitly forbids, with the
  arg-conditional ban on new user namespaces retained; verified live (fork works,
  `unshare -U` rejected, clone3 ENOSYS fallback). The earlier profile was a denylist weaker than the
  Docker default.
- **Session revocability and settings validation (medium)**: every session request re-checks
  the user (disabled), the existence of the membership and the CURRENT role, and binds the org claim
  to the configured SSO org; the settings loader rejects a secret shorter than 32 characters, a non-https
  JWKS URL (except localhost), a non-positive cache and a TTL outside the range 60-86400 s.
- **Cross-tenant access to private previews (high)**: requests authorized by a cookie jar
  are rejected when `Origin` does not match the host or `Sec-Fetch-Site` is cross-site (also on the
  websocket handshake); the cookie is set only for a token that actually authorized a
  grant and passes strict validation; the `Domain` attribute is stripped from upstream `Set-Cookie`
  headers.
- **Egress block is now enforced (high)**: `prod` start requires confirmation that the host egress
  script is installed (`SANDFORT_EGRESS_ACKNOWLEDGED`), `deploy/host-setup.sh` blocks the entire link-local
  range, the CGN range and the Azure wire-server with ip6tables equivalents, and the runbook states the obligation to
  run the script on every node.
- **Memory amplification of the log store (high, measured)**: frames of the same stream are
  merged up to 64 KiB per chunk and a global limit of 64 MiB across all logs is introduced
  (the oldest finished are evicted, then the oldest bytes of running ones), with unchanged offset
  read semantics.
- **Privilege escalation through memberships (high, confirmed)**: assigning and changing a role
  now require that the caller holds all scopes of that role (attenuation as with keys);
  otherwise `ScopeEscalation` 403 before any write.
- **SSO account takeover (high, confirmed by probes)**: the verifier now requires
  `email_verified` exactly `true`, a pure ASCII email before lowercasing, `azp` equal to the
  audience when `aud` is a list, `typ` JWT, a required `iat` no older than 300 s (with 60 s leeway);
  every rejection is the same generic 401.
- Adversarial review of the three riskiest surfaces (auth and SSO, toolbox exec and fs, proxy and
  webhook egress); findings are being fixed through guarded contracts in order of severity.
- **Git token theft from the sandbox (critical, confirmed)**: askpass now answers only the password
  prompt for the expected host; credentialed git calls run with an isolated config (hooks path to a
  nonexistent path, global and system config disabled, ssl verification forced, proxy and
  insteadOf reset). The remaining risk (reading the file during the operation window) is documented.

#### Added
- **TypeScript SDK** (`sdk/typescript`, `@sandfort/sdk`): transport over fetch with envelope
  parsing and error mapping, sandbox lifecycle with a wait loop, processExec and codeRun,
  fs transfer (upload, download, list, mkdir, move, remove) and snapshots; strict tsc and vitest
  with no runtime dependencies.
- **SDK and CLI cover members and SSO**: `client.members` (create, list, set_role, remove) and
  `exchange_sso` on the sync and async client; `sandfort members add|list|set-role|remove`
  commands in the CLI.
- **Gate 6** (`examples/gate6.py`): end-to-end acceptance check of the sixth phase on a real server -
  separate `api` and `worker` processes, member administration with last-admin protection,
  OIDC exchange with a real RS256 signature against a local JWKS endpoint and scope checks of a
  viewer session. Passed locally 2026-11-01.
- **Member administration completed**: `PATCH` and `DELETE /v1/org/members/{user_id}` with last-admin
  protection of the organization. (0012cba, spec d8afdb3)

#### Decided
- License FSL-1.1-Apache-2.0 and the design-partner phase (see the item in the section below). (60ea157)

### Phase 6: Enterprise operations (2026-10-31)

#### Added
- **Process roles `api`, `worker` and `all`** (`SANDFORT_ROLE`, default `all`): the API can be
  started without background workers, and a worker without an HTTP server. The API and worker therefore scale
  separately. (f500954)
- **RBAC foundation**: users, organization membership and the roles `admin`, `developer` and `viewer`
  mapped to the existing scopes. Access is assigned by role, not only by API key. (9ddcbea)
- **Organization member administration**: `GET/POST /v1/org/members`. (5bec8b4, spec e565958)
- **Short-lived stateless session tokens** for user authentication, signed with HMAC.
  Users do not have to carry long-lived API keys. (65a3703)
- **OIDC single sign-on token exchange**: `POST /v1/auth/sso/exchange` exchanges an OIDC token
  of an existing identity provider for a Sandfort session token. (ba55938, dependency d15984a, spec 5f01d18)
- **Kubernetes deploy kit** (`deploy/k8s/`): namespace, configmap, `api` Deployment with two replicas,
  `readyz`/`healthz` probes and a ClusterIP service, headless `worker` Deployment and kustomization.
  The Docker socket is mounted, with a warning that dedicated nodes are required. The kit comes with an
  **operations runbook** (`docs/operations.md`) covering deploy order (migrations first), backup,
  restore, upgrade, scaling and observability. (b79e7c7)

#### Decided
- License: FSL-1.1-Apache-2.0 (`LICENSE.md`); go-to-market through design-partner pilots.
  Details of the decision in `context/pricing-and-offers.md`.

#### Fixed
- `python -m sandfort.main` silently exited with code 0 without starting the server (the
  module-entry guard was missing); added the guard, a hermetic subprocess test and the `sandfort-server` entry point
  in `pyproject.toml`. (096806f)

#### Documentation
- Phase 6 was added to the delivery plan. (6d8a503)

### Phase 5: Enterprise hardening (2026-10-31)

#### Added
- **Preview proxy**: HTTP and WebSocket streaming routed by hostname to the dev server inside the
  sandbox, with preview tokens and optional public access
  (`POST /v1/sandboxes/{id}/preview-tokens`). An application from the sandbox can be opened in the
  browser. (1c8d121, seed 1742c84)
- **Web terminal** through the proxy (xterm 5.5.0 with a pinned version): interactive shell in the
  sandbox from the browser. (3f8b530)
- **Postgres production profile**: asyncpg engine, locking through `SELECT ... FOR UPDATE`,
  production compose (`deploy/compose.prod.yml`) and a burst test on a real Postgres. (5994cba)
- **Hardened isolation**: choice of container runtime (`SANDFORT_CONTAINER_RUNTIME`, e.g. `runsc`),
  custom seccomp profile (`deploy/seccomp.json`), host script for egress
  (`deploy/host-setup.sh`), disk quota protection in production and a fork-bomb containment test.
  (7ba5afc, deterministic test 9336474)
- **Tamper-resistant audit**: hash chain per organization, admin commands `audit-verify` and
  `audit-export` and retention that preserves the validity of the chain prefix. A later modification
  of audit records can be detected. (99c174c)
- **Driver registry** with discovery through entry points, a conformance suite for drivers and a
  **Firecracker skeleton**. The skeleton is tested only against a mock agent: it supports compute and exec,
  and does not support fs/pty/logs/images/volumes. It is not a production microVM driver. (f160186)
- **Resource change of a stopped sandbox** (`POST /v1/sandboxes/{id}/resize`) with
  quota reconciliation and admission overcommit. (eb6a5b2)
- **Load profile with SLO report** (`tests/load/test_load_profile.py`, p95 limits for
  create/exec/delete) and **chaos suite** (`tests/chaos/`, zero orphan containers after reconcile).
  The hard OpenAPI drift gate was also restored. (f57d52c)
- **GitHub Actions CI**: lint, strict types, import contracts, unit and docker jobs. (2eee22d)

#### Changed
- CI: job-level and per-test timeout for the docker suite, pre-pull of the test image with retries.
  (fcfe661, b940c10, 35729df)

#### Documentation
- README with features, quickstart, development and architecture. (cde805c)

#### Verification
- Gate 5: API and proxy in a single process; preview URL and web terminal verified in a real browser
  (`examples/gate5.py`). (0a0668a)

### Phase 4: Multi-tenant platform (2026-10-31)

#### Added
- **Quotas**: reservation in a transactional ledger, release on failure, stop and delete,
  recounting, org quota routes (`GET/PUT /v1/org/quota`, `GET /v1/org/quota/recount`)
  and host capacity protection. Quotas also hold under concurrent requests. (ad4eff6, seed 97eebab)
- **Events and webhooks**: transactional outbox, signatures per the standard-webhooks specification,
  SSRF protection with IP pinning, dispatcher with backoff, automatic shutdown of faulty endpoints,
  delivery history and redelivery (`/v1/webhooks...`). (1488f99)
- Optional flag `webhook_allow_private_networks` for receivers in a private network. The metadata IP address
  is always blocked. (7e0827b)
- **Metering**: usage intervals through the lifecycle, idempotent hourly rollups, storage
  sampler and usage report (`GET /v1/org/usage`). (41e3b95)
- **API key administration** with scope narrowing (`/v1/api-keys`) and **rate limiting**
  with a token-bucket algorithm (`429` response with `Retry-After`). (210df8a)
- **Observability**: OTel spans across the api/job/driver layers, a stable metrics catalog at
  `/metrics` and log correlation by request id. (3f42467)
- **Idempotency keys** on resource creation and **OpenAPI export** with a drift gate that
  compares the generated and committed spec. (ebf2f10)
- Admin command `create-org` for adding new tenants. (8cc24e9)

#### Verification
- Gate 4: two organizations, quota burst 10/40, signed webhooks verified live, usage report
  and metrics catalog. (24430c0, 7ea9cf6)

### Phase 3: Images, snapshots, volumes and background jobs (2026-10-30)

#### Added
- **Job queue and runner**: atomic leases, exponential backoff, wake-up in the same process,
  idempotent lifecycle handlers and a read-only jobs API (`/v1/jobs`). (819ec7b, seed d4e14dc)
- **Snapshots**: registration of an image from a registry with a pinned digest, commit from a sandbox
  (with a pause), creation of a sandbox from a snapshot, `409` protection while references exist and
  auto-flatten after 20 layers. (eb4ac05)
- **Declarative image builder**: deterministic Dockerfile compilation, strict package
  validation, docker build with limits and abort on timeout, build logs over SSE and a cache by spec
  hash (`POST /v1/images/builds`). (f8f693f)
- **Volumes**: labeled volumes, mounting at sandbox creation, `409` protection against deleting
  a mounted volume and size measurement. (665662e)
- **Auto-stop and auto-delete**: activity tracking with debounce, a scanner of inactive sandboxes and
  deletion on stop. (080cd44)
- **Reconciler and GC**: repair of state drift, removal of orphan resources with a grace period and
  cleanup of unreferenced images and volumes. (19f1b60)
- **SDK image DSL**, snapshot and volume clients and CLI commands with a schema compatibility guarantee.
  (f42cbb5)

#### Fixed
- The system audit of the reconciler tolerates unknown organizations and storage errors. Each attempt
  gets a new event id. (6d2bb99)

#### Verification
- Gate 3 on real Docker: declarative build, 20 creations with a p50 of 92 ms, snapshot chain,
  shared volume, auto-stop and chaos restart. (2d92316)

### Phase 2: Toolbox, SDK facades and CLI (2026-10-30)

#### Added
- **Fs toolbox**: streaming upload and download of archives, list and stat (GNU and BusyBox), mkdir, move,
  delete, path protection and audit of fs routes. (b853927, seed 57b71a1)
- **Exec sessions**: preserved cwd and env, asynchronous commands, logs limited to 10 MiB, SSE follow
  with resumption from an offset and kill. (144adf2)
- **Git toolbox**: clone, status, add, commit, push and pull. Credentials go through a temporary
  askpass that is guaranteed to be deleted, and tokens are redacted. (a42e4f9)
- **Interactive PTY**: docker tty exec, WebSocket endpoint with single-use connect tokens
  (`4401` on reuse or expiry), resize and closing on stop. (43e089c)
- **Container logs** over SSE (follow/tail/since), with fast release of the stream on
  disconnect. (29c4157)
- **SDK toolbox facades**: fs, git, process sessions and pty, with an SSE log iterator and a WebSocket
  pty. (49beafc)
- **Sandfort CLI v1**: login, sandbox lifecycle, exec, cp and an interactive shell that restores the terminal
  state. (cdb344a)

#### Fixed
- Log stream wake-up also works with SocketIO wrappers without `shutdown`. (b39883e)

#### Verification
- Gate 2 on real Docker: a complete toolbox demo on alpine and debian images. (ece4eac, 3df0795)

### Phase 1: Core of the sandbox lifecycle (2026-10-30)

#### Added
- Project skeleton, architecture, delivery plan and frozen driver protocols. (138ba0c, 44a3b61)
- **Docker compute driver**: create, start, stop and destroy with hardened settings, labels
  and idempotency. (e168aa1)
- **Docker exec**: demultiplexed streaming, kill on timeout and output limit. (2b6be11)
- **Persistence**: async engine, unit-of-work, organization-scoped repositories and
  alembic migrations. (d4bca15)
- **Authentication**: hashed API keys, bearer dependency, scopes and administrator
  bootstrap. (6cc84a9)
- **Sandbox service and API**: lifecycle orchestration, routes and error mapping. (8b73d12)
- **Process toolbox**: guards, execute and code-run. (17fd135)
- **Audit**: recorder with redaction in the unit-of-work and a listing route (`/v1/audit-events`).
  (17e1ad2)
- **Python SDK v0**: sync and async clients, sandbox facade and typed errors. (1cdc2f0)
- Toolbox and audit routers wired into the app factory. (75fc3d2)

#### Verification
- Gate 1 on real Docker: quickstart demo (`examples/quickstart.py`). (c7779f0, 75fc3d2)

#### Other
- Restored the orchestration block in `AGENTS.md`, added `.obsidian` to gitignore. (4eb0004)
