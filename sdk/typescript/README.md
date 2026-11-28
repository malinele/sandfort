# @sandfort/sdk

TypeScript SDK for the [Sandfort](https://sandfort.dev) sandbox platform (self-hosted, or the
invite-only hosted beta). It covers the core agent workflow of the Python SDK and has no
runtime dependencies. It is a subset of the API: see
[What is not covered](#what-is-not-covered).

> **Breaking change in 0.2.0.** `SnapshotInfo.imageRef` is now `string | null` (it was
> `string`). The server withholds the operator's registry host and path from label-scoped API
> keys and answers `image_ref: null`; 0.1.x rejected that answer with `InvalidResponseError`, so
> every snapshot call failed for such a key. Code that reads `snapshot.imageRef` as a string
> must now handle `null`. Also new in 0.2.0: verification of the signed audit export trailer
> (see [Audit](#audit)).

## Install

During the beta the SDK is delivered as a packed tarball, not from a public registry. To build
one from the repository:

```bash
cd sdk/typescript
npm ci
npm pack            # runs the build, writes sandfort-sdk-0.2.0.tgz
npm install ./sandfort-sdk-0.2.0.tgz   # in your project
```

It ships compiled JavaScript and type declarations in `dist/`, so it loads in plain Node
(>= 20.3, the `engines` floor) with no TypeScript toolchain required. It is ESM-only
(`import`, not `require`).

## Quickstart

```ts
import { SandfortClient } from "@sandfort/sdk";

const client = new SandfortClient({
  baseUrl: "https://api.sandfort.dev",
  apiKey: process.env.SANDFORT_API_KEY!,
});

const sbx = await client.createSandbox({ snapshot: "python:3.12-slim", wait: true });

// processExec takes the command as a string (or a string[] argv).
// A non-zero exit comes back as data, not an exception.
const r = await sbx.processExec("echo build; exit 7");
console.log(r.exitCode, r.stdout); // 7 "build\n"

const run = await sbx.codeRun("python", "print(21 * 2)");
console.log(run.stdout); // "42\n"

// The parent directory must exist; /tmp always does.
await sbx.fs.uploadFile("/tmp/main.py", new TextEncoder().encode("print('hi')"));

await client.stopSandbox(sbx.id);
await client.deleteSandbox(sbx.id);
```

A `baseUrl` that starts with `http://` and names a host other than loopback (`localhost`,
`127.0.0.0/8`, `::1`) sends the API key in clear text, so the client calls `process.emitWarning`
once, when it is built, with a warning named `InsecureBaseUrlWarning` (code
`SANDFORT_INSECURE_BASE_URL`, name exported as `INSECURE_BASE_URL_WARNING`). Use `https://`. On a
trusted private network, silence it with `node --disable-warning=SANDFORT_INSECURE_BASE_URL`
(Node 20.11 or later).

## What it covers

On the client: `createSandbox`, `getSandbox`, `listSandboxes` / `listSandboxesAll`,
`startSandbox`, `stopSandbox`, `deleteSandbox`; `createSnapshot` (with optional `labels`,
volume-label bounds), `getSnapshot`,
`listSnapshots` / `listSnapshotsAll`, `deleteSnapshot`, `exportSnapshotStream` /
`exportSnapshotBytes` (the `docker save` tar of a `ready` snapshot); the image builder
(`Image`, `buildSnapshot`, `followBuildLogs`; see "Image builder"); `createVolume`, `getVolume`,
`listVolumes` / `listVolumesAll`, `deleteVolume`; `status()`; `updateSandbox` (labels, timers,
`public` and a runtime replacement of the egress allowlist), `resetSandbox`, `resizeSandbox`,
`listIsolation`, `mintPreviewToken`, `statPath`, `followCommandLogs` (see
"Sandbox operations"); the interactive PTY (`connectPty`, `createPty`, `listPtys`, `getPty`,
`resizePty`, `deletePty`; `connectPty` needs a WebSocket — the global one of Node 22+ or the
`webSocket` client option); and the facades `client.webhooks`, `client.apiKeys`,
`client.audit` (including `verifyHead` and `verifyExport`) and `client.usage` (see below).

On a sandbox: `processExec`, `codeRun`; stateful code contexts (see below); sessions and
async commands (`createSession`, `runInSession`, `startCommand`, `getCommand`,
`getCommandLogs`, `killCommand`); the `fs` facade (`listDir`, `mkdir`, `move`, `remove`,
`uploadFile`, `downloadFile`, `stat`); the `git` facade (`clone`, `status`, `add`, `commit`, `push`,
`pull`).

`processExec` and `codeRun` take an optional `cwd`: any non-blank string, sent as is (the same
rule for both; the SDK does not require an absolute path, the server resolves it).

Sessions keep the working directory between `runInSession` calls; exported shell variables do
not persist. The default `python:3.12-slim` image has no `git`; use an image that ships it for
`sandbox.git`.

## Create options

`createSandbox` takes the fields of the `CreateSandboxRequest` schema in camelCase and sends them
in the schema's snake_case names. Options are checked before the request is sent; a bad value
throws `ValidationError`.

```ts
const vol = await client.createVolume("project-data");

const sbx = await client.createSandbox({
  name: "agent-1",
  snapshot: "python:3.12-slim",
  isolation: "gvisor",                                    // "container" | "gvisor" | "microvm"
  resources: { cpuMillicores: 2000, memoryMib: 2048, diskGib: 10 },
  public: false,
  autoStopMinutes: 30,                                    // -1 disables
  autoDeleteMinutes: 240,
  env: { MODE: "ci" },
  labels: { team: "agents" },
  blockNetwork: false,
  egressAllowlist: ["pypi.org"],                          // host names, .domains, CIDRs; [] means no network
  inheritResources: true,                                 // fill unset resource fields from the snapshot's record
  volumes: [
    { volumeId: vol.id, mountPath: "/data" },             // up to 16 mounts
    { volumeName: "models", mountPath: "/models", readOnly: true },
  ],
  idempotencyKey: "job-1234",                             // see Timeouts and retries
});
```

A volume can carry labels, set at creation and used by `listVolumes({ labels })`:

```ts
const vol = await client.createVolume("data", { labels: { team: "agents" } });
console.log(vol.labels, vol.maxBytes, vol.overLimit); // maxBytes is null when unlimited
```

Label keys must be non-blank. `labels`, `maxBytes` and `overLimit` are `undefined` when an
older server omits them. A sandbox's `volumes` are `VolumeMountInfo[]` (`volumeId`,
`mountPath`, `readOnly`).

A volume can be given by id or by name. The API takes ids only, so names cost one extra
`listVolumes` pass per `createSandbox` call (shared by all named mounts of that call) and fail
with `ValidationError` when no volume, or more than one, has that
name. Which isolation tiers a deployment offers is not queried by the SDK; the server answers 422
for a tier it does not offer.

`waitTimeoutS` (default 120) and `pollIntervalS` (default 0.5) must be positive finite numbers.
While waiting, the SDK long-polls the sandbox for up to 30 s at a time and raises the request
timeout of each poll to the poll length plus 10 s, so a small `timeoutMs` does not cut it off.

If `wait` ends in the `error` state the call throws `SandboxFailedError` (it carries
`sandboxId`), and the failed sandbox stays in your organization until you `deleteSandbox` it.

## Pagination

A page is `{ items, nextCursor }`; `nextCursor` is `null` on the last page. It can be passed back
as `cursor` as is (`null` and `undefined` both mean the first page). Filters must be the same on
every page; the server answers 422 naming the field that changed.

```ts
let page = await client.listSandboxes({ labels: { team: "agents" }, limit: 50 });
while (page.nextCursor !== null) {
  page = await client.listSandboxes({
    labels: { team: "agents" },
    limit: 50,
    cursor: page.nextCursor,
  });
}

// or let the SDK do it, lazily, one page at a time:
for await (const sandbox of client.listSandboxesAll({ state: "started", order: "desc" })) {
  console.log(sandbox.id);
}
```

`listSnapshotsAll` and `listVolumesAll` work the same way. Sandbox filters: `state`,
`stopCause`, `labels`, `includeDestroyed`, `order`; volume filter: `labels`.

## Timeouts and retries

```ts
const client = new SandfortClient({
  baseUrl, apiKey,
  timeoutMs: 60_000,  // per request, default 60000
  retries: 2,         // extra attempts, default 2, 0 turns retries off
  deadlineMs: 90_000, // optional: overall budget of one call, attempts and pauses together
});

const controller = new AbortController();
await client.getSandbox("sbx_1", { signal: controller.signal });  // every call takes `signal`
```

- A request that exceeds `timeoutMs` rejects with `RequestTimeoutError`; one aborted through
  `signal` rejects with `RequestAbortedError`. Both extend `TransportError`. Exec, code-run and
  session commands get at least their `timeoutS` plus 10 s, so the client does not cut off a
  command the server is still running. Large file transfers share the same timeout; raise
  `timeoutMs` for them.
- The TypeScript SDK never re-sends a POST after a 429 unless it carries an `idempotencyKey`
  (unlike the Python SDK, which also resends a keyless POST after a 429 `RATE_LIMITED`).
- Retries cover only a 429 (except `QUOTA_EXCEEDED`) and a 503 with code `CAPACITY`, and only
  for calls that are safe to repeat: GET, PUT and DELETE requests, and `createSandbox` with an
  `idempotencyKey`. A create without a key is never resent. Each pause honours `Retry-After`
  (capped at 30 s; all pauses of one call together stay within 60 s), or backs off with jitter.
  Timeouts, network failures and every other error are final.
- `deadlineMs` (off by default) bounds one call as a whole: every attempt and every retry pause
  together. When it runs out the call rejects with `RequestTimeoutError`, an attempt never
  outlives it, and a retry pause that would run past it is not started (the last reply is then
  returned as the error). It is a client option, so it applies to every call of that client.
- With the same `idempotencyKey` and arguments the server returns the same sandbox instead of
  creating another.

## Errors

All errors extend `SandfortError`.

- `ApiError` and subclasses `NotFound`, `Unauthorized`, `Forbidden`, `Conflict`, `InvalidState`,
  `RateLimited`, `ValidationFailed`: the server answered. Each carries `code`, `status`,
  `details` and `requestId`.
- `ValidationError`: an argument failed the SDK's own checks; nothing was sent.
- `TransportError`, `RequestTimeoutError`, `RequestAbortedError`, `InvalidResponseError`.
- `SandboxFailedError`, `SandboxTimeoutError`, `SnapshotFailedError`, `SnapshotTimeoutError`
  (all exported as values, so `instanceof` works).

## Secrets shown once

The secret of a create answer is a non-enumerable property: `apiKeys.create(...).key`,
`webhooks.create(...).secret` and `mintPreviewToken(...).token`. It stays out of
`JSON.stringify`, `Object.keys` and `console.log` / `util.inspect`. Read it immediately and
store it: a copy of the object (spread, `Object.assign`, `structuredClone`) does not carry it,
and `util.inspect(value, { showHidden: true })` still shows it, so do not log with that.
The `url` and `browserUrl` of a preview answer hold the same token and stay enumerable, so do
not log the whole answer.

```ts
const created = await client.apiKeys.create("ci", ["sandboxes:read"]);
const plaintext = created.key;    // read it now
const copy = { ...created };      // copy.key is undefined
```

## Scopes

Besides the scopes named in the sections above, `client.audit` needs the `audit:read` scope and
`client.usage` needs `usage:read`; a key without them gets `Forbidden`.

## Version

`VERSION` and `buildInfo()` (`{ name, version }`) report the SDK version, which also goes out as
the `User-Agent` of every request. `await client.status()` reads the public `GET /v1/status`:
server `version`, `buildSha`, `imageSha`, `buildMatchesImage`, `startedAt`, the operator
notice, and `auditPublicKey` / `auditKeyFingerprint` (the Ed25519 key that signs audit export
trailers and its fingerprint; both `null` while the server signs no heads).

## Git credentials

A credentialed `git.push` or `git.pull` must pass `remoteUrl` (the http(s) url of the remote)
together with `credential`. The server binds the token to that host and runs git against that
url, not against the url the sandbox's own git config names for the remote, so code running in
the sandbox cannot redirect the token. Without `remoteUrl` the SDK throws before any
request; without a credential `remoteUrl` is optional.

```ts
await sandbox.git.push("/work/repo", {
  remoteUrl: "https://github.com/acme/app.git",
  credential: { username: "x-access-token", token },
});
```

## Code contexts

A code context is a persistent Python kernel inside a started sandbox: variables and imports
survive from one run to the next. The state lives in the kernel process, so it is lost when the
sandbox is stopped, reset or deleted. Only Python is supported. Every call exists on the client
(with a sandbox id first) and on a `Sandbox`.

```ts
const sbx = await client.createSandbox();
// The live context of that name, or a new empty one; `created` says which.
const { context, created } = await sbx.ensureCodeContext("analysis");
if (created) await sbx.runInCodeContext(context.id, "import json; total = 0");

const cell = await sbx.runInCodeContext(context.id, "total += 41; total + 1", { timeoutS: 30 });
console.log(cell.result, cell.stdout, cell.stopReason); // "42" "" null

for await (const event of sbx.streamCodeContextRun(context.id, "print('working')")) {
  if (event.type === "stdout" || event.type === "stderr") process.stdout.write(event.data);
  else console.log(event.result.exitCode); // the last event is always the result
}

await sbx.interruptCodeContext(context.id); // KeyboardInterrupt in the running cell
await sbx.deleteCodeContext(context.id);
```

`runInCodeContext` returns a `CellResult`: the exec fields plus `result` (the `repr` of the
trailing expression), `error` (`{ type, message }` of a raised exception), `sandboxStopped` and
`stopReason` (`timeout`, `queue_timeout`, `output_limit`, `context_lost`, `sandbox_stopped`,
`sandbox_deleted`, `sandbox_reset`, `oom_killed`, `killed`, or `null`). A cell that exceeds `timeoutS` reports
`timedOut` and the state stays. Runs of one context are serialized by the server.
`streamCodeContextRun` raises the typed error of an `error` event and `TransportError` when the
stream ends without a result; a dropped stream cannot be resumed, a new call is a new run.
`createCodeContext` with a `name` answers `{ context, created }` like `ensureCodeContext` (on the
client and on a `Sandbox`); without a name it returns the new context. `name` is unique per API
process only: two creates of one name racing across processes may both succeed.

## Webhooks

`client.webhooks` manages endpoints and their delivery history. Every route needs the
`webhooks:write` scope. The server generates the signing secret and returns it on the answer of
`create` only; it is readable as `endpoint.secret` but not enumerable, so it stays out of
`JSON.stringify` and logs.

```ts
const endpoint = await client.webhooks.create("https://hooks.example/in", ["sandbox.*"]);
const secret = endpoint.secret; // shown once: store it now

await client.webhooks.update(endpoint.id, { enabled: false }); // only the given fields
const all = await client.webhooks.list();
const same = await client.webhooks.get(endpoint.id);

const page = await client.webhooks.deliveries(endpoint.id, { state: "failed", limit: 20 });
const started = { eventType: "sandbox.started" };
for await (const d of client.webhooks.deliveriesAll(endpoint.id, started)) {
  console.log(d.id, d.state, d.attemptHistory.length);
}
const delivery = await client.webhooks.getDelivery(endpoint.id, "dlv_1");
await client.webhooks.redeliver(endpoint.id, delivery.id); // a failed or disabled delivery
await client.webhooks.delete(endpoint.id); // answers the endpoint as it was
```

`deliveries` filters on `eventType` and `state` (`pending`, `delivered`, `failed`, `disabled`);
a cursor is bound to those filters, and a filtered page can be empty while `nextCursor` is set.
`create` and `redeliver` are POSTs without an idempotency key, so they are never resent after
a 429, a 503 or a lost connection.

## API keys

`client.apiKeys` needs the `api_keys:admin` scope. A key can only grant scopes its creator holds.

```ts
const created = await client.apiKeys.create("ci", ["sandboxes:read"], {
  sandboxLabels: { team: "agents" }, // limits the key to sandboxes with these labels (max 8)
  maxSandboxes: 5, // needs sandboxLabels
  expiresAt: new Date("2027-01-01T00:00:00Z"),
});
const plaintext = created.key; // returned once, not enumerable, cannot be read back

const active = await client.apiKeys.list({ status: "active" }); // or "revoked"; default: all
const revoked = await client.apiKeys.revoke(created.id, { cascade: true });
console.log(revoked.dependants.map((k) => k.id)); // live descendants (revoked with cascade)
```

`ApiKeyInfo` never carries the secret or its hash. `status` is `active`, `expired` or `revoked`.
A `create` is never resent: if its answer is lost, list the keys before trying again.

## Audit

`client.audit` reads the org's audit log.

```ts
const page = await client.audit.list({
  action: "sandbox.create",
  outcome: "denied",
  from: new Date("2026-11-01T00:00:00Z"),
  to: new Date("2026-11-08T00:00:00Z"),
  order: "desc",
  limit: 50,
});
for await (const event of client.audit.listAll({ actorId: "key_1" })) console.log(event.id);

const verdict = await client.audit.verifyChain(); // the server walks the whole hash chain
if (!verdict.ok) console.error(verdict.findings);
await client.audit.verifyChain({ fromId: "aud_100" }); // from that event on

for await (const line of client.audit.exportLines({ outcome: "denied" })) {
  process.stdout.write(line); // newline-delimited JSON, one row per line, then a trailer line
}
```

Filters: `actorId`, `action`, `targetId`, `requestId`, `outcome`, `from`, `to` (both `Date`s, sent
as UTC), `order` (`asc` default), `cursor`, `limit` (1 to 100). `verifyChain` is the full check;
it needs no client-side hashing. `exportLines` yields each line with its `\n` (the last one may
lack it) as the body arrives, does not parse it, and sends its request on the first read; pass
`timeoutMs` to give a large export more time than the client's `timeoutMs`. A stream that
breaks raises `TransportError` (`RequestAbortedError` after your `signal`); lines read before
that stay valid.

### Verifying an export

A server that has an audit signing key ends every non-empty export with a signed `audit_head`
line. The SDK checks it with `node:crypto` (no new dependency), as the Python SDK does:

```ts
import { verifyExport, verifyHead } from "@sandfort/sdk";

// Pin the key out of band when you can (the fingerprint is printed by the Python CLI and
// published as `auditKeyFingerprint` on /v1/status).
const publicKey = "...urlsafe base64 of the 32 raw key bytes...";

const result = await client.audit.verifyExport(
  client.audit.exportLines({ from: new Date("2026-11-01T00:00:00Z") }),
  publicKey, // or "status": read it from GET /v1/status after the file has been read
);
if (!result.ok) throw new Error(`export not verified (${result.reason})`);

verifyHead(trailerLine, publicKey); // the signature alone, no file, no network
```

`verifyHead(headLine, publicKey)` (pure, synchronous) checks the Ed25519 signature over the
head without `signature` and `hmac`, as compact JSON with sorted keys and ASCII only. The key
you pass is the trust anchor: the `public_key` named in the line is only compared with it (a
different one is `key_mismatch`), so a head forged under the forger's own key is refused.
It returns `{ ok, rowId, entryHash, publicKey, reason, signedAt, orgId }`; `reason` is `null` or one of
`unsigned`, `signature`, `key_mismatch`, `undated` (no valid `signed_at`),
`future_signed_at` (more than 5 minutes ahead of the local clock) and `expected_org_mismatch`
(see below). It throws `ValidationError` for a malformed line or key and never throws for a bad
signature.

`verifyExport(lines, publicKey, { allowUnchained?, previous?, expectedOrgId? })` takes the whole text, an
iterable of lines or an async iterable such as `exportLines()`. After the head it checks that
the file matches it: with a head that carries `signed_at` and `export_sha256` (and `row_count`, `first_row_id`) the row count, the SHA-256 over
the exact bytes of every event line and the first row id (`count_mismatch`, `content_mismatch`,
`first_row_mismatch`), then the last row against the head (`truncated`, `head_mismatch`), the
`prev_hash` linkage (`chain_break`, skipped for a filtered head), rows without a hash
(`unchained_rows`) and, with `previous` (an earlier export), that its event lines are an exact
byte prefix (`not_a_continuation`). It also reports `malformed_row`, `misplaced_trailer`,
`org_mismatch` and `no_trailer`, with `badLine` naming the line. It throws `ValidationError`
for an empty file, a last `export_summary` line (an unsigned export) or a bad key.

Org binding (0.2.1). `orgId` is the head's `org_id` when it is a non-empty text, else `null`, on
every result of `verifyHead` and `verifyExport`. Without more, a genuinely signed export of org B
verifies as ok when it is presented as org A's, so pass the org you expect:
`verifyHead(line, key, { expectedOrgId })` and `verifyExport(lines, key, { expectedOrgId })`
(also on `client.audit.verifyHead` and `client.audit.verifyExport`). A signed head that names
another org, or none, fails with `expected_org_mismatch`, checked after the signature (an
unsigned or tampered head keeps `unsigned` or `signature`) and before `signed_at`; the file
checks of `verifyExport` do not run then. An empty `expectedOrgId` throws `ValidationError`.
This is not the row-level `org_mismatch`, where a row's `org_id` differs from the head's.

What a client cannot prove: the row hashes are keyed with the server's chain key, and the
`hmac` of the head needs it too, so neither is recomputed here. A server that signs a
fabricated export verifies. Only `client.audit.verifyChain()` (the server-side walk) proves the
whole chain. Against a head without a content binding (no `export_sha256`, `row_count` or `first_row_id`), rows before
the last can be replaced by someone who rewrites `prev_hash` and `hash` consistently; check
`signedAt` so that an old, genuinely signed export is not taken for a fresh one.

Deviations from the Python SDK, both kept on purpose:

- Numbers are canonicalized as `JSON.parse` reads them. A number token rewritten in the head
  line as `3.0` or `3e0` still parses to the integer 3 and verifies, where the Python SDK would
  fail with `signature`. Only semantically equal values pass, so this does not let a forger
  change what the head says.
- With `publicKey: "status"` on the `client.audit` facade, the key is read from the `/v1/status`
  of the server being audited, so the trust anchor comes from the thing under audit. For a real
  audit, pin the key out of band (from the operator's records, not from that server) and pass it
  explicitly.

## Usage

`client.usage.get` returns the metered totals of the org for an explicit period.

```ts
const period = { from: new Date("2026-11-01T00:00:00Z"), to: new Date("2026-12-01T00:00:00Z") };

const totals = await client.usage.get(period);
console.log(totals.totals); // [{ dimension: "vcpu", unit: "...", total: 12.5 }, ...]

const page = await client.usage.get({ ...period, groupBy: "sandbox", limit: 20 });
const next = await client.usage.get({ ...period, groupBy: "sandbox", cursor: page.nextCursor });

for await (const group of client.usage.groupsAll({ ...period, groupBy: "label:team" })) {
  console.log(group.groupValue, group.totals);
}
```

`groupBy` is `"sandbox"` or `"label:<key>"`; `cursor` and `limit` need it, and a cursor goes with
the same `from`, `to` and `groupBy`. `groupsAll` walks the pages and raises
`InvalidResponseError` when the server repeats a cursor. A key limited to labelled sandboxes sees
only the sandboxes that carry all of its labels. Bad arguments raise `ValidationError` before
anything is sent.

## Sandbox operations

All of these exist on the client (sandbox id first) and on a `Sandbox`; the ones that return a
sandbox return a new `Sandbox` handle with the fresh record (handles are immutable).

```ts
// PATCH: labels (replaces all; null removes them all), auto timers in minutes (-1 = off), public.
const tagged = await sbx.update({ labels: { team: "infra" }, autoStopMinutes: 30 });

// Replace the egress allowlist (host names, leading-dot domains, CIDR ranges) of a sandbox
// created with a non-empty one; [] refuses every connection. The new `egressPolicyGeneration`
// is on the returned handle when the list changed (an equal list is a server-side no-op).
const narrowed = await sbx.update({ egressAllowlist: ["pypi.org"] });
console.log(narrowed.egressPolicyGeneration, narrowed.egressAllowlist);

// Replace the container with a fresh one; id, labels, volumes and timers are kept.
const fresh = await sbx.reset();

// New resources, stopped sandboxes only: any other state answers 409 (`Conflict`).
await client.stopSandbox(sbx.id);
const bigger = await client.resizeSandbox(sbx.id, { cpuMillicores: 2000, memoryMib: 4096 });

const tiers = await client.listIsolation(); // { default: "container", available: [...] }

// A started sandbox only (409 otherwise); ttlSeconds 60..604800, server default 3600.
const preview = await sbx.mintPreviewToken({ port: 3000, ttlSeconds: 600 });
console.log(preview.url, preview.expiresAt);
// browserUrl is set only when the server's preview origin is HTTPS: open it in a browser (the
// token sits in its fragment). Use url, or the Sandfort-Preview-Token header, from scripts.
console.log(preview.browserUrl);

const entry = await sbx.fs.stat("/tmp/main.py"); // { kind, sizeBytes, mode, modifiedAt, ... }

// Follow a command's output over server-sent events; the last event is `exit`.
const cmd = await sbx.startCommand(session.id, "make build");
for await (const event of sbx.followCommandLogs(session.id, cmd.id)) {
  if (event.type === "exit") console.log("exit", event.exitCode, event.state);
  else process.stdout.write(event.line); // event.type is "stdout" or "stderr"
}
```

The API does not rename a sandbox, so `update` has no `name`. Arguments are checked before any
request (`ValidationError`): `update` and `resize` need at least one field. `egressAllowlist`
entries (host names, leading-dot domains and CIDR ranges) are not checked client-side. The server
answers 422 `UNPROCESSABLE` for most invalid entries (uppercase, a scheme, a port, a wildcard, a bad
or denied CIDR, too many entries) and 422 `VALIDATION_ERROR` for whitespace or control characters
and malformed requests; both are `ValidationFailed`. `[]` is sent as an empty list, and `null` is
rejected, since an allowlist cannot be removed. The generation rises by 1 only when the list
actually changes: a list equal to the stored one is a no-op (200, nothing changes). The server
answers 409 `INVALID_STATE` (`InvalidState`, a `Conflict`) when the sandbox has no allowlist to
replace, was created with an empty one while `blockNetwork` was on, or predates egress v2, and 403
`FORBIDDEN` when operator policy forbids the change; the proxy applies the new list within its
cache window. Generation 0 with a non-null `egressAllowlist` means a legacy v1 credential: `reset`
to upgrade. With `egressAllowlist: null` the sandbox was created without an allowlist, and no
update or reset will enable one (reset would only discard the container's filesystem). `followCommandLogs` sends one event per line. Each event has `offset` (where its line starts) and `nextOffset` (the
resume point after it, from the SSE `id`; `null` if the server sent none). To resume, pass the
`nextOffset` of the last event you saw as `offset`: the stream continues with the following
line, none repeated and none missing. A stream that ends without `exit` throws
`TransportError`, an `error` event throws the typed error of its code, and leaving the loop
early closes the connection.

```ts
let resumeAt = 0;
try {
  for await (const event of sbx.followCommandLogs(session.id, cmd.id, { offset: resumeAt })) {
    if (event.nextOffset !== null) resumeAt = event.nextOffset;
    // ... handle the event
  }
} catch (error) {
  // a broken connection: call followCommandLogs again with { offset: resumeAt }
}
```

## Per-call options

Every call that takes options also accepts `signal`, `timeoutMs`, `retries` and `deadlineMs`.
They replace the client-wide values of the same name for that one call and are validated the
same way. A per-call `timeoutMs` that fires throws `RequestTimeoutError`, a per-call
`deadlineMs` too; an aborted `signal` throws `RequestAbortedError`. `createSandbox` applies
them to the create request; its wait polls use the client settings. For `followCommandLogs`,
`timeoutMs` bounds the whole stream (the default is long enough for the longest command). An
explicit `timeoutMs` always wins: exec, code-run, session and code-context runs raise the
request timeout to their `timeoutS` plus a margin only when the call sets no `timeoutMs`.
`retries` only helps calls that are safe to repeat (GET, HEAD, PUT, DELETE, or a POST with an
idempotency key); every other POST (`reset`, `processExec`, `codeRun`, `runInSession`,
`mintPreviewToken`, code-context runs, ...) is sent once, on a 429, a 503 or a network error.
A `deadlineMs`, per call or on the client, also caps long streams: `followCommandLogs`,
`streamCodeContextRun` and `audit.exportLines` stop with `RequestTimeoutError` ("exceeded its
deadline") when it runs out, however long the command or export still runs.

```ts
await client.getSandbox("sbx_1", { timeoutMs: 2_000, retries: 0 });
await sbx.reset({ deadlineMs: 10_000 });
```

## Image builder

`Image` is an immutable builder, like the Python `sandfort_sdk.image.Image`: every method returns
a new `Image`, and `serialize()` returns the image spec wire form (`schema_version` `"1"`) that
`POST /v1/images/builds` takes. Blank names and non-string values are a `ValidationError`; the
server enforces the structural limits and refuses unsafe values (a 422 `ValidationFailed`).

```ts
import { Image, SandfortClient } from "@sandfort/sdk";

const image = Image.debianSlim()          // python:3.12-slim
  .pipInstall("requests", "numpy")        // also accepts arrays; repeated names are skipped
  .aptInstall("git")
  .env({ APP_ENV: "dev" })
  .workdir("/app")
  .addFile("/app/hello.py", "print('hi')\n"); // a later file at the same path replaces it

const snap = await client.buildSnapshot(image, { name: "my-image" }); // `name` is optional
for await (const event of client.followBuildLogs(snap.id)) {
  if (event.type === "log") console.log(event.line);
  else console.log(event.state, event.succeeded);                    // final event
}
```

`Image.fromImage(reference)` starts from any registry image. `buildSnapshot` also takes a raw
wire-form spec object in place of an `Image`. It answers `pending` while the build runs, or
`ready` with `reused: true` when an identical spec was built before (`specHash` identifies the
spec). `followBuildLogs(snapshotId)` yields one `{ type: "log", line, index }` event per log
line, then a final `{ type: "state", state, snapshotId, digest, reason, succeeded }` event,
after which it ends; a stream that ends without the `state` event throws `TransportError`. The
request is sent on the first read, and the per-request timeout of the stream is at least 1 h
(an explicit `timeoutMs` replaces the floor).

## What is not covered

The TypeScript SDK is a subset of the REST API. It has no client for: jobs, org quota and
members, or SSO (and no SCIM client). For these, call the REST API directly; every
operation is in the OpenAPI spec (`openapi/sandfort.v1.json`). Snapshot registration IS
covered: `client.registerSnapshot(image, { name?, labels? })` posts `POST /v1/snapshots` and
returns the registered snapshot (the server pulls the image and answers `ready`). Snapshot export IS covered too: `client.exportSnapshotStream(id)` yields the tar
chunks and `client.exportSnapshotBytes(id)` holds the whole tar in memory; the server answers 409
(`InvalidState`) unless the snapshot is `ready`. The per-request timeout of an export is at
least 1 h and bounds the whole stream, body included (an explicit `timeoutMs` replaces the
floor; `deadlineMs` does not raise it and may end the call sooner). The tar is what
`docker save` produces: load it with `docker load -i <file>`. To write it to disk:

```ts
import { createWriteStream } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

await pipeline(Readable.from(client.exportSnapshotStream(id)), createWriteStream(file));
```

`SandboxInfo` also reports `createdAt`, `updatedAt`, `stoppedAt`, `stopCause`, `isolation`,
`volumes` (`VolumeMountInfo[]`) and `egressAllowlist`. They are `undefined` when the server
omits them, and `null` where the API sends null. `errorCode` (`SandboxErrorCode`, from the exported
`SANDBOX_ERROR_CODES`) says why a sandbox settled in `error`, for example `egress_unavailable`; it
is `null` when the server sends none, and a code this SDK does not know comes through as the plain
string, like `state`. `egressPolicyGeneration` is always a number: the version of the egress
allowlist, 0 when the server sends none (or null) or the sandbox predates egress v2; any other
non-integer value raises `InvalidResponseError`. Read 0 together with `egressAllowlist`: with a
non-null list it is a legacy v1 credential (`reset` upgrades it); with `egressAllowlist: null` no
allowlist was ever set and neither `update` nor `reset` will enable one.

## License

Apache-2.0, see `LICENSE` in this directory. The Sandfort server is licensed separately under
FSL-1.1-Apache-2.0; see the repository root.
