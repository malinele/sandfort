# @sandfort/sdk

TypeScript SDK for the [Sandfort](https://sandfort.dev) sandbox platform (self-hosted, or the
invite-only hosted beta). It covers the core agent workflow of the Python SDK and has no
runtime dependencies. It is a subset of the API: see
[What is not covered](#what-is-not-covered).

## Install

During the beta the SDK is delivered as a packed tarball, not from a public registry. To build
one from the repository:

```bash
cd sdk/typescript
npm ci
npm pack            # runs the build, writes sandfort-sdk-0.1.7.tgz
npm install ./sandfort-sdk-0.1.7.tgz   # in your project
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

## What it covers

On the client: `createSandbox`, `getSandbox`, `listSandboxes` / `listSandboxesAll`,
`startSandbox`, `stopSandbox`, `deleteSandbox`; `createSnapshot` (with optional `labels`,
volume-label bounds), `getSnapshot`,
`listSnapshots` / `listSnapshotsAll`, `deleteSnapshot`, `exportSnapshotStream` /
`exportSnapshotBytes` (the `docker save` tar of a `ready` snapshot); `createVolume`, `getVolume`,
`listVolumes` / `listVolumesAll`, `deleteVolume`; `status()`; `updateSandbox`, `resetSandbox`,
`resizeSandbox`, `listIsolation`, `mintPreviewToken`, `statPath`, `followCommandLogs` (see
"Sandbox operations"); and the facades `client.webhooks`, `client.apiKeys`, `client.audit` and
`client.usage` (see below).

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
  egressAllowlist: ["pypi.org"],                          // [] means no network
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
server `version`, `buildSha`, `imageSha`, `buildMatchesImage`, `startedAt` and the operator
notice.

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
that stay valid. The signed `audit_head` trailer is not verified by this SDK.

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

// Replace the container with a fresh one; id, labels, volumes and timers are kept.
const fresh = await sbx.reset();

// New resources, stopped sandboxes only: any other state answers 409 (`Conflict`).
await client.stopSandbox(sbx.id);
const bigger = await client.resizeSandbox(sbx.id, { cpuMillicores: 2000, memoryMib: 4096 });

const tiers = await client.listIsolation(); // { default: "container", available: [...] }

// A started sandbox only (409 otherwise); ttlSeconds 60..604800, server default 3600.
const preview = await sbx.mintPreviewToken({ port: 3000, ttlSeconds: 600 });
console.log(preview.url, preview.expiresAt);

const entry = await sbx.fs.stat("/tmp/main.py"); // { kind, sizeBytes, mode, modifiedAt, ... }

// Follow a command's output over server-sent events; the last event is `exit`.
const cmd = await sbx.startCommand(session.id, "make build");
for await (const event of sbx.followCommandLogs(session.id, cmd.id)) {
  if (event.type === "exit") console.log("exit", event.exitCode, event.state);
  else process.stdout.write(event.line); // event.type is "stdout" or "stderr"
}
```

The API does not rename a sandbox, so `update` has no `name`. Arguments are checked before any
request (`ValidationError`): `update` and `resize` need at least one field. `followCommandLogs`
sends one event per line. Each event has `offset` (where its line starts) and `nextOffset` (the
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

## What is not covered

The TypeScript SDK is a subset of the REST API. It has no client for: PTY, jobs, org quota and
members, image builds, or SSO. For these, call the REST API directly; every
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
omits them, and `null` where the API sends null.

## License

Apache-2.0, see `LICENSE` in this directory. The Sandfort server is licensed separately under
FSL-1.1-Apache-2.0; see the repository root.
