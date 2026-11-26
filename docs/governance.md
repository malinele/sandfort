# Governance reference

For platform and compliance reviewers. Every statement here was checked against the server
package (`src/sandfort/`); the source file is named where a reviewer may want to confirm it.
Defaults are the values in `src/sandfort/config.py`. Environment variables carry the
`SANDFORT_` prefix.

## API key scopes

An API key holds one or more of 12 scopes and belongs to one organization. Every authenticated
route requires exactly one scope (`src/sandfort/auth/scopes.py`); a missing scope is a 403
that lists it.

| Scope | Endpoints |
|---|---|
| `org:read` | `GET /v1/org/quota`, `GET /v1/org/quota/recount`, `GET /v1/org/members`, `GET /v1/nodes` |
| `sandboxes:read` | `GET /v1/sandboxes`, `GET /v1/sandboxes/{id}`, `GET /v1/sandboxes/{id}/logs`, `GET /v1/isolation`, `GET /v1/jobs`, `GET /v1/jobs/{id}` |
| `sandboxes:write` | `POST /v1/sandboxes`, `PATCH`/`DELETE /v1/sandboxes/{id}`, `POST /v1/sandboxes/{id}/start`, `/stop`, `/resize`, `/preview-tokens` |
| `toolbox:use` | everything under `/v1/sandboxes/{id}/toolbox/`: `process/execute`, `process/code-run`, `process/sessions`, `fs`, `git`, `pty` (REST) |
| `snapshots:read` | `GET /v1/snapshots`, `GET /v1/snapshots/{id}`, `GET /v1/images/builds/{id}/logs` |
| `snapshots:write` | `POST /v1/snapshots`, `POST /v1/snapshots/from-sandbox`, `DELETE /v1/snapshots/{id}`, `POST /v1/images/builds` |
| `volumes:read` | `GET /v1/volumes`, `GET /v1/volumes/{id}` |
| `volumes:write` | `POST /v1/volumes`, `DELETE /v1/volumes/{id}` |
| `api_keys:admin` | `/v1/api-keys` (create, list, revoke); `POST /v1/org/members`, `PATCH`/`DELETE /v1/org/members/{id}`; `PUT /v1/org/quota` (also needs a platform-admin key); `/v1/org/scim-tokens` when `SANDFORT_SCIM_ENABLED=true` |
| `webhooks:write` | all of `/v1/webhooks`, including list, get, deliveries and redeliver |
| `usage:read` | `GET /v1/org/usage` |
| `audit:read` | `GET /v1/audit-events`, `GET /v1/audit-events/export`, `GET /v1/audit-events/verify` |

Not behind a scope:

- `GET /healthz`, `GET /readyz`, `GET /metrics`, `GET /console` (a page that carries no data;
  the operator types a key into it) and `POST /v1/auth/sso/exchange` (it takes an identity
  token and returns a session).
- The PTY websocket `/v1/sandboxes/{id}/toolbox/pty/{pty}/connect` authenticates with the
  one-time token that `POST .../toolbox/pty` returns, not with a key.
- `/scim/v2` (only mounted when `SANDFORT_SCIM_ENABLED=true`) takes a SCIM bearer token.
- The preview proxy and the web terminal page use their own preview and connect tokens.

Keys cannot mint scopes their creator lacks: asking for a scope outside the creating key's
set is a 403 `ScopeEscalation` (`src/sandfort/services/api_key_admin.py`). Human users get
scopes from a role (`admin`, `developer`, `viewer`; `src/sandfort/domain/user.py`); `developer`
lacks `api_keys:admin` and `audit:read`, and `viewer` holds only the read scopes.

### Label-scoped keys

Scopes are per action. A key with `toolbox:use` and no label scope can exec in any sandbox of
its organization. To bind a key to a set of sandboxes, give it a label scope: `POST
/v1/api-keys` accepts an optional `sandbox_labels` object (`{key: value}`, at most 8 pairs;
label names starting with `sandfort.` are reserved). Absent or empty means the key is not
label scoped. The scope is stored with the key and shown by the key list. Source:
`src/sandfort/services/label_scope.py`, `src/sandfort/services/api_key_admin.py`.

A scoped key only sees and acts on sandboxes whose labels contain all of its pairs:

- A sandbox outside the scope answers 404, so its existence is not revealed.
- The sandbox list is filtered to the scope. A list filter that contradicts the scope (same
  label name, other value) returns an empty page.
- A create through the key gets the scope pairs added to its labels; other labels in the
  request are kept (`merge_scope` in `src/sandfort/services/label_scope.py`). A create with no
  labels, or with extra labels, is therefore an in-scope create; it meets the per-key
  `max_sandboxes` cap with 429 like any other. Only a label that names a scope key with another
  value is refused, with a 403, "this API key is limited to sandboxes labelled k=v". That
  refusal happens in `SandboxService.create` before the cap and the quota are checked, so a
  contradicting label is never masked by a 429.
- The internal ids of the sandbox and snapshot objects are withheld from a scoped key: `node_id`
  and `job_id` of a sandbox and `source_sandbox_id` of a snapshot are `null` for it (commit
  da31b5a, `src/sandfort/api/schemas/sandboxes.py`, `snapshots.py`). `GET /v1/nodes` is a 403
  for a scoped key.
- Changing the labels of a sandbox so that it leaves the scope is also a 403.
- A scoped key can only create keys whose scope contains all of its own pairs. Anything
  else is a 403 that lists the missing pairs under `details.excess_labels`.
- Every toolbox route under `/v1/sandboxes/{id}/toolbox/` runs a router-level guard first,
  so handlers that look up a session, command or PTY by id are covered too: a sandbox
  outside the scope answers 404 (`src/sandfort/api/routes/toolbox/scope_guard.py`).
- A scoped key with `api_keys:admin` lists and revokes only keys whose own labels contain all
  of its pairs (itself included); any other key id answers 404
  (`src/sandfort/services/api_key_admin.py`).
- A snapshot committed from a sandbox is visible and usable (get, list, delete, create a
  sandbox from it) only when its source sandbox is in the scope. A destroyed source keeps
  its labels and still decides; a source row that is gone hides the snapshot. Snapshots with
  no source sandbox (registered images, image builds) stay visible
  (`snapshot_in_label_scope` in `src/sandfort/services/snapshots.py`).
- Build logs follow the snapshot rule. Jobs (`GET /v1/jobs`, `GET /v1/jobs/{id}`) are
  visible to a scoped key only when the sandbox and snapshot their payload names are in the
  scope; jobs that name neither stay visible. Image build and snapshot create jobs also need
  `snapshots:read` from every caller, and the build spec is removed from the job payload for
  a scoped caller (`src/sandfort/api/routes/jobs.py`).
- The check that refuses to delete a snapshot still in use scans every sandbox of the
  organization, not only those in the scope, so a scoped key cannot delete an image from
  under another team's sandbox. The 409 names the sandbox only when the scope can see it.
- Idempotency keys are stored per `(org, API key, Idempotency-Key)`: another key sending the
  same `Idempotency-Key` neither replays the first key's response, nor gets a mismatch
  error, nor waits on its in-flight request (`src/sandfort/services/idempotency.py`).
- Sandbox names stay unique per organization. A create with a name that a sandbox outside
  the scope already uses answers 409 "sandbox name already exists in this org", which
  reveals that the name exists. Open; use per-scope name prefixes where that matters.
- `created_by` on an API key object (the id of the key that minted it) is visible to org-wide
  keys only. A label-scoped caller gets `created_by: null` on create, list and revoke, because the
  id would identify the admin key that minted its own key
  (`src/sandfort/api/routes/api_keys.py`, `src/sandfort/api/schemas/api_keys.py`, commit 7cdfb86).
  The stored value does not change; the key list of an org-wide caller still shows it.

Usage is label-scoped too: a scoped key that holds `usage:read` sees only its own sandboxes in
`GET /v1/org/usage`, in the totals, the per-sandbox groups and the per-label groups alike
(`src/sandfort/api/routes/usage.py`). Volumes follow the label rules in the next section. Audit
access requires an org-wide key: the three audit routes (`GET /v1/audit-events`, `/export` and
`/verify`) answer 403 ("audit events are org-wide; use an API key without sandbox labels") to a
key with `sandbox_labels`, even when it holds `audit:read`, because audit events belong to the
whole organization and a label scope only limits sandboxes (`src/sandfort/api/routes/audit.py`,
commit 41f9d3e).
Workers (reconciler, auto-stop, garbage collector) are not scoped. In a multi-node
deployment a forwarded request carries the caller's own credential and is checked again on
the node that owns the sandbox.

The SDK (`create_api_key`, `list_api_keys`, `revoke_api_key`) and the CLI (`sandfort key
create`, `sandfort key list`, `sandfort key revoke`) manage API keys too; the CLI `create` takes
`--scope` and `--label`, both repeatable. The same call through the REST API:

```bash
curl -s "$SANDFORT_BASE_URL/v1/api-keys" \
  -H "Authorization: Bearer $SANDFORT_API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"assistant-a","scopes":["sandboxes:read","sandboxes:write","toolbox:use"],
       "sandbox_labels":{"team":"a"}}'
```

The response shows the new key once. The `api_key.created` audit event records the
`sandbox_labels` of the new key.

### Volumes and labels

Volumes carry user labels, like sandboxes. Label names starting with `sandfort.` are reserved
and are not returned. Source: `src/sandfort/services/volumes.py`.

- A label-scoped key that creates a volume gets its scope pairs merged into the volume's labels.
- A label-scoped key sees only volumes whose labels carry all of its scope pairs; its volume
  list is filtered to them.
- A label-scoped key may mount only a volume carrying its scope labels. Any other volume, and
  a volume id that does not exist, is refused alike with a 403 naming the volume, so the
  answer does not reveal whether the id exists.
- Mount mode decides the key scope the create needs. A read-only mount (`read_only: true`)
  needs `volumes:read`. A read-write mount needs `volumes:write`. A create that mixes both
  modes needs both scopes.

## Image reference policy

Docker resolves a raw image reference against the host's local image store before any pull,
and it also resolves image IDs. Every user-supplied image reference is therefore checked
first (`check_user_image_reference` in `src/sandfort/images/dockerfile.py`, re-exported by
`src/sandfort/services/image_policy.py`). It applies to the image of a sandbox create, the
`base_image` of an image build and the image of a snapshot register (`POST /v1/snapshots`).
Refused with 422 `UNPROCESSABLE`:

- an image ID: `sha256:<hex>`, a bare 64-hex id or a short hex prefix ("image IDs are not
  accepted; pass an image name such as python:3.12-slim");
- a reference that names a reserved repository, compared case-insensitively on the part
  before the tag or digest, also with a registry prefix: `sandfort-snapshot` (where
  committed snapshot images live) and `moby-dangling` (the name Docker's containerd image
  store gives untagged images).

`name@sha256:...` with a repository name stays valid. A committed snapshot is reached only
by its snapshot id, which is scoped to the organization (and to the key's label scope, see
above). Before this check (c4ad194, c6ee3dd, 9a46b00; deployed on the hosted beta on
2026-11-05), a caller who knew another organization's snapshot digest, or probed short ids,
could start a sandbox from that organization's committed snapshot.

## Rate limits

- A token bucket per API key, or per user for session tokens (all sessions of a user share
  one bucket). It runs after authentication and before the scope check, so a bad key never
  touches a bucket.
- `SANDFORT_RATE_LIMIT_ENABLED` (`true`), `SANDFORT_RATE_LIMIT_REFILL_PER_S` (`100`),
  `SANDFORT_RATE_LIMIT_BURST` (`1000`).
- Buckets live in process memory: they are per server process and reset on restart.
- An empty bucket answers 429 `RATE_LIMITED` with `Retry-After` in whole seconds. There are
  no `X-RateLimit-*` headers.
- The SSO exchange is limited per peer address (never a forwarded header): 1 per second,
  burst 10. It is installed when rate limiting is enabled.
- Exempt: `/healthz`, `/readyz` and the PTY websocket.

Other caps: 8 live PTYs, 16 running async commands and 16 live log streams per organization
(one shared log-stream cap across container-log follow, command-log follow and build-log SSE:
`SANDFORT_MAX_PTYS_PER_ORG`, `SANDFORT_MAX_ASYNC_COMMANDS_PER_ORG`,
`SANDFORT_MAX_LOG_STREAMS_PER_ORG`; per process, `0` =
unlimited), 2 running volume exports or restores per organization and 8 per process
(`SANDFORT_MAX_VOLUME_TRANSFERS_PER_ORG`, `SANDFORT_MAX_VOLUME_TRANSFERS`; 409 `org_transfer_limit`
or `transfer_limit`), 16 MiB JSON request bodies (`SANDFORT_MAX_REQUEST_BODY_BYTES`, 413
`PAYLOAD_TOO_LARGE`), 256 MiB file uploads (fixed in code; the upload route is exempt from the
body cap).

Client disconnects (`src/sandfort/api/routes/toolbox/process.py`): a synchronous exec
(`process/execute` and `process/code-run`) is cancelled and its process tree killed when the
client disconnects; the server checks every 0.5 s. Async session commands are different: they
keep running when a log follower disconnects, and `kill_command` stops them.

## Audit

Each event stores: actor (type and id), action, target (type and id), outcome (`success`,
`denied` or `error`), request id, client IP, user agent and redacted details.

To read and verify an organization's audit log as a reviewer, see
[Reading and verifying the audit log](https://docs.sandfort.dev/audit-reviewers.html).

- Most non-GET calls write one event for what it did, with named
  exceptions rather than a promise of exactly one row. Two routes are known to write no row:
  `POST /v1/sandboxes/{id}/preview-tokens` and `PATCH /v1/webhooks/{id}`. No test walks every
  route to check this, so each feature is tested on its own and other gaps are possible.
  A call refused after a valid key writes
  one refusal row instead (`request.denied`, or `sandbox.create_refused` and
  `sandbox.start_refused` for host capacity or the key's `max_sandboxes` cap, below, or a row
  under the call's own action such as `toolbox.fs.upload`). A call that is accepted and then fails
  adds a failure row: `sandbox.failed` for a create or start whose driver call fails, and
  `sandbox.reset_failed` next to `sandbox.reset`. Most successful GETs are not
  audited, and failed authentication is not audited, except the refusal of a revoked or
  expired key (see below). The GETs that are audited because they
  read sandbox content: `sandbox.logs.read` (`GET /v1/sandboxes/{id}/logs`),
  `toolbox.fs.list`, `toolbox.fs.stat`, `toolbox.fs.download`, `toolbox.git.status`,
  `snapshot.exported` (`GET /v1/snapshots/{id}/export`) and `volume.export`
  (`GET /v1/volumes/{id}/export`).
  Listing and reading sandboxes, snapshots, volumes, jobs, usage and audit events, and reading
  session command logs, is not audited.
- A sandbox reset (`POST /v1/sandboxes/{id}/reset`) is audited as `sandbox.reset` with the
  state it started from; a reset whose driver call fails also writes `sandbox.reset_failed`
  with the (truncated) driver message.
- A refusal after a valid key (in practice 401 for a revoked or expired key, 403, 404 from a
  route that matched, 409, 422, and a 413 or 400 raised by a route) is recorded as
  `request.denied` with outcome `denied` and the method, path, status and error code. A 503
  with the code `CAPACITY` is recorded `denied` too, and any other 5xx is recorded as `error`
  with the action `request.failed`. One exception: a 422 for a
  request body that is not valid JSON is rejected before the key is resolved, so no
  `request.denied` row is written. Every other 422 after a valid key is recorded. A 429 with
  the code `QUOTA_EXCEEDED` is recorded too; a 429 with the code `RATE_LIMITED` is not, because a
  client in a retry loop would flood the chain. The write is best effort and never changes the
  response.
- Two refusals of a create look alike but are recorded differently. A create refused for host
  capacity answers 503 and is audited as `sandbox.create_refused` (a start is
  `sandbox.start_refused`). A create refused by the per-key `max_sandboxes` cap answers 429
  `QUOTA_EXCEEDED` and is audited as `sandbox.create_refused` with `reason` `key_cap` and the
  cap in `max` and `current` (`src/sandfort/services/admission.py`), not as `request.denied`.
  Other 429 `QUOTA_EXCEEDED` refusals are audited as `request.denied`. To find every refused
  create, query both actions.
- Capacity refusals are coalesced. A client in a retry loop (the SDK retries a 503) would
  write a permanent row per retry, so for the same action, API key and reason at most one
  `sandbox.create_refused` (and one `sandbox.start_refused`) row is written per 60 seconds
  per server process. The refusals suppressed in between are counted in the next row's
  details as `refusals_coalesced` (absent when nothing was suppressed). Like the revoked key
  throttle, the repeats leave no row, so the chain shows that a key was refused and how many
  came in between, not each one; a restart empties the in-memory map and each `api` process
  keeps its own (`src/sandfort/services/admission.py`).
- Some requests leave no row, with or without a valid key: a refusal by the request text guard
  (a body that is not valid JSON or UTF-8, a lone surrogate or NUL character, a repeated
  object key, a body nested too deep, an integer with too many digits, and bad text in the path or
  query string), a non-JSON content type (415), a body over the size limit (413), a path that
  matches no route (404), a wrong method (405) and every refusal on the `/scim/v2` routes. A
  call refused by a service that already wrote its own refusal row, for example
  `toolbox.fs.upload` for an upload, gets no second `request.denied` row. For the reviewer's
  view of all of this see the page linked at the top of this section.
- The actions written today (the `action` filter of `GET /v1/audit-events` takes any of them;
  details are redacted as below):

  | Action | Written when |
  |---|---|
  | `sandbox.create`, `sandbox.start`, `sandbox.stop`, `sandbox.update` | the call |
  | `sandbox.delete`, `sandbox.reset`, `sandbox.claim` | the call (`claim`: a warm standby) |
  | `sandbox.create_refused` | a create refused for host capacity (503) or by the key's `max_sandboxes` cap (429), outcome `denied` |
  | `sandbox.start_refused` | a start refused for host capacity (503), outcome `denied` |
  | `sandbox.failed`, `sandbox.reset_failed` | a driver failure after the call was accepted |
  | `sandbox.auto_stopped`, `sandbox.auto_deleted` | the idle timers |
  | `sandbox.resized`, `sandbox.egress_updated` | a resize, and a runtime egress allowlist replacement |
  | `sandbox.drift_detected`, `sandbox.orphan_removed` | the reconciler: a sandbox that stopped unexpectedly, and a container with no sandbox that was removed |
  | `sandbox.logs.read`, `sandbox.exec.replay` | a read of logs; a replayed idempotent exec |
  | `toolbox.process.execute`, `toolbox.process.code_run` | a synchronous exec or code-run |
  | `toolbox.code_contexts.create`, `.delete`, `.interrupt`, `.run` | a code context call |
  | `toolbox.code_contexts.run_stream` | a streamed run, rows as for `run` |
  | `toolbox.session.*`, `toolbox.pty.*` | session create, exec, kill; PTY create, resize, close |
  | `toolbox.fs.*`, `toolbox.git.*` | file and git calls (the audited GETs included) |
  | `snapshot.create`, `snapshot.register`, `snapshot.delete`, `snapshot.exported` | snapshots |
  | `volume.create`, `volume.delete`, `volume.restore`, `volume.export` | volumes, including a restore and an export |
  | `image.build.request`, `image.build.complete` | an image build request and its end |
  | `api_key.created`, `api_key.revoked`, `quota.updated` | key and quota admin |
  | `user.created`, `membership.added`, `membership.role_changed`, `membership.removed`, `membership.external_id_changed` | member admin, including SCIM Users calls |
  | `session.created` | an OIDC sign-in exchange |
  | `scim_token.created`, `scim_token.revoked` | SCIM token admin |
  | `webhook.endpoint_created`, `webhook.endpoint_deleted`, `webhook.redelivered`, `webhook.endpoint_disabled` | webhook admin. The last is written when delivery failures disable an endpoint |
  | `audit.chain_reanchored` | an operator acknowledges historical chain findings |
  | `request.denied`, `request.failed` | a refusal after a valid key |
- A revoked or expired key is refused with 401 and that refusal is recorded as
  `request.denied` on the key's organization: the actor is the key, the details carry the
  method, path, status, `error_code` and a `reason` of `revoked` or `expired`
  (`src/sandfort/auth/authenticate.py`, `src/sandfort/api/errors.py`). Only a key whose stored
  secret verified is recorded, because only then is the organization known. The row is
  throttled: at most one per key per 60 seconds per server process, kept in a bounded
  in-memory map (1024 keys, the oldest dropped first). What the throttle does not cover: the
  repeats inside the window leave no row, so the chain shows that a key was refused, not how
  often; a restart empties the map, and each process (each `api` pod) throttles on its own, so
  several processes can each write one row per window. Missing, malformed, unknown and
  wrong-secret keys name no organization and are not recorded. The write is best effort like
  the others.
- Redaction (`src/sandfort/services/audit.py`): `env` keeps only the sorted names and a
  count; `stdin`, `code`, `command`, `args`, `cmd` and `token` keep only
  `redacted-sha256:<hex>` and the byte length. The digests are unsalted, so a short or
  guessable value can be confirmed by hashing a guess. Other scalars pass through.
- The IP is the client address the ASGI server reports (the socket peer). The app never reads
  `X-Forwarded-For` itself: uvicorn applies it only when the peer is listed in
  `SANDFORT_FORWARDED_ALLOW_IPS`, so the IP is only as trustworthy as that setting. An address
  longer than 45 characters is stored as `null`.
- API key events (`api_key.created`, `api_key.revoked`) carry the request id, client IP and
  user agent like the other events: the key routes hand the app's correlated recorder to
  `ApiKeyAdminService` for the call (`src/sandfort/api/routes/api_keys.py`, commit 9571d1a).
  `quota.updated` carries them too: `QuotaService` is wired with the correlated recorder
  (`src/sandfort/api/wiring.py`). A quota release recorded outside a request (auto-stop,
  reconciler) still stores `null` for the three fields, as there is no request to name.
- Per-org hash chain: `hash = HMAC-SHA256(key, prev_hash + canonical(row))` when
  `SANDFORT_AUDIT_CHAIN_KEY` is set (at least 32 bytes), else `sha256(prev_hash +
  canonical(row))`, where the canonical form is compact, key-sorted JSON of id, org, actor,
  action, target, outcome, request id, details and time. IP and user agent are not hashed.
  Rows link by `prev_hash`. The chain is tamper-evident: it shows a changed, removed or
  reordered row, not who changed it. With the key set, a writer who only has database access
  cannot recompute the hashes of a rewritten history; without the key a writer can (and in
  `prod` the server refuses to start while the key is unset, unless
  `SANDFORT_UNKEYED_AUDIT_CHAIN_ACKNOWLEDGED=true` accepts the unkeyed chain explicitly).
- Keyed chain settings (`src/sandfort/services/audit_chain.py`):
  - `SANDFORT_AUDIT_CHAIN_KEY`: the HMAC key. Keep it out of the database and out of backups
    of the database. Changing or losing it makes keyed rows fail `audit-verify`.
  - `SANDFORT_AUDIT_CHAIN_ACCEPT_UNKEYED` (default `true`): whether verify accepts unkeyed
    rows (written before the key was set) at the start of an org's chain, and counts them.
    An unkeyed row after a keyed row is always a finding. With the key set, a chain whose
    newest row is unkeyed is also a finding whatever the flag says, because a writer without
    the key could otherwise replace the history with a self-consistent unkeyed chain. An org
    with no audited write since the key was set shows this finding until its next write.
  - Migration to a keyed chain: (1) set `SANDFORT_AUDIT_CHAIN_KEY` on every `api` and
    `worker` process and restart them; (2) make one audited write per org (any mutating
    call), so each org's newest row is keyed; (3) run `audit-verify` and confirm it exits 0
    and reports the number of unkeyed rows it accepted; (4) set
    `SANDFORT_AUDIT_CHAIN_ACCEPT_UNKEYED=false` and restart; the old unkeyed prefix then
    fails verify, so acknowledge it with `audit-reanchor` (below) or keep the flag on until
    retention has pruned those rows.
  - Signed head: with the chain key set, `audit-export` appends one trailer line per org after
    that org's rows. It names the newest row at export time (`type` `audit_head`, `org_id`,
    `row_id`, `hash`), binds the content of the export (below) and carries an HMAC over those
    fields with the chain key (`hmac`). The REST export (`GET /v1/audit-events/export`) ends
    with the same kind of line whenever the export holds at least one row: it names the last row
    of that export (the newest chain row unless `to` cut the export earlier). With a
    `request_id` or `outcome` filter the head is marked `filtered: true` and carries `filters`
    (the filter values, as text). Only an empty export, or a server without the chain key, ends
    in an unsigned `export_summary` line (`rows`, `filters`).
    Consumers of an export must skip lines whose `type` is `audit_head` or `export_summary`
    (row lines have no `type` field).
  - Content binding (round 63 and later): the head also carries `row_count` (the number of event
    lines above it), `first_row_id` (the id of the first one; `null` when there are none) and
    `export_sha256` (hex SHA-256 over the exact UTF-8 bytes of every event line, each with its
    trailing newline, in order; the trailer is not included). The server computes the digest
    while it streams the lines, in constant memory. In an operator `audit-export` of several
    orgs each head covers its own org's lines only. The three fields are covered by the HMAC
    and by the Ed25519 signature below. A head without them (older servers) still parses and
    verifies; `verify-head` then reports `content_bound` false and a stderr note, "legacy head:
    content not bound".
  - `audit-verify --head <export file>` checks every head's HMAC and that the live chain
    still reaches each head row with the same hash, which detects truncation of the newest
    rows; a bad HMAC is `head_invalid`, a missing or changed head row is `head_missing`. It
    needs the chain key, and retention that prunes past the head row also reports
    `head_missing`. It accepts heads with and without the content binding; it does not
    recompute the file's digest (`verify-head` does).
  - Ed25519 signature of the head (`src/sandfort/audit_signing.py`,
    `src/sandfort/services/audit_chain_head.py`): with `SANDFORT_AUDIT_SIGNING_KEY` set as
    well, the head carries four more fields: `alg` (`ed25519`), `public_key` (the raw public
    key, urlsafe base64), `signed_at` (UTC, ISO 8601, to the second) and `signature` (urlsafe
    base64). The signature covers the compact, key-sorted JSON of the head without `signature`
    and `hmac`, so `signed_at` and the content binding are covered. The HMAC needs the secret chain key and so only the
    server can check it; the signature needs only the public key, which lets an auditor who
    holds no secret check the head. Details:
    - `SANDFORT_AUDIT_SIGNING_KEY` is an Ed25519 private key, raw 32 bytes in urlsafe base64 or
      a PEM block (PKCS#8, no passphrase). Empty means unsigned heads. A malformed value fails
      the settings load, so the process does not start. Keep it in the secret store, out of
      the database and out of backups of it; see `docs/operations.md`, "Signing the audit
      export".
    - It depends on `SANDFORT_AUDIT_CHAIN_KEY`: a signing key without the chain key signs
      nothing. In `prod` the start is refused; elsewhere the server starts with a warning.
    - `GET /v1/status` publishes `audit_public_key`, the public key that verifies the heads,
      and `audit_key_fingerprint` next to it: the first 16 hex characters of sha256 over the
      raw public key, the value the CLI and `doctor` print. Both are `null` together. Pin
      the fingerprint out of band (release notes or the operator's own channel), not from
      the server whose export you are checking.
      It is published only while heads are actually signed, that is when both keys are set;
      otherwise it is `null`. The route needs no key, so an auditor can fetch it
      independently of an export. A trailer's own `public_key` is not a trust anchor: check
      against the key from the status route or one you pinned earlier.
    - Heads written before `signed_at` existed (beta.60 to beta.64) have `alg`, `public_key`
      and `signature` only. They verify but are undated: `verify-head` fails them as `undated`
      (exit 3), and `audit-verify --head --public-key` accepts them.
- The canonical row, exactly (`src/sandfort/services/audit_chain.py`): the JSON object of the
  fields `id`, `org_id`, `actor_type`, `actor_id`, `action`, `target_type`, `target_id`,
  `outcome`, `request_id`, `details` and `occurred_at`, serialised with sorted keys,
  separators `,` and `:` (no spaces) and `ensure_ascii`. `occurred_at` is Python's
  `datetime.isoformat()` with a `+00:00` offset, and the first row hashes with
  `prev_hash = ""`. The export shows the time with `Z`, so parse and re-format it before
  hashing. This reference verifier checks an export file of one org (Python 3.11 or later).
  It covers the unkeyed chain; for a keyed chain replace the `sha256` line with
  `hmac.new(key, text_with_prev.encode(), hashlib.sha256).hexdigest()` (`import hmac`), and it
  skips the trailer line (`audit_head` or `export_summary`):

  ```python
  import hashlib, json, sys
  from datetime import datetime

  KEYS = "id org_id actor_type actor_id action target_type target_id outcome request_id details"
  prev = None  # hash of the previous row
  for row in map(json.loads, open(sys.argv[1])):
      if row.get("type") in ("audit_head", "export_summary"):
          continue  # trailer line, not a row
      if row["hash"] is None and prev is None:
          continue  # written before the chain existed
      body = {key: row[key] for key in KEYS.split()}
      body["occurred_at"] = datetime.fromisoformat(row["occurred_at"]).isoformat()
      text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
      digest = hashlib.sha256(((row["prev_hash"] or "") + text).encode()).hexdigest()
      linked = prev is None or (row["prev_hash"] or "") == prev
      print(row["id"], "ok" if digest == row["hash"] and linked else "BROKEN")
      prev = row["hash"]
  ```

  The first hashed row seeds the chain with its own stored `prev_hash`, as the server does,
  so an export that starts after a retention prune still verifies.
- Verify: admin command `audit-verify` (every org; exit 3 on a broken chain), or
  `GET /v1/audit-events/verify` (the caller's org). Export: admin command `audit-export`
  (NDJSON), or `GET /v1/audit-events/export?from=&to=` (`from` inclusive, `to` exclusive).
  The two API routes need `audit:read` and an org-wide key (a key with `sandbox_labels` gets 403)
  and are in the pinned OpenAPI spec. The export route also takes `request_id` and `outcome`
  (see the list route below) and keeps only the rows that match. The list route,
  `GET /v1/audit-events`, takes the same `from` (inclusive) and `to` (exclusive) bounds on
  `occurred_at`, plus `actor_id`, `action`, `target_id`, `request_id` (the `X-Request-ID` of the
  request that wrote the row) and `outcome` (`success`, `denied` or `error`). The filters are
  exact matches and combine with AND. A query parameter outside the accepted set of a route
  (list: those above plus `order`, `cursor` and `limit`; export: `from`, `to`, `request_id`,
  `outcome`; verify: `from_id`) answers 422 naming it, so a typo such as `?requestid=` cannot
  return an unfiltered 200 (commit 965782c, `src/sandfort/api/routes/audit.py`). The check runs
  after authentication, so a caller without access still gets 401 or 403. The list route
  returns the oldest event first by
  default; `order=desc` returns the newest first (`order=asc` is the default; any other value is
  a 422). The order is by event id, which follows creation time, and `next_cursor` continues in
  the chosen order, so send the same `order` on every page (`src/sandfort/api/routes/audit.py`,
  commit 7cdfb86). The export route is not affected.
- Verify an export file: `sandfort audit verify-head <file>` (`cli/src/sandfort_cli/audit.py`,
  `cli/src/sandfort_cli/audit_verify_cmd.py`, `sdk/python/src/sandfort_sdk/audit_export.py`,
  SDK: `verify_export`) needs no credentials: the public key comes from `--public-key` (32
  bytes, urlsafe or standard base64) or, by default, from `audit_public_key` of `GET
  /v1/status`, which the command fetches without an API key (the base url is the profile's or
  `SANDFORT_BASE_URL`). Without `--public-key` it exits 2 when the server publishes no key. The
  file must end with an `audit_head` line. It checks, in this order, and reports the first
  reason that fails:
  1. The head signature with that key. Failures: `unsigned` (no Ed25519 signature),
     `signature` (does not verify), `key_mismatch` (the head names another public key than the
     one you trust), `undated` (the signature verifies but `signed_at` is absent, has no UTC
     offset or is before 1970-01-02) and `future_signed_at` (`signed_at` is more than 5
     minutes ahead of the local clock).
  2. When the head binds the content (round 63 and later), right after the signature:
     `count_mismatch` (the number of event lines differs from `row_count`: rows were removed or
     added), `content_mismatch` (the count is right, but the SHA-256 over the exact bytes of the
     file's event lines differs from `export_sha256`: a line was edited or reordered, including
     an edit that keeps `hash` and `prev_hash`) and `first_row_mismatch` (the first event line's `id` is not `first_row_id`).
     Event lines are the non-blank lines above the trailer; the digest includes each line's
     `\n`.
  3. `malformed_row`: a line is not a JSON object with a text `id`, `occurred_at`, `org_id` and
     `action` and the `hash` and `prev_hash` keys (text or null), is not valid UTF-8, is nested
     too deeply or is longer than 1 MiB. The output names the line.
  4. `misplaced_trailer`: an `audit_head` or `export_summary` line that is not the final line.
  5. `org_mismatch`: a row's `org_id` is not the head's. The output names the first such line.
  6. `truncated`: the last row of the file is not the row the head names (rows were cut, or
     the trailer belongs to a different, earlier or later, export), or the file has no rows.
  7. `head_mismatch`: the last row is the head's row, but its `hash` differs from the head's.
  8. `chain_break`: a row's `prev_hash` is not the `hash` of the row before it in the file
     (the first row's `prev_hash` is not checked, since an export may start mid-chain). The
     first such row is reported as `first_break`. Not checked for a head marked `filtered`
     (an export cut by `request_id` or `outcome` is not a contiguous run of the chain); the
     output says so, and `first_break` stays null.
  9. `unchained_rows`: a row carries no `hash`. Server exports always carry hashes, so this
     means rows were stripped of them. `--allow-unchained` accepts rows without a hash that
     come before the first hashed row (a prefix nobody has chained); they are counted, and a
     note on stderr says the server-side check covers them.
  10. With `--previous <file>` (SDK: `previous=`), `not_a_continuation`: the event lines of the
      earlier export are not an exact byte prefix of this export's event lines (this includes an
      export that starts at another row). On success the output reports `previous_rows` and
      `new_rows`, the number of rows added since. The earlier file is not itself verified;
      verify it on its own.

  One more reason replaces all of the above: `no_trailer`, when the file has event rows but
  its last line is not a usable `audit_head` (missing, junk, an extra row after the trailer);
  `first_break` is null there. `--head-only` checks the signature and `signed_at` alone and
  skips the rows (not combinable with `--previous`).

  Exit codes. Exit 0 when every check passes. Exit 3 when a check fails; the reason is printed
  (`error: export not verified (<reason>)`), and `--json` carries it in `reason`. A file with a
  trailer and no rows under it is exit 3 (`truncated`), not 2. Exit 2 only when the check
  cannot run: the file or the `--previous` file is missing or unreadable, the file is empty,
  the file has no valid row and its last line is not a usable `audit_head`, the last line is an
  `export_summary` (an unsigned export: the wrong kind of file, even with rows above it),
  `--head-only` finds no trailer, `--public-key` is not 32 bytes in base64, or no key was given
  and the server publishes none (or cannot be asked: no base url configured). A bad row, a
  misplaced trailer and a missing trailer after valid rows are exit 3, not 2.

  On success the command prints one stderr line: what was proven (the signature with the age of
  `signed_at`, the content digest, count and first row, each row's org and the last row, the
  linkage between neighbouring rows) and what was not (the keyed row hashes, and that this is
  the newest export). A legacy head adds "legacy head: content not bound"; a filtered head
  adds a note that linkage was not checked.

  What it proves and what it does not. With a head from round 63 or later, a verified file is
  exactly the sequence of event lines the server signed at `signed_at`: the signed digest,
  count and first row catch any added, removed, reordered or edited line, and every row has
  the head's org. Still not proven:
  - The keyed row hashes. They are HMACs with the chain key, so a client cannot recompute them.
    A server (or anyone holding the chain key and the signing key) can sign a fabricated
    export, and `verify-head` accepts it. Only the server-side verification (`sandfort audit
    verify`, `audit-verify` of the admin CLI, or `GET /v1/audit-events/verify`) proves the
    keyed hashes and the full chain.
  - Freshness. An older, genuinely signed export still verifies: check `signed_at`, and of two
    signed heads the later `signed_at` is the newer one. `--previous` shows that a later
    export extends an earlier one, not that it is the newest.
  - For a legacy head (before round 63) the client check binds only the last row to the signed
    head, plus the linkage between neighbouring rows: rows before the last can be replaced or
    removed by someone who rewrites `prev_hash` and `hash` consistently, and an edit of a row's
    content that keeps its `hash` and `prev_hash` passes.
  - A filtered export (`filtered: true`) binds its content but not that the rows are all of
    the matching rows in the chain.

  `audit-verify --head <file> --public-key <key>` also checks each head's signature against
  the live chain; an unsigned head or a bad signature is `head_invalid`. It accepts heads with
  and without the content binding, and legacy heads without `signed_at`, which `verify-head`
  fails as `undated`. `sandfort audit export` prints one stderr
  note with the signing key's fingerprint (first 16 hex characters of sha256 over the raw
  public key) when the trailer is a signed head; compare it with the fingerprint that
  `verify-head` prints and with the one the operator reads from the `audit keys` row of
  `python -m sandfort.admin_cli doctor`.
- An export ends in a signed head when the server has the chain key and the export holds at
  least one row (`src/sandfort/api/routes/audit.py`, `_export_lines`). The head names the last
  row of the export and its digest; with a `request_id` or `outcome` filter it is marked
  `filtered`. An empty export, or a server without the chain key, ends in an unsigned
  `export_summary` that names no row, and `verify-head` exits 2 on it.
- `audit-verify` and an unkeyed newest row (`src/sandfort/services/audit_chain.py`): with the
  chain key set, a chain whose newest row is unkeyed is reported as a `hash_mismatch` finding
  and `audit-verify` exits 3. It is an alarm, not a calm verdict: either the key was enabled
  after the last event, or keyed rows were deleted, and the rows alone cannot say which.
  Do not write an event to clear it. Compare the live chain against an earlier export with
  `audit-verify --head <earlier export>`.
- Verify from an anchor: `GET /v1/audit-events/verify?from_id=<audit event id>` starts the walk
  at that row instead of the first one (`src/sandfort/api/routes/audit.py`, commit 175ec2a).
  The response then carries `anchor_id` with the id you passed; a full walk leaves the field out.
  What it proves: the anchor row's own hash is recomputed and must match, and every row after it
  is checked as in a full walk (its hash, and its `prev_hash` against the row before it), so the
  chain from the anchor to the newest row is intact. What it does not prove: nothing before the
  anchor is checked, and the anchor's link to the row before it is not compared (the walker
  seeds from the first row it sees; the anchor's stored `prev_hash` is covered by its own hash,
  but nothing checks that it equals its predecessor's hash). Altered or removed history before
  the anchor therefore stays undetected by this call. Like a full walk, it cannot tell a
  consistent rewrite of the later rows from the original: to catch that, keep the anchor's
  `hash` and the reply's `last_hash` from an earlier `audit-export` or verify and compare them.
  Use a full walk, or `audit-verify`, to cover the whole history. An id that does not exist or
  belongs to another organization answers 404.
- Historical `link_broken` findings: before 6fe71aa, concurrent audit appends for the same org
  on Postgres could read the same chain head and both link to it, which forked the chain.
  Verify reports such rows as `link_broken`. None of these is a `hash_mismatch`: no event was
  altered. Appends are now serialised per org with a Postgres advisory transaction lock, and
  SQLite deployments were never affected. Breaks that already exist stay in the chain (an audit
  trail is not rewritten), so verify keeps reporting them; all of them predate the fix. On the
  hosted beta only 3 of the 5 evaluation orgs have such breaks; the other orgs verify clean.
- Re-anchor rule (`src/sandfort/services/audit_chain.py`, `src/sandfort/admin_cli.py`, commit
  d96b196): an operator can acknowledge an org's historical findings with the admin command
  `audit-reanchor --org <id> --note <text>`, which appends one `audit.chain_reanchored` event
  (actor `platform_admin`, details `acknowledged_through`, `findings`, `note`; see
  `docs/operations.md`). Since commit 100d088 the record can also name who acted and why: the
  options `--operator <name>` (1 to 255 characters) and `--reason-code`
  (`incident_acknowledged`, `migration` or `other`) are given together and are stored as
  `operator` and `reason_code` in the same details. Without them the event has neither, as the
  events written before that commit; the event's actor stays `sandfort-admin`, so `operator` is
  the name the person running the command chose to give, not an authenticated identity. The
  rule:
  - It acknowledges, it never hides. No row is changed or removed and the walker still finds
    every break. Verify only reports the findings on rows up to `acknowledged_through` apart, in
    `acknowledged_findings` (API) or in the `(M acknowledged finding(s))` suffix of
    `audit-verify`, and `reanchored_by` names the event. The `reanchor` object of the verify
    reply carries that event's `operator`, `reason_code`, `note`, `findings`,
    `acknowledged_through`, `event_id` and `occurred_at`, so the verify alone says who
    acknowledged what and why (`operator` and `reason_code` are `null` for an event written
    without them; the object is left out while there is no re-anchor). The listed `findings`
    hold only unacknowledged ones.
  - The full history stays in the export: `audit-export` and `GET /v1/audit-events/export`
    return the broken rows and the re-anchor event like any other row, and the note records why
    the operator accepted them.
  - Any later break still fails verify (`ok` false, exit 3): a finding on a row after
    `acknowledged_through`, including the re-anchor event itself, is not acknowledged. An event
    that names itself or a later row, lacks a row id or did not succeed acknowledges nothing.
  - Only the latest re-anchor event counts. The command writes nothing when the org has no
    unacknowledged findings.
  - The event is an ordinary chained, audited row: it shows that an operator accepted the
    findings and when. It does not show that they were harmless; that is the operator's note.
- Retention: `SANDFORT_AUDIT_RETENTION_DAYS` (`0` = keep forever) with a pass every
  `SANDFORT_AUDIT_RETENTION_INTERVAL_S` (`3600`). It prunes only the oldest prefix of an org's
  trail and never the newest row, and verification seeds from the first remaining row, so the
  rest of the chain still verifies. Export before you prune if you need the old rows.

## Usage metering

- `vcpu` and `memory_mib` are allocated time: an interval opens when a sandbox enters
  `started` and closes on `stopped`, `destroyed` or `error`. Two vCPUs for one hour are 7200
  vCPU-seconds.
- `disk_gib` is sampled, not allocated: the size of the container's writable layer, sampled
  every `SANDFORT_METERING_SAMPLE_INTERVAL_S` (`300`) for started sandboxes. It is not the
  requested `disk_gib`, and it excludes named volumes and the image. A driver that cannot
  report a size skips the sample.
- Hourly rollups (`SANDFORT_METERING_ROLLUP_INTERVAL_S` `3600`, recomputing the last
  `SANDFORT_METERING_ROLLUP_LOOKBACK_HOURS` `3` completed hours). `SANDFORT_METERING_ENABLED`
  (`true`) switches the worker.
- `GET /v1/org/usage?from=&to=` returns one total per dimension (a timestamp without an offset
  is UTC). Add `group_by=sandbox` or `group_by=label:<key>` for chargeback; sandboxes without
  the label form the `null` group. Grouped totals come from the raw intervals, because
  rollups are per org and cannot be split. Any other `group_by` is a 422. `group_by` is in
  the pinned OpenAPI spec.
- Metering records allocation; it does not imply billing.

## Webhooks

- 13 event types: `sandbox.created`, `.started`, `.stopped`, `.deleted`, `.error`,
  `.auto_stopped`; `snapshot.created`, `.active`, `.error`, `.deleted`; `volume.created`,
  `.deleted`; `quota.exceeded`. Delivery is at least once.
- Filters per endpoint: `*`, an exact type, or `prefix.*`; an empty list means all events;
  at most 32 filters.
- Signing follows Standard Webhooks. Headers `webhook-id` (stable per event, use it to
  deduplicate), `webhook-timestamp` (unix seconds) and `webhook-signature`, whose value is
  `v1,<base64 HMAC-SHA256>` over `id.timestamp.payload`. The secret starts with `whsec_` and
  is shown once, in the create response. Receivers should reject timestamps more than 300 s
  off.
- Delivery: a 2xx is success. Anything else, including a redirect (never followed) or a
  transport error, is retried; there are 6 attempts. The schedule holds delays of 1, 5, 25, 60 and 300 s, but the
  dispatcher looks for due deliveries every `SANDFORT_WEBHOOK_DISPATCH_INTERVAL_S` (default
  5 s), so the first retry comes about 5 s after the failure.
  The timeout is 10 s per attempt (`SANDFORT_WEBHOOK_TIMEOUT_S`). After 50 consecutive failed
  attempts the endpoint is disabled and `webhook.endpoint_disabled` is audited. A redelivery
  requeues a delivery.
- Receiver URLs (`src/sandfort/webhooks/ssrf.py`): no userinfo, ports 80, 443 or 8000-9000
  only, and every resolved address must be public. Loopback, private, link-local and cloud
  metadata addresses are rejected; `SANDFORT_WEBHOOK_ALLOW_PRIVATE_NETWORKS` (`false`) admits
  the first three, never the metadata addresses. The delivery connects to the vetted IP, so a
  second DNS answer cannot redirect it. A name the resolver reports as not existing is a 422
  (`details.reason` `not_resolved`); a resolver that times out or fails is retried once and then
  answers 503 `DNS_UNAVAILABLE` (`details.reason` `dns_unavailable`, `Retry-After`), never a
  claim that the host does not resolve. Each lookup is capped at 2.5 s.
- Secrets are encrypted at rest with `SANDFORT_WEBHOOK_SECRET_KEY` (a Fernet key). A server
  that has the key stores every new secret encrypted (a `SecretBox` marker prefix plus the
  Fernet token). The key is required when `SANDFORT_ENV=prod`: the server refuses to start in
  prod without it. Outside prod an empty key is allowed and stores new secrets in plaintext;
  a secret stored in plaintext before the key was set is still read as is. Set the key before
  you create endpoints you care about.
- `SANDFORT_WEBHOOK_REQUIRE_HTTPS` (`false`) rejects `http` URLs at registration and at
  delivery; it is forced on in `prod`.
- The hosted beta sets both `SANDFORT_WEBHOOK_REQUIRE_HTTPS` and `SANDFORT_WEBHOOK_SECRET_KEY`:
  webhook URLs on the beta must use `https`, and webhook secrets are encrypted at rest.

## Data retention and deletion

| Data | What happens |
|---|---|
| Sandbox delete | The container is force-removed with its writable layer and anonymous volumes. The sandbox row stays as a `destroyed` tombstone; nothing purges it. |
| Named volumes | Separate from sandboxes. Delete is refused (409) while a sandbox mounts the volume. |
| Snapshot delete | Refused (409) while a sandbox uses it. Otherwise the image is removed (best effort, a failure is logged) and then the row. |
| Orphans | A garbage collector removes untracked `sandfort-snapshot:` images and `sf-vol-` volumes after a grace period (`SANDFORT_GC_ENABLED` `true`, `SANDFORT_GC_INTERVAL_S` `300`, `SANDFORT_ORPHAN_GRACE_S` `300`). |
| Command and session output | Held in server memory only, lost on restart. Each command keeps at most 10 MiB; past that the log is marked truncated. The budget is per organisation: 256 retained commands and 64 MiB. Past either, eviction stays inside the organisation that produced the output: its oldest finished logs go first, then the oldest chunks of its running logs. A global ceiling of 256 MiB across all organisations squeezes only the organisation that just wrote, so one organisation's output does not evict another's logs (`src/sandfort/toolbox/command_logs.py`). |
| Sandbox logs | Read from the container; they go when it does. |
| Usage intervals, rollups, outbox events, jobs | Kept; no purge job. |
| Webhook deliveries | Kept; no purge job. Deleting an endpoint deletes its deliveries. |
| Idempotency records | Expire after 1 day. |
| Audit | The only data with a retention setting (see Audit). |

Deleted data is unlinked by Docker, not securely wiped.

## Telemetry

- Nothing is sent to the Sandfort maintainer. The server process makes outbound HTTP only for:
  webhooks you configure; the OIDC key set fetch from `SANDFORT_OIDC_JWKS_URL` when SSO is
  configured; and forwarding to peer nodes when cross-node routing is configured. The Docker
  daemon pulls images from registries when you register a snapshot or build an image.
- Tracing: `SANDFORT_TRACING_EXPORTER` is `none` (spans stay in process; the default) or
  `console`. There is no network exporter. `SANDFORT_TRACING_ENABLED` defaults to `true`.
- `/metrics` is unauthenticated. Keep it inside the cluster.
- The browser web terminal (`GET /terminal`, served by the preview proxy) loads xterm.js 5.5.0
  from `cdn.jsdelivr.net`, without a subresource-integrity hash. The `/console` page
  references no external URL.

## Isolation

Isolation is chosen per sandbox; see
[the isolation tiers page](https://docs.sandfort.dev/isolation-tiers.html) for measurements
and caveats. `container` is runc with namespaces, cgroups, seccomp and a reduced capability
set; it shares the host kernel, so a kernel exploit inside the sandbox reaches the host.
`gvisor` puts a user-space kernel between the code and the host kernel; it is not a hardware
boundary, and a bug in gVisor could still expose the host. `microvm` runs Kata Containers with
a guest kernel per sandbox; it is offered only where the host has KVM, and on the hosted beta
it runs on nested KVM, so it is not a claim of stronger isolation than other microVM products.
The Firecracker driver is a skeleton and is not offered.

Network default: `SANDFORT_DEFAULT_BLOCK_NETWORK` (`false`) makes a create that names no
network policy start with all outbound traffic blocked (`network.block_all`). An explicit
`block_all` of `true` or `false` in the request wins, and a create with an `egress_allowlist`
(even an empty one) keeps its own rules. Use it on a deployment that runs untrusted or student
code, so a client that forgets `block_network=True` is still offline.
