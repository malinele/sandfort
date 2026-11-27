# Sandfort hosted beta: connect guide

> First time here? The [quickstart](https://docs.sandfort.dev/quickstart.html) is one page:
> verify the delivery, install, first sandbox. This guide is the full reference behind it.

**Contents**

1. [What you receive from the maintainer](#1-what-you-receive-from-the-maintainer): endpoint, key,
   [scopes](#scopes-and-what-they-allow), [labelled keys](#keys-limited-to-labelled-sandboxes),
   [managing API keys](#managing-api-keys), [per-key sandbox cap](#per-key-sandbox-cap)
2. [Install the SDKs, MCP server and CLI](#2-install-the-sdks-mcp-server-and-cli)
3. [First sandbox in five minutes](#3-first-sandbox-in-five-minutes), then:
   [retries and idempotent create](#retries-and-idempotent-create),
   [running code and files](#running-code-output-limits-and-files),
   [idempotent exec](#idempotent-exec),
   [out of memory](#out-of-memory),
   [recovering after `sandbox_stopped`](#recovering-after-sandbox_stopped),
   [quotas and rate limits](#quotas), [reset](#resetting-a-sandbox),
   [Run code button](#a-student-facing-run-code-button),
   [course and grader walkthrough](#course-and-grader-walkthrough),
   [network](#network), [isolation tiers](#choosing-an-isolation-tier), [snapshots](#snapshots),
   [naming rules](#naming-rules),
   [long-running commands](#long-running-commands-and-the-exec-timeout),
   [code contexts](#code-contexts-state-that-survives-between-runs),
   [REST API](#rest-api)
4. [Preview URLs](#4-preview-urls)
5. [Beta limits](#5-beta-limits)
6. [Support and what we ask](#6-support-and-what-we-ask),
   [status](#status-and-incidents), [reporting a problem](#reporting-a-problem)

This is a shared evaluation instance operated by the maintainer so design partners can try the
API before anything else; in production Sandfort runs self-hosted on your own infrastructure.

**Beta terms:** price, availability, support, data, releases and isolation are stated in the
[beta terms](https://docs.sandfort.dev/beta-terms.html) on the docs site. In short: free for the
whole beta, no uptime guarantee, support at `office@sandfort.dev` with a response target of the next
business day (Monday to Friday, CET).

A note on paths: a link in this guide opens a page on the docs site. A file path in backticks that
is not a link, such as `openapi/sandfort.v1.json`, is a path inside the maintainer's repository.
You do not receive the repository, so such a path names where a file lives and is not a URL you
can open.

This guide covers connecting to the beta with the Python SDK and, depending on your stack, the
TypeScript SDK, the MCP server and the command-line client. You install nothing server-side, and
you do not receive the source code at this stage.

## 1. What you receive from the maintainer

- **Endpoint:** `https://api.sandfort.dev` (https only). The beta is served only at
  `sandfort.dev` (`api.sandfort.dev`, `docs.sandfort.dev`, `sandfort.dev` and
  `*.preview.sandfort.dev`).
- **An organization** created for your team. Every request is scoped to it.
- **An API key** delivered through a one-time secret link. The key starts with `sf_`, is shown
  exactly once and cannot be recovered later; the server stores only a salted hash. Save it in your
  secret manager when you open the link. If you lose it, write to `office@sandfort.dev` for a new one.
  The beta key is an organization admin key. For automation, create a narrower key and keep the
  admin key out of CI. A key holds some of these 12 scopes: `org:read`, `sandboxes:read`,
  `sandboxes:write`, `toolbox:use`, `snapshots:read`, `snapshots:write`, `volumes:read`,
  `volumes:write`, `api_keys:admin`, `webhooks:write`, `usage:read` and `audit:read`. A key can only
  grant scopes its creator holds. A scope covers an action, not a single sandbox. A `toolbox:use`
  key without a label scope can exec in any sandbox of your organization. To restrict a key to
  labelled sandboxes, see "Keys limited to labelled sandboxes" below. The endpoints each scope
  covers are in "Scopes and what they allow" below. The Python SDK has API key helpers
  (`create_api_key`, `list_api_keys`, `revoke_api_key`) and the CLI has `sandfort key create`, `key
  list` and `key revoke`. The REST calls and both clients are in "Managing API keys" below.
- **Delivery package:** the Python SDK wheel is always included. The TypeScript SDK tarball and the
  CLI wheel are included according to your stack, so do not assume all of them are present.
  Use only the sections below that match the files you were sent. The MCP server is not a file: it
  is the PyPI package `sandfort-mcp`, outside `SHA256SUMS` and `RELEASE.txt`. The delivered
  files come with a `SHA256SUMS` file and a plain-text release note, `RELEASE.txt`. The note
  names the commit and the build time. From `v0.1.0-beta.38` on it also names the tag. Since
  beta 60 the files also come with `SHA256SUMS.sig`, an OpenSSH signature over `SHA256SUMS`, and
  the file `release-allowed-signers` (signer `release@sandfort.dev`). Check the files before you
  install, in the directory that holds them: first the signature, then the checksums.

  ```bash
  ssh-keygen -Y verify -f release-allowed-signers -I release@sandfort.dev \
    -n sandfort-release -s SHA256SUMS.sig < SHA256SUMS   # prints "Good ..." and exits 0
  shasum -a 256 -c SHA256SUMS
  ```

### Scopes and what they allow

Every authenticated route requires exactly one scope. A missing scope answers 403 and lists it
(`details.missing_scopes`). There are 12 scopes; the table lists what each one guards.

| Scope | What it allows |
|---|---|
| `org:read` | `GET /v1/org/quota`, `/v1/org/quota/recount`, `/v1/org/members`, `/v1/nodes` |
| `sandboxes:read` | List and get sandboxes, sandbox logs, `GET /v1/isolation`, jobs |
| `sandboxes:write` | Create, patch, delete, start, stop, reset, resize, preview tokens |
| `toolbox:use` | Everything under `/v1/sandboxes/{id}/toolbox/`: exec, `code-run`, sessions, `code-contexts`, fs, git, PTY |
| `snapshots:read` | List, get and export snapshots, image build logs |
| `snapshots:write` | Register, create from a sandbox, delete snapshots, start image builds |
| `volumes:read` | List and get volumes |
| `volumes:write` | Create and delete volumes |
| `api_keys:admin` | Create, list and revoke API keys; add, change and remove organization members; `PUT /v1/org/quota` (that call also needs a platform-admin key, so it is not available to a partner key) |
| `webhooks:write` | All `/v1/webhooks` routes, including list, deliveries and redeliver |
| `usage:read` | `GET /v1/org/usage` (a key with `sandbox_labels` sees only its own sandboxes) |
| `audit:read` | `GET /v1/audit-events`, `/v1/audit-events/export`, `/v1/audit-events/verify`; an org-wide key only, a key with `sandbox_labels` gets 403 |

`GET /v1/nodes` (`org:read`) is for keys without sandbox labels: a key limited to labelled
sandboxes gets 403 ("node data is only for API keys without sandbox labels"), because the node
rows say where sandboxes run. `running_sandboxes` counts only the started sandboxes of your own
organization on each node, never other tenants', so it is not the load of the host.

No scope is needed for `GET /healthz`, `GET /readyz` and `GET /v1/status` (see "Status and
incidents"). A key can only grant scopes its creator holds (403 `details.excess_scopes`).

### Keys limited to labelled sandboxes

`POST /v1/api-keys` accepts an optional `sandbox_labels` object (`{key: value}`, at most 8
pairs). A key created with it only sees and acts on sandboxes whose labels contain all of
those pairs. Create the key with the REST API, or with `client.create_api_key(...)` in the Python
SDK (see "Managing API keys"):

```bash
curl -s "$SANDFORT_BASE_URL/v1/api-keys" \
  -H "Authorization: Bearer $SANDFORT_API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"assistant-a","scopes":["sandboxes:read","sandboxes:write","toolbox:use"],
       "sandbox_labels":{"team":"a"}}'
```

What the scoped key does:

- A sandbox outside the scope answers 404, so its existence is not revealed, and the sandbox
  list only shows sandboxes inside it.
- On create, the key's scope labels are added to every create automatically. A create with no
  labels, or with extra labels under other names, is therefore an in-scope create. For example,
  `labels: {"job": "7"}` through a `team=a` key gives `team=a` and `job=7`. No labels gives
  `team=a`. Such a create meets the per-key cap with 429 like any other create (see "Per-key sandbox
  cap"). Only a label that contradicts the scope, the same label name with another value, is
  refused, with a 403, "this API key is limited to sandboxes labelled team=a". That refusal happens
  before the cap and the quota are checked, so a contradicting label is never masked by a 429.
  Changing labels so that a sandbox leaves the scope is a 403 too.
- Internal ids are withheld from a label-scoped key: `node_id` and `job_id` of a sandbox, and
  `source_sandbox_id`, `image_ref` and `digest` of a snapshot, are `null` for it (the source may
  be a sandbox outside its scope, and `image_ref` names the operator's registry host and path).
  The same holds for image builds: the answer to a build request has `image_ref` and `digest`
  as `null` for it, and so does the `digest` in the final `state` event of the build log. A key
  without labels sees them.
- It can only create keys whose scope contains all of its own pairs (403 with
  `details.excess_labels` otherwise).

Scopes are label matches, not separate namespaces. A sandbox, volume or snapshot that carries both
`team=red` and `project=x` is visible to a key scoped to `team=red` and to a key scoped to
`project=x`. A key scoped to `team=red` can register a snapshot with `labels: {"project": "x"}`,
which is stored as `project=x,team=red` and is then visible and usable by the `project=x` key. So
give every scoped key in an organization the same label key (for example `student=...`), and
the scopes then never overlap.

- Every toolbox route under a sandbox id (process, sessions, fs, git, PTY) checks the scope
  first, so a session, command or PTY id of a sandbox outside the scope answers 404 too.
- With `api_keys:admin`, it lists and revokes only keys inside its own scope.
- A snapshot carries labels, and a scoped key's scope is merged into the labels of every snapshot
  it registers or creates. The key sees and uses a snapshot when its labels contain the scope, or
  when the sandbox it was committed from is in the scope (a destroyed source still counts by its
  labels). A snapshot with no labels and no source sandbox (registered by an org-wide key, or
  built) is shared by every scope: a scoped key sees and uses it but cannot delete it (403 "snapshot
  <id> is shared across the org; only a key without sandbox_labels can delete it").
- Snapshot names are unique per organization, so a register or create with a name that a snapshot
  outside the scope already uses answers 409, which reveals that the name exists. Names are
  organization-wide: prefix them with the scope, for example `student-3-base`.
- Build names, build logs and build jobs are visible to every key in the organisation (image
  build and snapshot create jobs need `snapshots:read`). An identical spec returns another key's
  build with `reused: true`, and the build log echoes the build steps, `ENV` values included, so
  image specs must not carry secrets. The build spec itself is not returned to a scoped key.
- Deleting a snapshot that any sandbox of the organization still uses is a 409, also when that
  sandbox is outside the scope (the message then does not name it).
- Idempotency keys belong to the API key: another key sending the same `Idempotency-Key` gets
  neither the first key's response nor a mismatch error.
- Sandbox names stay unique per organization. A create with a name that a sandbox outside the
  scope already uses answers 409 "sandbox name already exists in this org" with
  `details.reason` `name_taken`, which reveals that the name exists (no id and no data of that
  sandbox). Names are organization-wide, also across scoped keys: leave the name unset, or prefix
  names per scope, if that matters to you.

The usage report is label-scoped too. A scoped key holding `usage:read` sees only its own
sandboxes and label groups, not the whole organization (see "Usage report" under "First sandbox in
five minutes"). Volumes are scoped: a scoped key holding `volumes:read`
sees only the volumes whose labels contain all of its scope labels, and a volume it creates gets
the scope labels merged into its own (see "Volumes" under "First sandbox in five minutes"). A key
created with `shared_volume_labels` also sees, and can mount read-only, the volumes that carry
those labels (see "Sharing a class dataset read-only" in the course walkthrough).
A label-scoped key cannot read audit events: `GET /v1/audit-events`, `/export` and `/verify`
answer 403 ("audit events are org-wide; use an API key without sandbox labels") even when the key
holds `audit:read`, because audit events belong to the whole organization and a label scope only
limits sandboxes. Use an org-wide key (one without `sandbox_labels`) to read the audit log.

Every toolbox call is audited: exec, code run, file and git calls each write one row, and the
command and code are stored only as a hash and a length, never as text.

### Managing API keys

Every API key route needs the `api_keys:admin` scope. The plaintext key appears only in the create
response (field `key`); list and revoke return metadata (`id` with the `key_` prefix, `prefix`,
`scopes`, `sandbox_labels`, `expires_at`, `revoked_at`, `status`, ...). `status` is computed by the
server on every answer: `revoked` once `revoked_at` is set, otherwise `expired` once `expires_at` is
at or before the time of the answer, otherwise `active`. `revoked` takes precedence over `expired`.
`created_by` is the id of the key that created it. It is shown to org-wide keys only: a label-scoped
key gets `created_by: null` on create, list and revoke.

```bash
# Create: optional expires_at (ISO 8601 with a time zone), sandbox_labels and, with labels,
# max_sandboxes.
curl -s "$SANDFORT_BASE_URL/v1/api-keys" \
  -H "Authorization: Bearer $SANDFORT_API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"ci-runner","scopes":["sandboxes:read","sandboxes:write","toolbox:use"],
       "expires_at":"2026-12-01T00:00:00Z"}'
# List the organization's keys (metadata only).
curl -s -H "Authorization: Bearer $SANDFORT_API_KEY" "$SANDFORT_BASE_URL/v1/api-keys"
# Revoke: DELETE on the key id. A repeat answers 200 with the already revoked key.
curl -s -X DELETE -H "Authorization: Bearer $SANDFORT_API_KEY" \
  "$SANDFORT_BASE_URL/v1/api-keys/key_..."
```

`GET /v1/api-keys?status=active` returns only the keys that are neither revoked nor expired, and
`?status=revoked` only the revoked ones; without the parameter the list holds every key. Any other
value answers 422. The unfiltered key list is unpaginated and grows with every revoked key, so
scripts should prefer `status=active`. A repeated `status` answers 422 "must be given once"
(see "Unknown query parameters answer 422 on every list route" under "REST API"). The Python SDK's
`list_api_keys(status=...)` accepts the same filter as the HTTP endpoint and the CLI's
`key list --status`, so revoked keys can be listed from code too (`status="revoked"`).

A label-scoped key (one with `sandbox_labels`) lists only the keys whose own labels contain every
label pair of the caller. A key without labels, such as the bootstrap admin key, is therefore not
in that list, and neither is a key labelled for another scope; an org-wide key lists every key of
the organization.

An unknown field in a request body answers 422 and names the field; it is not ignored. This
holds for the key create body, sandbox create (`POST /v1/sandboxes`) and the other request bodies
of the API (sandbox update and resize, snapshots, image builds, volumes, webhooks and the
toolbox bodies for fs, git, process, PTY and sessions). A body that is not valid JSON answers 422
with the location `["body"]` alone.

The Python SDK does the same with `create_api_key` (it needs `api_keys:admin`; the plaintext key
is on the returned object, field `key`, and nowhere else):

```python
from datetime import datetime, timedelta, UTC

created = client.create_api_key(
    "student-7",
    ["sandboxes:read", "sandboxes:write", "toolbox:use"],
    sandbox_labels={"student": "7"},
    max_sandboxes=3,
    expires_at=datetime.now(UTC) + timedelta(days=7),   # must be timezone-aware
)
print(created.id, created.key)        # store created.key now; it is not shown again
```

**Minting from a capped key.** A key that has a `max_sandboxes` cap can mint keys only with exactly
its own `sandbox_labels` and a `max_sandboxes` that is set and no larger than its own; anything
else is a 403 naming the creator's cap (see "Per-key sandbox cap"). Every key it mints counts the
same sandboxes as the creator, so the creator's cap counts every key it mints and a teacher key
cannot be bypassed by minting a fresh, bigger one.

`create_api_key` also takes `shared_volume_labels={...}` (needs `sandbox_labels`): the key may then
list, get and mount read-only the volumes whose labels contain all those pairs, and
`ApiKeyInfo.shared_volume_labels` shows it.

`list_api_keys()` returns the metadata of every key (revoked ones included; pass
`status="active"` or `status="revoked"` to have the server filter, any other string raises
`ValueError` before a request is sent). The defaults differ on purpose: the SDK method and the HTTP
list return every key including revoked ones unless you filter, while `sandfort key list` hides
revoked keys unless you pass `--all`. `revoke_api_key(key_id)` revokes one. `AsyncClient` has the same three methods. The SDK's
`ApiKeyInfo` (and the `CreatedApiKey` that create returns) carries `status`, the server's
answer-time value: `"active"`, `"expired"` or `"revoked"`. The type `ApiKeyStatus` lists them and
is exported from `sandfort_sdk`; the field itself is a plain `str`, so a value a newer server adds
still loads. `revoked_at` and `expires_at` stay on the object. Against an older server that omits
the field, `status` reads `"active"`, so use `revoked_at` and `expires_at` there. The CLI's
`key list` shows the same status in its STATUS column.

The CLI (if you received the CLI wheel) has the same three operations under `sandfort key`:

```bash
# Create: the secret goes to stdout, a "shown only once" warning to stderr. --scope and --label
# repeat; --max-sandboxes needs at least one --label (without one: usage error, exit 2);
# --shared-volume-label KEY=VALUE (repeatable) shares volumes read-only and needs --label too;
# --expires-at needs a time zone (a value that is not ISO 8601, or has no time zone, and a --label
# that is not KEY=VALUE are usage errors, exit 2).
sandfort key create student-7 -s sandboxes:read -s sandboxes:write -s toolbox:use \
  -l student=7 --max-sandboxes 3 --expires-at 2026-12-01T00:00:00Z
sandfort key list                      # id, name, status, expires (UTC, "-" = never), scopes, labels, cap
sandfort key list --all                # also the revoked keys
sandfort key list --status active      # the server filters; --status revoked lists only revoked keys
sandfort key revoke key_... key_...    # one id per line; --if-exists skips an unknown id
```

`key list` hides revoked keys unless you pass `--all` (`-a`), and it always prints the ID column in
full, so an id can be copied into `key revoke`. The table columns are ID, NAME, STATUS, EXPIRES,
SCOPES, LABELS and MAX SANDBOXES. STATUS is `active`, `expired` (past `expires_at`) or `revoked`;
EXPIRES is the expiry in UTC (`YYYY-MM-DD HH:MM`), or `-` for a key that never expires; SCOPES shows
the first two scope names and then `+N more`. The revocation time is only in the `--json` objects,
which also carry the same `status` for each key. `key list --status active|revoked` asks the server
for that subset and overrides the default hiding. With the global `--json` flag `key create` prints
the whole key object. The secret is the field `key`. `key list` prints a list of objects, and
revoked ones only with `--all`. `key revoke` prints the revoked key. For several ids it prints a
list. A skipped id is `{"id": ..., "skipped": "not_found"}`. All three need the `api_keys:admin`
scope.

`create_api_key(..., max_sandboxes=...)` without `sandbox_labels` raises `ValueError` ("'max_sandboxes'
needs a non-empty 'sandbox_labels'") in the SDK before any request is sent; the REST API answers
the same mistake with 422. An empty `name` or an empty `scopes` list also raises `ValueError`.

#### Per-key sandbox cap

`max_sandboxes` (an integer from 1 to 1000) caps the live sandboxes of a label-scoped key. It
counts the sandboxes inside the key's label scope, so it needs a non-empty `sandbox_labels`; without
one the create is a 422. When the key already holds that many, `POST /v1/sandboxes` answers 429 with
the code `QUOTA_EXCEEDED` and `error.details` of `{"limit": "key_max_sandboxes", "max": 3,
"current": 3}` (`QuotaExceeded` in the Python SDK). The check runs in the same transaction that
inserts the sandbox, so two parallel creates at the cap cannot both pass. Delete a sandbox (or let
`auto_delete_minutes` remove it) and the key can create again. The labels are merged before the cap
is counted, so a key at its cap answers 429 `QUOTA_EXCEEDED` whether the create adds extra labels or
none; only a label that conflicts with the key's own value is refused first, with the 403 above.
The refusal is audited as `sandbox.create_refused` (details `limit`, `max`, `current`), not as
`request.denied`.

- The cap counts every live sandbox that carries all of the key's labels, whoever created it:
  another key with the same labels, or an unscoped admin key, counts too. Sandboxes that miss any
  one of the labels, and deleted ones, do not count.
- A sandbox in state `error` is not deleted and not "destroyed", so it counts too. A create
  without `--wait` (CLI) or with `wait=False` (SDK) that ends in `error` stays against the key's
  `max_sandboxes` until you delete it; `create --wait` with the default `delete_on_failure=True`
  deletes it for you (see "First sandbox in five minutes"). After a failed create that you did
  not wait for, delete the sandbox before you retry, or the next create can meet the cap.
- A capped key can only create keys with exactly its own labels (the same pairs, no extra ones) and
  a `max_sandboxes` that is set and no larger than its own. Every key it mints therefore counts the
  same sandboxes as the key itself, so the creator's cap bounds them all. Anything else is a 403
  with `details.max_sandboxes` set to the creator's cap; a label mismatch also names the creator's
  labels in `details.sandbox_labels`. A label-scoped key without a cap can still create keys with
  additional label pairs.
- The cap belongs to a label scope, not to one key's own sandboxes; it does not replace an
  organization quota. The beta may set organization limits (see Quotas).
- The SDK does not retry a 429 `QUOTA_EXCEEDED` (a cap does not free itself); see "Retries and
  idempotent create".

For a key without a cap, bound what it can leave behind with an `expires_at` and with
`auto_stop_minutes` and `auto_delete_minutes` on its sandboxes; a hard organization-wide cap is a
quota that only the maintainer sets.

## 2. Install the SDKs, MCP server and CLI

The CLI quick start below and the Python walkthrough in section 3 are two alternative first paths.
You need only one of them.

### CLI in five commands

Wheel names below use `bNN` for the beta number in the release note next to the wheels (for
example `0.1.0b60`). Use the exact file names you were sent.

```bash
python3.12 -m venv .venv && .venv/bin/pip install ./sandfort_sdk-0.1.0bNN-py3-none-any.whl \
  ./sandfort_cli-0.1.0bNN-py3-none-any.whl
export PATH="$PWD/.venv/bin:$PATH"
printf "API key from your secret link: "; read -s -r SANDFORT_API_KEY; echo
export SANDFORT_API_KEY
sandfort login --base-url https://api.sandfort.dev --verify-key
sandfort sandbox create cli-first --wait
# exec runs the argv directly: shell operators such as && need sh -c '...'.
# The default working directory is the root directory (/); use --cwd to change it.
# Options such as --cwd and -t go BEFORE the sandbox name:
#   sandfort exec --cwd /tmp cli-first -- pwd
sandfort exec cli-first python -c "print(21 * 2)"   # prints 42
echo hello > hello.txt
# Remote cp paths must be absolute.
sandfort cp ./hello.txt cli-first:/tmp/hello.txt
sandfort sandbox rm cli-first
```

The CLI reads the key from `SANDFORT_API_KEY`. The `read -s` line takes it from the prompt without
echo, so it never appears on the command line or in your shell history.

In a script there is no prompt. Either point `SANDFORT_API_KEY_FILE` at a key file (see below), or
pipe the key to `login` on stdin with `--key-stdin`:

```bash
printf '%s\n' "$KEY" | sandfort login --key-stdin --base-url https://api.sandfort.dev --verify-key
```

`--key-stdin` reads one line from stdin and ignores the other key sources. It cannot be combined
with `--api-key` or `--key-file`. If stdin is empty, `login` stops with a usage error that names
the key sources, and it does not wait. An error about the key says where the key came from, such
as "the api key read from stdin".

Options of `exec`, such as `--cwd` and `-t`, go before the sandbox name:
`sandfort exec --cwd /tmp NAME -- cmd`. After the name, everything is part of the command.

As an alternative, `SANDFORT_API_KEY_FILE` names a file that holds the key. The key is on the first
line of the file. The file must have mode 600 and belong to you, and the CLI checks the mode and
the owner. If `SANDFORT_API_KEY` is also set, the CLI uses it and does not read the file.
`sandfort login --key-file PATH` also reads such a file.

This block is the only CLI install in this guide. The sections below cover each step in detail.

### Python SDK

The SDK arrives as a wheel file. The package name is `sandfort-sdk`; the import name is `sandfort_sdk`.
The file name has the form `sandfort_sdk-0.1.0bNN-py3-none-any.whl`, where `NN` is the beta number
from the release note.

```bash
python3.12 -m venv .venv
.venv/bin/pip install ./sandfort_sdk-0.1.0bNN-py3-none-any.whl   # use the file you were sent
```

The Python SDK and the CLI require Python 3.12 or newer. A stock system `python3` (often 3.9 on
macOS) fails the install with a version error from `pip`, so create the venv with a 3.12 interpreter
as shown.

To verify the install, run `python -c "import sandfort_sdk; print(sandfort_sdk.build_info())"`; it
prints the wheel's commit and tag. The one-line check that the wheel matches the running server is
comparing `build_info().commit` with `client.status().build_sha`.

The CLI has the same check: `sandfort version` prints the CLI and the SDK build and makes no network
call. For JSON use `sandfort --json version`; the global `--json` flag goes before the subcommand,
and `sandfort version --json` is a usage error. The JSON form carries the full commit, the text
line shows a 12-character prefix.

Since beta 60 the wheel version comes from the release tag (`0.1.0b60`, `0.1.0b61`, and so on),
so `pip list` tells builds apart and installing the newer wheel upgrades the venv without
`--force-reinstall`. Wheels from earlier betas all carry `0.1.0`; for those, use a fresh venv.
`build_info()` still reports the commit and the tag.

### TypeScript SDK (if you received the tarball)

The TypeScript SDK is a packed npm tarball named `@sandfort/sdk`. It ships compiled JavaScript with
type declarations, so a plain `npm install` of the file you were sent works in Node (20 or newer)
with no TypeScript toolchain. It is delivered as a file during the beta, not from a public registry.

```bash
npm install ./sandfort-sdk-0.1.1.tgz   # use the tarball you were sent
```

### MCP server

The MCP server is the PyPI package `sandfort-mcp` (Python 3.12 or newer), not a file in the
delivery package. In an MCP client that takes a JSON config, run it with `uvx` and set
`SANDFORT_BASE_URL` and `SANDFORT_API_KEY` in the environment:

```json
{
  "mcpServers": {
    "sandfort": {
      "command": "uvx",
      "args": ["sandfort-mcp"],
      "env": {
        "SANDFORT_BASE_URL": "<the base URL you were sent>",
        "SANDFORT_API_KEY": "sf_..."
      }
    }
  }
}
```

`uvx sandfort-mcp` runs the newest release on PyPI. The tools and options below need
`sandfort-mcp` 0.1.1 or newer. Version 0.1.0 has 14 tools, no `start_sandbox` or `stop_sandbox`,
and a `create_sandbox` that takes only `name` and `snapshot`.

From version 0.1.1 the server has 16 tools: create, start, stop, list and delete for sandboxes,
`create_snapshot`, `run_code`, `run_command` and eight file tools (text and binary upload and
download, `list_directory`, `stat_path`, `make_directory`, `delete_path`). What an agent needs to
know:

- `create_sandbox` takes the optional `auto_stop_minutes`, `auto_delete_minutes`, `labels`,
  `block_network`, `egress_allowlist` and `isolation`. An option left out keeps the server default.
- By default (no `auto_stop_minutes`), a sandbox created through MCP stops after 15 idle minutes
  and is not deleted unless the agent passes `auto_delete_minutes` to `create_sandbox`. A stopped
  sandbox keeps its files (see "What
  stop, start, resize, reset and delete keep" below). `start_sandbox` starts it again and waits
  until it is started, for 1 to 600 seconds (default 60). `stop_sandbox` returns at once, so the
  state may still be `stopping`.
- Without a `snapshot` the image is `python:3.12-slim`: Python and pip, no git. See "What the
  default image contains" below.
- Text and binary uploads and downloads are limited to 1 MiB. A text upload counts UTF-8 bytes,
  not characters.
- A tool error comes back as text in the form `error: <message>`. The server acts with the scopes
  of the API key it is given.

### Command-line (if you received the CLI wheel)

The install is in "CLI in five commands" above. This section covers what the CLI does after it.

The sandbox name of `sandbox create` is a positional argument. Without `--snapshot` the image is
`python:3.12-slim`. `exec` keeps the remote exit code. `cp` uploads, and you swap the arguments to
download. `sandbox rm` works on a running sandbox.

`login` reads the key from `SANDFORT_API_KEY` in the environment, so the key stays out of your
shell history. `SANDFORT_API_KEY_FILE` is the file form: a file with mode 600 that holds the key,
which the CLI checks for mode and owner. `sandfort login --key-file PATH` reads such a file too.
Keep `--base-url` in the `login` command. `sandbox rm` does not prompt for confirmation and has no
`-y` option.

`login` stores the URL and key in a local profile with mode 600. The profile is the file
`profile.json` in the CLI's config directory (default `~/.config/sandfort`). Set
`SANDFORT_CONFIG_DIR` to point the CLI at another profile directory: that is the supported way to
keep parallel accounts side by side (one directory per account) and to isolate a test harness from
your real profile. Set it for `login` and for every later command that should use that profile.
`SANDFORT_BASE_URL` and `SANDFORT_API_KEY` still override the values read from the profile.
`SANDFORT_API_KEY_FILE` overrides the profile key in the same way, unless `SANDFORT_API_KEY` is set.

Before it saves anything, `login` sends one unauthenticated `GET` to `<base-url>/v1/status` (5 s
timeout). The probe does not follow redirects, and when the URL answers with one, the login error
names the redirect case and suggests the final URL as the base URL. If the server answers with a
status document, the profile is saved and the CLI prints one line,
`server <base-url>: build <first 12 characters of build_sha>`. A status document is a JSON object
whose `data` has the key `build_sha`. When that value is `null` (the server reports no build), or
an empty or non-text value, the line reads `build unreported`. That is the only meaning of
"unreported": an answer that is valid JSON but has no `build_sha` key at all is rejected as not
being a status document, like any other body that is not one. If the URL does not answer
(connection error, a non-2xx status, or a body that is not a status document), nothing is saved,
an existing profile is left as it was, and the command exits 1 with an error that names the URL.
A URL that is structurally unusable (for example an unclosed IPv6 bracket) never gets that far: it
is a usage error with exit 2, described below, and nothing is sent or saved. For a host that cannot reach the server yet (an air-gapped machine, a
server that is not up), use `sandfort login --no-verify ...`: it saves the profile without any
request and prints `server <base-url>: not checked (--no-verify)`.

Without `--verify-key`, a successful login does not prove that the key is valid: the status
endpoint needs no key, so a wrong key is saved and shows only on the next command. The CLI says so
in a second line, `api key: NOT verified (a wrong key shows on the next command; use --verify-key
to check it now)`. With `sandfort login --verify-key ...`, the CLI makes one authenticated
`GET /v1/sandboxes?limit=1` with the key, after the status probe and before it saves anything. The
table gives the outcomes; the notes below it explain the rows. The last column shows what changes
when `--require-verified` is used instead of `--verify-key` (see the notes).

| Answer to the key check | Profile saved | Exit | `--json` output | With `--require-verified` |
|---|---|---|---|---|
| 2xx | yes | 0 | `key_verified: true`, `key_status: "verified"` | same |
| 403 with the server's error envelope | yes | 0 | `key_verified: "limited-scope"`, `key_status: "limited-scope"`, plus `missing_scopes`, `missing_scopes_beyond_cap` and `request_id` | not saved, exit 1, error object |
| 403 without the envelope (for example a proxy or login page) | yes | 0 | `key_verified: false`, `key_status: "not-checked"` | not saved, exit 1, error object |
| 401 | no (an existing profile stays) | 1 | error object; `details` has `server_code` and `request_id` when the server sent them | same |
| Any other status (3xx, 4xx, 5xx) | no | 1 | error object, same `details` | same |
| The status probe fails (no answer, a non-2xx status, or a body that is not a status document); the key check is never sent | no (an existing profile stays) | 1 | error object with the client wrapper code `CLI_ERROR` and empty `details`; `"source": "client"` when nothing was sent (connection failure) | same |
| The key check request fails after the probe succeeded (timeout, connection error) | no | 1 | error object; `"source": "client"` when nothing was sent | same |
| `--no-verify` (no request at all, so no key check) | yes | 0 | `key_verified: false`, `key_status: "not-checked"` | usage error, exit 2: the flags cannot be combined |
| Default (status probe only, no `--verify-key`) | yes | 0 | `key_verified: false`, `key_status: "not-checked"` | not applicable: the flag runs the key check, so the rows above apply |

- 2xx prints `api key: verified (HTTP 200 on GET /v1/sandboxes)`.
- A 403 whose body is the server's own error envelope (a JSON object with `"success": false`)
  means the key is probably valid but lacks the sandbox read scope. The line reads `api key: the
  server answered 403 (HTTP 403 on GET /v1/sandboxes); the key is probably valid but lacks the
  sandbox read scope`, followed by the missing scope names when the envelope lists them and by the
  request id. The key may be fine for other work.
- A 403 that is not that envelope did not come from the Sandfort API. So the CLI does not claim the
  key is valid. The line reads `api key: NOT verified; the 403 answer (HTTP 403 on GET
  /v1/sandboxes) did not come from the server's API (...); the profile was saved anyway`. Such a 403
  deliberately does not adopt an `x-request-id` header that a proxy supplied: that id is not the
  server's, so the line and the error object carry no request id.
- On a 401 or any other status, the error names the server's error code, message and request id
  when its envelope parsed. A 3xx adds the redirect hint (redirects are not followed; use the final
  URL as the base URL), and a 5xx, 408 or 429 suggests a retry or a login without the flag.
- On the text success line, a key check that was answered but not verified (the 403 without the
  envelope) reads `Profile saved to <path>; the api key was not verified` instead of
  `Logged in; profile saved to <path>`.

`--require-verified` is the strict mode for bootstrap scripts. It implies the key check (you do not
need `--verify-key` with it) and it succeeds only when the key check is answered 2xx. Any other
outcome exits 1 and saves nothing, and an existing profile stays as it was. That includes the two
403 rows that `--verify-key` still saves: the 403 with the server's envelope (a limited-scope key)
and the 403 without it. The error says that the api key was not verified and that the profile was
not saved. With `--json` the error object's `details` carries `key_status` (`limited-scope` or
`not-checked`), `missing_scopes` (a pure array) and `missing_scopes_beyond_cap` (a number) when the
server named scopes, `request_id` when it sent one, and
`server_code` when the server's error envelope sent a code (the 403 without an envelope has none).
The code is sanitised like any relayed text (see below).
`--require-verified` cannot be combined with `--no-verify`: that is a usage error with exit 2.
Combining it with `--verify-key` is accepted and changes nothing.

The advice in a strict-mode failure never offers `--verify-key` or `--no-verify`: you did not type
the first, and the second cannot be combined with the strict flag. It says to retry (a 5xx, 408 or
429 answer, or a failed key-check request) or to check the base URL (its query string is sent too),
followed by `or drop --require-verified if saving without the key check is acceptable`. A failed
status probe says `check the url and retry`, and a redirect gives the redirect hint, both without
the `--no-verify` offer that the other modes make.

`--verify-key` also cannot be combined with `--no-verify`. With the global `--json` flag the build
and key lines are not printed, and the success object has three fields: `profile` (the path of the
saved profile file), `key_status` and `key_verified`. `key_status` is a string with three values:
`verified`, `limited-scope` and `not-checked`. `key_verified` is the older field, kept for
compatibility; it mixes types (`true`, the string `"limited-scope"`, or `false`), and `false` covers
every `not-checked` case, so prefer `key_status` in new scripts. Two fields appear only in some
cases. A `limited-scope` key adds three fields. `missing_scopes` is a list of the scope names the
server reported, at most 20. It is a pure array of names, and it can be empty.
`missing_scopes_beyond_cap` is a number: how many more scope names the server reported than the 20
listed, or `0` when none were cut. `request_id` is a string, or `null` when the server sent none.
`userinfo_removed` is `true`, and present only then, when userinfo was removed from the saved base
URL (see below). A failed login prints a JSON error object (`{"error": {...}}`) on stdout and saves
nothing, so there is no success object to read.

With `--json` the login never prompts. When `--base-url` or `--api-key` (or `SANDFORT_API_KEY`) is
missing, stdout carries one usage-error object whose `error.code` is `USAGE_ERROR`, and the exit
code is 2. Without `--json` the missing value is prompted for. The same usage error (exit 2, and
the same object under `--json`) ends a login whose `--api-key` or `--base-url` is empty, or whose
base URL is unusable on this machine. Every such URL is one family with one wording, `base url <url>
is not a valid url (<reason>); nothing was sent, check the url`, exit 2 (with `--json`:
`USAGE_ERROR` and `"source": "client"`). Nothing is saved, and the check runs before `--no-verify`
is considered, so an unchecked save never stores such a URL. The reasons are:

- `unsupported scheme, it must start with http:// or https://`
- `no host` (`http://`, `https:///`, and what is left of `http://user@` or `http://:80` after the
  userinfo is removed)
- `invalid port` (a port that is not a number)
- `the host is longer than 253 characters`
- `port out of range 1-65535` (port `0` and negative ports included)
- `whitespace or a control character in the host`
- `malformed brackets in the host` (an unclosed IPv6 bracket, or text after the closing bracket)
- `the url cannot be parsed` (a URL that Python's `urlsplit` or the `httpx` parser used for the
  requests refuses; the reason is this fixed phrase because a parser's own message can quote parts
  of the URL)

An empty port (`host:`) is accepted. A URL with an unclosed IPv6 bracket is therefore a usage error
with exit 2 and the `malformed brackets in the host` reason, like the other reasons, not a client
error with exit 1.

The same checks run on the base URL that the CLI reads from `SANDFORT_BASE_URL` or from the
profile, for every command that needs a login, before a client is built. An unusable configured URL
ends the command with the same usage error (exit 2, and one `USAGE_ERROR` object under `--json`),
never with a traceback. The error names where the URL came from: `SANDFORT_BASE_URL`, or `base_url`
in the profile file.

`--json` is a global option and must come BEFORE the command: `sandfort --json sandbox list`. After
the command (`sandfort sandbox list --json`) it is a usage error, and the message ends with the
hint `--json is a global option and belongs before the command, for example: sandfort --json
sandbox list`. The command in that example is fixed text: the hint does not repeat your own
command, so read it as a pointer to the position of the flag, not as a suggestion to run `sandbox
list`.

This is true for the whole CLI, not only for `login`. Give `--json` before the command. Then a usage
error anywhere, such as a bad option value or a missing argument, is printed as one JSON object on
stdout. The object has `error.code` `USAGE_ERROR` and `"source": "client"`. The exit code is 2. The
framed usage box is not printed. Without `--json` the usage box stays. A command group called with
no command behaves the same way. Put `--json` before it, as in `sandfort --json sandbox`. Then
stdout carries one usage-error object and no help text, so the output stays parseable. The message
is `missing command for 'sandfort sandbox'; the help is available in text mode (run it without
--json, or add --help)`. The exit code is 2. Without `--json` the group prints its help.

The bad-value usage errors are checked before any request and before the login is read. A
`--label` or `--env` that is not `KEY=VALUE` (on `sandbox create`, `sandbox list` and `key create`)
and a `key create --expires-at` that is not ISO 8601 or has no time zone are usage errors with exit
2, naming the option. So is `key create --max-sandboxes` without any `--label`: the cap counts the
sandboxes that the key's labels select, so the message says `at least one KEY=VALUE is required
with --max-sandboxes` and names `--label` (before, this case was a client error with exit 1).

A key repeated among the `--label` values, or among the `--env` values, is a usage error too (exit
2): the message names the key (`label key 'job' is given more than once`) instead of keeping the
last one. A key made only of terminal control sequences counts as empty and is refused before any
request. The `api_key` field of the profile has four error messages: not a string, empty,
malformed and too long (more than 512 characters). "Malformed" means the key is not printable
ASCII with no whitespace inside or around it: a character outside printable ASCII, whitespace
inside the key, a whitespace-only key and whitespace around the key all count. Each
message ends with `run 'sandfort login'` and never echoes the key.

When one of these messages echoes the value you typed, the echo is sanitised like relayed text. The
value is the bad `--label`, `--env` or `--expires-at`. The echo is cut on its own to 120 characters,
with an ellipsis. So the reason after it always survives the 600-character cap of the whole message.

The parser's own value errors use one style. A whole-number option or argument is checked before
anything is sent. The options and arguments are `exec --timeout`, `key create --max-sandboxes` and
the `preview` port. If the value is not a whole number, or is out of range, the CLI answers `Invalid
value for <option>: must be a whole number greater than 0, got '<value>'`, with exit 2. For the port
the text reads `... from 1024 to 65535 ...`, the range the server accepts for a preview token. The
wording is the same under `--json`, with code `USAGE_ERROR` and `"source": "client"`. Nothing is
sent. A whole-number option or argument takes plain ASCII digits with an optional leading minus and
nothing else: `+5`, a value with surrounding spaces, `1_000` and digits from other scripts are
refused with the same message, although Python's own `int()` would take them. For a value with
surrounding whitespace the message ends with `; surrounding whitespace is not allowed`, because the
echoed value is flattened and would otherwise look like a plain number. A number with more digits
than Python's integer parser allows is refused with the same message. The integer options of
`sandbox create` (`--auto-stop`, `--auto-delete`, `--cpu-millicores`, `--memory-mib`, `--disk-gib`),
`cmd start --timeout` and `preview --ttl` follow the same style, and their help shows the
placeholder `INTEGER`. Positional placeholders on the usage line are written in angle brackets
(`<sandbox>`, `<sandbox>...`, `<argv>...`, `<port>`, `<session-id>`, `<command-id>`, `<key-id>...`,
`<name>`), not in curly braces; the arguments of `cp`, `snapshot`, `volume` and the member commands
use them too (`<source>`, `<destination>`, `<snapshot-id>`, `<volume-id>`, `<user-id>`, `<email>`).

`exec --timeout` (and `cmd start --timeout`) is capped up front at 3600 seconds, the server's
default maximum for a command (`SANDFORT_MAX_EXEC_TIMEOUT_S`): a larger value is the usage error
`must be a whole number from 1 to 3600`, found before anything is sent. An empty or blank id, name
or reference argument is a usage error as well (`must not be empty`, exit 2, naming the argument),
also before any request and never a traceback. A name made only of invisible format characters (zero
width space, joiners, bidirectional marks and the other default-ignorable code points), alone or
mixed with whitespace, counts as blank too: nothing of it is visible. A name made only of terminal
escape sequences is refused with the exact message `must not be empty (after removing terminal
control sequences)`, so you can tell it was not typed empty. It applies to every sandbox reference.
These are the reference of `sandbox get`, `stop`, `start`, `reset` and `rm`, and every reference
given is checked. They are also the reference of `exec`, `cmd start`, `cmd logs`, `cmd kill`,
`preview` and `snapshot create`. The reference of `shell` is checked before the interactive-terminal
check. The sandbox part of a remote `cp` path is checked on either side. This includes a `cp`
argument that is only whitespace before the colon. An empty one, as in `:/path`, is a local path
instead. It also applies to the name of `sandbox create`. It applies to the session and command ids
of `cmd logs` and `cmd kill`. It applies to the `key create` name and every `key revoke` id. It
applies to the `snapshot create` name, the `snapshot register` image and `--name` value, and the
`snapshot` ids of the other `snapshot` commands. It applies to the `volume create` name and the
`volume` ids. It applies to the `members add` email and display name, and to the user id of `members
set-role` and `members remove`.

A blank value of an option is refused locally in the same way (usage error, exit 2, the option
named, nothing sent). Blank means empty, only whitespace, only invisible format characters, or
containing a control character with nothing visible (a name made only of control characters is
blank too, since round 54). The options checked: `--scope` of `key create` (each value),
`--snapshot` and `--egress` (each value) and `--mount` of `sandbox create`, `--state` of `sandbox
list`, `--cwd` of `exec`, `--session` of `cmd start`, `--name` of `snapshot build` and `--output`
of `snapshot export`. Other options keep their own rules: a blank value of `--env` or `--label`
is legal, but a key made only of blank characters is a usage error. A whole-number option that
gets a value the echo would show as a plain number gets a note that says why it is not one:
- a leading plus sign: `a sign is not accepted; write the number without it`;
- an invisible character inside it: `contains an invisible character U+200B`, with the code point
  of the character (a control character is named the same way: `control character`);
- a byte the shell could not decode: `contains an undecodable byte`;
- a digit outside ASCII: `only plain ASCII digits are accepted`.

`sandbox create --mount` with a value that is not `VOLUME_ID:PATH` (no colon, or a blank volume id or
path) is a usage error with exit 2 (`invalid mount ...; expected VOLUME_ID:PATH`). It exited 1
before round 54, so a script that matched on 1 for a bad mount must now expect 2. The check runs
before any other option is parsed and before the login is read.

`cp` has more usage errors. All are exit 2 and are found before any request. One is a blank local
path or a blank remote path, which is the part after the colon. The error names `<source>` or
`<destination>`. Another is a wrong endpoint form, where neither or both of the two arguments are
in the sandbox-path form. Its message is `exactly one of source and destination must be
<sandbox-id>:<path>`. The rest are the other checks the CLI makes on your side before it sends
anything: a missing local source, a relative remote path, and a destination directory that does not
exist or is not writable. These errors exited 125 before round 64; scripts that matched on 125 for
them must now expect 2. A failure after the request is sent, such as an unknown sandbox, an
authentication error or a server error, keeps exit 125 (see the `exec` table below).

`login` refuses a malformed api key before it sends anything and before it saves anything. A key
that is not printable ASCII, or has whitespace inside it, is the usage error `Invalid value for
--api-key: is malformed (an api key is printable ASCII with no whitespace inside)`. The exit code
is 2. So is a key longer than 512 characters (surrounding whitespace not counted): `Invalid value
for --api-key: is too long (an api key is at most 512 characters)`, exit 2. A real key is about 60
characters; the cap only stops absurd input. When the hidden `Api key` prompt reads input that is
not valid UTF-8 text, the result is the `is malformed` usage error as well, exit 2, not a
traceback. The key itself is never echoed. It is the same check that every other command applies to
a configured key, the length cap included.

Text that the CLI relays from the server or from the network is sanitised before it is printed or
put in a JSON field, in text and `--json` mode alike, on every command (the sanitiser is one shared
module, `cli/src/sandfort_cli/sanitise.py`; it is not limited to `login`). It covers:

- the server's error code, message, `details` and request id, in the text line and in the `--json`
  error object of any command, and the fields of a failed sandbox (`sandbox_id`, `state`,
  `error_reason`, `error_code`). The keys and values of `details` are kept up to 50 entries, nested
  at most 4 levels deep. A deeper level is shown as `…`. A code is cut to 100 characters, an id to
  128, and a server message to the default relay limit of 300 characters. Every other relayed field
  follows the same limit (see the last rule below). The higher limit of 600 characters applies only
  to transport errors and to the message (and `error_reason`) of a failed sandbox;
- the hint lines printed under an error, which may repeat what you typed or an id from the server;
- the build value in the status line, the missing scope names and the reason of a failed status
  probe or key-check request from `login`, and the URL echoed in its usage and invalid-URL errors;
- the message of a usage error, and the text errors that typer itself prints in text mode
  (`unexpected extra argument`, `No such command`, `No such option`). They echo what was typed. A
  key given there by mistake is masked. Control characters are removed. The message is cut to 600
  characters;
- the CLI's own error messages get a lighter pass: control characters and your api key (and any
  key-shaped token) are removed or masked, and the text is cut to 2000 characters;
- success output of the sandbox commands. This covers the sandbox table (`sandbox list`) and the
  field view (`sandbox get` and the other commands that show one sandbox). It covers the `--json`
  sandbox object, where each string and each key is covered, and numbers, booleans and `null` keep
  their type. It also covers the `sandbox isolation` view and the id that `sandbox rm` prints. These
  values are flattened to one line and cut only at the raw bound of 2000 characters, not at 300 (the
  labels and the error reason in the sandbox table are still cut to 32);
- the snapshot, volume, key and member views (tables, field views and `--json` objects), the
  output of `preview`, and the lines of `cmd start` and `cmd kill` get the same pass as the sandbox
  views. Three outputs are exceptions, and only these:
  - the one-time secret of `key create` is printed byte for byte: the plaintext key on stdout in
    text mode and the `key` field of the `--json` object. Every other field of that object is
    sanitised;
  - the preview token is not changed: the `token` field of `preview --json` is exactly what the
    server returned. The URL is sanitised like any server text, except that the token stays usable
    in it. The sanitiser would mask every query value, as in `?sandfort_preview_token=***`. So the
    value of the `sandfort_preview_token` query parameter is put back as returned, when the token is
    ordinary text. Ordinary text means the sanitiser would leave it unchanged. Other query values
    stay masked. When the URL cannot carry the token that way, text mode prints the exact token on a
    `token: <token>` line after the URL. A token that holds control characters is never printed in
    text mode (a note on stderr says to use `--json`), and the URL then shows it masked;
  - the build log lines that the CLI echoes while it follows a snapshot build follow the program
    output policy of `exec` (see "Program output" in the rules below). Dangerous terminal sequences
    are removed. The content is not masked. Nothing is flattened or cut, so indentation is kept.

In the `--json` success output this is the stated contract. Whitespace inside a string value is
flattened to single spaces. So a label value with a line break or a run of spaces is not returned
byte for byte. A query-like value inside a label string is masked as `?name=***`, as in error text.
Such a value is a URL-shaped text followed by `?name=value`. Do not use a label to carry text that
must come back unchanged.

Two keys of one mapping (two label keys that differ only in a hidden character) can become equal
after sanitising. A key that sanitising left as it was keeps its exact name, also one shaped like
`a#2`. A key that sanitising changed takes its cleaned name when that is free, otherwise the
cleaned name with the suffix `#<n>` and the lowest free number from 2, in the mapping's order. So a
key with a hidden character never takes the plain name of a genuine key, whichever order the
server sent them in, and no pair is lost.

Scripting note for CI: because of this, a label written through the CLI does not round-trip
through the CLI. `sandfort sandbox create --label url=https://ci.example/run?id=7 ...` stores the
value as typed, but `sandfort --json sandbox get ...` returns `https://ci.example/run?id=***`, and
a value with a line break or a run of spaces comes back flattened. Do not feed a label read from
`--json` output back into a comparison, a `--label` filter or another command. The Python SDK
applies none of this and returns the stored value unchanged. Store URLs without a query string, or
read the label through the SDK.

The rules:

- The api key you passed is masked as `***` wherever it appears in the text, also in its URL-encoded
  forms.
- Userinfo is removed without any marker (`https://user:password@host` is relayed as
  `https://host`), also without a scheme, and before control characters are stripped, so a control
  character inside a password cannot hide the rest of the URL. Query values are masked
  (`?token=***`), and so is a fragment that follows a URL (`#***`). A query is masked only after a
  URL context. A URL context is one of these: a scheme or `//`; a path; a dotted host name; a host
  with a port or a bracketed address; a word in any script before a `?`; or ASCII text before a `?`
  that is followed by `key=`. The ASCII text can also be empty. For a word in any script, letters,
  digits, `-`, `_`, `.` and combining marks count as a host. The IDNA dot variants U+3002, U+FF0E,
  U+FF61, U+2024 and U+2025 read as `.`. So `café?token=***` is masked like `what?x=***`. Brackets,
  quotes and sentence breaks such as the ideographic comma do not make a host. A question mark in
  prose (`what?`, a question in Chinese, Japanese or Thai text) is left as it is. The scheme-less
  forms are not treated alike, because the sanitiser must not damage email addresses in relayed
  text:
  - Scheme-relative userinfo (`//user:password@host`) is always removed.
  - A bare `user:password@host` is removed only when it reads as a URL authority, that is, when the
    host is followed by a port or a path (`user:password@host.internal:8443`,
    `user:password@host.internal/path`).
  - Ordinary email addresses and label-and-email pairs survive unchanged
    (`write to mailto:support@example.com`, `contact:ops@example.com`, `help@example.com`).
  - The tradeoff: a bare `user:password@host` with neither a port nor a path after the host is
    intentionally left as it is. That holds for a plain word (`user:password@plainword`) and just as
    much for a dotted host alone (`user:password@host.internal`), because neither can be told apart
    from a label followed by an email address. Do not rely on the sanitiser to hide a credential
    written that way.
  - A fragment of only ASCII digits is read as an anchor or an issue number and stays readable: up
    to six digits in a token without a scheme, only up to three after a scheme. An empty user does
    not hide a bare credential: `:secret@host` is masked only when a port or a path follows the
    host, and the host must also read as a host (it has a port, is dotted, is bracketed or starts
    with a letter). Unicode whitespace other than the plain space and LF (tab, no-break space, line
    separator) inside a bare credential no longer splits it. Trade-offs: a plain space or LF inside
    a credential still ends it, a bare `user:pw@host` with no port or path stays readable, and
    non-credential text shaped like `user:pw@host/path` is masked too. Examples:
    - `refs/heads/feature#12` stays as written; `https://host.test/verify#123456` becomes
      `https://host.test/verify#***`.
    - `:secret@host:8443` is masked, with a dotted host or a bracketed one as well.
    - `user:pw@host.internal` (no port, no path) stays readable.
    - `:secret@host.internal` (empty user, no port, no path) stays readable too.
    - `ratio 3:2@4/5` is masked, because it has the shape `user:pw@host/path`.
- Terminal escape and control sequences (OSC, CSI and the other escape strings, backspaces,
  newlines), the other control characters that are not whitespace and invisible characters are
  stripped. "Invisible" has two views. The displayed text loses only the genuinely invisible format
  characters (category Cf) and an explicit list of fillers. The fillers are the soft hyphen, the
  combining grapheme joiner, the Arabic letter mark and the zero width space. They also include the
  directional marks and bidirectional controls, the Hangul fillers, the braille blank, the BOM and
  the Unicode tag characters. Format characters that draw something stay visible: the Arabic number
  signs and end-of-ayah marks (U+0600 to U+0605, U+06DD, U+0890, U+0891, U+08E2), the Syriac
  abbreviation mark (U+070F), the Kaithi number signs and the Egyptian hieroglyph format controls. A
  well-formed emoji tag sequence (the black flag, two to eight tag letters or digits and the cancel
  tag, as in the flags of Scotland or Wales) keeps its tag characters; any other tag character is
  removed. The internal matching view is wider: it uses the Unicode Default_Ignorable_Code_Point
  property (assigned and unassigned code points alike), the categories Cf, nonspacing mark (Mn) and
  enclosing mark (Me), and the explicit lists. It looks through all of them to find a hidden key or
  userinfo, and it also ignores plain spaces and delimiters inside a terminal sequence. The mark
  categories, the zero width joiner and non-joiner and the variation selectors are used solely in
  that matching view. They are not stripped from the output. So real-language combining marks and
  emoji sequences are preserved in what is printed. Examples of combining marks are Thai,
  Devanagari, Hebrew niqqud, Arabic harakat and decomposed accents. Secrets are masked before this
  strip as well as after it, looking through such characters and escape bytes, so a key or a
  credential pair joined with them is still masked, and the marks around the masked part stay. Every
  whitespace character (tab, line break, vertical tab, form feed, the separator controls, next-line,
  the non-breaking space and the other Unicode spaces, the line and paragraph separators) counts as
  whitespace in every step below, and runs of it become one space. In particular, such a character
  inside the password of a URL does not end the userinfo, so no password prefix survives.
- The input is bounded: the raw text is cut to 2000 characters before any rule runs, so the time the
  sanitiser takes does not depend on what the server sends. When the text was cut, the tail is
  examined only after the control and invisible characters are stripped, so characters interleaved
  to hide it do not help. Two kinds of tail are dropped. The first is a piece that is only the start
  of your api key. The key can be literal, URL-encoded, or partly percent-encoded. This kind also
  covers the start of any key-shaped token, which is `sf_` and up to 15 more key characters. The
  second is the last token that holds a colon or a double slash. A plain space delimits the token.
  It is dropped because a URL cut inside its userinfo has no `@` left to be recognised by. A token
  whose last URL already has a complete authority, closed by `/`, `?` or `#` (a long path, for
  example), is kept only up to its last slash: a credential pair (a colon) in the last path segment
  is dropped. A text cut this way always ends with an ellipsis; if nothing is left of a URL or a
  typed value longer than 2000 characters, the echo is the ellipsis alone, never an empty string.
- Key masking works on the decoded text as well: your api key is masked also when it is written as
  any mix of literal and percent-encoded characters (`sf%5Ftest_key`), in either hex case. Any other
  token with the shape of an api key (`sf_` followed by at least 16 key characters) in a relayed
  text is masked too, not only the key you passed.
- Stage order (round 54). Two security testers found gaps where one stage hid text from the next;
  these are closed, and each stage now gives the same text when it runs twice:
  - A key of its real length (about 60 characters) with one hidden character inside it, at any
    position (a zero width space, a joiner, a control or escape byte, a lone surrogate), is masked
    whole, both your own key and a key-shaped token. Earlier, the tail behind the hidden character
    could survive. The key mask also runs once more between the strip of terminal sequences and the
    flattening of whitespace, and a lone surrogate counts as a hidden character.
  - Query and fragment values are masked before the terminal sequences are stripped. An escape
    sequence that consumes the `?`, the colon of `://` or the `#` can no longer leave the value
    readable. A terminal sequence can have a body that holds an `@` and a `#` or `?` inside a
    password with whitespace. Its body can no longer turn into text that shows the rest of the
    password.
  - The URL-context test for a query (and for a fragment) looks at the matching view, so a joiner
    or a combining mark in front of the `?` does not hide it, and non-ASCII host names count as
    hosts: `bücher.example?token=***`, `пример.рф?token=***` and `例子.测试:8080?token=***` are
    masked. A question mark in prose is still left alone.
  - Whitespace other than the plain space inside a query or fragment value (tab, line break,
    vertical tab, form feed, next-line, no-break space and the other Unicode spaces) does not end
    the value, because flattening would turn it into a space and split the value. Only the plain
    space ends it: `?token=abc def` is relayed as `?token=*** def`.
  - A fragment right after a host without a scheme is masked like a query: `host.test#***`,
    `host.test:8080#***`, `localhost#***`, `[::1]:8080#***`, `/v1/x#***`. A hash without a URL
    context (`issue #123`, `C#`) is left as it is.
- A reply body that is nested so deeply that it cannot be parsed is treated like a body that is not
  JSON (for the status probe: not a status document; for the key check: no server error
  envelope), never as a traceback. The request id of a server error envelope is read from the
  error object, else from the envelope's `meta`, else from the `x-request-id` response header.
- Each field is cut to 300 characters, and the cut ends with an ellipsis (`…`). There are three
  exceptions. A URL echoed in a message is cut on its own to 200 characters. A typed value echoed in
  a usage message (see above) is cut on its own to 120. So the reason after either survives. The
  message of a usage error is cut to 600 characters.
- Program output is a different case: it is relayed, not sanitised. `exec` and the `cmd logs`
  follower print the command's stdout and stderr. Both `cmd logs --follow` and `cmd logs` without it
  count as the follower. Only the string sequences a terminal acts on are removed. These are OSC
  (window title, hyperlinks, clipboard write), DCS, SOS, PM and APC, in both the `ESC` form and the
  8-bit form. A sequence that never ends is cut at the next `ESC` or at the end, as a terminal would
  read it. The sanitiser does not touch anything else, and nothing in the output is masked: a key or
  URL that the program prints appears in your terminal and logs. Colour and cursor sequences (CSI)
  are passed on by the sanitiser, but the CLI prints through `typer.echo`, which removes them when
  the stream is not a terminal. They reach the screen only when stdout (stderr, for the program's
  stderr) is a terminal; piped or redirected output loses them. `shell` is an interactive terminal
  and relays the remote byte stream raw by design; the `exec` and `cmd logs` filter does not apply
  to it, so run `shell` only against programs you trust to write to your terminal.
- At most 20 missing scope names are relayed. The count of the rest is not an entry in the list: it
  is the number in the field `missing_scopes_beyond_cap` (`0` when nothing was cut), and the text
  line of the scopes ends with `, and N more`. `missing_scopes` stays a pure array of scope names.

A build value that is empty after this is shown as `build unreported`, like a `null` one.

A base URL can be configured rather than typed at `login`. It is set by `SANDFORT_BASE_URL`, or by
`base_url` in the profile. It is checked on every other command before the client is built, with the
same checks as `login`. A control character anywhere in it is rejected as `a control character in
the url`. This includes userinfo, path and query. Userinfo in a configured URL is removed before any
request is sent, with `note: userinfo was removed from the configured base url (it would replace the
api key as a Basic authorization header)` on stderr (text mode only; with `--json` the note is not
printed). The bearer `Authorization` header with your api key is kept, so authentication works as
before. The not-logged-in error comes first: with no api key configured (neither `SANDFORT_API_KEY`
nor the profile), a command fails with `not logged in` before any URL validation, so fix the key
first and only then will a URL error show up. A profile whose `base_url` field is present but not a
usable string is reported as a malformed profile instead. The same holds for the `api_key` field of
the profile. Suppose it is present but is not a JSON string, such as a number, `null`, a list, an
object or a boolean. Or suppose it is the empty string. Then the profile is damaged, not logged out.
The command ends with a usage error, exit 2, that names the profile. The text is `api_key in
<profile path>`: `is not a string (an api key is a json string); run 'sandfort login'`, or `is empty
(an api key is a non-empty string); run 'sandfort login'`. The value is never echoed. Only an absent
`api_key` field is `not logged in`. `SANDFORT_API_KEY` in the environment takes precedence, so a
damaged profile key matters only when the variable is not set.

Do not put credentials inside the base URL itself (`https://user:password@host`). The login probe
removes the `user:password@` part before it sends any request, and the same part is removed from the
URL saved into the profile. When the login succeeds and the URL you typed carried userinfo, the CLI
prints `note: userinfo was removed from the saved base url (it would replace the api key as a Basic
authorization header)` after the server line. With `--json` the success object has
`"userinfo_removed": true` instead. The note is a text-mode line only. The note belongs to a
successful login only: a failed login prints no note and saves nothing. A URL whose host is empty
after the removal (for example `http://user@` or `http://:80`) is one of those failures: it is
rejected as not valid (`no host`), with nothing sent. The URL echoed in the lines and errors above
hides userinfo, shows query values as `***` (for example `?token=***`) and shows a fragment as
`#***`. The rest of the URL is saved as you entered it: only surrounding whitespace and a trailing
`/` are trimmed, and the scheme is matched case-insensitively and saved in lowercase (`HTTPS://`
becomes `https://`). A secret in the query string or fragment therefore stays on disk. Pass the key
with `--api-key` instead.

Put `exec` options (`--cwd`, `--timeout`, `-i`) before the sandbox reference; everything after it is
the remote command. If the first word of the command is one of those options, `exec` does not run it
as the program. Examples are `exec <sandbox> -t 5 ls`, `exec <sandbox> --cwd=/tmp ls`, and a short
option with digits attached, `-t5`. Instead `exec` ends with a usage error, exit 2. Nothing is sent.
The hint says the option came after the sandbox name and shows the right order. A program whose name
starts with a dash goes after the double dash: `sandfort exec <sandbox> -- -mytool arg`. A
dash-prefixed word that is not exactly one of the exec options (`-tool`, `-input`) is taken as a
program name even without the `--`; only the `--` form is safe when the name could collide with an
option.

`exec` runs an argv, not a shell string: use `sh -c '...'` for pipes, `$VARS` and `&&`. A leading
`--` before the command is accepted. `exec -i` forwards the CLI's stdin to the command; without `-i`
a piped stdin is not sent, and the CLI prints "sandfort: stdin is not forwarded to the command; pass
-i to send it". `-i` accepts UTF-8 text only: binary stdin is refused with "stdin is not valid UTF-8
text". An exec on a stopped sandbox ends with the hint "start it with: sandfort sandbox start
<sandbox>". `sandbox start` takes the same `--wait` and `--wait-timeout SECONDS` options as `sandbox
create`. With `--wait` it blocks until the sandbox is `started`. The timeout is one budget that
covers the start request and the wait together. These cases are rejected as a usage error with exit
2, also under `--json`: a value of 0 or less, a non-finite value such as `nan` or `inf`, a value
that is not a number at all, and `--wait-timeout` without `--wait`. The wording is the same on
`sandbox create` and `sandbox start`. It is `requires --wait` when only the flag is missing. It is
`must be a finite number greater than 0` when only the value is wrong. It is `requires --wait, and
must be a finite number greater than 0` when both are. Without `--wait` the command returns right
after the server answers, as before. On the hosted beta the start reply already says `started`, so
plain `start` and `start --wait` look identical there; `--wait` is there for slower backends.

```bash
sandfort sandbox start cli-first --wait --wait-timeout 60   # returns once the sandbox is started
echo hello | sandfort exec -i cli-first -- sh -c 'tr a-z A-Z'   # HELLO
sandfort cp -r ./project cli-first:/work     # the directory's contents land in /work
sandfort cp -r cli-first:/work ./out         # and back; the target is created if missing
sandfort cmd start cli-first -- sh -c 'sleep 30; echo done'   # prints session and command ids
sandfort cmd logs cli-first <session> <command> --follow      # exits with the command's code
sandfort cmd kill cli-first <session> <command>               # stop a running command
sandfort cmd sessions cli-first                               # list the sessions of the sandbox
sandfort cmd rm-session cli-first <session>                   # delete one and kill its commands
sandfort preview cli-first 8000              # prints a preview URL for the port
sandfort shell cli-first                     # interactive shell
```

`cp -r` extracts the directory's contents into the target path (created if missing), needs `tar` in
the sandbox image, and its archive is subject to the 256 MiB upload cap. `cp` prints the number of
bytes it transferred and the number of files. For `-r` the byte count is the sum of the sizes of the
regular files. It is not the size of the archive, which is gzip-compressed on upload. For one file
the count reads `1 file`, not `1 files`. `cp` without `-r` on a remote directory ends with `<path>
is a directory; use -r for directories`, and a local download target whose parent is a file ends
with `destination <path> is not a directory`. `cmd start` takes `--session S` to reuse a session;
without it a new session is created. Every such session stays until you delete it. List them with
`cmd sessions` and delete one with `cmd rm-session`, which also kills the commands still running in
it. To clean up in one step, run `cmd start --follow --close -- <command>`: it waits for the command,
streams its output, deletes the new session and exits with the command's status. `--close` needs
`--follow` and cannot be combined with `--session`. If the delete fails, the CLI prints a warning on
stderr and keeps the command's status. A followed command that exits 127 because the program is missing gets the same hint line as `exec`. `cmd rm-session` exits 1 with a `NOT_FOUND` message when the session does not exist, like `sandbox rm` for a missing sandbox (125 stays for platform errors). Add `--if-exists` to skip a missing session with a note on stderr (`<session>: not found, skipped`) and exit 0. `volume rm` prints the volume id on one line, like the other `rm` commands; `--json` still prints the volume object. `cp -r` upload skips a symlink whose target is absolute or leaves the uploaded directory, and prints `skipped symlink <name> -> <target> (points outside the copied tree)` on stderr, as the download already did. `shell` and the SDK's `sbx.pty.create()` work on the beta, over
https. A closed terminal can still appear in the PTY list of a sandbox; the per-organization cap of
8 counts live terminals, not the listed ones.

Every command that takes a sandbox (`sandbox get`, `stop`, `start`, `rm`, `exec`, `shell`, the
`<sandbox>:<path>` form of `cp`, and `snapshot create`) accepts either the sandbox id (`sbx_...`) or
its name. `sandbox rm` removes a running sandbox directly; stopping it first is not needed.
`sandbox delete` is an alias of `sandbox rm` (same arguments, options and output); it is hidden from
`--help`. `snapshot delete` and `volume delete` are hidden aliases of `snapshot rm` and `volume rm`
in the same way.

`sandfort sandbox rm REF [REF ...]` deletes the sandboxes in the order given and prints one line per
deleted sandbox with only its id (with `--json`: the sandbox object for one ref, a list of objects
for several). In cleanup scripts, use `--if-exists`: a name with no live sandbox, an id the server
answers with `NOT_FOUND`, or an already-destroyed sandbox is skipped with a note on stderr (`<ref>:
not found, skipped`) and the exit code stays 0. Without the flag, `sandfort sandbox rm <name>` exits
1 with `NOT_FOUND: no sandbox named '<name>'; ...` when the sandbox is already gone. `--if-exists`
still fails (exit 1) on real errors: an ambiguous name, authentication, a network failure or a 5xx.
As a last step, list the sandboxes by label to find a job that was killed before its trap ran:

```bash
trap 'sandfort sandbox rm --if-exists "$NAME"' EXIT
# ... create the sandbox with --label job=<id> and do the work ...
sandfort sandbox list --state started --label job=<id>   # remove any that remain
```

Use the label value exactly as you stored it. A label filter with the raw value still matches:
`--label` sends the value as typed, and the sanitising described in the label round-trip note
(under "Scripting note for CI" above) changes only what the CLI prints. A value copied back from
that output is the one that may differ from the stored one.

#### Machine-readable output and exit codes

With the global `--json` flag, errors are JSON too. They are printed to stdout as:

```json
{"error": {"code": "...", "message": "...", "details": {}, "request_id": "..."}}
```

A sandbox that failed during `create --wait` adds `sandbox_id` and `state` to that object, with the
code `SANDBOX_FAILED`.

Scripts that read the result of `login --json` should read `key_status`; `key_verified` stays only
for compatibility.

The request id of an error that is not from `login` comes from the server's own error envelope
(`error.request_id`, the value of the `x-request-id` header of the same reply). The text line ends
with `(request id <id>)` and the `--json` error object has it as `request_id`. It is `null` when the
CLI never sent the request (`"source": "client"`), when the reply was not a server error envelope (a
proxy or login page, for example), and when the envelope itself held no id. A sandbox name that
matches no live sandbox is the exception to the envelope rule. The miss is found in a list reply,
not in an error envelope. So the error carries the `x-request-id` of the last list reply it looked
through. It appears in the text line and as `request_id` in the `--json` error object. It is `null`
only when that reply sent no id.

Collections in `details` that are cut stay what the server sent. A mapping or list is cut to 50
entries and gets no marker entry inside it, so a script that loops over it sees only real data. The
number of dropped entries is a sibling field: `<key>_beyond_cap` next to a cut value inside
`details` (the same name as `missing_scopes_beyond_cap`), and `details_beyond_cap` in the error
object when `details` itself was cut. The text line has no `_beyond_cap` pair: a cut collection ends
with `and N more` inside its closing bracket (`key=[...; and 3 more]`), and a cut `details` mapping
ends with `and N more` after its pairs. For a list of lists, the `and N more` at the end of the
outer list counts the entries cut from the inner lists. It also counts those cut from the outer one.
This is because a list has no room for a sibling field. The `--json` sibling carries the same total.

A validation error (422, `VALIDATION_ERROR`) keeps its `details.errors` list of `{type, loc, msg}`
entries in `--json`. In the text line the list is written once, as readable pairs after the base
message: `VALIDATION_ERROR: request validation failed: body.resources.disk_gib: <message>; ...`.
Each pair is the location joined by dots, then the message; at most five pairs are shown, then `and
N more`. The server's own message repeats the first pair and ends with `(and N more)`; the CLI drops
that copy, so the first issue is not printed twice. A message that does not repeat the first
location is kept whole, other `details` keys go in parentheses, and a list that does not have the
`{loc, msg}` shape is printed like any other detail. The message of one pair, and the server's own
validation message, are cut at 600 characters in the text line. The cut used to be shorter. So a
message that lists all the allowed values is printed whole. An example is the twelve api key scopes,
about 200 characters. `--json` keeps the list as the server sent it, cut as before.

In the text line, a `details` value that is not a string is written as compact JSON with real
characters: a non-ASCII letter is printed as that letter, not as a `\uXXXX` escape. The strings
are sanitised first. A lone surrogate cannot be written to a terminal, so that one stays an escape.

When `sandbox rm` removes several sandboxes and one of them fails, `--json` prints one document, not
two: `{"error": {...}, "processed": [...]}`, where `processed` holds the refs handled before the
failure (a removed sandbox as its object, a skipped one as `{"ref": "...", "skipped":
"not_found"}`). The key is absent when nothing was processed.

On a `login` key-check failure the top-level `error.code` is always the client wrapper value
`CLI_ERROR`, never the server's own code, so a script must read the server's code from the
`server_code` field of `error.details` (`error.details.server_code`, present only when the server's
error envelope sent a code). A failed status probe (the step before the key check) carries the
same client wrapper code `CLI_ERROR` with empty `details`: there is no server-code field in that
object, so a script must not expect `error.details.server_code` (or any other `details` key) after
a probe failure.

`"source": "client"` is added to that object when no request of the failed step reached the server:
the connection was refused, the request timed out before it was sent, or the CLI rejected the input
before sending anything. The input errors that carry it include a bad base URL, an empty key, the
not-logged-in case, an unreadable or malformed profile, stdin that is not valid UTF-8 for `exec`,
and the missing interactive terminal for `shell`. Such an error has no server request id, so
`request_id` is `null`. Without `"source"`, the server may have received the request. A CLI error
raised on a server reply has no `"source"`. This covers a build log that ends without a final state,
a build the server reports as failed, and a command with no reported result. It also covers an
extract that failed or timed out in the sandbox, and an unsafe archive path. A sandbox name that
matches more than one sandbox is found in the list reply, so it has no `"source"` either. A name
that matches no live sandbox is different under `--json`. This applies to `sandbox get`, `stop`,
`start`, `reset` and `rm`, `exec`, `preview`, `cp`, `shell`, `snapshot create` and `cmd start`,
`logs` and `kill`. The error object has the code `NOT_FOUND`, the same code as a missing id. So a
script branches on one code. It has no `"source"` field, because the name lookup did reach the
server (a list or get call), and `"source": "client"` means that no request of the failed step did.
The exit code does not change. In text mode the line now starts with the prefix `NOT_FOUND:`, like
the line of an id miss. An example is `NOT_FOUND: no sandbox named '<name>'; pass an id (sbx_...) or
the name of an existing sandbox`. Under `--json` the code is the `code` field. So the `message`
carries no prefix and is unchanged. The name you typed is sanitised before it is placed in the
message. An ambiguous name stays `CLI_ERROR`. The text line of a transport error ends with `(request
id <id>)` when the error has one. `--help` of the root command and of every command group explains
the field.

`exec` exits with these codes:

| Exit code | Meaning |
|-----------|---------|
| the command's own | The remote command's exit code is passed through. |
| 124 | The command timed out. |
| 120 | The command's own exit code was 0, but the server had stopped it or cut its output (`stop_reason` set, or `truncated` true). The CLI prints one sentence on stderr that names the reason, for example `sandfort: the command was stopped: output_limit; output truncated`. This is the same test as `ExecResult.ok` in the SDK, so `sandfort exec ... && deploy` no longer goes ahead after a killed job. A non-zero exit code of the command is still passed through as it is. `cmd start --follow` (and `--close`) and `cmd logs --follow` use the same rule. |
| 125 | The platform or the CLI failed before or without running the command: sandbox not found, exec against a stopped sandbox, authentication, bad local input. |
| 137 | A stop, an auto-stop or a resource limit interrupted the command while it ran; the result has `sandbox_stopped: true`. The stderr sentence tells a stop from a limit. A process kill inside a running sandbox (the command's own process is killed, or the OOM killer takes just the process on the `container` tier) also exits 137, but with `sandbox_stopped: false` and `stop_reason` `killed`. |
| 127 | `command not found: <cmd>` or `working directory does not exist: <dir>`. The CLI adds a hint line only when stderr says a command is missing. A program that exits 127 on its own gets no hint. |
| 2 | Usage error (for example no command given, an exec option placed after the sandbox name, or a blank option value). |

`cp` follows the same convention for failures after the request is sent: they exit 125. Errors
the CLI finds on your side before it sends anything exit 2, like usage errors: a blank local or
remote path, a wrong endpoint form (neither or both arguments in the sandbox-path form), a missing
local file, a relative remote path and an unusable local destination. These exited 125 before round
64. A bad `sandbox create --mount` value is a usage error too and exits 2; it exited 1 before round
54.

With `--json`, the `exec` result has an `ok` field (true only for exit code 0 with no `stop_reason`, no timeout and no truncated output). The exit code is 120 in that case too.

On a timeout, without `--json`, the CLI prints `error: command timed out; allow more time with
-t/--timeout SECONDS, which goes before the sandbox reference: sandfort exec -t 60 <sandbox> --
<command>`. It goes to stderr, on its own line, even when the command's stderr did not end with a
newline.

For agents and CI, authenticate with the `SANDFORT_API_KEY` and `SANDFORT_BASE_URL` environment
variables. Do not use the single stored login profile. The CLI reads the environment first and falls
back to the profile. `SANDFORT_API_KEY_FILE` is the file form of the key (see "Command-line (if you
received the CLI wheel)"). A CI job that labels its sandboxes should read the label round-trip note
under "Scripting note for CI". Read it before you read those labels back through the CLI.

`sandbox create` takes these options besides `--snapshot` and `--wait`:

- `--auto-stop` and `--auto-delete`, in minutes. A negative value means never. Auto-delete counts
  from the moment the sandbox stops and runs on a periodic sweep, so the delete happens within about
  a minute of the due time, not instantly.
- `--env` / `-e` and `--label` / `-l`, each in `KEY=VALUE` form and repeatable (a value without `=`
  or with an empty key is a usage error, exit 2). The sandbox receives
  the environment values you pass, but API responses (create, get, list) show only the keys, with
  every value masked as `***`.
- `--cpu-millicores`, `--memory-mib` and `--disk-gib` for sizing; values you leave out take the SDK
  defaults (`Resources()`: `cpu_millicores` 1000, `memory_mib` 512, `disk_gib` 3). The per-sandbox
  maximum on the beta is 4000 millicores, 8192 MiB and 20 GiB (see Quotas).
- `--egress HOST` (repeatable) for the egress allowlist, and `--mount VOLUME_ID:PATH` (repeatable)
  for volumes.
- `--block-network`, which turns off all outbound traffic. The server rejects it together with
  `--egress`.
- `--wait-timeout SECONDS` (a number greater than 0, only together with `--wait`): give up waiting
  after that many seconds. It bounds the blocking create too. On the hosted beta the create request
  itself returns only once the sandbox is started. So the given seconds are one deadline over the
  whole call. The call is the create request, any pause before a resend and the wait for `started`.
  See the SDK notes below. A timeout prints one `error:` line and exits 1. The sandbox may exist
  server-side and keep running (a create that timed out may still finish), so check with `sandbox
  list` and remove it with `sandbox rm`.
- `--keep-on-failure` (with `--wait`): by default a sandbox whose start ends in the `error` state is
  deleted before the error is reported; this flag keeps it for inspection.
- Without `--wait`, `create` prints the sandbox as the server answered. On the hosted beta the
  create request returns only once the sandbox has started or failed, so that answer can already
  be in the `error` state. The CLI then exits 1: it prints `error: sandbox sbx_... is error
  [<error_code>]: <reason>` and a hint, "the sandbox was kept; repeat the create with --wait to
  have it deleted on failure, or delete it with: sandfort sandbox rm sbx_...". With `--json` the
  error object (code `SANDBOX_FAILED`, with `error.hint`) goes to stdout. The sandbox is not
  deleted, so remove it yourself; `create --wait` deletes it for you. In this no-wait path the
  error carries the `x-request-id` of the create reply: the text line ends with
  `(request id <id>)` and the error object's `request_id` holds it. Quote it, with the sandbox id,
  when you report such a failure.

```bash
sandfort sandbox create ci-run --wait --wait-timeout 120 --keep-on-failure
```

`snapshot create SANDBOX NAME --wait` blocks until the snapshot is ready.

**Narrow terminals.** A table keeps one line per row. When the terminal is too narrow, the CLI cuts
free-text cells with an ellipsis and drops whole columns. In `audit list` it drops the actor and
request id columns whole rather than cut an id. When it drops columns, it prints one line on stderr
that names them: `(hidden at this width: <columns>; widen the terminal or use --json)`. `key list`
and `audit list` follow this rule. `--json` always has every field.

**Snapshots and images in the CLI.** `snapshot list` prints a table with the columns ID, NAME, STATE
and IMAGE. A label-scoped key gets `null` for `image_ref` and `digest`. The CLI shows `-` for them.
It does so in the IMAGE column and in the `image_ref` and `digest` fields of a single snapshot. It
also does so in the "build ... ready" line of a build, when neither the digest nor the image
reference is available.

`sandbox list` takes `--state`, a repeatable `--label KEY=VALUE`, `--order asc|desc` and
`--stop-cause`. A bad `--label` pair is a usage error, exit 2. `--order` sorts by creation time.
`desc` is newest first. When you leave it out, the server default applies, which is oldest first.
`--stop-cause` shows only sandboxes that stopped for that cause: `requested`, `auto_stop`,
`container_exited`, `oom_killed` or `unknown`. Any other value is a usage error, exit 2. Giving
`--stop-cause`, `--state` or `--order` more than once is a usage error too (exit 2); on this command
only `--label` repeats. The list hides `destroyed` sandboxes; `--all` or `--state destroyed` shows
them. With the global `--json` flag the sandbox objects carry `created_at` and `updated_at` as ISO
8601 strings. The commands that print one sandbox (`sandbox create`, `get`, `start`, `stop`,
`reset`) list both in their field output when the server reports them. Those commands also print a
`snapshot` row. It holds the snapshot id or image reference the sandbox came from, or `-` when there
is none, and always `-` for a label-scoped key. They also print an `error_code` line when the
sandbox has one. After `error_code` come a `stop_cause` line and a `stopped_at` line (ISO 8601 with
an offset), each present only when the server reports a value (see "Why a sandbox stopped" below); a
`started` sandbox shows neither. The field view also has a `labels` row: every label as `key=value`,
one per line, `-` when there is none. The row is never cut to the table cell width; a long line
folds onto further lines when the terminal is narrow. Each line is sanitised like the table cell, so
a line break inside a label cannot pass for a second label. `--json` objects carry `error_code`,
`stop_cause` and `stopped_at` (`null` when there is none). A failed `create --wait` prints the
failure with the code after the state, for example `sandbox sbx_... is error [image_access_denied]:
...`. The table has the columns ID, NAME, STATE, ISOLATION, CPU (m), MEM (MiB), DISK (GiB), CREATED,
LABELS and REASON. CREATED is the creation time in UTC as `YYYY-MM-DD HH:MM:SS` (blank when the
server reports none). LABELS shows `key=value` pairs and REASON shows the `error_reason` of a
sandbox in the `error` state, written `<error_code>: <error_reason>` when a code is set (the code
alone when there is no reason). When a sandbox has neither an error code nor an error reason, REASON
shows its `stop_cause` instead (empty when there is none either), so a sandbox that was stopped by
the idle timer reads `auto_stop` in the table.

`sandfort exec`, `shell`, `cp` and `cmd` (every command that resolves a sandbox ref) on a sandbox
that is not started print "start it with: sandfort sandbox start <ref>; stopped because: <cause>"
when the server reports the cause. The hint is a second line after the error; with `--json` it is
`error.hint`.

`sandfort key create --help` lists the scope names. In tables, a value longer than 32 characters
ends in an ellipsis. The cut is made at a grapheme boundary (UAX #29). So it never leaves half an
emoji sequence, a base letter without its combining marks, a lone regional indicator, or a conjunct
cut at its virama. A cell can therefore be a few characters shorter than 32.
32. Table cells and the title are shown literally: text such as `[red]x[/red]` or `[/x]`
in a label or a reason is printed as it is and is not read as markup. In LABELS and REASON,
whitespace runs (newlines and tabs) also become one space and other control characters (ESC
among them) are dropped before the cut. With `--json`, `sandbox create --wait` that ends in a failed start prints an error
object with the code `SANDBOX_FAILED`, which carries `sandbox_id`, `state`, `error_reason`,
`error_code` and `deleted`.

## 3. First sandbox in five minutes

This Python walkthrough and the CLI quick start in section 2 are two alternative first paths. You
need only one of them.

Export the key from the secret link as `SANDFORT_API_KEY`, then run the snippets below in order in
one Python session. The later ones reuse `client` and `sbx`.

```python
import os
from sandfort_sdk import Client

client = Client(
    base_url="https://api.sandfort.dev",
    api_key=os.environ["SANDFORT_API_KEY"],
)
# Without snapshot= the image is python:3.12-slim.
# labels= tags the sandbox so you can find it later; auto_delete_minutes= deletes it that many
# minutes after it stopped (auto-delete is off by default).
sbx = client.create_sandbox(
    name="first",
    snapshot="python:3.12-slim",
    labels={"purpose": "walkthrough"},
    auto_delete_minutes=60,
    wait=True,
)
print(sbx.id, sbx.name, sbx.state)                        # sbx_... first started

# A non-zero exit code is returned in the result; it does not raise.
bad = sbx.process_exec(argv=["sh", "-c", "echo oops >&2; exit 3"])
print(bad.exit_code, bad.stderr.strip(), bad.ok)          # 3 oops False
# result.ok is True only for exit code 0 with no stop_reason, no timeout and no truncated output.
# code_run takes the language first, then the code string.
run = sbx.code_run("python", "print(21 * 2)")
print(run.exit_code, run.stdout.strip())                  # 0 42
# File round trip through the fs facade.
sbx.fs.upload_file("/tmp/hello.txt", b"hello\n")
print(sbx.fs.read_bytes("/tmp/hello.txt"))                # b'hello\n'
```

`code_run` starts a fresh process every time, so variables do not survive from one call to the
next. When state has to persist (a data frame, an import, a counter), open a persistent code
context, a Python kernel inside the sandbox:

```python
ctx = sbx.code_contexts.create()
ctx.run("x = 21")
print(ctx.run("x * 2").result)                            # 42
```

Only Python, and the state is lost when the sandbox stops, resets or is deleted. The full
behaviour is in "Code contexts: state that survives between runs" below.

For untrusted or student code, create sandboxes with `block_network=True`.

When you are done, delete the sandbox. Put the work in a `try` block so that a failure still
deletes it:

```python
try:
    print(sbx.code_run("python", "print(21 * 2)").stdout.strip())     # 42
finally:
    sbx.delete()
```

`labels=` lets you list your sandboxes later (`sandfort sandbox list --label purpose=walkthrough`),
and `auto_delete_minutes=` removes one you forgot to delete. Use the two together.

Left out, `auto_stop_minutes` is 15 (idle minutes) and `auto_delete_minutes` is -1, which never
deletes. `auto_delete_minutes` counts minutes after the sandbox stopped, and 0 deletes it at the
next scan after any stop. A stopped sandbox therefore stays, with its files and its disk, until you
delete it. The MCP `create_sandbox` tool takes the same two options (`sandfort-mcp` 0.1.1 or
newer).

### What the default image contains

A sandbox created without a `snapshot` starts from `python:3.12-slim`. It has Python 3.12 and pip,
plus the basic shell tools. It does not have git, curl, Node or build tools (no compiler, no
`make`). A command that needs one exits 127 with `command not found: <name>`, and a git call
answers 409 `CONFLICT` with `error.details.reason` `git_missing` and a message that names the
fix. To get more, pick another image when you create the sandbox: `snapshot="python:3.12"` in
Python, or `sandfort sandbox create -s python:3.12` on the command line. `python:3.12` is the
full Debian-based image and includes git, curl and a C compiler toolchain. For Node use
`node:22-bookworm`.

Every git example in this guide assumes a sandbox like this one:

```python
sbx = client.create_sandbox(name="with-git", snapshot="python:3.12", wait=True)
try:
    sbx.git.clone("https://github.com/octocat/Hello-World.git", "/work/hello")
    print(sbx.git.status("/work/hello").branch)           # master
finally:
    sbx.delete()
```

**Next steps**

- Run code and move files: [running code, output limits and
  files](#running-code-output-limits-and-files).
- Keep data between sandboxes: [volumes](#volumes) and [snapshots](#snapshots).
- Read your usage: [usage report](#usage-report) and [quotas](#quotas).
- Check who did what: the audit items under [REST API](#rest-api) and the `sandfort audit`
  commands under [Beta limits](#5-beta-limits).
- When something fails: [retries and idempotent create](#retries-and-idempotent-create),
  [recovering after `sandbox_stopped`](#recovering-after-sandbox_stopped) and
  [reporting a problem](#reporting-a-problem).

The `snapshot` parameter takes a plain image reference such as `python:3.12-slim`, a snapshot id, or
the name of one of your organization's snapshots (REST: the `snapshot` field of `POST
/v1/sandboxes`). A snapshot name of your organization is used before an image of the same name; a
value that matches no snapshot of yours is treated as an image reference. The outcome is the same as
a create by the snapshot's id: a snapshot that is not `ready` is refused, and so is one outside a
label-scoped key's scope. With the default `wait=True`, an unresolvable reference makes the create
call raise `SandboxFailedError`, and the message carries the reason `no such image or snapshot:
<reference>`. With `wait=False` the call returns a sandbox object that is in the `error` state with
that same reason. `SandboxFailedError` carries `sandbox_id`, `state`, `code == "SANDBOX_FAILED"`,
`error_reason`, `error_code`, `deleted` and `request_id` (the `x-request-id` of the reply that
showed the failed state; quote it in a report; `sandfort sandbox create --json` repeats it as
`error.request_id`). `str(exc)` is the message plus ` [<error_code>]` when the code is set, so a
logged failure keeps its code (placed before a trailing ` (request id ...)`, so `str()` keeps the
request id); the message alone is `exc.message`. When the sandbox is `destroyed` (for example a
create with an `idempotency_key` replayed with `wait` after the sandbox it made was deleted) the SDK
raises the subclass `SandboxDestroyedError`: `state` is `"destroyed"` and `error_code` is `None`
unless the record kept a code from before the delete. `except SandboxFailedError` catches it too.

A sandbox object carries `error_code` next to the free-text `error_reason` (REST field
`error_code`; SDK `SandboxInfo.error_code`, read as `sbx.info.error_code` or `sbx.error_code`, and
`SandboxFailedError.error_code`). It is `null` when there is no error, and for errors recorded
before the field existed. The server picks it from the kind of failure, never from the wording of
`error_reason`, so branch on the code and treat the text as a message for people. The values, and
whether repeating the same call can help. A sandbox in the `error` state is terminal: `start`
answers 409 `INVALID_STATE`, and the only way out is to delete it. So "retry" below means delete
the sandbox and create a new one (with the same arguments where the table says yes, with a changed
reference or access where it says no):

| `error_code` | Meaning | Retry? |
|---|---|---|
| `image_not_found` | The driver did not find the image or snapshot named at create; an image with no variant for the server's CPU architecture also lands here (Docker selects the platform from the manifest list and reports not-found when no entry matches; this is Sandfort's mapping of the daemon's not-found answer, not the registry's own answer) | no, not with the same reference |
| `registry_unreachable` | The network to the image registry failed (resolver, dial, timeout or an EOF), the registry throttled the pull (HTTP 429, for example the Docker Hub pull rate limit) or the registry failed on its side (HTTP 5xx); the image may well exist | yes, after a pause |
| `registry_tls_error` | The TLS connection to the registry failed validation (an untrusted, expired or wrong-name certificate, or a plain-HTTP registry answering an HTTPS request); `error_reason` is a fixed sentence: "could not pull <reference>: the TLS connection to the registry failed validation (an untrusted or wrong certificate, or a plain-HTTP registry); fix the registry trust or configuration" | no, not until the registry trust or configuration changes |
| `image_access_denied` | The registry answered and refused the pull, in any phrasing (`unauthorized`, `denied:`, a bare `denied`, a 401 or 403 status such as containerd's `403 Forbidden`, "no basic auth credentials"); `error_reason` is a fixed sentence on every path: "the registry refused to pull <reference>; check the image name and the registry access" | no, not until the reference or the access changes |
| `invalid_image_reference` | The image reference cannot be parsed ("invalid reference format"); `error_reason` is a fixed sentence: "invalid image reference <reference>", followed by ": invalid reference format" when the daemon said so | no, fix the name |
| `start_failed` | Any other driver error while creating or starting the sandbox | inspect `error_reason`; if it gives no cause, send the `request_id` |
| `timeout` | A driver operation ran past its deadline | yes |
| `reset_failed` | The driver failed during a reset, after the old container was removed; the sandbox is in `error` | delete it and create a new one; what was written to the old container is gone, named volumes are kept; if it repeats, send the `request_id` |
| `container_missing` | The reconciler found the container of a started sandbox gone, or present but never started; the sandbox is in `error` | delete it and create a new one; treat the old container's files as lost; if it repeats, send the `request_id` |
| `container_exited` | The reconciler found the container exited; the sandbox is `stopped` (not `error`) with this code and a reason, and can be started again | `start` it again (a successful start clears the code); if it stops again, lower its memory or process use |
| `node_lost` | Reserved for a lost node; no code path sets it yet | not applicable today; if it ever appears, delete the sandbox, create a new one and send the `request_id` |
| `internal` | Anything else: a failure the server does not classify; the detail is in the server log | once after a pause, with a new sandbox; if it repeats, send the `request_id` |

The four image codes (`registry_unreachable`, `registry_tls_error`, `image_access_denied`,
`invalid_image_reference`) are chosen from the kind of failure the driver reports, never from the daemon's text. The
daemon's "pull access denied ... may require 'docker login'" sentence is still `image_not_found` (so a private Docker Hub repository and a missing one look the same), unless a registry follows it with its own specific `denied: <message>`; then it is `image_access_denied`. A registry that answered 401 or 403 is `image_access_denied` even when its message mentions a certificate, a throttle, a 503 or network words such as `dial tcp: lookup backend.invalid: no such host` (the answered body is the registry's data; only a transport failure the daemon itself reports, before the registry's answer text, is `registry_unreachable`); `registry_tls_error` is for a TLS handshake or certificate validation that failed before the registry answered.
For `registry_tls_error`, `image_access_denied` and `invalid_image_reference` the `error_reason`
is a fixed sentence built from the reference you supplied, on every path that pulls (sandbox create, reset, snapshot
register); the daemon's own text, which can name the host's identity, goes to the server log and
is not returned. A pull failure that matches none of the classes keeps its error type, and its
`error_reason` is always "could not pull <reference>", never the daemon's text. Any other runtime
error that the server does not classify carries one fixed sentence as the `error_reason` of the
sandbox and as the `message` of a 502 `DRIVER_ERROR` answer:
"the sandbox runtime reported an error; the details are in the server log". Two more fixed
sentences cover the other kinds of runtime failure: "the object does not exist" for a not-found
failure and "the operation conflicts with the current state" for a conflict. A not-found or
conflict answer carries the runtime's own wording only when it is a short phrase that names an
object you supplied, such as "No such container: <name>" or "<name> is not running"; any other
wording is replaced by the matching fixed sentence. The same fixed sentences
apply to every sandbox operation, not only to image pulls. The detail is written to the server log only, and you
cannot read it. When you report such an error, send the `request_id` of the answer (see above)
to support: the request_id is what support needs, because the operator finds the server-side detail by that id. An image build
follows the same rule for its base image (see Data analysis). A reference that merely contains a word such as
"forbidden" is not taken for a refusal: the pull failure is classified from the registry's answer,
not from the name. The SDK's `ErrorCode` type and `is_known_error_code()` list all twelve codes,
these four included.

**Older SDK clients and `registry_tls_error`.** An older client is unaffected by the new code.
`SandboxInfo.error_code`, `Sandbox.error_code` and `SandboxFailedError.error_code` are deliberately
`str | None`, not the `ErrorCode` Literal, so a client from before `registry_tls_error` (0.1.0b70
and earlier betas) receives it as a plain string. Nothing fails to parse, `is_known_error_code()`
returns `False` on that client, and code that branches on the constants falls through to its
default branch. Upgrading the SDK adds the constant and the Literal member; no other change is
needed.

A successful start clears `error_code` together with `error_reason`. The sandbox events carry
`error_code` next to `reason` in their payload. The spec file `openapi/sandfort.v1.json` (a
repository path, not a site URL) lists `error_code` and `snapshot` in the sandbox response.

**Why a sandbox stopped.** A sandbox object carries two more nullable fields, `stop_cause` and
`stopped_at` (REST fields of the same names; SDK `SandboxInfo.stop_cause` and
`SandboxInfo.stopped_at`, also read as `sbx.stop_cause` and `sbx.stopped_at`). `stopped_at` is the
time the sandbox stopped, UTC in ISO 8601 with an offset (a `datetime` in the SDK); it is `null`
unless the state is `stopped`. `stop_cause` is a string, `null` unless the state is `stopping` or
`stopped`:

| `stop_cause` | Meaning | What to do |
|---|---|---|
| `requested` | A user or API key asked for the stop. | Nothing; start the sandbox when you want it back. |
| `auto_stop` | The idle timer stopped it after `auto_stop_minutes` without activity. | Start it again; raise `auto_stop_minutes` (or set a negative value) if the stop was unwanted. |
| `container_exited` | The reconciler found the container exited (a resource limit or the main process ending); `error_code` is `container_exited` as well. | Start it again; if it exits repeatedly, lower its memory or process use. |
| `oom_killed` | The container was killed for exceeding its memory limit and exited with code 137, as the Docker daemon records it. Set on the `container` and `gvisor` tiers, while `microvm` reads `container_exited`. | Resize the stopped sandbox to more memory before starting it. |
| `unknown` | The sandbox is `stopping` or `stopped` with no recorded cause, for example a stop recorded before the field existed. | Starting it is safe; the cause cannot be recovered. |

The rules are these. A successful start clears the cause. A second stop request never overwrites it.
A stop on a `stopped` sandbox returns it unchanged. A stop on a `stopping` one answers 409
`INVALID_STATE`. Only three paths set a cause today: a stop request, the idle timer and the
reconciler. A reset, a lost node, an operator action and a quota never set a cause. The audit rows
`sandbox.stop`, `sandbox.auto_stopped` and `sandbox.drift_detected` (with `stopped_unexpectedly`)
carry it in `details.stop_cause`, and the `sandbox.stopped` webhook payload carries it as
`stop_cause` next to `reason` and `error_code`; the other sandbox events carry the key with `null`.
Against a server that does not report the fields, the SDK gives `None` for both.

A lifecycle request has two 409 answers. `INVALID_STATE` means the sandbox's current state does
not allow the call (`details.state` names it): read the state, then move the sandbox to one that
does. `CONFLICT` with `details.reason` `concurrent_update` and the message "sandbox <id> was
modified concurrently" means a concurrent lifecycle request changed the same sandbox first: refresh
the sandbox (fetch it again) and retry the call once.

The SDK keeps `stop_cause` a plain `str | None`, so a cause that a newer server adds does not break
an older SDK. Branch on the constants, exported from `sandfort_sdk`: `SANDBOX_STOP_CAUSE_REQUESTED`,
`SANDBOX_STOP_CAUSE_AUTO_STOP`, `SANDBOX_STOP_CAUSE_CONTAINER_EXITED`,
`SANDBOX_STOP_CAUSE_OOM_KILLED` and `SANDBOX_STOP_CAUSE_UNKNOWN`. The type `StopCause` (a `Literal`
of the five values) and `is_known_stop_cause(value)`, a guard that narrows the string to
`StopCause` for a type checker, are exported too. The constants are not named `STOP_*`, which
would clash with the exec `STOP_REASON_*` constants.

To list the sandboxes that stopped for one cause, filter on the server. `GET
/v1/sandboxes?stop_cause=container_exited` takes one value: `requested`, `auto_stop`,
`container_exited`, `oom_killed` or `unknown`. Any other value answers 422. A `stop_cause` parameter
given more than once also answers 422, with "must be given once". The filter combines with `state`,
`label`, `order` and `cursor`. A sandbox that shows no cause (a started or destroyed one) matches
none of them. `sandfort sandbox list --stop-cause <value>` and the SDK's
`list_sandboxes(stop_cause=...)` pass the same server filter: one value, one of the five above. To
see whether one sandbox keeps exiting, list its `sandbox.drift_detected` audit rows by target id
(needs `audit:read` and an org-wide key): `GET
/v1/audit-events?action=sandbox.drift_detected&target_id=<sandbox id>`. The reconciler also writes
that event for a container that is gone or was never started, so filter the rows on
`details.stop_cause` equal to `container_exited`. Several such rows for the same sandbox mean repeat
container exits; alert when that happens, and lower the sandbox's memory or process use.

A stopping or stopped sandbox also shows its cause when a toolbox call fails: exec, code-run,
sessions, fs, git, PTY create and code contexts answer 409 `CONFLICT` with `error.details.reason`
`no_container`, `details.state`, and `details.stop_cause`. The sandbox logs route sends
`details.state` only. The value is the one the API shows on the sandbox: `unknown` when the
sandbox is stopping or stopped and its stored cause is missing; the key is absent for a deleted
sandbox. A concurrent-update 409 (`concurrent_update`) also carries `details.expected_version`,
the version the caller's write expected.

```python
from sandfort_sdk import SANDBOX_STOP_CAUSE_AUTO_STOP, SANDBOX_STOP_CAUSE_CONTAINER_EXITED

sbx.refresh()
if sbx.state == "stopped" and sbx.stop_cause in (
    SANDBOX_STOP_CAUSE_AUTO_STOP,
    SANDBOX_STOP_CAUSE_CONTAINER_EXITED,
):
    sbx.start()          # idle stop or a died container: bring it back with its files
```

With the default `delete_on_failure=True`
the client deletes the sandbox before it raises (`deleted` is true and the message says so), so a
failed create leaves no live `error` row and its name can be reused right away. Pass
`delete_on_failure=False` to keep the sandbox for inspection: it then stays in state `error` until
you delete it, and `sandbox_id` tells you which one. The sandbox is kept too when the delete itself
fails (`deleted` is false). The option applies to the `error` state only; after a
`SandboxTimeoutError` the sandbox exists and is yours to delete. With `wait=False` the call returns
before any of this and nothing is deleted. Because nothing is deleted, `wait=False` can leave a
sandbox in `error` for you to delete (on the hosted beta the create request itself returns only
once the sandbox has started or failed, so the returned object can already be in `error`; check
`sbx.state`). If the wait for `started` runs
out, `create_sandbox` raises `SandboxTimeoutError`, which carries `sandbox_id` and `state` (the last
state seen); the sandbox exists on the server, so delete it if you do not want it. The sandbox host pulls an image
it has not used before, so the first create can take longer than later ones. Session commands keep
the working directory between commands; environment variable assignments do not persist, so export
what you need per command.

The sandbox object is a handle: `sbx.refresh()`, `sbx.stop()`, `sbx.start()` and `sbx.delete()`
update the same object in place. `sbx.name`, `sbx.error_reason`, `sbx.error_code`,
`sbx.stop_cause` and `sbx.stopped_at` are available directly next to `sbx.id` and `sbx.state`.

With the async client, `AsyncClient.create_sandbox(..., delete_on_cancel=True)` (the default) keeps
a cancelled create from leaking a sandbox. If the awaiting task is cancelled during the create
request or during the wait for `started`, the sandbox is deleted in the background (best effort: a
failed delete is logged, and `CancelledError` is still raised). `aclose()`, or leaving `async with`,
waits up to 10 s for those deletes. Pass `delete_on_cancel=False` to keep the sandbox; a create that
was cancelled mid-request then cannot report its id.

The cleanup is guaranteed only when the client is closed: use `async with AsyncClient(...)` or call
`await client.aclose()`. A bare `asyncio.run(...)` that never closes the client can still leak a
cancelled create. On the hosted beta the create request itself returns only when the sandbox is
started. `create_sandbox(wait=True)` (sync and async) honours `wait_timeout_s` even then, as one
deadline over the whole blocking create. The deadline starts just before the create request is sent
and covers the POST, the pauses before a resend (for example after a 429 `RATE_LIMITED`) and the
wait for `started`. The POST gets the time left as its timeout; a pause that would pass the deadline
is not taken (the error is raised instead), and the wait for `started` long-polls only for the time
that is left. When the POST runs out of time, `SandboxTimeoutError` says one of two things. The
first is that the cleanup below deleted the sandbox: "the sandbox it made (sbx_...) was deleted, so
nothing is left behind". Then `sandbox_id` carries the id and `SandboxTimeoutError.deleted` is
`True`. The second is that the create may still finish on the server. Then `deleted` is `False`.
Resend the same call with the same `idempotency_key` to get the sandbox. Branch on `deleted`, not on
the message text. With the global `--json` flag the CLI prints the same two facts in
`error.details`: `sandbox_id` (when known) and `deleted`. `wait=False` has no such bound.

The cleanup after a create timeout deletes only a sandbox this call made. It applies with
`wait=True`, `delete_on_failure` and a `name`: the client looks the name up once before the POST
(that lookup does not count against `wait_timeout_s`). After a POST that timed out once it was sent,
it makes one attempt to delete the sandbox found under the name. A failure of this attempt is
logged. It does this only when the name was free before the call. It also needs that sandbox's
`created_at` to be no earlier than just before the POST, less 60 s of clock skew. A name that
already belonged to a live sandbox (an earlier attempt, another process), an older sandbox, or one
without `created_at` is left alone, and a warning names its id (for a sandbox without `created_at`
the warning also says how to delete it manually). Sandbox objects carry `created_at` and
`updated_at` (UTC, ISO 8601 with an offset): `created_at` never changes, and `updated_at` moves
forward when the record changes, for example on a state change. The cleanup relies on `created_at`;
against a server that reports none it leaves the sandbox alone. The Python SDK exposes `created_at`
and `updated_at` on the sandbox handle (`sbx.created_at`, `sbx.updated_at`) and on `SandboxInfo`
(`sbx.info.created_at`, `sbx.info.updated_at`). A sandbox object records where it came from in
`snapshot`: the snapshot id (`snap_...`) or the image reference given at create. A snapshot name of
your organization is stored as its id; an image reference is stored as given. It is `null` when the
create named no snapshot, and for sandboxes created before the field existed. It is set at create
and does not change. It is also `null` for a label-scoped key (one created with `sandbox_labels`),
because the source may be a snapshot outside that key's scope; a key without labels sees the value.
The SDK reads it as `SandboxInfo.snapshot` (and `sbx.snapshot`). The command-line tool shows it as a
`snapshot` row in the field output of the single-sandbox commands (`-` when there is none); the
`sandbox list` table does not show it, and `--json` carries it. The cleanup is one best-effort
attempt, so `idempotency_key` remains the strongest guarantee: resend the same call with the same
key and you get the same sandbox, whatever happened to the first request. When the timeout came
before the request left the client (`RequestTimedOut.request_sent` is `False`), the server never saw
the request and nothing is deleted. To bound the whole call with your own deadline instead, wrap it
in `asyncio.wait_for(...)` (the cleanup works with it):

```python
import asyncio, os
from sandfort_sdk import AsyncClient

async def main() -> None:
    async with AsyncClient(base_url="https://api.sandfort.dev",
                           api_key=os.environ["SANDFORT_API_KEY"]) as client:
        sbx = await asyncio.wait_for(client.create_sandbox(name="bounded"), timeout=60)
        await sbx.delete()

asyncio.run(main())
```

### Retries and idempotent create

`Client` and `AsyncClient` take `max_retries` (default 2, `0` turns retries off). The client resends
a request on its own only when repeating it is safe: `GET`, `HEAD`, `DELETE`, or a `POST` that
carries an `Idempotency-Key` header. One exception: a 429 with the code `RATE_LIMITED` is resent
for every method, including a `POST` without a key, `PUT` and `PATCH` (uploads), because the
server refused that request before it did any work. The exception has a limit: the body must be
sendable again (JSON, bytes, or none). An upload from a file object is a one-shot stream, so it
is not resent after `RATE_LIMITED` and `RateLimited` is raised at once.

- On 429 it waits `Retry-After` (at most 30 s), then resends. `Retry-After` may be a number of
  seconds or an HTTP-date; an unusable value counts as 1 s.
- A 429 with the code `QUOTA_EXCEEDED` is never resent: a quota or a per-key sandbox cap does not
  free itself. `QuotaExceeded` is raised at once; `RATE_LIMITED` is the code that is retried.
- On 503, or a connection or timeout error before any response, it waits with jitter. The delay
  doubles from 0.5 s: 0.5 s, 1 s, 2 s and so on, at most 8 s. Each pause is a random time between
  half of that delay and all of it. So many clients do not retry at the same moment. Then it
  resends. The SDK uses this backoff for every 503. If the answer carries a `Retry-After` (seconds
  or an HTTP-date), the SDK honours it: it waits at least that long, at most 30 s, or the backoff
  pause when that is longer. A 503 without the header waits the backoff alone. A 503 with the code
  `CAPACITY` means there is no room right now. For example, the host has no capacity for the
  reservation. It carries `Retry-After: 5`. So a resent call waits about 5 s before the next
  attempt, not the 0.25 to 1 s of the backoff. `retry_after_s` on the exception is 5. The
  per-organization cap on live terminals is also a 503 `CAPACITY`, with `Retry-After: 30`: a slot
  frees only when a terminal closes. If a call is still refused after the retries, wait longer
  yourself, for example `time.sleep(exc.retry_after_s)` before the next call: capacity frees up only
  when sandboxes stop or are deleted (or, for terminals, close). This applies to calls the SDK
  resends; a call that is not safe to repeat (see below) is not resent after a 503.
- A `POST` that carries an `Idempotency-Key` is also resent on a 409 whose `details.reason` is
  `in_progress` (the first create with that key is still running). Without a key a 409 is never
  resent.
- It never resends any other answer. It never resends a `POST` without a key, or a `PUT` or `PATCH`,
  after a 503, a connection error or a 409. Uploads are an example. Only the `RATE_LIMITED` 429
  above is resent for them. It never resends a file-object upload after any answer. It never resends
  a stream, such as a log follow or a download. After the last attempt the original error
  (`RateLimited`, `TransportError`, ...) is raised as it is.

Errors the SDK raises. Every one derives from `SandfortSDKError`, so `except SandfortSDKError`
catches everything the SDK raises on purpose (a bad argument, such as the `ValueError` below, is
not one of them). The typed exceptions you are most likely to branch on:

- `IdempotencyMismatch` (a `ValidationFailed`, code `IDEMPOTENCY_MISMATCH`): an `idempotency_key`
  was reused with other arguments (422).
- `ServiceUnavailable` (code `NODE_UNAVAILABLE` by default): any 503, for example the node that
  owns the sandbox cannot serve now; `CapacityExceeded` is its subclass for `CAPACITY`. Both
  carry `retry_after_s` (1 if the server sent no `Retry-After`).
- `RateLimited` (429 `RATE_LIMITED`, with `retry_after_s`) and `QuotaExceeded` (429
  `QUOTA_EXCEEDED`, never retried).
- `Conflict` (409) has two typed subclasses, chosen by `error.details.reason`: `NameTaken`
  (`name_taken`: a sandbox with that name exists) and `NoContainer` (`no_container`: the sandbox
  is stopped or deleted; its `state` attribute holds `details.state`, or `None`). `except
  Conflict` catches both, and any other 409 stays a plain `Conflict`.
- `NotFound`, `InvalidState`, `Unprocessable`, and the rest of the `ApiError`
  family for the other statuses; `SandboxTimeoutError` and `SandboxFailedError` for a create that
  runs out of time or ends in `error`.

`Sandbox`, `AsyncSandbox` and the code-context handles are context managers: leaving a
`with` (or `async with`) block on a sandbox deletes the sandbox, and leaving it on a code context
deletes its kernel. A sandbox or context that is already gone is ignored; another delete error
is raised, unless an exception is already propagating out of the block (then it is logged, so it
does not mask the original error).

```python
with client.create_sandbox(name="job-42", idempotency_key="job-42-create") as sbx:
    print(sbx.code_run("python", "print(21 * 2)").stdout.strip())     # 42
# the sandbox is deleted here
```

`create_sandbox(..., idempotency_key="job-42-create")` sends the key as `Idempotency-Key`, which
makes the create safe to resend: the same key with the same arguments returns the same sandbox
instead of a second one, and the same key with other arguments answers 422
`IDEMPOTENCY_MISMATCH`. Without a key a create is never resent, so a lost connection during
create can leave a sandbox you do not know about; use a key in agent loops.

The replay window is one day: the server keeps the first response of a key for 24 hours after it
was stored. Inside the window a replay answers the stored status code (for example 201) with the
sandbox's current representation, not the stored body, and carries the `Idempotent-Replayed:
true` header. A sandbox that was deleted in the meantime therefore replays as state `destroyed`,
not as `started`; if its row no longer exists, the stored body is replayed unchanged. After 24
hours the key is forgotten, and the same key sends a create that makes a new sandbox. Keys belong
to the API key that sent them. Only a create that succeeded stores a response.

```python
client = Client(base_url="https://api.sandfort.dev",
                api_key=os.environ["SANDFORT_API_KEY"], max_retries=3)
sbx = client.create_sandbox(name="job-42", idempotency_key="job-42-create")
```

Environment variables you pass at create are given to the sandbox, but API responses
(create, get, list) show only the keys, with every value masked as `***`.

Request validation errors name the problem in the message, for example
`request validation failed: body.language: Input should be 'python', 'javascript', 'typescript'
or 'bash'`. A body that is not valid JSON answers 422 with the message `request body is not valid
JSON` and the location `["body"]` (no character offset). A field the API does not know answers
422 and names the field.

#### Idempotent exec

Creates are not the only calls that take an `Idempotency-Key`. The exec route,
`POST /v1/sandboxes/{id}/toolbox/process/execute`, takes it too, so a client that lost the
answer can send the same exec again without running the command a second time. The SDK takes
`idempotency_key=` on exec and the CLI has `exec --idempotency-key`; in a REST call set the header:

```bash
curl -s -X POST "$SANDFORT_BASE_URL/v1/sandboxes/$SBX/toolbox/process/execute" \
  -H "Authorization: Bearer $SANDFORT_API_KEY" -H "Content-Type: application/json" \
  -H "Idempotency-Key: build-42-step-3" \
  -d '{"argv": ["make", "build"], "timeout_s": 300}'
```

The rules, from the server code:

- The key is 1 to 255 characters; any other length answers 422.
- It belongs to the API key and to the sandbox. Another API key, or another sandbox, with the
  same text neither replays the answer nor collides with it.
- The first answer is kept for one day (24 hours). A repeat with the same key and the same JSON
  body (key order and spaces do not matter) inside that time returns the first answer, with
  the same status code, and carries the header `Idempotent-Replayed: true`. The command does
  not run again. The replay is audited as `sandbox.exec.replay`.
- The same key with another body answers 422 `IDEMPOTENCY_MISMATCH`.
- A repeat that arrives while the first call still runs answers 409 `CONFLICT` with
  `error.details.reason` `in_progress`. Wait and send it again.
- A replay needs the sandbox started, as a first run does. A stopped or deleted sandbox
  answers its normal error before any key is looked at. After a reset, or after a stop and a
  new start, the same key runs the command again.
- Only an answer is kept: an error response keeps nothing, so the same key can be sent again.
- An answer is kept in full only when it is not `truncated` and stdout plus stderr together are
  at most 256 KiB. For a larger one only a marker is kept: the key stays used and the command
  does not run again, but a repeat answers 409 `IDEMPOTENCY_RESULT_UNAVAILABLE` ("this command
  already ran; its output was too large to keep for replay; use a new Idempotency-Key to run it
  again"). Use a new key if you want to run it again, and write big output to a file.
- A result cut short because the sandbox was stopped, auto-stopped, deleted or reset while the
  command ran (`stop_reason` `sandbox_stopped`, `sandbox_deleted` or `sandbox_reset`) is not
  kept, and neither is one where the client disconnected. The key is released, so a repeat runs
  the command again. A death under a resource limit that the sandbox row does not explain
  (the sandbox still reads `started`) is kept like any other answer.
- If the server restarts after the command finished and before the answer was stored, a repeat
  can run the command again.

A grader can use this to run a grade once per submission, even if its own retry loop sends the call
twice. Build the key from the submission, for example `f"grade-{submission_id}"`, or from a hash of
the submission id when the id is long or has odd characters (a key is 1 to 255 characters). Do not
use one fixed key such as `"grade"`. In a sandbox that you do not reset between submissions, a fixed
key replays the first submission's grade for every later one. A command that exits non-zero is
still an answer, so a failed grade is kept and replayed with its exit code like a passing one. The
repeat does not run the tests again.

```python
result = sbx.process_exec(
    argv=["python", "/work/run_tests.py"],
    timeout_s=60,
    idempotency_key=f"grade-{submission_id}",
)
passed = result.ok
```

#### Out of memory

A command that goes over the sandbox's memory limit is killed with SIGKILL and exits 137, and it
usually prints nothing. What else happens depends on the isolation tier (see "Choosing an isolation tier"):

- `container`: only the process that went over is killed. The sandbox stays `started`;
  `sandbox_stopped` is false and `stop_reason` is `killed`.
- `gvisor`: usually the whole sandbox stops. The result has `sandbox_stopped` true, the stderr
  sentence says the sandbox exceeded its memory or process limit, and the sandbox is `stopped`
  with an `error_reason` and its files kept; `start()` brings it back. Sometimes only the
  process is killed (exit 137, empty stderr, sandbox still `started`).
- `microvm`: the guest kernel kills the process. Exit 137, empty stderr, the sandbox keeps
  running, `sandbox_stopped` is false and `stop_reason` is `killed`. A single huge allocation
  can fail with `MemoryError` (exit 1) instead.

Check `sandbox_stopped` and `stop_reason` after every exit 137; `killed` also covers a program
that kills itself, so it does not prove an out-of-memory kill. The sandbox's `stop_cause`
value `oom_killed` is set when the container died of it on the `container` and `gvisor` tiers (not on `microvm`). To fix
it, lower the program's memory use, or stop the sandbox, resize it to more memory and start it
(see "Quotas" for the limits; the files in the root filesystem are kept across the resize).

### Running code, output limits and files

`code_run` accepts the languages `python`, `javascript`, `typescript` and `bash`. Each call is a
fresh process: files written in the sandbox persist between calls, variables do not. To keep
variables, imports and loaded data between runs, use a Python code context (`sbx.code_contexts`,
see "Data analysis").

`javascript` and `typescript` are accepted but need Node in the sandbox image. The default
`python:3.12-slim` image has no Node, so there they exit 127 with `command not found: node`
(`javascript`) or `command not found: npx` (`typescript`). To run them, create the sandbox from an
image that includes Node, for example `node:22-bookworm`. `python` and `bash` work on the default
image.

Command output is capped at 1 MiB (1,048,576 bytes) per call. When a command's output reaches the
cap, the command is stopped, the result has `truncated=True`, and stderr says "the command was
stopped because its output exceeded the limit of 1048576 bytes". A process killed for exceeding the
sandbox memory limit exits with code 137 and usually prints nothing.

Exec results include `sandbox_stopped` (the REST field of that name; `ExecResult.sandbox_stopped` in
the Python SDK). It is true when the command's sandbox stopped, which is what a limit overrun on the
`gvisor` tier does, and what a fork bomb can do on `microvm`. Use it instead of re-reading the
sandbox state right after an exit code 137. In text mode the CLI prints the remote stderr sentence
and then its own hint, "sandfort: the sandbox has stopped; start it again with: sandfort sandbox
start <sandbox>", on a separate line, also when the remote stderr did not end with a newline. The
exit code stays 137.

Exec results also carry `stop_reason` (`ExecResult.stop_reason` in the Python SDK; `None` on older
servers that omit it). It says why the server stopped the command, and it is `null` for a normal
exit. The values are `timeout`, `output_limit`, `sandbox_stopped`, `sandbox_deleted`,
`sandbox_reset` and `killed`; code-context runs add `queue_timeout` and `context_lost` (see "Code
contexts: state that survives between runs"). `sandbox_stopped` stays true for `sandbox_deleted` and
`sandbox_reset`, so branch on `stop_reason`, not on the flag alone. `timeout`, `output_limit`,
`sandbox_stopped` and `killed` come from the result flags only, never from the output text; when
several apply, the first in that order is used. `sandbox_stopped` means the sandbox stopped under
the command. A stop by the caller or by auto-stop and a death by a limit share the reason. The limit
is memory or process count. Tell them apart in three ways. One is the stderr sentence. Another is
the sandbox row, where `error_code` is null after a stop and `container_exited` after a death. The
last is the audit log. It has `sandbox.stop` recorded for the key that stopped it, and
`sandbox.drift_detected` with outcome `error` for a death. `sandbox_deleted` and `sandbox_reset`
refine it: another caller deleted or reset the sandbox while the command ran. The server decides
them from the sandbox record, `exit_code` stays 137 and `sandbox_stopped` stays true, and stderr
then reads "the sandbox was deleted while running this command" or "the sandbox was reset while
running this command". After `sandbox_reset`, repeat the command on the fresh sandbox if you still
want it; after `sandbox_deleted` there is nothing to recover, and the audit log shows who did it.
`killed` means the process exited 137 (SIGKILL) without any of the other reasons: an out-of-memory
kill inside the sandbox, or user code killing itself, not necessarily a sandbox-initiated kill. A
command stopped at `timeout_s` also prints `the command was stopped after N s (timeout); allow more
time, up to 3600 s` on stderr (exit 124). The sentence is on its own line (a newline comes first
when the command's stderr did not end with one) and names no parameter, because the setting is
`timeout_s` in the SDK and REST and `-t/--timeout` in the CLI. The SDK sandbox handle exposes
`sbx.auto_stop_minutes` and `sbx.auto_delete_minutes`. For a ready-made mapping from `stop_reason`
and exit codes to messages for a student-facing "Run code" button, see "A student-facing Run code
button" below.

`code_run` runs in the sandbox's working directory, so relative file paths in the code see your
files and relative writes persist. An optional `cwd` (`sbx.code_run(..., cwd="/work")` or
`sbx.process.code_run(..., cwd="/work")`) overrides the directory. The script itself lives in a
private per-run directory under `/tmp` that is removed after the run. A Python traceback names the
short script `main.py` (`File "main.py", line 3`), not that directory, and the offending source line
is still printed. `__file__` stays the real absolute path, but the repr of the `__main__` module
reads `<module '__main__' from 'main.py'>`, so a pickle error such as "Can't get attribute 'M' on
<module '__main__' ...>" does not show the directory. For the other languages a traceback shows
an absolute path ending in `main.js`, `main.ts` or `main.sh`; the file name is stable and the
directory is not. There is no stdin for `code_run`, so `input()` does not wait for input.

#### Recovering after `sandbox_stopped`

When a response has `sandbox_stopped` true, the sandbox state is already `stopped`: the server
settles it before it answers. Calling `start()` right away is safe, and the exec after it works; no
polling is needed. `start()` works once the sandbox shows `stopped`. It also starts a sandbox whose
container died while its record still said `started`. This is the one place that says which call
to use; the Run code button and grader sections refer back here:

- **`start()` alone** when the files may stay: the sandbox comes back with its files. This is
  also how you bring back an auto-stopped sandbox. Use it for a student session, an interactive
  agent, or any sandbox whose files you want to keep.
- **`reset()` and then `start()`** when the files must be clean, as for a grader or eval harness
  that reuses a worker sandbox. Reset clears the files and processes the submission left behind
  (see Resetting a sandbox; about 0.4 s on the beta) and works from `started` and from
  `stopped`, but it leaves a stopped sandbox `stopped`, so start it afterwards. Reset also
  removes the grader's own files, so upload them again.

A sandbox that dies right after a reset (for example a fork bomb in the fresh container) is
settled at once and shows `stopped`; the reconciler's 60 s reset window applies only to the
container the reset replaced. When a sandbox dies before or at the deadline, the result is exit 137 with
`sandbox_stopped` true, not a timeout (124). `timeout_s` is a budget, not an exact cutoff: a
command returns within about 0.2-1.5 s of `timeout_s`, and the kill takes longer on `gvisor`. The
classic bash fork bomb `:(){ :|:& };:` usually returns exit 0 within about 1 s on `gvisor` and
`microvm`, and the NEXT exec reports `sandbox_stopped` (after up to about 5 s on `microvm`).

```python
res = sbx.process_exec(argv=["python", "-c", "..."])
if res.stop_reason == "sandbox_stopped":     # not sandbox_deleted / sandbox_reset (see above)
    sbx.start(wait=True, wait_timeout_s=60)   # state is already stopped; files are kept
    print(sbx.process_exec(argv=["echo", "alive"]).exit_code)   # 0
    # Files must be clean (grader)? Call sbx.reset() before sbx.start(), then upload
    # the grader's files again.
```

To restart by id and block until the sandbox reports `started`, call
`client.start(sandbox_id, wait=True, wait_timeout_s=60)` (`AsyncClient.start` takes the same
arguments). `wait_timeout_s` is one budget for the start request and the wait together, and must be
a finite number greater than 0. A start that exceeds the budget raises `SandboxTimeoutError`; when
the start request itself timed out, its `state` is `None`, and the start may still finish on the
server, so poll `client.get(sandbox_id)` if you need certainty. The handle works the same way:
`sbx.start(wait=True, wait_timeout_s=...)` forwards to the client's `start` with the same budget
and errors.

`upload_file` and `move` need the destination folder to exist. Create it first with `fs.mkdir`,
which creates parent folders as well; otherwise the error says `no such directory: <dir>; create it
first`. An upload onto a path that is already a directory answers 409 Conflict, "is a directory:
<path>; upload to a file path inside it", on every tier. `download_dir` returns a tar archive stream. A single `upload_file` is capped at
268435456 bytes (256 MiB); a larger upload answers 413 `PAYLOAD_TOO_LARGE` before the request body
is read, with a message such as `upload limit is 256 MiB (268435456 bytes); this upload is N bytes`
and `details` holding `limit_bytes` and `size_bytes`. The Python SDK raises `PayloadTooLarge` before
it sends anything. Split the file, or fetch it from inside the sandbox.

```python
sbx.fs.mkdir("/tmp/data/in")
sbx.fs.upload_file("/tmp/data/in/a.txt", b"a\n")
```

To reattach to an existing sandbox from another process, fetch it with `client.get(ref)` rather than
keeping the object around. `ref` is an id (`sbx_...`) or the name of a live sandbox:
`client.get("job-42")`; `client.get_sandbox(ref)` is the same call under the name that sits next
to `create_sandbox` and `list_sandboxes` (sync and async). A name is looked up among the live sandboxes (`destroyed` ones are
ignored, and a sandbox in `error` loses against another with the same name). No match raises
`NotFound`; if several live sandboxes still share the name, `AmbiguousSandboxName` is raised and
lists their ids and states.

Deleted sandboxes are kept as tombstones with the state `destroyed`. An unfiltered list hides
them: `client.list_sandboxes()` and `GET /v1/sandboxes` return only sandboxes that are not
`destroyed`. To see them, pass `include_destroyed=True` (`client.list_sandboxes(include_destroyed=True)`
and `iter_sandboxes(include_destroyed=True)`; REST `GET /v1/sandboxes?include_destroyed=true`) to get
every state, or filter on them with `state="destroyed"` (REST `?state=destroyed`).
The list call takes one `state` value, for example `client.list_sandboxes(state="started")` (or
`iter_sandboxes(state="started")` to walk all pages). `list_sandboxes` returns a page you can
iterate (`for s in page`) and measure with `len()`; it also has `.items` and `.next_cursor`.
Both list calls take `order="asc"` (oldest first, the default) or `order="desc"` (newest first):
`client.list_sandboxes(order="desc", limit=5)` is the five newest sandboxes, and
`iter_sandboxes(order="desc")` sends the same `order` on every page. The CLI has
`sandfort sandbox list --order desc`.

Each single-value query parameter of the list route (`state`, `stop_cause`, `order`, `limit`,
`include_destroyed` and `cursor`) must be given once. A repeated one, for example
`?state=started&state=stopped`, answers 422 "must be given once". Only `label` may repeat.

### Quotas

Organizations can have resource limits: vCPU, memory, disk and a maximum number of sandboxes.
Self-hosted operators set them, and the hosted beta may set them for your organization. A `null`
limit means unlimited: a dimension without a number in the reply below has no organization limit,
and exceeding a number that is set answers `QUOTA_EXCEEDED` (a per-key `max_sandboxes` cap does too;
see "Per-key sandbox cap"). Read the
limits and usage with `client.quota.get()` in the SDK, with `sandfort quota` in the CLI, or with a
GET on the `quota` path under `/v1/org`. The key needs the `org:read` scope, also when it is
limited to labelled sandboxes. The reply has `limits`, `reserved` and `scope`:

```python
quota = client.quota.get()
print(quota.limits.max_sandboxes, quota.reserved.sandboxes)
if quota.scope:                       # only for a key with sandbox_labels
    print(quota.scope.sandboxes, quota.scope.max_sandboxes, quota.scope.remaining)
```

```bash
sandfort quota            # add --json for {"limits", "reserved", "scope"}
curl -s -H "Authorization: Bearer $SANDFORT_API_KEY" https://api.sandfort.dev/v1/org/quota
```

An org-wide key gets the organization's numbers, and `scope` is `null`. A key limited to labelled
sandboxes gets the same `limits`. Its `reserved` counts only the sandboxes in its scope, and
`scope` holds `labels`, `max_sandboxes` (the key's cap, `null` without one), `sandboxes` (live
sandboxes in the scope) and `remaining` (the cap minus `sandboxes`, `null` without a cap).

A default sandbox reserves about one vCPU and 512 MiB of memory (`cpu_millicores=1000`,
`memory_mib=512`), so where a modest sandbox cap is set it also caps how many run at once. Where an
organization limit is set, exceeding it returns HTTP 429 with the error code `QUOTA_EXCEEDED`
(`QuotaExceeded` in the Python SDK). Rate limiting also uses 429, but with the code `RATE_LIMITED`
and a `Retry-After` header in seconds (no `X-RateLimit-*` headers; the buckets are per API key;
the default sizes are under "Beta limits").
A quota 429 is not retryable on its own: free
resources by deleting sandboxes, or raise the limit (on a self-hosted install) or write to
`office@sandfort.dev`.

Per-sandbox maximums apply on the hosted beta whether or not your organization has limits: 4000
millicores of CPU, 8192 MiB of memory and 20 GiB of disk. A create request above them is rejected at
create time with HTTP 422 and the error code `UNPROCESSABLE` (`Unprocessable` in the Python SDK);
the error details list the requested and the maximum values. This is a validation error, not a quota
429, and deleting other sandboxes does not help: lower the request, or write to
`office@sandfort.dev`.

Below those per-sandbox maximums the request schema has its own ceilings. They only keep a number
out of the database's integer range. `auto_stop_minutes` and `auto_delete_minutes` go up to 525600,
which is one year, on create and update. The value `-1` still disables the timer. `cpu_millicores`
goes up to 1000000, `memory_mib` up to 16777216 and `disk_gib` up to 1048576, on create
(`resources`) and resize. A value above a ceiling, including a number far beyond any machine
integer, answers 422 with the code `VALIDATION_ERROR`, and `details.errors` names the field in `loc`
(for example `["body", "auto_stop_minutes"]`). Earlier builds let such a value reach the database
and answered 500. On create, a value between the per-sandbox maximum and the ceiling still gets the
422 `UNPROCESSABLE` answer described above.

`PUT /v1/org/quota` sets the organization quota. It is a platform-admin operation; on the hosted
beta the operator sets it, not your key. The quota body has ceilings of its own. A value above a
ceiling answers 422 `VALIDATION_ERROR`, with the field in `details.errors` and `loc` `["body", "<field>"]`. The
ceilings are `max_vcpus` up to 1000, `max_memory_mib` up to 16777216, `max_disk_gib` up to 1048576
and `max_sandboxes` up to 1000000. The `max_vcpus` ceiling is the per-sandbox CPU ceiling of 1000000
millicores, in vCPUs. A fraction such as `0.5` is fine. A value of `0` is allowed and a missing or
`null` dimension is unlimited. `max_vcpus` must also be finite: `Infinity`, `-Infinity`, `NaN` and a
literal such as `1e309` that parses to infinity answer 422 as well; earlier builds answered 500 for
a non-finite `max_vcpus`.

Three request inputs answered 500 in earlier builds and now answer 422 `VALIDATION_ERROR` with the
parameter in `loc`: `max_vcpus` of the organization quota (the bound and the non-finite values are
above), and these two, each with a documented bound:

- `GET /v1/sandboxes/{id}/logs?since=` is a Unix time in seconds, from `0` up to but not including
  `253402300800` (10000-01-01T00:00:00Z, the first moment a year-9999 limit cannot hold). Values
  such as `253402300800` and `1e300` answer 422 with `loc` `["query", "since"]`. `nan`, `inf` and
  `-inf` also answer 422 with `loc` `["query", "since"]`. They have their own type, `finite_number`,
  and the message "Input should be a finite number of seconds". They do not get a bound message
  (round 54). A value that is not a number at all keeps the usual float parse error.
- `GET /v1/audit-events` and `GET /v1/audit-events/export` take `from` and `to` as datetimes (a
  value without a time zone is read as UTC). A value that leaves the representable range (years 1 to
  9999) once it is converted to UTC, such as `9999-12-31T23:00:00-23:00` or
  `0001-01-01T00:00:00+23:00`, answers 422 with `loc` `["query", "from"]` or `["query", "to"]` and a
  message that ends with `datetime is out of range once converted to UTC`. The same holds for `from`
  and `to` of `GET /v1/org/usage`, which share the bound. The edge itself is accepted:
  `9999-12-31T23:59:59.999999Z` works. On the export route, a `to` that is not after `from` answers
  422, with the code `UNPROCESSABLE`. Since round 53 the usage report answers the same. It answered
  400 `VALIDATION_ERROR` before. Since round 54 the audit list (`GET /v1/audit-events`) answers the
  same when both bounds are given. The message is "`to` must be after `from`". It returned an empty
  page before, so a poller that used an inverted window as "nothing yet" must now expect 422.

**Disk size is enforced on the hosted beta.** The requested disk size (`disk_gib`) is a hard cap on
all three isolation tiers. We checked it on the beta with `disk_gib=1`: writing 1.5 GiB stopped at
1 GiB (1073676288 bytes) in both `/tmp` and `/root`. To your code a full disk looks like a failed
write ("No space left on device" (ENOSPC); `dd` exits with 1), and the sandbox keeps running. Exec
keeps working on a full disk, with no stray stderr. A file upload into a full sandbox answers HTTP
409 CONFLICT (`Conflict` in the SDK) with "the sandbox disk is full (no space left on device):
delete files in the sandbox or create it with a larger disk_gib" and no host paths. Delete files to
free space, or create a sandbox with a larger `disk_gib`, up to the 20 GiB per-sandbox maximum
above.

A sandbox written until ENOSPC with 0 bytes free restarts with its data on all three tiers
(verified on `gvisor`, `microvm` and `container`). Stop, start and snapshot of a full sandbox work;
a snapshot of a full `microvm` sandbox restored all its files into a new `disk_gib=3` sandbox. The
quota is `disk_gib` plus 32 MiB, and Sandfort keeps a 16 MiB file, `/.sandfort-reserve`, in the
sandbox: it empties the file in place before every stop and refills it after every start. `df`
therefore shows about 32 MiB more than `disk_gib` (1.1G for `disk_gib=1`). Do not touch
`/.sandfort-reserve`. If you delete, truncate or replace it and then fill the disk, the sandbox
cannot be started again: it goes to the state `error`. Without the file you lose the protection
until the next start recreates it, and a full disk in that window is what causes the failure.

Recovery tip: a sandbox in `error` whose container still exists can be snapshotted to get its files
back. Run `client.snapshots.create_from_sandbox(sbx.id, "rescue", wait=True)`, then create a new
sandbox from that snapshot id with a larger `disk_gib`. If the container is already gone the
snapshot fails, and delete is all that is left.

### Usage report

The usage report shows how much vCPU and memory your sandboxes were allocated, and how much disk they used, in a period.
It is label-scoped. A key with `sandbox_labels` sees only its own sandboxes and label groups. An
org-wide key sees the whole organization. The key needs the scope `usage:read`. The report records
allocation. It is not a bill.

The `vcpu` and `memory_mib` totals use the allocated size and are exact. `disk_gib` is different:
it uses the size the sandbox has used, as sampled, not the `disk_gib` you allocated (see the
operations runbook). The usage is credited for the whole time a sandbox runs, at the last sampled
size. A new sandbox is sized within about 15 seconds. Stop and delete take one final sample, so a
sandbox deleted before its first regular sample is still credited over its whole run. If the
platform cannot read the size at that moment, the last sampled size stands, and a run that was never
sized counts 0 disk.

The CLI command is `sandfort usage`. It takes `--from` and `--to` for the period, in ISO 8601. A
date alone is midnight UTC. The period defaults to the current UTC month so far. `--group-by
sandbox` gives one row per sandbox. `--group-by label:KEY` gives one row per value of the label
`KEY`. `--limit` sets the groups per page (1 to 100, server default 50), and `--all` pages through
every group. A cursor belongs to its period, so `--cursor` needs an explicit `--from` and `--to`.
When a page has more groups, the command for the next page is printed on stderr.

```bash
sandfort usage
sandfort usage --from 2026-11-01 --to 2026-11-08 --group-by sandbox
sandfort usage --group-by label:team --all
```

The Python SDK has `client.usage.get` and `client.usage.iter`. The async client has the same two
methods. `from_` and `to` are timezone-aware datetimes. Without `group_by`, `get` returns the
organization totals. With `group_by`, it returns one page of groups and a `next_cursor`. `iter`
walks every page and yields the groups. Each group has `group_key`, `group_value`, `name`,
`labels` and `totals`. For `group_by="sandbox"`, `group_value` is the sandbox id, and `name` and
`labels` are those of the sandbox at the time of the report. For `label:<key>`, `group_key` is the
key and `group_value` is the label value, or `None` for sandboxes without that label. When no
sandbox in the window carries the label key at all (a typo is the usual cause), the one `None`
group holds the whole total and the answer's `meta.note` says `label key 'nope' was not found on any
sandbox in this window; check the key`. The SDK shows it as `UsageReport.note`, and `sandfort usage
--group-by label:<key>` prints it on stderr (with `--json` it is a `note` key, present only then).

```python
from datetime import datetime, timezone

start = datetime(2026, 11, 1, tzinfo=timezone.utc)
end = datetime(2026, 11, 8, tzinfo=timezone.utc)
for group in client.usage.iter(from_=start, to=end, group_by="label:team"):
    print(group.group_value, [(t.dimension, t.unit, t.total) for t in group.totals])
# async: async for group in client.usage.iter(from_=start, to=end, group_by="label:team"): ...
```

### What stop, start, resize, reset and delete keep

What each action keeps or removes, checked against the code on 2026-11-26. "Image scratch
volumes" are the volumes behind `image_mounts` (see "Volumes" below).

| Action | Root filesystem | Processes | Image scratch volumes | Named volumes | Id, name, labels, timers |
|---|---|---|---|---|---|
| `stop` | Kept, all of it: `/root`, `/etc`, cron entries, SSH keys, shell profiles | End | Kept | Kept | Kept |
| `start` (of a stopped sandbox) | Same container, same files | Start fresh | Kept | Kept | Kept |
| `resize` (stopped only) | Kept (copied into the new container) | End | Kept | Kept | Kept |
| `reset` | Replaced by the image's, everything written is gone | End | Emptied: new empty volumes | Kept | Kept, with resources, env, network policy, tier and volume mounts |
| `delete` | Removed | End | Removed | Kept, they are separate objects | Gone |

- `stop` is a plain stop of the same container: nothing is committed or removed
  (`src/sandfort/drivers/docker/containers.py`, `stop_container`). A stopped sandbox gives back its
  whole quota reservation (CPU, memory, disk and its count against the sandbox limit), while its
  files keep using disk on the host until it is deleted. `start` reuses the container. Sandfort
  rewrites `/etc/resolv.conf` on start where it manages DNS, removes stale pid files, and on
  `gvisor` puts an empty `/tmp/.sandfort-keep`. With a disk quota, a stop empties the reserve file
  `/.sandfort-reserve` and a start fills it again. Your own files are not touched.
- On the hosted beta, files survive a stop on `gvisor` because the runtime is registered with
  `--overlay2=none` (`deploy/node-setup.sh`). On a self-hosted node, register `runsc` the same way.
  The server does not check it.
- `reset` removes the container together with the image scratch volumes and creates new, empty
  ones. Anything a `volumes` entry mounts is a named volume and is not touched.
- `delete` removes the container, the image scratch volumes and the saved image a resize leaves
  behind. Volumes you created through the volumes API stay until you delete them.

### Resizing a stopped sandbox

`POST /v1/sandboxes/{id}/resize` changes the CPU and memory of a stopped sandbox. On a sandbox that
is started it returns 409 `INVALID_STATE`, so stop it first. There is no SDK or CLI helper for it
yet; call the REST endpoint directly.

The files in the sandbox's root filesystem are kept across a resize (for example `/tmp` and
`/root`), on every isolation tier. The container is replaced when the sandbox is started again:
the stopped container is saved to a local image, the new container with the new resources is
created from it, and that image is removed when the sandbox is deleted. Mounted volumes stay
attached.
Running processes and anything held in memory do not survive the stop, as with any stop. A reset
still wipes the root filesystem; a resize does not. Disk usage written before the resize
counts as part of the image the new container starts from, not against the new `disk_gib` of its
writable layer.

### Resetting a sandbox

`sbx.reset()` (REST: `POST /v1/sandboxes/{id}/reset`; CLI: `sandfort sandbox reset <sandbox>`)
replaces the sandbox's container with a fresh one made from the same image and spec. It is the
clean slate: everything written to the old container is gone. The sandbox keeps its id, name,
labels, resources, env, network policy, isolation tier, volume mounts and auto timers. Named
volumes (from `POST /v1/volumes`) are separate objects and are kept, so a mounted volume is not
cleaned. The scratch volumes an image declares (`image_mounts`) are emptied.

- Allowed from `started` (the sandbox ends `started`) and from `stopped` (it ends `stopped`).
  Any other state answers 409.
- Refused with 409 while a snapshot of the sandbox is in progress, and on a server that runs
  sandbox lifecycle as jobs (there is no reset job); there, delete the sandbox and create a new one.
- Open terminals (PTY) of the old container are closed.
- The reset is audited as `sandbox.reset`. If the driver fails after the old container was
  removed, the sandbox goes to `error` with the reason, `sandbox.reset_failed` is audited, and
  you delete the sandbox and create a new one.
- Reset is the clean slate for a student-facing "Run code" button too; see the next subsection.

### A student-facing Run code button

A button that runs code a student typed: the code is untrusted, the student is waiting, and the
sandbox must be small and offline. The steps, each checked against the server and SDK code:

1. **Create one sandbox per student session** (not one shared by students):

   ```python
   sbx = client.create_sandbox(
       name=f"student-{session_id}",
       snapshot="python:3.12-slim",        # node:22-bookworm for javascript / typescript
       resources=Resources(cpu_millicores=500, memory_mib=256, disk_gib=1),
       block_network=True,                  # no network and no DNS on every tier
       auto_stop_minutes=10,                # idle minutes
       auto_delete_minutes=60,              # minutes after it stopped
       labels={"app": "run-button", "session": session_id},
   )
   ```

   The defaults are `cpu_millicores=1000`, `memory_mib=512`, `disk_gib=3`; pass your own so a
   student cannot take more than you budgeted. `javascript` and `typescript` need an image with
   Node. The first create from `node:22-bookworm` has to pull the image and is slower than later
   ones; create one warm sandbox before class. Reusing one sandbox per session is faster per run
   than creating a sandbox per run, but a per-run sandbox starts clean without a `reset()`;
   measure both on your own host.
2. **Run the code with a budget:** `result = sbx.process.code_run("python", student_code,
   timeout_s=10)`. A non-zero exit is a normal result (HTTP 200), not an exception. Output is
   capped at 1 MiB per call. `input()` cannot wait for the student (there is no stdin); Python
   raises `EOFError`, so collect input in your UI and pass it through `argv` or a file.
3. **Map `stop_reason` and the exit code to a message.** `stop_reason` comes from the result
   flags, never from the output text, and is `null` for a normal exit:

   | `stop_reason` | `exit_code` | Message to show |
   |---|---|---|
   | `timeout` | 124 | "Your program ran too long. Check for an endless loop." |
   | `output_limit` | any, `truncated` true | "Your program printed too much output." |
   | `sandbox_stopped` | 137 | "The environment stopped." Then restart it (below) and offer a re-run. |
   | `killed` | 137 | "Your program used too much memory or was killed." |
   | `null` | 0 | Show stdout. |
   | `null` | 1 or other | Show stderr as the program's error (an uncaught exception exits 1). |
   | `null` | 127 | "This language is not available here." (the image lacks the interpreter) |

   When several flags are set the order is timeout, output limit, sandbox stopped, killed.
4. **Restart after `sandbox_stopped`:** the student's files may stay, so `sbx.start()` alone is
   enough (an auto-stopped sandbox is started the same way); see "Recovering after
   `sandbox_stopped`" above for when `reset()` then `start()` is the right call instead. A
   sandbox that fails to start stays in `error` until you delete it.
5. **Start over** with `sbx.reset()` when the student wants a clean slate (see Resetting a
   sandbox; the sandbox ends in the state it had, so call `start()` afterwards if it was
   `stopped`), and delete the sandbox when the session ends.
6. **Tracebacks.** A Python traceback names `main.py`. For the other languages it shows
   `/tmp/.sandfort-run-<random>/main.js` (or `.ts`, `.sh`); strip the directory with a regular
   expression such as `/tmp/\.sandfort-run-[0-9a-f]+/` before you show it.

Do not use the hosted beta for production secrets or sensitive data (see "Beta limits").

### Course and grader walkthrough

For a course platform that grades student code, the pieces above fit together in this order.
Each step points to the section that has the details.

1. **Class dataset volume (optional).** If every student reads the same files, put them in one
   volume that the instructor owns and share it read-only. The worked example is under "Sharing a
   class dataset read-only" below; do it before step 2 so the student keys can name the volume.
2. **One key per student, with a cap.** Create the keys with the instructor (admin) key, each
   limited to that student's label and capped, and give them an `expires_at` (see "Managing API
   keys" and "Per-key sandbox cap"). The key holds `volumes:read` so that it can list and mount
   the class dataset; add `shared_volume_labels` for it (see the worked example):

   ```python
   key = client.create_api_key(
       f"student-{n}",
       ["sandboxes:read", "sandboxes:write", "toolbox:use", "volumes:read"],
       sandbox_labels={"student": str(n)}, max_sandboxes=3,
       shared_volume_labels={"course": "cs101"},   # the class dataset, read-only
       expires_at=term_end,                       # timezone-aware datetime
   )
   ```

   Add `org:read` to the scopes if a student should see the remaining cap with `sandfort quota` or
   `client.quota.get()`. The reply then shows that student's own sandbox count and cap.

3. **Student sandboxes** use the Run code button recipe: small, offline, labelled with the
   student's label (see "A student-facing Run code button").
4. **The grader sandbox is owned by the instructor key, not by a student key.** Create it without
   the student's labels, so the student key gets 404 for it. Harden it as described under "Isolation
   tiers". That means hidden tests in a `0700` directory, the candidate run as an unprivileged user,
   and one sandbox per untrusted submission.
5. **Recovery rule.** After `sandbox_stopped`, the grader calls `reset()` and then `start()`,
   then uploads its files again; a student session calls `start()` alone (see "Recovering after
   `sandbox_stopped`").
6. **Cleanup.** Delete each grader sandbox in a `finally` block, set `auto_stop_minutes` and
   `auto_delete_minutes` as a backstop, and revoke the student keys at the end of the term
   (`revoke_api_key` or `sandfort key revoke`); `expires_at` ends them on its own.

**Warning: the cap counts every live sandbox that carries all of the key's labels, whoever
created it.** A grader sandbox that carries a student's labels counts against that student's
`max_sandboxes`, and the student's key can also see it and read its files. Give grader sandboxes
labels the student keys do not have, for example `{"role": "grader"}`.

#### Sharing a class dataset read-only

A key limited to `{"student": "3"}` sees no volume of the instructor's: the volume list is empty,
get answers 404, and a mount in `create_sandbox` answers 403 "cannot mount volumes outside that
scope". Give the student keys the optional `shared_volume_labels` instead. A key with it can, next
to its own scope, **list and get** every volume whose labels contain all of those pairs, and
**mount it read-only**. It can never mount it read-write (403, and the message names the rule),
update it or delete it. Only a key that holds `api_keys:admin` can set the field, and it needs
`sandbox_labels` (an org-wide key does not need it). The field takes up to 8 pairs, under the same
rules as `sandbox_labels`.

1. **The instructor creates the dataset volume with course labels.** Use the instructor (admin,
   org-wide) key:

   ```python
   data = client.volumes.create("cs101-data", labels={"course": "cs101"})
   ```

2. **Seed it once from a seed sandbox, then delete that sandbox.** Mount the volume read-write,
   write the files into it, and delete the sandbox. The volume stays. The label `{"role": "seed"}`
   keeps the sandbox away from every student key:

   ```python
   from sandfort_sdk import VolumeMount

   with client.create_sandbox(
       name="cs101-seed", labels={"role": "seed"},
       mounts=[VolumeMount(data.id, "/data")], wait=True,
   ) as seed:                                        # leaving the block deletes it
       seed.fs.upload_file("/data/iris.csv", open("iris.csv", "rb").read())
   ```

   The volume cannot be deleted while a sandbox still mounts it (409 `in_use`), so delete the seed
   sandbox before you hand out the keys and before any later cleanup.
3. **Create the student keys with `shared_volume_labels` and `volumes:read`** (the key from step 2
   of the walkthrough above). With the CLI:

   ```bash
   sandfort key create student-3 -s sandboxes:read -s sandboxes:write -s toolbox:use \
     -s volumes:read -l student=3 --shared-volume-label course=cs101 --max-sandboxes 3
   ```

4. **A student mounts it read-only.** The student key lists the volume (`client.volumes.list()`)
   and mounts it with `read_only=True`; a mount without it answers 403:

   ```python
   sbx = student_client.create_sandbox(
       name="cs101-lab",
       mounts=[VolumeMount(data.id, "/data", read_only=True)],   # CLI: --mount VOLUME:/data:ro
       wait=True,
   )
   ```

The student key still sees only the volumes of its own scope plus the ones that carry
`{"course": "cs101"}`. A volume it creates gets its own scope labels, not the shared ones. A
label-scoped creator may only give a new key `shared_volume_labels` that include all of the
creator's own `sandbox_labels` or all of its own `shared_volume_labels`.

**A key with `shared_volume_labels` cannot publish shared data.** A create that would give the
volume all of the key's shared labels answers 403 ("cannot create volumes carrying its
shared_volume_labels"). Without this rule one student could plant a volume next to the
instructor's dataset. Only a key without the field, such as the instructor key, can create it.
A key without `volumes:write`, such as the student keys above, never reaches this rule: its
create gets the missing-scope 403 (`details.missing_scopes` lists `volumes:write`). Only a key
with `volumes:write` and `shared_volume_labels` sees the rule text.
Volume names are unique per org, so a student can still take a name first, and the instructor
then gets a 409.

**Matching is by subset, so use a label only for shared data.** A volume is shared when its labels
contain every shared pair, and extra labels do not matter. If you label each student's private
volume `{"course": "cs101", "student": "4"}` and the student keys share `{"course": "cs101"}`,
every student can list and mount every other student's volume. Use a label that only shared data
carries, for example `{"share": "cs101-data"}`, and give the student keys
`--shared-volume-label share=cs101-data`. Keep `course` and `student` for the private volumes.

### Network

A sandbox has open outbound internet by default. The hosted beta does not change that default
(it sets neither `SANDFORT_DEFAULT_BLOCK_NETWORK` nor `SANDFORT_ENFORCE_BLOCK_NETWORK`, checked
2026-11-27), so code in an open sandbox can send data out over DNS and HTTPS. For code you do
not trust, use **Blocked**, or **Allowlist** when it needs a package index. Choose the mode
when you create it:

- **Open (default):** no network argument; outbound traffic is not restricted. Names resolve on all
  tiers (`gvisor` and `microvm` resolve through `1.1.1.1` and `8.8.8.8`).
- **Allowlist:** `egress_allowlist=["pypi.org", "files.pythonhosted.org"]` (a list of host names).
  Allowlisted hosts are reachable only through the egress proxy that the sandbox's `HTTP_PROXY` and
  `HTTPS_PROXY` variables point to (`pip`, `curl` and Python `requests` use them); every other
  destination is refused. For `pip`, list both the package index host and the file-download host.
  The proxy only accepts `CONNECT`. Any other method, which is what a client sends for a plain
  `http://` URL through `HTTP_PROXY`, answers 405 `Method Not Allowed` with `Allow: CONNECT`
  and the connection is closed, so use `https://` URLs under an allowlist. The host-name rules
  for the list are in [Naming rules](#naming-rules).
  The proxy variables, including the per-sandbox proxy credentials, are visible to code inside the
  sandbox. DNS differs by tier:
  - On `gvisor` and `microvm`, direct DNS lookups fail immediately.
  - On the `container` tier, the sandbox's only DNS server is the egress proxy's sink
    (on the beta since the API restart at 2026-11-25T08:12:30Z), which answers every query
    REFUSED and forwards nothing, so direct lookups fail here too and only the proxy resolves
    names. A sandbox created before that instant, including one created earlier on
    2026-11-25, keeps the old resolvers until it is reset or recreated.
- **Blocked:** `block_network=True` in the SDK (`network: {"block_all": true}` in REST). There is no
  network and no DNS on any tier: the sandbox shows no DNS configuration from the host, and name
  lookups fail at once on every tier.

### Choosing an isolation tier

You choose the isolation boundary per sandbox, behind the same API. There are three tiers:

- **`container`:** Linux namespaces, cgroups, a seccomp profile and a reduced capability set. The
  profile is Docker's default unless `SANDFORT_SECCOMP_PROFILE_PATH` names a file (empty by
  default). Two kits set it: the Kubernetes kit in `deploy/k8s/configmap.yaml`, to the profile
  generated from `deploy/seccomp.json`, and the self-host Compose file
  `deploy/selfhost/compose.yml`, which mounts `deploy/seccomp.json` read-only.
  `deploy/compose.prod.yml` does not set it, so that Compose deployment uses Docker's default
  profile unless you add the variable to `deploy/sandfort.env` and bind-mount the profile file into
  the container yourself (an unreadable path fails server start; see the
  [security page](https://docs.sandfort.dev/security.html)). The Docker daemon passes
  the profile under `runsc` (the `gvisor` tier), but `runsc` does not enforce it, so "Docker's
  default profile" is the container tier's wording only. All capabilities are
  dropped except `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `KILL`, `SETGID`, `SETUID` and
  `NET_BIND_SERVICE`. The hardening set is the same on all three tiers, except what a tier's
  runtime replaces (under `gvisor` the user-space kernel is the system-call boundary; under
  `microvm` the guest kernel is). It is the fastest tier for spawn-heavy and
  small-file-heavy work, and it shares the host kernel: a kernel exploit inside the sandbox would
  reach the host. `nproc` and `MemTotal` show the host's values, not the sandbox limits, so size
  thread pools from the resources you requested.
- **`gvisor`:** a user-space kernel (gVisor) handles the sandbox's system calls, so the host kernel
  sees only a small, filtered surface (a bug in gVisor itself can still expose it). Create, exec,
  CPU-bound work and file transfer cost about the same as on `container`; spawn-heavy and
  small-file-heavy work is slower (see Overhead below), and a few behaviors differ.
- **`microvm`:** hardware virtualization with Kata Containers 4.3.1 (Rust runtime, QEMU) on the
  beta VM's KVM (nested virtualization). Each sandbox has its own guest kernel in a lightweight VM;
  it reported 6.18.56, not the host's 6.8. Start is much slower and each sandbox uses more memory.
  With `block_network=True` a create takes about 5 s longer (Kata behaviour, see below).

`GET /v1/isolation` returns `{"default": ..., "available": [...]}`. On the hosted beta the
available tiers are `container`, `gvisor` and `microvm`, and `gvisor` is the default, so a sandbox
created without an `isolation` value runs under gVisor. Requesting a tier that is not offered is a
422 that names the available tiers.

The hosted beta is moving image builds onto gVisor and enabling user-namespace remapping on the
sandbox node; there is no date for either. With remapping on, the `container` and `gvisor` tiers
run with container root mapped to an unprivileged host user, while `microvm` stays in the host
user namespace because Kata cannot run remapped. These are host-side hardening steps and change
nothing in the tier descriptions above: `container` still shares the host kernel, `gvisor` is
still not a hardware boundary, and we do not claim microVM-grade isolation for the `container` or
`gvisor` tiers.

```python
sbx = client.create_sandbox(name="isolated", isolation="gvisor", wait=True)
print(sbx.isolation)                      # gvisor
print(client.isolation())                 # the default tier and the available tiers
```

```bash
sandfort sandbox create isolated --isolation gvisor
sandfort sandbox isolation
```

In REST the field is `isolation` on create and on every sandbox response.

How the `gvisor` tier behaves differently from `container`:

- `uname -r` inside the sandbox reports a gVisor kernel (`4.19.0-gvisor`), not the host's.
- Exceeding the memory or process limit usually stops the whole sandbox, not just one process (the
  limits count gVisor's own host processes). The command then reports "the sandbox stopped while
  running this command: it exceeded its memory or process limit; start it again" with exit code 137.
  The sandbox moves to the state `stopped` with an `error_reason` that explains why, its files are
  kept, and starting it again works. Sometimes only the offending process is killed instead: the
  command exits with 137 and an empty stderr, and the sandbox is still `started`. Hitting the
  process limit can also just make new process creation fail (fork errors such as ENOMEM) without
  stopping anything. Because the outcomes differ, check `sandbox_stopped` in the exec result after
  any exit code 137 before you continue. On the `container` tier only the offending process is
  killed.
- Streamed log events can split a line across events. Join the text of consecutive events rather
  than parsing each event as a line.
- Large writes count toward the memory limit. gVisor keeps file data in sandbox memory, so writing
  large amounts of data also uses the memory limit. In our evaluation on a 512 MiB `gvisor`
  sandbox, writes of 1-2 GiB were fine under both `/root` and `/tmp`, while writes of 3.5 GiB stopped
  the sandbox in some runs on either path (3 of 7 under `/tmp`, 4 of 6 under `/root`). Keep single
  large writes well under a few GiB per sandbox on the `gvisor` tier, or raise the sandbox's memory
  limit.
- If you supervise sandboxes from your own code, treat an exec that fails with HTTP 409 "the sandbox
  container is not running" as the sandbox being down, and re-read the sandbox state. It moves to
  `stopped` within a few seconds after an exec sees the sandbox die.
- Several different situations share the status 409 and the code `CONFLICT`. Tell them apart by
  `error.details.reason` (see REST API). The message and `details.state` add detail. A toolbox call
  on a sandbox that is not running has the message "sandbox is stopped; toolbox calls require a
  started sandbox", with `details.state`. The same call on a deleted sandbox has `details.state`
  `destroying` or `destroyed`. Its message is "the sandbox was deleted; create a new one", so do not
  start it. A create with a name that is already in use has the message "sandbox name already exists
  in this org". (A refusal such as resizing a running sandbox uses the code `INVALID_STATE` instead,
  which has no `reason`.)
- `/tmp` stays in the root filesystem, so it is covered by the disk quota and included in
  snapshots like any other path. Sandfort keeps it there with an empty `/tmp/.sandfort-keep`
  marker file; do not delete it. Sandboxes created before 2026-11-04 keep their old separate
  `/tmp` volume until they are deleted.
- DNS: `gvisor` sandboxes resolve names through public resolvers (`1.1.1.1` and `8.8.8.8` by
  default on the hosted beta; a self-hosted operator can change them), because gVisor cannot reach
  Docker's internal resolver.
- User namespaces, measured on the hosted beta host on 2026-11-26 with the create options of a
  sandbox (one run per tier, not a guarantee): on `container`, `unshare -U` is refused. On `gvisor`
  and `microvm`, `unshare -U` succeeds, but writing `/proc/self/uid_map` is refused with `EPERM`,
  so a process cannot map itself root in its new namespace.
- Kernel introspection such as the kernel symbol table (`kallsyms`) is absent. `nproc` and
  `MemTotal` reflect the sandbox's limits.
- The Docker daemon passes the seccomp profile for every runtime, but per gVisor's documentation
  `runsc` does not apply Docker seccomp profiles; gVisor is itself the system-call boundary.

Overhead of `gvisor` relative to `container` varies by host and workload. Two measurements follow;
treat both as indicative, not as a benchmark of the hosted beta.

First measurement, on a laptop-class machine inside a nested Docker daemon (median of 6 runs):

- Create to started: 158 ms on `container`, 160 ms on `gvisor`. A trivial exec takes about 20 ms on
  both. A CPU-bound Python loop is within about 2-5%, a 5 MB upload or download within about 5%,
  and stop, start and delete within about 10%.
- Spawn-heavy work is slower: 200 sequential process spawns took 103 ms on `container` and 384 ms on
  `gvisor` (about 3.7x).
- Small-file-heavy work is slower: creating, stat-ing and deleting 10,000 small files took 172 ms
  on `container` and 776 ms on `gvisor` (about 4.5x).

Second measurement, by a second evaluator on a different run:

- 200 Python subprocess spawns: 26 ms on `container`, 216 ms on `gvisor` (about 8x).
- 200 `/bin/true` runs from a bash loop: 0.044 s on `container`, 1.80 s on `gvisor` (about 40x).
- 10,000 small files: 0.30 s on `container`, 2.63 s on `gvisor` (about 9x).

Create, exec, CPU-bound work and file transfer cost about the same on both tiers. Spawn-heavy and
small-file-heavy work is several times slower on `gvisor`, from about 3x to about 9x in our
measurements, and more for very fork-heavy shell loops. Time your own build or test command on both
tiers before you choose. Package installs, git, compilers and large test suites are typical
spawn-heavy and small-file-heavy workloads.

`gvisor` is not a hardware boundary. It is a user-space kernel, and a bug in gVisor itself could
still expose the host kernel. That is why the `microvm` tier (hardware virtualization) exists for
the highest-risk code.

How the `microvm` tier behaves. These facts were checked on the hosted beta on 2026-11-04:

- Create to started takes about 4 s (six runs: 3.70-3.96 s, median 3.84 s; start alone 3.7 s). With
  `block_network=True` it takes about 8-9 s (8.1-9.1 s observed over 22 creates). The other tiers
  are well under a second. Plan for that if your agent creates a sandbox per task. The extra
  time is Kata behaviour, not Sandfort's start path: with `block_network=True` the container has no
  network interface, and the Kata shim waits for its network rescan timeout of about 5 s (measured
  on 2026-11-05: about 3.9 s with the network, 8.6-9.0 s with `block_network=True`).
- Exec, the clean 127 messages, timeouts (exit 124), file upload and download including `/tmp`,
  `code_run`, stop and start with files kept, and delete (0.7 s) all work.
- An upload over an existing file can take about 1 s to become visible to commands on `microvm`
  (`gvisor` and `container` show it at once). If a command must read a file you just replaced,
  wait about a second or upload to a new path.
- A program that touches more memory than the limit is OOM-killed inside the VM: exit code 137 with
  an empty stderr (the guest kernel logs "Out of memory: Killed process"). The sandbox keeps
  running and `sandbox_stopped` is false. A single huge allocation can instead fail with
  `MemoryError` (exit code 1).
- A fork bomb can stop the whole `microvm`, as on `gvisor`. The exec then reports exit code 137 with
  `sandbox_stopped` true and the message "the sandbox stopped while running this command ...". The
  sandbox is already `stopped` when the response arrives, with an `error_reason`, and starting it
  again works at once (start takes about 4 s on `microvm`). On the beta, of 29 python fork bombs
  on `microvm`, 26 returned exit 137 with `sandbox_stopped` true within 6.1-12.7 s, and 3 returned
  124 `timed_out` with the sandbox already dead. A death before or at the deadline counts instead of
  the timeout, so that case is reported as exit 137 with `sandbox_stopped` true. Caveat: the classic
  bash fork bomb `:(){ :|:& };:` usually returns exit 0 within about 1 s; the next exec then reports
  `sandbox_stopped` (after up to about 5 s on `microvm`).
- The CPU limit is enforced: CPU-seconds per wall second matched the requested 500, 1000 and 2000
  millicores. The sandbox's own views differ from the request, though: `nproc` reports 1, 2 and 3
  for those sizes, and `MemTotal` is somewhat below the requested memory (454328 kB for 512 MiB).
  Size thread pools from the resources you requested, not from `nproc`.
- DNS: `microvm` sandboxes resolve through the same public resolvers as `gvisor`. With
  `block_network=True` there is no DNS configuration at all (see Network).

Running untrusted submissions (graders, course platforms): use one sandbox per untrusted
submission. On the `gvisor` tier a limit overrun stops the whole sandbox, and a backgrounded fork
bomb can exit 0 before the sandbox stops, so in a reused sandbox the next submission would fail
instead. A fork bomb can stop a whole `microvm` too, so the same advice applies there. Separate
sandboxes are not affected by each other.

Grader or eval harness: the simplest layout is one sandbox per candidate. If creating a sandbox
per candidate is too slow for your harness, keep a worker sandbox and call `sbx.reset()` between
candidates; the reset is the clean slate, since it replaces the container and discards everything
a candidate wrote (see Resetting a sandbox above). Upload the grader's own files after each
reset, because a reset removes them too. Whichever layout you use, run the candidate as an unprivileged user inside the sandbox (for example with `runuser` or
`setpriv`, if your image has them; check on your image), not as root. Exec runs as the image's
default user, which is root in `python:3.12-slim`, and root code can change files the grader
relies on and tamper with `/.sandfort-reserve` (see Quotas). A fork bomb or limit overrun can still
stop the worker sandbox. After `sandbox_stopped` a grader needs clean files, so call `reset()`
and then `start()` (see "Recovering after `sandbox_stopped`" above for why and for when
`start()` alone is enough). Then upload the grader's files again and re-run the candidate.

Hidden tests: a label-scoped student key with `toolbox:use` can read every file in its own
sandbox (fs download, `cat` through exec), so hidden tests must not sit in a sandbox the student
key can reach. Grade in a separate sandbox that you create with the instructor key and without
the student's labels; a student key then gets 404 for it. Upload the tests at grading time,
together with the submission, and delete the grading sandbox afterwards, or `reset()` it between
submissions.

Hardening recipe: inside the grading sandbox the candidate must not be able to read the hidden
tests either, because exec runs as root unless you say otherwise. Put the tests in a directory
that only root can enter (mode `0700`, files `0600`) and run the candidate as an unprivileged
user. `setpriv` is present on `python:3.12-slim`; `65534` is the `nobody` user and group:

```python
sbx.fs.mkdir("/grader", mode="700")                  # directory 0700
sbx.fs.upload_file("/grader/test_hidden.py", hidden_tests, mode="600")   # file 0600
sbx.fs.mkdir("/work", mode="755")                    # the candidate can read this one
sbx.fs.upload_file("/work/submission.py", candidate_code, mode="644")

# 1) the candidate runs as nobody; it cannot list or open /grader
res = sbx.process_exec(
    argv=["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
          "python", "/work/submission.py"],
    timeout_s=10,
)
# 2) the hidden tests run as root, after the candidate has finished
verdict = sbx.process_exec(argv=["python", "/grader/test_hidden.py"], timeout_s=30)
```

Check on your own image before you rely on it: after the upload, run
`setpriv --reuid=65534 --regid=65534 --clear-groups cat /grader/test_hidden.py` and expect
"Permission denied". Run the same check against the other files the grader relies on, and note
that an unprivileged candidate cannot write to root-owned paths. This keeps the candidate away from the tests while it runs; it does
not replace one sandbox per untrusted submission, because a candidate can still stop the sandbox.

Checklist for untrusted submissions (graders, course platforms):

- Create one sandbox per submission, with `block_network=True`, explicit `resources` and an
  explicit `timeout_s`.
- Treat `sandbox_stopped`, exit code 137, `truncated=True` and a failing follow-up exec as failure
  of the submission.
- After every submission, run one trivial probe exec (for example `true`) in the same sandbox and
  treat an exception, a non-zero exit or `sandbox_stopped` as a runtime error. On `timed_out`,
  probe before you report a timeout: a dead sandbox is a runtime error, not a timeout.
- Classify a submission in this order. The first match is the result:
  1. `RUNTIME_ERR` if `sandbox_stopped`, exit code 137 or `truncated`.
  2. `RUNTIME_ERR` if the probe fails.
  3. `TIMEOUT` if `timed_out` and the probe is alive.
  4. `RUNTIME_ERR` on any other non-zero exit.
  5. Otherwise `PASS` or `WRONG`, by comparing the output.
- Budget per submission about 1-3 s on `gvisor` and 9-12 s on `microvm` with
  `block_network=True`. `timeout_s` is a budget, not an exact cutoff.
- Hostile submissions take longer on `microvm`. At `timeout_s=10` we saw about 14 s for a python
  fork bomb, about 15 s for a bash fork bomb, about 19 s for a memory hog and about 23 s for an
  infinite loop. Set the worker timeout to `timeout_s` + 15 s on `gvisor` and `timeout_s` + 25 s
  on `microvm`.
- Delete the sandbox in a `finally` block. The server retries a delete after a crash, so no
  client retry is needed.

### Snapshots

Commit a running sandbox into a snapshot with `client.snapshots.create_from_sandbox`, which takes the
sandbox id and a name. With `wait=True` it returns once the snapshot is ready; without it the call
returns a `pending` snapshot. Start a new sandbox from the snapshot id (it has the `snap_` prefix):

```python
snap = client.snapshots.create_from_sandbox(sbx.id, "after-setup", wait=True)
print(snap.id, snap.state)                                # snap_... ready
again = client.create_sandbox(name="second", snapshot=snap.id, wait=True)
```

Do not delete the source sandbox before the snapshot finishes.

A snapshot can carry labels, like a sandbox or a volume. Set them when you create or register it, and
filter the list by them:

```python
snap = client.snapshots.create_from_sandbox(sbx.id, "after-setup", labels={"course": "cs101"}, wait=True)
mine = list(client.snapshots.iter(labels={"course": "cs101"}))   # every pair must match
```

```bash
sandfort snapshot create cli-first after-setup -l course=cs101 --wait
sandfort snapshot list -l course=cs101                     # -l repeats; every pair must match
curl -s "$SANDFORT_BASE_URL/v1/snapshots?label=course=cs101" -H "Authorization: Bearer $SANDFORT_API_KEY"
```

In the REST API the create and register bodies take a `labels` object, and `GET /v1/snapshots` takes
a repeatable `label=k=v` query parameter. `snapshot register` takes `-l` as well. A label-scoped key
gets its scope merged into the labels (see "Keys limited to labelled sandboxes").

A snapshot keeps the source sandbox's filesystem but none of the env values set on it: neither
the `env` you passed at create nor the variables Sandfort injects (such as the egress proxy URL).
The keys stay in the snapshot with empty values, and a key that overrode a variable of the base
image (for example `PATH`) gets the base image's value back. Pass `env=` again when you create a
sandbox from the snapshot. Docker can blank a key in a commit but cannot remove it, so `env`
inside the new sandbox still lists those keys, empty.

Snapshots taken from a sandbox before 2026-11-06 may still hold env values from their source
sandbox; images already committed were not rewritten. If that sandbox had secrets in `env`,
delete the snapshot, or recreate it from a sandbox and delete the old one.

A snapshot taken from a sandbox records that sandbox's isolation tier; it is shown as `isolation` on
the snapshot. A sandbox created from it without an explicit `isolation` gets the same tier, and an
explicit `isolation` overrides it. If the recorded tier is not offered, the create is refused with a
422 that names the available tiers. Snapshots made from a public image or an image spec have no
recorded tier.

A label-scoped key sees `image_ref` and `digest` of a snapshot as `null`, as it does
`source_sandbox_id`: `image_ref` names the operator's registry host and path. A key without labels
sees both. The same applies to the answer of an image build and to the `digest` of the final
`state` event of its build log. In the Python SDK `SnapshotInfo.image_ref` and
`SnapshotInfo.digest` are optional (`str | None`), so for a label-scoped key check them for
`None` before you use them. The CLI shows `-` in place of a withheld `image_ref` or `digest`
(see "Snapshots and images in the CLI" below).

A sandbox created from a snapshot does not inherit the source sandbox's resources: it gets the
defaults (`cpu_millicores` 1000, `memory_mib` 512, `disk_gib` 3) unless you pass `resources=`. It
does inherit the isolation tier. The new sandbox's disk quota counts only what it writes itself;
the snapshot content it starts from does not count against `disk_gib`.

#### Exporting a snapshot

A `ready` snapshot can be downloaded as an image tar, the archive `docker save` produces. It
needs the `snapshots:read` scope; the call is audited as `snapshot.exported`.

```python
size = client.export_snapshot(snap.id, "after-setup.tar")   # bytes written; streamed, not buffered
```

```bash
sandfort snapshot export snap_... -o after-setup.tar         # REST: GET /v1/snapshots/{id}/export
docker load -i after-setup.tar                                # on any Docker host
```

- A snapshot that is not `ready` answers 409 `INVALID_STATE` (`details.state` names the state).
  The body is `application/x-tar`, with the file name taken from the snapshot name.
- The exported image carries only the filesystem and the safe image config (command, working
  directory, `PATH`); no sandbox environment variables, secrets or labels. The tar names no
  repository, so `docker load` prints the image id (`Loaded image ID: sha256:...`) and creates
  no tag. That is a plain local Docker image on the host where you loaded it, addressed by that
  id; it is not a Sandfort snapshot there.
- The platform's disk reserve file (`/.sandfort-reserve`) is not included in the export.
- **Making it a snapshot on another Sandfort server.** Snapshot register always pulls from a
  registry: the server runs a pull for the reference and stores the registry digest, so an image
  that exists only in the target's local Docker store cannot be registered. The `sandfort-snapshot`
  repository is also reserved, and a register or create that names it answers 422. So retag the
  loaded image, push it to a registry that the target server can pull from, and register that
  reference:

  ```bash
  docker tag <image id> registry.example.org/team/after-setup:v1
  docker push registry.example.org/team/after-setup:v1
  sandfort snapshot register registry.example.org/team/after-setup:v1 --name after-setup
  ```

  (`client.snapshots.register(image, name=...)` in the SDK.) The target server needs pull access
  to that registry. A sandbox created from the registered snapshot gets the default resources
  unless you pass `resources=`, as described above.

To take only some files out of a sandbox, download them: `sbx.fs.download_file(path)` or
`sbx.fs.read_bytes(path)` for a file, `sbx.fs.download_dir(path)` for a directory as a tar stream,
or the CLI copy command (`sandfort cp <sandbox>:<path> ./local`, `cp -r` for a directory). To resume
a large download, pass `range=(start, None)` with the byte offset you already have.

### Volumes

A volume is a named, persistent directory tree that you mount into sandboxes. Listing, getting
and mounting read-only need `volumes:read`; creating, deleting and mounting read-write need
`volumes:write`. A volume belongs to the organization, not to one sandbox.

**Create one, with labels.** The name is 1 to 63 characters (letters, digits, `_`, `.` and `-`,
starting with a letter or digit). A volume takes at most 32 labels, under the label rules in
[Naming rules](#naming-rules):

```bash
curl -s "$SANDFORT_BASE_URL/v1/volumes" \
  -H "Authorization: Bearer $SANDFORT_API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"dataset","labels":{"team":"data"}}'
sandfort volume create dataset --label team=data      # --label repeats
sandfort volume get dataset                           # get and rm take an id or a name
sandfort volume rm dataset                            # refused while a sandbox mounts it
```

```python
vol = client.volumes.create("dataset", labels={"team": "data"})   # vol.id, vol.labels
```

A label-scoped key sees only the volumes whose labels contain all of its scope labels, and a
volume it creates gets the scope labels merged into its own. It does not see the rest of the
organization's volumes, except those that a key created with `shared_volume_labels` is meant to
share: it lists and gets the volumes whose labels contain all of those pairs and may mount them
read-only (read-write is a 403; a delete is a 403 too, "volume <id> is shared with this API key
(shared_volume_labels k=v) and cannot be deleted; only a key that owns its labels can delete it", while
a volume the key cannot see at all is a 404). See "Sharing a class dataset
read-only" under "Course and grader walkthrough".

**Mount it read-write or read-only.** A sandbox takes up to 16 mounts at create time. Each is a
`volume_id`, a `mount_path` and an optional `read_only` flag (default `false`). The sandbox view
lists them under `volumes`, with `read_only` on each:

```bash
sandfort sandbox create analysis --wait --mount <volume-id>:/data:ro --mount <out-id>:/out
```

```python
from sandfort_sdk import VolumeMount

sbx = client.create_sandbox(
    name="analysis",
    mounts=[VolumeMount(vol.id, "/data", read_only=True), VolumeMount(out.id, "/out")],
    wait=True,
)
```

In the CLI, `VOLUME:PATH` mounts read-write and `VOLUME:PATH:ro` mounts read-only (`:rw` is
accepted too). In REST the field is `"volumes": [{"volume_id": "...", "mount_path": "/data",
"read_only": true}]`. An upload, a mkdir, a delete or a move on a read-only mount answers 409
`READ_ONLY_PATH`.

**Mount paths.** A mount path must be a visible, normalised, absolute path: it starts with `/`,
has no trailing slash, no empty segment (`//`), no `.` or `..` segment, and no invisible
characters. It cannot be `/`. It cannot be one of these system directories itself: `/bin`,
`/boot`, `/dev`, `/etc`, `/lib`, `/lib64`, `/proc`, `/root`, `/run`, `/sbin`, `/sys`, `/usr`,
`/var` and `/var/run`. A colon, a comma or a backslash anywhere in the path is refused too (see
[Naming rules](#naming-rules)). Anything under `/proc`, `/sys`, `/dev` or `/boot` is refused as well, and so is
anything under the system binary trees (hiding them breaks every exec): `/bin`, `/sbin`, `/lib`,
`/lib32`, `/lib64`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/lib32`, `/usr/lib64` and
`/usr/libexec`. The files Docker manages and the account files cannot be mounted over:
`/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`, `/etc/passwd`, `/etc/group` and
`/etc/shadow` (exact paths only). Deeper paths under the other directories are allowed, such as
`/root/work`, `/etc/app/data` or `/usr/local/bin`. A refused path answers 422 and the message
names the rule that matched (system directory, system binaries or docker-managed file). `/data`
and `/mnt/out` are fine.

**Size: a soft limit, no hard cap.** The server setting `SANDFORT_VOLUME_MAX_BYTES` sets a soft
limit. The hosted beta's value is an operator setting. So read it from the volume object instead of
assuming one. `size_bytes` is the last sampled size, and `null` until the first sample. `max_bytes`
is the limit, and `null` when there is none. `over_limit` is `true` when the sampled size exceeds
it. A read-write mount of an over-limit volume answers 422 `VOLUME_OVER_LIMIT`; a read-only mount is
not refused, so you can still read the data. The size of a volume is not covered by `disk_gib`,
which limits only the sandbox's own filesystem, and there is no hard cap.

**Lifetime.** A volume persists after the sandboxes that mounted it are deleted, and a later
sandbox can mount it again. Deleting a volume that a sandbox still mounts answers 409 with
`details.reason` `in_use`. `details.sandbox_id` names the first such sandbox and
`details.sandbox_ids` lists all of them, but only the ones your key can see. Sandboxes outside a
scoped key's labels are counted in `details.hidden_sandboxes` instead, and their ids are not
shown.

**`image_mounts`.** Some images declare volume paths of their own. The sandbox view lists, in
`image_mounts` (sorted; empty when there are none), the declared paths that none of your
`volumes` covers. Each is backed by a per-sandbox scratch volume, mounted read-write, that lives
outside `disk_gib`, is deleted with the sandbox and is emptied by a reset. The soft size limit
does not cover these volumes. Mount a volume of your own at such a path if the data must outlive
the sandbox.

#### Exporting and restoring a volume

You can download the files of a volume as a gzipped tar and put them back later, into the same volume or into another
one. Export needs `volumes:read`, restore needs `volumes:write`; both are audited (`volume.export`, `volume.restore`).

```bash
sandfort volume export dataset -o dataset.tar.gz       # REST: GET  /v1/volumes/{id}/export
sandfort volume restore dataset dataset.tar.gz         # REST: POST /v1/volumes/{id}/restore, raw gzip body
```

```python
written = client.volumes.export(vol.id, "dataset.tar.gz")      # bytes written; streamed, not buffered
result = client.volumes.restore(vol.id, "dataset.tar.gz")      # a path, bytes or a binary file object
print(result.restored_bytes)                                   # decompressed tar bytes, headers included
# async: await client.volumes.export(...), await client.volumes.restore(...)
```

```bash
curl -fsS -o dataset.tar.gz -H "Authorization: Bearer $SANDFORT_API_KEY" "$SANDFORT_BASE_URL/v1/volumes/$VOLUME_ID/export"
curl -fsS -X POST -H "Authorization: Bearer $SANDFORT_API_KEY" -H "Content-Type: application/gzip" \
  --data-binary @dataset.tar.gz "$SANDFORT_BASE_URL/v1/volumes/$VOLUME_ID/restore"
```

**A restore replaces everything, and it is not atomic.** The volume must already exist. Restore empties it first (it
keeps its id, name and labels) and then extracts the archive; nothing is merged. Restore has two phases:

- **A refusal before extraction starts leaves the volume untouched and carries no `volume_emptied` key.** Besides the
  request checks below, this covers a body that the server can see is bad while it decodes the first block of it (up to
  1 MiB of decompressed data): empty, not gzip, a gzip header, deflate or CRC error, no data. A gzip CRC is only
  checked at the end of the stream, so a small archive (it arrives in the first chunks and decompresses to at most 1 MiB)
  with a bad CRC is refused in this phase (422, the volume keeps its content), while a larger archive with the same
  corruption is found only at its end, in the second phase. This early rejection is intentional.
- **Once the restore has begun, any failure leaves the volume empty and says so:** `error.details.volume_emptied` is
  `true`. A tar the policy refuses, a duplicate path, an unreadable or cut-short tar are always in this phase,
  and so is a body that grows past the size limit while it is extracted. (`volume_emptied` is `false` only if emptying itself failed.)

Export a copy before you restore over data you care about. To recover from a failed restore, restore again or restore
from an earlier export.

- **Refused before anything is changed:** a sandbox that is not deleted still mounts the volume (409, `details.reason`
  `in_use`; stop and delete those sandboxes first); another restore of the volume is running (409 `restore_in_progress`);
  the body is empty, not gzip, or holds no data, or shows a gzip error in its first decoded block (422, no `volume_emptied` key); a `Content-Length` above 256 MiB (413). A key that sees the volume
  only through `shared_volume_labels` gets 403 for both export and restore.
- **Size:** the compressed body is at most 256 MiB. The extracted data is counted and must stay within the volume's
  `max_bytes` (the soft limit above) when it has one: over it is 413 and the volume is left empty. Whatever the limit, the extracted data
  may also be at most 64 times the compressed size (never below 16 MiB): a body that expands more is 413 and the volume is left
  empty. Your organization's quotas are not consulted by export or restore.
- **Permissions and ownership** are kept as the tar records them: mode (setuid, setgid and sticky bits included), uid,
  gid and modification time. Extended attributes are not restored.
- **What a restore accepts:** regular files, directories, and symlinks whose target is relative and stays inside the
  volume. Anything else answers 422 with `error.details.reason` `forbidden_entry`, `details.violation` and `details.entry`
  (the member name), and leaves the volume empty. The violations are `path_traversal` (a `..` in a name), `absolute_path`,
  `invalid_name` (also a control character in a name), `invalid_link_target`, `hardlink`, `symlink_absolute`, `symlink_escape`, `symlink_through` (a member below a symlink of the
  archive), `duplicate_entry` (a second member whose normalised path equals an earlier member's, whatever the types: two files of one name, `./a` after `a`; the first is never overwritten), `special_file` (devices and FIFOs), `unsupported_entry`, `header_too_large` (an extended tar header over 1 MiB) and `too_many_entries` (over 100000 members). A tar that is corrupt, cut
  short, or has data after its end marker is a 422 `the archive is not a readable tar`, also with the volume emptied (the tar is read only after the volume was emptied, so these are always second-phase failures).
- **A round trip can fail.** Export copies whatever the volume holds, but restore applies the rules above. A volume
  that contains an absolute symlink (a Python venv's `bin/python -> /usr/bin/python3`, for example) or a hard link
  exports fine, and restoring that archive is refused with 422 naming the entry. Use relative symlinks if you need to
  restore the archive.
- **Export is not a point-in-time copy** when a running sandbox is writing to the volume: files can change while the
  tar is read. Stop the sandboxes first if you need a consistent copy. The archive has no checksum, and a download that
  fails midway ends early, so check it (`gzip -t dataset.tar.gz`) before you rely on it. A restore that starts while an
  export of the same volume still streams is refused with 409. Each organization can run 2 exports or restores at once,
  the server 8; over that is 409 `org_transfer_limit` or `transfer_limit`: retry when one finishes.
- **Known race:** the check that no sandbox mounts the volume happens at the start of the restore. A sandbox you create
  during the restore can still mount the volume, so do not create sandboxes that mount it until the restore returns.
- The TypeScript SDK does not have these calls; use REST.

### Naming rules

A name that breaks a rule answers 422 and the message names the rule. The rules differ by what
you name: names and hosts are ASCII only, labels are not.

- **Sandbox and volume names.** 1 to 63 characters that match `^[A-Za-z0-9][A-Za-z0-9_.-]*$`:
  an ASCII letter or digit first, then ASCII letters, digits, `_`, `.` and `-`. No spaces and
  no letters of other scripts. The sandbox name is optional on create.
- **Egress host names** (`egress_allowlist`). Each entry is a lowercase ASCII host name.
  Write an international name in its IDNA `xn--` form. A leading `.` covers the domain and all
  its subdomains. Split at the dots, each label is 1 to 63 characters that match
  `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?` (lowercase letters, digits and inner hyphens), and the
  name is at most 253 characters without the leading dot. Nothing is normalised: uppercase, a
  trailing dot or surrounding space is refused. An entry may not hold a scheme, a path (`/`,
  `?`, `#`), a port, a `*` wildcard or an IP literal (a last label made of digits or `0x` and
  hex digits). To allow an address range, write a CIDR entry instead (an entry with a `/`,
  such as `140.82.112.0/20`): it must already be canonical (compressed lowercase IPv6, no
  leading zeros), name the network address (no host bits set), have a prefix of at least `/8`
  for IPv4 or `/32` for IPv6, be entirely global (no loopback, private, shared, link-local,
  multicast, reserved or documentation addresses) and not overlap the server's denied
  networks (`SANDFORT_EGRESS_DENIED_CIDRS`). The proxy admits an IP-literal target only
  through a CIDR entry, and a CIDR entry never admits a host name. Host names, leading-dot
  domains and CIDR entries can be mixed in one list. A list takes at most 16 entries (the server setting
  `SANDFORT_EGRESS_ALLOWLIST_MAX_ENTRIES`; read the beta's value from the 422 message), and
  an empty list is valid but cannot be combined with `block_network`.
- **Labels** (sandboxes and volumes; the same rules for both). Any script is accepted, not only
  ASCII. At most 32 labels. A key is at most 63 code points and a value at most 256 code
  points. The limits count Unicode code points, not bytes, so a key of 63 Cyrillic letters
  fits. A key must show something: it is refused when it holds a control character (tab and
  newline included), or when it is only whitespace, invisible format characters (such as the
  zero-width space) or blank-looking fillers (such as the Hangul filler or the braille blank).
  Whitespace between visible characters is accepted. A value is only checked for length. A key
  that starts with `sandfort.` is reserved and answers 422 with the code `RESERVED_LABEL`.
- **Mount paths.** At most 255 characters, absolute and normalised: they start with `/`, with no
  trailing slash, no `//`, no `.` or `..` segment, no control or invisible characters and no line or
  paragraph separator. They may not contain a colon, a comma or a backslash, because Docker reads
  those as separators in a bind string; the message names the character. They stay outside the
  system directories: `/bin`, `/boot`, `/dev`, `/etc`, `/lib`, `/lib64`, `/proc`, `/root`, `/run`,
  `/sbin`, `/sys`, `/usr`, `/var`, `/var/run` and `/` itself. They stay outside anything under
  `/proc`, `/sys`, `/dev` and `/boot`. They also stay outside the binary trees at any depth: `/bin`,
  `/sbin`, `/lib`, `/lib32`, `/lib64`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/lib32`,
  `/usr/lib64` and `/usr/libexec`. The files Docker manages and the account files are refused as
  exact paths: `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`, `/etc/passwd`, `/etc/group` and
  `/etc/shadow`. See "Volumes" for the other rules (the number of mounts, read-only mounts).

### Long-running commands and the exec timeout

A plain blocking `process_exec` or `code_run` has a default timeout of 60 seconds. When it is exceeded
the command is killed, `exit_code` is `124` and `timed_out` is `True`; the result still carries
whatever output the command produced before it was killed. Raise the limit with `timeout_s`, for
example `sbx.process_exec("make build", timeout_s=300)`, and use the async session route below for
long work. If the client of a blocking exec (`process_exec` or `code_run`) disconnects, the server
cancels the exec and kills its process tree; it checks every 0.5 s. Work that should outlive the
client belongs on the async session route.

For long work and dev servers, start the command in the background with
`sbx.process.start(command, ...)`. It creates a session (or reuses `session_id=`), runs the
command asynchronously and returns a handle with `info()`, `logs()`, `follow()`, `kill()` and
`wait()`. Used as `with` (or `async with` on `AsyncSandbox`), the handle kills the command on
exit if it is still running. This replaces `create_session` +
`execute_session_command(run_async=True)` + `kill_command`; those calls still work. Without
`timeout_s` the command gets the 60 s default budget, so pass a larger one for a dev server:

```python
# A dev server for a preview URL; it is killed when the with block ends.
with sbx.process.start("python -m http.server 8000", cwd="/tmp", timeout_s=1800) as server:
    print(sbx.preview(8000).url)
    input("open the URL, then press Enter to stop the server")

# Long work: follow the log until the command exits, or poll with wait().
job = sbx.process.start("sleep 90; echo done", timeout_s=1800)
with job.follow() as stream:                              # stream until exit
    for event in stream:
        print(event.stream, event.line, event.exit_code)
info = job.wait(timeout_s=30)                             # polls until it is not running
print(info.state, info.exit_code)                         # exited 0
```

**Auto-stop does not wait for a running command or cell.** `auto_stop_minutes` (default 15) counts
the time since the last toolbox request to the sandbox; a request that is still running does not
renew it. When that time passes, the sandbox is stopped even though a cell or a command is still
running. A cell or command that runs longer than the auto-stop window, with no other toolbox
call in between, is therefore killed: the result has exit code 137, `sandbox_stopped` true and
`stop_reason` `sandbox_stopped`. For long work, set `auto_stop_minutes` larger than the longest
run (a value of 0 or less turns auto-stop off), or make a short toolbox call, such as a `stat`,
now and then. After the stop, `start()` brings the sandbox back with its files (see "Recovering
after `sandbox_stopped`").

An async command keeps running when a log follower disconnects. `job.kill()` stops a running
command; `job.session_id` and `job.command_id` are the ids the CLI's `cmd logs` and `cmd kill`
take.

**Process sessions.** A session wraps each command in its own `sh -c`, so only two things carry
from one command to the next. The working directory does: the directory the command ended in
becomes the session's directory for the next one (a command that fails to `cd` leaves it
unchanged). Shell state does not: a variable you `export`, an alias or a shell function is gone
when the command ends. Only the `env` you gave when the session was created is set for every
command, so put what you need there or set it in each command. When commands of one session
run at the same time, the one that finishes last decides the directory.

Clean up in this order: a sandbox started from a snapshot must be deleted before the snapshot itself.
Deleting a snapshot that a sandbox still uses returns a 409 conflict.

```python
for box in (sbx, again):
    box.delete()                    # a running sandbox can be deleted; no stop needed
client.snapshots.delete(snap.id)    # last, after every sandbox started from it is gone
client.close()
```

### Data analysis

The default `python:3.12-slim` image has no pandas, numpy or matplotlib. A `pip install` of them
takes about a minute on the shared beta (50.9 s when last measured), and a reset clears it
again, so do not install per run. Prepare the environment once and start sandboxes from it:

- **Declarative image:** describe it with the SDK's `Image` DSL and build it with
  `client.snapshots.build(...)`. The build returns a `pending` snapshot (or a `ready` one when an
  identical spec was built before); poll `client.snapshots.get(snap.id)` until its state is
  `ready`, then pass the snapshot id as `snapshot=`.
- **Snapshot after setup:** install into one sandbox, then
  `client.snapshots.create_from_sandbox(sbx.id, "pandas", wait=True)` (see Snapshots above).

```python
import time
from sandfort_sdk.image import Image

spec = Image.debian_slim().pip_install("pandas", "numpy", "matplotlib").workdir("/work")
snap = client.snapshots.build(spec, name="analysis")
while snap.state == "pending":
    time.sleep(2)
    snap = client.snapshots.get(snap.id)
if snap.state != "ready":                    # "error": read client.snapshots.follow_build_logs
    raise RuntimeError(f"image build {snap.id} ended {snap.state}")
box = client.create_sandbox(name="analysis", snapshot=snap.id, wait=True)
```

A build creates an unlabelled snapshot that every label scope shares: any key in the organization
sees and uses it, and an identical spec built by another scope's key is returned as `reused: true`.
A label-scoped key cannot delete a built snapshot.

A failed build does not show the registry's own text. If the base image (the first `FROM`) is
refused, the last line of the build log and the build error both read "image build failed: the
registry refused to pull <image>; check the image name and the registry access". If the registry
cannot be reached, they start with "image build failed: could not pull <image>: ". A failed build
step reads "image build failed: a build step exited with a non-zero code", and any other failure
"image build failed: the Docker daemon could not complete the build". Neither of the last two
names the step or points to the build log; read the log lines above the last one.

What a label-scoped key sees in the build log: the lines are the builder's own, with the image
identifiers the builder prints replaced by the placeholder "the built image". That covers the
internal tag `sandfort-snapshot:<id>` and the id after "Successfully built". It covers the 12-hex
ids the classic builder prints after " ---> ", after "Running in " and after "Removing intermediate
container " or "Removed intermediate container ". The live builder prints the past tense. It covers
a `sha256:<64 hex>` digest and the image named on a "writing image" line. It also covers the same
identifiers in the `reason` of the final `state` event, whose `digest` is `null`. Your own lines are
unchanged. So git SHAs, bare hex ids and `--hash=sha256:...` values that your build steps print stay
as they are. There is one exception. A `sha256:<64 hex>` that your own line prints is also replaced
for a label-scoped key. An example is a pinned digest in an `ENV` value. It is not replaced when it
follows `=` or a word character. A key without labels sees the whole log. Both kinds of key see the
build steps echoed, `ENV` values included, so an image spec must not carry secrets.

Each `code_run` is a fresh process: files written in the sandbox persist between runs, variables
do not. `code_run` runs in the sandbox's working directory, so relative paths in the code read and
write there (for the image above, `/work`). When one step should see the variables, imports and
loaded data of the earlier steps, as in a notebook, use a code context instead.

#### Code contexts: state that survives between runs

`sbx.code_contexts.create()` starts a Python kernel inside a started sandbox. `ctx.run(code)`
executes a cell in it, and what earlier cells defined is still there:

```python
box.fs.upload_file("/work/sales.csv", open("sales.csv", "rb").read())
ctx = box.code_contexts.create(cwd="/work")          # cwd is optional

ctx.run("import pandas as pd\ndf = pd.read_csv('sales.csv')")           # loaded once
res = ctx.run("df['amount'].sum()")                                     # reuses df
print(res.stdout)                                    # the repr of the trailing expression, e.g. 1234.5
ctx.run("by_region = df.groupby('region')['amount'].sum()\nprint(by_region)")

slow = ctx.run("while True: pass", timeout_s=5)      # one cell over its limit ...
print(slow.timed_out, slow.exit_code)                # True 124
print(ctx.run("len(df)").stdout)                     # ... and df is still there
ctx.delete()                                         # kill the kernel; its state is gone
```

How it behaves:

- Only Python, and the sandbox image must have `python3`; otherwise the create is refused.
- The result is a `CellResult` (SDK) with every `ExecResult` field of `code_run` (`stdout`,
  `stderr`, `exit_code`, `stop_reason`, ...) plus two more. `result` is the `repr` of the cell's
  trailing expression, or `None` when the cell has none, when the expression is `None`, or when the
  cell raised. `error` is `None` unless the cell raised; then it holds `type` (the exception class
  name) and `message` (its `str()`), and that includes `TimeoutError` and `KeyboardInterrupt`. The
  same two fields are in the REST response as `result` and `error` (`{"type", "message"}`).
  `result`, the error type and the error message are each cut to 4096 characters and end in `...
  [truncated]` when longer; the printed `repr` in `stdout` is not cut. A cell that raises exits 1.
  Its traceback names the cell as `<cell-N>`, a number that grows with every cell of that context.
  It shows the offending source line. So a function defined in an earlier cell shows its own source
  line when a later cell calls it. The source of the last 100 cells is kept. A syntax error names
  `<cell>`. A trailing expression is also printed like in a notebook (its `repr`), so
  `df['amount'].sum()` needs no `print`.
- The context's working directory is first on `sys.path`, as in `code_run`: a module file
  written there imports from a cell. The kernel's own files are not importable from cells.
- Each cell has its own `timeout_s` (default 60 s). A cell that does not finish ends in one of
  three ways, in this order:
  1. Its own `timeout_s` fires inside the kernel when control is back in Python and raises
     `TimeoutError`; the result has `timed_out` true and exit code 124, and the kernel keeps its
     state.
  2. An interrupt (`ctx.interrupt()`) does the same at once when it can. A cell can get stuck in
     native code, such as a long C call or a ctypes sleep, and never return to Python. It does not
     stop but goes on. Later runs on the context queue behind it, each for up to its own
     `timeout_s`. This lasts until the cell ends at 1 or 3. An interrupt never removes the context.
  3. Only when the run's exec deadline (`timeout_s` plus a 5 s margin) passes with the cell still
     not answering is the kernel sent an interrupt and given 2 s. A kernel that answers keeps its
     context, and the run ends with `stop_reason` `timeout`. So does a check of the kernel that is
     slow or fails (it times out, returns an unexpected exit code or a driver error), and a removal
     that fails: a slow or failed check never removes a healthy context. A kernel that is found to
     be gone, or that stays silent after the 2 s, is stopped and its context removed; only that run
     answers `stop_reason` `context_lost`, so the status is reported only when the context was
     really removed. It comes with `timed_out` true and exit code 124 still set and a stderr line
     saying the context was stopped. That run's stderr says "the cell exceeded its N s limit and the
     kernel did not stop when interrupted; its state is lost". N is the cell's own `timeout_s`, not
     the longer exec deadline. After that comes "the context was stopped because the cell did not
     return; create a new context". Do not retry the same context: create a new one, because later
     runs on its id answer 404, which the SDK raises as `NotFound`. `DELETE` removes a context at
     once, with no grace.
- **Interrupt.** `ctx.interrupt()` (REST: `POST
  /v1/sandboxes/{id}/toolbox/code-contexts/{context_id}/interrupt`, scope `toolbox:use`) sends
  SIGINT to the kernel. What it guarantees: a running cell raises `KeyboardInterrupt` in Python
  code, which is a cell error, and the state stays; between cells there is nothing to interrupt. What it does
  not guarantee: it names no cell, so it interrupts whichever cell is running at that moment,
  and it cannot stop a cell that is stuck in native code (a long C call that never returns to
  Python). Such a cell goes on and later runs queue behind it, as described in the item above;
  an interrupt never stops the kernel or removes the context. It returns `True` when a cell was running and the kernel was sent the interrupt,
  and `False` when no cell is running (between cells) or the context has no live kernel (REST:
  `interrupted`). The async handle has `await ctx.interrupt()`.
  Each interrupt is audited as `toolbox.code_contexts.interrupt`.
- **A cancelled or disconnected run interrupts its own cell only.** A client can go away in two
  ways: the connection drops, or the awaiting task is cancelled with the async client. Then the
  server interrupts the cell of that run. It waits up to 2 s for the cell to end before the next run
  starts. Each run has a cell number that the kernel checks, so this interrupt never stops a later
  run's cell; if it arrives before the kernel began the cell, the kernel skips the cell and the run
  ends as an interrupted cell. A run that hits the output limit (`stop_reason` `output_limit`)
  interrupts its own cell the same way; the context and its state are kept, and the result reports
  `exit_code` 137 whichever stream overflowed. The limit for a context run is 1 MiB minus 64 KiB of
  `stdout`, which leaves room for `result` and `error`. If the interrupted cell is stuck in native
  code and does not end in those 2 s, it keeps running and the next run queues behind it, as
  described under Interrupt.
- **Lost contexts.** The state lives in the kernel process. It is lost when the sandbox is
  stopped, reset or deleted, and when a cell kills the kernel itself (for example `os._exit`).
  Auto-stop stops the sandbox, so it loses the contexts too: the default `auto_stop_minutes` is
  15 idle minutes, so a sandbox that nobody uses for that long loses its contexts even if you
  never stop it. Auto-stop does not wait for a running cell either; see "Auto-stop does not wait
  for a running command or cell" above. After the sandbox is started again, a run on the old context id answers 404
  and the SDK raises `NotFound`; while it is stopped the call answers 409. Files written to
  disk are not affected by any of this, so write results you need to keep to files, for example
  a parquet or CSV file, and create a new context after a restart.
- **Stop reasons of a context run.** Besides the ones of `code_run`, a run can end with
  `context_lost` or `queue_timeout`. `context_lost` means one of three things. The kernel died or
  closed the connection during the run. Or the context was deleted mid-run. Or a stuck cell's kernel
  was stopped and its context removed after the exec deadline and the 2 s grace. In the last case
  `timed_out` and exit code 124 stay set. The SDK type `StopReason` lists it. `queue_timeout` is
  described in the next item. `context_lost` is reported only when the context was really removed;
  when the kernel answers the interrupt, or the check of the kernel is slow or fails, the context is
  kept and the run reports `timeout`. A run that ends in `context_lost` after the exec deadline
  reports it instead of `timeout`, so code that checks only for `timeout` must check `context_lost`
  too. On `context_lost` do not retry the same context: its state is gone and its id answers 404, so
  create a new context.
- **A stop during a run is reported as a stop, not as a limit.** A sandbox can be stopped while a
  cell runs, by your `stop()` or by auto-stop. Its container can also be gone. Then the run ends
  with `stop_reason` `sandbox_stopped`, `exit_code` 137, `timed_out` false and `sandbox_stopped`
  true, not `timeout`. When the caller or auto-stop stopped the sandbox, stderr reads "the sandbox
  was stopped while the cell was running; the context is gone, create or ensure a new one". When the
  container no longer exists, stderr reads "the sandbox container is gone; ...". The sandbox may
  have died under a resource limit, for example an out-of-memory kill. Its main process may also
  have ended. In both cases stderr keeps the limit wording, and the sandbox is not called "stopped".
  A cell ended by a delete or a reset of the sandbox names the cell too. For a delete the text is
  "the sandbox was deleted while the cell was running". For a reset it is "the sandbox was reset
  while the cell was running; the context is gone, create or ensure a new one". The `stop_reason` is
  `sandbox_deleted` or `sandbox_reset`. The container-gone line appears once. The context is gone
  with the kernel: start the sandbox and call `ensure` again, then run the setup cells. A streamed
  run ends the same way: with a normal `result` event that carries `stop_reason` `sandbox_stopped`,
  not an `error` event, and the SDK raises nothing (see "Streaming a cell" below). A driver failure
  that the run could not turn into a result is still sent as an `error` event; one that means the
  sandbox is no longer running carries the code of a 409 conflict and `stop_reason`
  `sandbox_stopped`, any other stays a generic internal error. The message of that `error` event is
  chosen from the sandbox row, like the stderr of a result. It is one of four texts. The first is
  the container-gone sentence. The second is the stop sentence, used only when the caller or
  auto-stop stopped the sandbox. The third is a delete or reset line that names the cell. It is used
  when the row shows a delete or a reset. The delete line is "the sandbox was deleted while the cell
  was running". The reset line is "the sandbox was reset while the cell was running; the context is
  gone, create or ensure a new one". The fourth is the limit wording, used in all other cases. The
  code and `stop_reason` of the `error` event stay the same; only the message differs. `exec` and
  `code_run` report a stop the same way: when a caller or auto-stop stopped the sandbox, stderr says
  "the sandbox was stopped while the command was running; start it again"; a death under a resource
  limit keeps the limit wording. `stop_reason` is `sandbox_stopped` in both cases, and the stderr
  sentence says which. The stop wording on `exec`, `code_run` and streamed runs, including the
  delete and reset wordings that name the cell and the wording of the streamed `error` event, is the
  current behaviour of the hosted beta.
- Cells of one context run one at a time. When you start runs in parallel on one context, they queue
  and run one after the other, in the order the requests reach the server. There is no ordering
  guarantee within a single `asyncio.gather` (or any batch of parallel calls), because the order in
  which those requests arrive is not fixed; send cells that depend on each other one after the
  other, or use one context per independent line of work. Parallel cells on one sandbox share one
  kernel host, so use a pool of sandboxes for parallel work. A run can wait longer than its own
  `timeout_s` for the earlier one. Then it answers `timed_out` true with exit code 124 and
  `stop_reason` `queue_timeout`. It has one stderr line saying another run on this context was still
  executing. The run never started. The context and its state are kept, so send that cell again.
- **Plots.** There are no inline images. Write the figure to a file with `plt.savefig(...)` and
  download it:

  ```python
  ctx.run("import matplotlib\nmatplotlib.use('Agg')\nimport matplotlib.pyplot as plt\n"
          "plt.plot([1, 2, 3])\nplt.savefig('/work/plot.png')")
  png = box.fs.read_bytes("/work/plot.png")           # the PNG as bytes
  ```
- **Cells that print a lot.** Output is buffered: the kernel collects the writes of each stream and
  sends them as one chunk every 50 ms, when the collected text reaches 64 KiB, and at the end of the
  cell. A loop of small `print` calls therefore does not cost a round trip per line, and the order
  within a stream is exact (across `stdout` and `stderr` it is approximate). A loop of many small
  `print` calls still takes about ten times as long as the same loop under `code_run`. `ctx.run`
  does not stream: the output arrives with the result; `run_stream` yields the output as it is
  written (see "Streaming a cell" below). When a run hits the output limit, the notice that says so
  starts on its own line in `stderr`.
- `multiprocessing` inside a context needs the `fork` start method. With `spawn` and `forkserver`,
  the children cannot find functions defined in cells (as in notebooks), so the cell hangs until its
  `timeout_s` runs out instead of failing at once. When a cell times out or is interrupted while
  such children are alive, `error.message` ends with a hint line. The same line is the last line of
  `stderr`. The hint is "hint: functions defined in cells are not importable by spawn/forkserver
  children; use multiprocessing.get_context("fork") or put the function in a module file". The hint
  explains the hang; it does not prevent it. Ask for the fork context explicitly:

  ```python
  ctx.run("""
  import multiprocessing

  def square(x):
      return x * x

  with multiprocessing.get_context("fork").Pool(2) as pool:
      print(pool.map(square, [1, 2, 3]))
  """)
  ```
- `sbx.code_contexts.list()` returns the live contexts of the sandbox. The REST routes are under
  `/v1/sandboxes/{id}/toolbox/code-contexts` (create, list, delete, `run` and `interrupt`) and
  need `toolbox:use`.
- `with sbx.code_contexts.create() as ctx:` (or `async with`) deletes the kernel when the block
  ends; a context that is gone already is ignored.

##### Named contexts

A context can carry a name, unique among the live contexts of its sandbox. The name follows the
character rules of sandbox names (letters, digits, `_`, `.`, `-`, starting with a letter or digit,
at most 63 characters). `ensure` returns the live context of that name, or starts one:

```python
ctx = sbx.code_contexts.ensure("analysis", cwd="/work")   # async: await ...ensure(...)
ctx.run("import pandas as pd\ndf = pd.read_csv('sales.csv')")
print(ctx.name)                                           # analysis
```

- One idempotent call: run it at the start of every step instead of keeping the context id.
  `cwd` is used only when a context is created; it is not compared with the live one. `create(name=...)` does the same, and
  `ctx.name` is `None` for an unnamed context.
- `ctx.created` (read-only, on `CodeContext` and `AsyncCodeContext`) says which happened: `True`
  when the call started the kernel, so run the setup cells, and `False` when it found a live
  context of that name (`create()` without a name is always `True`; a context from `list()` is
  `False`). A named `create` or `ensure` is resent after a 429 `RATE_LIMITED` like any other
  call.
- A call on a context whose kernel is gone raises `NoContainer` (the sandbox is stopped) or
  `NotFound` (the context or the sandbox was deleted). `CONTEXT_GONE_ERRORS`, exported from the
  package root, is that pair `(NoContainer, NotFound)`, so one `except` covers both:

  ```python
  from sandfort_sdk import CONTEXT_GONE_ERRORS

  ctx = sbx.code_contexts.ensure("analysis", cwd="/work")
  if ctx.created:                      # a new, empty kernel: run the setup
      ctx.run("import pandas as pd\ndf = pd.read_csv('sales.csv')")
  try:
      ctx.run("df.describe()")
  except CONTEXT_GONE_ERRORS:
      ...                              # start the sandbox if needed, then ensure() again
  ```

  Both classes carry a typed `state` attribute (`str | None`), so `except CONTEXT_GONE_ERRORS as
  exc` can read `exc.state` under a strict type checker. `NoContainer.state` is the sandbox state
  the server reported in `details["state"]` (for example `stopped`), or `None` when it sent none.
  `NotFound.state` is always `None`: a not-found answer carries no sandbox state. Read the state
  from `NoContainer` only, or treat `None` as "the context or the sandbox is gone". Catching the
  base `ApiError` and reading `exc.details.get("state")` still works as an alternative.
- A memory overrun in a cell stops the whole sandbox on the `gvisor` tier (the default), so
  all of its contexts and their variables are gone, not only the one that ran the cell. The cell
  answers `stop_reason` `sandbox_stopped` (or `oom_killed` when the server could see the kill)
  and its stderr says the context and its variables are gone. Recover in this order: start the
  sandbox, `ensure()` the context again, check `created` (it is `True`: the kernel is new and
  empty), and reload the data from files, as in the example above. Keep the loading code in one
  place that runs whenever `created` is `True`.
- REST: `POST .../code-contexts` takes `name`; it answers 200 with the existing context when a
  live context has that name, and 201 for a new one. The 200 reply carries the `cwd` of the
  existing context: the `cwd` of the request is ignored, not compared. If the live contexts cannot
  be read (a driver failure), the create fails instead of starting a context, so a transient
  error does not leave two contexts with one name. `GET .../code-contexts?name=<name>` lists only
  the context of that name (an empty list when there is none).
- **The state is still lost on restart.** A named context lives in the kernel process like any
  other. After the sandbox was stopped (auto-stop included), reset or deleted and started again,
  `ensure` brings back a context with the same name, but empty: variables, imports and loaded
  data are gone, so run the setup cells again. Files on disk are unaffected.
- Two named creates of the same name in one sandbox take turns on a lock in the server process
  (the second waits up to 30 s, then answers 409 `in_progress`), so two concurrent `ensure` calls
  handled by that process get the same context. **Uniqueness is per API process only:** there is
  no stored constraint, so two creates of one name that race across different server processes
  may both succeed. Not tested: this race with more than one server process.

##### Streaming a cell

`ctx.run_stream(code, timeout_s=60)` runs a cell like `run`, but yields the output as it is
written: an `OutputChunk` (`stream` is `"stdout"` or `"stderr"`, `data` is the text) for each
output event, then the same `CellResult` that `run` returns as the last item.

```python
from sandfort_sdk import CellResult

for event in ctx.run_stream("for i in range(3): print(i)\n42"):
    if isinstance(event, CellResult):
        print("result:", event.result, "exit:", event.exit_code)    # result: 42 exit: 0
    else:
        print(event.stream, event.data, end="")                      # stdout 0 ...

# async: stream = await ctx.run_stream(code); async for event in stream: ...
```

- Errors before the stream starts (`NotFound`, `NoContainer`, `ValidationFailed`) are raised by the
  `run_stream` call itself, as `run` raises them. A stream that ends without a result, or whose read
  breaks off, raises `TransportError`; it and `InvalidResponseError` from a stream carry
  `request_id`, the `x-request-id` of the stream response (`None` when it had none).
- Close the stream, or use `with` (async: `async with`), to stop reading early.
- There is no separate queue timeout: a run that waits for another run of the same context gives
  up after its own `timeout_s`.
- REST: `POST /v1/sandboxes/{id}/toolbox/code-contexts/{context_id}/run/stream` takes the body of
  `run` and answers `text/event-stream` with `stdout` and `stderr` events (`data: {"data": <text>}`),
  then one final `result` event that carries the object `run` answers (the complete `stdout` and
  `stderr`, `exit_code`, `result`, `error`, ...). A sandbox that is stopped during a streamed run
  ends the stream with a normal `result` event that carries `stop_reason` `sandbox_stopped` (not an
  `error` event); the SDK raises nothing and the final `CellResult` has `stop_reason`
  `"sandbox_stopped"`. A dedicated `error` event (`code`, `message`, and `stop_reason` when the
  driver failure means the sandbox is no longer running) is reserved for server-side failures
  after the stream has started, and takes the place of `result`. An unknown context or a sandbox that is
  not started is refused with the usual error response before the stream starts. It needs
  `toolbox:use`, like `run`.
- Order within one stream is exact. Order across `stdout` and `stderr` is approximate: the kernel
  batches the writes of each stream (about 50 ms or 64 KiB), so interleaved prints can arrive
  stream by stream instead of strictly interleaved.
- `stdout` streams whole lines. The server holds back the last line until its newline arrives or the
  run ends. So some output arrives late. This includes a partial line, a prompt without a newline,
  and a progress bar that redraws itself with carriage returns (`\r`) and no newline. It arrives
  when the next newline is written or when the run ends, not as it is drawn. `stderr` is forwarded
  as it arrives. The final `result` event still holds the complete `stdout` and `stderr`. The
  `stderr` events, joined, equal the `stderr` of the `result` event in every ending. This holds for
  a stop, for a delete or a reset of the sandbox, and for the sentence a timeout adds. The sentence
  that names the ending is the last `stderr` chunk, sent just before `result`.
- An `error` event raises the matching SDK exception from the iteration. Since the stream answer
  itself was a 200, the exception has `status_code` 200. It has the `request_id` of the stream
  response, so quote it in a report. `details` is the event's `details` object. When the event had
  none, `details` is `{}` and `has_details` is `False`. `details` is always a dict, never `None`.
  The same holds for an error reply without details.
- The value of a trailing expression arrives twice: the cell prints it, so it is the last
  `stdout` chunk, and it is also the `result` field of the `result` event. A client that prints
  both shows it twice; print one of them.
- Streaming is SDK and REST only. The command-line tool has no streaming command.

A blocking `code_run` or `process_exec` has a default timeout of 60 s; `timeout_s` goes up to
3600. For long jobs, start the command in the background and stream its output:

```python
job = box.process.start("python analyze.py", cwd="/work", timeout_s=3600)
with job.follow() as stream:
    for event in stream:
        print(event.line, end="")
info = job.wait(timeout_s=30)
print(info.state, info.exit_code)
```

### REST API

The SDK and CLI call the REST API under `/v1`. The spec is the repository file
`openapi/sandfort.v1.json` (not a site URL); the API reference on the docs site is generated from it.

- **Auth.** Every call sends `Authorization: Bearer <key>`. A missing or malformed header is 401.
- **Envelope.** JSON responses are `{success, data, error, meta}`. On success `data` holds the
  payload and `error` is `null`; on failure `data` is `null` and `error` is
  `{code, message, details, request_id}`. Streams (SSE, PTY), file downloads and the upload body
  are not wrapped in the envelope.
- **Request id.** Every response carries an `x-request-id` header, and the same value is
  `error.request_id` in an error. A client-supplied `X-Request-Id` (1-64 characters of
  `A-Za-z0-9._-`) is echoed back; when none is sent, or the id is empty, longer than 64 characters
  or has other characters, the server makes one (`req_` and 32 hex digits) and does not reject the
  request. Treat the id as an opaque string, and quote it
  when you report a problem (see "Reporting a problem").
- **Create.** `POST /v1/sandboxes` returns 201 when the sandbox is started on the beta, so no
  polling is needed. The SDK still polls if a server answers earlier.
- **Pagination.** List calls take `cursor` and `limit` (default 50, maximum 100). The response's
  `meta.next_cursor` is the cursor for the next page, or `null` on the last page.
- **Sort order.** `GET /v1/sandboxes?order=desc` lists the newest sandbox first; the default,
  `order=asc`, lists the oldest first. `next_cursor` continues in the chosen order, so send the
  same `order` on every page (`iter_sandboxes` does). Any other value answers 422. The Python
  SDK takes `order=` on `list_sandboxes` and `iter_sandboxes` (typed `SortOrder`, exported from
  `sandfort_sdk`), and the CLI has `sandbox list --order asc|desc`.
- **Create by snapshot name.** The `snapshot` field of `POST /v1/sandboxes` accepts a snapshot id,
  the name of one of your organization's snapshots, or an image reference; a snapshot name is used
  before an image of the same name.
- **Sandbox timestamps.** A sandbox object has `created_at` (never changes) and `updated_at`
  (moves forward when the record changes), both UTC in ISO 8601 with an offset. The Python SDK
  has them as `SandboxInfo.created_at` and `SandboxInfo.updated_at` (`None` when a server
  reports none), and `sandfort --json` sandbox output carries both as ISO 8601 strings. A third
  timestamp, `stopped_at`, is `null` unless the sandbox is `stopped`; it comes with `stop_cause`
  (see "Why a sandbox stopped" in section 3).
- **Audit window, filters and anchor.** `GET /v1/audit-events` takes `from` (inclusive) and `to`
  (exclusive) on the event time. It also takes `actor_id`, `action`, `target_id`, `request_id` and
  `outcome`. The `request_id` is the `X-Request-ID` of the request that wrote the row. Quote the id
  from a failed call to find its rows. The `outcome` is `success`, `denied` or `error`. The filters
  are exact matches and combine with AND. `GET /v1/audit-events/export` takes `from`, `to`,
  `request_id` and `outcome`, and `GET /v1/audit-events/verify` takes only `from_id`. When both
  `from` and `to` are given on the list or the export, `to` must be after `from`, else 422 with the
  code `UNPROCESSABLE`. Any other query parameter on these routes answers 422 with the code
  `VALIDATION_ERROR` and one entry in `details.errors` per unknown parameter, `{"type":
  "extra_forbidden", "loc": ["query", "requestid"], "msg": "Extra inputs are not permitted"}`
  (`type`, `loc` and `msg` only; the value you sent is not echoed. `?requestid=` is refused, not
  ignored; the message also lists the accepted parameters). The list is oldest first by default;
  `order=desc` lists newest first, and `next_cursor` continues in the chosen order, so send the same
  `order` on every page. `GET /v1/audit-events/verify?from_id=<audit event id>` verifies the chain
  from that event on instead of from the first one; see "Beta limits" for what that proves.
- **Unknown query parameters answer 422 on every list route.** Not only the audit routes do this.
  `GET /v1/sandboxes`, `/v1/isolation`, `/v1/snapshots`, `/v1/volumes`, `/v1/api-keys`,
  `/v1/webhooks`, `/v1/webhooks/{id}/deliveries`, `/v1/nodes`, `/v1/jobs` and `/v1/org/usage` refuse
  a query parameter they do not declare. They answer with the 422 `VALIDATION_ERROR` described
  above. There is one `extra_forbidden` entry per unknown name in `details.errors`, with `loc`
  `["query", name]`. The value is not echoed. The message lists the accepted parameters. A misspelt
  filter such as `?stat=started` is therefore refused, not ignored into an unfiltered 200. A
  single-value parameter that the route does declare and that is given twice (for example `status`)
  answers 422 "must be given once" on every route; only a parameter documented as repeatable, such
  as `label`, may repeat. The accepted set is per route: `cursor`, `limit` and `order` are accepted
  only where the route declares them. The check runs after authentication, so a call without a valid
  key still gets 401 or 403 first. The same 422 now covers `GET /v1/org/members`,
  `/v1/org/scim-tokens`, `/v1/org/quota` and `/v1/org/quota/recount`, and the toolbox list routes of
  a sandbox (the directory listing under `toolbox/fs`, the git status, the lists of PTYs, process
  sessions and code contexts). A drift test fails when a new `GET` route lacks the check. The check
  also covers `GET /v1/sandboxes/{id}`, where a misspelt `wait_for` or `timeout_s` now answers 422
  instead of silently returning without waiting, the sandbox log route (`GET
  /v1/sandboxes/{id}/logs`) the toolbox `fs/stat` and `fs/download` routes, and the two
  process-session command log routes (the list and the follow route). The SCIM resource routes under
  `/scim/v2/` stay RFC-lenient: they accept the RFC 7644 parameters (`filter`, `startIndex`,
  `count`). **Routes that have no filters accept unknown query parameters** and ignore them. The
  answer is a 200, not a 422. These routes are the get-by-id routes for snapshots, volumes, jobs,
  webhook endpoints, process sessions, commands and PTYs: `GET /v1/snapshots/{id}`,
  `/v1/volumes/{id}`, `/v1/jobs/{id}`, `/v1/webhooks/{id}`,
  `.../toolbox/process/sessions/{session_id}`, `.../sessions/{session_id}/commands/{command_id}` and
  `.../toolbox/pty/{pty_id}`. They also include the snapshot export (`GET
  /v1/snapshots/{id}/export`) and the image build log stream (`GET
  /v1/images/builds/{snapshot_id}/logs`). The list routes and the routes with filters or options
  listed above answer 422. `GET /v1/sandboxes/{id}` is on the 422 side because it takes `wait_for`
  and `timeout_s`. Do not rely on a misspelt parameter being refused on the routes that accept
  unknown ones.
- **Security headers.** Every answer of the API carries `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`, and JSON (and empty) answers also
  carry `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`. Pages the API serves
  as HTML keep their own policy. `/docs` (Swagger UI) and `/redoc` (Redoc) load pinned builds from
  `cdn.jsdelivr.net`. The builds are `swagger-ui-dist@5.17.14` and `redoc@2.2.0`. They load with
  Subresource Integrity hashes. The pages contain no inline script. The Swagger UI bootstrap is a
  same-origin script, `/docs/init.js`. The pages send their own page CSP. In it, `script-src` is
  `'self'` plus `cdn.jsdelivr.net`, and `'unsafe-inline'` is allowed for styles only. The pages
  request no favicon or fonts from a third-party host. `HEAD /v1/status` answers 200 with the
  headers of the `GET` answer and no body, for uptime probes; `HEAD` on `/docs`, `/redoc` and
  `/docs/init.js` does the same. The docs site and the landing page send `X-Content-Type-Options:
  nosniff`, `X-Frame-Options`, `Referrer-Policy` and a `Content-Security-Policy`, and their 404
  pages carry no nginx version. That also covers `/metrics` and `/console` on the API host, which
  are routed to the landing server. Other error pages made by the shared hosting proxy, for example
  a 404 for an unknown top-level path, come from the proxy, not from the application, so do not
  expect the error envelope or these headers on them; they may still show the proxy's defaults.
- **Upload.** `PUT /v1/sandboxes/{id}/toolbox/fs/upload?path=/abs/path` takes the file as the raw
  request body (`application/octet-stream`), not multipart and not base64. Send `Content-Length`
  (or `size_bytes`, plain decimal digits up to 268435456). When you send both they must match, else
  422 `UNPROCESSABLE` and nothing is written (see "Request text, numbers and names" below).
  A size over that cap, whether in `size_bytes` or in `Content-Length`, answers 413
  `PAYLOAD_TOO_LARGE` before the body is read, with `details` `{limit_bytes, size_bytes}`.
- **Download.** `GET .../toolbox/fs/download?path=...` of a file whose size is known carries
  `Content-Length` and, when the modification time is known too, a weak `ETag`, and answers
  `Accept-Ranges: bytes`. To resume an interrupted download, send one byte range, for example
  `Range: bytes=1048576-`: the answer is 206 with `Content-Range: bytes 1048576-<last>/<size>` and
  the `Content-Length` of that range. A range that starts at or past the end of the file answers 416
  `RANGE_NOT_SATISFIABLE` with `Content-Range: bytes */<size>`. Several ranges, another unit and a
  malformed value are ignored and the whole file is sent with 200. A directory tar answers
  `Accept-Ranges: none`. `HEAD` on the same path returns the same status and headers without a body;
  it accepts only the `path` query parameter. In the Python SDK, `sbx.fs.read_bytes(path,
  range=(start, end))` and `download_file(path, range=(start, end))` read part of a file.
- **Exec.** `POST .../toolbox/process/execute` and `.../code-run` answer 200 with the result even
  when the command exits non-zero; look at `exit_code`, `timed_out`, `truncated`,
  `sandbox_stopped` and `stop_reason`. An HTTP error means the call itself failed.
- **Followed logs (SSE).** `GET .../process/sessions/{session}/commands/{command}/logs/follow`
  answers `text/event-stream`. Each frame is an `event:` line, an `id:` line, a `data:` line with
  compact JSON, and a blank line:

  ```
  event: stdout
  id: 12
  data: {"stream":"stdout","offset":6,"line":"hello\n"}

  event: exit
  id: 12
  data: {"exit_code":0,"state":"exited","truncated":false}
  ```

  There is one `stdout` or `stderr` event per output chunk. Its `id` is the byte offset where the
  next chunk starts, so the `id` of the last frame you read is the resume point. The stream ends
  with one `exit` event whose `id` is the final offset. While idle the server sends a `: keepalive`
  comment about every 15 s. To resume, reconnect with `Last-Event-ID: <id>` (or `?offset=<id>`);
  the bytes you already read are not repeated. The sandbox log stream and the image build log
  stream use other event names and `id` meanings; they are described in the OpenAPI spec.
- **OpenAPI.** The spec declares the error responses (400, 401, 403, 404, 409, 422, 429, 500) with
  the error envelope, the binary operations (upload, download) and the SSE operations, and the
  served spec is the same document as the committed one. Operation ids are clean names.
- **400, 422 and the unprocessable code.** Three validation answers differ, so a client should not
  treat them alike:
  - The label filter of `GET /v1/sandboxes` (`?label=k=v`, repeatable) answers 422 with the code
    `VALIDATION_ERROR`, a message such as `label filter must be k=v, got 'x'` and `details.errors`,
    when a pair has no `=` or an empty key. A label key given twice with different values is 422
    too.
  - Request body and query type validation answers 422 with the code `VALIDATION_ERROR` and
    `details.errors`. It covers a wrong type, a missing or unknown field, and a body that is not
    valid JSON. `details.errors` is a list of `{type, loc, msg}` entries. These are the error type,
    the location as a list of strings, and the message. Examples of a location are `["body",
    "max_vcpus"]` and `["query", "since"]`. `details.errors` belongs to this code only. The
    `UNPROCESSABLE` answers below carry other `details` keys, not an `errors` list. An integer
    literal in a JSON body can have at most 64 digits; a longer one is 422 with the type
    `integer_too_long`. A body nested deeper than 64 levels is 422 with the type
    `nesting_too_deep`. A duplicate JSON key anywhere in a body is 422 (`duplicate key 'x' in the
    request body`), because the last value would otherwise win without a warning.
  - A bad environment variable name in a create answers 422 with a different code, `UNPROCESSABLE`,
    not `VALIDATION_ERROR`: the message is `invalid environment variable names` and `details.names`
    lists the offending names (a name must match `[A-Za-z_][A-Za-z0-9_]*`). Names that start with
    the reserved `SANDFORT_` prefix answer the same code with their own message and the names in
    `details.names`. The `names` list is used by only these cases. One is the environment variable
    names of a sandbox create. Another is the environment variable names of the toolbox calls that
    take an environment: process exec, code run, sessions and PTY. The last is the reserved label
    names of a create, with the message `label names starting with ... are reserved`. Other
    `UNPROCESSABLE` answers use their own keys, for example `field`, `path`, `requested` and
    `available` (an isolation tier), `mount_paths` or `supported`.

  Other answers that a client meets:

  - An `Idempotency-Key` that is empty or over 255 characters is 422 `VALIDATION_ERROR`, with
    the header as the location. The same header sent twice with different values is 422 too.
  - A body with an unsupported `Content-Type` (not `application/json`) is 415
    `UNSUPPORTED_MEDIA_TYPE`. An empty body, a file upload and SCIM are not affected.
  - Command info has `stop_cause` `sandbox_stopped` when a sandbox stop ended the command.
  - The `in_progress` 409 of an idempotent call has no `Retry-After` header: wait, then resend.
  - Exec, code-run and session create all honour `Idempotency-Key`. The SDK takes
    `idempotency_key` on `process.exec` and `process.create_session`, and the CLI has
    `sandfort exec --idempotency-key`.
  - A session can be deleted: `DELETE /v1/sandboxes/{id}/toolbox/process/sessions/{sid}`, in the
    SDK `process.delete_session(sid)`. It kills the running commands and removes the session.

  So read the code together with the status; `error.details` has a different shape in each case.
- **Request text, numbers and names (round 53).** Inputs that earlier builds stored badly or
  answered 500 for are now refused with a 422, or read back safely:
  - *NUL and lone surrogates in request text.* A string with a NUL character answers 422
    `VALIDATION_ERROR`. So does a string with a lone UTF-16 surrogate, such as the JSON escape
    `\ud800`. The answer has the usual `details.errors` shape, with `loc` naming where the text was.
    The `loc` is `["path"]`, `["query", "<name>"]` or `["body", ...]`. The types are `nul_in_string`
    or `surrogate_in_string`. The offending text is not echoed. It covers every query parameter name
    and value. A query string that is not valid percent-encoded UTF-8 gets the type `invalid_utf8`.
    It covers the URL path. See the next item for the raw-bytes check and the NUL case. It also
    covers every string in a JSON body, object keys included, at any depth. A body counts as JSON
    when its `Content-Type` is absent or names JSON; the raw upload body is never read, but its path
    and query are checked. The one exception is the `stdin` field of `POST
    .../toolbox/process/execute`, which may carry NUL (binary input); a lone surrogate is refused
    there too. The check runs before authentication and before the route, so nothing is stored or
    audited. A websocket handshake whose path or query holds a NUL or a lone surrogate is refused
    before the connection is accepted. In the code (`src/sandfort/api/text_guard.py`) a refused
    handshake gets the same 422 envelope only when the server supports the ASGI websocket
    denial-response extension; otherwise the connection is closed with the policy-violation code
    (1008). Observed on the hosted beta on 2026-11-10: the handshake is answered with HTTP 422 (the
    same envelope) for a refused path or query, and with HTTP 400 from the edge proxy for a NUL
    byte; neither is a websocket close code.
  - *The URL path (round 54).* Invalid UTF-8 or a percent-encoded lone surrogate in the URL path
    (`%FF`, `%ED%A0%80`) is refused before routing with the same 422 `VALIDATION_ERROR` envelope,
    `loc` `["path"]` and the type `invalid_utf8` (bad bytes) or `surrogate_in_string` (an encoded
    surrogate). Earlier builds decoded such a path with U+FFFD in place of each invalid byte and
    routed it as decoded. A NUL in the URL path is different on the hosted beta. The edge proxy in
    front of the application refuses it with a plain 400. This happens before the request reaches
    the application. So that answer is the proxy's own and not the JSON envelope. Do not parse it as
    one. Not tested: the percent-encoded form of a NUL in the path. The application's own check
    (`loc` `["path"]`, type `nul_in_string`) is what would answer a request that does reach it.
  - *Depth.* The guard parses a JSON body only when its raw bytes contain a NUL byte, or a `\u`
    escape for NUL (`\u0000`) or for a surrogate code point (`\ud800` to `\udfff`), or a UTF-8
    encoded surrogate. Such a body nested deeper than 64 levels of arrays and objects answers 422
    with the type `nesting_too_deep` and `loc` `["body"]`; a body nested exactly 64 levels deep is
    walked. A body with some other `\u` escape is also parsed when it has more than 64 opening
    brackets, so the depth rule covers it too. Any other body, however deep, is not parsed by the
    guard; the framework parses it as before. A body too deep for the JSON parser to read, on a
    route that reads a JSON body, answers 400 `HTTP_400` ("There was an error parsing the body"),
    not 422. A body the parser can read is validated by the route as usual. The guard does its
    parsing of large bodies (above 64 KiB) on its own small worker limit (4 threads), apart from
    the threads the routes use.
  - *Stored lone surrogates are read back as U+FFFD.* Text already stored that holds a lone
    surrogate is returned with the replacement character U+FFFD in its place, in JSON answers and
    in event streams (SSE), instead of a 500 or a broken stream. The stored value is not changed.
  - *Label filters and stored lone surrogates (round 54).* A sandbox row written before the
    round-53 guard may hold a NUL or a lone surrogate in its labels. A label filter (`labels` on the
    list routes and `--label` in `sandbox list`) used to fail the whole query on such a row. Now the row is excluded from every label-filtered result: it simply does
    not match, and the other rows are returned. A list without a label filter still shows it, with
    U+FFFD in place of the character. The operator repairs the rows with the admin command
    `python -m sandfort.admin_cli repair-labels`, which rewrites each lone surrogate and each NUL in
    the stored labels (keys and values) to U+FFFD, in every state including destroyed sandboxes.
    Its flags are `--org ORG_ID` (only that organization; the default is every organization; an
    unknown id is an error, exit 1) and `--dry-run` (report the rows, change nothing). It prints the
    id of each changed sandbox, then `repaired labels of N sandbox row(s)` (`would repair ...` on a
    dry run). A repaired key that collides with another key, repaired or genuine, gets further U+FFFD
    appended, so no pair is lost; a genuine key (one with nothing to repair) always keeps its name,
    wherever it sits in the labels. Only `labels` and the row version change; audit rows are not touched, so the audit hash
    chain stays byte-identical, and the repair is not itself audited. When a label filter skips rows,
    the server writes a warning to its log (`label filter skipped N row(s) of org ... with unreadable
    labels; run sandfort-admin repair-labels --org ...`), at most once per organization every 10
    minutes per server process. You do not run the command on the hosted beta; ask the maintainer if
    a label filter seems to miss a sandbox.
  - *Booleans on numeric fields.* A JSON `true` or `false` on a numeric field answers 422
    `VALIDATION_ERROR` with the type `number_not_bool` and the field in `loc`. Earlier builds read
    it as 1 or 0. This holds for the quota body fields `max_vcpus`, `max_memory_mib`, `max_disk_gib`
    and `max_sandboxes`. It also holds for the sandbox body fields `cpu_millicores`, `memory_mib`,
    `disk_gib`, `auto_stop_minutes` and `auto_delete_minutes`, on create, update and resize. Since
    round 54 the rule covers every numeric request field, not only those. It covers `max_sandboxes`
    of the API key create body, `size_bytes` of the fs upload body and `max_bytes` of the fs
    download body. It covers `depth` of the git clone body and `timeout_s` of process execute and
    code-run. It covers `rows` and `cols` of PTY create and resize.
  - *Visible names.* The name of an API key and every label key of a sandbox must contain a visible
    character and no control characters. This applies on create and update. A name made only of
    invisible format characters answers 422 `VALIDATION_ERROR`. Examples of such characters are zero
    width space, joiners, bidirectional controls and tag characters. A name with a control
    character, tab and newline included, answers 422 `VALIDATION_ERROR` too. A joiner between
    visible characters (an emoji sequence) and any non-ASCII script stay accepted. Label values are
    not checked by this rule. API key creation applies the same label-key rule to the keys of its
    `sandbox_labels` scope selector: a key that is only invisible characters, or has a control
    character, answers 422 `VALIDATION_ERROR` and no key is stored.
  - *Member display names (round 54).* `POST /v1/org/members` answers 422 `VALIDATION_ERROR` with
    `loc` `["body", "display_name"]` in three cases. The `display_name` is blank, meaning empty
    after trimming whitespace. Or it holds a control character. Or it holds nothing but whitespace
    and invisible format characters. The messages are "must not be blank" and "must contain a
    visible character, not only whitespace and invisible format characters". The `sandfort members
    add` command already refuses a blank display name locally (a usage error, see above); the server
    rule also covers a name of invisible characters and callers that skip the CLI. A name in any
    visible script is accepted.
  - *Usage period.* `GET /v1/org/usage` with `to` not after `from` answers 422 with the code
    `UNPROCESSABLE` and the message "`to` must be after `from`", like the audit export. It answered
    400 `VALIDATION_ERROR` before; a script that matched on 400 for this case must now expect 422.
  - *Git clone depth.* `depth` of a git clone is 1 to 1000000; a larger value answers 422
    `VALIDATION_ERROR`. Omit it for the full history.
  - *Upload size.* On `PUT .../toolbox/fs/upload`, a `size_bytes` that differs from `Content-Length`
    answers 422 `UNPROCESSABLE` before the body is read, with `declared_bytes` and `received_bytes`
    in `details`, and nothing is written. A body whose length differs from the declared size is also
    422. When both are sent they must match. Since round 54 the `size_bytes` query parameter is a
    strict bounded integer: plain decimal digits only, from 0 to 268435456 (256 MiB). A sign, a
    decimal point (`10.0`), an exponent, surrounding spaces or a larger value answers 422
    `VALIDATION_ERROR` (the digits-only rule has the type `int_parsing` and the message "Input should
    be a non-negative integer written as plain digits"); earlier builds read `10.0` and ` 10 ` as 10.
- **409 CONFLICT.** Every `CONFLICT` answer carries `error.details.reason`, a stable string; switch
  on it instead of parsing the message. The values:
  - `name_taken`: a sandbox with that name already exists in the organization.
  - `already_exists`: the object (member, external id, file, row id) already exists.
  - `concurrent_update`: another writer changed the row first; retry. `details.expected_version`
    is the version the write expected.
  - `no_container`: the sandbox has no running container instance for the call. `details.state`
    is set when the state is known, and `details.stop_cause` when the sandbox is `stopping` or
    `stopped` (`unknown` when no cause is stored; absent for a deleted sandbox). Exec, code-run,
    sessions, fs, git, PTY create and code contexts carry both; the sandbox logs route sends
    `details.state` only.
  - `in_progress`: the same work (idempotency key, snapshot) has not finished yet.
  - `in_use`: the object is still used by a sandbox (mounted volume, source snapshot).
  - `closed`: the PTY or session is closed or not in a state that accepts the call.
  - `operation_failed`: a git or fs command in the sandbox failed.
  - `git_missing`: the sandbox's image has no git (the default `python:3.12-slim` has none);
    create the sandbox from an image that has it, for example `python:3.12`.
  - `changed_during_reset`: the sandbox changed state while a reset was replacing it.
  - `unsupported_mode`: the operation is not supported in the configured run mode.
  - `disk_full`: the runtime reported that the sandbox disk is full.
  - `runtime_conflict`: the runtime refused the operation for another reason.
  - `conflict`: the fallback when none of the above applies.

  `INVALID_STATE` (also status 409) is a different code and has no `reason`.

## 4. Preview URLs

To create a token for a port, run `sandfort preview <sandbox> <port>`, which prints the preview URL,
or call `sbx.preview(port)` in the Python SDK, which returns a `PreviewInfo` with `url`, `token` and
the expiry. In REST, POST to the sandbox's `preview-tokens` endpoint. Open the returned `url` in a
browser: it works as returned because it already carries the access token as a query parameter.
Preview URLs are served under the wildcard preview domain over HTTPS and stop working at
`expires_at`.

Treat the `url` as a credential. Whoever holds it can open that port of the sandbox, as often as
they like, until `expires_at`. The lifetime is `ttl_seconds`: 1 hour by default, at least 60
seconds and at most 7 days. No endpoint revokes a token before it expires, so choose a short
`ttl_seconds`. On the first open, the proxy takes the token out of the query, sets it as an
`HttpOnly` cookie and does not forward it to your app. The URL as you opened it can still stay in
browser history and in the access logs on the way. Do not share it and do not paste it into tickets
or chat. Mint a new token for each person who needs one.

The sandbox must be started to create a token. For a stopped or deleted sandbox the call answers 409
`no_container`, with `details.state` and, when the sandbox is `stopping` or `stopped`,
`details.stop_cause`. Start the sandbox and ask again.

## 5. Beta limits

- **Audit chain incident (fixed).** Before 2026-11-04, concurrent appends under load forked the
  per-organization audit chain. In 3 of the 5 evaluation orgs, `audit-verify` and
  `GET /v1/audit-events/verify` therefore report historical `link_broken` findings. No event was
  altered (no `hash_mismatch`), and appends are serialized per org since then. New partner orgs
  start with a clean chain. The operator may re-anchor the orgs hit by this incident (see
  "Re-anchor" under the audit item below); until that is done for an org, its verify keeps
  reporting the findings.
- **Security fix, deployed 2026-11-05: image references.** A sandbox create, an image build base
  image and a snapshot register refuse, with 422, a reference that is an image ID
  (`sha256:<hex>`, a bare or short hex id) or that names the platform's `sandfort-snapshot`
  repository or `moby-dangling`. Until 2026-11-05, Docker resolved such a reference against the
  host's local image store, so a caller who knew another org's snapshot digest, or probed short
  ids, could start a sandbox from that org's committed snapshot. Pass an image name (for example
  `python:3.12-slim`, or `name@sha256:...` with a repository name) or a snapshot id. We audited
  the beta's database: no sandbox was ever created from an image ID or a `moby-dangling`
  reference, and no sandbox runs another org's snapshot. That check covers existing snapshots
  only; deleted snapshot rows are removed, so older history cannot be checked.
- **Disk is enforced per sandbox.** Writes beyond `disk_gib` fail with "No space left on device"
  and the sandbox keeps running; an upload into a full sandbox answers 409. Delete files, or
  create a sandbox with a larger `disk_gib`, up to the 20 GiB per-sandbox maximum (see Quotas
  above). Do not delete `/.sandfort-reserve` (see Quotas).
- **Volume size and transfer limits (set on the beta on 2026-11-14).** The per-volume size
  limit (`SANDFORT_VOLUME_MAX_BYTES`) is 64 MiB (67108864 bytes): a restore whose decompressed
  content goes past it answers 413 with `details.limit_bytes` and leaves the volume empty, and
  the compressed restore body itself stays capped at 256 MiB with a pre-body 413 for a larger
  declared `Content-Length`. Concurrent volume transfers (exports and restores together) are
  capped at 2 per organization and 8 in the server process; a transfer over the cap answers
  409 `CONFLICT` with `details.reason` `org_transfer_limit` or `transfer_limit` and
  `details.limit`. An announced test window may temporarily raise the per-org cap; the 409
  details always name the limit in force.
- **One shared VM.** The beta is a single VM (6 vCPU, 24 GiB RAM) shared by all evaluators. On
  2026-11-04 from 15:08 to 15:46 it was down: the host killed the VM's QEMU for exceeding its
  memory limit during parallel heavy tests, and the re-created VM came up without network. Fixed:
  QEMU has 2 GiB of memory headroom above the guest, and the VM's MAC address is pinned. Please
  keep to about 3 concurrent heavy sandboxes (multi-GiB writes, `microvm` fleets).
- A shared evaluation instance on modest hardware. Its round-trip latency over the public internet
  is not representative, and you should not read it as a service level or run load tests against it.
  Measure latency on your own host, colocated with your agent; that is where an agent inner loop
  runs in production.
- Per-key rate limits and per-sandbox maximums apply (see Quotas above); the beta may also set
  per-organization limits (`null` means unlimited). A request over a rate limit is refused with
  HTTP 429; tell us if the limits block your evaluation.
  - *Rate limit model:* a token bucket per API key (per user for session tokens). An empty bucket
    answers 429 `RATE_LIMITED` with `Retry-After` in whole seconds and no `X-RateLimit-*` headers;
    the SDK waits and retries it. Buckets live in server memory and reset when the server
    restarts, so a restart gives every key a full bucket. `/healthz`, `/readyz` and the PTY
    websocket are exempt, and a missing or bad key is a 401 that takes no token. The server's
    configured defaults are a refill of 100 requests per second and a burst (bucket size) of
    1000 requests per key: a key can make 1000 requests back to back, then about 100 per
    second. They are settings, so an instance can differ from the defaults; honour
    `Retry-After` rather than counting on these numbers.
  - *Usage metering:* `GET /v1/org/usage?from=&to=` (scope `usage:read`) returns one total per
    dimension. `vcpu` and `memory_mib` are allocated time, counted while a sandbox is `started`.
    `disk_gib` is sampled from the size of the sandbox's writable layer, not the requested
    `disk_gib`. It is credited for the whole run at the last sampled size (see the operations
    runbook). `vcpu` and `memory_mib` are exact. `group_by=sandbox` or
    `group_by=label:<key>` splits the totals. A key with `sandbox_labels` sees only its own
    sandboxes and label groups. Metering records allocation; it does not imply billing. See "Usage
    report" under "First sandbox in five minutes".
  - *Webhooks* (scope `webhooks:write`): events such as `sandbox.created`, `sandbox.stopped`,
    `sandbox.error`, `snapshot.created` and `quota.exceeded`. A `sandbox.error` event is sent once
    when a sandbox enters the state `error`; its payload has `sandbox_id`, `state`, `reason` (the
    sandbox's `error_reason`) and `error_code` (see the `error_code` table above), so branch on
    the code. The key is `reason` in the event and `error_reason` on the sandbox object. The
    payload of a `sandbox.stopped` event also has `stop_cause` (see "Why a sandbox stopped" in
    section 3); the other sandbox events carry the key with `null`. Events
    are delivered at least once and signed as Standard
    Webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature`, secret `whsec_...` shown
    once). Deduplicate on `webhook-id`. A non-2xx answer or a redirect is retried, and an endpoint
    that keeps failing is disabled. Receiver URLs must use `https`, a public address and port 80,
    443 or 8000-9000; loopback, private and cloud-metadata addresses are refused, and a host that
    does not exist answers 422. If the server's DNS lookup of your host only fails or times out, the
    create answers 503 `DNS_UNAVAILABLE` with `Retry-After` and creates nothing: send it again.
    Create an
    endpoint with `url` and `event_types`; the secret is in the create answer only:

    ```bash
    curl -s "$SANDFORT_BASE_URL/v1/webhooks" \
      -H "Authorization: Bearer $SANDFORT_API_KEY" -H "Content-Type: application/json" \
      -d '{"url":"https://hooks.example.com/sandfort",
           "event_types":["sandbox.error","sandbox.stopped"]}'
    ```

    `event_types` is a list of exact types or patterns (`*` or `sandbox.*`). Unknown fields are
    rejected: a body with a misspelled field such as `events` answers 422 and names it, instead
    of the field being ignored.

    **Troubleshooting: events do not arrive.** Anything but a 2xx answer counts as a failure
    (so does a redirect, which is never followed, and a transport error). A failed delivery is
    tried 6 times in all, and then it is `failed`. The schedule holds delays of 1, 5, 25, 60 and
    300 seconds, but the dispatcher looks for due deliveries only every 5 seconds
    (`SANDFORT_WEBHOOK_DISPATCH_INTERVAL_S`, default 5), so the first retry comes about 5 seconds
    after the failure, not 1.
    After 50 consecutive failed attempts the endpoint is disabled and `webhook.endpoint_disabled`
    is written to the audit log. Your endpoint must answer 2xx within the timeout of one
    attempt, 10 seconds by default (the server setting `SANDFORT_WEBHOOK_TIMEOUT_S`; the beta's
    value is an operator setting). Do slow work after you answer, not before.

    1. `GET /v1/webhooks/<endpoint id>` shows `enabled` and `failure_count`. `enabled: false`
       means the endpoint was disabled: fix the receiver, then send `PATCH` with
       `{"enabled": true}`, which also resets `failure_count`.
    2. `GET /v1/webhooks/<endpoint id>/deliveries` lists the deliveries (paged with `next_cursor`).
       Read these fields: `state` (`pending`, `delivered`, `failed` or `disabled`), `attempts` (how
       many tries so far), `next_attempt_at` (when the next retry is due, `null` when none is) and
       `last_status` (the HTTP status of the latest answer, `null` when there was none: a timeout or
       a connection error). A `last_status` of 301 or 302 is a redirect your URL must not issue; a
       4xx or 5xx is your receiver's answer. The delivery object also has `event_type`,
       `last_error`, `payload_sha256` and `attempt_history`. `last_error` is the reason of the
       latest failed attempt, at most 200 characters, and `null` after a success. `payload_sha256`
       is the hash of the signed body. The body itself is not stored. `attempt_history` holds the
       newest 6 attempts, oldest first. Each has `kind`, `attempted_at`, `status`, `error`,
       `duration_ms` and `actor_id`. Deliveries from before the r0022 migration have `event_type`,
       `last_error` and `payload_sha256` as `null` and an empty history. The list takes `event_type`
       and `state` filters; its cursor is bound to the endpoint and to those filters.
    3. A `failed` (or `disabled`) delivery can be sent again:
       `POST /v1/webhooks/<endpoint id>/deliveries/<delivery id>/redeliver`. It sets the
       delivery to `pending` with `attempts` back to 0, so it gets the full schedule again. A
       `delivered` delivery is final and answers 409 `INVALID_STATE`, and so does a redeliver
       on an endpoint that is still disabled: enable it first (step 1). The attempt history is
       kept and gets a `redelivered` entry that names the key; `next_attempt_at` stays `null`
       until the dispatcher makes the next attempt. The call is audited as `webhook.redelivered`.
    4. Deliveries that stay `pending` with `attempts` 0: no attempt was made at all. The
       server's dispatcher is disabled or failing, and nothing on your side can fix it. Ask the
       operator and send the `x-request-id` of the list call. `sandfort webhook deliveries`
       prints a note on stderr when every delivery it listed is `pending` with 0 attempts and
       the oldest was created more than five minutes ago ("deliveries have not been attempted
       for N min; the server's dispatcher may be disabled or failing, ask the operator"). The
       note is not printed with `--json`.

    Delivery is at least once and a redelivery repeats the event, so deduplicate on the
    `webhook-id` header.

    **Webhooks from the CLI.** The `sandfort webhook` group needs the `webhooks:write` scope.
    Add the global `--json` before the group name for machine-readable output.

    ```bash
    # Create: --event repeats ('*', 'group.*' or 'group.name'). The server generates the secret
    # and returns it once; it prints only with the global --json and --show-secret.
    sandfort --json webhook create https://hooks.example.com/sandfort \
      --event sandbox.error --event sandbox.stopped --show-secret
    sandfort webhook list
    sandfort webhook get <endpoint-id>
    # update changes only the fields you pass; --enable also resets failure_count.
    sandfort webhook update <endpoint-id> --url https://hooks.example.com/v2 --enable
    sandfort webhook rm <endpoint-id>            # no prompt

    # Deliveries in id order, one page per call (next cursor on stderr); --all pages through.
    sandfort webhook deliveries <endpoint-id> --state failed --event-type sandbox.error
    sandfort webhook deliveries <endpoint-id> --all --limit 100
    # One delivery with its attempt history (not combinable with the list options).
    sandfort webhook deliveries <endpoint-id> --show <delivery-id>
    sandfort webhook redeliver <endpoint-id> <delivery-id>
    ```

    `--state` is `pending`, `delivered`, `failed` or `disabled`. There is no option to pass
    your own secret: `create` has no `--secret-file` or `--secret-stdin`. Keep the printed
    secret; no later call returns it. With `--json`, one page of `deliveries` prints
    `{"deliveries": [...], "next_cursor": ...}` and `--all` prints a plain list.
- Sandboxes auto-stop on a timer (`auto_stop_minutes`, API default 15) and can auto-delete
  (`auto_delete_minutes`, API default off). Do not keep state in a sandbox you cannot recreate.
  For both, a negative value means never and a positive value means that many minutes.
  Auto-stop counts idle time (for auto-stop, `0` also disables the timer), and a request that is
  still running does not renew it: a long command or cell is stopped (see "Auto-stop does not wait
  for a running command or cell"). Auto-delete counts minutes
  since the sandbox stopped, and it does fire; `0` deletes the sandbox on the next sweep after it stops. A sandbox
  set to never auto-delete stays until you delete it explicitly.
- No uptime guarantee (one VM, one region); support is best-effort. The operator announces planned
  deploys through the status notice at least two minutes before the API restarts (see "Status and
  incidents"); a restart takes under a minute and running sandboxes keep running. An unplanned
  restart or outage can come without a notice. See the
  [beta terms](https://docs.sandfort.dev/beta-terms.html).
- Do not process production secrets or sensitive data in the beta.
- Isolation is chosen per sandbox (see Isolation tiers above). The beta offers the `container`,
  `gvisor` and `microvm` tiers, and `gvisor` is the default. The `container` tier shares the host
  kernel, and the `gvisor` tier puts a user-space kernel between your code and the host kernel; a
  bug in gVisor itself could still expose the host kernel. The `microvm` tier runs Kata Containers
  on the beta VM's nested KVM, so the beta VM is itself virtualized. It is a shared evaluation
  instance either way, so do not run your highest-risk code on the beta.
- The per-organization audit hash chain is verified and exported with the server-side admin commands
  `audit-verify` and `audit-export`. A client with the `audit:read` scope and an org-wide key can
  also read audit events through three routes. A key with `sandbox_labels` gets 403 on these routes.
  `GET /v1/audit-events` lists the events. Its filters `from` (inclusive) and `to` (exclusive) apply
  to the event time. The default order is oldest first, and `order=desc` gives newest first. The
  exact-match filters are `actor_id`, `action`, `target_id`, `request_id` and `outcome`, and they
  combine with AND. Any other query parameter gets a 422 that names it. `GET
  /v1/audit-events/export?from=&to=` streams the chained rows as NDJSON, and it also takes
  `request_id` and `outcome`. `GET /v1/audit-events/verify` checks the whole chain. The export and
  verify routes are in the published OpenAPI spec. Pass `from_id=<audit event id>` to verify from
  one event on: that event's own hash is recomputed, every later event is checked against the one
  before it, and the reply names the start in `anchor_id`. It proves the chain from that event to
  the newest one, not the history before it, and it takes the event's link to its predecessor as
  given, so keep that event's `hash` from an earlier export and compare it. An id that is unknown or
  belongs to another organization answers 404, and an empty `from_id` answers 422. Events record the
  client IP address that uvicorn reports. Behind a proxy that address is the proxy's, unless the
  proxy is listed in `SANDFORT_FORWARDED_ALLOW_IPS`: only then does uvicorn honour
  `X-Forwarded-For`, and a header from any other peer is ignored. A user agent longer than 512
  characters is cut to 512, and an address too long for the column (45 characters) is stored as
  null. The event list is returned oldest first unless you pass `order=desc`. An event stores the
  actor (type and id), the action, the target, the outcome (`success`, `denied` or `error`), the
  request id, the client IP, the user agent and redacted details. API key create and revoke events
  (`api_key.created`, `api_key.revoked`) carry the request id, client IP and user agent like the
  others. A call that changes state writes one event or more, not always exactly one (see "Rows per
  call" below). The GETs that read sandbox content are audited too (sandbox logs, fs list, stat and
  download, git status), while listing sandboxes, snapshots, volumes, jobs, usage and audit events
  is not. A refusal after a valid key is recorded as `request.denied`, with the method, path, status
  and `error_code` in the details. These refusals are audited: 401 for a revoked or expired key (see
  below), 403, 404, 409, 422 and 429 with error code `QUOTA_EXCEEDED` (an organization quota; a
  create past the per-key sandbox cap is audited as `sandbox.create_refused` instead, see below). A 429 with error code `RATE_LIMITED` is not
  audited, because a client in a retry loop would flood the chain. A 422 for a request body that is
  not valid JSON is not recorded as `request.denied` either: the body is rejected before the key is
  resolved. Every other 422, and every 401, 403, 404 and 409 after a valid key, is recorded.

  A revoked or expired key is refused with 401, and that refusal is audited as `request.denied`
  on the key's organization, with `reason` `revoked` or `expired` in the details next to the
  method, path, status and `error_code`; the actor is the key. The row is written at most once
  per key per minute per server process, so a client that keeps sending a revoked key does not
  flood the chain; the repeats within that minute leave no row. Unknown, malformed, missing and
  wrong-secret keys are not audited, because no organization is known for them. In the details, `env`
  keeps only the variable names, and
  `stdin`, `code`, `command`, `args`, `cmd` and `token` keep only a SHA-256 digest and the byte
  length (the digests are unsalted, so a short guessable value can be confirmed by hashing a
  guess). A snapshot export is recorded as `snapshot.exported`. For the historical `link_broken`
  findings on some evaluation orgs, see the first item of this section.

  **Re-anchor.** A re-anchor is an operator action: the maintainer runs the server-side admin
  command `audit-reanchor` for one organization, with a required note and, optionally, an operator
  name and a reason code. It acknowledges the historical breaks that verify finds in that org's
  chain. It appends one chained event, `audit.chain_reanchored`. Its details are
  `acknowledged_through`, `findings`, `note`, and `operator` and `reason_code` when given. The
  reason code is `incident_acknowledged`, `migration` or `other`. The operator is the name the
  person running the command gave, not an authenticated identity. Nothing is hidden or rewritten: no
  row is changed or removed, every finding stays in the history and in `GET
  /v1/audit-events/export`, and a break after the acknowledged row still fails verify. `GET
  /v1/audit-events/verify` then reports the acknowledged findings separately:
  `acknowledged_findings` counts them, `reanchored_by` is the id of the re-anchor event, and
  `findings` lists only the unacknowledged ones, so `ok` is true when none remain. The reply also
  carries a `reanchor` object with that event in full: `event_id`, `operator`, `reason_code`,
  `acknowledged_through`, `findings` (how many the operator acknowledged), `note` and `occurred_at`,
  so the verify alone says who acknowledged what and why (`operator` and `reason_code` are `null`
  for an event written without them). These fields are left out of the reply for an org that has no
  re-anchor. The hosted beta's operator may re-anchor the orgs hit by the 2026-11 incident. After a
  re-anchor you can read the event and its note with `GET
  /v1/audit-events?action=audit.chain_reanchored`. The published OpenAPI spec lists these reply
  fields.

  **Export trailer.** Every `GET /v1/audit-events/export` ends with one trailer line. It has no
  `id` field and is told apart from the rows by its `type`:

  - `audit_head`: a signed head over the last row (`org_id`, `row_id`, `hash`, `hmac`; with an
    Ed25519 signing key also `alg`, `public_key`, `signature` and `signed_at`). It
    appears when the server has a chain key and the export is unfiltered and unbounded (no
    `request_id`, `outcome` or `to` that cuts off the newest row).
  - `export_summary`: the row count (`rows`) and the filter names (`filters`). It appears in
    every other case: a filtered export, an empty one, or a server without a chain key. It
    names no row and is not signed.

  A consumer that parses each line as a row must skip the last line:

  ```python
  lines = [json.loads(x) for x in body.splitlines() if x.strip()]
  rows, trailer = lines[:-1], lines[-1]   # trailer["type"] is audit_head or export_summary
  ```

  **Rows per call.** A call can write more than one row, and the rows share its request id.
  `POST /v1/org/members` with an email that has no user yet writes `user.created` and then
  `membership.added` (two rows); for a known user it writes `membership.added` only. A revoke
  of an API key with `cascade` writes one `api_key.revoked` row for each key it revokes, so a
  key with descendants gives several. A refused call writes `request.denied` instead of the
  action. Count rows by `request_id`, not by assuming one row for each call.

  **Window bounds.** `from` is inclusive and `to` is exclusive, on the event time. A row whose
  time equals `to` is not returned, so to read a whole day send `from=2026-11-10` and
  `to=2026-11-11`. The CLI passes `--from` and `--to` through unchanged, so `--to` is exclusive
  too, whatever its help text says.

  **CLI audit commands.** `sandfort audit` has four commands: `list`, `verify`, `verify-head` and
  `export`. `list`, `verify` and `export` need `audit:read` and an org-wide key (a label-scoped
  key gets 403); `verify-head` works on a file.

  - `sandfort audit list` takes `--actor`, `--action`, `--target`, `--request-id`, `--outcome`,
    `--from`, `--to`, `--order asc|desc` and `--limit`. A date alone is midnight UTC, and a
    value without an offset is UTC. One page prints per call, and the next cursor goes to
    stderr (`next_cursor` in `--json`); continue with `--cursor`. `--all` pages through every
    event and prints each page as it arrives (it cannot be combined with `--cursor`).
  - `sandfort audit verify [--from-id ID]` walks the chain. Exit codes: `0` the chain is intact,
    `1` the request failed (network, key, server), `2` a usage error (a bad option value), `3`
    the chain is broken (the findings are printed first). Scripts should test for `3` apart
    from `1`: a `1` says nothing about the chain.
  - `sandfort audit export [--from] [--to] [--request-id] [--outcome] [--output FILE]
    [--force]` writes the body unchanged, trailer included, to stdout, or to `--output`. The
    file gets mode 600, and the command prints `wrote N bytes to FILE`. An existing file is
    refused without `--force`, before any request is sent; a directory is refused always. The
    lines go to a temporary file in the same directory, which replaces `--output` only when
    the export is complete. A failed or interrupted export (SIGINT, SIGTERM; the command
    ends with 128 plus the signal number) removes the temporary file and leaves an existing
    `--output` as it was. A symlink is followed: the file it points to is replaced and the
    link stays. A target that is not a regular file (the null device, a fifo, a terminal) is
    written directly, without a temporary file. If the file appears during the export, it is
    not overwritten without `--force`. If the export ends without a trailer line (an `audit_head`
    or `export_summary`), it may be cut short. The lines received are still written, the CLI
    prints a warning on stderr, and the exit code is 3.
  - `list`, `verify`, `export` and `verify-head` refuse an option that takes one value when you
    give it twice (for example two `--from`). The command ends with a usage error, exit 2, that
    names the option. Before this, the last value won without a word.

  **Checking a signed head (`verify-head`).** Every non-empty export ends with an `audit_head`
  trailer. It carries `alg` (`ed25519`), `public_key`, `signature` and `signed_at` next to
  `org_id`, `row_id`, `hash` and `hmac`, and also `row_count`, `first_row_id` and
  `export_sha256` (the SHA-256 of the event lines). An export cut by `request_id` or `outcome` is
  marked `filtered: true`; the check then skips the linkage of adjacent rows. The server signs the
  head when the operator set `SANDFORT_AUDIT_SIGNING_KEY`. `GET /v1/status` (no key needed)
  returns the matching `audit_public_key`, an Ed25519 public key as urlsafe base64, or `null`
  when there is no signing key, and `audit_key_fingerprint`. Check the head with the public key
  alone:

  ```bash
  sandfort audit export --output audit.ndjson
  # stderr: audit head signed with Ed25519 key fingerprint <16 hex characters> ...
  sandfort audit verify-head audit.ndjson                      # key from GET /v1/status
  sandfort audit verify-head audit.ndjson --public-key <key>   # a key you pinned earlier
  sandfort audit verify-head new.ndjson --previous old.ndjson  # new is old plus more rows
  sandfort audit export | sandfort audit verify-head -         # a file named - is read from stdin
  ```

  `verify-head` fetches the public key from `/v1/status` without credentials. Pin the
  fingerprint (`data.audit_key_fingerprint`) out of band, for example in your runbook, and
  compare it with the one the command prints. `--previous` checks that an earlier export is an
  exact prefix of this one (the lines are identical), so nothing before it was changed.

  Exit codes: `0` every check passes. `3` a check fails; the reason is printed. `2` the check
  cannot run: the file or the `--previous` file is missing or unreadable, the file is empty, it
  has no valid row and no usable head, the `--previous` file holds no event rows, its last line is
  an `export_summary`, `--head-only` is used without a trailer or together with `--previous`,
  `--public-key` is bad, or no key is
  available (the server publishes none and you gave none). Each reason below gives exit `3`.
  The checks run in this order:

  | Reason | The check fails when |
  |---|---|
  | `unsigned` | The head has no Ed25519 signature |
  | `key_mismatch` | The head names another public key than the one you trust |
  | `signature` | The signature does not verify |
  | `undated` | `signed_at` is absent, has no UTC offset, or is before 1970-01-02 |
  | `future_signed_at` | `signed_at` is more than 5 minutes ahead of now |
  | `count_mismatch` | The number of event lines differs from `row_count` (rows removed or added) |
  | `content_mismatch` | The count is right, but the SHA-256 of the event lines differs from `export_sha256` (a line edited or reordered) |
  | `first_row_mismatch` | The first row is not the `first_row_id` of the head |
  | `malformed_row` | A line is not a valid event row (see the list below the table) |
  | `misplaced_trailer` | `audit_head` or `export_summary` is not the last line |
  | `org_mismatch` | A row belongs to another organization than the head |
  | `truncated` | The last row is not the row the head names |
  | `head_mismatch` | The last row has another hash than the head |
  | `chain_break` | A `prev_hash` is not the previous row's hash (skipped if filtered) |
  | `unchained_rows` | A row has no hash (accepted with `--allow-unchained`) |
  | `not_a_continuation` | With `--previous`, the earlier export is not an exact prefix |
  | `no_trailer` | There are rows, but the last line is no usable `audit_head` |

  Verify an export byte for byte as downloaded. If a tool changed the file to CRLF line endings or
  added a BOM, the check fails, usually as `content_mismatch`, and the CLI adds a hint that names
  the change.

  A `malformed_row` is a line that is not a JSON object, lacks a text `id`, `occurred_at`,
  `org_id` or `action`, lacks the keys `hash` and `prev_hash`, is bad UTF-8, is nested too
  deep, or is over 1 MiB.

  The SDK does the same: `client.audit.verify_head(line, public_key)` takes the key as a
  required argument, or the text `"status"` to read it from the server (`await` it on
  `AsyncClient`). The operator can also run `audit-verify --head <export file> --public-key
  <key>`, which reports an unsigned head or a bad signature as a `head_invalid` finding.

  **Undated heads.** A head must carry a valid `signed_at`, which the signature covers. Signed
  heads from the builds `v0.1.0-beta.60` to `v0.1.0-beta.64` have none: they still parse, and
  the signature can verify, but the check reports `undated` and exit `3`, not `ok`. A new
  export from a server with a signing key carries `signed_at`.

  Take the key from the status route or from a copy you pinned, never from the export: the head
  names its own key, and the check refuses a head whose key differs from the one you trust
  (`key_mismatch`). A valid signature proves
  that the server signed that head. Together with the exported rows relinking (each row's
  `prev_hash` is the previous row's `hash`, and the last one is the head's `hash`) it is
  evidence of the exported chain's shape. It does not recompute the keyed hashes; only
  `audit-verify` and `GET /v1/audit-events/verify` on the server do that. The operator can also
  run `audit-verify --head <export file>` to check that the live chain still reaches each
  head in an earlier export, which detects truncation.

  The action names you will see in `GET /v1/audit-events` (filter with `?action=`):

  | Action | Written when |
  |---|---|
  | `org.created` | The operator creates the org with `bootstrap` or `create-org` (the first row of the org's chain; orgs created before 2026-11-26 do not have it) |
  | `api_key.created`, `.revoked` | A key is created or revoked (a repeat revoke writes nothing). The first key of an org is recorded with actor type `platform_admin` and actor id `sandfort-admin` |
  | `request.denied` | An authenticated request, or one with a revoked or expired key (`reason`), is refused (statuses above), outcome `denied` |
  | `sandbox.create`, `.start`, `.stop`, `.delete` | A sandbox is created, started, stopped or deleted (`sandbox.create` and `sandbox.delete` details both carry the sandbox `name` and `labels`) |
  | `sandbox.create_refused` | A create is refused with 503 because the host is full, or with 429 because the key is at its `max_sandboxes` cap (target: the org), outcome `denied` |
  | `sandbox.start_refused` | A start is refused with 503 because the host is full (target: the sandbox), outcome `denied` |
  | `sandbox.update`, `sandbox.resized` | Sandbox settings change; a stopped sandbox is resized |
  | `sandbox.reset`, `.reset_failed` | A sandbox is reset, or the reset fails after removal |
  | `sandbox.failed` | A create or start fails and the sandbox moves to `error` (outcome `error`) |
  | `sandbox.claim` | A sandbox is claimed from the warm pool |
  | `sandbox.logs.read` | Sandbox logs are read |
  | `sandbox.auto_stopped`, `sandbox.auto_deleted` | An auto-stop or auto-delete timer fires |
  | `sandbox.preview_token_created` | A preview token is minted (port, `ttl_seconds`, `expires_at`; never the token or the URL) |
  | `sandbox.drift_detected`, `.orphan_removed` | The reconciler finds state drift, or removes an orphan. For a container that exited, the row carries `exit_code` and `oom_killed` (`true`, or `null` when the runtime did not report it) |
  | `snapshot.register`, `.create`, `.delete`, `.exported` | A snapshot is registered, created, deleted, exported |
  | `image.build.request`, `image.build.complete` | A declarative image build is requested or ends |
  | `volume.create`, `volume.delete` | A volume is created or deleted |
  | `toolbox.process.execute`, `toolbox.process.code_run` | A command or code snippet is run |
  | `toolbox.code_contexts.create`, `.delete`, `.interrupt`, `.run` | A code context is created, deleted, interrupted or run |
  | `toolbox.session.create`, `.exec`, `.kill` | A session is created, runs a command or is killed |
  | `toolbox.pty.create`, `.resize`, `.close` | A terminal is opened, resized or closed |
  | `toolbox.fs.stat`, `.list`, `.mkdir`, `.move`, `.delete`, `.upload`, `.download` | A file operation |
  | `toolbox.git.clone`, `.status`, `.add`, `.commit`, `.push`, `.pull` | A git operation |
  | `webhook.endpoint_created`, `.endpoint_updated`, `.endpoint_deleted` | A webhook endpoint is created, updated or deleted (an update lists the changed field names in `changed`, never the URL or the secret, and is written even when nothing changed) |
  | `webhook.endpoint_disabled` | An endpoint is disabled after repeated delivery failures |
  | `user.created` | A member add names an email that has no user yet (target: the user id) |
  | `membership.added`, `.removed` | A member is added to the org or removed from it |
  | `membership.role_changed` | A member's role changes (details: `from_role`, `role`) |
  | `membership.external_id_changed` | A member's external id is set, changed or cleared |
  | `audit.chain_reanchored` | An operator acknowledges historical chain breaks of the org (`audit-reanchor`) |
  | `quota.updated` | An organization quota is changed |
  | `gc.image_removed`, `.volume_removed` | The garbage collector removes an image or a volume |

  **A refused create or start is audited.** `sandbox.create_refused` and `sandbox.start_refused`
  have outcome `denied` and are the request's only audit row (no `request.denied` next to them).
  A host-full refusal carries `reason` `capacity`, `requested` (the resources of the request) and
  `host_full` `true`; the host-wide totals are other tenants' usage and are never in the row. A
  create refused by the key's `max_sandboxes` cap carries `reason` `key_cap`, `limit`
  `key_max_sandboxes`, `max` and `current`, the same numbers as the 429's `error.details`. A client
  that keeps retrying is coalesced: for the same action, key and reason at most one row is written
  per minute per server process, and the next row carries `refusals_coalesced` with the number
  of refusals left out. `GET /v1/audit-events?action=sandbox.create_refused` lists them.

  **A failed create or start is audited.** When a driver error moves a sandbox to `error`
  during create or start, the same transaction writes `sandbox.failed` with outcome `error`
  (target type `sandbox`, target id the sandbox id). Its details are `phase` (`create` or
  `start`), `error_code` and `error_reason`, the same values the sandbox object carries. The actor
  is the API key that asked for the operation when it is known, otherwise the system. Find them
  with `GET /v1/audit-events?action=sandbox.failed` or `?outcome=error`. A failed reset is still
  `sandbox.reset_failed`, and a container the reconciler finds gone is `sandbox.drift_detected`.

  The members API writes `user.created` and the `membership.*` actions listed above. The code
  also defines `session.created` and `scim_token.*` actions for single sign-on and SCIM; SSO and
  SCIM are not enabled on the beta.
- Single sign-on (OIDC) and SCIM user provisioning are self-hosted configuration features. They are
  not enabled on this evaluation beta.
- Metrics and the console are not reachable on the beta's public host.
- Sandfort is source-available (FSL-1.1-Apache-2.0), version `0.1.0`, with no production
  references yet.

For the full operation list and the security model, see the API reference and the security section
of the beta landing page on the public Sandfort site (`https://sandfort.dev`), or
write to `office@sandfort.dev`. The API reference on the docs site is refreshed on every deploy from the
committed spec (the repository file `openapi/sandfort.v1.json`), so it lists the code-context routes, including `interrupt`,
`order` on the sandbox list, `from_id` and `anchor_id` on audit verify, and `created_at` and
`updated_at` on sandbox objects. `GET /v1/nodes` is left out of the exported spec on purpose.
For a cell stuck in native code, the sequence in the code-context list above (its own
`timeout_s`, the queue behind it, removal only after the exec deadline plus 2 s) is also what the
exported spec describes.

## 6. Support and what we ask

The support contact for design partners is `office@sandfort.dev`. The response target is the next
business day (Monday to Friday, CET), on a best-effort basis; include the `request_id` from the
error answer (see "Reporting a problem"). The full terms are in the
[beta terms](https://docs.sandfort.dev/beta-terms.html).

### Status and incidents

`GET /v1/status` needs no API key. Check it before you debug your own code:

```bash
curl -s https://api.sandfort.dev/v1/status
```

```python
info = client.status()          # also on AsyncClient; works without a valid key
print(info.status, info.version, info.build_sha, info.started_at)
if info.notice:
    print(info.notice.message, info.notice.updated_at)
```

The reply is in the usual envelope; `data` has `status`, `version`, `build_sha`, `started_at` and
`notice`:

- `status` is `ok` or `degraded`. `degraded` means the maintainer has posted a notice that starts
  with `degraded:`.
- `version` is the installed package version (`unknown` if the metadata is missing), `build_sha`
  the commit of the running build (`null` when the operator does not report one), `started_at`
  when the server process started. A recent `started_at` after you saw a failure means the server
  restarted or was upgraded.
- `notice` is `null` when there is none. Otherwise it has `message` (the maintainer's text, at most
  2 KiB, without the `degraded:` prefix) and `updated_at` (when the notice was last changed).

The maintainer posts incident and maintenance notices there. The operator sets a notice at least
two minutes before the API restarts for a planned deploy, a `degraded:` one when sandboxes or
calls will be interrupted, and clears it when the deploy is checked. A restart takes under a
minute, running sandboxes keep running, and the new build shows in `build_sha`; a recent
`started_at` shows that the server restarted. Absence of a notice is not a guarantee: the beta has
no uptime guarantee, an unplanned restart has no notice until the maintainer writes one, and the
notice is written by hand.

**During a planned deploy.** The API is unavailable for under a minute while it restarts. The
SDK's own back-off does not cover that: with the default `max_retries=2` it pauses about 0.5 s
and then about 1 s (at most 1.5 s across the retries, less with jitter) and then raises the
error. So do one of two things around a deploy:

- poll `GET /v1/status` and wait until `notice` is `null` again before you resume (the operator
  clears the notice when the deploy is checked); or
- wrap your calls in your own retry that keeps trying for up to 60 s.

Only repeat calls that are safe to repeat: `GET`, `HEAD` and `DELETE`, and a `POST` that carries
an `Idempotency-Key`. That is a create with an `idempotency_key` (see "Retries and idempotent
create") and an exec with the header over REST (see "Idempotent exec"). Any other `POST` can run
twice if you repeat it. Running sandboxes keep running through the restart.

### Reporting a problem

Send `office@sandfort.dev` the `x-request-id` of the failing call. Every response carries it, an
error body repeats it as `error.request_id`, and the SDK exceptions expose it. You cannot read the
server logs; the maintainer finds the call by that id. You may send your own `X-Request-Id`
(1-64 characters of `A-Za-z0-9._-`) so you know the id before the call returns; a malformed one is
replaced, not rejected. Also send the time, the sandbox id, what you expected and what happened.

In return, the pilot asks for:

- feedback sessions, in which you tell us where the API, the SDK or this guide got in your way;
- the right for us to name you as a reference.

These terms come from the design-partner arrangement. The beta is free of charge for the whole
beta period; paid plans come after the beta, and no prices are quoted
(see the [beta terms](https://docs.sandfort.dev/beta-terms.html)).
