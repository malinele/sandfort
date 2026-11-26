# Reading and verifying the audit log

For security and compliance reviewers who read an organization's audit log and verify it themselves.
It covers the key, the routes, the signed head and its limits.

The statements here were read from the server package (`src/sandfort/`), the CLI
(`cli/src/sandfort_cli/`) and the Python SDK (`sdk/python/src/sandfort_sdk/`). Where a statement
comes from reading the source and was not run, the text says so. Where a limit matters for a
decision, it is stated next to the feature. Environment variables carry the `SANDFORT_` prefix. The
server side of the audit trail is described in [the governance
page](https://docs.sandfort.dev/governance.html), section Audit.

## Who this is for

You are a reviewer, an auditor or a security engineer. You do not run the sandboxes. You want to
answer three questions with evidence you can recheck, within the limits listed below:

- What did the callers of this organization do, and what was refused?
- Was the recorded history changed after the fact?
- What can this log not tell me?

The audit log is per organization. Rows are kept in a hash chain. When the operator has set both
the chain key and the signing key, an export ends in a head that the server signs with an Ed25519
key, and you can check that signature with a public key and no secret.

## What you need

Three routes serve the audit log: `GET /v1/audit-events` (list), `GET /v1/audit-events/export` and
`GET /v1/audit-events/verify`. All three need:

- the scope `audit:read`, and
- an organization-wide key. A key that carries `sandbox_labels` gets `403`, with the message that
  audit events are org-wide.

No human role is read-only plus audit. The `admin` role holds every scope. The `developer` role
holds every scope except `api_keys:admin` and `audit:read`. The `viewer` role holds only `org:read`,
`sandboxes:read`, `snapshots:read`, `volumes:read` and `usage:read` (`src/sandfort/domain/user.py`).
A reviewer therefore gets an API key that holds only `audit:read`.

### Mint an audit-only key

The caller must hold `api_keys:admin` and `audit:read`, which in practice means an org admin. The
creating key must itself be org-wide. A key with `sandbox_labels` can only mint keys that keep those
labels, and such a key cannot read the audit log. A key can only grant scopes its creator holds, so
a request for any scope the creator lacks is refused with `403`. If the creating key has an expiry,
the new key cannot outlive it.

```sh
curl -sS -X POST "$SANDFORT_BASE_URL/v1/api-keys" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"audit-review","scopes":["audit:read"],"expires_at":"<ISO 8601 timestamp, about a week ahead>"}'
```

The body takes `name` (1 to 255 characters), `scopes` (at least one), and the optional fields
`expires_at` (a timestamp with a timezone, in the future), `sandbox_labels`, `max_sandboxes` and
`shared_volume_labels`. Leave `sandbox_labels` out, or the key cannot read the audit log. The
plaintext key is in `data.key` of the response. It is shown once and cannot be read back later. The
mint itself writes an `api_key.created` row with the name, prefix, scopes and expiry
(`src/sandfort/api/routes/api_keys.py`).

The CLI equivalent is:

```sh
sandfort key create audit-review --scope audit:read --expires-at "<ISO 8601 timestamp>"
```

The timestamp must carry a timezone and lie in the future. Give the reviewer a short expiry. Hand
over the key through a channel you trust, and let the reviewer keep it in a private file. Give the
reviewer the organization id and the public key from the operator as well, not from the export under
review. The CLI reads it from `SANDFORT_API_KEY_FILE`, or from `SANDFORT_API_KEY`, which wins when
both are set, with the server address in `SANDFORT_BASE_URL`.

## Reading events

### With the CLI

```sh
export SANDFORT_BASE_URL="https://sandfort.example.com"
export SANDFORT_API_KEY_FILE="$HOME/.sandfort-audit-key"

sandfort audit list --outcome denied --from 2026-11-01 --order oldest --limit 100
sandfort audit list --action sandbox.create --json
sandfort audit list --all --json
```

`sandfort audit list` takes these options:

**CLI filters for audit list**

| Option | Meaning |
|---|---|
| `--actor` | Exact actor id. |
| `--action` | Exact action name, for example `sandbox.create`. |
| `--target` | Exact target id. |
| `--request-id` | The `X-Request-ID` of the request that wrote the row. |
| `--outcome` | `success`, `denied` or `error`. |
| `--from` | At or after this moment (inclusive). ISO 8601. A date alone is midnight UTC. |
| `--to` | Before this moment (exclusive). ISO 8601. `--to` must be after `--from`. |
| `--order` | `newest` (the CLI default) or `oldest`. `desc` and `asc` are aliases. |
| `--limit` | Events per page, 1 to 100, default 50. |
| `--cursor` | Continue after a cursor. |
| `--all` | Page through every event. Not with `--cursor`. |

Filters combine with AND. Repeating an option is a usage error. With `--json`, a single page prints
`{"events": [...], "next_cursor": ...}`, and `--all` prints a plain list.

### With the API

```sh
curl -sS "$SANDFORT_BASE_URL/v1/audit-events?outcome=denied&from=2026-11-01&order=desc&limit=100" \
  -H "Authorization: Bearer $SANDFORT_API_KEY"
```

The query parameters are `actor_id`, `action`, `target_id`, `request_id`, `outcome`, `from`, `to`,
`order`, `cursor` and `limit`. Any other parameter is rejected with `422` and named. The page of
rows is in `data`. When more rows exist, `meta.next_cursor` holds the cursor for the next page.

Two details that catch people out:

- The REST route lists oldest first by default (`order=asc`). The CLI lists newest first by default.
  Send the same `order` on every page, because a cursor is bound to the filters and the order that
  issued it. A mismatch is a `422`.
- A row in the list has no hash. Only export rows carry `prev_hash` and `hash`.

### What a row holds

**Fields of an audit row**

| Field | Meaning |
|---|---|
| `id` | Row id. Ids follow creation order. |
| `org_id` | The organization. Every row of a chain has the same one. |
| `actor_type` | `api_key`, `system` or `platform_admin`. |
| `actor_id` | The key id (or the SSO session token id) for `api_key` rows, `sandfort-admin` for `platform_admin` rows, and `null` for `system` rows. |
| `action` | What was done, for example `sandbox.create` or `request.denied`. |
| `target_type`, `target_id` | The object the action was about. |
| `outcome` | `success`, `denied` or `error`. |
| `request_id` | The `X-Request-ID` of the request that wrote the row. |
| `ip` | The socket peer as the ASGI server reports it. `X-Forwarded-For` counts only when the peer is in `SANDFORT_FORWARDED_ALLOW_IPS`. |
| `user_agent` | The client's user agent. |
| `details` | Redacted detail of the call. |
| `occurred_at` | When the row was written. |

Notes on reading these fields:

- `outcome` is `success` for an accepted call. A refusal after the key was resolved is `denied`. The
  statuses are `401` for a revoked or expired key, `403`, `404` from a route that matched, `409`,
  `413` raised by a route, `422` from field validation, `429` with the code `QUOTA_EXCEEDED` and
  `503` with the code `CAPACITY` (a full host, or an organization's cap on terminals or async
  commands). A `400` is recorded the same way in two narrow cases, a `Last-Event-ID` that is not a
  byte offset on the command log follow route and a blank SCIM token name.
- The action of a refusal is usually `request.denied`, with `details.status` and
  `details.error_code`. Two cases write another action and carry no `details.status` or
  `details.error_code`. A create or start refused for host capacity (`503`) is
  `sandbox.create_refused` or `sandbox.start_refused`, with `details.reason` `capacity`. A create
  refused by the key's own `max_sandboxes` cap (`429` `QUOTA_EXCEEDED`) is `sandbox.create_refused`,
  with `details.reason` `key_cap`, `details.limit` `key_max_sandboxes`, `details.max` and
  `details.current`, and the target is the organization. A refusal can also be recorded under the
  call's own action, for example `toolbox.fs.upload` for a refused or failed upload and
  `sandbox.exec.replay` for a keyed exec replay whose output was not kept (`409`, `details.reason`
  `result_unavailable`). Such a call leaves no `request.denied` row. For an upload, a `success` row
  can come first, and a later `denied` or `error` row names it in `details.supersedes`. Filter on
  `outcome` `denied` and on `error` without an action filter, not on `request.denied` alone.
- A `5xx` other than a `503` with the code `CAPACITY` is `error`. It is the action `request.failed`
  when no service row was written for the request. A call that was accepted and then failed in the
  background writes `error` rows under other actions, for example `sandbox.failed`,
  `sandbox.reset_failed`, `sandbox.drift_detected`, `snapshot.create`, `image.build.complete` and
  `volume.create`. A `404` is stored as `denied` too, so `outcome` alone does not mean a permission
  was refused. For `request.denied` and `request.failed` rows, read `details.status` and
  `details.error_code`.
- `actor_type` is `api_key` for a person who signed in through SSO. The actor id is then the id of
  the session token, not a user id.
- `ip` and `user_agent` are stored as received and are not part of the row hash. Anyone with
  `audit:read` can read them.
- In `details`, `env` keeps only the sorted key names and a value count. The keys `stdin`, `code`,
  `command`, `args`, `cmd` and `token` keep only `redacted-sha256:` and the byte length. These
  digests are unsalted, so a guessable value can be confirmed by hashing a guess
  (`src/sandfort/services/audit.py`).
- The server also writes rows for itself: auto-stop, auto-delete, the reconciler and garbage
  collection use `actor_type` `system`. Operator commands such as `create-key` use `platform_admin`.

## Exporting and verifying

### Export

```sh
sandfort audit export --output audit.ndjson
```

The file has one JSON row per line, in chain order, and a trailer on the last line. `--output`
writes mode 600 and replaces an existing file only with `--force`. The file is written through a
temporary file and put in place only when the export is complete. Options `--from`, `--to`,
`--request-id` and `--outcome` narrow it. Without the CLI, call `GET /v1/audit-events/export` with
the same parameters.

An export row has the 13 fields above plus `prev_hash` and `hash`. The trailer is told apart by its
`type` field:

- `audit_head` when the server has an audit chain key and the export holds at least one row. It
  names the last row (`row_id`, `hash`) and binds the content with `row_count`, `first_row_id` and
  `export_sha256` (SHA-256 over the exact bytes of every row line, each with its newline). When the
  server also has a signing key, the head carries `alg` (`ed25519`), `public_key`, `signature` and
  `signed_at`.
- `export_summary` otherwise: an empty export, or a server with no chain key. It is not signed and
  `verify-head` cannot use it.

An export cut by `--request-id` or `--outcome` is marked `filtered`. Its rows are not a contiguous
run of the chain, so the link between neighbouring rows is not checked. Do not treat a filtered
export as complete.

A file that ends without a trailer may have been cut short. The CLI then warns on stderr and exits
3.

### Get the public key from a second channel

Anyone can read the public key and its fingerprint without a key:

```sh
curl -sS "$SANDFORT_BASE_URL/v1/status"
```

The response carries `data.audit_public_key` (urlsafe base64) and `data.audit_key_fingerprint` (the
first 16 hex characters of the SHA-256 of the raw key). Both are `null` unless the server has both
`SANDFORT_AUDIT_CHAIN_KEY` and `SANDFORT_AUDIT_SIGNING_KEY` set.

That route belongs to the same server whose export you are checking. By default `verify-head`
fetches the key from that route, so a server that fabricated an export could publish a matching key
and the check would pass. This is the weak point, and the fix is a second channel:

1. Ask the operator for the public key or the fingerprint over a different channel than the one that
   gave you the export, such as a signed message or a change record. Better, record it once and keep
   it.
2. Pass the key to `verify-head` with `--public-key`. There is no `--fingerprint` option. If you
   only hold the fingerprint, compare it by eye with the `fingerprint` field that `verify-head`
   prints for the key it used, and with the stderr note that `sandfort audit export` prints when the
   trailer is a signed head.
3. Treat the key in the trailer itself as untrusted. `verify-head` never uses it.

### Verify the head

```sh
sandfort audit verify-head audit.ndjson --public-key "$PINNED_KEY" --expect-org "$ORG_ID"
```

The command checks the signature and `signed_at`. Then, when the head binds the content (newer
servers do, older ones sign only the last row), it checks that the file's rows are the ones the
server signed: their SHA-256, their count and the first row. It also checks that every row has an
id, a timestamp, an action and the head's org, that the last row is the row the head names, and that
each row's `prev_hash` is the `hash` of the row before it. A file name of `-` reads standard input.

Options:

**Options of verify-head**

| Option | Meaning |
|---|---|
| `--public-key` | A 32-byte Ed25519 key, urlsafe or standard base64. |
| `--expect-org` | The head must name this org id, or the check fails with `expected_org_mismatch`. Without it, a genuine export of another org verifies. |
| `--previous` | An earlier export. Its rows must be an exact byte prefix of this file's rows. The command reports the count of new rows. |
| `--head-only` | Check the signature alone. |
| `--allow-unchained` | Accept rows without hashes. |

Verify the file byte for byte as downloaded. A copy with changed line endings fails with
`content_mismatch`.

**Exit codes of verify-head**

| Exit code | Meaning |
|---|---|
| 0 | Every check passed. |
| 3 | A check failed. The reason is printed, and `--json` carries it as `reason`. |
| 2 | The check could not run: the file or `--previous` is unreadable or empty, the file ends in an unsigned `export_summary`, or it has neither a usable trailer nor any valid row, `--public-key` is not 32 bytes, or no key is available. |
| 1 | Another CLI failure, for example a request that failed. |

Reasons that exit 3 can name: `unsigned`, `signature`, `key_mismatch`, `undated`,
`future_signed_at`, `expected_org_mismatch`, `truncated`, `head_mismatch`, `chain_break`,
`content_mismatch`, `count_mismatch`, `first_row_mismatch`, `org_mismatch`, `not_a_continuation`,
`malformed_row`, `misplaced_trailer`, `unchained_rows` and `no_trailer` (event rows with no trailer
line after them). A row whose text was edited fails as `content_mismatch`, because the content
digest is checked before the links. A removed row fails as `count_mismatch`. A wrong key fails as
`key_mismatch`.

On success, without `--json`, the command prints one stderr line that says what was proven and what
was not.

### Verify the chain on the server

```sh
sandfort audit verify
```

This calls `GET /v1/audit-events/verify`. The server walks the org's chain, recomputes every hash
and reports `ok`, `checked`, `first_id`, `last_id`, `last_hash` and `findings`. The command exits 3
when the chain is broken. `--from-id` starts the walk at an anchor row, and then history before that
row is not checked. Read what this proves in the next section, because a reviewer runs this check on
the server being audited.

The Python SDK offers the same checks: `client.audit.list`, `iter`, `verify`, `export`,
`export_lines` and `public_key`, and the top-level functions `sandfort_sdk.verify_export` and
`sandfort_sdk.verify_head`. The SDK also refuses to trust the key named in the head.

## What the chain proves and does not prove

Each row's hash covers the previous row's hash and the canonical form of the row. With
`SANDFORT_AUDIT_CHAIN_KEY` set (at least 32 bytes), the hash is HMAC-SHA256 with that key. Without
it, the hash is a plain SHA-256 and anyone who can write the database can rewrite history and
recompute every hash. In the `prod` environment the server refuses to start with no chain key unless
the operator sets `SANDFORT_UNKEYED_AUDIT_CHAIN_ACKNOWLEDGED=true`.

Rows written before the chain key was set stay unkeyed. Verify accepts them before the first keyed
row while `SANDFORT_AUDIT_CHAIN_ACCEPT_UNKEYED` is true (the default). That early part of the trail
is rewritable by a database writer. An unkeyed row after a keyed one is a finding.

With a signed head and a key you pinned, `verify-head` proves:

- the file is exactly the sequence of rows the server signed at `signed_at`, so a change made to the
  file after it was signed is detected,
- every row belongs to the head's org, the last row is the head's row, and the rows link to each
  other.

It does not prove:

- **That the database was unchanged before this export.** The server signs the rows it holds at
  export time and does not recompute the keyed row hashes while exporting. A single export therefore
  shows that the file is intact, not that history was never edited. To detect earlier edits, keep
  every export and run `verify-head --previous <earlier file>`. A row edited after the earlier
  export was taken makes the earlier lines fail to match as an exact prefix. Also ask the operator
  to run `sandfort audit verify` with the chain key.
- **The keyed row hashes.** Only the holder of the chain key can recompute them. `sandfort audit
  verify` does, but it runs on the server, so you trust the server for that check. A server that
  holds both keys can sign a fabricated export, and `verify-head` accepts it.
- **That the export is the newest.** An older genuine export still verifies. Read `signed_at`, ask
  for a fresh export, and use `--previous` to show that a later export extends an earlier one.
- **Completeness of a filtered export.**
- **Who changed anything.** The chain shows that a row was changed, removed or reordered. It does
  not name the person. Access to the database or the Docker socket on the host leaves no row.
- **Anything before the last row, on a legacy head.** Older servers sign only the last row. If the
  CLI notes a legacy head, ask for a fresh export.

Retention can shorten the trail. When `SANDFORT_AUDIT_RETENTION_DAYS` is above 0 (the default is 0,
keep forever), the server prunes only the oldest rows, never the newest, and verification starts
from the first remaining row. An operator can also acknowledge past chain findings with
`audit-reanchor`. That adds a row and hides nothing. The `operator` and the `note` it stores are
free text chosen by the person running the command. The `reason_code` is one of
`incident_acknowledged`, `migration` or `other`. The command checks none of them against an
identity.

## What is not recorded

Check this list against your control objectives before you rely on the log.

- **Successful reads.** Listing, exporting and verifying audit events, and listing or reading
  sandboxes, snapshots, volumes, jobs and usage, write no row. A few reads are recorded because they
  expose sandbox, volume or snapshot content: `sandbox.logs.read`, `toolbox.fs.list`,
  `toolbox.fs.stat`, `toolbox.fs.download`, `toolbox.git.status`, `volume.export` and
  `snapshot.exported`. A read that is refused after a valid key and after the route matched does
  write a `request.denied` row, for example a `404` for an unknown sandbox. A path that matches no
  route does not. A key without `audit:read` that tries to read the log leaves a `request.denied`
  row.
- **Most failed sign-ins.** A missing, malformed or unknown key, or a wrong secret, leaves no row. A
  revoked or expired key whose secret is correct leaves a `request.denied` row, at most one per key
  per 60 seconds per server process. A `429` with the code `RATE_LIMITED` leaves no row, while a
  `429` with the code `QUOTA_EXCEEDED` does (see the notes on `outcome` above for the action). A
  request body that is not valid JSON is answered with `422` and leaves no row, with or without a
  valid key, because the body is rejected before the key is resolved. The same holds for every
  refusal by the request text guard (`src/sandfort/api/text_guard.py`): a lone surrogate or NUL
  character in the body, the path or the query string, a body that is not valid UTF-8, an integer
  with too many digits, a repeated object key and a body nested too deep. It also holds for a
  non-JSON content type (`415`), a body over the size limit (`413` from the body limit), a path
  that matches no route (`404`), a wrong method (`405`) and every refusal on the `/scim/v2` routes.
  Repeated refusals of a create or a start for host capacity, and of a create by the per-key
  `max_sandboxes` cap, are merged into one `sandbox.create_refused` or `sandbox.start_refused` row
  per action, key and reason per 60 seconds per server process, and the next row counts the
  suppressed ones in `refusals_coalesced`. The refusal row is written on a best effort basis and
  never changes the response. If that write fails, the server tries a generic `request.denied` row
  for the same answer instead, and if the audit store is unavailable, the refusal leaves no row.
- **Organization creation and the first key.** `create-org` and `bootstrap` write the org, an
  optional default quota and the first key without an audit row. `create-key` and `revoke-key` do
  write rows, as `platform_admin` with the actor id `sandfort-admin`.
- **Host-level access.** Operator commands such as `migrate`, `create-org`, `bootstrap`,
  `audit-verify`, `audit-export`, `repair-labels` and `doctor`, and any direct access to the
  database or the Docker socket, leave no row. The exceptions are `create-key`, `revoke-key` and
  `audit-reanchor`.
- **Command text, stdin and output.** A `toolbox.process.execute` row holds a digest and byte length
  of the command, the arguments and stdin, the names of the environment variables and no values, and
  `cwd` and `timeout_s` in clear. A `toolbox.process.code_run` row does the same for the code and
  the arguments. The text of the command and of stdin is not stored, and neither is the output.
  Terminal sessions record only create, resize and close, not keystrokes or output.
- **Sandbox traffic.** Outbound network attempts of a sandbox are not in the audit log. The egress
  proxy and the preview proxy write no audit rows.
- **Some mutating routes.** Rows are tested per feature. We have no test that walks every route. Two
  routes are known to write no row: minting a preview token (`POST
  /v1/sandboxes/{id}/preview-tokens`) and updating a webhook (`PATCH /v1/webhooks/{id}`). The
  governance page lists the main actions, but the list is not complete. Take the action names that
  actually occur from your own export (`sandfort audit list --all --json`, then count the distinct
  `action` values). Ask the operator about any mutating call you expect that never appears, or check
  a route you rely on by calling it with a test key and reading the row it writes.
- **Person-level identity.** A row names a key id or a session token id, not a person.

## Getting events out continuously

There is no audit webhook. The 13 webhook event types are lifecycle only: `sandbox.created`,
`sandbox.started`, `sandbox.stopped`, `sandbox.deleted`, `sandbox.error`, `sandbox.auto_stopped`,
`snapshot.created`, `snapshot.active`, `snapshot.error`, `snapshot.deleted`, `volume.created`,
`volume.deleted` and `quota.exceeded`. None of them is an audit row.

To pull events into your own store, poll:

- For a feed, call `GET /v1/audit-events` with `order=asc`. Follow `meta.next_cursor` until it is
  `null`. Then store the `occurred_at` and the `id` of the last row. On the next run, start with
  `from=<that occurred_at minus a safety margin such as 5 minutes>` (inclusive) and drop rows whose
  `id` you already stored. A row committed late by a concurrent request can carry a lower `id` than
  a row you already read, so keep the set of ids seen in the overlap instead of a single last id.
  Use the same filters and `order` on every page.
- For evidence, take a full `sandfort audit export` on a schedule, run `verify-head` with your
  pinned key and `--previous` on the earlier file, and keep both. The export has no pagination, and
  the server reads the whole chain of the organization on each call (the `from` and `to` filters are
  applied after the read). This page has no measured timing, so test one export at a quiet time
  before you schedule them.

Both calls need only the audit-only key. Neither writes an audit row.

## Windows

Reading the source shows that the `sandfort` CLI imports the Unix-only standard library modules
`termios` and `tty` when it loads, so it should not start on native Windows. This was not run on
Windows. WSL2 is not tested. On native Windows use `curl` for the routes above, and the Python SDK
for the checks. The SDK has no such import. This sketch follows the signatures in
`sdk/python/src/sandfort_sdk/audit_export.py` and was not run against a server:

```python
from sandfort_sdk import verify_export

# Read the file byte for byte, so that line endings stay as the server wrote them.
with open("audit.ndjson", encoding="utf-8", newline="") as handle:
    body = handle.read()

result = verify_export(body, "<pinned public key>", expected_org_id="<org id>")
print(result.ok, result.reason)
```

`result.ok` is true when every check passed. Otherwise `result.reason` carries one of the reasons
listed above. Pass `previous=` with an earlier export to check that this one extends it.

## Open questions for the operator

This page does not answer these, so ask:

- **Key rotation.** This page does not describe how the signing key is rotated. A head signed with a
  retired key fails against a different key with `key_mismatch`, so ask for the old public keys and
  the dates they were in use.
- **Retention.** If `SANDFORT_AUDIT_RETENTION_DAYS` is above 0, rows pruned from the start of the
  trail make `--previous` against an older export fail with `not_a_continuation`. Ask for the
  retention setting.

## Checklist

- [ ] The audit-only key has only `audit:read`, no `sandbox_labels` and a short expiry. The org id
      and the public key came from the operator, not from the export.
- [ ] `GET /v1/status` shows an `audit_public_key`. If both fields are `null`, exports are not
      signed and `verify-head` cannot run. Ask the operator whether `SANDFORT_AUDIT_CHAIN_KEY` is
      set, because without it anyone who can write the database can rewrite the chain.
- [ ] The public key or fingerprint came from a channel other than the server, and is passed with
      `--public-key`.
- [ ] The export was taken by you, and you checked `signed_at`.
- [ ] `sandfort audit verify-head` exited 0 with `--public-key` and `--expect-org`.
- [ ] A later export verifies with `--previous` against an earlier one.
- [ ] The operator showed you a `sandfort audit verify` run on the server and the chain is not
      broken, or each finding is explained. Count this as the operator's statement, not your own
      proof.
- [ ] Every row with outcome `denied` or `error` was reviewed for the periods that matter,
      whatever its action. Examples are `request.denied`, `request.failed`,
      `sandbox.create_refused`, `sandbox.start_refused`, `toolbox.fs.upload` and `sandbox.failed`.
- [ ] The list of what is not recorded was checked against your control objectives.
