"""Operation descriptions for the exported OpenAPI document (round 65).

An operation whose route has no docstring or ``description=`` gets its text from here, keyed by
``(METHOD, path)``. A route that documents itself keeps its own text: ``describe`` only fills a
gap. Every entry says what the operation does and its key error cases in plain English; the
shared 401, 403, 404, 429, 500 and 503 answers are not repeated unless the operation has a
specific reason for them. ``tests/test_openapi_contract_r65d.py`` fails when an operation has no
description, so a new route must add its text here or in its own docstring.
"""

from typing import Any

_SANDBOX = "/v1/sandboxes/{sandbox_id}"
_FS = _SANDBOX + "/toolbox/fs"
_GIT = _SANDBOX + "/toolbox/git"
_SESSION = _SANDBOX + "/toolbox/process/sessions/{session_id}"
_COMMAND = _SESSION + "/commands/{command_id}"
_PTY = _SANDBOX + "/toolbox/pty"

_STARTED = "The sandbox must be started, else 409 `CONFLICT` with reason `no_container`."
_TOOLBOX_READ = "Works on a stopped sandbox too; an unknown id answers 404."

DESCRIPTIONS: dict[tuple[str, str], str] = {
    # -- health and login -------------------------------------------------------------------
    ("GET", "/healthz"): (
        "Liveness probe: answers 200 `{status: ok}` whenever the process is serving requests. "
        "It does not check the database or the container runtime; use `/readyz` for that."
    ),
    ("GET", "/readyz"): (
        "Readiness probe: answers 200 `{status: ready}` when the database and the container "
        "runtime both respond. Otherwise it answers 503 `CAPACITY` with `error.details."
        "component` set to `database` or `driver`."
    ),
    ("POST", "/v1/auth/sso/exchange"): (
        "Trades an OIDC identity token for a short-lived user session token, with its expiry "
        "and the member's role. Every refusal (sessions disabled, unknown identity, invalid "
        "token) answers 401 and does not say whether the email is known."
    ),
    # -- api keys ---------------------------------------------------------------------------
    ("POST", "/v1/api-keys"): (
        "Creates an API key and returns its plaintext secret once; it cannot be read again. "
        "The key can only grant scopes the calling key holds (403 otherwise), and a name or "
        "scope the API refuses answers 422."
    ),
    # -- image builds -----------------------------------------------------------------------
    ("POST", "/v1/images/builds"): (
        "Starts a declarative image build from `spec` and answers 202 with the pending "
        "snapshot. When the same spec was built before it answers 200 with the ready "
        "snapshot and `reused` true; a spec the API refuses answers 422."
    ),
    # -- jobs -------------------------------------------------------------------------------
    ("GET", "/v1/jobs/{job_id}"): (
        "Returns one background job of the org: its kind, state, attempts and last error. A "
        "job the caller may not see (another org, or outside a label-scoped key) answers 404."
    ),
    # -- org members and quota --------------------------------------------------------------
    ("GET", "/v1/org/members"): (
        "Lists every member of the caller's org with role and external id. The list is not "
        "paginated."
    ),
    ("POST", "/v1/org/members"): (
        "Adds a member by email, reusing the user when the email is known. A second "
        "membership in the same org answers 409 `CONFLICT` with reason `already_exists`; "
        "granting a role above the caller's answers 403."
    ),
    ("DELETE", "/v1/org/members/{user_id}"): (
        "Removes the user's membership in the caller's org and answers 204 with no body; the "
        "user itself is kept. Removing the only admin answers 409 `INVALID_STATE`, and an "
        "unknown member 404."
    ),
    ("PATCH", "/v1/org/members/{user_id}"): (
        "Changes a member's role and returns the member. A change that would leave the org "
        "without an admin answers 409 `INVALID_STATE`; an unknown member answers 404."
    ),
    ("PUT", "/v1/org/quota"): (
        "Replaces the org's limits; a missing or null dimension means unlimited. This is a "
        "platform operation: it needs the admin scope and a platform-admin key (403 "
        "otherwise), and is recorded as a `quota.updated` audit event."
    ),
    ("GET", "/v1/org/quota/recount"): (
        "Compares the quota ledger totals with freshly recomputed totals, so a drift between "
        "them can be seen. It changes nothing and needs only `org:read`."
    ),
    # -- sandboxes --------------------------------------------------------------------------
    ("DELETE", _SANDBOX): (
        "Deletes the sandbox and its container; volumes are kept. Deleting a sandbox that is "
        "already deleted returns it unchanged, and a delete while a snapshot of the sandbox "
        "is in progress answers 409 `CONFLICT` with reason `in_progress`."
    ),
    ("GET", _SANDBOX): (
        "Returns one sandbox. With `wait_for` the call holds for up to `timeout_s` seconds "
        "until the sandbox reaches that state (or `error` or `destroyed`) and then answers "
        "with the row as it is; an unknown id answers 404."
    ),
    ("PATCH", _SANDBOX): (
        "Changes labels, `auto_stop_minutes`, `auto_delete_minutes` or `public`; omitted "
        "fields keep their value. `labels` replaces every user label (null clears them, "
        "reserved labels stay), and a sandbox being deleted answers 409 `INVALID_STATE`."
    ),
    ("GET", _SANDBOX + "/logs"): (
        "Streams the container's stdout and stderr as server-sent events; `follow`, `tail` "
        "and `since` choose what is sent. A failure before the first byte (unknown sandbox, "
        "no container) answers with the normal error envelope instead of a stream."
    ),
    ("POST", _SANDBOX + "/resize"): (
        "Changes the CPU, memory or disk of a stopped sandbox; omitted fields keep their "
        "value. The files in the sandbox's root filesystem are kept: the next start commits "
        "the stopped container and creates the new one from that image (mounted volumes "
        "stay attached; running processes do not survive the stop, as with any stop). A "
        "sandbox that is not stopped answers 409, a resize beyond the org quota 429 "
        "`QUOTA_EXCEEDED` and one beyond the host's capacity 503 `CAPACITY`."
    ),
    ("POST", _SANDBOX + "/start"): (
        "Starts a stopped sandbox, recreating its container first if it was resized (the root "
        "filesystem is kept). A "
        "sandbox that is already started is returned unchanged; a state that cannot start "
        "answers 409 `INVALID_STATE`, and a full org or host answers 429 or 503."
    ),
    ("POST", _SANDBOX + "/stop"): (
        "Stops a started sandbox and keeps it for a later start. A sandbox that is already "
        "stopped is returned unchanged; a state that cannot be stopped answers 409 "
        "`INVALID_STATE`."
    ),
    # -- filesystem -------------------------------------------------------------------------
    ("POST", _FS + "/delete"): (
        "Deletes a file or directory inside the sandbox; a directory needs `recursive` true "
        "(else 409 `CONFLICT` with reason `operation_failed`). Deleting the filesystem root "
        "answers 422 and a missing path 404. " + _STARTED
    ),
    ("GET", _FS + "/list"): (
        "Lists the entries of a directory with kind, size, mode and modification time. A "
        "path that is a file answers 409, a missing path 404 and a listing too large to "
        "return 413. " + _STARTED
    ),
    ("POST", _FS + "/mkdir"): (
        "Creates a directory with the given octal `mode`, with missing parents unless "
        "`parents` is false; `created` is false when it already existed. A path under /proc, "
        "/sys or /dev, or a bad mode, answers 422. " + _STARTED
    ),
    ("POST", _FS + "/move"): (
        "Moves or renames a path. An existing destination answers 409 `CONFLICT` with reason "
        "`already_exists` unless `overwrite` is true, a missing destination directory 404, "
        "and identical paths or the root 422. " + _STARTED
    ),
    ("GET", _FS + "/stat"): (
        "Returns kind, size, mode and modification time of one path. A missing path answers "
        "404. " + _STARTED
    ),
    # -- git --------------------------------------------------------------------------------
    ("POST", _GIT + "/add"): (
        "Stages files in a repository inside the sandbox; `files` defaults to `.`. A path "
        "that is not a repository, or any other git failure, answers 409 `CONFLICT` with "
        "reason `operation_failed`; an empty file name answers 422. " + _STARTED
    ),
    ("POST", _GIT + "/clone"): (
        "Clones a repository into `path` inside the sandbox, optionally one `branch`, a "
        "shallow `depth` and a `credential` that is never stored or echoed. A `url` or "
        "`branch` that starts with `-` answers 422, as does a credential with a non-http(s) "
        "`url`; a failed clone answers 409 `CONFLICT` with reason `operation_failed`. " + _STARTED
    ),
    ("POST", _GIT + "/commit"): (
        "Commits the staged changes of the repository at `path` and returns the new commit "
        "sha. A missing git identity (author name and email) answers 422 and a failed commit "
        "409 `CONFLICT` with reason `operation_failed`. " + _STARTED
    ),
    ("POST", _GIT + "/pull"): (
        "Pulls from a remote into the repository at `path`. With a `credential` the "
        "`remote_url` is required and must match the repository's remote scheme and host "
        "(422 otherwise); a git failure answers 409 `CONFLICT` with reason "
        "`operation_failed`. " + _STARTED
    ),
    ("POST", _GIT + "/push"): (
        "Pushes the repository at `path` to a remote. With a `credential` the `remote_url` is "
        "required and must match the repository's remote scheme and host (422 otherwise); a "
        "rejected push answers 409 `CONFLICT` with reason `operation_failed`. " + _STARTED
    ),
    ("GET", _GIT + "/status"): (
        "Returns the branch, ahead and behind counts and the changed files of the repository "
        "at the `path` query parameter. A path that is not a repository answers 409 "
        "`CONFLICT` with reason `operation_failed`. " + _STARTED
    ),
    ("POST", _GIT + "/status"): (
        "Same as the GET form, with `path` in the JSON body, for clients that cannot send a "
        "query string. A path that is not a repository answers 409 `CONFLICT` with reason "
        "`operation_failed`. " + _STARTED
    ),
    # -- exec sessions ----------------------------------------------------------------------
    ("GET", _SANDBOX + "/toolbox/process/sessions"): (
        "Lists the exec sessions of the sandbox. " + _TOOLBOX_READ
    ),
    ("GET", _SESSION): (
        "Returns one exec session with its working directory and state. " + _TOOLBOX_READ
    ),
    ("POST", _SESSION + "/commands"): (
        "Runs a shell command in the session, in its working directory and environment. "
        "Synchronously (200) the result carries the output and exit code; with "
        "`mode: async` or `?async=true` it answers 202 with a running command to read "
        "later. A closed session answers 409 `CONFLICT` with reason `closed`. " + _STARTED
    ),
    ("GET", _COMMAND): (
        "Returns the status of one command of the session: its state, exit code once "
        "finished and, for a command ended by a stop, the `stop_cause`. " + _TOOLBOX_READ
    ),
    ("POST", _COMMAND + "/kill"): (
        "Kills a running command and returns its status; a command that already finished "
        "is returned unchanged. An unknown command answers 404. " + _STARTED
    ),
    ("GET", _COMMAND + "/logs/follow"): (
        "Streams the command's output as server-sent events until it exits. Resume after a "
        "dropped connection with `Last-Event-ID` or `?offset=`; a `Last-Event-ID` that is not "
        "a byte offset answers 400, and an unknown command 404."
    ),
    # -- pty --------------------------------------------------------------------------------
    ("GET", _PTY): ("Lists the terminals of the sandbox. " + _TOOLBOX_READ),
    ("POST", _PTY): (
        "Opens an interactive terminal and returns its id, a single-use connect token and the "
        "websocket URL to attach to. Too many open terminals for the org answers 503 "
        "`CAPACITY` with `Retry-After`, and a driver without terminals 501. " + _STARTED
    ),
    ("DELETE", _PTY + "/{pty_id}"): (
        "Closes the terminal, ending its process, and returns it with state `closed`. An "
        "unknown terminal answers 404."
    ),
    ("GET", _PTY + "/{pty_id}"): ("Returns one terminal with its size and state. " + _TOOLBOX_READ),
    ("POST", _PTY + "/{pty_id}/resize"): (
        "Changes the rows and columns of an open terminal. A terminal that is already closed "
        "answers 409 `CONFLICT` with reason `closed`. " + _STARTED
    ),
    # -- snapshots --------------------------------------------------------------------------
    ("POST", "/v1/snapshots"): (
        "Registers a registry image as a snapshot: the image is pulled and pinned to its "
        "digest, and the call answers 201 with a ready snapshot. An image reference the "
        "policy refuses answers 422 and a name already in use 409 `CONFLICT` with reason "
        "`name_taken`."
    ),
    ("POST", "/v1/snapshots/from-sandbox"): (
        "Commits a sandbox into a snapshot and answers 202 with a pending row; poll the "
        "snapshot until it is `ready` or `error`. An unknown sandbox answers 404, a sandbox "
        "that is not started, stopped or in error 409 `INVALID_STATE`, and a name in use 409 "
        "`NAME_TAKEN`."
    ),
    ("DELETE", "/v1/snapshots/{snapshot_id}"): (
        "Deletes a snapshot and removes its image. A snapshot a sandbox still runs from "
        "answers 409 `CONFLICT` with reason `in_use`, and an unknown one 404."
    ),
    ("GET", "/v1/snapshots/{snapshot_id}"): (
        "Returns one snapshot with its state (`pending`, `ready` or `error`), digest and "
        "labels. An unknown id answers 404."
    ),
    # -- volumes ----------------------------------------------------------------------------
    ("POST", "/v1/volumes"): (
        "Creates a named volume and answers 201 with a ready volume. A name already used in "
        "the org answers 409 `CONFLICT` with reason `name_taken`; a key that holds shared "
        "volume labels may not create a volume carrying all of them (403)."
    ),
    ("DELETE", "/v1/volumes/{volume_id}"): (
        "Deletes a volume and its data. A volume that a sandbox still mounts answers 409 "
        "`CONFLICT` with reason `in_use`, and an unknown one 404."
    ),
    ("GET", "/v1/volumes/{volume_id}"): (
        "Returns one volume with its state and the last sampled size. An unknown id answers 404."
    ),
    # -- webhooks ---------------------------------------------------------------------------
    ("GET", "/v1/webhooks"): (
        "Lists the org's webhook endpoints; the signing secret is never included. The list "
        "is not paginated."
    ),
    ("POST", "/v1/webhooks"): (
        "Creates a webhook endpoint and returns its signing secret once; it is not shown "
        "again. A URL the SSRF guard refuses (for example a private address, or a host the "
        "resolver reports as not existing) answers 422 `UNPROCESSABLE`; a host that does not "
        "resolve carries `error.details.reason` `not_resolved`. A resolver that times out or "
        "fails is not a verdict on the URL: the lookup is retried once, then the call answers "
        "503 `DNS_UNAVAILABLE` (`error.details.reason` `dns_unavailable`, with `Retry-After`) "
        "and creates nothing; retry it. A lookup is cut off after 2.5 s per attempt."
    ),
    ("DELETE", "/v1/webhooks/{endpoint_id}"): (
        "Deletes a webhook endpoint and returns it. An unknown endpoint, or one of another "
        "org, answers 404."
    ),
    ("GET", "/v1/webhooks/{endpoint_id}"): (
        "Returns one webhook endpoint without its secret. An unknown endpoint, or one of "
        "another org, answers 404."
    ),
    ("PATCH", "/v1/webhooks/{endpoint_id}"): (
        "Changes the URL, event filter or enabled flag of an endpoint; omitted fields keep "
        "their value. A new URL is vetted by the SSRF guard (422, or 503 `DNS_UNAVAILABLE` when "
        "the DNS lookup failed; see the create call), and enabling a disabled endpoint resets "
        "its failure count."
    ),
}


def describe(method: str, path: str, operation: dict[str, Any]) -> dict[str, Any]:
    """``operation`` with the description for ``(method, path)`` when it has none of its own."""
    text = DESCRIPTIONS.get((method.upper(), path))
    if text is None or operation.get("description"):
        return operation
    return {**operation, "description": text}
