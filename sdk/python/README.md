# Sandfort Python SDK

Synchronous (`Client`) and asynchronous (`AsyncClient`) client for the Sandfort REST API.
Version `0.1.0`. Python 3.12 or newer; runtime dependencies are `httpx` and `websockets`.

This guide assumes the server from the repo quickstart is running on port 8000. Every call
below exists in `src/sandfort_sdk/`; the end-to-end versions are the gate scripts in
`examples/` (`gate2.py` and `gate3.py` cover most of this page).

## Install

The package is not published on a package index. From a repo checkout:

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e sdk/python
```

## Connect

```python
from sandfort_sdk import AsyncClient, Client

client = Client(base_url="http://127.0.0.1:8000", api_key="sf_...")
# async: aclient = AsyncClient(base_url="http://127.0.0.1:8000", api_key="sf_...")
```

The API key comes from `python -m sandfort.admin_cli bootstrap`, which prints the plaintext
`sf_...` key once. It cannot be recovered later.

Both clients are context managers (`with Client(...)`, `async with AsyncClient(...)`) and have
`close()` / `aclose()`. The optional `timeout` keyword is the per-request timeout in seconds
(default 30). The async client has the same methods; every call is awaited and returns the
same value types. The examples below are synchronous.

## Sandbox lifecycle

```python
sbx = client.create_sandbox(name="hello", snapshot="python:3.12-slim", wait=True)
print(sbx.id, sbx.state)          # state as returned at creation: "started"

info = client.get(sbx.id)         # fetch the current record
print(info.state)

client.stop(sbx.id)
client.delete(sbx.id)
```

- `snapshot` is an image reference such as `python:3.12-slim`, a snapshot id, or the name of a
  snapshot of your organization (gate 2 uses the first form, gate 3 the second).
  `examples/quickstart.py` omits it. A snapshot name wins over an image of the same name, and a
  value that matches no snapshot of yours is treated as an image reference; the server
  resolves the name to the id, so the rest is the same as a create by id.
- `wait=True` (the default) polls until the sandbox is `started`. `wait_timeout_s` (default
  120) and `poll_interval_s` (default 0.5) bound that wait. With `wait=False` the call
  returns the record as the server first reported it.
- `sbx.state` and `sbx.info` are the record from when the handle was built; they do not
  refresh. Call `client.get(sandbox_id)` for the current state.
- Other `create_sandbox` keywords: `resources` (a `Resources` value), `env`, `labels`,
  `block_network`, `auto_stop_minutes`, `auto_delete_minutes`, `public`, `mounts`.
- `client.start`, `client.stop` and `client.delete` take a sandbox id and return the
  updated handle. `client.list_sandboxes(state=..., labels=..., cursor=..., limit=...)`
  returns a `Page`; `client.iter_sandboxes(...)` walks all pages. Both hide `destroyed`
  tombstones unless `include_destroyed=True` (sent only when true; `state="destroyed"` always
  returns them). Both take `order="asc"` (oldest first, the server default) or `order="desc"`
  (newest first); it is sent only when given. `order` is typed `SortOrder`
  (`Literal["asc", "desc"]`, exported from `sandfort_sdk`), so a type checker flags any other
  value; at run time the SDK does not check it and the server refuses it with 422.
  `iter_sandboxes` sends the same `order` on every page. Both also take `stop_cause`, one of
  the `StopCause` literal values (sent only when given), for example
  `client.list_sandboxes(state="stopped", stop_cause="auto_stop")`; `iter_sandboxes` sends it
  on every page.
- `client.get(ref)` takes an id (`sbx_...`) or the name of a live sandbox. A name that matches
  nothing raises `NotFound`, which carries the `request_id` of the last list reply it searched;
  one that matches several raises `AmbiguousSandboxName` with the
  ids in `candidates` (a sandbox in the `error` state loses against any other with that name).
  `client.get_sandbox(ref)` is the same method under the name that sits next to
  `create_sandbox` and `list_sandboxes` (sync and async).
- `delete_on_failure=True` (the default): when the wait ends in the `error` state, the sandbox
  is deleted before `SandboxFailedError` is raised, so a failed create leaves no live error
  row. The error then has `deleted=True` and says so. `False` keeps the sandbox.
- With `wait=True`, one deadline of `wait_timeout_s`, started just before the create request
  is sent, bounds the whole blocking create. The POST's timeout is the time left (a server
  without jobs mode holds it open until the sandbox is `started`) and a timeout is not
  resent; a pause before a resend (for example after a `429 RATE_LIMITED`) counts, and one
  that would pass the deadline is not taken: the error is raised instead. The wait for
  `started` then long-polls only for the time left. When the POST times out,
  `SandboxTimeoutError` names the sandbox. If the cleanup below deleted the sandbox, the
  message says so ("the sandbox it made (sbx_...) was deleted, so nothing is left behind"),
  `sandbox_id` carries the id and `SandboxTimeoutError.deleted` is `True`. Otherwise the message
  says the create may still finish on the server (with an `idempotency_key`: resending the same
  call with that key returns the sandbox) and `deleted` is `False`, so code that handles the
  error need not parse the message. When the wait runs out, the error carries `sandbox_id` and
  the last `state`; `deleted` is `False` there too.
- Create timeout cleanup (`wait=True`, `delete_on_failure` and a `name`): the SDK looks the
  name up once before the POST (this lookup is not counted in `wait_timeout_s`). After a POST
  that timed out once sent, it makes one best-effort try (logged if it fails) to delete the
  sandbox found under the name, and only when the name was free before the call and that
  sandbox's `created_at` is no earlier than just before the POST less 60 s of clock skew.
  A sandbox that already had the name (an earlier attempt, another process), an older one or
  one without `created_at` is left alone, and a warning names its id. A timeout while
  connecting (`RequestTimedOut.request_sent` is `False`: the server never saw the request)
  never triggers the cleanup.
- A handle exposes the fields of its record as read-only properties: `id`, `name`, `state`,
  `isolation`, `resources`, `labels`, `env` (the names with the masked values the API returns;
  `env_keys` for the names only), `block_network`, `public`, `auto_stop_minutes`,
  `auto_delete_minutes`, `error_reason`, `error_code`, `stop_cause`, `stopped_at`, `job_id`,
  `snapshot`, `created_at` and `updated_at`. `snapshot`, `created_at` and `updated_at` are
  `None` while the server does not report them. For a label-scoped key (see "Code contexts,
  status and API keys") the server sends `job_id`, `node_id` and `snapshot` as `null`, because
  those are internal or may name something outside its scope. The server reports
  `created_at` (UTC, set once at create) and `updated_at` (UTC, moves forward when the record
  changes); both are also fields of the record (`sbx.info.created_at`, `sbx.info.updated_at`).
  `snapshot` holds the snapshot id (`snap_...`) or the image reference the sandbox was created
  from (a snapshot name of your organization is stored as its id). It is `None` for a sandbox
  created with no snapshot, for sandboxes created before the server recorded it, and against a
  server that does not report it.
  `SandboxInfo.error_code` is the machine-readable code next to `error_reason`: one of
  `image_not_found`, `registry_unreachable`, `registry_tls_error`, `image_access_denied`,
  `invalid_image_reference`, `start_failed`, `timeout`, `reset_failed`, `container_missing`, `container_exited`,
  `node_lost` (reserved, no path sets it yet) or `internal`; `None` when there is no error or
  the server does not report it. Branch on the code, not on the `error_reason` text. The handle
  has the same value as `sbx.error_code` (`sbx.info.error_code` reads the same field).
  `SandboxInfo.stop_cause` says why the sandbox stopped: `requested` (a user or API key asked),
  `auto_stop` (the idle scanner), `container_exited` (the reconciler found the container
  exited), `oom_killed` (memory limit; reserved, no server path sets it yet) or `unknown` (a
  stop recorded without a cause). It is `None` unless the state is `stopping` or `stopped`, and
  a successful start clears it. `SandboxInfo.stopped_at` is when the sandbox stopped (UTC); it
  is `None` unless the state is `stopped`. Both are `None` against a server that does not
  report them, and both are read-only properties of the handle (`sbx.stop_cause`,
  `sbx.stopped_at`). `stop_cause` stays `str | None`, so a cause a newer server adds does not
  break an older SDK. The constants `SANDBOX_STOP_CAUSE_*`, the `StopCause` type and
  `is_known_stop_cause(value)` are exported from `sandfort_sdk`; the guard narrows the string
  to `StopCause` for a type checker. Restart guidance per cause is in the
  `sandfort_sdk.stop_causes` module docstring.
  Whether a repeat can help: `registry_unreachable` (the network to the registry failed, or it
  throttled the pull with HTTP 429 or failed with HTTP 5xx; the image may exist) and `timeout`
  yes; `image_not_found`, `registry_tls_error` (the registry's TLS connection failed validation;
  fix the registry trust or configuration), `image_access_denied` (the registry refused the
  pull) and `invalid_image_reference` (the reference cannot be parsed) no, not with the same
  input; `start_failed` is a general driver error, so read `error_reason`.
  The field stays `str | None`, so a code a newer server adds does not break an older SDK. The
  constants `ERROR_CODE_*`, the `ErrorCode` type and `is_known_error_code(value)` are exported
  from `sandfort_sdk`, and `ErrorCode` covers all twelve codes above, the four image codes
  included (`ERROR_CODE_REGISTRY_UNREACHABLE`, `ERROR_CODE_REGISTRY_TLS_ERROR`,
  `ERROR_CODE_IMAGE_ACCESS_DENIED`, `ERROR_CODE_INVALID_IMAGE_REFERENCE`); `is_known_error_code()` returns `True` for each of them.
  Retryability: `registry_unreachable` is retryable (the registry did not answer, throttled the
  pull or failed with HTTP 5xx; try again after a pause); `registry_tls_error`,
  `image_access_denied` and `invalid_image_reference` are not, because they stay the same until
  the registry trust or configuration, the reference or the registry access changes. For those three the `error_reason` is a fixed
  sentence naming your reference; the daemon's own text is not returned.
  Older clients and `registry_tls_error`: an older SDK is unaffected by the new code.
  `SandboxInfo.error_code`, `Sandbox.error_code` and `SandboxFailedError.error_code` are
  deliberately `str | None`, not the `ErrorCode` Literal, so a client from before
  `registry_tls_error` (0.1.0b70 and earlier betas) receives it as a plain string. Nothing fails to
  parse, `is_known_error_code()` returns `False` on that client, and code that branches on the
  constants falls through to its default branch. Upgrading the SDK adds the constant and the
  Literal member; no other change is needed.
- A handle is a context manager (`with` / `async with`): leaving the block deletes the sandbox.
  A delete of a sandbox that is gone already is ignored. Any other delete error is raised,
  unless an exception is already propagating out of the block: that one is never masked, and
  the delete error is logged instead.

```python
with client.create_sandbox(name="scratch") as sbx:
    print(sbx.process_exec("echo hi").stdout)
```

## Run commands

`process_exec` takes exactly one of `command` (a shell string) or `argv` (a list). A list or
tuple passed as `command` is sent as `argv` (never as a shell string); an empty list, a list of
non-strings, or a list together with `argv` is a `ValueError`. A non-zero exit code is returned
in the result; it does not raise.

```python
result = sbx.process_exec(argv=["python3", "-c", "import sys; print(21 * 2); sys.exit(3)"])
print(result.exit_code, result.stdout.strip())   # 3 42
print(result.stderr, result.timed_out, result.truncated, result.duration_ms)
```

Optional keywords: `cwd`, `env`, `stdin`, `timeout_s` (default 60). `ExecResult.ok` (and
`CellResult.ok`) is true only when the exit code is 0, `stop_reason` is `None`, the command did
not time out and its output was not `truncated`: a run stopped for `output_limit` can report
exit code 0 and is still not ok.

`code_run` writes a snippet into the sandbox and runs it with the language's interpreter.
The server accepts `python`, `javascript`, `typescript` and `bash`; any other value is
rejected as `Unprocessable`. The interpreter must exist in the sandbox image, and
`typescript` runs through `npx --yes tsx`, which needs outbound network.

```python
ok = sbx.code_run("python", "print('hello from code_run')")
print(ok.exit_code, ok.stdout)                   # 0 hello from code_run

bad = sbx.code_run("python", "raise ValueError('boom')")
print(bad.exit_code)                             # non-zero
print(bad.stderr)                                # the interpreter's traceback, ending in ValueError: boom
```

`code_run` also accepts `argv`, `env` and `timeout_s`. It has no `idempotency_key`: the server
honours `Idempotency-Key` on `process/execute` only, so a repeated `code_run` runs again.

### Retry-safe exec: `idempotency_key`

```python
result = sbx.process_exec(argv=["make", "deploy"], idempotency_key="deploy-2026-11-11")
again = sbx.process_exec(argv=["make", "deploy"], idempotency_key="deploy-2026-11-11")
print(again.replayed)                            # True: the first result, nothing ran again
```

`idempotency_key` (on `process_exec` and `sbx.process.exec`, sync and async) is sent as
`Idempotency-Key`. It must be 1 to 255 printable ASCII characters (space to `~`, no leading or
trailing space), otherwise a `ValueError` is raised before any request. The server keeps the key
for 24 hours, per API key and sandbox. The same key and arguments return the first result and
`ExecResult.replayed` is `True` (from the `Idempotent-Replayed: true` header; `False` for a
real run and when no key is given). The same key with other arguments is 422
`IdempotencyMismatch`; a running first request is a 409 that the SDK waits out like a 503.
Because the key makes the call safe to repeat, the SDK resends it after a connection error or
a `503` (see Retries below); without a key an exec is never resent. A result cut short by a
stop, delete or reset of the sandbox, a failed attempt, and output over 256 KiB are not kept
(the latter answers 409 `IDEMPOTENCY_RESULT_UNAVAILABLE`). The CLI has the same option:
`sandfort exec --idempotency-key KEY SANDBOX -- CMD`.

## Files

`sbx.fs` operations (all take sandbox paths):

- `list_dir(path="/")` returns a `DirListing`; its `entries` are `FileEntry` values.
- `stat(path)` returns one `FileEntry` (`name`, `path`, `kind`, `size_bytes`, `mode`).
- `mkdir(path, mode="755", parents=True)`.
- `move(source, destination, overwrite=False)`.
- `delete(path, recursive=False)`.
- `upload_file(path, data, overwrite=True, mode="644")`; `data` is `bytes` or a binary file
  object (`size_bytes` is required if the object is not seekable). An upload is limited to
  256 MiB (268435456 bytes): a larger one raises `PayloadTooLarge` before any request is sent
  (`details["limit_bytes"]`, `details["size_bytes"]`), and the server answers the same 413
  before it reads the body.
- `download_file(path, range=None)` streams chunks, `read_bytes(path, range=None)` returns the
  whole file. `range=(start, end)` reads only those bytes (`end` inclusive, `None` for "to the
  end"); a start at or past the end of the file raises `ApiError` with status 416, and so does
  any range on an empty file (read an empty file without a range).
- `download_dir(path)` streams a directory as an uncompressed tar archive.

The SDK has no filesystem search or replace calls. `sbx.git` also exists; see `git.py`.

```python
sbx.fs.mkdir("/work/app")
sbx.fs.upload_file("/work/app/hello.txt", b"hello\n")
print([e.name for e in sbx.fs.list_dir("/work/app").entries])   # ['hello.txt']
assert sbx.fs.read_bytes("/work/app/hello.txt") == b"hello\n"
```

`download_file` and `download_dir` check the path kind: using the wrong one raises
`InvalidResponseError`. A `range` the server does not honour (it answers 200 instead of 206)
also raises `InvalidResponseError`, so a resume never appends a whole file to a partial one.

Resume an interrupted download of a large file (the server answers `206 Partial Content`; a
directory tar has no ranges):

```python
import os

remote, local = "/data/big.bin", "big.bin.part"
size = sbx.fs.stat(remote).size_bytes
done = os.path.getsize(local) if os.path.exists(local) else 0
if done < size:  # a start at the end of the file would be a 416
    with sbx.fs.download_file(remote, range=(done, None)) as stream, open(local, "ab") as out:
        for chunk in stream:
            out.write(chunk)
assert os.path.getsize(local) == size
```

If the file may have changed between attempts, compare `stat(remote).modified_at` first and
start over when it differs. The SDK does not send `If-Range`; a raw HTTP caller can send
`If-Range: <ETag of the first response>` with its `Range`, and the server then answers `200`
with the whole file instead of `206` when the file has changed. The `ETag` is weak and a date
form of `If-Range` never matches. If-Range is compared to the weak ETag; this deviates from
RFC 9110, which forbids weak validators there, so a changed file with an unchanged mtime could
resume wrongly.

## Sessions and long commands

A session keeps shell state between commands. `execute_session_command` runs synchronously
by default and returns a `SessionExecResult` whose `result` is an `ExecResult`. With
`run_async=True` it returns at once and `command` holds the running `CommandInfo`.

```python
session = sbx.process.create_session()
sbx.process.execute_session_command(session.id, "cd /work/app")
pwd = sbx.process.execute_session_command(session.id, "pwd")
print(pwd.result.stdout.strip())                 # /work/app

started = sbx.process.execute_session_command(session.id, "for i in 1 2 3; do echo $i; sleep 1; done", run_async=True)
with sbx.process.follow_logs(session.id, started.command.id) as stream:
    for event in stream:
        if event.is_exit:
            print("exit code", event.exit_code)
            break
        print(event.stream, event.line, end="")
```

`follow_logs` yields `LogEvent` values (one `stdout` or `stderr` line each, terminator
included, then a final `exit` event) and accepts `offset` to resume. If the stream ends
before the `exit` event it raises `TransportError`. Also available on `sbx.process`: `list_sessions`, `get_session`,
`get_command`, `get_command_logs(offset=, limit=)` for polling instead of streaming, and
`kill_command`.

`CommandInfo.stop_cause`, `LogPage.stop_cause` and the `exit` `LogEvent.stop_cause` are
`"sandbox_stopped"` (`COMMAND_STOP_CAUSE_SANDBOX_STOPPED`, type `CommandStopCause`) when a
sandbox stop ended the command (state `killed`, `exit_code` `None`), otherwise `None`. They stay
`str | None` so a cause a newer server adds does not break the SDK; narrow with
`is_known_command_stop_cause`. This is not the sandbox `StopCause`, which has five other values.

`sbx.pty` provides interactive terminals: `with sbx.pty.create(rows=24, cols=80) as pty:`
then `pty.send_bytes(b"...")`, iterate `pty` for output bytes, and `pty.resize(rows, cols)`.
`gate2.py` shows a full round trip.

## Snapshots

`client.snapshots.create_from_sandbox(sandbox_id, name)` commits a sandbox into a snapshot.
It returns immediately with state `pending`. The state becomes `ready` when the commit
finishes, or `error`. **A sandbox can only be started from a snapshot that is `ready`**, so
poll before using it:

```python
import time

snap = client.snapshots.create_from_sandbox(sbx.id, name="after-setup")   # state: pending
while snap.state == "pending":
    time.sleep(0.5)
    snap = client.snapshots.get(snap.id)
if snap.state != "ready":
    raise RuntimeError(f"snapshot {snap.id} ended in state {snap.state}")

child = client.create_sandbox(name="child", snapshot=snap.id, wait=True)
print(child.fs.read_bytes("/work/app/hello.txt"))   # b'hello\n'
```

Snapshot states are `pending`, `ready`, `error` and `deleting`. Related calls on
`client.snapshots`: `register(image, name=)`, `list`, `iter`, `get`, `delete`, and
`build(image_or_spec)` with `follow_build_logs(snapshot_id)` for declarative images (the
`Image` class). `delete` raises `Conflict` while a sandbox uses the snapshot.

`client.export_snapshot(snapshot_id, path)` (also `client.snapshots.export`) streams a `ready`
snapshot to a file as an image tar and returns the byte count. The body is written in chunks,
never held in memory, and a failed download removes the partial file. Load the tar with
`docker load -i <path>`. A snapshot that is not `ready` raises `InvalidState`.

## Volumes

```python
from sandfort_sdk import VolumeMount

vol = client.volumes.create(name="shared")
a = client.create_sandbox(name="a", snapshot="python:3.12-slim", mounts=[VolumeMount(vol.id, "/data")])
b = client.create_sandbox(name="b", snapshot="python:3.12-slim", mounts=[(vol.id, "/data")])
a.fs.upload_file("/data/x.txt", b"shared\n")
assert b.fs.read_bytes("/data/x.txt") == b"shared\n"
```

`client.volumes` also has `list`, `iter`, `get` and `delete`. Deleting a volume while a
sandbox mounts it raises `Conflict` (gate 3 checks this).

## Code contexts, status and API keys

`sbx.code_contexts` runs Python in a persistent kernel, like a notebook: variables and imports
survive between runs. The state lives in the kernel process, so it is lost when the sandbox is
stopped, reset or deleted.

```python
ctx = sbx.code_contexts.create(cwd="/work")        # cwd=None: the sandbox default
ctx.run("x = 40")
print(ctx.run("print(x + 2)", timeout_s=20).stdout)   # 42
print([c.id for c in sbx.code_contexts.list()])
ctx.delete()
```

A context can have a name, unique among the live contexts of its sandbox (the character rules
of sandbox names, at most 63 characters). `sbx.code_contexts.ensure(name, language="python",
cwd=None)` (async: `await ...ensure(...)`) returns the live context of that name or starts one;
`create(cwd=None, *, name=None, language="python")` does the same when given a `name`, and
`ctx.name` is `None` for an unnamed context. `cwd` is used only when a context is created.
The call is idempotent, so it brings a context back after the sandbox was stopped (auto-stop
included), reset or deleted and started again, but the state is not restored: variables, imports
and loaded data are gone, so run the setup cells again. The server answers 200 for an existing
context and 201 for a new one, and the handle says which: `ctx.created` (read-only) is `True`
when the call started the kernel and `False` when it found a live one, so no probe cell is needed
to decide whether to re-run the setup. `create()` without a name is always `True`; a context from
`list()` is `False`. A named `create`/`ensure` is resent after a 429 `RATE_LIMITED` like any
other call; `list()` returns each context with its `name`.

A call on a context whose kernel is gone raises `NoContainer` (the sandbox is stopped) or
`NotFound` (the context or the sandbox was deleted). `CONTEXT_GONE_ERRORS` (exported from the
package root) is that pair, so a restart-safe wrapper needs one `except`:

```python
from sandfort_sdk import CONTEXT_GONE_ERRORS

ctx = sbx.code_contexts.ensure("analysis", cwd="/work")
if ctx.created:   # a new, empty kernel: run the setup
    ctx.run("import pandas as pd\ndf = pd.read_csv('sales.csv')")
try:
    ctx.run("df.describe()")
except CONTEXT_GONE_ERRORS:
    ...   # start the sandbox if needed, then ensure() again
```

`run` returns a `CellResult`, an `ExecResult` subclass: every `ExecResult` field plus `result`
(the `repr()` of the trailing expression, or `None`) and `error` (a `CellError` with `type` and
`message` when the cell raised, else `None`; the traceback stays on `stderr`). A cell that hits
`timeout_s` reports `timed_out` and keeps the state. Only Python is supported.

`ctx.run_stream(code, timeout_s=60)` runs a cell like `run` but yields its output as it is
written: an `OutputChunk` (`stream` is `"stdout"` or `"stderr"`, `data` is the text) for each
output event, then the same `CellResult` that `run` returns as the last item. Errors before the
stream starts (`NotFound`, `NoContainer`, `ValidationFailed`) are raised by the `run_stream`
call, as `run` raises them. An error event the server sends during the stream (it takes the place
of the `result` event) raises the matching SDK exception from the iteration, not
`TransportError`: the `ApiError` subclass for the event's `code`, as for a normal error reply
(plain `ApiError` for a code the SDK does not know). It carries `code` and `message`, the
`request_id` of the stream response (its `x-request-id` header) and the `status_code` of that
response (200, because the failure arrived inside the stream); `details` is the event's
`details` object, or `{}` when the event has none (`has_details` is then `False`, as it is for an
error reply without details). An error event whose data is not JSON, or
whose `code` or `message` is not a string, raises `InvalidResponseError`. `TransportError` is
raised only when the stream ends with neither an error event nor a result, or the read breaks
off. Both `InvalidResponseError` and `TransportError` from a stream carry `request_id`, the
`x-request-id` header of the stream response (`None` when it had none). Close the stream (or
use `with`) to stop reading early. There is no separate queue timeout: a run that waits for
another run of the context gives up after its own `timeout_s`. `stdout` is streamed by whole
lines: the server holds the last line back until its newline arrives (or the run ends), so a
partial line and a carriage-return progress bar arrive late; `stderr` is forwarded as it arrives.
The final `CellResult` carries `stop_reason`, `timed_out` and `sandbox_stopped` exactly as the
`run` result does, sync and async, so a stream cut short by a sandbox stop reports
`stop_reason` `"sandbox_stopped"` and a normal end reports `None` (see the `stop_reason` notes
below). A sandbox stopped during a streamed run ends the stream with a normal `result` event
carrying `stop_reason` `sandbox_stopped`, not an `error` event, so the SDK raises nothing; a
dedicated `error` event is reserved for server-side failures.
The sync call returns a
`CellStream` and the async call an `AsyncCellStream` (both exported, with `OutputChunk`); they
have `close()` / `aclose()` and a `closed` property. The call posts to
`.../code-contexts/{id}/run/stream`, a route the server in this repository defines
(`stream_code_context_run`, d43eec1) and the committed `openapi/sandfort.v1.json` lists. Whether
a deployed server has it depends on its version (a server without it answers 404; use `run`
there).

```python
from sandfort_sdk import CellResult

for event in ctx.run_stream("for i in range(3): print(i)\n42"):
    if isinstance(event, CellResult):
        print("result:", event.result, "exit:", event.exit_code)
    else:
        print(event.stream, event.data, end="")

# async: stream = await ctx.run_stream(code); async for event in stream: ...
```

`ctx.interrupt()` sends the kernel an interrupt and returns `True`, or `False` when no cell is
running or the context has no live kernel. It names no cell: whichever cell is running raises
`KeyboardInterrupt` (`error.type`), and between cells nothing is signalled. The interrupt reaches Python code only. A cell
stuck in native code (a long C call that never returns to Python) goes on: its own `timeout_s`
ends it only once control is back in Python, and later runs on the context queue behind it,
each for up to its own queue timeout. Only when a run's exec deadline (`timeout_s` plus a 5 s
margin) passes with the cell still not answering is the kernel sent an interrupt and given 2 s;
a kernel that still does not answer is stopped and the context removed only after that grace,
and later runs on it raise `NotFound`. In that case `stderr` says "the cell exceeded its N s
limit and the kernel did not stop when interrupted; its state is lost", with N the cell's own
`timeout_s`. The state of the context stays after an interrupt.
`CodeContext` and `AsyncCodeContext` are context managers: leaving the block deletes the
context, and a context that is gone already is ignored.

The context's working directory (`cwd`) is first on `sys.path`, as in `code_run`, so a module
file written there imports from a cell. When a cell times out or is interrupted while
`multiprocessing` children started with `spawn` or `forkserver` are alive, the hint line that
ends `error.message` is also written as the last line of `stderr`.

A traceback names each cell separately (`<cell-1>`, `<cell-2>`, ...), so a function defined in
an earlier cell shows its own source line when a later cell calls it (the source of the last 100
cells is kept; a syntax error names `<cell>`). `result` and the `error` type and message are cut
to 4096 characters and end in `... [truncated]`; `stdout` still holds the whole `repr`. A
run's `stdout` is limited to 1 MiB minus 64 KiB so that `result` and `error` always fit. A run
stopped at that limit (`stop_reason` `output_limit`) reports `exit_code` 137, whichever stream
overflowed.

`stop_reason` stays `str | None`, so a value a newer server adds does not break your code.
`STOP_REASON_*` constants and the `StopReason` type are exported from `sandfort_sdk`;
`is_known_stop_reason(value)` narrows a value to `StopReason`. Code-context runs add
`queue_timeout` (the run waited for another run of the same context and gave up; the context is
kept) and `context_lost` (the kernel died or was deleted mid-run, or a stuck cell's kernel was
stopped and its context removed). A run that ends in `context_lost` after its exec deadline
still has exit code 124 and `timed_out` true, and it reports `context_lost` instead of
`timeout`, so code that checks only `stop_reason == "timeout"` must also check
`context_lost`. It is reported only when the context was really removed: a kernel that answers
the interrupt, or a probe that is slow or fails, keeps the context and the run stays `timeout`.

### Async example

The server runs the cells of one context one at a time, so cells started concurrently queue
behind each other, in the order their requests reach the server. That order is not fixed within
one `asyncio.gather`, so do not rely on it for cells that depend on each other. Use one context
per independent line of work. Parallel cells on one sandbox share one kernel host, so use a
pool of sandboxes for parallel work.

```python
import asyncio

from sandfort_sdk import (
    STOP_REASON_CONTEXT_LOST,
    STOP_REASON_QUEUE_TIMEOUT,
    STOP_REASON_TIMEOUT,
    AsyncClient,
    is_known_stop_reason,
)


async def main() -> None:
    async with AsyncClient("https://sandfort.example", "sf_...") as client:
        async with await client.create_sandbox(name="agent", wait=True) as sbx:
            async with await sbx.code_contexts.create() as ctx:   # deleted on exit
                await ctx.run("total = 0")
                # Concurrent runs are serialized per context: they run one after the other.
                cells = await asyncio.gather(
                    *(ctx.run(f"total += {n}\ntotal") for n in range(1, 4))
                )
                print(max(int(c.result or 0) for c in cells))     # 6

                slow = asyncio.create_task(ctx.run("import time; time.sleep(60)", timeout_s=90))
                await asyncio.sleep(1)
                print(await ctx.interrupt())                      # True
                cell = await slow
                if cell.error is not None:
                    print(cell.error.type)                        # KeyboardInterrupt

                cell = await ctx.run("1 / 0")
                print(cell.result, cell.error)                    # None CellError(type=...)

                cell = await ctx.run("40 + 2")
                print(cell.result)                                # 42
                if cell.stop_reason in (STOP_REASON_TIMEOUT, STOP_REASON_QUEUE_TIMEOUT):
                    ...                                           # retry later or raise timeout_s
                elif cell.stop_reason == STOP_REASON_CONTEXT_LOST:
                    ctx = await sbx.code_contexts.create()        # the kernel state is gone
                elif is_known_stop_reason(cell.stop_reason):
                    ...                                           # another reason this SDK knows
                elif cell.stop_reason is not None:
                    ...                                           # a reason a newer server sent


asyncio.run(main())
```

**Cancellation.** Cancelling a task that awaits `ctx.run(...)` closes its HTTP request, and the
server then interrupts that run's own cell (each run has a cell number the kernel checks), never
a later one. A run that hit the output limit or whose client went away is interrupted the same
way. The server waits up to 2 s for the interrupted cell to end. A cell stuck in native code may
not stop in that time and may keep running; the next run then queues behind it. When a run's
exec deadline passes and the kernel does not answer the interrupt within 2 s, the context is
removed after that grace and the run reports `context_lost` (with `timed_out` true and exit code
124). A kernel that answers keeps its context and the run reports `timeout`. `ctx.interrupt()` and the REST route
are different: they interrupt whatever cell is running at that moment and never remove the
context.

`client.status()` returns a `StatusInfo` (`status`, `version`, `build_sha`, `started_at` and
`notice`, a `StatusNotice` with `message` and `updated_at`, or `None`). It also carries
`image_sha` (the build baked into the image), `build_matches_image` (`True` when it equals
`build_sha`, `None` when either is unknown), `audit_public_key` (the Ed25519 public key, urlsafe
base64, that verifies signed audit heads; `None` unless heads are signed) and
`audit_key_fingerprint` (`None` unless the server sends one). All four are optional and `None`
on older servers. The route needs no authentication.

API keys need the `api_keys:admin` scope. The plaintext key is in the answer of the create
and nowhere else:

```python
from datetime import UTC, datetime

created = client.create_api_key(
    "ci", ["sandboxes:read", "toolbox"],
    sandbox_labels={"team": "a"}, max_sandboxes=5,      # the cap needs sandbox_labels
    expires_at=datetime(2027, 1, 1, tzinfo=UTC),        # must be timezone-aware
)
print(created.key)                                      # shown once
keys = client.list_api_keys()                           # metadata only
client.revoke_api_key(created.id)                       # repeating it is harmless
```

Every key answer carries a `status`, computed by the server when it answers: `revoked` once
`revoked_at` is set, otherwise `expired` once `expires_at` has passed, otherwise `active`
(`revoked` wins). `ApiKeyInfo.status` holds that value (`CreatedApiKey` has it too), and
`ApiKeyStatus` (exported from `sandfort_sdk`) is the `Literal` of the three values; the field
itself stays a plain `str`, so a value a newer server adds still loads as sent. Against a server that
predates the field, `status` loads as `"active"` whatever `revoked_at` says, so read
`revoked_at` and `expires_at` there. The status is as of the answer: a key can expire after
you listed it.

**Label-scoped keys and create.** A key made with `sandbox_labels` adds those labels to every
sandbox it creates, automatically. A `create_sandbox` with no `labels`, or with extra labels
under other names, is therefore an in-scope create, and it meets the key's `max_sandboxes` cap
with `QuotaExceeded` (429) like any other create. Only a label that contradicts the scope (the
same label name with another value) is refused, with `Forbidden` (403), and that refusal happens
before the cap and the quota are checked, so it is never masked by a `QuotaExceeded`. The same
key gets `null` for `node_id`, `job_id` and `snapshot` in sandbox objects and for
`source_sandbox_id`, `image_ref` and `digest` in snapshot objects and in image-build answers
(`SnapshotInfo.image_ref` and `digest` are optional, `None` for such a key).

All of these exist on `AsyncClient` and `AsyncSandbox` with `await`.

## Retries and idempotent create

`Client` and `AsyncClient` resend a request on their own when it is safe to repeat: `GET`,
`HEAD`, `DELETE`, or a `POST` that carries an `Idempotency-Key` header. The one exception that
covers every method is a `429` with code `RATE_LIMITED`: the server did not process that
request, so it is resent for a `POST` without a key, `PUT` and `PATCH` as well, but only when
the body can be sent again (a JSON body, bytes, or no body). An upload from a file object is
a one-shot stream: after `RATE_LIMITED` it is not resent and `RateLimited` is raised at once.

- `429`: waits `Retry-After` (seconds or an HTTP-date; at most 30 s), then resends. A `429`
  with code `QUOTA_EXCEEDED` is never resent: a quota does not free itself. For a call that
  is not safe to repeat, only code `RATE_LIMITED` is resent.
- `503`, or a connection or timeout error before any response: waits 0.5 s, 1 s, 2 s, ...
  (at most 8 s), then resends. The pause has full jitter: a random value between half and
  all of that delay. A `503` that carries `Retry-After` (seconds or an HTTP-date) waits at least
  that long, at most 30 s, or the back-off pause when that is longer; a `503` without the header
  keeps the back-off alone. So a resent call that gets a `503` `CAPACITY` (`Retry-After: 5`)
  waits about 5 s, not 0.5 s. Only calls that are safe to repeat are resent (see above), and
  `retry_after_s` stays on the raised exception.
- `409` with `details.reason == "in_progress"`, for a `POST` that carries an `Idempotency-Key`
  only: backs off like a `503`, so a resend while the first create is still running waits for
  it instead of failing.
- Any other answer, a `POST` without a key (except after `RATE_LIMITED`), `PUT`/`PATCH` (for
  example uploads; a bytes upload only after `RATE_LIMITED`, a file-object upload never), and
  streams (SSE log follow, downloads) are never resent.
- `max_retries` (default `2`, `0` disables) caps the resends. After the last attempt the
  original error (`RateLimited`, `CapacityExceeded`, `TransportError`, ...) is raised as is.

```python
client = Client(base_url, api_key, max_retries=3)
sandbox = client.create_sandbox(name="job-42", idempotency_key="job-42-create")
```

`idempotency_key` is sent as `Idempotency-Key`. Retrying the create with the same key and the
same arguments returns the same sandbox (the server answers with `idempotent-replayed: true`),
so a network failure during create does not leave a second sandbox behind. The same key with
other arguments answers 422 `IDEMPOTENCY_MISMATCH`, raised as `IdempotencyMismatch`. The server
keeps the first response of a key for one day (24 hours). A replay inside that window answers the
stored status code with the sandbox's current state, not the stored body (a sandbox deleted in the
meantime replays as `destroyed`); after the window the key is forgotten and the same call creates
a new sandbox.

## Errors

`SandfortSDKError` (`sandfort_sdk.exceptions`, also exported from the package root) is the base
to catch everything the SDK raises. `ApiError` covers only the HTTP error answers of the
server; `SandboxFailedError`, `SandboxTimeoutError`, `AmbiguousSandboxName` and
`TransportError` are siblings of it, so `except ApiError` does not catch them.

- `TransportError`: no response (connect failure, timeout) or a log stream that ended early.
  `RequestTimedOut` (a subclass) is the timeout case. `request_id` is set when a code-context
  run stream broke off after its response began (its `x-request-id`), else `None`.
- `InvalidResponseError`: a successful response with an unexpected shape, or a file/directory
  mismatch on download; `request_id` as for `TransportError`.
- `CONTEXT_GONE_ERRORS`: the tuple `(NoContainer, NotFound)`, for one `except` around calls on a
  code context whose kernel is gone (sandbox stopped, or context or sandbox deleted).
- `SandboxTimeoutError`: the sandbox was not `started` within `wait_timeout_s`, or the create
  request outlived it (the message then says whether the cleanup deleted the sandbox, and
  `deleted` is `True` exactly when it did; the attributes `sandbox_id` and `state` are `None` when
  there is no sandbox to name).
  `SandboxFailedError` (attributes `sandbox_id`, `state`, `error_reason`, `error_code`,
  `deleted`, `request_id`; `error_code` is the sandbox's code, for example `"image_not_found"`
  or `"timeout"`, and is kept when the create deleted the failed sandbox): it reached
  `error`, `destroying` or `destroyed`; `request_id` is the `x-request-id` of the reply that
  showed that state (the create path fills it; `sandfort sandbox create --json` repeats it in
  `error.request_id`). Its subclass `SandboxDestroyedError` is raised when the sandbox is
  `destroyed`, for example when a create with an `idempotency_key` is replayed (with `wait`)
  after the sandbox it made was deleted: `state` is `"destroyed"`, `error_code` is `None` unless
  the record kept a code from before the delete, and `except SandboxFailedError` still catches it.
  `SandboxFailedError` and `SandboxDestroyedError` pickle and copy (`pickle`, `copy.copy`,
  `copy.deepcopy`) with their attributes intact.
  `AmbiguousSandboxName`: `client.get(name)` matched several live sandboxes.
- `SnapshotInfo`: `image_ref` and `digest` are `None` when the server hides them, which it does
  for a label-scoped API key; check for `None` before using them.
- `ApiError`: any error returned by the server, with `code`, `status_code`, `details` (a dict,
  `{}` when the server sent none, never `None`), `has_details` (`True` only when the server sent
  a non-empty `details` object, so "no details" can be told apart from some) and
  `request_id`. Subclasses by server code: `ValidationFailed` (and its subclass
  `IdempotencyMismatch`, code `IDEMPOTENCY_MISMATCH`), `Unauthorized`, `Forbidden`, `NotFound`,
  `Conflict` with its subclasses `NameTaken` (409 `details.reason` `name_taken`: the name is in
  use) and `NoContainer` (`no_container`: the sandbox is stopped or deleted; `state` holds
  `details.state` or `None`), so `except Conflict` still catches both and any other 409
  stays a plain `Conflict`; `InvalidState`, `PayloadTooLarge`, `Unprocessable`, `QuotaExceeded`,
  `RateLimited` (adds `retry_after_s`), `ServiceUnavailable` (any 503, for example
  `NODE_UNAVAILABLE`; adds `retry_after_s`) with its subclass `CapacityExceeded` (`CAPACITY`),
  `InternalError`, `Unsupported`, `DriverTimeout`, `DriverError`. An unrecognized code raises
  plain `ApiError`, except that every 503 is a `ServiceUnavailable`.
- Argument problems caught before a request is sent (for example both or neither of `command`
  and `argv`) raise `ValueError`.

## License

Apache-2.0, see `LICENSE` in this directory. The Sandfort server is licensed separately under
FSL-1.1-Apache-2.0; see the repository root.
