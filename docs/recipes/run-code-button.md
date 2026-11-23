# Recipe: a student-facing "Run code" button

A button that runs code a student typed. The code is untrusted, the student is waiting, and the
sandbox must be clean, small and offline. Examples use the Python SDK; the REST fields are the
same. Facts below come from the code (commits are in brackets) or from measurements on the
hosted beta, which are single evaluator measurements, not an SLO.

## 1. Create the sandbox

```python
from sandfort_sdk import Client, Resources

sbx = client.create_sandbox(
    name=f"student-{session_id}",
    snapshot="python:3.12-slim",            # node:22-bookworm for javascript / typescript
    resources=Resources(cpu_millicores=500, memory_mib=256, disk_gib=1),
    block_network=True,                      # untrusted code: no network, no DNS
    auto_stop_minutes=10,
    auto_delete_minutes=60,
    labels={"app": "run-button", "session": session_id},
)
```

- **No network.** `block_network=True` (REST: `network: {"block_all": true}`) removes the
  network and DNS on every tier. On a self-hosted server, set `SANDFORT_DEFAULT_BLOCK_NETWORK=true`
  and every create that names no network policy gets `block_all` (a5b9390). An explicit
  `block_network=False` still opens the network, and a create with an `egress_allowlist` keeps its
  own rules. The CLI has `--block-network` and `--no-block-network` (b58a0ff).
- **Small, explicit resources.** The defaults are `cpu_millicores=1000`, `memory_mib=512`,
  `disk_gib=3`. Pass your own so a student cannot take more than the budget you chose, and so the
  org quota covers the number of concurrent students.
- **Timers.** `auto_stop_minutes` counts idle minutes (API default 15); `auto_delete_minutes`
  counts minutes since the sandbox stopped (API default off, `-1`). The values above stop an idle
  student sandbox after 10 minutes and delete it an hour after that. A negative value means never,
  and `0` for auto-delete deletes the sandbox on the next sweep after it stops. Read them back with
  `sbx.auto_stop_minutes` and `sbx.auto_delete_minutes` (63b3d72).
- **Image.** The default `python:3.12-slim` has no Node. `javascript` and `typescript` need an
  image with Node such as `node:22-bookworm`. On the beta the first create from that image pulled
  it and took about 19.5 s; later creates reuse the pulled image. Create one warm sandbox from the
  image before the class starts, or accept one slow first click.

## 2. One sandbox per session, or one per run

| Strategy | Run cost on the beta | Use when |
|---|---|---|
| One sandbox per student session, reused | about 0.4 s per run (measured on the beta) | Students build on earlier files, or latency matters. |
| One sandbox per run (create, run, delete) | about 1 s (measured on the beta) | Every run must start clean and you do not want to call `reset`. |

Both numbers are single measurements on a shared evaluation VM; measure on your own host.
Reuse one sandbox per student session and delete it when the session ends. Do not share one
sandbox between students.

## 3. Run the code

```python
result = sbx.process.code_run("python", student_code, timeout_s=10)
```

- `timeout_s` defaults to 60. Set it to what a lesson needs. It is a budget, not an exact cutoff:
  the call returns within about 0.2-1.5 s after it.
- Output is capped at 1 MiB per call.
- A non-zero exit code is a normal result (HTTP 200), not an exception.
- **Working directory.** `code_run` runs in the sandbox's working directory, so relative paths in
  the student's code (`open("data.csv")`) see the files you uploaded, and files the code writes
  persist for the next run. An optional `cwd` field overrides the directory
  (`sbx.process.code_run(..., cwd="/work")`; the `sbx.code_run` shortcut does not take it)
  (b58a0ff). The script itself lives in a private per-run directory under `/tmp`, removed after
  the run (7202c31).
- **Tracebacks.** A Python traceback names the short script, `File "main.py", line 3`, and still
  prints the offending source line; the private directory is not shown (e61bc9c). The other
  languages get the absolute path of that directory, for example
  `/tmp/.sandfort-run-<random>/main.js`. The directory changes per run; the file name is `main`
  plus the language suffix (`main.js`, `main.ts`, `main.sh`). If you show those tracebacks to
  students, strip the directory, for example with a regular expression on
  `/tmp/\.sandfort-run-[0-9a-f]+/`.
- **`input()` is not interactive.** The code-run request has no stdin field and the exec attaches
  no stdin, so `input()` does not wait for the student; Python raises `EOFError`. Pass data
  through `argv` or a file, or collect it in your UI before the run.

## 4. Map the result to a student message

`stop_reason` is derived from the result flags, never from the output text (63b3d72). It is
`null` for a normal exit.

| `stop_reason` | `exit_code` | Meaning | Message to show |
|---|---|---|---|
| `timeout` | 124, `timed_out=true` | The command hit `timeout_s`; the last line of stderr says "the command was stopped after N s (timeout); allow more time, up to 3600 s" (on its own line; it names no parameter, so do not match on a parameter name). | "Your program ran too long. Check for an endless loop." |
| `output_limit` | any, `truncated=true` | Output reached 1 MiB and the command was stopped. | "Your program printed too much output." |
| `sandbox_stopped` | 137, `sandbox_stopped=true` | The sandbox died during the run (for example a fork bomb, or a memory limit on the `gvisor` tier). | "The environment stopped. Restarting it." Then `sbx.start()` and offer a re-run. |
| `killed` | 137 | The process got SIGKILL: usually an out-of-memory kill, or the code killed itself. | "Your program used too much memory or was killed." |
| `null` | 0 | Success. | Show stdout. |
| `null` | 1 or other | The program failed (an uncaught Python exception exits 1). | Show stderr as the program's error. |
| `null` | 127 | Command not found, for example `node` in the Python image. | "This language is not available here." (an operator problem) |

Precedence when several flags are set: timeout, output limit, sandbox stopped, killed.

```python
if result.stop_reason == "sandbox_stopped":
    sbx.start()          # the server settled the state to stopped before it answered; no polling
```

After `sandbox_stopped`, the sandbox state is already `stopped` and its files are kept. After an
auto-stop the same applies: `start()` and run again. A sandbox that fails to start stays in
`error` until you delete it.

## 5. A clean slate for the next run or student

`sbx.reset()` (REST: `POST /v1/sandboxes/{id}/reset`, CLI: `sandfort sandbox reset <sandbox>`)
replaces the sandbox's container with a fresh one from the same image and spec (975b76f).

- Kept: id, name, labels, resources, env, network policy, isolation tier, volume mounts, auto
  timers. Gone: everything written to the old container. Named volumes are kept, so do not mount
  one if you want a clean slate.
- Allowed from `started` (ends `started`) and `stopped` (ends `stopped`). Other states answer 409.
- Refused with 409 while a snapshot of the sandbox is in progress, and when sandbox lifecycle runs
  as jobs.
- A reset is audited (`sandbox.reset`; `sandbox.reset_failed` when the driver fails). If the driver
  fails after the old container is removed, the sandbox moves to `error`: delete it and create a
  new one. A concurrent stop or reconcile during a reset is handled (6be6470, db7bb93).

Use it when a student starts over. For isolation between people, a separate sandbox per student
is simpler than a pool of reset sandboxes.

## 6. Checklist

- `block_network=True`, or `SANDFORT_DEFAULT_BLOCK_NETWORK=true` on a self-hosted server.
- Small `Resources`, a `timeout_s` per lesson, `auto_stop_minutes` and `auto_delete_minutes` set.
- Handle `stop_reason`, restart after `sandbox_stopped`, delete the sandbox when the session ends.
- Strip the random directory from JavaScript, TypeScript and bash tracebacks (Python tracebacks
  show `main.py`); do not rely on `input()`.
- Warm the `node:22-bookworm` image before class if you run JavaScript or TypeScript.
- Do not use the hosted beta for production secrets or sensitive data (see "Beta limits" in the
  [beta connect guide](../connect-guide.md)).
