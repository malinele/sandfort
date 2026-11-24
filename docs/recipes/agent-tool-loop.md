# Give a Claude agent a sandbox: exec and fs tools over the Python SDK

This recipe wires a Claude tool-use loop to a Sandfort sandbox. The model gets three
tools — `run_command`, `write_file`, `read_file` — and every call runs inside an
isolated sandbox instead of on your host. The same pattern works with any model API
that supports tool calling; the code below uses the Anthropic Python SDK.

A runnable version that needs no model API key is `examples/agent_tool_loop.py`: it
replays a fixed plan through the same tools against a real sandbox and exits non-zero
on any failure.

## Prerequisites

- A running Sandfort server and an API key (`README.md`, Quickstart: one Python
  process, SQLite and a local Docker daemon are enough).
- `pip install anthropic` and an `ANTHROPIC_API_KEY`.
- The Sandfort Python SDK (`sdk/python`, package `sandfort-sdk`).

## The tools

Each tool closes over one sandbox. Exec and file read/write cover most agent work;
the toolbox API has no chmod, search or find operations, so anything else — git
branches, permissions, grep — goes through `run_command`.

```python
from sandfort_sdk import Client

client = Client(base_url="http://127.0.0.1:8000", api_key="sf_...")
sbx = client.create_sandbox(name="agent-demo", wait=True)
```

```python
from anthropic import beta_tool

@beta_tool
def run_command(command: str) -> str:
    """Run a shell command in the sandbox; returns exit code, stdout and stderr.

    Args:
        command: The command line to run with sh -c.
    """
    result = sbx.process_exec(argv=["sh", "-c", command])
    return f"exit={result.exit_code}\nstdout={result.stdout}stderr={result.stderr}"

@beta_tool
def write_file(path: str, content: str) -> str:
    """Write a text file in the sandbox.

    Args:
        path: Absolute path inside the sandbox.
        content: The file content.
    """
    sbx.fs.upload_file(path, content.encode())
    return f"wrote {len(content)} bytes to {path}"

@beta_tool
def read_file(path: str) -> str:
    """Read a text file from the sandbox.

    Args:
        path: Absolute path inside the sandbox.
    """
    return sbx.fs.read_bytes(path).decode()
```

## The loop

The SDK's tool runner drives the request → execute → append-result cycle until the
model stops calling tools:

```python
import anthropic

anthropic_client = anthropic.Anthropic()

runner = anthropic_client.beta.messages.tool_runner(
    model="claude-opus-5-5",
    max_tokens=16000,
    tools=[run_command, write_file, read_file],
    messages=[{
        "role": "user",
        "content": "Write a script that computes the 10th Fibonacci number, "
                   "run it in the sandbox, and tell me the result.",
    }],
)
final = runner.until_done()
print(next(b.text for b in final.content if b.type == "text"))
```

If you write the loop by hand instead (check `stop_reason == "tool_use"`, execute,
append `tool_result` blocks), return all results of one assistant turn in a single
user message — the model may call several tools in parallel.

## What the sandbox gives the loop

- The model's code runs under the sandbox's isolation (`cap_drop=ALL`,
  `no-new-privileges`, seccomp, `pids_limit`, CPU/memory/disk limits), not on the
  host that runs your agent.
- No `SANDFORT_` variable is visible inside the sandbox, so the platform's own
  credentials cannot leak into model-written code. Note that anything your agent
  itself writes into the sandbox (for example an API key in a script) is readable
  by all later code in that sandbox.
- Network is controlled per sandbox at create time: `network.block_all`, or an
  `egress_allowlist` of hostnames routed through a CONNECT proxy (hostnames only,
  fixed at creation; software that ignores proxy variables has no network).
- `auto_stop_after_s` / `auto_delete_after_s` on create clean up sandboxes the
  agent abandons; an idempotency key on create prevents duplicates on retried
  requests.

## Where to go next

- Long commands with streamed logs, persistent sessions and an interactive PTY:
  `src/sandfort/toolbox/` operations are all exposed in the Python SDK (`process`,
  `sessions`, `pty` facades).
- State that survives between runs of Python code without re-running imports:
  named code contexts (`client` code-contexts API; Python only, state is lost on
  stop, reset and delete).
- Reproducible starting images: snapshots and the declarative image builder
  (`docs/architecture.md`).
