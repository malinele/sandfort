# Give an OpenAI model a sandbox: exec and fs tools over the Python SDK

This recipe wires an OpenAI Chat Completions tool-calling loop to a Sandfort sandbox.
The model gets three tools — `run_command`, `write_file`, `read_file` — and every call
runs inside an isolated sandbox instead of on your host. It is the same pattern as
`docs/recipes/agent-tool-loop.md` (Anthropic tool runner); only the message shape
differs. The loop below is written by hand, so the request, execute and append-result
steps are visible: you execute the `tool_calls` and append the results yourself.

A runnable version that needs no `openai` package and no API key is
`examples/openai_tool_loop.py`: a scripted stand-in class returns the assistant messages
a model would return, and the loop replays them through the same tools against a real
sandbox. It exits non-zero on any failure.

## Prerequisites

- A running Sandfort server and an API key (`README.md`, Quickstart: one Python
  process, SQLite and a local Docker daemon are enough).
- `pip install openai` and an `OPENAI_API_KEY`.
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

The Python functions are the same three as in the Anthropic recipe:

```python
def run_command(command: str) -> str:
    result = sbx.process_exec(argv=["sh", "-c", command])
    return f"exit={result.exit_code}\nstdout={result.stdout}stderr={result.stderr}"

def write_file(path: str, content: str) -> str:
    sbx.fs.upload_file(path, content.encode())
    return f"wrote {len(content)} bytes to {path}"

def read_file(path: str) -> str:
    return sbx.fs.read_bytes(path).decode()

TOOL_FUNCTIONS = {"run_command": run_command, "write_file": write_file, "read_file": read_file}
```

Chat Completions takes the tool definitions as JSON Schema, one `function` object per
tool:

```python
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a shell command in the sandbox; returns exit code, stdout, stderr.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command line, run with sh -c."}
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write a text file in the sandbox.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path in the sandbox."},
                    "content": {"type": "string", "description": "The file content."},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file from the sandbox.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path in the sandbox."}
                },
                "required": ["path"],
            },
        },
    },
]
```

## The loop

Call the model with `tools`, append its assistant message, execute every entry of
`tool_calls`, append one `role: "tool"` message per call keyed by `tool_call_id`, and
repeat until an assistant message arrives without `tool_calls`:

```python
import json

from openai import OpenAI

openai_client = OpenAI()

messages = [{
    "role": "user",
    "content": "Write a script that computes the 10th Fibonacci number, "
               "run it in the sandbox, and tell me the result.",
}]

for _ in range(8):  # turn limit: the loop must not run unbounded
    response = openai_client.chat.completions.create(
        model="<your-model>",  # any Chat Completions model that supports tool calling
        messages=messages,
        tools=TOOLS,
    )
    assistant = response.choices[0].message
    messages.append(assistant)
    if not assistant.tool_calls:
        print(assistant.content)
        break
    for call in assistant.tool_calls:
        arguments = json.loads(call.function.arguments)
        result = TOOL_FUNCTIONS[call.function.name](**arguments)
        messages.append({"role": "tool", "tool_call_id": call.id, "content": result})
else:
    raise RuntimeError("agent did not finish within the turn limit")
```

Points the loop has to get right:

- `function.arguments` is a JSON string, not an object, and a model can emit invalid
  JSON or an unknown tool name. In production catch `json.JSONDecodeError`, `KeyError`
  and `TypeError` and return the error text as the `role: "tool"` content so the model
  can correct itself; the example above lets them raise to stay short.
- One assistant message can carry several `tool_calls`. Every `tool_call_id` needs its
  own `role: "tool"` reply before the next request, or the API rejects the history.
- Sandbox failures (a command that exits non-zero is not one; an SDK exception is)
  should also be returned as tool content or abort the loop deliberately, not be
  swallowed.

## What the sandbox gives the loop

- The model's code runs under the sandbox's isolation (`cap_drop=ALL`,
  `no-new-privileges`, seccomp, `pids_limit`, CPU/memory/disk limits), not on the
  host that runs your agent. This is container isolation (optionally a gVisor
  runtime), not a microVM.
- No `SANDFORT_` variable is visible inside the sandbox, so the platform's own
  credentials cannot leak into model-written code. Anything your agent itself writes
  into the sandbox (for example an API key in a script) is readable by all later
  code in that sandbox.
- Network is controlled per sandbox at create time: `network.block_all`, or an
  `egress_allowlist` of hostnames routed through a CONNECT proxy (hostnames only,
  fixed at creation; software that ignores proxy variables has no network).
- `auto_stop_after_s` / `auto_delete_after_s` on create clean up sandboxes the
  agent abandons; an idempotency key on create prevents duplicates on retried
  requests.

## Limits to design around

- Use one sandbox per untrusted submission or conversation. Sandboxes are isolated
  from the host, not from the code that earlier tool calls left in the same sandbox.
- Timeouts are budgets, not guarantees: set a turn limit on the loop and an explicit
  timeout on long commands, and let `auto_delete_after_s` reap what is left behind.
- The tool results go back to the model verbatim. Truncate large `stdout` before
  appending it, and treat file contents read from the sandbox as untrusted input to
  the model.
- The OpenAI side of this recipe (model name, request parameters, response shape) is
  not exercised by the offline example; check it against the current OpenAI API
  reference before relying on it.

## Run the offline example

```bash
.venv/bin/python examples/openai_tool_loop.py
```

It needs a local Docker daemon and no `openai` package or API key. It starts a
Sandfort server on port 4212 with a temporary SQLite database, creates a sandbox, runs
the three-step plan (write a Fibonacci script, run it, read the result) through the
loop above with the scripted stand-in, deletes the sandbox, and prints
`OPENAI TOOL LOOP: PASS`. It exits non-zero on any failure. On the author's
machine the run took 3.9 s wall time against a real local Docker daemon; this is one
local run, not a benchmark.

## Where to go next

- Long commands with streamed logs, persistent sessions and an interactive PTY:
  `src/sandfort/toolbox/` operations are all exposed in the Python SDK (`process`,
  `sessions`, `pty` facades).
- State that survives between runs of Python code without re-running imports:
  named code contexts (`client` code-contexts API; Python only, state is lost on
  stop, reset and delete).
- Reproducible starting images: snapshots and the declarative image builder
  (`docs/architecture.md`).
