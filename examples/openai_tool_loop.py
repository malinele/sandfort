"""OpenAI tool loop demo: a Chat Completions tool-calling loop over a Sandfort sandbox.

Run: .venv/bin/python examples/openai_tool_loop.py
Requires a local Docker daemon. It needs NO `openai` package and NO API key: a scripted
stand-in class returns the assistant messages (with `tool_calls`) that a Chat Completions
model would return, so the loop, the tools and the sandbox are real and the script exits
non-zero if any step fails. The guide that pairs a real model with the same three tools is
docs/recipes/openai-tool-loop.md.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from sandfort_sdk import Client  # noqa: E402
from sandfort_sdk.sandbox import Sandbox  # noqa: E402

PORT = 4212
BASE = f"http://127.0.0.1:{PORT}"

FIB_SCRIPT = (
    "def fib(n: int) -> int:\n"
    "    a, b = 0, 1\n"
    "    for _ in range(n):\n"
    "        a, b = b, a + b\n"
    "    return a\n"
    "\n"
    "with open('/tmp/answer.txt', 'w') as fh:\n"
    "    fh.write(str(fib(10)))\n"
)

Message = dict[str, Any]

# Tool definitions in the Chat Completions shape: {"type": "function", "function": {...}}.
TOOLS: list[Message] = [
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


def tool_call(call_id: str, name: str, arguments: dict[str, str]) -> Message:
    """One entry of an assistant message's `tool_calls`; `arguments` is a JSON string."""
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


class ScriptedChatModel:
    """Stands in for `client.chat.completions.create(...)` so the demo needs no API key.

    `create(messages, tools)` returns the assistant message the API would return inside
    `response.choices[0].message`, as a plain dict. It replays a fixed plan: write a
    script, run it, read its output, then answer from the last `role: "tool"` message.
    With a real model this class is replaced by the API call (see
    docs/recipes/openai-tool-loop.md); the loop below stays the same.
    """

    _PLAN: tuple[tuple[str, str, dict[str, str]], ...] = (
        ("call_1", "write_file", {"path": "/tmp/fib.py", "content": FIB_SCRIPT}),
        ("call_2", "run_command", {"command": "python3 /tmp/fib.py"}),
        ("call_3", "read_file", {"path": "/tmp/answer.txt"}),
    )

    def create(self, messages: list[Message], tools: list[Message]) -> Message:
        if not tools:
            raise ValueError("the loop must pass the tool definitions on every request")
        step = sum(1 for m in messages if m["role"] == "assistant")
        if step < len(self._PLAN):
            call_id, name, arguments = self._PLAN[step]
            return {
                "role": "assistant",
                "content": None,
                "tool_calls": [tool_call(call_id, name, arguments)],
            }
        last_tool = next(m for m in reversed(messages) if m["role"] == "tool")
        return {
            "role": "assistant",
            "content": f"The 10th Fibonacci number is {last_tool['content'].strip()}.",
        }


def make_tools(sbx: Sandbox) -> dict[str, Callable[..., str]]:
    """The three tools the model gets, each backed by the sandbox.

    Exec and file read/write cover most agent work; anything else (git, chmod,
    search) goes through run_command.
    """

    def run_command(command: str) -> str:
        result = sbx.process_exec(argv=["sh", "-c", command])
        return f"exit={result.exit_code}\nstdout={result.stdout}stderr={result.stderr}"

    def write_file(path: str, content: str) -> str:
        sbx.fs.upload_file(path, content.encode())
        return f"wrote {len(content)} bytes to {path}"

    def read_file(path: str) -> str:
        return sbx.fs.read_bytes(path).decode()

    return {"run_command": run_command, "write_file": write_file, "read_file": read_file}


def run_tool_call(call: Message, tools: dict[str, Callable[..., str]]) -> Message:
    """Execute one `tool_calls` entry and build the `role: "tool"` result message."""
    name = call["function"]["name"]
    result = tools[name](**json.loads(call["function"]["arguments"]))
    print(f"[tool] {name} -> {result.splitlines()[0]}")
    return {"role": "tool", "tool_call_id": call["id"], "content": result}


def agent_loop(
    model: ScriptedChatModel,
    tools: dict[str, Callable[..., str]],
    prompt: str,
    max_turns: int = 8,
) -> str:
    """Chat Completions loop: call the model, run its tool_calls, append role:'tool'
    results keyed by tool_call_id, repeat until an assistant message has no tool_calls."""
    messages: list[Message] = [{"role": "user", "content": prompt}]
    for _ in range(max_turns):
        assistant = model.create(messages, TOOLS)
        messages.append(assistant)
        calls = assistant.get("tool_calls") or []
        if not calls:
            return str(assistant["content"])
        # A real model may return several tool_calls in one message; answer every one.
        messages.extend(run_tool_call(call, tools) for call in calls)
    raise SystemExit("agent did not finish within the turn limit")


def wait_health(timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{BASE}/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.3)
    raise SystemExit("server did not become healthy")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-openai-loop-")
    db = os.path.join(tmp, "openai-loop.db")
    env = {
        **os.environ,
        "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db}",
        "SANDFORT_DRIVER": "docker",
        "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
        "PYTHONPATH": "src",
    }
    py = str(REPO / ".venv" / "bin" / "python")
    subprocess.run([py, "-m", "sandfort.admin_cli", "migrate"], cwd=REPO, env=env, check=True)
    out = subprocess.run(
        [py, "-m", "sandfort.admin_cli", "bootstrap",
         "--org-name", "OpenAILoop", "--org-slug", "openai-loop"],
        cwd=REPO, env=env, check=True, capture_output=True, text=True,
    ).stdout
    key = next(tok for tok in out.split() if tok.startswith("sf_"))

    server = subprocess.Popen(
        [py, "-m", "uvicorn", "--factory", "sandfort.main:create_app", "--port", str(PORT)],
        cwd=REPO, env=env,
    )
    try:
        wait_health()
        client = Client(base_url=BASE, api_key=key)

        sbx = client.create_sandbox(name="openai-loop-demo", wait=True)
        print(f"[1] created {sbx.id} state={sbx.state}")

        prompt = (
            "Write a script that computes the 10th Fibonacci number, "
            "run it in the sandbox, and tell me the result."
        )
        answer = agent_loop(ScriptedChatModel(), make_tools(sbx), prompt)
        print(f"[2] agent answered: {answer}")
        assert "55" in answer, f"expected 55 in the answer, got: {answer!r}"

        client.stop(sbx.id)
        client.delete(sbx.id)
        print(f"[3] deleted {sbx.id}")
        print("OPENAI TOOL LOOP: PASS")
        return 0
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
