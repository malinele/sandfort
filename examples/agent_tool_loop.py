"""Agent tool loop demo: an agent drives a Sandfort sandbox through exec and fs tools.

Run: .venv/bin/python examples/agent_tool_loop.py
Requires a local Docker daemon and no model API key: a scripted stand-in emits the
tool calls a model would make, so the loop, the tools and the sandbox are real and
the script exits non-zero if any step fails. The guide that pairs a real model with
the same three tools is docs/recipes/agent-tool-loop.md.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

from sandfort_sdk import Client  # noqa: E402
from sandfort_sdk.sandbox import Sandbox  # noqa: E402

PORT = 4211
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


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, str]


@dataclass(frozen=True)
class ModelTurn:
    """One assistant turn: either tool calls to execute, or a final text answer."""

    tool_calls: tuple[ToolCall, ...] = ()
    text: str = ""


@dataclass
class ScriptedModel:
    """Stands in for a model client so the demo runs without an API key.

    It replays a fixed plan: write a script, run it, read its output, answer.
    With a real model, this class is replaced by a Messages API call whose
    response carries the tool_use blocks (see docs/recipes/agent-tool-loop.md);
    the loop below stays the same.
    """

    results_seen: list[str] = field(default_factory=list)

    _PLAN = (
        ModelTurn(
            tool_calls=(ToolCall("write_file", {"path": "/tmp/fib.py", "content": FIB_SCRIPT}),)
        ),
        ModelTurn(tool_calls=(ToolCall("run_command", {"command": "python3 /tmp/fib.py"}),)),
        ModelTurn(tool_calls=(ToolCall("read_file", {"path": "/tmp/answer.txt"}),)),
    )

    def next_turn(self, turn_index: int) -> ModelTurn:
        if turn_index < len(self._PLAN):
            return self._PLAN[turn_index]
        answer = self.results_seen[-1].strip() if self.results_seen else "?"
        return ModelTurn(text=f"The 10th Fibonacci number is {answer}.")

    def record(self, result: str) -> None:
        self.results_seen.append(result)


def make_tools(sbx: Sandbox) -> dict[str, Callable[..., str]]:
    """The three tools the agent gets, each backed by the sandbox.

    These are the same operations the guide exposes to a real model: exec and
    file read/write cover most agent work; anything else (git, chmod, search)
    goes through run_command.
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


def agent_loop(
    model: ScriptedModel, tools: dict[str, Callable[..., str]], max_turns: int = 8
) -> str:
    """The loop a real integration runs: ask the model, execute its tool calls, repeat."""
    for turn_index in range(max_turns):
        turn = model.next_turn(turn_index)
        if not turn.tool_calls:
            return turn.text
        for call in turn.tool_calls:
            result = tools[call.name](**call.arguments)
            print(f"[tool] {call.name}({', '.join(call.arguments)}) -> {result.splitlines()[0]}")
            model.record(result)
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
    tmp = tempfile.mkdtemp(prefix="sandfort-agent-loop-")
    db = os.path.join(tmp, "agent-loop.db")
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
         "--org-name", "AgentLoop", "--org-slug", "agent-loop"],
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

        sbx = client.create_sandbox(name="agent-loop-demo", wait=True)
        print(f"[1] created {sbx.id} state={sbx.state}")

        answer = agent_loop(ScriptedModel(), make_tools(sbx))
        print(f"[2] agent answered: {answer}")
        assert "55" in answer, f"expected 55 in the answer, got: {answer!r}"

        client.stop(sbx.id)
        client.delete(sbx.id)
        print(f"[3] deleted {sbx.id}")
        print("AGENT TOOL LOOP: PASS")
        return 0
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
