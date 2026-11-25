"""Gate 11: egress v2 round 4, pinned resolution and the controlled DNS sink, end to end.

One egress proxy subprocess and one server process (role ``all``) run against the local Docker
daemon. A sandbox is created with the allowlist ``["example.com"]`` and these checks run:

* P: pinned resolution. The proxy is started through a launcher that counts its own name
  lookups for the allowlisted host (a count only, written to a file in the gate's temporary
  directory). Two https fetches inside the pin window must cause exactly one lookup
  (``SANDFORT_EGRESS_DNS_PIN_S``, 30 s here).
* D1: the DNS sink answers a udp query and a tcp query REFUSED, echoing the query id and the
  recursion-desired bit, with no answer records.
* D3: a runc sandbox on ``sf-egress-net`` cannot resolve a public name on its own (``getent``
  fails, ``localhost`` still resolves as a positive control), while the proxy reaches the
  allowlisted host. The server is given the sink address and the container's ``dns`` points at it.

Steps that need a Linux host are reported, never skipped silently. Each prints ``CHECK`` when it
ran and ``SKIP <step>: <reason>`` when it did not, and the final line names the skipped steps.

* The sink binds port 53, so D1 needs root (or ``CAP_NET_BIND_SERVICE``), else it is skipped.
  The sink address is ``GATE11_DNS_SINK_ADDRESS`` when set, else ``127.0.0.1``.
* D3 needs a Linux Docker host (the beta VM) and ``GATE11_DNS_SINK_ADDRESS`` set to an IPv4
  address the egress network can reach, normally the ``sf-egress-net`` gateway, with
  ``deploy/host-setup.sh`` applied there (it admits udp and tcp 53 to that address only). Without
  both, D3 is skipped.

Run: .venv/bin/python examples/gate11.py
Requires a local Docker daemon with ``python:3.12-slim`` available and outbound internet access.
A fresh temporary sqlite database is migrated and bootstrapped in-process. Prints one progress
line per step and exits non-zero on any failure; both processes and the database are removed.
"""

from __future__ import annotations

import os
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

API_PORT = 4205
PROXY_PORT = 4206
API = f"http://127.0.0.1:{API_PORT}"
PROXY_ADDRESS = f"host.docker.internal:{PROXY_PORT}"
EGRESS_SECRET = "gate11-egress-signing-secret-0123456789abcdef"
IMAGE = "python:3.12-slim"
SNAPSHOT_NAME = "gate11-python"
ALLOWED_HOST = "example.com"
PIN_WINDOW_S = "30"
SINK_ENV = "GATE11_DNS_SINK_ADDRESS"
LOOPBACK_SINK = "127.0.0.1"
DNS_PORT = 53
DNS_TIMEOUT_S = 3.0
SINK_WAIT_S = 8.0
FETCH_TIMEOUT_S = 15
EXEC_TIMEOUT_S = 40
HEALTH_TIMEOUT_S = 40.0
START_WAIT_S = 120.0
DESTROY_TIMEOUT_S = 90.0
GONE_STATES = frozenset({"destroyed", "deleted"})
FLAG_QR = 0x8000
FLAG_RD = 0x0100
RCODE_MASK = 0x000F
RCODE_REFUSED = 5
QUERY_NAME = "gate11-sink-check.invalid"

# Counts the proxy's own name lookups for one host. Writes one byte per lookup, never the name.
LAUNCHER = (
    "import os, socket\n"
    "real = socket.getaddrinfo\n"
    "def counting(host, *args, **kwargs):\n"
    "    if host == os.environ['GATE11_COUNT_HOST']:\n"
    "        with open(os.environ['GATE11_COUNT_FILE'], 'ab') as handle:\n"
    "            handle.write(b'x')\n"
    "    return real(host, *args, **kwargs)\n"
    "socket.getaddrinfo = counting\n"
    "from sandfort.egress.proxy import main\n"
    "raise SystemExit(main())\n"
)

SKIPPED: list[str] = []


def check(condition: bool, message: str) -> None:
    """Fail the gate (non-zero exit) unless ``condition`` holds."""
    if not condition:
        raise SystemExit(f"GATE11 FAIL: {message}")


def step(message: str) -> None:
    print(f"CHECK {message}", flush=True)


def skip(name: str, reason: str) -> None:
    SKIPPED.append(name)
    print(f"SKIP {name}: {reason}", flush=True)


def wait_health(base: str) -> None:
    deadline = time.time() + HEALTH_TIMEOUT_S
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise SystemExit(f"GATE11 FAIL: {base} did not become healthy")


def provision(env: dict[str, str]) -> str:
    """Migrate and bootstrap in-process; return the platform key."""
    os.environ.update(env)
    from sandfort import admin_cli

    admin_cli.migrate()
    key = admin_cli.bootstrap("Gate11", "gate11")
    check(key.startswith("sf_"), "bootstrap did not return an sf_ key")
    return key


def can_bind_dns(address: str) -> str | None:
    """``None`` when udp and tcp ``address``:53 can be bound here, else the reason it cannot."""
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        probe = socket.socket(socket.AF_INET, kind)
        try:
            probe.bind((address, DNS_PORT))
        except OSError as exc:
            return f"cannot bind {address}:{DNS_PORT} ({exc.strerror}); needs root or CAP_NET_BIND"
        finally:
            probe.close()
    return None


def spawn_proxy(env: dict[str, str], sink: str, count_file: Path) -> subprocess.Popen[bytes]:
    proxy_env = {
        **env,
        "SANDFORT_EGRESS_SECRET": EGRESS_SECRET,
        "SANDFORT_EGRESS_LISTEN_HOST": "0.0.0.0",  # noqa: S104 - containers must reach it
        "SANDFORT_EGRESS_LISTEN_PORT": str(PROXY_PORT),
        "SANDFORT_EGRESS_DNS_PIN_S": PIN_WINDOW_S,
        "SANDFORT_EGRESS_DNS_SINK_LISTEN": sink,
        "GATE11_COUNT_HOST": ALLOWED_HOST,
        "GATE11_COUNT_FILE": str(count_file),
    }
    return subprocess.Popen(
        [str(REPO / ".venv" / "bin" / "python"), "-c", LAUNCHER], cwd=REPO, env=proxy_env
    )


def spawn_server(env: dict[str, str], sink: str) -> subprocess.Popen[bytes]:
    server_env = {
        **env,
        "SANDFORT_ROLE": "all",
        "SANDFORT_PORT": str(API_PORT),
        "SANDFORT_EGRESS_PROXY_ADDRESS": PROXY_ADDRESS,
        "SANDFORT_EGRESS_SECRET": EGRESS_SECRET,
        "SANDFORT_EGRESS_DNS_SINK_ADDRESS": sink,
    }
    return subprocess.Popen(
        [str(REPO / ".venv" / "bin" / "python"), "-m", "sandfort.main"], cwd=REPO, env=server_env
    )


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def dns_query(ident: int) -> bytes:
    """One A question for ``QUERY_NAME`` with recursion desired."""
    header = struct.pack("!HHHHHH", ident, FLAG_RD, 1, 0, 0, 0)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in QUERY_NAME.split("."))
    return header + labels + b"\x00" + struct.pack("!HH", 1, 1)


def check_refused(reply: bytes, ident: int, transport: str) -> None:
    check(len(reply) >= 12, f"{transport} reply is shorter than a dns header")
    got_id, flags, _, answers, _, _ = struct.unpack("!HHHHHH", reply[:12])
    check(got_id == ident, f"{transport} reply does not echo the query id")
    check(bool(flags & FLAG_QR), f"{transport} reply is not marked as a response")
    check(bool(flags & FLAG_RD), f"{transport} reply does not echo recursion desired")
    check(flags & RCODE_MASK == RCODE_REFUSED, f"{transport} rcode is {flags & RCODE_MASK}")
    check(answers == 0, f"{transport} reply carries {answers} answer records")


def udp_exchange(address: str, query: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(DNS_TIMEOUT_S)
        sock.sendto(query, (address, DNS_PORT))
        return sock.recvfrom(4096)[0]


def tcp_exchange(address: str, query: bytes) -> bytes:
    with socket.create_connection((address, DNS_PORT), timeout=DNS_TIMEOUT_S) as sock:
        sock.sendall(len(query).to_bytes(2, "big") + query)
        size = int.from_bytes(_read_exact(sock, 2), "big")
        return _read_exact(sock, size)


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        check(bool(chunk), "tcp connection closed before the full reply arrived")
        data += chunk
    return data


def check_sink_refuses(proxy: subprocess.Popen[bytes], address: str) -> None:
    deadline = time.time() + SINK_WAIT_S
    while True:
        check(proxy.poll() is None, "egress proxy exited while starting the dns sink")
        try:
            reply = udp_exchange(address, dns_query(0x1101))
            break
        except OSError:
            check(time.time() < deadline, f"dns sink at {address}:{DNS_PORT} never answered")
            time.sleep(0.3)
    check_refused(reply, 0x1101, "udp")
    check_refused(tcp_exchange(address, dns_query(0x1102)), 0x1102, "tcp")
    step(f"dns sink {address}:{DNS_PORT} answers udp and tcp queries REFUSED (D1)")


def register_snapshot(client: httpx.Client) -> str:
    body = {"image": IMAGE, "name": SNAPSHOT_NAME}
    registered = client.post("/v1/snapshots", json=body, timeout=300)
    check(registered.status_code == 201, f"register -> {registered.status_code} {registered.text}")
    data = registered.json()["data"]
    check(data["state"] == "ready", f"snapshot is {data['state']!r}, not ready")
    return str(data["id"])


def create_started(client: httpx.Client, snapshot_id: str) -> str:
    body = {"snapshot": snapshot_id, "name": "gate11", "egress_allowlist": [ALLOWED_HOST]}
    created = client.post("/v1/sandboxes", json=body)
    check(created.status_code in (200, 201, 202), f"create -> {created.status_code} {created.text}")
    sandbox_id = str(created.json()["data"]["id"])
    deadline = time.time() + START_WAIT_S
    state = "unknown"
    while time.time() < deadline:
        polled = client.get(f"/v1/sandboxes/{sandbox_id}")
        check(polled.status_code == 200, f"poll {sandbox_id} -> {polled.status_code}")
        state = str(polled.json()["data"]["state"])
        if state == "started":
            return sandbox_id
        check(state != "error", f"sandbox {sandbox_id} entered state 'error'")
        time.sleep(0.5)
    raise SystemExit(f"GATE11 FAIL: sandbox {sandbox_id} is {state!r}, not started")


def wait_gone(client: httpx.Client, sandbox_id: str) -> None:
    deadline = time.time() + DESTROY_TIMEOUT_S
    while time.time() < deadline:
        response = client.get(f"/v1/sandboxes/{sandbox_id}")
        if response.status_code == 404:
            return
        if response.status_code == 200 and response.json()["data"]["state"] in GONE_STATES:
            return
        time.sleep(0.5)
    raise SystemExit(f"GATE11 FAIL: sandbox {sandbox_id} was not destroyed in time")


def run_exec(client: httpx.Client, sandbox_id: str, command: str) -> dict[str, Any]:
    body: dict[str, Any] = {"command": command, "timeout_s": EXEC_TIMEOUT_S}
    response = client.post(f"/v1/sandboxes/{sandbox_id}/toolbox/process/execute", json=body)
    check(response.status_code == 200, f"exec -> {response.status_code} {response.text}")
    result: dict[str, Any] = response.json()["data"]
    return result


def fetch_command(host: str) -> str:
    """Python urllib fetch: honors the proxy variable and tunnels https with CONNECT."""
    code = (
        "import sys, urllib.request\n"
        "try:\n"
        f"    urllib.request.urlopen('https://{host}/', timeout={FETCH_TIMEOUT_S})\n"
        "except Exception as exc:\n"
        "    print(exc, file=sys.stderr)\n"
        "    sys.exit(1)\n"
    )
    return f"python -c {shlex.quote(code)}"


def check_pinning(client: httpx.Client, sandbox_id: str, count_file: Path) -> None:
    for attempt in (1, 2):
        fetched = run_exec(client, sandbox_id, fetch_command(ALLOWED_HOST))
        print(f"  fetch {attempt}: exit {fetched['exit_code']} {fetched['stderr']!r}", flush=True)
        check(fetched["exit_code"] == 0, f"allowlisted fetch {attempt} failed: {fetched}")
    count = count_file.stat().st_size
    check(count != 0, "the proxy never resolved the host: the lookup counter is broken")
    check(count == 1, f"{count} lookups for 2 fetches inside the pin window, expected 1")
    step(f"two fetches of {ALLOWED_HOST} inside the {PIN_WINDOW_S} s pin window: 1 lookup (P1)")


def check_container_dns(client: httpx.Client, sandbox_id: str) -> None:
    local = run_exec(client, sandbox_id, "getent hosts localhost")
    check(local["exit_code"] == 0, f"positive control failed, getent is unusable: {local}")
    public = run_exec(client, sandbox_id, f"getent hosts {ALLOWED_HOST}")
    print(f"  getent {ALLOWED_HOST}: exit {public['exit_code']}", flush=True)
    check(public["exit_code"] != 0, f"the sandbox resolved {ALLOWED_HOST} without the proxy")
    step(f"runc sandbox cannot resolve {ALLOWED_HOST} itself; the proxy still reaches it (D3)")


def run_gate(key: str, count_file: Path, container_dns: bool) -> None:
    headers = {"Authorization": f"Bearer {key}"}
    with httpx.Client(base_url=API, headers=headers, timeout=60) as client:
        sandbox_id = ""
        try:
            snapshot_id = register_snapshot(client)
            step(f"snapshot {snapshot_id} registered from {IMAGE}")
            sandbox_id = create_started(client, snapshot_id)
            step(f"sandbox {sandbox_id} started with allowlist [{ALLOWED_HOST!r}]")
            check_pinning(client, sandbox_id, count_file)
            if container_dns:
                check_container_dns(client, sandbox_id)
        finally:
            if sandbox_id:
                client.delete(f"/v1/sandboxes/{sandbox_id}")
                wait_gone(client, sandbox_id)
        step("sandbox deleted and destroyed")


def plan_dns() -> tuple[str, bool]:
    """The sink address the proxy serves ("" = none) and whether D3 runs; reports skipped steps."""
    configured = os.environ.get(SINK_ENV, "").strip()
    sink = configured or LOOPBACK_SINK
    reason = can_bind_dns(sink)
    if reason is not None:
        skip("D1", reason)
        skip("D3", "no sink is served, so a sandbox has nothing to resolve against")
        return "", False
    if not configured:
        skip("D3", f"{SINK_ENV} is not set (an IPv4 address the egress network can reach)")
    elif sys.platform != "linux":
        skip("D3", "needs a Linux Docker host: sandbox dns reaches the sink only there")
    else:
        return sink, True
    return sink, False


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate11-")
    count_file = Path(tmp) / "lookups"
    count_file.touch()
    processes: list[subprocess.Popen[bytes]] = []
    try:
        env = {
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{Path(tmp) / 'gate11.db'}",
            "SANDFORT_DRIVER": "docker",
            "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
        }
        key = provision(env)
        step("database migrated and org bootstrapped")

        print("NOTE host firewall (deploy/host-setup.sh) is not exercised.")
        sink, container_dns = plan_dns()
        proxy = spawn_proxy(env, sink, count_file)
        processes.append(proxy)
        time.sleep(1.0)
        check(proxy.poll() is None, "egress proxy exited at startup")
        step(f"egress proxy listening on 0.0.0.0:{PROXY_PORT}, pin window {PIN_WINDOW_S} s")
        if sink:
            check_sink_refuses(proxy, sink)

        processes.append(spawn_server(env, sink if container_dns else ""))
        wait_health(API)
        step(f"server healthy; sandboxes reach the proxy at {PROXY_ADDRESS}")

        run_gate(key, count_file, container_dns)
        suffix = f" (skipped: {', '.join(SKIPPED)})" if SKIPPED else ""
        print(f"GATE11 PASS{suffix}", flush=True)
        return 0
    finally:
        for process in processes:
            stop(process)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
