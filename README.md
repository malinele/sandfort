# Sandfort

**The sandbox platform your security team can audit: exec, files, git and a PTY for AI agents — with a hash-chained audit log, RBAC and quotas — on a Linux Docker host. No KVM required for the default tier.**

Sandfort is a self-hosted sandbox server for running AI-generated code: a REST API, a Python SDK and a CLI over isolated Docker-backed sandboxes. The `container` isolation tier needs only a Docker daemon. The `gvisor` tier needs the gVisor `runsc` runtime registered with Docker (`docs/operations.md`). The optional `microvm` tier needs KVM and Kata Containers. A deployment offers only `container` unless the operator maps the other tiers to runtimes (`SANDFORT_ISOLATION_RUNTIMES`). Pre-1.0 beta (version `0.1.0`, released as tags `v0.1.0-beta.N`), source-available, built October-November 2026. Read [Limits](#limits) before you decide anything.

```text
agent code ──► SDK / CLI / REST ──► Sandfort API ──► Docker driver ──► sandbox (container)
                                        │                                  ▲
                                        ├─ Postgres (prod) / SQLite (dev)  │ exec, fs, git, PTY run from the
                                        ├─ workers: reconciler, auto-stop, │ host through driver primitives;
                                        │  GC, metering, webhooks          │ no daemon inside the sandbox
                                        └─ audit chain, quotas, RBAC       │
```

## Why it exists

An agent that writes code has to run it somewhere. With a hosted sandbox API, that code, the repositories it touches and their data leave your infrastructure. Sandfort is the same kind of API (create a sandbox, run a command, read and write files, commit to git, open a terminal) that you run on hosts you control, with the controls a security review asks about built into the same package: who did what (audit chain), who may do what (scoped API keys, roles, OIDC SSO), and how much (per-org quotas, metering, rate limits).

It is not the only self-hosted option. See the [comparison](https://sandfort.dev/compare.html) for the facts, with sources and check dates.

## Quickstart

Requirements: Python 3.12 and a local Docker daemon. On Docker Desktop (macOS) the host has no disk-quota support (the `storage-opt` size option), so per-sandbox disk limits are not enforced there; the server logs a warning and tolerates it outside the `prod` environment.

```bash
git clone https://github.com/malinele/sandfort.git sandfort && cd sandfort
python3.12 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/pip install -e sdk/python
.venv/bin/pip install -e cli
```

Configuration comes from `SANDFORT_*` environment variables (see `src/sandfort/config.py`):

```bash
export SANDFORT_DATABASE_URL="sqlite+aiosqlite:///$PWD/sandfort.db"
export SANDFORT_DRIVER=docker
export SANDFORT_API_KEY_PEPPER="$(openssl rand -hex 16)"
```

Keep the pepper the same for the life of the database: a new value makes every key answer 401. Store it in the env file the server starts from, not only in the shell.

Run the migration, then create the first organization. The plaintext API key (it starts with `sf_`) is printed once and cannot be recovered:

```bash
.venv/bin/python -m sandfort.admin_cli migrate
.venv/bin/python -m sandfort.admin_cli bootstrap --org-name Acme --org-slug acme
# stdout: the sf_... key; stderr: "Store this key now; it cannot be shown again."
```

Start the server (interactive OpenAPI docs are served at `/docs`):

```bash
.venv/bin/python -m uvicorn --factory sandfort.main:create_app --port 8000
```

In a second terminal, use the SDK. Replace the key with the one `bootstrap` printed:

```python
from sandfort_sdk import Client

client = Client(base_url="http://127.0.0.1:8000", api_key="sf_...")

sbx = client.create_sandbox(name="hello", snapshot="python:3.12-slim", wait=True)
result = sbx.process_exec(argv=["python3", "-c", "print(21 * 2)"])
print(result.exit_code, result.stdout.strip())  # 0 42
client.stop(sbx.id)
client.delete(sbx.id)
```

Check the audit chain of the rows you just wrote (run it where `SANDFORT_DATABASE_URL` and `SANDFORT_API_KEY_PEPPER` are exported):

```bash
.venv/bin/python -m sandfort.admin_cli audit-verify; echo "exit $?"
# ok: N audit rows verified
# exit 0
```

`audit-verify` exits 3 and prints `audit chain broken: N finding(s) in M rows` when any row fails. This quickstart does not set `SANDFORT_AUDIT_CHAIN_KEY`, so the chain is an unkeyed hash that anyone who can write the database can recompute; see [Audit chain](#audit-chain).

The gate scripts in `examples/` (`quickstart.py` and `gate2.py` to `gate10.py`) start their own server on a temporary SQLite database, bootstrap a key and exit non-zero on any failure. Most run against local Docker and drive the server through the SDK, with exceptions: `gate6.py` and `gate10.py` use the `fake` driver and need no Docker daemon, `gate10.py` drives plain HTTP, `gate1` (`quickstart.py`) calls the audit endpoint with raw `httpx`, and `gate5.py` keeps its server alive for a real browser. `examples/benchmark.py` is in the same directory but is not a gate. `examples/quickstart.py` (gate 1) creates a sandbox, runs Python, deletes it, checks the audit trail and checks that no `SANDFORT_` variable leaks into the sandbox. The other gates cover the full toolbox, images and snapshots, quotas and signed webhooks, preview URLs, roles, OIDC sign-on and org members (gate 6), multi-node placement (gate 7), an egress allowlist, cross-node routing and SCIM.

## What is in it

| Area | What exists | Source |
|---|---|---|
| Sandbox lifecycle | Create, start, stop, reset, resize (stopped sandboxes only) and delete, run inline by default and as async jobs when jobs mode is enabled (`reset` is unavailable in jobs mode); auto-stop and auto-delete timers; per-sandbox resources, env and labels. `reset` replaces the container from the same spec and keeps the sandbox id | `src/sandfort/services/sandbox_reset.py`, `src/sandfort/workers/`, `src/sandfort/config.py` |
| Toolbox | Process exec and code-run; sessions with a persisted working directory; async commands with live log follow over SSE; interactive PTY with resize (CLI `shell` and a web terminal); preview URLs for dev servers inside a sandbox | `src/sandfort/toolbox/`, `src/sandfort/proxy/` |
| Files and git | Filesystem: list, stat, upload, download, mkdir, move, delete. Git: clone, status, add, commit, push, pull, with a temporary askpass credential that is removed afterwards | `src/sandfort/api/routes/toolbox/fs.py`, `git.py` |
| Code contexts | Named persistent Python kernels: variables survive between runs; run, streamed run and interrupt. Python only; state is lost on stop, reset and delete | `src/sandfort/toolbox/code_contexts.py` |
| Images | Register a public image as a snapshot; build from a declarative image spec (cache keyed by `spec_hash`); snapshot a running sandbox (state `pending` until the commit finishes, then `ready`); export a ready snapshot as a `docker save` tar; named volumes | `src/sandfort/images/`, `src/sandfort/api/routes/snapshots.py` |
| Isolation | `cap_drop=ALL` plus a short allow list, `no-new-privileges`, seccomp, `pids_limit`, CPU/memory/disk limits, blocked metadata IP (requires `deploy/host-setup.sh` run as root on the host; `prod` refuses to start without it), `network.block_all`, per-sandbox egress allowlist (needs the egress proxy, see [Limits](#limits)), runtime choice per sandbox (`container`, `gvisor`, `microvm`) | `docs/architecture.md` §1, `docs/isolation-tiers.md`, `deploy/seccomp.json`, `deploy/host-setup.sh` |
| Access control | Organizations; API keys with scopes (only an HMAC is stored, the key is shown once); roles `admin`, `developer`, `viewer` mapped onto scopes; label-scoped keys; OIDC SSO token exchange into one org; SCIM 2.0 Users; per-key rate limits | `src/sandfort/auth/`, `src/sandfort/api/routes/sso.py`, `users.py`, `scim.py` |
| Governance | Per-org quotas reserved transactionally; metering of allocated resources with a usage report; signed webhooks (Standard Webhooks) with delivery history and redelivery, SSRF protection | `src/sandfort/services/quota.py`, `src/sandfort/services/usage.py`, `src/sandfort/webhooks/signing.py`, `docs/governance.md` |
| Audit | Per-org hash-chained audit log; every non-GET route writes an audit row (meta-test; named exceptions, see `docs/governance.md`); `audit-verify` and `audit-export` admin commands; `audit-export` appends signed head lines that `audit-verify --head` checks for truncation | `src/sandfort/services/audit_chain.py`, `src/sandfort/admin_cli.py` |
| Operations | `/metrics` (Prometheus), `/healthz`, `/readyz`; OpenTelemetry tracing; JSON logs with request id; process roles `api`, `worker`, `all`; Kubernetes kit for one sandbox node in `deploy/k8s/` (single pod, role `all`; multi-node manifests are not shipped); runbook in `docs/operations.md`; SQLite for development, Postgres for production | `docs/operations.md`, `deploy/` |
| Extensibility | Frozen driver protocols (`src/sandfort/drivers/base.py`), entry-point registry and a driver conformance suite. The only production driver is Docker | `src/sandfort/drivers/` |
| Interfaces | 91 HTTP operations on 70 paths in the exported OpenAPI spec (counted 2026-11-22; includes `/healthz` and `/readyz`; excludes the PTY WebSocket, `/metrics`, the preview proxy, the web terminal, `/v1/nodes` and the SCIM routes). Python SDK (sync and async), TypeScript SDK (subset, see below), CLI `sandfort`, an MCP server over stdio | `openapi/sandfort.v1.json`, `sdk/`, `cli/`, `mcp_server/sandfort_mcp.py` |

### Isolation tiers

Isolation is chosen per sandbox with the `isolation` field of `POST /v1/sandboxes`; `GET /v1/isolation` lists the tiers a deployment offers.

| Tier | Runtime | Boundary | What it costs |
|---|---|---|---|
| `container` | runc | Linux namespaces, cgroups, seccomp, a reduced capability set | Shares the host kernel |
| `gvisor` | runsc (gVisor) | A user-space kernel handles the sandbox's system calls; not a hardware boundary | Spawn-heavy and small-file-heavy work measured about 3x to about 9x slower, and about 40x for a fork-heavy bash loop (`docs/isolation-tiers.md`); exceeding a memory or process limit usually stops the whole sandbox; large writes count toward memory |
| `microvm` | Kata Containers behind the same Docker driver | Hardware virtualization, a guest kernel per sandbox | Needs KVM; create to started about 4 s on the hosted beta, which runs it on nested KVM |

Sandfort does not claim stronger isolation than microVM-based products. The Firecracker driver in `src/sandfort/drivers/firecracker/` is a skeleton tested against a mock agent and is not offered. Details: `docs/isolation-tiers.md`.

### Audit chain

Each audit row stores `prev_hash` and `hash = sha256(prev_hash + canonical(row))`; `canonical` covers the immutable fields as compact JSON with sorted keys. With `SANDFORT_AUDIT_CHAIN_KEY` set (at least 32 bytes) the hash is `HMAC-SHA256(key, ...)`, so a database writer without the key cannot recompute a rewritten history. Without the key the chain is an unkeyed hash: anyone who can write the database can rewrite history consistently and `audit-verify` still passes (the server logs a warning). Set the key for any deployment where that matters. Every non-GET route writes an audit row, with named exceptions: a refused call writes `request.denied`, and failed authentication is not audited (`docs/governance.md`). `audit-verify` re-checks every org's chain and exits 3 on any finding (`hash_mismatch`, `link_broken`, `missing_hash`, `head_missing`, `head_invalid`). The chain is tamper-evident, not immutable: it shows that history changed, it does not stop a writer from changing it.

## Limits

These are the current limits, stated up front. Each one comes from the code or the docs in this repository.

- **Isolation is container-based by default.** `container` shares the host kernel; `gvisor` is a user-space kernel, not a hardware boundary, and needs `runsc` registered with Docker. `microvm` (Kata Containers) needs KVM. The Firecracker driver is a skeleton and is not supported. If your threat model requires microVM isolation in production, Sandfort is not a fit today.
- **Pre-1.0 beta (version `0.1.0`, tags `v0.1.0-beta.N`), built October-November 2026.** No production references, no certifications (no SOC 2, no ISO 27001).
- **A sandbox lives on one node.** The multi-node MVP exists (node registry, placement at create, node affinity, cross-node toolbox routing), but there is no rescheduling and no live migration. Multi-node needs jobs mode, which refuses creates that mount volumes or use an egress allowlist and has no sandbox reset. The cross-node hop is plain HTTP with an HMAC-signed route token, so the nodes need a private network. Container logs, the preview proxy and the web terminal page stay node-local. The Kubernetes kit covers a single sandbox node (`docs/operations.md`, `docs/roadmap.md`).
- **Metadata IP blocking is a host step, not a built-in.** The block exists only after an operator runs `sudo sh deploy/host-setup.sh` as root on the Linux host, and it must be run again after every reboot or iptables flush. `prod` refuses to start without it; other environments only log a warning.
- **Docker socket.** Server processes on sandbox nodes mount `/var/run/docker.sock`, which gives control of the node. Use dedicated nodes (`docs/operations.md`). The socket is never mounted into a sandbox.
- **No built-in TLS**, and `/metrics` has no authentication. Terminate TLS in front of the API and keep `/metrics` inside the cluster.
- **Disk limits need XFS project quotas.** Without them `disk_gib` is not enforced, and `prod` refuses to start.
- **The egress allowlist is narrow.** Hostnames only (no CIDR), set at create and not changeable on a running sandbox, enforced by a CONNECT proxy (software that ignores the proxy variables gets no network), not available in jobs mode. It requires running the egress proxy (`python -m sandfort.egress.proxy`; allowlisted creates are refused without it), and allowed ports default to 443 and 80 (`SANDFORT_EGRESS_ALLOWED_PORTS`). On the `container` tier DNS is a side channel. It is not a firewall.
- **The toolbox has a defined scope.** Filesystem: no chmod, search, find or replace. Git: no branch or checkout. Use `process_exec` for those. Code contexts: Python only, state lost on stop, reset and delete.
- **The TypeScript SDK is a subset.** It has no PTY, jobs, org quota, image builder, members, SSO or SCIM, and it does not verify the signed audit trailer. Use the REST API for those. There are no SDKs for other languages.
- **SSO is tied to one organization** (`SANDFORT_OIDC_ORG_ID`). SCIM 2.0 covers Users only: no groups, bulk or etag, and the only filter is `userName eq`; it is off unless `SANDFORT_SCIM_ENABLED` is set.
- **Reproducible measurements are single-host.** See [Status](#status).

## Hosted evaluation instance

If you want to try the API before installing anything, the maintainer runs an invite-only hosted beta for evaluation and design partners. It is a shared instance on modest hardware, with no SLA, no production secrets and no sensitive data, and it may be upgraded with downtime. It offers all three isolation tiers (`gvisor` is the default; `microvm` is Kata on the instance's nested KVM). Production use of Sandfort is self-hosted. When you move, your agent code stays the same and only `base_url` in `Client` changes. To ask for access, write to `office@sandfort.dev`. Terms: `docs/beta-terms.md`.

## SDKs and CLI

- **Python SDK** (`sdk/python/`, sync `Client` and async `AsyncClient`): lifecycle, exec, code contexts, fs, git, PTY, snapshots, image DSL, volumes, members, usage report. Requires Python 3.12. Not published on a package index: install from a checkout.
- **TypeScript SDK** (`sdk/typescript/`, `@sandfort/sdk`, ESM only, Node 20.3 or newer): lifecycle (create with `egressAllowlist`, get, list, start, stop, delete), update, reset, resize, isolation info, preview token, exec, code-run, code contexts, sessions and async commands with SSE follow, fs, git, snapshots (including export), volumes, API keys, webhooks, audit (list, chain verification, NDJSON export), usage and status. No PTY, jobs, org quota, image builder, members, SSO or SCIM, and no verification of the signed audit trailer (checked 2026-11-20).
- **CLI** `sandfort` (`cli/src/sandfort_cli/`): `login`, `sandbox`, `snapshot`, `volume`, `members`, `key`, `usage`, `quota`, `webhook`, `audit` (list, verify, verify-head, export), `cmd`, `preview`, `exec`, `cp`, `shell`, `version`, and a global `--json` flag.
- **MCP server** over stdio (`mcp_server/sandfort_mcp.py`): create, run_code, run_command, upload and download of text files, list, delete, snapshot.

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q                 # unit tests
.venv/bin/python -m pytest -q -m docker       # driver tests, require a Docker daemon
.venv/bin/python -m mypy --strict src/sandfort
.venv/bin/ruff check .
.venv/bin/lint-imports                        # import-linter layering contracts
```

Docker-dependent tests are marked `@pytest.mark.docker`, so CI without Docker stays green. The layering contracts live under `[tool.importlinter]` in `pyproject.toml`. The full design (modules, REST API, data model, phases) is in `docs/architecture.md`; the delivery plan is in `docs/PLAN.md`; the roadmap, including what is explicitly unscheduled, is in `docs/roadmap.md`.

## Status

- Eleven delivery phases are documented in `CHANGELOG.md` (phases 7 and 8 are still marked in progress there); acceptance gates 1-10 pass (gates 1-5 on local Docker, recorded in commit messages; gates 6-10 run locally on 2026-11-01 and 2026-11-02).
- The suite has 16653 collected tests (`pytest --collect-only -q`, 2026-11-22, HEAD a622e30b)<!-- re-pin count and commit at publication -->. That is a collected count, not a pass count. CI (lint, strict mypy, import contracts, unit and docker jobs) was green on GitHub as of the last pushed commit, 2026-11-19.
- Latency, from `examples/benchmark.py`, single local runs and not service levels: on macOS arm64 with Docker 29.8.2 and `alpine:3.20` pre-pulled (2026-11-01), sandbox create waiting for `started` took p50 107 ms and p95 145 ms over 20 creates, and a short exec took p50 18 ms and p95 25 ms over 50 commands in one sandbox. On a Linux KubeVirt VM with 6 vCPU on a shared Hetzner host (nested virtualization, Ubuntu 24.04, Docker 29.9.2, XFS pquota; 2026-11-03), create took p50 248 ms and p95 323 ms and exec took p50 52 ms and p95 60 ms. Run `examples/benchmark.py` on your own host; the numbers depend on it.

## License

- **Server** (`src/sandfort/`): [FSL-1.1-Apache-2.0](./LICENSE.md). Self-hosting, internal use and modification are permitted; making the software available as a competing commercial product or service is not. Each version converts to Apache-2.0 two years after it is made available. This is source-available, not open source, until it converts.
- **Python SDK, TypeScript SDK and CLI** (`sdk/python/`, `sdk/typescript/`, `cli/`): Apache-2.0.

## Maintainer and contact

Sandfort is written and maintained by **Nenad Mitrović**.

- Questions, design-partner pilots and hosted beta access: `office@sandfort.dev`. Response target is the next business day (Monday to Friday, CET), best effort, no SLA.
- Security: report vulnerabilities privately; see [`SECURITY.md`](./SECURITY.md). Do not open a public issue for a vulnerability.
