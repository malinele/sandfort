# Sandfort: a self-hosted elastic sandbox platform for AI-generated code (architecture v1)

This document is the authoritative architecture of the implemented system; paths refer to the repo as built.

---

## 0. Key decisions

| # | Decision | Why |
|---|---|---|
| D1 | **One process, `sandfort-server --role all\|api\|worker`.** The API and the background workers share one codebase. Workers run as lifespan tasks in the MVP. | A single host needs no broker. Later you split by role and change nothing else. |
| D2 | **Lifecycle operations are async jobs** (a DB-backed `jobs` table). `POST` returns 202. Callers wait with a long-poll: `GET ...?wait_for=started&timeout_s=30`. The job runner is woken in-process by an `asyncio.Event`, so jobs don't wait for a poll cycle. | Crash-safe and retryable. It still gives p50 under 1 s from a cached image. |
| D3 | **The toolbox runs on the host and uses only driver primitives**: `exec`, `put_archive`/`get_archive`, `open_pty`. The Docker driver has no daemon inside the sandbox. | Works with any image and adds no trust boundary inside the sandbox. A Firecracker driver would provide the same primitives through a vsock guest agent. |
| D4 | **Intent first, then act.** The DB row and job are committed before any driver call. **A DB transaction is never held open across a driver call.** | Prevents orphan containers and SQLite lock stalls. |
| D5 | **Audit rows, outbox events, quota-ledger updates and usage intervals are written in the same unit of work as the state change.** | Nothing can be mutated without an audit trail. Webhooks are delivered at least once. |
| D6 | **docker-py runs in a bounded thread pool with two lanes** (`anyio.to_thread` under a total `CapacityLimiter`, `SANDFORT_DOCKER_THREAD_LIMIT`, default 64, and a bulk lane nested inside it, `SANDFORT_DOCKER_BULK_THREADS`, default 48; see "D6 in detail" below). Its typed stubs (`types-docker`) keep `mypy --strict` passing. | It is mature and typed. aiodocker's typing is weak. One limiter for every call let log followers, uploads and pulls starve short calls such as `start` and `inspect`; the lanes separate them (`docs/driver-offload-design.md`). |
| D7 | **Response envelope**: `{"success": bool, "data": T\|null, "error": {code,message,details,request_id}\|null, "meta": {next_cursor,...}\|null}`. Streams (SSE, WebSocket, downloads) don't use it. | One shape for SDK parsing. |
| D8 | **IDs are prefixed, time-sortable strings**, e.g. `sbx_...`, `snap_`, `vol_`, `org_`, `key_`, `job_`, `evt_`, `whk_`, `aud_`, `stk_`. The body is 10 characters of millisecond time plus 15 random characters (75 random bits) in Crockford base32, 25 in all, so it is not a 26-character ULID (`src/sandfort/ids.py`). | Sortable, readable in logs, and portable to Postgres. |
| D9 | **Metering is allocation-based**: resources allocated × time in state, recorded as `usage_intervals`. It is not cgroup sampling. | Deterministic, auditable and cheap. |
| D10 | **Layering is enforced by `import-linter`** (see §2). | Packages written by AI agents can't erode the boundaries. |

### D6 in detail: lanes and the cancellation contract

Every docker-py call leaves the event loop through `drivers/docker/lanes.py`. The thread source
is still `anyio.to_thread`; what D6 now adds is two lanes over one thread budget.

- **Control lane** (`run_blocking`): takes one token from the total limiter.
- **Bulk lane** (`run_bulk`): takes a bulk token first, then a total token. The bulk limiter is
  nested inside the total and always smaller: its ceiling is `min(bulk, max(total - 1, 1))`, so
  at least `total - bulk` tokens can never be taken by bulk calls and `start`, `stop` and
  `inspect` keep a free token while followers and pulls wait.
- **The total never exceeds `SANDFORT_DOCKER_THREAD_LIMIT`.** A token is freed only when its
  thread returns, so the process cannot run more worker threads than the total.

Which operations ride which lane. A call is bulk when its duration depends on a peer other than
the docker daemon's own request and response, or can exceed a few seconds.

- Bulk: exec output reads (`exec.py` `_Pump.read`), pty reads and writes, container log follow
  reads, archive upload and download chunks, image-build progress reads, image pull, commit,
  flatten and remove (including the pull inside create), and the volume usage call `api.df`.
- Control: container create, start, stop, pause, inspect and list; exec create, start, kill and
  wait; pty resize and close; networks; capability checks.
- A call put in the wrong lane costs capacity, never correctness. When the bulk lane is full,
  new stream openers queue in order on the limiter; they are not refused.

Cancellation contract. One rule for every cancel, anyio scope or native `Task.cancel()`: the
token lives as long as the thread, and the outcome is always observed.

1. The runner acquires its tokens, runs the call as its own task through `anyio.to_thread` on a
   private unbounded limiter, and awaits that task through `asyncio.shield`. A done-callback on
   the task releases the tokens.
2. A cancelled awaiter gets its `CancelledError` at once, but never abandons a running thread
   unobserved: the docker operation runs on to completion and the token stays borrowed until
   the thread returns.
3. A failure after cancellation is logged once at warning level with the function name and is
   never raised; a success is dropped.
4. A caller that was not cancelled receives the worker's own exception object, and
   `translate_errors` still wraps the await, so error types are unchanged.
5. A caller that needs the outcome of a cancelled step re-inspects, as D4 already requires:
   `create` adopts by name, `destroy` ignores `DriverNotFound`, the reconciler removes orphans.
6. Two deliberate abandon points remain, and they also hold their tokens until the thread
   returns: the image-build deadline and the log follower `wake()`.

Not covered: nothing interrupts a blocked docker-py call; the contract only guarantees that it
is observed and that its token is held. The lanes are process-wide, so one `DockerDriver` per
process is the supported shape.

Shutdown. `DockerDriver.aclose()` is an optional method outside the frozen protocols. It kills
live terminals, makes new lane calls (and calls still queued for tokens) fail with
`DriverError`, waits for both limiters to drain and closes the docker-py client. The lifespan
calls it after the workers stop and before the engine is disposed; see the shutdown order in
`docs/operations.md`.

---

## 1. System architecture

```
  Python SDK / CLI / curl  (Authorization: Bearer sf_live_...)            Webhook receivers
            |  HTTPS                                                            ^ HMAC-signed POST
            v                                                                   |
+---------------------------- sandfort-server (single host, MVP) --------------------------------+
|  FastAPI app                                                                                    |
|   middleware: request_id -> otel -> rate_limit -> (deps) authenticate -> Principal{org,scopes}  |
|   routes/platform (sandboxes, snapshots, volumes, orgs, keys, webhooks, usage, audit, jobs)     |
|   routes/toolbox  (/v1/sandboxes/{id}/toolbox/{process,sessions,fs,git,pty})                    |
|            |                                  |                                                 |
|   services/ (sandboxes, snapshots, volumes,   toolbox/ (process, sessions, fs, git, pty,        |
|     quota, audit, events, usage, orgs, keys,           code_run, command_logs)                  |
|     webhooks, activity)                               |                                         |
|            |                                          |                                         |
|   UnitOfWork + repositories -----------------> SQLite (WAL) | Postgres (prod profile)           |
|            |                                          |                                         |
|            +-------------> SandboxDriver Protocol <---+   (drivers/base.py)                     |
|                              |-- DockerDriver (MVP)   |-- FakeDriver (tests)                    |
|                              |-- [Firecracker/Kata later; Kata = Docker runtime option]         |
|   workers/ (lifespan tasks): job_runner | reconciler | autostop | metering |                    |
|                              webhook_dispatcher | gc                                            |
|   proxy/ (phase 5): preview URLs + web terminal (separate ASGI app, same package)               |
+-------------|-----------------------------------------------------------------------------------+
              | docker-py over /var/run/docker.sock  (host only; NEVER mounted into sandboxes)
              v
   Docker Engine (runtime runc | runsc(gVisor) | kata; userns-remap is a daemon option, the cgroup parent and the per-tier user-namespace opt-out are server settings, see "Container hardening")
     containers  sf-<sbx_id>   --init, cap-drop ALL, no-new-privileges, pids/cpu/mem(/swap)/disk limits
     volumes     sf-vol-<vol_id>        network sf-net (bridge, icc=false, metadata IP blocked)
     images      sandfort-snapshot:<snap_id lower-cased>   build cache keyed by spec_hash
```

### Component responsibilities

- **API server.** Validates input (Pydantic v2), authenticates, enforces scopes, scopes every query to an org, and calls services. At the code-layer level it never touches Docker: routes call services, and only the driver talks to the daemon. At the process level it does: the API process builds the Docker driver and holds the docker-py client (`api/wiring.py`, `build_driver`), and so does every other role. The process that serves the API can therefore reach the Docker socket (see `docs/security.md`, section 3).
- **Auth and tenancy.**
  - Key format: `sf_<env>_<prefix8>_<secret43>`. The DB stores `prefix` plus `HMAC-SHA256(pepper, key)` and compares in constant time. The pepper comes from env.
  - The `Principal` carries `org_id`, `key_id` and `scopes`.
  - Every repository method takes `org_id` as a required argument. There is no "list all" outside the system or reconciler paths.
- **Services.** Orchestrate units of work: state transitions through `domain/lifecycle.py`, quota reservation, audit, outbox, usage intervals and job enqueueing.
- **`SandboxDriver` interface.** Composed from four protocols: `ComputeDriver`, `ExecDriver`, `ImageDriver`, `VolumeDriver`. Rule: drivers import nothing from `db`, `services` or `api`.
- **Docker driver.**
  - Builds a hardened `HostConfig`.
  - Exec has demuxed streaming, timeouts and kill.
  - Archive I/O, `commit`, `build` and volumes.
  - Labels on every managed object: `sandfort.managed=true`, `sandfort.sandbox_id`, `sandfort.org_id`.
  - A capability self-check at startup (`drivers/docker/capabilities.py`) verifies storage-opt disk quota support and that the configured runtime is registered with the daemon. It also reads three more facts from `docker info`: whether user-namespace remapping is active (`name=userns` in `SecurityOptions`), the daemon's default runtime and its cgroup driver. The remapping finding and the default-runtime finding follow the gate rules in "Container hardening"; the cgroup driver is reported only.
- **State store.** SQLAlchemy 2.0 typed ORM with async sessions (aiosqlite / asyncpg) and Alembic.
  - SQLite runs in WAL mode with `busy_timeout=5000`. Quota transactions use `BEGIN IMMEDIATE`.
  - The schema uses only portable types.
- **Job runner.** Claims jobs by lease (`lease_owner`, `lease_expires_at`) and retries with backoff.
- **Reconciler** (every 30 s, and at startup). Compares DB desired state with `driver.list_managed()`:
  - Adopts containers it can match.
  - Removes orphans older than 5 minutes.
  - Marks missing sandboxes `error`.
  - Recounts the quota ledger and alerts on drift.
- **Autostop.** Stops sandboxes idle past `auto_stop_minutes` (measured from `last_activity_at`). Deletes stopped sandboxes past `auto_delete_minutes`.
- **Metering.** Usage intervals are opened and closed on transitions. A worker rolls them up into `usage_rollups` once an hour (`metering_rollup_interval_s`, default 3600). A sampler credits each started sandbox's disk size to its `disk_gib` intervals every `metering_sample_interval_s` (default 300 s). Snapshots and volumes are not metered.
- **Audit.** `AuditRecorder.record(...)` writes inside the unit of work. Details are redacted: no request bodies, no stdin, commands truncated to 512 chars, credentials dropped. Every non-GET route writes an audit row except the few on the exemption list of `tests/test_audit_route_coverage_r96.py`, which walks every registered mutating route.
- **Webhook dispatcher.** Reads the outbox and fans out to matching endpoints. Delivery:
  - Signed with Standard-Webhooks headers (`webhook-id`, `webhook-timestamp`, `webhook-signature`).
  - SSRF guard re-checked at delivery time, no redirects, 5 s timeout.
  - Exponential backoff for up to 24 h, then `dead`. An endpoint is auto-disabled after 50 consecutive failures.
- **Observability.** OpenTelemetry tracing (FastAPI auto-instrumentation plus manual spans around driver calls), OTel metrics exported to Prometheus at `/metrics`, and structlog JSON logs carrying `trace_id`/`request_id`.
- **SDK.** `sandfort-sdk`, built on httpx, sync and async (`Sandfort`, `AsyncSandfort`), with ergonomics like Daytona's: `sb = client.create(...)`, `sb.process.exec(...)`, `sb.fs.upload_file(...)`, `sb.git.clone(...)`, `Image.debian_slim("3.12").pip_install([...])`. Wire models are generated from the committed OpenAPI spec. The facade is hand-written.
- **CLI.** `sandfort`, built with Typer on top of the SDK. Server administration is a separate module, run as `python -m sandfort.admin_cli` (bootstrap org/key, migrate, reconcile-now).

### Create-sandbox flow

1. `POST /v1/sandboxes` goes through authn, the scope check, `ResourceSpec` validation against per-sandbox maximums, and image resolution.
2. In one unit of work (`BEGIN IMMEDIATE`): reserve quota on the ledger, insert the sandbox with `state=pending, desired=started`, write the audit row, write the outbox event `sandbox.created`, and enqueue `create_sandbox`. Commit, then return 202.
3. The job runner claims the job. It calls `driver.create(spec)` with the deterministic name `sf-<id>`, so a retry adopts the existing container on 409. Then it calls `driver.start`.
4. In a second unit of work: `state=started`, open a usage interval, write the event `sandbox.started`.
5. On failure: `state=error` with `error_reason`, release the quota, write the event `sandbox.error`.

### Container hardening (built in `drivers/docker/hardening.py`, asserted by tests)

`--init`, `cap_drop=ALL` plus a minimal add-list (`CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID, KILL, NET_BIND_SERVICE`), `no-new-privileges`, the daemon's default seccomp profile unless `SANDFORT_SECCOMP_PROFILE_PATH` names another, `pids_limit=512` (`pids_limit=1536` plus an `nproc` ulimit of 512 on the runsc family, see `docs/isolation-tiers.md` "Process limits per tier"). The driver sets no AppArmor option, so the daemon's default applies where AppArmor is enabled.

| Limit | Setting |
|---|---|
| CPU | `nano_cpus = millicores × 1e6` |
| Memory | `mem_limit = memory_swap` (no swap) |
| `/dev/shm` | `shm_size = min(64 MiB, mem/4)` |
| Disk | `storage_opt.size = disk_gib` (requires XFS pquota) |
| File handles | ulimit `nofile 4096` |
| Logs | log driver `local`, `max-size=10m`, 3 files |

Also: no devices, never privileged, no Docker socket, and a fixed network `sf-net` (or `none` when `network.block_all`).

User-namespace remapping and the cgroup parent are **opt-in**, not always on. Three server settings (`src/sandfort/config.py`) control the parts Sandfort owns:

| Environment variable | Default | Validation |
|---|---|---|
| `SANDFORT_CGROUP_PARENT` | empty (unset: Docker's default cgroup parent) | Blank, or a systemd slice name: letters, digits, `_`, `.`, `@`, `:`, `-`, ending in `.slice`; no `/`, no `..`, no whitespace or control characters. Anything else fails settings loading. The documented value is `sandfort.slice`. |
| `SANDFORT_USERNS_HOST_TIERS` | `microvm` | Comma-separated tier names from `container`, `gvisor`, `microvm`; case and surrounding spaces are ignored and duplicates collapse. An unknown name fails settings loading. A blank value (set but empty) removes the opt-out: no tier runs in the host user namespace. |
| `SANDFORT_REQUIRE_USERNS_REMAP` | `false` | Boolean (`1/true/yes/on`, `0/false/no/off`). When `true`, `prod` refuses to start on a daemon without user-namespace remapping. |

- **Remapping** is the Docker daemon option `userns-remap` in `/etc/docker/daemon.json` (`deploy/node-setup.sh --userns-remap` sets it to `default`). It is daemon-wide: it applies to every container the daemon starts, builds included. The Kata (`microvm`) tier cannot run in a remapped user namespace, so it opts out per container.
- **Per-container opt-out.** For every tier named in `SANDFORT_USERNS_HOST_TIERS` the driver creates the container with `userns_mode="host"` (`hardening.py`, `USERNS_MODE_HOST`). The tier is the sandbox's requested tier or, when none is requested, the deployment default tier. The driver sends the mode without checking whether the daemon remaps. Every tier not listed keeps the daemon's setting.
- **Cgroup parent.** When `SANDFORT_CGROUP_PARENT` is set, the driver passes it as `cgroup_parent` on every container create (for example `sandfort.slice`, which caps the total across all sandboxes and reserves headroom for the control plane; `deploy/node-setup.sh --with-slice` creates that slice). Unset, sandboxes get Docker's default parent. The `user` field of `HardeningOptions` is still not fed by any setting.
- **Capability facts.** The capability report carries `userns_remap` (true when `name=userns` is among the daemon's security options), `default_runtime` (`docker info` `DefaultRuntime`, empty when not reported) and `cgroup_driver` (`CgroupDriver`, empty when not reported).
- **Legacy single-runtime configuration.** With no tier map and `SANDFORT_CONTAINER_RUNTIME` set to the Kata runtime, the Kata runtime sits on the `container` tier. `container` is not in the default `SANDFORT_USERNS_HOST_TIERS`, so those sandboxes stay in the remapped namespace on a remapped daemon, where Kata cannot run. Set `SANDFORT_USERNS_HOST_TIERS=container` (or move to a tier map with Kata on `microvm`).

Startup gate (`check_isolation` in `api/app.py`, findings from `capabilities.py`):

- **Remapping finding**, text: `user-namespace remapping: not active on the daemon (userns-remap in daemon.json); container root maps to host root except for tiers that opt out per container`. In `prod` it refuses startup only when `SANDFORT_REQUIRE_USERNS_REMAP=true`; with the flag off it is logged as a warning at every startup (`isolation advisory (does not refuse startup)`). Outside `prod` it is part of the findings that are logged and tolerated.
- **Default-runtime finding**, text: `default runtime {default!r} is not among the configured sandbox runtimes {configured}; tenant image builds run on it (advisory only: logged as a warning, never refuses startup until a separate require flag exists)`. It is raised when the daemon reports a default runtime that no tier maps to (a tier mapped to an empty runtime counts as the daemon default). It is advisory in every environment: a warning, never a refusal.

### Secrets

- The platform never puts its own config into a sandbox.
- A test runs `env` in a sandbox and asserts that no `SANDFORT_*` server variable appears.
- The reserved env prefix `SANDFORT_` is rejected on input.
- Git credentials arrive per request and are never stored. They are written into a small `sh` script (the askpass helper) under `/tmp/.sandfort-git` inside the sandbox, with mode 700 for the directory and the script, and git reads it through `GIT_ASKPASS`. The script is removed in a `finally` exec, shielded from cancellation. There is no sweep: if the removal fails after a successful operation the call raises, and a leftover script stays in the sandbox. Any process in the sandbox can read the token during the operation, so tokens must be short-lived and narrowly scoped (`src/sandfort/toolbox/git_credentials.py`). Credentials are never logged or audited.
- Webhook secrets are stored Fernet-encrypted with a server key.

---

## 2. Module layout (`src/sandfort/`; every file under 400 lines)

**Layering contracts (import-linter):**
- `api → services|toolbox → domain, db.repositories.ports, drivers.base`
- `workers → services`
- `drivers.* → domain, errors` only
- `domain` → stdlib + pydantic only

```
src/sandfort/
  __init__.py                  version
  main.py                      create_app(settings) factory + uvicorn entrypoint, --role
  config.py                    Settings (pydantic-settings, prefix SANDFORT_), limits, paths
  logging.py                   structlog JSON config, request/trace id binding
  errors.py                    domain error hierarchy (NotFound, Conflict, QuotaExceeded, InvalidState, ...)
  ids.py                       prefixed time-sortable id generation/parsing
  clock.py                     Clock protocol + SystemClock/FrozenClock
  admin_cli.py                 python -m sandfort.admin_cli: bootstrap org/key, migrate, reconcile-now
  domain/
    resources.py               ResourceSpec (cpu_millicores, memory_mib, disk_gib) + bounds
    sandbox.py                 Sandbox entity, SandboxState enum, NetworkPolicy
    lifecycle.py               transition table + assert_transition(); pure
    snapshot.py                Snapshot entity, SnapshotState, SnapshotSource
    image_spec.py              declarative ImageSpec (base, apt, pip, env, files, workdir, run) + validators
    volume.py                  Volume entity, VolumeMount
    org.py                     Org, ApiKey, Scope enum
    quota.py                   Quota + Ledger value objects; pure check(reserve) -> Decision
    events.py                  event type catalog + payload models
    usage.py                   interval math (vcpu_seconds, gib_seconds) pure functions
  auth/
    api_keys.py                key format, generation, HMAC hashing, constant-time verify
    principal.py               Principal dataclass
    authenticate.py            FastAPI dependency: header -> Principal (+ last_used debounce)
    scopes.py                  require_scopes() dependency
    connect_tokens.py          single-use 60 s tokens for the PTY websocket and web terminal (in memory)
  db/
    base.py                    DeclarativeBase, naming convention, Timestamp/Version mixins
    engine.py                  async engine/session factory, SQLite pragmas, BEGIN IMMEDIATE hook
    unit_of_work.py            UnitOfWork (session + repos + commit/rollback), lock_for_quota()
    models/                    one file per aggregate: orgs, api_keys, quotas, sandboxes, snapshots,
                               volumes, jobs, exec, pty, events, webhooks, audit, usage, nodes, idempotency
    repositories/
      ports.py                 repository Protocols (seed; frozen)
      orgs.py api_keys.py quotas.py sandboxes.py snapshots.py volumes.py jobs.py exec.py
      events.py webhooks.py audit.py usage.py idempotency.py     (one impl each)
  migrations/                  alembic env.py (render_as_batch for sqlite) + versions/
  services/
    sandboxes.py               create/start/stop/delete/update orchestration (UoW + jobs)
    sandbox_jobs.py            job handlers: create/start/stop/destroy sandbox
    quota.py                   reserve/release/recount against ledger under lock
    snapshots.py               register/build/commit/delete snapshot orchestration
    snapshot_jobs.py           job handlers: pull, commit, build, delete image
    volumes.py                 volume CRUD + mount validation
    orgs.py                    org CRUD, quota admin
    api_key_admin.py           create/list/revoke keys
    webhooks.py                endpoint CRUD, secret issue, test event, redeliver
    audit.py                   AuditRecorder + redaction rules
    events.py                  EventPublisher (outbox insert)
    usage.py                   open/close intervals, usage queries
    activity.py                debounced last_activity_at batching (flush 30 s)
    idempotency.py             Idempotency-Key handling for POST creates
  toolbox/
    guards.py                  load started sandbox for principal, touch activity
    process.py                 sync exec with timeout + output caps
    code_run.py                language -> interpreter argv; upload code to /tmp then exec
    sessions.py                exec sessions (cwd/env persisted), async commands registry
    command_logs.py            host-side capped log files + follow iterator
    fs.py                      list/stat/mkdir/delete/move (chmod, search, find, replace were designed but are NOT implemented)
    fs_parse.py                parse stat output into FileInfo (find/grep parsing was designed but is NOT implemented)
    fs_transfer.py             streaming upload/download via tar (stream, never extract on host)
    paths.py                   path normalization/validation
    git.py                     clone/status/add/commit/push/pull argv builders (branches and checkout were designed but are NOT implemented)
    git_credentials.py         ephemeral askpass credential injection + cleanup
    pty.py                     PTY session registry, WS bridge, resize
  drivers/
    base.py                    Compute/Exec/Image/Volume Protocols + DTOs (seed; frozen)
    errors.py                  DriverError, NotFound, Conflict, Unsupported, Timeout
    registry.py                select driver by config / entry points
    fake.py                    in-memory FakeDriver (seed)
    docker/
      client.py                docker-py client factory + CapacityLimiter + to_thread helper
      labels.py                label schema, selectors, container naming
      hardening.py             HostConfig builder from ResourceSpec + NetworkPolicy + settings
      containers.py            create/start/stop/remove/inspect/list_managed
      exec.py                  exec create/start/demux stream/wait/kill (pid-file wrapper)
      pty.py                   tty exec, socket attach, resize
      archive.py               put_archive/get_archive streaming
      logs.py                  container log follow
      images.py                pull/inspect/commit/remove/flatten
      build.py                 BuildKit build from context tar, limits, log stream
      volumes.py               named volume create/remove/usage
      networks.py              ensure sf-net (icc=false)
      capabilities.py          startup self-check (storage-opt, runtimes, userns remap, default runtime, cgroup driver)
      driver.py                DockerDriver composing the above (implements all Protocols)
  images/
    dockerfile.py              ImageSpec -> deterministic Dockerfile + context; spec_hash
    sdk_dsl_schema.py          JSON schema export for SDK Image builder parity
  workers/
    runner.py                  lifespan supervisor: start/stop loops, health
    jobs.py                    claim (lease) / heartbeat / complete / fail / backoff
    handlers.py                job type -> handler registry
    reconciler.py              desired vs actual reconciliation + ledger recount
    autostop.py                auto-stop / auto-delete scanner
    metering.py                rollup intervals -> usage_rollups; storage sampler
    webhook_dispatcher.py      outbox fan-out + delivery attempts
    gc.py                      unreferenced image / dangling volume / temp file GC
  webhooks/
    signing.py                 Standard Webhooks HMAC signing/verification
    ssrf.py                    URL + resolved-IP validation (deny private/loopback/link-local)
    delivery.py                httpx send, no redirects, timeout, result classification
  api/
    app.py                     router assembly, middleware, exception handlers registration
    deps.py                    UoW/service/driver dependencies
    errors.py                  domain/driver error -> envelope + HTTP status mapping
    envelope.py                Envelope[T] generic, ok()/fail() helpers
    pagination.py              cursor pagination over time-sortable ids
    sse.py                     SSE encoder for AsyncIterator[OutputChunk]
    openapi.py                 OpenAPI customization + export command
    middleware/  request_id.py  rate_limit.py (token bucket, in-memory behind interface)
    schemas/     common.py sandboxes.py snapshots.py volumes.py orgs.py api_keys.py
                 webhooks.py usage.py audit.py jobs.py
                 toolbox_process.py toolbox_sessions.py toolbox_fs.py toolbox_git.py toolbox_pty.py
    routes/      health.py sandboxes.py sandbox_logs.py snapshots.py volumes.py orgs.py api_keys.py
                 webhooks.py usage.py audit.py jobs.py
      toolbox/   process.py sessions.py fs.py git.py pty.py
  observability/ tracing.py  metrics.py (metric catalog: sandboxes_by_state, create_latency, exec_*)
  proxy/         app.py routing.py (port-sandbox host parse) tokens.py terminal.py static/  (phase 5)
  testing/       driver_contract.py  (reusable conformance suite for any driver)
sdk/python/src/sandfort_sdk/   client.py async_client.py sandbox.py process.py fs.py git.py pty.py
                               snapshots.py volumes.py image.py errors.py _http.py _generated/models.py
cli/src/sandfort_cli/          main.py config.py sandbox.py exec.py fs.py snapshot.py volume.py output.py
openapi/sandfort.v1.json       committed spec; CI fails on drift
```

---

## 3. REST API surface

- **Auth**: `Authorization: Bearer sf_...` on all routes except health.
- **Idempotency**: create POSTs accept an `Idempotency-Key` header.
- **Envelope**: JSON responses use the D7 envelope. Lists return `data: [...]` plus `meta.next_cursor`.
- **Error codes**: 400 validation, 401, 403 scope, 404 (also returned for other orgs' resources), 409 invalid state or conflict, 413, 422, 429 quota or rate.

### Platform

| Method | Path | Request → Response (data) |
|---|---|---|
| GET | `/healthz`, `/readyz`, `/metrics` | liveness; DB+driver readiness; Prometheus |
| POST | `/v1/admin/orgs` (platform-admin key) | `{name, slug, quota?}` → Org |
| GET | `/v1/orgs/me` | → Org |
| GET | `/v1/orgs/me/quota` | → `{limits: Quota, used: Ledger}` |
| PUT | `/v1/admin/orgs/{org_id}/quota` | Quota → Quota |
| POST | `/v1/api-keys` | `{name, scopes[], expires_at?}` → `{id, key (shown once), prefix, scopes}` |
| GET / DELETE | `/v1/api-keys`, `/v1/api-keys/{id}` | list (no secrets) / revoke |
| POST | `/v1/sandboxes` | `{name?, snapshot? (id\|name, default org default), resources{cpu_millicores, memory_mib, disk_gib}, env{}, labels{}, volumes[{volume_id, mount_path, read_only}], auto_stop_minutes=15, auto_delete_minutes=-1, network{block_all}, public=false}` → 202 Sandbox `{id, state:"pending", job_id, ...}` |
| GET | `/v1/sandboxes` | `?state&stop_cause&label=k=v&cursor&limit≤100` → Sandbox[]; `stop_cause` takes one value from the stop-cause set (`requested`, `auto_stop`, `container_exited`, `oom_killed`, `unknown`) and matches the cause the sandbox shows; `unknown` matches a NULL cause while `stopping` or `stopped`; any other value answers 422 |
| GET | `/v1/sandboxes/{id}` | `?wait_for=started\|stopped&timeout_s≤60` (long-poll) → Sandbox |
| PATCH | `/v1/sandboxes/{id}` | `{labels?, auto_stop_minutes?, auto_delete_minutes?, public?}` → Sandbox |
| POST | `/v1/sandboxes/{id}/start` / `/stop` | → 202 Sandbox |
| DELETE | `/v1/sandboxes/{id}` | → 202 Sandbox (`destroying`) |
| POST | `/v1/sandboxes/{id}/resize` (P5, stopped only) | `{resources}` → Sandbox |
| POST | `/v1/sandboxes/{id}/snapshot` | `{name}` → 202 Snapshot (`pending`) |
| GET | `/v1/sandboxes/{id}/logs` | `?follow&since&tail` → SSE `event: stdout\|stderr` |
| POST | `/v1/sandboxes/{id}/preview-tokens` (P5) | `{port, ttl_seconds?}` → 201 `{token, url, browser_url?, port, expires_at}`. The token is multi-use, lives 60 s to 7 days (default 1 h) and is held in process memory (`proxy/tokens.py`). `url` carries it in the query. `browser_url` is present only when `SANDFORT_PUBLIC_PREVIEW_URL` is an https origin and carries it in the URL fragment of the proxy's handoff page `/__sandfort/preview`. A sandbox that is not started answers 409 `no_container`. |
| POST | `/v1/snapshots` | `{name, image: "python:3.12-slim"}` or `{name, build: ImageSpec}` → 202 Snapshot |
| GET | `/v1/snapshots`, `/v1/snapshots/{id}` | list / get (`state, size_bytes, layer_count, image_digest`) |
| GET | `/v1/snapshots/{id}/build-logs` | `?follow` → SSE |
| DELETE | `/v1/snapshots/{id}` | 409 `in_use` while a sandbox that is not deleted was created from it → 200 Snapshot (`deleting`, the row is already removed when the call returns) |
| POST | `/v1/volumes` | `{name}` → 201 Volume |
| GET / DELETE | `/v1/volumes[/{id}]` | list/get; delete returns 409 if mounted |
| GET | `/v1/jobs/{id}` | → `{id, type, state, attempts, error?, target}` |
| POST | `/v1/webhooks` | `{url, event_types[], description?}` → `{id, secret (once), ...}` |
| GET / PATCH / DELETE | `/v1/webhooks[/{id}]` | CRUD (`enabled`, `event_types`, `url`) |
| POST | `/v1/webhooks/{id}/test` | → Delivery |
| GET | `/v1/webhooks/{id}/deliveries` | → Delivery[] |
| POST | `/v1/webhooks/{id}/deliveries/{did}/redeliver` | → Delivery |
| GET | `/v1/usage` | `?from&to&granularity=day&group_by=sandbox\|none` → `[{day, sandbox_id?, vcpu_seconds, memory_gib_seconds, disk_gib_hours, snapshot_gib_hours, volume_gib_hours}]` |
| GET | `/v1/audit-events` | `?actor_id&action&target_id&from&to&cursor` → AuditEvent[] |

### Toolbox (prefix `/v1/sandboxes/{sid}/toolbox`)

Every toolbox call requires `state=started` (else 409) and touches `last_activity_at`. Mutating calls are audited.

> **Implementation status (checked against `openapi/sandfort.v1.json` and `src/sandfort/api/routes/toolbox/`, 2026-11-10).**
> This table is the original design. The filesystem routes that exist are `GET /fs/list`,
> `GET /fs/stat` (the design calls it `/fs/info`), `POST /fs/mkdir`, `POST /fs/move`,
> `POST /fs/delete` (the design uses `DELETE /fs`), `PUT /fs/upload` and `GET /fs/download`.
> The git routes that exist are `POST /git/clone`, `GET` and `POST /git/status`, `POST /git/add`,
> `POST /git/commit`, `POST /git/push` and `POST /git/pull`. Rows marked **NOT IMPLEMENTED** have
> no route, server code or SDK method; they are kept as design history. Routes that exist but are
> not in this table: persistent Python code contexts under `/code-contexts` (create, list, delete,
> run, run/stream, interrupt). Other details in the table (for example `upload-batch`) also
> differ from the code; the spec is authoritative for the REST surface.

| Method | Path | Request → Response |
|---|---|---|
| POST | `/process/execute` | `{command: str \| argv: list[str], cwd?, env?, timeout_s=60 (≤3600), stdin?}` → `{exit_code, stdout, stderr, timed_out, truncated, duration_ms}` (1 MiB per stream cap) |
| POST | `/process/code-run` | `{language: python\|javascript\|typescript\|bash, code, argv?, env?, timeout_s}` → same as execute |
| POST | `/process/sessions` | `{session_id?, cwd?, env?}` → Session |
| GET / DELETE | `/process/sessions[/{ssid}]` | list/get (with commands) / delete (kills running) |
| POST | `/process/sessions/{ssid}/commands` | `{command, run_async=false, timeout_s}` → `{command_id, exit_code?, stdout?, stderr?}` |
| GET | `/process/sessions/{ssid}/commands/{cid}` | → `{state, exit_code?, started_at, finished_at}` |
| GET | `/process/sessions/{ssid}/commands/{cid}/logs` | `?follow` → SSE `stdout\|stderr\|exit` |
| POST | `/process/sessions/{ssid}/commands/{cid}/kill` | → Command |
| GET | `/fs/list?path` | → FileInfo[] `{name, path, is_dir, size, mode, mtime, owner, group}` |
| GET | `/fs/info?path` | → FileInfo |
| GET | `/fs/download?path` | → `application/octet-stream` (file) or `application/x-tar` (dir); 413 > `max_download` |
| POST | `/fs/upload?path&mode?` | raw body or multipart (streamed, `max_upload` cap) → FileInfo |
| POST | `/fs/upload-batch` | multipart `files[]` + `paths[]` → FileInfo[] |
| POST | `/fs/mkdir` | `{path, mode="755", parents=true}` |
| DELETE | `/fs?path&recursive=false` | → 204-equivalent envelope |
| POST | `/fs/move` | `{source, destination, overwrite=false}` |
| POST | `/fs/permissions` | **NOT IMPLEMENTED (design only).** `{path, mode?, owner?, group?}` |
| GET | `/fs/search?path&glob` | **NOT IMPLEMENTED (design only).** → paths[] (by name) |
| GET | `/fs/find?path&pattern` | **NOT IMPLEMENTED (design only).** → `[{file, line, content}]` (content grep) |
| POST | `/fs/replace` | **NOT IMPLEMENTED (design only).** `{files[], pattern, new_value}` → `[{file, replacements}]` |
| POST | `/git/clone` | `{url, path, branch?, commit_sha?, depth?, credentials?{username, password}}` |
| GET | `/git/status?path` | → `{branch, ahead, behind, files[{path, status}]}` |
| GET / POST | `/git/branches` | **NOT IMPLEMENTED (design only).** list / `{path, name, from?}` |
| POST | `/git/checkout` | **NOT IMPLEMENTED (design only).** `{path, branch}` |
| POST | `/git/add` | `{path, files[]}` |
| POST | `/git/commit` | `{path, message, author{name, email}, allow_empty=false}` → `{sha}` |
| POST | `/git/push`, `/git/pull` | `{path, remote="origin", branch?, credentials?}` |
| POST | `/pty` | `{cols, rows, cwd?, env?, shell="/bin/bash"}` → `{pty_id, connect_url, connect_token}` |
| GET / DELETE | `/pty[/{id}]` | list / close |
| POST | `/pty/{id}/resize` | `{cols, rows}` |
| WS | `/pty/{id}/connect?token=` | binary frames carry stdin/stdout; text JSON frames `{type:"resize"}`; close frame carries exit code |

### Event types (webhooks)

- `sandbox.{created,started,stopped,deleted,error,auto_stopped}`
- `snapshot.{created,active,error,deleted}`
- `volume.{created,deleted}`
- `quota.exceeded`

---

## 4. Data model

Conventions: the primary key of an entity table is a prefixed time-sortable id, `TEXT(30)` (see D8). The exceptions are in `src/sandfort/db/models/`: `nodes.id` is an operator-set `String(64)`, `usage_intervals` and `quota_ledger` use an integer autoincrement `id`, and `quotas`, `idempotency_keys`, `org_memberships` and `usage_rollups` use their `org_id` or a composite key (`(org_id, key)`, `(user_id, org_id)`, `(org_id, period_start, dimension)`) as primary key. Times are tz-aware UTC. JSON columns use generic `JSON`. Enums are `TEXT` + `CHECK`. Each row below lists the `created_at` and `updated_at` columns its table has, and only `sandboxes` has a `version` int for optimistic locking.

| Table | Key fields |
|---|---|
| `organizations` | id, name, slug UNIQUE, status(active\|suspended), created_at, updated_at |
| `quotas` | org_id PK/FK, max_vcpus, max_memory_mib, max_disk_gib, max_sandboxes, updated_at |
| `quota_ledger` | id (integer autoincrement), org_id FK, sandbox_id, vcpus, memory_mib, disk_gib, state(reserved\|released), created_at, updated_at. One row per sandbox reservation, released and never deleted. IDX(org_id, state), IDX(sandbox_id) |
| `api_keys` | id, org_id (indexed), name, prefix UNIQUE, secret_hash, scopes JSON, is_platform_admin, sandbox_labels JSON NULL, max_sandboxes NULL, shared_volume_labels JSON NULL, last_used_at, expires_at, revoked_at, created_by, created_at, updated_at |
| `users` | id, email UNIQUE, display_name, disabled_at NULL, created_at, updated_at |
| `org_memberships` | PK(user_id, org_id), role(admin\|developer\|viewer), external_id NULL, created_at, updated_at. UNIQUE(org_id, external_id), IDX(org_id) |
| `scim_tokens` | id, org_id (indexed), name, prefix UNIQUE, secret_hash, max_role(admin\|developer\|viewer), last_used_at NULL, revoked_at NULL, created_by NULL, created_at, updated_at |
| `nodes` | id (`String(64)`, operator-set), name, max_sandboxes, state(active\|draining), last_heartbeat_at, internal_url, egress_ready, egress_ready_at NULL, created_at, updated_at |
| `sandboxes` | id, org_id, name, state, desired_state, image_ref, driver, driver_ref NULL, cpu_millicores, memory_mib, disk_gib, env JSON, labels JSON, network_policy JSON, public, auto_stop_minutes, auto_delete_minutes, last_activity_at NULL, started_at NULL, stopped_at NULL, error_reason NULL, error_code NULL, deleted_at NULL, standby, spec_hash NULL, node_id, egress_allowlist JSON NULL, snapshot NULL (the snapshot id or image reference the create named), stop_cause NULL, egress_policy_generation, egress_credential_epoch, created_at, updated_at, version. UNIQUE(org_id, name) only among sandboxes whose state is not `destroyed`, `error` or `destroying` (partial index `ix_sandboxes_org_id_name_live`), IDX(state), IDX(spec_hash), IDX(node_id) |
| (none) | There is no volume mount table. A sandbox's mounts are one JSON-encoded list stored as a single `labels` value under the reserved key `sandfort.volume_mounts` (`encode_mounts` and `decode_mounts` in `services/volumes.py`), each entry with volume_id, provider_volume_name, mount_path and read_only (omitted when false). |
| `snapshots` | id, org_id, name, image_ref, digest, layer_count, state(pending\|ready\|error\|deleting), source_sandbox_id NULL, spec_hash NULL, isolation NULL, cpu_millicores NULL, memory_mib NULL, disk_gib NULL, labels JSON, created_at. UNIQUE(org_id, name) |
| `volumes` | id, org_id, name, provider_volume_name, state(ready\|deleting), sampled_size_bytes NULL, labels JSON, restoring_since NULL, created_at. UNIQUE(org_id, name) |
| `jobs` | id, org_id, kind, payload JSON, state(queued\|leased\|done\|failed\|dead), attempts, run_after, lease_expires_at NULL, last_error NULL, node_id, created_at, updated_at. IDX(state, run_after), IDX(node_id) |
| `exec_sessions` | id, org_id, sandbox_id FK, cwd NULL, env JSON, state(active\|closed), created_at, updated_at. IDX(org_id, sandbox_id) |
| `exec_commands` | id, org_id, sandbox_id FK, session_id FK NULL, argv JSON, state(running\|exited\|killed), exit_code NULL, stdout_bytes, stderr_bytes, created_at, finished_at NULL. IDX(org_id, sandbox_id), IDX(session_id) |
| `pty_sessions` | id, org_id, sandbox_id FK, state(open\|closed), rows, cols, created_at, closed_at NULL. IDX(org_id, sandbox_id) |
| (none) | There is no token table. PTY connect tokens (single use, 60 s) and preview tokens (multi use, 60 s to 7 days) live in process memory as SHA-256 digests (`auth/connect_tokens.py`, `proxy/tokens.py`), so a restart drops them. |
| `outbox_events` | id, org_id, event_type, payload JSON, created_at, dispatched_at NULL, attempts. IDX(dispatched_at) |
| `webhook_endpoints` | id, org_id, url, secret, enabled, failure_count, event_types JSON, created_at |
| `webhook_deliveries` | id, endpoint_id FK, event_id FK (outbox_events), state(pending\|delivered\|failed\|disabled), attempts, next_attempt_at NULL, last_status NULL, event_type NULL, payload_sha256 NULL, last_error NULL, attempt_history JSON, created_at, updated_at. UNIQUE(endpoint_id, event_id), IDX(state, next_attempt_at) |
| `audit_events` | id, org_id, actor_type(api_key\|system\|platform_admin), actor_id, action, target_type, target_id, outcome(success\|denied\|error), request_id, ip, user_agent, details JSON (redacted), occurred_at, prev_hash, hash (chain added in P5). Append-only, no UPDATE/DELETE path. Indexes IDX(org_id, occurred_at), IDX(org_id, request_id). |
| `usage_intervals` | id (integer autoincrement), org_id, sandbox_id, dimension(vcpu\|memory_mib\|disk_gib), amount, started_at, ended_at NULL. IDX(org_id, ended_at), IDX(sandbox_id, ended_at) |
| `usage_rollups` | PK(org_id, period_start, dimension), dimension(vcpu\|memory_mib\|disk_gib), total |
| `idempotency_keys` | PK(org_id, key), request_hash, response_status, response_body JSON, expires_at. IDX(expires_at) |

**Lifecycle transitions** (`domain/lifecycle.py`):
- `pending→creating→started`
- `started→stopping→stopped`
- `stopped→starting→started`
- `{any non-terminal}→destroying→destroyed`
- `{creating,starting,stopping}→error`
- `error→destroying`

Snapshotting is a job flag, not a state. The sandbox stays `started`; the container is paused for the duration of the commit.

---

## 5. Phased delivery plan

**How packages are written.** Each phase opens with a **seed** written by the orchestrator, not by an agent package. The seed has frozen interfaces and typed stub modules for every file the phase will fill. Packages inside a phase own **disjoint files** and replace the stub bodies. Each phase closes with an orchestrator-owned **gate**: an e2e demo test plus a full CI run.

**Global acceptance for every package**: `ruff check`, `ruff format --check`, `mypy --strict`, `pytest` with ≥80% coverage on owned files, `lint-imports` passing, and no file over 400 lines. Docker-dependent tests are marked `@pytest.mark.docker`.

### Phase 1: Walking skeleton (demo: the SDK creates a sandbox, runs Python, deletes it, and the audit trail shows all three)

**Seed S1:**
- pyproject (hatch), ruff/mypy/pytest/import-linter config, CI workflow
- `config.py`, `errors.py`, `ids.py`, `clock.py`
- `domain/{resources,sandbox,lifecycle,org,events}.py`
- `drivers/base.py` (all four protocols, final), `drivers/errors.py`, `drivers/fake.py`
- `db/base.py`, `db/repositories/ports.py`
- `api/envelope.py`, `api/schemas/common.py`
- stubs for all P1 files

| WP | Goal | Files owned | Acceptance checks |
|---|---|---|---|
| 1.1 Docker compute driver | Hardened create/start/stop/destroy/inspect/list_managed | `drivers/docker/{client,labels,hardening,containers,networks,driver}.py` | `inspect` of a 1000m/512MiB sandbox shows NanoCpus=1e9, Memory=MemorySwap=536870912, PidsLimit=512, CapDrop=[ALL], SecurityOpt contains no-new-privileges, Init=true, labels set; create is idempotent on name conflict; destroy removes container and anonymous volumes |
| 1.2 Docker exec | Streaming exec with demux, timeout, kill, output caps | `drivers/docker/exec.py` | `exit 3` → 3; stdout and stderr separated; `sleep 600` with timeout 2 s is killed within 3 s, `timed_out=true`, and no process survives (`ps` check); a `yes` flood is truncated at the cap without memory growth over 50 MiB |
| 1.3 Persistence | Engine, UoW, models and repositories for orgs/keys/sandboxes/idempotency; initial migration | `db/{engine,unit_of_work}.py`, `db/models/{orgs,api_keys,sandboxes,idempotency}.py`, `db/repositories/{orgs,api_keys,sandboxes,idempotency}.py`, `migrations/` | `alembic upgrade head` runs on SQLite and on Postgres (CI service); every sandbox repo method requires `org_id`; a cross-org read returns None; optimistic `version` conflict raises Conflict |
| 1.4 Auth | Key generation/hash/verify, Bearer dependency, scopes, admin bootstrap | `auth/{api_keys,principal,authenticate,scopes}.py`, `admin_cli.py` | wrong, revoked or expired key → 401; missing scope → 403; hashing is constant-time (uses `hmac.compare_digest`); `sandfort-admin bootstrap` prints a key exactly once |
| 1.5 Sandbox service and API | Lifecycle orchestration, job-less sync path for P1 (create+start inline after commit), routes, error mapping, app factory | `services/sandboxes.py` (split 2026-11-25 into mixin modules `services/sandbox_{commands,mounting,service_base,resize,queries,create_rules,snapshot_resolution,create_intent,update}.py`), `api/{app,deps,errors,pagination}.py`, `api/schemas/sandboxes.py`, `api/routes/{health,sandboxes}.py`, `main.py` | tests on FakeDriver: create/list/get/stop/start/delete happy paths; illegal transition → 409; per-sandbox maximums enforced (422); reserved env prefix rejected; envelope shape on every response |
| 1.6 Audit and process toolbox | AuditRecorder in UoW, sync `/process/execute` + code-run | `services/audit.py`, `db/models/audit.py`, `db/repositories/audit.py`, `toolbox/{guards,process,code_run}.py`, `api/schemas/toolbox_process.py`, `api/routes/toolbox/process.py`, `api/routes/audit.py` | tests: audited calls yield one audit row with redacted details, and exec on a stopped sandbox → 409 |
| 1.7 Python SDK v0 | Sync and async clients, Sandbox facade, process.exec / code_run, typed errors | `sdk/python/**` | respx-mocked tests for every call; envelope errors map to typed exceptions; `client.create(..., wait=True)` handles long-poll |

**Gate 1**: `examples/quickstart.py` against a real Docker host. Also: `env` inside the sandbox contains no `SANDFORT_` server variable.

### Phase 2: Full toolbox (demo: an agent clones a repo, edits files, runs tests with streamed output, then opens an interactive shell from the CLI)

**Seed S2:** schemas for fs/git/sessions/pty; `db/models/{exec,pty}.py` + repository ports; `api/sse.py`; `auth/connect_tokens.py` interface; stubs.

| WP | Goal | Files owned | Acceptance checks |
|---|---|---|---|
| 2.1 FS toolbox | All fs endpoints over archive and exec primitives | `drivers/docker/archive.py`, `toolbox/{fs,fs_parse,fs_transfer,paths}.py`, `api/routes/toolbox/fs.py` | works on both `debian:bookworm-slim` and `alpine` (GNU and busybox stat); 100 MiB upload streams with RSS under 64 MiB; directory download is a tar; nothing is ever extracted on the host; size caps → 413 |
| 2.2 Sessions and async commands | Sessions with persisted cwd/env, async commands, host-side capped logs, SSE follow, kill | `toolbox/{sessions,command_logs}.py`, `db/repositories/exec.py`, `api/routes/toolbox/sessions.py` | `cd /tmp` persists to the next command; async command logs follow live with ordered stdout/stderr events and a final `exit` event; reconnect resumes from offset; logs are capped at 10 MiB |
| 2.3 Git toolbox | Git operations with ephemeral credentials | `toolbox/{git,git_credentials}.py`, `api/routes/toolbox/git.py` | clone/commit/push against a local authenticated git HTTP test server; after the operation, no credential file exists, the token is absent from `env`, `/proc/*/environ`, audit rows and logs |
| 2.4 PTY | TTY exec, WebSocket bridge, resize, single-use connect tokens | `drivers/docker/pty.py`, `toolbox/pty.py`, `auth/connect_tokens.py`, `db/repositories/pty.py`, `api/routes/toolbox/pty.py` | WS echo round-trip; resize reflected by `stty size`; a reused or expired token → 4401 close; server-side close on sandbox stop |
| 2.5 Container logs | `/logs` SSE with follow/tail/since | `drivers/docker/logs.py`, `api/routes/sandbox_logs.py` | follow emits new lines within 500 ms; client disconnect releases the docker stream (no leaked threads, checked via the limiter counter) |
| 2.6 SDK toolbox | `fs`, `git`, `process` sessions, and `pty` facades in the SDK | `sdk/python/src/sandfort_sdk/{fs,git,pty,process}.py` | mocked tests for every endpoint; streaming iterator API for logs; PTY via `websockets` |
| 2.7 CLI v1 | `sandfort` CLI: login, sandbox create/list/rm/stop/start, exec, cp, shell (PTY) | `cli/**` | Typer CliRunner tests; JSON and table output; `shell` restores terminal mode on exit |

**Gate 2**: the demo above runs on alpine and debian images.

### Phase 3: Snapshots, images, volumes, lifecycle automation (demo: build a declarative image, start 20 sandboxes from it at p50 under 1 s, snapshot one, mount a shared volume, watch auto-stop fire)

**Seed S3:** `domain/{snapshot,image_spec,volume}.py`; models and repository ports for jobs/snapshots/volumes; `workers/handlers.py` registry interface; stubs.

| WP | Goal | Files owned | Acceptance checks |
|---|---|---|---|
| 3.1 Job queue and runner | Leased jobs, backoff, in-process wakeup; `services/sandbox_jobs.py` moves P1's inline path onto jobs | `workers/{jobs,runner,handlers}.py`, `db/repositories/jobs.py`, `services/sandbox_jobs.py`, `api/routes/jobs.py` | two runners never run the same job; an expired lease is re-claimed; a crash mid-job resumes idempotently; create latency p50 under 1 s with a cached image |
| 3.2 Snapshots | Register a registry image (pull, digest pin), commit from a sandbox (pause), delete with reference check | `drivers/docker/images.py`, `services/{snapshots,snapshot_jobs}.py`, `db/repositories/snapshots.py`, `api/routes/snapshots.py` | sandbox → snapshot → new sandbox sees the file; delete while referenced → 409; `layer_count` recorded; auto-flatten when depth exceeds 20 |
| 3.3 Declarative image builder | ImageSpec → deterministic Dockerfile; BuildKit build with CPU/mem/time limits; build-log SSE; `spec_hash` cache | `images/{dockerfile,sdk_dsl_schema}.py`, `drivers/docker/build.py` | golden-file Dockerfile tests; package names validated by regex (no shell metacharacters reach `RUN`); the same spec skips the build; a build over the timeout is killed |
| 3.4 Volumes | CRUD, mount on create, deletion guard, size sampling | `drivers/docker/volumes.py`, `services/volumes.py`, `db/repositories/volumes.py`, `api/routes/volumes.py` | two sandboxes share a file through a volume; another org's volume → 404; delete while mounted → 409 |
| 3.5 Auto-stop and auto-delete | Activity debounce, scanner, `auto_stopped` event | `services/activity.py`, `workers/autostop.py` | FrozenClock tests: idle 15 min → stopped; toolbox activity resets the timer; `auto_delete_minutes=0` deletes on stop |
| 3.6 Reconciler and GC | Drift repair, orphan removal, unreferenced image/volume GC | `workers/{reconciler,gc}.py`, `drivers/docker/capabilities.py` | kill a container behind the platform's back → `error` within 60 s; a manually created labelled container is removed after the grace period; startup reconcile is idempotent |
| 3.7 SDK and CLI for images, snapshots, volumes | `Image` DSL (`debian_slim().pip_install().apt_install().add_file()`), snapshot/volume clients, CLI commands | `sdk/python/src/sandfort_sdk/{image,snapshots,volumes}.py`, `cli/src/sandfort_cli/{snapshot,volume}.py` | DSL serializes to exactly the server ImageSpec JSON schema (schema-compat test) |

**Gate 3**: the demo above, plus a reconciler chaos test (restart the server mid-create).

### Phase 4: Multi-tenant governance (demo: two orgs; quotas hold under a concurrent burst; webhooks reach a receiver with valid signatures; usage report; Grafana-ready metrics)

**Seed S4:** `domain/{quota,usage}.py`; models for quotas/ledger/events/webhooks/usage; `services/events.py` interface; stubs.

| WP | Goal | Files owned | Acceptance checks |
|---|---|---|---|
| 4.1 Quotas | Ledger reservation under lock, release on failure or stop, recount; org quota routes; host capacity guard | `services/quota.py`, `db/repositories/quotas.py`, `api/routes/orgs.py`, `api/schemas/orgs.py` | 50 concurrent creates with a 10 vCPU quota at 1 vCPU each → exactly 10 succeed and the rest get 429 `QUOTA_EXCEEDED`; a failed driver create releases; recount equals the ledger |
| 4.2 Events and webhooks | Outbox publisher, endpoint CRUD, signing, SSRF guard, dispatcher, redelivery | `services/{events,webhooks}.py`, `webhooks/{signing,ssrf,delivery}.py`, `workers/webhook_dispatcher.py`, `db/repositories/{events,webhooks}.py`, `api/routes/webhooks.py` | signatures verify with a reference Standard-Webhooks verifier; `http://127.0.0.1`, `169.254.169.254`, and a DNS-rebinding host are rejected; no redirect follow; backoff schedule; auto-disable after 50 failures |
| 4.3 Metering | Intervals on transitions, rollups, storage sampler, usage API | `services/usage.py`, `workers/metering.py`, `db/repositories/usage.py`, `api/routes/usage.py` | FrozenClock: 2 vCPU running 1 h → 7200 vcpu_seconds; stop/start splits intervals; rollup is idempotent on rerun |
| 4.4 API keys and rate limits | Key management routes, scopes per route, token-bucket middleware behind an interface | `services/api_key_admin.py`, `api/routes/api_keys.py`, `api/middleware/rate_limit.py` | a key cannot grant scopes it lacks; burst over rps → 429 with `Retry-After` |
| 4.5 Observability | OTel tracing (API plus driver spans), metric catalog, `/metrics`, log correlation | `observability/{tracing,metrics}.py`, `logging.py`, `api/middleware/request_id.py` | an in-memory span exporter test shows the `sandbox.create` trace across API → job → driver; metrics names are stable (snapshot test) |
| 4.6 Idempotency and OpenAPI | `Idempotency-Key` on creates; OpenAPI export plus drift check; SDK regeneration | `services/idempotency.py`, `api/openapi.py`, `openapi/sandfort.v1.json`, `sdk/python/src/sandfort_sdk/_generated/` | the same key with the same body returns the same response; the same key with a different body → 422; CI fails on spec drift |

**Gate 4**: the two-org demo, a burst test, and webhook receiver verification.

### Phase 5: Enterprise hardening and human access (demo: browser web terminal, preview URL of a running dev server, gVisor runtime, Postgres deployment, third-party driver certification)

**Seed S5:** `proxy/` interfaces, `testing/driver_contract.py` skeleton, `nodes` model; stubs.

| WP | Goal | Files owned | Acceptance checks |
|---|---|---|---|
| 5.1 Preview proxy | `{port}-{sid}.preview.<domain>` routing; HTTP and WS streaming proxy; token or `public` access | `proxy/{app,routing,tokens}.py` | private sandbox without a token → 401; WebSocket upgrade proxied; only ports 1024–65535 allowed |
| 5.2 Web terminal | xterm.js static page using the PTY connect token | `proxy/terminal.py`, `proxy/static/` | Playwright e2e: type `echo hi`, see `hi` |
| 5.3 Postgres production profile | asyncpg, `SELECT ... FOR UPDATE` path in UoW, prod compose, full suite on PG | `db/engine.py` (PG branch via strategy file `db/locking.py`), `deploy/compose.prod.yml`, CI matrix | the entire test suite passes on SQLite and PG; the quota burst test passes on PG |
| 5.4 Isolation hardening | gVisor/Kata runtime selection, egress policy (DOCKER-USER rules via installer), metadata block, disk-quota enforcement self-check, custom seccomp | `drivers/docker/{hardening,capabilities}.py` (extend), `deploy/host-setup.sh`, `deploy/seccomp.json` | a fork bomb is contained (pids limit on the `container` tier, the `nproc` ulimit on `gvisor`, the end of the VM on `microvm`, see `docs/isolation-tiers.md` "Process limits per tier"); writing over `disk_gib` fails with ENOSPC; curl to 169.254.169.254 fails; the server refuses to start in prod mode without disk-quota support |
| 5.5 Audit tamper-evidence and retention | Hash chain, verify command, NDJSON export, retention job | `services/audit.py` (chain in `services/audit_chain.py`), `workers/audit_retention.py` | `sandfort-admin audit verify` detects a modified row |
| 5.6 Driver plug-in certification | Entry-point driver registry; packaged conformance suite; Firecracker driver skeleton passing compute+exec subset against a mock agent | `drivers/registry.py`, `testing/driver_contract.py`, `drivers/firecracker/` (skeleton) | FakeDriver and DockerDriver pass 100% of the suite; the third-party sample passes via `pytest --driver=...` |
| 5.7 Resize and capacity admission | `/resize` on stopped sandboxes, node capacity plus overcommit admission, ledger adjust | `services/resize.py`, `services/admission.py`, `api/routes/sandboxes.py` (resize handler in `api/routes/sandbox_resize.py`) | resize beyond quota → 429; host over capacity → 503 `CAPACITY` |
| 5.8 Load and chaos suite | Locust profile (create/exec/delete at 200 concurrent), chaos scenarios (dockerd restart, DB lock, disk full) | `tests/load/`, `tests/chaos/` | SLOs recorded: create p95 under 2 s, exec round-trip p95 under 150 ms; zero orphans after chaos plus reconcile |

---

## 6. Top 8 technical risks and mitigations

1. **Docker exec streaming, timeouts and backpressure.** docker-py blocks; demuxing is fragile; Docker has no exec-kill API; floods can exhaust memory.
   - Every Docker call runs in `to_thread` under a `CapacityLimiter`.
   - Exec frames go into a bounded `anyio` memory stream, so a slow client pauses the reader.
   - Hard output caps with a `truncated` flag.
   - Commands launch through a wrapper that writes a PID file and runs `setsid` so they form a process group. Timeout or kill sends `kill -KILL -<pgid>` through a second exec. If that fails, stop the container after a 10 s grace period.
   - `--init` (tini) reaps zombies.
   - On disconnect, a `finally` cleans up and the limiter counter is asserted in tests.

2. **Orphans and DB/driver divergence** (a crash between driver call and commit, or out-of-band `docker rm`).
   - Intent is committed first (D4).
   - Deterministic names `sf-<id>` make retries adopt existing containers.
   - Labels carry org and sandbox IDs.
   - The reconciler runs at startup and every 30 s, with a 5-minute orphan grace period.
   - Jobs are idempotent by design and checked by tests that kill the process mid-job.

3. **Quota enforcement races.**
   - One `quota_ledger` row per sandbox is inserted in the same transaction as the sandbox row. The lock serialises check-then-reserve per org: every SQLite transaction starts with `BEGIN IMMEDIATE`, and Postgres takes `SELECT ... FOR UPDATE` on the org row, then the org's quota row (`db/locking.py`).
   - Reserve before acting; release in a compensating unit of work on failure.
   - The reconciler recounts from the source of truth and alerts on drift.
   - Idempotency keys prevent double-reserving when clients retry.
   - A node capacity guard stops aggregate oversubscription across orgs.

4. **Escaping resource limits.** Disk quota silently unsupported; fork bombs; swap; `/dev/shm`; Docker's own log files filling the host; noisy neighbours starving the API.
   - In prod, XFS pquota is required for `storage_opt` and the capability check refuses to start without it. Dev mode falls back to a `du` watchdog that stops offenders.
   - Limits: pids, `memory_swap=memory`, `shm_size` cap, `local` log driver with rotation, ulimits.
   - A cgroup parent slice with a total cap, leaving reserved CPU and memory for the control plane, is opt-in: set `SANDFORT_CGROUP_PARENT` (see "Container hardening"). It is unset by default, and the slice itself is a host resource that `deploy/node-setup.sh --with-slice` creates.
   - Limits are asserted through `inspect` in tests. Two live Docker tests exercise abuse, both in `tests/test_docker_hardening_phase5.py`: a fork bomb on the default runtime (`test_fork_bomb_exhausts_its_pid_budget_and_spares_the_host`) and the repository seccomp profile refusing a user namespace (`test_repository_seccomp_profile_denies_user_namespaces`, skipped under gVisor). `tests/test_docker_process_cap_tiers_b14.py` runs a fork loop on each tier (gvisor and microvm skip without their runtime). No live test covers out-of-memory, `ENOSPC` or CPU abuse. Those behaviours are measured on the beta and recorded in `docs/isolation-tiers.md`. The egress DNS channel has live driver tests (`tests/test_docker_egress_dns_v2.py`).
   - Process caps per tier: `container` has `pids.max` 512; `gvisor` has an `nproc` ulimit of 512 (per uid) plus a host `pids_limit` of 1536; `microvm` has no guest cap, and a fork loop there ends the whole VM (measured on the beta on 2026-11-26 and 2026-11-27, see `docs/isolation-tiers.md` "Process limits per tier").

5. **Container escape and shared-kernel attack surface.**
   - `cap_drop ALL`, `no-new-privileges`, seccomp and the daemon's AppArmor default. The repository seccomp profile applies only where `SANDFORT_SECCOMP_PROFILE_PATH` is set, and `runsc` does not enforce it (gVisor's Sentry is the syscall boundary). Seccomp does not block `ptrace` (`deploy/seccomp.json` allows it for kernels 4.8 and later, as Docker's default profile does). A refused `ptrace` inside a sandbox comes from the dropped capabilities, the host's Yama `ptrace_scope` on the `container` tier, or the runtime boundary on `gvisor` and `microvm` (see `docs/security.md` section 2). Also `userns-remap` where the node enables it, with a per-container host-user-namespace opt-out for the tiers in `SANDFORT_USERNS_HOST_TIERS` (default `microvm`; see "Container hardening").
   - gVisor (`runsc`) is the recommended prod runtime; Kata is one config line.
   - The tiers contain untrusted code and do not hide the sandbox from it: gVisor and Sandfort itself leave recognisable traces (`docs/isolation-tiers.md` "Contained, not hidden"), so detonating evasive malware is not a supported use case.
   - The Docker socket is never mounted.
   - ICC-disabled bridge; host and metadata IPs blocked.
   - Platform secrets never enter a sandbox (env test). Git credentials are ephemeral and never persisted.
   - The driver interface plus the conformance suite keep Firecracker a drop-in replacement.

6. **Snapshot size and layer-depth growth.** `docker commit` stacks layers (overlay2 tops out around 128); there is no automatic GC; images grow without bound.
   - Track `layer_count` and `size_bytes` per snapshot.
   - Auto-flatten (export → import, preserving config) when depth exceeds 20; hard refusal above 100.
   - Per-org snapshot count and size quotas; GiB-hours metered.
   - A GC worker deletes images with no snapshot or sandbox reference.
   - Builds pin digests, and the `spec_hash` cache dedupes identical builds.

7. **SQLite write contention and Postgres drift.**
   - WAL, `busy_timeout`, short transactions, and no driver I/O inside a transaction (enforced by review checklist plus a UoW guard that raises if a driver call happens while a transaction is open).
   - Activity and `last_used_at` writes are batched and debounced.
   - Portable types only; Alembic batch mode.
   - The full test suite runs against both SQLite and PG from Phase 1 (CI service container), so drift fails fast.

8. **Webhook SSRF and delivery reliability.**
   - Validate the URL at registration, then re-resolve and check every IP at delivery time (blocks DNS rebinding): no private, loopback, link-local, CGNAT or metadata ranges.
   - HTTPS only in prod, no redirects, 5 s timeout, response body cap.
   - The outbox gives at-least-once delivery. `webhook-id` = event id lets receivers dedupe.
   - Backoff for up to 24 h, then dead-letter with manual redelivery; endpoints auto-disable after repeated failure.

**One more risk, specific to how this will be built: interface drift between packages written by different agents.**
- Frozen seed interfaces per phase.
- Stub-first module creation, so file ownership never overlaps.
- import-linter layering.
- An OpenAPI snapshot test.
- `testing/driver_contract.py` as the single behavioural spec for drivers.
- An orchestrator-owned gate test closes every phase.
