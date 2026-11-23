# Docker driver thread offload: design decision

Status: proposal, nothing here is implemented. This is a decision document for phase eleven.
It started from the premise that docker-py calls block the event loop. Section 1 shows that
premise does not hold in the current code, so this document designs the corrected problem: the
residual defects of the offload that already exists, the mechanism, its failure modes and the
delivery slices.

## 1. Goal and constraint

Goal: the docker driver's thread offload has separated capacity for short and long calls, one
defined cancellation contract, a clean shutdown, and a test that pins the property the
platform relies on: a slow docker call never stalls the event loop.

Problem as received: every docker call (create, start, exec, archive copy, commit, logs,
stats, remove) runs its blocking socket I/O on the event loop thread. Checked against the
code, that is not what happens; the next subsection lists the evidence. What is true is that
one process-wide limiter serves every call, that a cancelled await behaves differently
depending on how it was cancelled, and that nothing shuts the offload down.

### The premise, checked

- Every docker-py call site in `src/sandfort/drivers/docker/` goes through `run_blocking` in
  `client.py`: `containers.py`, `exec.py`, `archive.py`, `pty.py`, `logs.py`, `images.py`,
  `build.py`, `volumes.py`, `networks.py` and `capabilities.py`. docker-py is only imported
  lazily by `load_docker_module`, and no other package touches a docker client.
- `run_blocking` is `anyio.to_thread.run_sync` under a module-level `CapacityLimiter`, sized
  by `Settings.docker_thread_limit` (env `SANDFORT_DOCKER_THREAD_LIMIT`, default 64).
  `docs/architecture.md` records it as decision D6. It dates from the first docker driver
  commit (`e168aa1`), and `docs/roadmap.md` carries no offload item.
- The `time.sleep` calls in the package (`exec.py` `_wait_exit_blocking`, `pty.py`
  `initial_resize`) run inside worker-thread helpers, never on the loop.
- One blocking call does happen outside a worker: `DockerDriver.__init__` calls
  `make_client()`, and docker-py 7.2.0 `from_env()` with no version runs a `/version`
  request to detect the server API version. That is in the synchronous app factories
  (`create_app`, `create_worker_app`), not on a request path.
- Nothing pins the property. `tests/test_docker_driver_unit.py` checks that `run_blocking`
  returns a result and resizes; no test measures loop latency under a slow call.

### What exists today

- Construction: `drivers/registry.py` `_docker_factory` builds `DockerDriver(settings)`;
  `api/wiring.py` `build_driver` resolves it, `instrument_driver` (`observability/tracing.py`,
  `_DriverProxy`) wraps it with spans and the wrapper goes to services, workers and toolbox.
  `app.state` keeps the raw driver (`DRIVER_ATTR`), which the preview proxy shares
  (`main.py`) or, standalone, builds again with `build_driver`.
- Callers: `workers/runner.py` (jobs: create, start, stop, destroy through
  `services/sandbox_jobs.py`), `workers/reconciler.py`, `workers/gc.py`,
  `services/sandboxes.py` (inline lifecycle and `_recreate_if_resized`), the toolbox
  (`toolbox/process.py` exec, `fs.py` and `git.py` exec and archive, `sessions.py`
  `exec_stream`, `pty.py` `create_pty`, `code_run.py` `put_archive`),
  `api/routes/sandbox_logs.py` (`stream_logs`), `api/routes/health.py` (`list_managed`) and
  `proxy/app.py` (`get_endpoint`).
- Cancellation: `run_blocking` uses anyio's default `abandon_on_cancel=False`. In anyio 4.15.1
  (`_backends/_asyncio.py`, `run_sync_in_worker_thread`) the token is acquired by
  `async with limiter`, the call runs in `CancelScope(shield=True)` and the awaiter blocks on
  a future. The shield defers cancellation delivered by an anyio scope. A native
  `Task.cancel()` is not deferred: it raises at the `await future`, the `async with` releases
  the token, and the worker thread keeps running unobserved. `logs.py` documents exactly this
  and builds on it (`_next_frame`, `wake`). `workers/runner.py` times handlers out with
  `asyncio.wait_for`, which is a native cancel.
- Streams: exec output (`exec.py` `exec_stream`) polls `_Pump.read` for at most 0.25 s per
  call; pty reads (`pty.py` `read_pty`) poll `read_some` at 0.25 s; log follows
  (`logs.py` `_LogStream.read_frame`) park in `recv` with the socket timeout disabled;
  uploads (`archive.py` `_put_blocking`) hold one thread for the whole upload and pull chunks
  from the loop with `anyio.from_thread.run`; downloads read one chunk per call
  (`_next_blocking`); builds read one progress object per call (`build.py` `_next_chunk`).
- Tests that touch the mechanism: `tests/test_docker_driver_unit.py`
  (`configure_thread_limit`, `_get_limiter`), `tests/test_docker_logs.py`
  (`wait_until_limiter_idle` reads `borrowed_tokens` of `_get_limiter()`), the docker-marked
  suites and `tests/test_driver_contract.py`.
- Conformance: `testing/driver_contract.py` runs compute, exec, archive, logs, volumes and
  images checks through the public protocols for the fake driver always and for docker under
  `@pytest.mark.docker`. It pins results and error types, not threading, and its test helper
  calls `aclose()` on a driver when one exists. `DockerDriver` has none.

### The gap

Five defects, each verified in the code:

1. One limiter for everything. A log follow parks a thread for as long as the container is
   quiet, an upload pins one for its whole duration, and a pull or commit pins one for
   minutes. 64 such calls leave `start`, `stop`, `inspect` and exec setup queued behind them.
   Terminals and async commands are capped per org (`max_ptys_per_org` 8,
   `max_async_commands_per_org` 16); log followers and uploads are not (the roadmap lists
   per-org caps on streams as open).
2. Two cancellation regimes. An anyio-scope cancel waits for the thread; a native cancel
   releases the token while the thread runs on. In the second case the process can exceed
   `docker_thread_limit` threads, and a failure of the abandoned call is lost.
3. No shutdown. `_serve_lifespan` in `api/app.py` stops workers and disposes the engine; it
   never touches the driver. Live terminals in `DockerPtyRegistry` keep their exec running,
   and the docker-py client and its pooled sockets are never closed.
4. The docker-py pool is narrower than the thread limit. `make_client` takes docker-py's
   `DEFAULT_MAX_POOL_SIZE` of 10 and the unix adapter builds its pool with `maxsize` only, so
   the urllib3 default (non-blocking) applies: above 10 concurrent requests extra connections
   are opened and then discarded with a warning. Correct, but wasteful at 64 threads.
5. The limiter is module-level state. A second `DockerDriver` with another size replaces it
   while calls are in flight; tests reach into it through `_get_limiter`.

## 2. Hard constraints

- docker-py stays, and the frozen protocols in `drivers/base.py` do not change. The fake
  driver (`drivers/fake.py`), `drivers/registry.py` and the firecracker skeleton are untouched.
- No behavior change visible to a caller at default settings: same results, same error types
  (`drivers.errors`), same ordering, same streaming framing. `translate_errors` still maps
  docker-py failures where it does today.
- No new dependency and no new daemon or thread outside the worker threads anyio already makes.
- The total number of worker threads never exceeds `docker_thread_limit`.
- A running docker operation is never lost unobserved: its thread either finishes under a held
  token, or the process is exiting.
- Streams stay pull-based. No new queue between a worker thread and the loop.
- Single-node and dev setups pay nothing: threads are still created lazily by anyio.
- Every new file stays under 400 lines (AGENTS.md); verify commands are side-effect free.

## 3. Candidate mechanisms

### (a) Keep anyio threads, split the limiter into lanes, own the lifecycle (chosen)

Keep `anyio.to_thread` as the thread source. Add a bulk lane nested inside the total limiter,
make the token live as long as the thread, and give the driver an `aclose`. See section 4.

Failure modes:
- A new wrapper runs on every blocking call (one extra task and a done-callback). The
  benchmark gate in section 4 exists to catch a measurable cost.
- Immediate cancel changes the anyio-scope case from "wait" to "return at once"; section 4
  lists the one latent race this exposes in `exec.py` and fixes it in the same slice.
- A mis-classified call lands in the wrong lane. The cost is capacity, never correctness.

### (b) Per-call `asyncio.to_thread` on the loop's default executor

Dismissed: the default executor is shared with `getaddrinfo` and anything else on the loop,
has a fixed size no setting reaches, cannot be drained, and loses `anyio.from_thread.run`
that `archive.py` needs.

### (c) One driver-owned `ThreadPoolExecutor` with `run_in_executor`

Dismissed: it gives ownership and `shutdown(wait=True)`, but the bound already exists as a
`CapacityLimiter`. It would also drop anyio's context copy into the thread, force
`archive._BlockingSource` onto `asyncio.run_coroutine_threadsafe`, and make a cancelled
awaiter abandon the thread by default, which is the leak this document removes. Revisit only
if a need appears for thread names, affinity or a pool that outlives the event loop.

### (d) aiodocker or another async client

Dismissed: a new dependency with weaker typing than `types-docker` (architecture D6) and a
different shape for hijacked sockets, log framing and archive streaming, so ten modules and
the conformance behavior would be rewritten to fix a problem the threads already solve.

### (e) Move lifecycle fully into worker processes

Dismissed: jobs mode is partial and default off, and it relocates blocking calls instead of
removing them. What stays on the api path:
- `sandbox_jobs_enabled` defaults to False (`config.py`): create, start, stop and delete run
  inline after the intent commit (`services/sandboxes.py`).
- With jobs on, `_recreate_if_resized` still calls `inspect`, `destroy` and `create` inline.
- Always on the api path: toolbox exec, files, git, sessions and terminals (they must run on
  the owning node and stream, so they cannot be jobs), container logs, the health probe
  `list_managed` and the preview proxy's `get_endpoint`.
- In role `all` the job runner shares the api process and its loop anyway.

### (f) Do nothing and document single-node limits

Dismissed: the loop is already safe, but defects 1 to 3 have no workaround. Raising
`SANDFORT_DOCKER_THREAD_LIMIT` moves the cliff and widens the connection churn of defect 4.

## 4. Recommendation

Use (a): two lanes sharing one thread budget, token lifetime equal to thread lifetime, and a
driver `aclose`. `run_blocking` keeps its name and signature.

### Lanes

New module `drivers/docker/lanes.py`. A call takes tokens in a fixed order, bulk then total:

- `run_blocking(func, *args, **kwargs)` is the control lane: it takes one total token.
- New `run_bulk(func, *args, **kwargs)` is the bulk lane: it takes a bulk token, then a total
  token. The bulk limiter is smaller than the total, so at least `total - bulk` tokens are
  never reachable by bulk calls.
- A new function is used instead of a `lane=` keyword because kwargs are forwarded to the
  docker-py call.
- A worker thread never submits to a lane, so the fixed order cannot deadlock.

Classification rule: a call is bulk when its duration depends on a peer other than the docker
daemon's own request and response, or can exceed a few seconds. Everything else is control.

- Bulk: `exec.py` `_Pump.read`; `pty.py` `read_some` and `write_all`; `logs.py`
  `read_frame`; `archive.py` `_put_blocking` and `_next_blocking`; `build.py` `_next_chunk`;
  `images.py` pull, commit, flatten and remove; the `images.pull` inside
  `containers.py` `_create_pulling_missing`; `volumes.py` `api.df`.
- Control: container create, start, stop, pause, inspect and list; exec create, start,
  kill and wait; pty resize and close; `_open_*` helpers; networks; `capabilities.py`.

### Configuration

- `SANDFORT_DOCKER_THREAD_LIMIT` (`docker_thread_limit`, default 64): unchanged, now defined
  as the total thread budget of the process for this driver.
- `SANDFORT_DOCKER_BULK_THREADS` (`docker_bulk_threads`, default 48): ceiling of the bulk
  lane inside the total; an integer of at least 1. The effective ceiling is
  `min(setting, max(total - 1, 1))`, so a total of 1 degrades to one shared token and
  existing small configurations stay valid.
- `configure_thread_limit(limit, bulk)` keeps its name and a default for `bulk`;
  `_get_limiter()` keeps returning the total limiter, so existing tests stay valid.

Default derivation, for one node. The control reserve is 64 - 48 = 16: the job runner is one
sequential loop (`workers/runner.py`), the other workers are periodic passes counted as one
in-flight call each (about five), the api path adds short exec setup, inspect and endpoint
calls up to docker-py's pool width of 10, and one is spare. The bulk lane of 48 is two orgs
at both default caps (2 x (8 terminals + 16 async commands)); log followers, uploads and
pulls share it. The total does not change, so an operator who tuned 64 keeps the same bound.

`make_client` gains a `max_pool_size` argument (docker-py accepts it in `from_env` and
`DockerClient`); `DockerDriver` passes `docker_thread_limit`. Hijacked sockets leave the pool,
so the pool never needs to be wider than the total.

### Cancellation contract

This is the decision the request asked to record. One rule for every cancel: the token lives
as long as the thread, and the outcome is always observed.

1. The lane runner acquires its tokens, starts the call as its own task through
   `anyio.to_thread.run_sync` against an unbounded private limiter, and awaits it through
   `asyncio.shield`. A done-callback on that task releases the tokens.
2. A cancelled awaiter (anyio scope or native `Task.cancel()`) gets its `CancelledError`
   at once. The docker operation runs on to completion under its held tokens.
3. The callback retrieves the result. A failure after cancellation is logged once at warning
   level with the function name and never raised; success is dropped. Nothing is "unobserved".
4. The thread count never exceeds the total, because a token is freed only when its thread
   returns. This removes the overshoot of defect 2.
5. A caller that needs the outcome of a cancelled step re-inspects, as the intent-then-act
   design (AGENTS.md) already requires: `create` adopts by name, `destroy` ignores
   `DriverNotFound`, and the reconciler removes orphans.
6. Error propagation is unchanged on the normal path: the awaiter receives the same exception
   object the worker raised; `translate_errors` still wraps the await.
7. `anyio.CancelScope(shield=True)` cleanup blocks in `exec.py`, `pty.py`, `logs.py` and
   `archive.py` keep working: they only wait.
8. Two deliberate abandon points remain and now also hold their tokens: the build deadline
   (`build.py` `_within`, bounded by the build call's read timeout) and the log `wake()`.
9. Hazard fixed in the same slice: with immediate cancel, `exec_stream`'s `finally` can close
   the socket while a poll still sits in `select`. `_Pump.read` catches `OSError` only, and a
   closed descriptor raises `ValueError`; it must catch both, as `pty.py` `read_some` does.
   Before this change the native-cancel path had the same exposure.

### Streaming endpoints

Each stream is an async generator that starts the next blocking read only when the consumer
asks. The thread never writes into a queue, so backpressure is the kernel socket buffer and
the docker daemon, exactly as today. Offload adds one thread hop per chunk and no buffering.

- Exec output: `_Pump.read` (select plus `recv` of 64 KiB) leaves the loop through the bulk
  lane. A slow consumer stops further reads, the socket fills and the process blocks.
  Cancel: the generator's `finally` kills the process tree through a control call, then
  closes the pump.
- Container logs: `read_frame` parks in `recv`; each follower holds one bulk token. Cancel:
  `_next_frame` calls `wake()`, which shuts the socket down, the read returns and the token
  is freed.
- Pty sockets: `read_some` polls 0.25 s under a lock, `write_all` is a `sendall` that can
  block when the process stops reading. Both are bulk. `close_pty` runs shielded.
- Archive upload: one bulk thread for the whole upload, pulling at most 1 MiB per hop from
  the loop; the producer is paced by docker. A client disconnect raises in the source, which
  aborts the request body. A source that stalls pins the token until the server's own body
  timeout fires.
- Archive download: `_next_blocking` reads one chunk per call under bulk; the `finally`
  closes the stream shielded.
- Build log: `_next_chunk` per progress object under bulk; the deadline abandons the read.
- Saturation: when the bulk lane is full, new stream openers queue on the limiter in order
  and wait. They are not refused; this equals the behavior at 64 today.

### Shutdown

`DockerDriver` gains `aclose()`, an optional method outside the frozen protocols (the
conformance helper already calls `aclose` when it exists). It is idempotent and does this:

1. Close every live terminal (`DockerPtyRegistry` gains a `drain` that returns its handles).
2. Refuse new lane calls with `DriverError("docker driver is closed")`.
3. Wait for `borrowed_tokens` of both limiters to reach zero, polling every 50 ms, up to the
   constant `CLOSE_TIMEOUT_S = 10`; on timeout log the count still borrowed and continue.
4. Close the docker-py client in a worker thread outside the lanes.

`_serve_lifespan` calls it on the raw driver after the workers stop and before the engine is
disposed, so a job that is mid-call finishes against an open driver. A driver without
`aclose` (the fake driver, third-party entry points) is skipped.

### Gates

- No regression: the full unit suite, `tests/test_driver_contract.py` for the fake driver, and
  with Docker `pytest -m docker` (including `test_docker_driver_passes_full_suite`),
  `tests/load/test_load_profile.py` and `tests/chaos/test_chaos.py`, all unchanged.
- Event loop stays responsive (new test, slice 1). The `FakeDriver` is async and cannot
  block, so the technique works one level lower: `DockerDriver(settings, client=...)` takes
  an injected client. The test supplies a slow client whose methods call `time.sleep(0.3)`,
  or block in `select` on a `socket.socketpair()` that a helper thread feeds late. A ticker
  task records the largest gap between `asyncio.sleep(0.005)` wake-ups while the driver call
  runs; the assertion is `max_lag < 0.1`. A negative control calls the same slow method
  directly on the loop and asserts the ticker sees a lag of at least 0.27, so the probe is
  proven able to fail. Cases: unary call, exec stream, log follow, pty read, archive upload.
- No starvation (new test, slice 4): lanes are set to total 4 and bulk 3. The test parks four
  log followers on a gated fake response, then asserts `inspect` returns within one second.
  On the old single limiter the four followers take all tokens and the call times out.
- Benchmark: `examples/benchmark.py` is run three times on the same host before slice 2 and
  after slice 6; the median is compared. Fail when p50 grows by more than max(25 %, 5 ms) or
  p95 by more than max(50 %, 10 ms) for create, exec or delete. The benchmark is serial, so
  the expected change is zero; it guards the per-call wrapper cost. The reference
  figures (create 107 ms p50, exec 18 ms p50, from `examples/benchmark.py` on one local macOS
  host) apply only on a matching host; no new figure is published from this gate.

### Delivery slices

Each slice is at most five files, one contract, lands green alone and ends with its gate.
Routing of call sites does not change until slice 4, so slices 2 and 3 are safe to stop at.

1. Pin the property. Files: `tests/test_docker_loop_responsive.py` (new). Gate: the new
   test passes on the unchanged code, its negative control fails as designed, and the rest of
   the unit suite is untouched.
2. Lane runner. Files: `src/sandfort/drivers/docker/lanes.py` (new),
   `src/sandfort/drivers/docker/client.py`, `src/sandfort/drivers/docker/exec.py`,
   `tests/test_docker_lanes.py` (new), `tests/test_docker_driver_unit.py`. `run_blocking`
   moves onto the runner with the total limiter only; `run_bulk` exists but nothing calls it.
   Gate: a cancelled call keeps `borrowed_tokens` above zero until its thread returns and
   then frees it; a failure after cancel is logged once and not raised; the awaiter gets the
   worker's exception object; total 4 with bulk 3 keeps one token free for a control call;
   the clamp rules; `_Pump.read` survives a closed descriptor; slice 1 and
   `test_docker_logs.py` still pass.
3. Settings and pool width. Files: `src/sandfort/config.py`,
   `src/sandfort/drivers/docker/driver.py`, `src/sandfort/drivers/docker/client.py`,
   `tests/test_docker_lanes.py`, `tests/test_docker_driver_unit.py`. Gate: env parsing and the
   "at least 1" error of `SANDFORT_DOCKER_BULK_THREADS`; defaults 64 and 48; `make_client`
   receives `max_pool_size` equal to the total (fake docker module); `mypy --strict` clean.
4. Streams to the bulk lane. Files: `src/sandfort/drivers/docker/logs.py`,
   `src/sandfort/drivers/docker/archive.py`, `src/sandfort/drivers/docker/exec.py`,
   `src/sandfort/drivers/docker/pty.py`, `tests/test_docker_starvation.py` (new). Gate: the
   starvation test (red on the old routing, green now); slice 1 still green;
   `test_docker_logs.py`, `test_docker_pty.py` and `test_docker_exec_unit.py` pass with
   `wait_until_limiter_idle` unchanged.
5. Long unary calls to the bulk lane. Files: `src/sandfort/drivers/docker/images.py`,
   `src/sandfort/drivers/docker/containers.py`, `src/sandfort/drivers/docker/build.py`,
   `src/sandfort/drivers/docker/volumes.py`, `tests/test_docker_starvation.py`. Gate: with
   the bulk lane full of parked pulls, `inspect` and `start` still complete; create still
   pulls a missing image once (`test_docker_driver_unit.py` unchanged); image-build and
   snapshot suites pass.
6. Shutdown. Files: `src/sandfort/drivers/docker/driver.py`,
   `src/sandfort/drivers/docker/pty.py`, `src/sandfort/drivers/docker/lanes.py`,
   `src/sandfort/api/app.py`, `tests/test_docker_close.py` (new). Gate: `aclose` is
   idempotent; live terminals are killed; calls after close raise `DriverError`; tokens are
   zero afterwards; a stub with a recording `aclose` shows the lifespan order workers, then
   driver, then engine; a driver without `aclose` is skipped; `pytest -m docker` and the
   contract suite pass with the helper now closing a real driver.
7. Benchmark gate and docs. Files: `docs/architecture.md`, `docs/operations.md`,
   `CHANGELOG.md`. Gate: the benchmark comparison above passes and
   its before and after medians are recorded in `CHANGELOG.md`; `docs/architecture.md`
   D6 states lanes and the cancellation contract; `docs/operations.md` documents both
   settings and the shutdown drain; the changelog entry names behavior, not speed.

## 5. Non-goals for the first version

These items are out of scope:

- No change to the frozen protocols, the fake driver, the registry or the firecracker
  skeleton, and no new dependency. aiodocker and executor swaps stay dismissed.
- No per-org or per-sandbox caps on log followers, uploads or terminals; the lanes bound the
  node, and the roadmap item for per-org stream caps stays separate.
- No lane metrics or saturation gauge. The limiter statistics exist for a later change.
- No interruption of a blocked docker-py call. The design only guarantees that it is observed
  and that its token is held until it returns.
- No fix for the per-container inspect that docker-py `containers.list` performs
  (`models/containers.py`), which makes `list_managed` and `list_instances` N+1 on the
  daemon; that is a separate performance item.
- No support for different sizes in two `DockerDriver` instances of one process: the lanes
  stay process-wide, and a second `configure_thread_limit` with other sizes replaces them.
  One driver per process is the supported shape (the standalone preview proxy is its own
  process).
- No change to the construction-time `/version` request in `make_client`; it runs in the
  synchronous app factories.
- No change to cross-node routing (`docs/cross-node-routing-design.md`); the hop is an
  ordinary request on the owner and uses the same driver and lanes.
- No re-tuning of `capabilities.py`, networks or the 0.25 s poll intervals.
