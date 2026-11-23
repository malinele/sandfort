# Cross-node toolbox routing: design decision

Status: proposal, nothing here is implemented. This is a decision document for the first
phase-nine package. It names a mechanism, its failure modes and the delivery slices.

## 1. Goal and constraint

Goal: a toolbox request sent to any api process reaches the node that owns the sandbox, so
an SDK or CLI user needs one server URL and no router that knows about node ownership.

Problem: the node registry places sandboxes across nodes, but every synchronous toolbox
operation runs against the docker daemon of the process that received the request. Exec,
async commands and their logs, file upload and download, git, sessions and interactive
terminals all fail, or find nothing, when that process is not on the owning node.

### What exists today

- Ownership: `SandboxRow.node_id` (`db/models/sandboxes.py`, index `ix_sandboxes_node_id`) is
  stamped at create by `stamp_sandbox` in `services/node_registry.py`. `Settings.node_id`
  (`config.py`, env `SANDFORT_NODE_ID`) is the identity of a process.
- Registry: `NodeRegistry.heartbeat` upserts a `Node` through `uow.nodes.upsert_heartbeat`
  every `node_heartbeat_interval_s`. `NodeRow` (`db/models/nodes.py`) has `id`, `name`,
  `max_sandboxes`, `state` and `last_heartbeat_at`, and no address. `HEARTBEAT_STALE_AFTER`
  is 90 seconds; `pick_node` already skips stale nodes for placement.
- Roles: `api` serves requests and starts no worker, so it never heartbeats. `worker` serves
  health probes only (`create_worker_app` in `api/app.py`). `all` does both.
- Toolbox surface: `api/routes/toolbox/{process,fs,sessions,git,pty}.py` under the prefix
  `/v1/sandboxes/{sandbox_id}/toolbox`, aggregated in `api/routes/toolbox/__init__.py`. The
  terminal websocket `/pty/{pty_id}/connect` carries no API key; its single-use token is
  redeemed from the in-memory `InMemoryConnectTokenStore` (`auth/connect_tokens.py`), and
  live terminals sit in the process-local `PtyRegistry` (`toolbox/pty.py`).
- Host-side state: async command logs are capped files on the node's host
  (`toolbox/command_logs.py`), so a log read must also reach the owner.
- Signed tokens: `egress/tokens.py` mints `sfe_<payload>.<signature>`, base64url JSON claims
  signed with HMAC-SHA-256, verified with canonical re-encoding and one generic error.
- Proxy: `proxy/app.py` already streams HTTP through httpx minus hop-by-hop headers and
  bridges websockets with the `websockets` client, answering 502 in the standard envelope.
- Errors: `errors.py` defines the taxonomy; `api/envelope.py` `fail` builds the envelope;
  `api/errors.py` adds `Retry-After` for `RateLimited` only.
- Documented limit: `docs/operations.md` (section Multi-node) says each node serving
  toolbox traffic runs its own co-located api behind a router. `docs/roadmap.md` lists
  cross-node routing as near-term.

### The gap

Placement is global and the toolbox is local. A request that lands on the wrong node cannot
be served, and the operator must run a sandbox-aware router that the platform does not ship.

## 2. Hard constraints

- One server binary on every node. No new daemon, no agent in the sandbox
  (`docs/architecture.md` D3: the toolbox uses driver primitives on the host).
- The owner handles the request with the same routes, authentication, quota, rate limit and
  audit code as today. Forwarding adds no second implementation of any toolbox operation.
- At most one hop. A request that already was forwarded is never forwarded again.
- Fail closed. An unverifiable token, a stale owner or a missing address refuses the
  request; nothing falls back to serving it from the wrong node.
- Single-node and dev setups are unchanged and pay nothing: no lookup, no new dependency.
- Streams stay streams. Uploads, downloads, SSE logs and terminals are never buffered whole.
- Secrets never reach logs, error messages or the sandbox: the routing secret, the route
  token and the caller's `Authorization` header are not logged.
- Every new file stays under 400 lines (AGENTS.md).

## 3. Candidate mechanisms

### (a) Application-level forwarding between server processes (chosen)

Any process that receives a toolbox request for a sandbox it does not host forwards it once
to the owning node's internal address and streams the answer back. See section 4.

Failure modes:
- The caller's API key crosses the internal network in clear text, because the hop is plain
  HTTP. This is the reason for the private-network assumption in section 4.
- The owner can be down while its row still looks fresh (up to 90 seconds). The caller then
  sees a retryable 503, never a hang; section 4 sets the connect timeout.
- A response cut mid-body after the status line is a truncated stream, exactly like the
  preview proxy today. The client must treat a short stream as a failure.
- Per-process state (rate-limit buckets, activity tracker, live terminals) lives on the
  owner, because the owner runs the real handler. Limits that were per process stay so.

### (b) A router in front of per-node api instances (status quo)

Dismissed: every operator must rebuild ownership knowledge outside the platform, and the
single server URL of the SDK and CLI stops being true.

### (c) The central api drives remote docker daemons

Dismissed: it exposes `docker.sock` or a TCP daemon across the network, which is host-level
control of the node (`docs/operations.md`), and docker-py calls are blocking.

### (d) Route toolbox calls through the jobs table

Dismissed: jobs are leased and polled, so they add latency and cannot stream output or carry
a pty.

### (e) HTTP redirect to the owning node

Dismissed: it needs every node reachable by clients, leaks topology, and clients do not
re-send credentials or follow redirects on websockets reliably.

### (f) A new RPC protocol (gRPC or custom) between nodes

Dismissed: a second stack to build and secure when the owner already exposes the exact
routes needed over HTTP.

### (g) Consistent hashing of sandbox to node

Dismissed: ownership is already a database fact set by least-loaded placement; hashing
would contradict it.

## 4. Recommendation

Use (a): forward once over plain HTTP, authenticated by a short-lived HMAC route token.

### Serving topology

A node that must serve toolbox traffic runs role `all` (api plus workers), so one process
has the routes, the docker daemon and the heartbeat. The `api` role stays valid as a pure
edge that forwards and hosts nothing. The `worker` role keeps its health-only app and is
not a forward target; a node that was `worker` for gate 7 switches to `all` to serve
toolbox traffic. Teaching the worker app to serve routes is out of scope.

### Configuration

New fields on `Settings` (`config.py`), read with the existing `SANDFORT_` prefix:

- `SANDFORT_NODE_INTERNAL_URL` (`node_internal_url`, default empty): the address this node
  advertises in its heartbeat. Form `http://host:port`, with no path, query or userinfo.
  Empty means this node accepts no forwards.
- `SANDFORT_ROUTING_SECRET` (`routing_secret`, default empty): the shared HMAC secret, at
  least `MIN_SESSION_SECRET_CHARS` (32) characters. Empty disables routing entirely.
- `SANDFORT_ROUTING_TIMEOUT_S` (`routing_timeout_s`, default 5.0): connect, write and pool
  timeout of the hop; must be positive.

`node_internal_url` without `routing_secret` is a startup error. The read timeout of the hop
is unbounded: the owner's own limits (exec timeout, body caps) bound the work, and logs and
terminals idle legitimately. All nodes and edges must share one `routing_secret`.

### The route token

New module `routing/tokens.py`, same idiom as `egress/tokens.py`:

- Format `sfr_<payload>.<signature>`; payload is unpadded base64url JSON with keys `sbx`,
  `node`, `iat` and `exp`, serialized with sorted keys and compact separators.
- The signature is HMAC-SHA-256 of the payload under `routing_secret`, compared with
  `hmac.compare_digest`. Verification re-encodes the decoded bytes and rejects any
  non-canonical spelling before it checks the signature or parses JSON.
- Lifetime is the constant `ROUTE_TOKEN_TTL_S = 30`; `iat` more than 5 seconds in the future
  is rejected. Nodes need synchronized clocks.
- `node` is the owner's id. The owner accepts a token only when `node` equals its own
  `Settings.node_id` and `sbx` equals the sandbox id in the request path.
- Every failure raises one generic `InvalidRouteToken`; no token material in messages.
- The token proves "a platform node sent this hop". It carries no principal. The owner
  authenticates the forwarded `Authorization` header itself, against the shared database.

The egress module is not touched: it is proven by gate 8. Sharing the small base64 and
HMAC helpers is a follow-up once both modules are stable.

### The address on the nodes row

- `Node` (`domain/node.py`) gains `internal_url: str = ""` and a frozen `NodeRoute` with
  `node_id`, `internal_url`, `state` and `last_heartbeat_at`.
- `NodeRow` gains `internal_url` (`String(255)`, not null, default empty); migration
  `r0009_node_internal_url.py` adds the column with a batch alter like `r0008_egress.py`.
- `NodeRegistry` takes `internal_url` and includes it in every heartbeat, so a changed
  address converges within one interval. `upsert_heartbeat` writes it on insert and update.
- `NodeRepository` gains `route_for_sandbox(sandbox_id) -> NodeRoute | None`, one join of
  `sandboxes.id` and `nodes.id`. It is a system path, not org scoped, like the rest.
- A route is usable when the node is not stale (`HEARTBEAT_STALE_AFTER`) and has an address.
  A `draining` node still owns running sandboxes and stays a valid target.

### Forwarding

New package `routing/`. An ASGI middleware, installed in `create_app` only when
`routing_secret` is set, matches paths `/v1/sandboxes/{id}/toolbox/...` and does this:

1. No credential on the request (no `Authorization` header, and for the websocket no
   `token` query value): pass through. The local handler answers its usual 401, so an
   anonymous caller cannot tell a hosted sandbox from a remote one.
2. The request already carries the hop header: pass through (the owner guard handles it).
3. Look up the route. No row: pass through, the handler answers 404. Row with
   `node_id == Settings.node_id`: pass through, local.
4. Stale owner or empty address: answer 503 `NODE_UNAVAILABLE` without a connection.
5. Otherwise mint a token for that node and sandbox and forward.

Forward request: same method, raw path and query, body streamed from `receive`. Headers are
copied minus hop-by-hop headers, `host` and any inbound `x-sandfort-*`. It adds
`X-Sandfort-Forwarded: 1`, `X-Sandfort-Route-Token`, and `X-Forwarded-For`; `X-Request-Id`
and `Idempotency-Key` pass through so one id spans both hops in logs and audit rows.

Forward response: status, headers minus hop-by-hop, body relayed chunk by chunk with
`aiter_raw`, unchanged. SSE log streams and downloads keep their framing. The middleware
sits innermost, around the routes, so the body limit, request id and telemetry wrap it and
the edge never runs the toolbox route dependencies; the owner runs them once.

Websockets: the middleware dials `ws://<owner>/<path>?<query>` with the same two headers
using the `websockets` client, accepts the client socket only after the upstream is open,
and pumps both directions until either side closes, mapping close codes through the same
sendable-code rule as the preview proxy. The pty create call is an ordinary forwarded REST
call, so the connect token is minted and redeemed on the owner and the edge never touches
`CONNECT_TOKENS_ATTR`. A reused token still closes with 4401 from the owner.

### The owner guard

In the same package, a second ASGI middleware always installed when `routing_secret` is set:
when the hop header is present it verifies the token (signature, expiry, node, sandbox) and
checks `route_for_sandbox` names this node. Any failure answers 503 `NODE_UNAVAILABLE` with
reason `rejected` or `misrouted`; it deliberately is not 401, which clients read as a bad
API key. A verified request is marked forwarded in the ASGI scope and the forwarding
middleware never runs for it. A client that sends the hop header by hand gets 503, never an
unauthenticated path.

### Errors

`errors.py` gains `NodeUnavailable(SandfortError)`: code `NODE_UNAVAILABLE`, status 503, a
`retry_after_s` like `RateLimited`, and `details` with `reason` and `node_id`.
`api/errors.py` sends `Retry-After` for it. Reasons: `stale`, `no_address`, `unreachable`,
`timeout` (edge side) and `rejected`, `misrouted` (owner side, passed through unchanged).
Over websockets an edge failure closes with 1013 (try again later) or, when the server
supports `websocket.http.response`, answers the handshake with the same envelope.
There is no automatic retry: exec and writes are not idempotent, the client decides.

### Local development

With the default empty `routing_secret`, `create_app` installs neither middleware, so a
single node, the default node id `local` and every existing test behave as before with no
extra query. With a secret set on one node, the lookup finds `node_id == Settings.node_id`
and passes through after one primary-key join.

### Why not mutual TLS now

HMAC plus a private network is chosen first because:
- mTLS needs an operator PKI (issuance, rotation, revocation, trust store) that this
  repository does not ship, and uvicorn and the `websockets` client each need extra setup.
- The route token follows the proven egress idiom, with one shared secret to rotate.
- The internal address already carries a scheme, so `https` plus certificate verification
  can be added later without a schema change.

The cost is stated plainly: the hop is unencrypted, so the caller's API key and the file
and command bytes cross the internal network in clear text. Operators must run nodes on a
private network or an encrypted overlay. This is a documented requirement, not a feature
of the token.

### Delivery slices

Each slice is at most five files, one contract, and ends with its gate.

1. Settings and route token. Files: `src/sandfort/config.py`,
   `src/sandfort/routing/__init__.py`, `src/sandfort/routing/tokens.py`,
   `tests/test_routing_tokens.py`, `tests/test_routing_config.py`. Gate: unit tests for
   round trip, canonical re-encoding, wrong secret, wrong node, wrong sandbox, expiry,
   future `iat`, short secret and `node_internal_url` without a secret.
2. Address on the nodes row. Files: `src/sandfort/domain/node.py`,
   `src/sandfort/db/models/nodes.py`, `src/sandfort/db/repositories/nodes.py`,
   `src/sandfort/migrations/versions/r0009_node_internal_url.py`,
   `tests/test_node_address.py`. Gate: migration up and down on SQLite,
   `route_for_sandbox` for hit, miss and stale cases, and the existing
   `tests/test_nodes.py` and `tests/test_placement.py` still pass.
3. Registry advertises. Files: `src/sandfort/db/repositories/ports.py`,
   `src/sandfort/services/node_registry.py`, `src/sandfort/api/wiring.py`,
   `tests/test_nodes.py`. Gate: a heartbeat stores the configured address and a changed
   address converges on the next beat; `mypy --strict src/sandfort` is clean.
4. Error and shared streaming helpers. Files: `src/sandfort/errors.py`,
   `src/sandfort/api/errors.py`, `src/sandfort/proxy/streaming.py`,
   `src/sandfort/proxy/app.py`, `tests/test_routing_errors.py`. The helpers
   (hop-by-hop set, request body iterator, sendable close code, websocket pumps) move out
   of `proxy/app.py` unchanged. Gate: the envelope has status 503, `NODE_UNAVAILABLE` and
   `Retry-After`; `tests/test_proxy.py` and `tests/test_proxy_terminal.py` pass untouched.
5. HTTP forwarding and owner guard. Files: `src/sandfort/routing/forward.py`,
   `src/sandfort/routing/guard.py`, `src/sandfort/routing/middleware.py`,
   `src/sandfort/api/app.py`, `tests/test_routing_http.py`. Gate: two in-process apps
   sharing one database, nodes `alpha` and `beta`, fake driver; exec, upload, download and
   SSE logs sent to alpha for a beta sandbox return the beta result with streaming intact;
   no credential gives 401; a stale owner gives 503 `stale` with no connection attempt; a
   closed port gives `unreachable`; a forged or wrong-node token gives `rejected`; a hand-
   sent hop header without a token gives 503; one forward per request; with no secret set
   the middleware is absent and no extra query runs.
6. Websocket forwarding. Files: `src/sandfort/routing/ws_forward.py`,
   `src/sandfort/routing/middleware.py`, `tests/test_routing_ws.py`. Gate: a pty created
   and connected through alpha for a beta sandbox echoes bytes both ways; resize works; a
   reused token closes 4401; an unreachable owner closes 1013; client close tears down the
   upstream.
7. Real gate and docs. Files: `examples/gate9.py`, `docs/operations.md`,
   `docs/roadmap.md`, `CHANGELOG.md`. Gate: `examples/gate9.py`
   starts two role `all` processes (nodes alpha and beta, shared database, real Docker),
   creates sandboxes on both, then through alpha only runs exec, a file round trip, a git
   init and commit, an async command with followed logs and an interactive terminal on a
   beta sandbox; stops beta and shows a retryable 503; exits non-zero on any failure.

## 5. Non-goals for the first version

These items are out of scope:

- No snapshot or volume migration between nodes, and no re-placement of a sandbox to
  another node; `node_id` stays what placement stamped.
- No mutual TLS and no encryption of the hop; the private network is an assumption.
- No routing of `api/routes/sandbox_logs.py` (container logs), the preview proxy
  (`proxy/app.py`) or the web terminal page; they keep their current node-local behavior.
- No teaching of the `worker` role to serve routes, and no multi-hop or fan-out requests.
- No automatic retry, failover to another node or queueing of forwarded requests.
- No routing metrics or per-org caps shared across nodes. Caps on terminals and async
  commands that rely on process-local counters become per node; slice 5 verifies this and
  records the result in `CHANGELOG.md`.
- No token revocation. A leaked route token is replayable for its 30 second life against
  one sandbox and one node, and still needs a valid API key or connect token to do work.
- No dynamic secret rotation: changing `SANDFORT_ROUTING_SECRET` needs a restart of every
  node, and nodes with different secrets reject each other with `rejected`.
