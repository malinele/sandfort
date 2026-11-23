# Per-sandbox egress allowlists: design decision

Status: implemented (slices 1 to 3 and the live gate; status checked against the code on
2026-11-10). This was a decision document for the last phase-eight package. It names a
mechanism, its failure modes and the delivery slices; the sections below keep the original
design text, and "Implementation status" lists where the code is narrower or different.

## Implementation status (2026-11-10)

Implemented, with sources:

- Slice 1, model and validation: `egress_allowlist` on the create request and the sandbox
  response (`src/sandfort/api/schemas/sandboxes.py`, `src/sandfort/domain/sandbox.py`,
  `openapi/sandfort.v1.json`), hostname rules and a leading-dot domain form, the entry cap
  `SANDFORT_EGRESS_ALLOWLIST_MAX_ENTRIES` (default 16), `block_all` with a non-empty allowlist
  rejected, migration `src/sandfort/migrations/versions/r0008_egress.py`. Sandboxes with an
  allowlist bypass the warm pool (`src/sandfort/services/warm_pool.py`).
- Slice 2, proxy: `src/sandfort/egress/proxy.py`, a CONNECT-only asyncio proxy per node
  (`python -m sandfort.egress.proxy`). Every resolved address passes `check_address` from
  `src/sandfort/webhooks/ssrf.py`, and the proxy connects to a vetted address. It fails closed:
  407 for a bad or missing credential, 403 for a name outside the allowlist or a blocked
  address, 502 for an unresolvable name or unreachable upstream, 405 for any method other than
  CONNECT. Decisions are logged with sandbox id and target host, never the credential.
- Slice 3, wiring: `SANDFORT_EGRESS_PROXY_ADDRESS` and `SANDFORT_EGRESS_SECRET`
  (`src/sandfort/config.py`); a create with an allowlist is refused when either is unset; the
  sandbox environment receives the proxy variables (`src/sandfort/egress/env.py`); the Docker
  driver selects a separate `sf-egress-net` bridge (`src/sandfort/drivers/docker/networks.py`).
  The driver creates both bridges with fixed interface names, `sf-br0` for `sf-net` and `sf-br1`
  for `sf-egress-net`, because the host rules match the interface name; a network recreated
  under a generated `br-<id>` name would match no rule. `deploy/host-setup.sh` installs the
  `SANDFORT-EGRESS-PROXY` chain; the operator steps are in `docs/operations.md` ("Egress
  proxy").
- Clients: `egress_allowlist` in the Python SDK `create_sandbox`, `--egress` on
  `sandfort sandbox create`, `egressAllowlist` in the TypeScript SDK `createSandbox`.
- Slice 4, gate: `examples/gate8.py` runs against real Docker. A sandbox with an allowlist
  receives the proxy variables, a fetch of the allowed host succeeds through the CONNECT
  tunnel, a fetch of an unlisted host is refused (403) and a fetch with a wrong credential is
  refused (407). It does not exercise a direct IP connection, the metadata address or software
  that ignores the proxy variables, which the design asked the gate to show. The host firewall
  chain is a Linux-only step and is not run on macOS.

Differences from the design text below:

- The credential is not a stored hash. It is a signed token (HMAC, `src/sandfort/egress/tokens.py`)
  that carries the sandbox id and the allowlist, so the proxy needs no lookup. This is the
  "signed token" option the design names as the first version.
- The port in `CONNECT host:port` is restricted by a setting, not per sandbox: see "Proxy
  limits" below. The non-goals section no longer says the port is unrestricted.
- An empty allowlist (`[]`) is not refused. The create succeeds and the sandbox is created with
  `block_all` set, whatever the deployment default or an explicit `block_all=false`, so it
  has no network at all (`_with_default_network` in `src/sandfort/services/sandboxes.py`). Only
  `None` (no allowlist) leaves egress as it was.
- Jobs mode (`SANDFORT_SANDBOX_JOBS_ENABLED`, required for multi-node) refuses creates with an
  allowlist (`docs/operations.md`, "Egress proxy"), so an allowlist and multi-node placement
  cannot be combined today.
- The allowlist is fixed at create; there is no route to change it on a running sandbox.

## Proxy limits (2026-11-10)

The proxy applies the limits below on top of the allowlist. Each is read from the environment
by `egress_limits_from` in `src/sandfort/config.py` (and mirrored as a `Settings` field), with
the defaults named there. Defaults are restrictive; `EgressProxy` built directly in code is
permissive until given limits, and only `ProxyConfig` / `EgressProxy.from_config` carry the
defaults.

| Limit | Setting | Default | Effect |
|---|---|---|---|
| Denied CIDRs | `SANDFORT_EGRESS_DENIED_CIDRS` | loopback (`127.0.0.0/8`, `::1/128`), link-local (`169.254.0.0/16`, `fe80::/10`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) | Every resolved address is checked against these, in addition to `check_address`. The node's own interface addresses are always added (discovered at start-up), so an allowlisted name that resolves to the host itself is refused (403). |
| Allowed ports | `SANDFORT_EGRESS_ALLOWED_PORTS` | `443,80` | A `CONNECT` to any other port is refused (403). One list for the whole node, not per sandbox. |
| Connection cap | `SANDFORT_EGRESS_MAX_CONNECTIONS_PER_SANDBOX` | 64 | A sandbox holding that many open tunnels gets 429 for the next one. The range is 1 to 100000. |
| Idle timeout | `SANDFORT_EGRESS_IDLE_TIMEOUT_S` | 300 | A tunnel that moved no bytes for this many seconds is closed. The range is 1 to 86400. |
| Token lifetime | `SANDFORT_EGRESS_TOKEN_TTL_S` | 7 days (604800) | The token is minted at sandbox creation and carries an expiry. The proxy refuses an expired token, and one whose lifetime exceeds the configured limit. The range is 60 seconds to 400 days. |

The token lifetime bounds the damage of a leaked token, not the sandbox: a sandbox older than
the lifetime loses proxy access until it is recreated, because there is no re-mint route.

Setting a denied-CIDR or port list to an invalid value fails start-up; a blank
`SANDFORT_EGRESS_DENIED_CIDRS` is an empty list (no denied ranges beyond the node's own
addresses), so leave it unset unless you mean that.

## 1. Goal and threat

Goal: a sandbox reaches only the hosts the operator named for it, for example the model
provider API and nothing else.

Threat: code running in a sandbox (often AI-generated) can
- send data it can read (mounted volumes, cloned repositories, environment) to any host, or
- reach internal services and cloud credentials from inside the operator's network.

### What exists today

- `block_all` (`NetworkPolicy` in `domain/sandbox.py`, `build_host_config`): sets
  `network_mode` to `none`; otherwise the container joins `sf-net`.
- Host egress chain (`deploy/host-setup.sh`): `SANDFORT-EGRESS` rejects 169.254.0.0/16,
  100.64.0.0/10, 168.63.129.16/32 and RFC 1918; the rest of the public internet is allowed.
- Host input guard (same script): `SANDFORT-HOST-GUARD` rejects new connections from
  sandboxes to host services. It is hooked into INPUT for the sandbox bridge and the default
  bridge (build containers). The allowlist bridge has its own chain,
  `SANDFORT-HOST-GUARD-PROXY`, which admits replies and exactly one new-connection exception
  (tcp to the proxy address on the proxy port, `SF_EGRESS_PROXY` and `SF_EGRESS_PROXY_PORT`,
  default 3128) and rejects the rest. IPv6 INPUT has no guard.
- Prod acknowledgement (`egress_acknowledged` in `config.py`, `api/app.py`): prod start
  requires `SANDFORT_EGRESS_ACKNOWLEDGED=true`; the process cannot observe iptables.
- Webhook SSRF guard (`webhooks/ssrf.py`): protects the server's own outbound webhook
  calls, not sandbox traffic.

The metadata address is blocked for sandboxes by the host script (the link-local range). The
separate metadata list in `webhooks/ssrf.py` applies to webhook delivery only.

### The gap

The choice per sandbox is binary: no network, or every public address. There is no way to say
"only `api.example-provider.com`". A networked sandbox can send data to any public host.
Known limits of the host script also remain: public IPv6 is not filtered, and Docker's
nftables backend is not supported.

## 2. Candidate mechanisms

### (a) Forward proxy on the host

Each node runs a small proxy. A sandbox is created with the proxy environment variables
(`HTTPS_PROXY`, `HTTP_PROXY`, lowercase variants) and its network is closed except for the
proxy address. The proxy accepts `CONNECT host:port` and plain HTTP requests, checks the
target host against the sandbox's allowlist, and relays or refuses.

Failure modes:
- Software that ignores the proxy variables has no network at all. This fails closed and is
  acceptable; it is the reason to prefer this design.
- TLS is tunneled, so the proxy sees the requested hostname and nothing else. It cannot see
  paths, bodies or whether the payload is what the operator expected. Allowing a host allows
  everything that host will accept, including attacker-controlled accounts on it.
- The proxy must map each connection to a sandbox. Source IP is fragile on a shared bridge
  with icc disabled and address reuse. Per-sandbox proxy credentials
  (`Proxy-Authorization`) are the clean answer, at the cost of minting and delivering a secret.
- The credential is visible to code in the sandbox. It is only useful through the proxy, so
  the exposure is limited to that sandbox's own allowlist.
- The proxy resolves names itself. It must refuse targets that resolve to blocked ranges
  (the same rule as `check_address` in `webhooks/ssrf.py`), or an allowlisted name pointing
  at an internal address becomes an internal-service bypass.
- Direct IP connections are blocked by the network rule, not by the proxy; the network rule
  is therefore load-bearing and must be verified.

### (b) Per-sandbox firewall rules on the host

Install iptables or nft rules per container, permitting the resolved addresses of the
allowed hosts.

Failure modes:
- Rules are by IP, allowlists are by name. Addresses of large providers change often and sit
  behind shared CDNs, so a resolved set goes stale or admits unrelated tenants of the same
  address.
- Resolution races: the name resolved at create time and the one the sandbox resolves later
  may differ.
- Rule churn: every create, stop and delete edits the shared tables; cleanup after a crash
  needs the reconciler to learn about firewall state.
- It depends on the iptables backend, which `host-setup.sh` already documents as a
  limitation.

Not chosen: fragile at scale and it controls addresses, not the names operators think in.

### (c) DNS-filtering resolver

Answer only allowlisted names, return nothing for the rest.

Dismissed. It is trivially bypassed by connecting to an IP address directly, by a
hard-coded address in the code, or by a resolver the code ships itself. It controls
discovery, not reachability. It could still be a hint layered on (a), but it is not a
control.

## 3. Recommendation

Use (a): a forward proxy with per-sandbox credentials, failing closed.

Fail closed means: an unknown credential, an unresolvable name, a resolved blocked address, a
port outside the allowed ports, an unreachable api for a lookup, or an expired token all
result in a refusal, and an empty allowlist creates a sandbox with no network. Absence of a
policy never means allow.

### Data model

- `CreateSandboxCommand` and `Sandbox` gain `egress_allowlist: list[str] | None`.
  `None` keeps today's behavior, so existing callers are unchanged.
- Entries are validated as hostnames: lowercase ASCII or IDNA, labels of 1 to 63 characters,
  at most 253 in total, no scheme, port, path or IP literal. A leading dot (`.example.com`)
  means the domain and all its subdomains; `example.com` means that name only.
- The number of entries is capped by a setting.
- `block_all=true` with a non-empty allowlist is rejected at validation as contradictory.
- A per-sandbox proxy credential is minted at create. Only a hash is stored, with the same
  discipline as API keys; the plaintext goes to the sandbox environment once.
- The warm-pool fingerprint (`services/warm_pool.py`) must include the allowlist, or a pooled
  sandbox with different egress could be handed out. Safest first step: sandboxes with an
  allowlist bypass the pool.
- Create is audited like every non-GET route; allowlist entries are not secrets.

### The proxy

- A small CONNECT-method proxy process on each node, next to the worker. It listens on an
  address reachable from the sandbox network only.
- It authenticates the credential, obtains the allowlist for that sandbox from the api, or
  from a signed token carrying it, and may cache the result briefly. A signed token avoids a
  call per connection; an api lookup would allow changes without a restart. The first
  version uses the token: simpler failure behavior, and the allowlist is immutable for the
  life of the sandbox.
- It resolves the name itself, rejects blocked ranges, and connects to the address it
  vetted, so a second DNS answer cannot redirect the connection.
- It logs allow and deny decisions with sandbox id and target host, never credentials.

### Driver wiring

- Sandboxes with an allowlist join a separate bridge network whose host chain rejects
  everything except the proxy address and replies. `deploy/host-setup.sh` creates that
  network and chain; `ensure_network` in `drivers/docker/networks.py` is the pattern.
- `build_host_config` selects the network by policy and the driver sets the proxy variables.
- The prod acknowledgement covers the new rules, and a missing proxy on a node makes
  allowlisted creates fail instead of falling back to open egress.

### Delivery slices

1. Schema and api field: `egress_allowlist` on create, validation, storage, response,
   openapi, SDK and CLI option. No enforcement yet; creating with an allowlist is refused
   until slice 3 lands, so the field cannot give a false sense of safety.
2. Proxy process: CONNECT handling, credential or token check, resolution and range checks,
   decision logging, with unit tests that need no Docker.
3. Driver wiring: network, host script rules, environment variables, credential mint and
   token signing, reconciler cleanup, then lifting the refusal from slice 1.
4. Gate: a script in `examples/` that creates a sandbox allowing one host, shows that host
   works, that another host, a direct IP and the metadata address all fail, and that
   software ignoring the proxy variables has no network. Runs against real Docker.

## 4. Non-goals for the first version

- No packet inspection and no TLS interception. Only the requested hostname is controlled.
- No wildcard semantics beyond the leading-dot convention; no patterns, regexes or globs.
- No per-sandbox port rules. The allowed ports are one node-wide setting
  (`SANDFORT_EGRESS_ALLOWED_PORTS`, default `443,80`).
- No allowlist changes on a running sandbox.
- No content or volume limits on allowed destinations.
