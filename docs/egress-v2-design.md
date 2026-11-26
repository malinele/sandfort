# Egress v2: address rules, runtime policy changes, controlled DNS and jobs mode

Status: design, 2026-11-24, checked against HEAD 9d9f1c18. Revised the same day after review:
the admission re-check that makes the propagation contract hold (sections 4.1, 4.2.1, 5.3) and
the lookup that brings v1 tokens under revocation (section 5.5). The code facts behind both were
re-read at HEAD dd14c9b7 (`src/sandfort/egress/proxy.py`, `src/sandfort/egress/tokens.py`).
Update 2026-11-25: rounds 1 to 5 are implemented and ship in `v0.1.0-beta.83`
(`CHANGELOG.md` rounds 84 to 88). The "Implementation status" list below records rounds 1 to 3
in detail, and the changelog is authoritative for the rest. This document extends
`docs/egress-allowlist-design.md` (v1).

## Implementation status

Round 1, address rules (2026-11-24, commit 2b90fdee):
CIDR entries in validation and the proxy, IP-literal targets, translation prefixes;
tests/test_egress_rules_v2.py, tests/test_egress_cidr_proxy_v2.py and
tests/test_egress_cidr_validation_v2.py pass with the v1 egress gate files.
Review hardening, same day: the always-refused set extends the fixed four prefixes of
section 4.3 with `::/96` (IPv4-compatible, `::` and `::1` excepted), `::ffff:0:0:0/96`
(IPv4-translated SIIT) and `fec0::/10` (deprecated site-local); entry validation also
refuses those ranges, `5f00::/16` (SRv6 SIDs) and a zone id inside a CIDR entry.
Round 2, proxy policy channel (2026-11-24, commit a2dc726e): sfe2_ tokens, the signed
policy lookup client and cache, per-phase
admission budgets with the step 11 re-check, the tunnel registry and sweep, and v1
token lookup; tests/test_egress_tokens_v2.py, tests/test_egress_policy_wire_v2.py,
tests/test_egress_policy_client_v2.py, tests/test_egress_tunnels_v2.py,
tests/test_egress_proxy_v2.py, tests/test_egress_admission_v2.py and
tests/test_egress_legacy_lookup_v2.py pass with the round 1 and v1 egress gate
files.
Round 3 server half (2026-11-24, this commit; the hash is recorded in the next round):
migration r0027 (policy generation and credential epoch columns), the internal policy
route with the response MAC bound to the request body, PATCH egress_allowlist with the
sandbox.egress_updated audit row, and v2 minting at create and reset;
tests/test_egress_migration_v2.py, tests/test_egress_patch_v2.py,
tests/test_egress_policy_route_v2.py and tests/test_egress_mint_v2.py pass with the
round 1, round 2 and v1 egress gate files. The SDK and CLI clients (section 13 round 3
fallback) follow as their own contract.
Each round in section 13 adds one line here with its commit and the tests that
pass, using the same format as the v1 document.

## 1. Goals and non-goals

v1 lets a sandbox reach only the hosts the operator named for it. The proxy resolves those
names, vets every answer and connects by address. v2 keeps that mechanism and closes four gaps,
listed in priority order:

1. **Address rules.** An allowlist entry can be a CIDR range as well as a hostname. The proxy
   decides an IP-literal target by the address it will connect to, never by a name.
2. **Policy changes on a running sandbox.** `PATCH /v1/sandboxes/{id}` replaces the allowlist
   without recreating the container. The change is written to the audit log in the same
   transaction as the row. Propagation has a stated time bound, for new connections and for
   tunnels that are already open.
3. **Controlled DNS.** The container-tier DNS side channel is closed. Only the proxy resolves
   names, only names an allowlist rule admits, and it reuses the vetted answer for a bounded
   window.
4. **Jobs mode.** An allowlisted create works when sandboxes are created by jobs, which
   multi-node needs. Placement only picks nodes that can enforce the policy.

The design partner set three evaluation conditions, and this document answers each one:

- A bounded contract for enforcement, for DNS and address changes, and for policy updates
  (sections 4, 5.3 and 6).
- Synthetic allowed and denied cases (section 12).
- The new capabilities are evaluated separately from the DNS2 operational item, which is the
  transient host resolver failure on the beta VM (section 6.5).

Non-goals:

- No TLS interception and no packet or content inspection. The proxy sees the CONNECT target,
  meaning the name or address and the port. It does not see the SNI, the Host header, paths or
  bodies.
- No per-entry ports. Ports stay one node-wide list, `SANDFORT_EGRESS_ALLOWED_PORTS`.
- No patterns, regexes or globs. The leading dot stays the only wildcard for names.
- No reaching private ranges through tenant rules. The operator's denied CIDRs always win over
  a tenant's CIDR entry.
- No switch between egress modes on a running sandbox. Open becomes restricted, restricted
  becomes open, and a create-time `[]` (no network) gets a network are all refused. The
  network a container joins is fixed when the container is created.
- No push invalidation from the api to the proxies. Propagation is bounded by a polling
  interval (section 5.3).
- No serve-stale DNS. A resolver failure is a 502, as it is today.
- No new webhook event types, and no proxy decisions written to the audit chain. Proxy
  decisions stay in its log.
- No warm-pool support for allowlisted sandboxes (section 8).
- No sandbox reset in jobs mode. That is a separate gap (section 7.5).

## 2. Current state

v1 is a CONNECT-only asyncio proxy, one per node (`src/sandfort/egress/proxy.py`). It
authenticates a signed token (`sfe_`, `src/sandfort/egress/tokens.py`) whose claims carry the
sandbox id and the allowlist, so the proxy needs no lookup. It then checks the node-wide port
list and matches the target name against the allowlist: an exact name, or a leading-dot domain
and its subdomains. It resolves the name itself with `getaddrinfo`, refuses the request if any
answer falls in a denied network or fails `check_address`, and connects by address. The
allowlist is stored in three places: the `egress_allowlist` column, the token baked into the
container env at create, and the network choice. The `sandfort.egress_restricted` label puts
the container on `sf-egress-net`, whose host chain admits only the proxy port. A reset re-mints
the token. A start reuses the container and its env.

The whole admission runs under one deadline. `EgressProxy.handle` wraps `_admit` in
`asyncio.wait_for(..., REQUEST_TIMEOUT_S)` (15 s), and `_admit` covers reading the request,
authentication, the allowlist match, resolution and every connect attempt (`CONNECT_TIMEOUT_S`,
10 s per address). The allowlist decision is taken early in `_admit`, and the 200 is sent only
after the upstream connection is open.

The token is the only revocation point v1 has. `_authenticate` returns `claims.allowlist`, and
nothing is looked up, so a token stays usable with the allowlist it carries until it expires.
Tokens issued before `LEGACY_TOKEN_CUTOVER` (2026-11-11) skip the lifetime limit and were minted
for up to 400 days.

Four limits follow from this. Entries are hostnames only, and IP literals are refused at
validation. Changing the allowlist would need a new token in a running process's environment,
so there is no route for it. On the `container` tier, Docker's embedded resolver still answers
queries from `sf-egress-net`, which leaks data through the queried names
(`docs/isolation-tiers.md`, the internal known-issues log). Jobs mode refuses allowlisted creates
because `Lifecycle.spec` in `src/sandfort/services/sandbox_jobs.py` builds the driver spec
without the egress label, so the container would join the open bridge
(`src/sandfort/services/sandboxes.py`, the refusal in `_validate`).

## 3. Data model and API

### 3.1 Allowlist entries

`egress_allowlist` stays one list of strings, and each entry has one of three forms:

| Form | Example | Admits |
|---|---|---|
| Host | `api.example.com` | A CONNECT to exactly that name |
| Domain | `.example.com` | `example.com` and every subdomain of it |
| CIDR | `198.51.100.0/24`, `2001:db8:10::/48` | A CONNECT whose target is an IP literal inside the range |

Host and domain entries keep the v1 rules from `check_egress_allowlist` in
`src/sandfort/domain/sandbox.py`. A CIDR entry is accepted only if all of the following hold:

- `ipaddress.ip_network(entry, strict=True)` succeeds and `str(network) == entry`. The entry
  must be canonical: no host bits set, compressed lowercase IPv6, no leading zeros. Nothing is
  normalized, which matches the hostname rule.
- The prefix is at least `/8` for IPv4 and at least `/32` for IPv6. The constants
  `EGRESS_CIDR_MIN_PREFIX_V4` and `EGRESS_CIDR_MIN_PREFIX_V6` live in the domain layer. Without
  this minimum, `0.0.0.0/0` would make IP literals an open network.
- The network is entirely global. It must not overlap loopback, link-local, private, shared
  (`100.64.0.0/10`), multicast, reserved or documentation ranges. Stdlib `ipaddress`
  properties are used here, because the domain layer may import nothing else
  (`[tool.importlinter]`).
- The network does not overlap any entry of `Settings.egress_denied_cidrs`. The proxy still
  checks every address, because a node can run a different denied list (section 4.3).

The examples in this document use documentation ranges (RFC 5737, RFC 3849). Validation
refuses those as non-global, and the tests inject a permissive check.

An entry that is neither a valid hostname nor a canonical CIDR is a 422 that names the entry.
`SANDFORT_EGRESS_ALLOWLIST_MAX_ENTRIES` (default 16) counts entries of all three forms.

### 3.2 Sandbox row

| Column | Type | Meaning |
|---|---|---|
| `egress_allowlist` | JSON list, nullable (unchanged) | Entries of section 3.1. `NULL` means no allowlist, as today |
| `egress_policy_generation` | `INTEGER NOT NULL DEFAULT 0` | 0: no allowlist, or a legacy v1 token. 1 at a v2 create, plus 1 per effective PATCH |
| `egress_credential_epoch` | `INTEGER NOT NULL DEFAULT 0` | Raised by 1 each time a reset re-mints the token. The token carries it, and a mismatch revokes the token |

On the domain `Sandbox`, the comment on `egress_allowlist` changes from "fixed at create" to
"replaced by PATCH while the generation is at least 1". The two new fields are plain ints.

Migration `r0027_egress_v2.py` adds both columns with defaults, so no backfill is needed. Its
downgrade drops them. Round 5 adds a separate migration, `r0028_node_egress_ready.py`, which
puts `egress_ready BOOLEAN NOT NULL DEFAULT false` on `nodes`.

### 3.3 Create

The request shape does not change. The description of `egress_allowlist` changes to: "Host
names, leading-dot domains or CIDR ranges the sandbox may reach through the egress proxy. An
empty list means no network at all (block-all). Omitting the field keeps the operator
default." A v2 create stores `egress_policy_generation = 1` and mints a v2 token
(section 5.1).

### 3.4 PATCH

`UpdateSandboxRequest` gains `egress_allowlist: list[str] | None`. The handler distinguishes a
missing field from an explicit `null` through `model_fields_set`.

| Request | Result |
|---|---|
| Field absent | Egress unchanged, as today |
| `"egress_allowlist": [...]` with at least one entry | Validated as at create (section 3.1, the count cap, `enforce_block_network`). Replaces the list and raises the generation by 1 |
| `"egress_allowlist": []` | Accepted for a sandbox created with a non-empty list. Every new CONNECT is refused and open tunnels are closed (section 5.4). The sandbox stays on `sf-egress-net` and `block_all` is not set |
| `"egress_allowlist": null` | 422: "egress_allowlist cannot be removed from a sandbox, create a new sandbox for open egress" |
| A list equal to the stored one (same entries, same order) | 200. No generation change and no egress audit row |

Preconditions, which apply to every request that carries the field:

- The sandbox was created with `egress_allowlist` set to `None`: 409. The container is on the
  open bridge.
- The sandbox was created with `[]` (stored `block_all`): 409. The container has no network.
- `egress_policy_generation == 0`, a legacy v1 token: 409 with the message "reset the sandbox
  to upgrade its egress credential". A reset mints a v2 token (section 9.2).
- The state is `destroying` or `destroyed`: 409, the existing rule.
- `enforce_block_network` is on: 403, the same rule as at create.

The PATCH writes only to the database. No driver call is made, so it works in any other state:
pending, creating, started, stopped or error. A stopped sandbox gets the new policy on its next
connection. The egress change and the other PATCH fields (labels, minutes, `public`) commit in
one transaction. Concurrent PATCHes behave like today's PATCH: the update runs with
`expected_version`, and a conflict surfaces as it does now.

The scope stays `sandboxes:write`, the existing `Writer` dependency. Section 15 asks whether a
separate scope should be required.

Example:

```
PATCH /v1/sandboxes/sbx_123
{"egress_allowlist": ["api.example.com", "198.51.100.0/24"]}

200 {"data": {..., "egress_allowlist": ["api.example.com", "198.51.100.0/24"],
              "egress_policy_generation": 4, ...}}
```

The 200 means the policy is stored. It does not confirm that a proxy has applied it. The
contract for that is in section 5.3.

### 3.5 Response

`SandboxResponse` gains `egress_policy_generation: int | null`. The value is `null` when
`egress_allowlist` is `null`, 0 for a legacy sandbox, and at least 1 otherwise. The token never
appears in a response. The existing test `tests/test_api_sandboxes.py` (token not leaked) is
extended to cover v2 tokens.

### 3.6 Internal policy route

`POST /internal/egress/v1/policies` is mounted with `include_in_schema=False`, like the SCIM
routes. Only proxies call it.

Request body: `{"nonce": "<nonce>", "sandbox_ids": ["sbx_1", "sbx_2"]}`, compact JSON in that key
order, with 1 to 256 ids and a client-generated nonce (a non-empty base64url string of at most 64
characters; the client uses `secrets.token_urlsafe(16)`). The route requires exactly these two
keys and answers 422 otherwise.

Response body:

```
{"issued_at": 1795000000,
 "policies": [
   {"sandbox_id": "sbx_1", "found": true, "generation": 4, "epoch": 1,
    "rules": ["api.example.com", "198.51.100.0/24"]},
   {"sandbox_id": "sbx_2", "found": false}]}
```

`found` is false when the sandbox does not exist, is `destroying` or `destroyed`, or has no
allowlist (`egress_allowlist` is `NULL`). A legacy row (generation 0) is returned like any
other, with its stored rules, because the proxy also looks up v1 tokens (section 5.5). The
repository gets a read across orgs keyed by sandbox id, used only by this route.

Request authentication:

- Header `X-Sandfort-Egress-Auth: t=<unix>,s=<b64url>`.
- `s` is the HMAC-SHA-256, under the derived key `K_req`, of
  `"POST\n/internal/egress/v1/policies\n<t>\n<hex sha256 of body>"`.
- The api refuses a request with a missing or bad MAC, or with `|now - t| > 30 s`, with an
  unsigned 401.

Response authentication:

- Header `X-Sandfort-Egress-Signature: t=<unix>,s=<b64url>`.
- `s` is the HMAC under `K_resp` of `"<t>\n<hex sha256 of body>"`.
- The proxy treats any response without a valid signature as "policy unavailable". That
  includes an unsigned 404 from an api that predates the route. Such a response is never read
  as "not found" (section 9.3).
- **Round 3 amendment (security review of round 2, 2026-11-24, MANDATORY):** when the server
  route lands, the response MAC message becomes
  `"<t>\n<hex sha256 of request body>\n<hex sha256 of response body>"`, so a signed response
  binds to the exact request and a captured response for one id set can never answer another
  request nor be replayed against a later lookup inside the 30 second window. The client
  (`policy_wire.verify_response`) changes in the same round 3 commit as the server route;
  until then the channel is inert (nothing mints v2 tokens and the policy URL stays unset),
  so no deployed proxy ever speaks the unbound format. The verifier also then checks the
  body's `issued_at` against the header `t`.
- **Round 3 amendment, second (same review, 2026-11-24):** the first amendment alone did not
  stop replay, because an identical id list produced an identical request body, so a captured
  signed 200 (for example one made before a PATCH narrowed an allowlist, or before a reset
  raised the epoch) still verified against the next request for the same ids inside the 30
  second window. The request body therefore carries a client-generated random nonce, drawn
  fresh for every request. The response MAC's request-body-hash term then binds each response
  to one request instance: a captured response verifies only against the exact body it was
  signed for, and a later request, even for the same ids, has a different body and refuses it.
  The server needs no nonce store; the proof is on the client, which compares against the body
  it just sent. The nonce adds no secrecy, only uniqueness, and the freshness window still
  bounds how long a request MAC can be replayed against the route itself (a replayed request
  yields only a fresh, correctly signed answer to the same question).
- **Route mounting and ordering (same review, 2026-11-24):** the route is mounted only when
  `SANDFORT_EGRESS_POLICY_ROUTE_ENABLED` is set and `SANDFORT_EGRESS_SECRET` is configured
  (section 3.8); otherwise the public API app answers 404 for the path. The route checks the
  auth header's form and freshness before it reads the request body, so a stale or malformed
  header costs no body read.

Derived keys, all from `SANDFORT_EGRESS_SECRET`:

- `K_tok2 = HMAC(secret, "sandfort/egress/token/v2")`
- `K_req = HMAC(secret, "sandfort/egress/policy/request/v1")`
- `K_resp = HMAC(secret, "sandfort/egress/policy/response/v1")`

v1 tokens keep the raw secret, so each use has its own key.

The hop is plain HTTP on the private network, like the toolbox routing hop
(`docs/operations.md`). The MACs give integrity and freshness. They give no confidentiality,
and allowlist entries are not secrets.

### 3.7 OpenAPI impact

- Create request: new description for `egress_allowlist`.
- `SandboxResponse`: one new property, `egress_policy_generation`.
- `UpdateSandboxRequest`: one new property, `egress_allowlist`, with the PATCH semantics above
  in its description.
- In round 5, if `ERROR_CODES` appears in the spec, it gains `egress_unavailable`. That feeds
  `tests/test_openapi_error_vocabulary.py`.
- No new public path. The count of 91 HTTP operations on 70 paths does not change, because the
  internal route is outside the spec. `context/metrics-snapshot.md` needs no recount.

### 3.8 New settings

| Setting | Read by | Default | Effect |
|---|---|---|---|
| `SANDFORT_EGRESS_POLICY_ROUTE_ENABLED` | api | false | Mounts the internal policy route (section 3.6), and only together with `SANDFORT_EGRESS_SECRET`. Off: the path answers 404 on the public API app. Set it on the api instances the proxies' policy URL points at |
| `SANDFORT_EGRESS_POLICY_URL` | proxy | unset | Base URL of an api instance on the private network. Unset: v2 tokens get 503, v1 tokens follow their claims with no lookup and no revocation (section 5.5), and the proxy logs a startup warning |
| `SANDFORT_EGRESS_POLICY_CACHE_S` | proxy | 5 (range 2 to 60) | Called C below. How long a fetched policy is used, counted from the moment the request was sent. Also the sweep interval |
| `SANDFORT_EGRESS_POLICY_TIMEOUT_S` | proxy | 2 (range 1 to 10, and less than C) | Called L. Timeout of one lookup |
| `SANDFORT_EGRESS_POLICY_MAX_STALE_S` | proxy | 60 (at least C) | Called M. Open tunnels of a sandbox whose policy cannot be refreshed are closed after this long |
| `SANDFORT_EGRESS_DNS_PIN_S` | proxy | 30 (range 0 to 300) | Pin window per sandbox and name (section 4.4). 0 resolves on every CONNECT, which is v1 behavior |
| `SANDFORT_EGRESS_DNS_SINK_LISTEN` | proxy | unset | `addr` on which the proxy serves the DNS sink, udp and tcp on port 53 (section 6.2) |
| `SANDFORT_EGRESS_DNS_SINK_ADDRESS` | api and driver | unset | The sink address given as the only DNS server to `container`-tier sandboxes on `sf-egress-net`. Unset: the v1 behavior plus a startup warning |

L must be less than C, so a sweep's lookups always finish before the next sweep starts
(section 5.3). With C at its minimum of 2, L can only be 1.

The proxy settings are read in `ProxyConfig.from_env` (`src/sandfort/egress/proxy_limits.py`),
not in `config.py`; only the api-side `SANDFORT_EGRESS_POLICY_ROUTE_ENABLED` lives in `Settings`, so `config.py` (1011 lines) does not grow by more than the one `Settings`
field. Invalid values, including `L >= C`, fail startup, as they do for the existing proxy
limits.

## 4. Proxy enforcement

### 4.1 Order of checks

| Step | Check | Refusal |
|---|---|---|
| 1 | Request read within 15 s, method is CONNECT | 405 |
| 2 | `Proxy-Authorization` decoded, token verified locally (`sfe_` v1 or `sfe2_` v2) with signature, expiry and lifetime limit. The username equals the sandbox id | 407 |
| 3 | Target parsed (`host:port`, IPv6 in brackets, no zone id) | 400 |
| 4 | Port in `SANDFORT_EGRESS_ALLOWED_PORTS` | 403 |
| 5 | Policy: from the cache or a lookup (section 5.2), for v2 tokens and, when the policy URL is set, for v1 tokens (section 5.5). Not found, epoch mismatch (v2) or generation at least 1 (v1) gives 407. Unavailable gives 503. A v1 token with the policy URL unset takes its rules from the claims | 407, 503 |
| 6 | Rule match: an IP literal against CIDR rules, a name against host and domain rules | 403 |
| 7 | Per-sandbox tunnel slot | 429 |
| 8 | Addresses: the literal itself, or a pinned or freshly resolved set. Nothing resolves: 502 | 502 |
| 9 | Every address passes the denied networks, the fixed translation prefixes (section 4.5) and `check_address` | 403 |
| 10 | Connect in order with 10 s each. If every pinned address fails, drop the pin, re-resolve once and repeat steps 9 and 10 | 502 |
| 11 | Admission re-check (section 4.2.1): the sandbox's current cache entry, refreshed first if it is stale, must still admit the target. Refusal closes the upstream connection | 403, 407, 503 |
| 12 | Tunnel registered (sandbox, target, port, address, generation) with no await since step 11's last await, then 200 and relay | none |

The port check (step 4) runs before the policy lookup, so a refused port costs no lookup. The
global ceiling (503) and the pre-authentication cap (429) stay as they are, before step 1. A
503 for "policy unavailable" is told apart from the global-ceiling 503 by the reason in the log
line.

### 4.1.1 Time budgets

v1 bounds the whole admission with one 15 s `asyncio.wait_for` (section 2). In v2 that single
deadline would also have to cover the policy lookup, a possible refresh at step 11 and, with
pinning, a second resolve-and-connect round. A single connect timeout (10 s) on a pinned
address would then leave too little time for the re-resolution in step 10 to finish. v2
replaces the single deadline with one budget per phase:

| Phase | Budget | Constant or setting |
|---|---|---|
| Read the request line and headers (step 1) | 15 s, unchanged slow-header defense | `REQUEST_TIMEOUT_S` |
| Policy lookup (step 5) and the refresh in step 11 | L each | `SANDFORT_EGRESS_POLICY_TIMEOUT_S` |
| One resolution (step 8, and the re-resolution in step 10) | 5 s | `RESOLVE_TIMEOUT_S` (new) |
| One connect attempt (step 10) | 10 s per address | `CONNECT_TIMEOUT_S` |
| One connect round over an address set (step 10) | 12 s | `CONNECT_ROUND_S` (new) |
| Whole admission after the request is read (steps 2 to 12) | 2L + 2 x 5 + 2 x 12, which is 38 s with the defaults | computed at startup |

So a pinned address that times out after 10 s still leaves its round 2 s, and the
re-resolution and second round get their own budgets. The admission cap is the sum of the
phase budgets, so no phase is cut short by an earlier one.

The cost is that a slow upstream holds its global and per-sandbox slots for up to 38 s instead
of 15 s. The ceilings themselves do not change.

The propagation contract (section 5.3) does not depend on any of these budgets. Step 11 decides
the policy again at the moment of the 200, however long steps 6 to 10 took.

### 4.2 Name targets

A name target is admitted only by a host or domain rule, with the same matching as
`host_allowed` today. **A name that matches no host or domain rule is refused before any
resolution**, even when its addresses would fall inside a CIDR rule. If the proxy resolved
unlisted names, a sandbox could send data to any DNS zone owner by asking for
`<data>.attacker.example`, and the proxy would become the DNS side channel that section 6
closes. A client that needs an address range reaches it with an IP-literal target.

### 4.2.1 Admission re-check

The rule match in step 6 happens before resolution and connection, which can take most of the
38 s admission budget. A decision taken at step 6 can therefore be older than the cache window
by the time the 200 is sent. Step 11 closes that gap:

- It reads the sandbox's current cache entry, not the entry step 5 used. If a sweep or another
  CONNECT has stored a newer policy in the meantime, that one applies.
- If the entry is stale (older than C, counted from when its request was sent), it is
  refreshed first, with timeout L. A failed refresh refuses with 503.
- It repeats the decisions of step 5 and step 6 against that entry: `found`, the epoch (v2),
  the generation (v1, section 5.5) and the rule match for the target form. The connected
  address of a literal target is matched against the CIDR rules again.
- A refusal closes the upstream connection and answers 403, 407 or 503 as in steps 5 and 6.
- Between the last await of step 11 and the registration in step 12 there is no await. The
  proxy runs on one event loop, so no cache update can land between the re-check and the
  registration.

The address vetting of step 9 is not repeated, because the denied networks and translation
prefixes do not change while the process runs.

### 4.3 IP-literal targets and CIDR rules

A target that `ipaddress.ip_address` accepts in its strict form is an IP literal: IPv4 with no
leading zeros, or IPv6 in brackets. It is admitted only by a CIDR rule that contains the
address, after the IPv4-mapped normalization in section 4.5. The address is then vetted in step
9, like a resolved address. The denied list on the node therefore wins over a tenant rule even
when api validation passed, for example after an operator changes the denied list on one node.

Host and domain rules never admit a literal. A string such as `2130706433` or `0x7f.0.0.1` is
not a literal under the strict parse, so it is handled as a name. No rule admits it, so it is
refused without resolution.

### 4.4 Resolution, pinning and TTL

The proxy is the only resolver for allowlisted traffic. It uses the host resolver
(`getaddrinfo` through `resolve_host`), as v1 does.

- **Pinning.** After a name passes steps 6 to 9, its vetted address set is pinned for the pair
  (sandbox, name) for `SANDFORT_EGRESS_DNS_PIN_S`. Within that window, every CONNECT of that
  sandbox to that name uses the pinned set without a new query. Pins are per sandbox, so one
  tenant cannot tell from timing what another resolved. Each sandbox holds at most 256 pins
  (LRU), and the proxy at most 65536.
- **Consistency.** Every answer of a resolution must pass. One denied answer refuses the whole
  request (step 9), which is the v1 rule. Inside the window the set does not change, so a
  rebinding answer cannot alternate with a public one. After the window, the next resolution
  is vetted from scratch.
- **TTL.** `getaddrinfo` does not expose record TTLs. The pin window is therefore a fixed
  bound, not the record's TTL, and the proxy can use an address for up to the pin window after
  the record has changed. Step 10 limits the cost: when every pinned address fails to connect,
  the pin is dropped and the name re-resolved once, within the budgets of section 4.1.1. A
  TTL-aware resolver would need a new dependency and is not part of v2.
- **Errors.** A resolver error, an empty answer or a resolution that exceeds
  `RESOLVE_TIMEOUT_S` is a 502 and is never pinned. Resolution happens again on the next
  CONNECT.
- **Policy interaction.** A pin is dropped when the sandbox's current policy no longer admits
  the name.
- **What pinning is for.** It is for consistency and lower resolver load. It is not a security
  control. The controls are the rule match before resolution, the vetting of every answer, and
  the connection by address.

### 4.5 IPv6

- An IPv4-mapped literal (`[::ffff:10.0.0.1]`) is turned into IPv4 before rule match and
  vetting, the same way `parse_address` already treats resolver answers. A rule
  `10.0.0.0/8` could not exist anyway (section 3.1), and the mapped form never escapes the
  IPv4 denied list.
- Zone ids (`fe80::1%eth0`) are refused at parse time with 400.
- Translation prefixes are always refused, as a fixed set that `SANDFORT_EGRESS_DENIED_CIDRS`
  cannot remove: NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16` and Teredo
  `2001::/32`. They can carry an IPv4 address that the IPv4 denied list would otherwise not
  see.
- The proxy dials IPv6 upstreams only if the host itself has IPv6 egress. When it has none,
  connections to IPv6 addresses fail in step 10 and the next address in the set is tried.
- `sf-egress-net` stays IPv4-only. Round 4 makes `ensure_network` refuse to adopt an
  `sf-egress-net` that has `EnableIPv6` set, and the prod probe reports it.
- v2 does not change the existing host limit: IPv6 INPUT has no guard (section 11).

### 4.6 Ports

`SANDFORT_EGRESS_ALLOWED_PORTS` (default `443,80`) applies to every rule form. It is one list
per node and is checked before the policy lookup. A CIDR rule carries no port. The rule
"`198.51.100.0/24`, port 22" cannot be expressed unless the operator adds 22 to the list, and
that opens 22 for every allowlisted sandbox on the node. Port 53 is not on the default list,
and adding it, or 853, gives sandboxes DNS to allowed addresses. That is the operator's choice,
and `docs/operations.md` states it next to the setting.

### 4.7 What the proxy cannot decide

- **Redirects.** A client that follows an HTTP redirect to another host opens a new CONNECT,
  which is checked again. A redirect on the same host is invisible and needs no check.
- **Relays.** An allowed host that forwards data (an upload API, a paste service, an object
  store bucket, a webhook relay, an open proxy) carries anything to anyone. See section 11.
- **Name versus TLS.** The proxy checks the CONNECT name only. The client can send a different
  SNI or `Host` inside the tunnel (domain fronting). With HTTP/2 connection coalescing, it can
  also reuse a tunnel opened for an allowed name for another name on the same certificate and
  address. Comparing the SNI with the CONNECT name would raise the bar, but Encrypted Client
  Hello hides the SNI and the `Host` header stays encrypted. It is left out of v2
  (section 15).
- **Plain HTTP proxying.** Absolute-URI requests such as `GET http://...` are still refused
  with 405. Clients send `http://` URLs through CONNECT only if they are configured to do so.

## 5. Runtime policy updates

### 5.1 Token v2

The format is `sfe2_<payload>.<signature>`, with the same base64url encoding and canonical
checks as v1, signed under `K_tok2`.

- Claims: `{"v": 2, "sbx": <sandbox id>, "ep": <credential epoch>, "iat": ..., "exp": ...}`.
- There is no allowlist claim. The policy is looked up.
- The lifetime follows the v1 rule (`token_lifetime_s`).
- A v1 verifier refuses the token because the prefix differs. A v2 verifier refuses an `sfe_`
  token, and the proxy sends that token down the v1 path instead.
- A v2 token is minted at create (inline mode), by a reset, and in jobs mode by the owning node
  before the container is created (section 7.2).
- A reset raises `egress_credential_epoch` and mints with the new epoch, so the previous
  container's v2 token stops working within C. In v1 that token stayed valid until it expired.
  A previous container's v1 token stops working within C as well, through the generation check
  of section 5.5.

The env layout is the v1 layout: the four proxy variables, with the id and token as userinfo,
plus `no_proxy`. Code inside the sandbox can still read the token (section 11).

### 5.2 Lookup and cache

- The cache key is the sandbox id. A cached entry holds `found`, the generation, the epoch, the
  parsed rules and the time the request was sent.
- An entry is fresh for C seconds from that time. A fetch that started before a PATCH committed
  can therefore never extend the old policy past T + C.
- A lookup result replaces the cached entry only if its request was sent later than the cached
  entry's request. A slow, older response can never overwrite a newer one.
- When a result replaces an entry and its `found`, generation or epoch differs, every
  registered tunnel of that sandbox is re-checked at once (section 5.4), whichever path
  fetched it: a sweep, a CONNECT lookup or a step 11 refresh.
- A CONNECT for a sandbox with no fresh entry triggers a lookup. Concurrent CONNECTs of one
  sandbox share a single in-flight lookup.
- The lookup outcome decides the request:
  - Lookup timeout (L), transport error or bad signature: 503 "egress policy unavailable".
  - `found: false`: 407.
  - v2 token: token epoch differs from the policy epoch: 407.
  - v1 token: policy generation is at least 1: 407 (section 5.5).
- The cache is bounded (LRU, 65536 entries). An entry with no open tunnels is evicted once it
  is stale.

### 5.3 Propagation contract

Take a PATCH whose transaction commits at time T, a proxy that can reach the policy URL, and
the defaults C = 5 s and L = 2 s. The contract applies to every token the proxy looks up: all
v2 tokens, and v1 tokens when the policy URL is set (section 5.5).

1. **New connections.** Every CONNECT that the proxy admits after T + C (5 s) is decided under
   the PATCH's generation or a later one. This holds however long the admission took.
2. **Open tunnels.** Every tunnel whose target the new generation no longer admits is closed by
   T + C + L (7 s).
3. **Widening.** A newly added entry admits connections no later than T + C. Nothing has to be
   closed.
4. **Lookup failure.** When the proxy cannot refresh a sandbox's policy, its new CONNECTs are
   refused (503) as soon as the cached entry is stale. Its open tunnels are closed once M
   (60 s) has passed since the last successful refresh. A tunnel therefore never outlives a
   successful refresh by more than M + C.
5. **No acknowledgement.** The api does not learn when a proxy applied a generation. The bound
   above is the contract. The proxy logs `gen=` on every allow and deny line, so operators can
   check it.

Why clause 1 holds. "Admitted" means the moment of the 200, which follows step 11 with no await
in between. Step 11 uses an entry whose request was sent less than C before that moment. If the
200 comes after T + C, the request was sent after T, so the api answered it from a database
where the PATCH had already committed. An admission that decided at step 6 under an older entry
and then spent up to 38 s resolving and connecting is re-decided at step 11 and refused if the
new generation does not admit it (test U12).

Why clause 2 holds. A tunnel admitted under the old generation was registered before the new
generation landed in that proxy's cache. Tunnels registered later were re-checked at step 11
against an entry at least that new, because the cache never moves back (section 5.2). The first
sweep that starts at or after T starts before T + C. It sends a fresh request for every
sandbox with tunnels, and that request finishes within L. L is less than C, so this sweep
never joins a lookup still in flight from the previous sweep, which could have been sent before
T. When the result lands, by T + C + L, the re-check of section 5.4 runs for every registered
tunnel of the sandbox and cancels those the new generation does not admit. A CONNECT lookup or
step 11 refresh that lands earlier triggers the same re-check earlier.

Clause 2 does not hold through a lookup failure. Clause 4 is the bound then.

### 5.4 Open tunnels

The tunnel registry (`src/sandfort/egress/tunnels.py`) records, for each open tunnel: the
sandbox, the target form (name or literal), the port, the connected address, the generation at
admission and the task handling the connection. Tunnels opened with a v1 token are registered
the same way and swept when the policy URL is set.

Every C seconds, a sweep refreshes the policy of every sandbox that has tunnels. It uses batch
lookups of up to 256 ids, sent concurrently with timeout L each, so a node with N active
sandboxes makes about N / 256 requests every C seconds. When a result lands, and whenever any
other lookup replaces an entry with a different `found`, generation or epoch (section 5.2),
the sandbox's tunnels are re-checked against the current rules:

- A name tunnel is checked against host and domain rules.
- A literal tunnel is checked against CIDR rules.
- Every tunnel of a sandbox that is no longer found, whose v2 epoch changed, or whose v1 token
  now meets a generation of at least 1, is closed.

The address of a name tunnel was vetted at admission. The denied list does not change while
the process runs, so it is not checked again. A tunnel that no longer matches has its task
cancelled. The `finally` path in `EgressProxy.handle` releases the slots and closes both sides,
and the client sees a reset connection. For a policy of `[]`, every tunnel of the sandbox is
closed.

### 5.5 Legacy v1 tokens

A v1 token carries its allowlist in signed claims, and v1 never looks anything up (section 2).
If v2 kept that path unchanged, every v2 revocation would miss v1 tokens:

- A legacy sandbox reset onto v2 (epoch 1) would leave the previous container's v1 token usable
  with the old, possibly wider allowlist until it expires. Tokens issued before
  `LEGACY_TOKEN_CUTOVER` can last up to 400 days.
- Deleting the sandbox would not stop the token either. Snapshots made before 5fa64d8 can hold
  such tokens (the internal known-issues log), so they can surface in other sandboxes.
- Any process that holds `SANDFORT_EGRESS_SECRET` could mint a v1 token with any allowlist for
  any sandbox id, and the proxy would honor the claims.

So, when `SANDFORT_EGRESS_POLICY_URL` is set, the proxy looks up v1 tokens as well, through the
same cache and route as v2 tokens:

- `found: false` (deleted, destroying, destroyed or no allowlist): 407.
- Generation at least 1: 407. The sandbox has been reset onto a v2 credential, so any v1 token
  for it belongs to an earlier container.
- Generation 0: admitted under the **rules stored in the row**, not the claims. The claims
  allowlist is ignored, so a forged or stale v1 token cannot widen a sandbox's policy.
- v1 tokens carry no epoch, so no epoch check applies to them.
- Signature, expiry, lifetime limit and the `LEGACY_TOKEN_CUTOVER` rules still apply first, at
  step 2.

In normal operation the row and the claims hold the same list, because a generation-0 row can
only change through a create or a reset, and both mint a matching token. The lookup therefore
changes no decision for an untouched legacy sandbox. It adds revocation by delete and by reset,
with the bounds of section 5.3.

When the policy URL is unset, v1 tokens keep the v1 behavior: claims, no lookup, no
revocation. The proxy logs a startup warning that names this. Once round 3 is deployed the URL
is needed in practice anyway, because without it no sandbox created after the upgrade has
egress. The proxy does not refuse to start without it, so that rounds 2 and 3 can roll out in
order (section 9.3). Section 15 asks when v1 acceptance should end altogether.

### 5.6 Rejected alternatives

- **The proxy reads the database directly.** The proxy parses untrusted input from sandboxes.
  Giving it database credentials would widen what a proxy compromise exposes. SQLite also
  makes a separate process's access awkward.
- **Push from the api to the proxies.** This needs the api to know every node's proxy, adds a
  delivery and retry path, and still needs polling as the safety net. It could be added later
  as a hint that shortens C.
- **Re-minting the token into the running container.** A process environment cannot be changed
  from outside. Writing the token to a file would break every client that reads
  `HTTPS_PROXY`.
- **Registering a pending admission at step 6.** The sweep would then see admissions still in
  resolution or connection and cancel them. It needs a second registry state and still lets a
  lookup that lands between step 6 and the 200 go unchecked unless the cancel path is exact.
  The step 11 re-check gives the same bound with one decision point.
- **Stating the bound as T + C + 15 s + L.** It would describe the v1 deadline, not a property
  of the policy, and it would grow with every budget in section 4.1.1. The design partner asked
  for a bound on the policy, so v2 fixes the code path instead of widening the number.
- **Honoring v1 claims for generation-0 rows.** It keeps the forged-allowlist path open to any
  holder of the shared secret. The row is the policy, and the token only names the sandbox.

## 6. Controlled DNS

### 6.1 Who resolves

Only the proxy resolves, and only names admitted by a host or domain rule (section 4.2).
Sandboxes on `sf-egress-net` have no working resolver on any tier. Clients that resolve the
target locally before using the proxy fail, as they do on `gvisor` and `microvm` today.

### 6.2 `container` tier: the DNS sink

On the `container` tier (runc), Docker's embedded resolver at `127.0.0.11` answers inside the
container and forwards external names to the host's upstream servers, so a queried name leaves
the host. A fail-fast `resolv.conf` does not help, because code can query `127.0.0.11`
directly.

v2 changes where those forwarded queries go:

- For a container on `sf-egress-net` whose runtime has no network stack of its own,
  `build_host_config` (`src/sandfort/drivers/docker/hardening.py`) sets
  `dns=[SANDFORT_EGRESS_DNS_SINK_ADDRESS]`.
- The proxy process serves a DNS sink on that address, udp and tcp port 53. The sink answers
  every query with REFUSED and never forwards.
- It logs counts per source address once a minute and never logs the queried names. A name can
  carry data, and the host logs are not where it should land.
- `deploy/egress-dns-sink.sh`, which `host-setup.sh` sources, adds one exception to
  `SANDFORT-HOST-GUARD-PROXY`: udp and tcp 53 to the sink address.
- The sink binds port 53, so the proxy needs `CAP_NET_BIND_SERVICE` or must run as root.
  `docs/operations.md` states this.

The design rests on two assumptions, verified in round 4 against real Docker on Linux before
any documentation changes:

- **A1.** With `dns` set, the embedded resolver forwards external names only to the configured
  server and never falls back to the host's resolvers.
- **A2.** The forward reaches the sink whether dockerd sends it from the container's network
  namespace or from the host's. The sink listens on the bridge gateway address, which is local
  in both cases.

The test asserts three things inside a runc container on `sf-egress-net`: `getent hosts
example.com` fails, the sink's counter for that source rises, and the stub upstream configured
for the test sees zero queries. If A1 or A2 fails, round 4 stops at the driver change. The
`container`-tier warning stays in `docs/isolation-tiers.md` and positioning, and the finding is
recorded in the internal known-issues log.

A residual effect: the embedded resolver still answers container names on the same network
(`sf-<id>`), which tells code that other sandboxes exist and what their addresses are. With
`icc` disabled, those addresses are not reachable, and the answer never leaves the host.

The prod probe (`src/sandfort/drivers/docker/egress_probe.py`, with the DNS part in a new
`egress_probe_dns.py`) gains one check. A runc canary on `sf-egress-net` must fail to resolve a
public name. An answer is a finding, which matches the existing "any success is a finding"
rule.

When `SANDFORT_EGRESS_DNS_SINK_ADDRESS` is unset, v1 behavior stays and the api logs a startup
warning. This keeps existing deployments working on upgrade. Section 15 asks whether prod
should require the sink in a later release.

### 6.3 `gvisor` and `microvm`

No change. These guests never see `127.0.0.11`. They get the fail-fast `resolv.conf`, and the
host chain drops their direct DNS.

### 6.4 Pinning

Pinning is specified in section 4.4. It belongs to controlled DNS because it defines which
answer a connection uses.

### 6.5 Separation from DNS2

DNS2 is the transient host-resolver failure on the beta VM: "server misbehaving" on
2026-11-08, 11-17 and 11-19, and FallbackDNS not engaging. It stays its own open operational
item. For egress v2:

- No acceptance criterion depends on the host resolver. Hermetic tests inject a resolver, and
  gate 11 checks policy outcomes, not resolver uptime.
- A resolver failure is a 502 with `reason=resolver error` in the proxy log. That reason is
  distinct from every policy denial, so a DNS2 occurrence cannot be counted as an egress v2
  failure, and the other way round.
- A pinned name can keep working through a short resolver failure inside its window. This is
  a side effect. It is not claimed as a fix for DNS2, and serve-stale is a non-goal.

## 7. Jobs mode and multi-node

### 7.1 One spec builder

`Lifecycle.spec` (`src/sandfort/services/sandbox_jobs.py`) sets
`labels=egress_spec_labels(sandbox)`, so the inline path and the job path produce the same
spec. The egress merge in `MountingLifecycle.spec` is removed, and that method keeps only the
mounts. No driver protocol changes: labels and env travel in existing `SandboxSpec` fields
(`src/sandfort/drivers/base.py`, frozen), and the `dns` option is a host-config choice inside
the Docker driver.

### 7.2 Minting on the owning node

In jobs mode, the api stores the sandbox without proxy variables. Its `_sandbox_env` mints only
inline. Before `driver.create`, `drive_create` calls a provisioning step
(`src/sandfort/services/egress_provision.py`):

- If the sandbox has a non-empty allowlist and its stored env has no proxy variables, the step
  mints a v2 token with this node's `EgressReminting` (its own proxy address and secret). It
  writes the env in its own unit of work and commits. Only then does the driver call run,
  which follows the intent-then-act rule (`docs/architecture.md` D4).
- If the node has no egress settings (`_job_egress is None`), `record_failure` runs with the
  new code `egress_unavailable`. No container is created on any bridge.

A retried job finds the proxy variables already stored and does not mint again. An adopted
container keeps its env, and that token stays valid because the epoch has not changed.

Because the node mints, the proxy URL always names the proxy of the node that owns the
sandbox. Nodes can have different `sf-egress-net` subnets.

### 7.3 Placement

- Each node's heartbeat records `egress_ready`, which is true when that node has a proxy
  address, a secret and a policy URL configured. It is stored in the `nodes.egress_ready`
  column.
- For an allowlisted create, `pick_node` gets `require_egress=True` and considers only nodes
  with `egress_ready`. **It never falls back to the local node** unless the local node
  qualifies. When no node qualifies, the create gets 409 "no node can run
  egress-allowlisted sandboxes".
- A job that reaches a node anyway, for example because its heartbeat flipped after placement,
  fails closed under section 7.2.

### 7.4 Requirements for multi-node egress

These come on top of the existing list in `docs/operations.md`:

- The same `SANDFORT_EGRESS_SECRET` on every api and proxy process.
- On every node: a proxy, the sink, `host-setup.sh` (including the sink exception), and
  `SANDFORT_EGRESS_POLICY_URL` reachable over the private network.
- Synchronized clocks. Policy requests and responses carry a 30-second window.

### 7.5 What stays the same

- The volume refusal in jobs mode stays.
- Sandbox reset stays unavailable in jobs mode, so neither the epoch nor the token can be
  refreshed there. An allowlisted jobs-mode sandbox that outlives `SANDFORT_EGRESS_TOKEN_TTL_S`
  (default 7 days, or its auto-delete horizon plus one day) loses egress. This is the v1 limit
  for a sandbox that is never reset, and it is stated in the docs.
- PATCH works in jobs mode, because it makes no driver call.
- Per-sandbox tunnel caps remain exact, because a sandbox lives on one node.

## 8. Warm pool

No change. `is_eligible` (`src/sandfort/services/warm_pool.py`) keeps refusing any create that
has an allowlist, including an empty one, and `compute_spec_hash` keeps leaving the allowlist
out. A pooled sandbox has `egress_allowlist = None`, and a PATCH that would make it restricted
is refused (section 3.4), so a claimed pool member can never gain an allowlist.

Because v2 looks the policy up, a pool of members already on `sf-egress-net` holding a v2 token
becomes possible later. That is a separate design and not part of v2.

## 9. Migration and backward compatibility

### 9.1 Database

- `r0027` (round 3) adds two columns with defaults. Existing rows get generation 0 and epoch 0.
- `r0028` (round 5) adds `nodes.egress_ready` with default false. Until upgraded nodes send a
  heartbeat, no node qualifies for allowlisted creates in jobs mode, which fails closed.
- A downgrade below `r0027` drops the columns. v2 sandboxes then fail closed with 503 until a
  reset on the old code mints v1 tokens.

### 9.2 Existing sandboxes

- A legacy sandbox (generation 0, `sfe_` token) keeps its allowlist. With the policy URL set,
  the proxy takes the rules from the row and refuses the token once the sandbox is deleted,
  destroying or reset onto v2 (section 5.5). With the URL unset, it behaves exactly as in v1.
  The `LEGACY_TOKEN_CUTOVER` rules still apply in both cases.
- PATCH on a legacy sandbox gets 409 with a reset hint. A reset (inline mode only) mints a v2
  token and sets the generation to at least 1 and the epoch to 1. From then on, the previous
  container's v1 token gets 407.
- An allowlist created in round 1 or 2 may already contain CIDR entries, because round 1 lets
  v1 tokens carry them. The proxy's rule engine reads them the same way from the claims and
  from the row.

### 9.3 Mixed versions

- **Rollout order: proxies first.** The round 2 proxy accepts v1 and v2 tokens. Round 3 api
  code mints v2. An old proxy refuses a v2 token with 407, which fails closed.
  `deploy/redeploy-beta.sh` already recreates the proxy (`tests/test_redeploy_egress_r63o.py`).
- **The policy URL is set after the api has the route.** While the URL is unset, a round 2
  proxy treats v1 tokens exactly as v1 does. Setting it against a pre-round-3 api would turn
  every v1 CONNECT into 503, because that api answers the route with an unsigned 404. So the
  URL is set on every proxy in the same deploy step that brings the round 3 api, and
  `docs/operations.md` states that order. Between the api upgrade and the URL change, sandboxes
  created by the new api get 503, which fails closed.
- **Api rollback below round 3.** The proxies still accept v2 tokens. The old api answers the
  internal route with an unsigned 404, which the proxy reads as "unavailable" (503), never as
  "not found". v2 sandboxes lose egress until the api rolls forward again. With the URL still
  set, legacy v1 sandboxes lose egress too. Unsetting the URL restores v1 behavior for them,
  without revocation. Nothing opens.

### 9.4 Clients

- Old Python and TypeScript SDKs and the CLI send `egress_allowlist` as a list of strings, so
  CIDR entries pass through them unchanged. None of them validates entries locally.
- A response with an unknown field must be ignored. Round 3 adds a parse test for the Python
  SDK. The TypeScript SDK's model parser has to be confirmed in its own follow-up.
- The Python SDK has no sandbox PATCH today. Round 3 adds
  `client.set_egress_allowlist(sandbox_id, entries)` (sync and async) and
  `sandfort sandbox egress set <id> [--allow ENTRY ...] [--deny-all]` plus
  `sandfort sandbox egress show <id>`.
- The `egressAllowlist` option on the TypeScript SDK's `updateSandbox` is a follow-up outside
  the five rounds, because the runner's gates are pytest and mypy only.

## 10. Audit events and failure modes

### 10.1 Audit

- `sandbox.egress_updated` is recorded through `Lifecycle.record` in the same unit of work as
  the row update. Details: `{"old_allowlist": [...], "new_allowlist": [...],
  "old_generation": n, "new_generation": n + 1}`. Entries are not secrets, which matches the
  create note. If other fields change in the same PATCH, the existing `sandbox.update` row is
  written as well, in the same transaction.
- A PATCH that changes nothing writes no egress row.
- The create note already records `egress_allowlist`.
- The reset audit row is unchanged. The epoch is visible in the row, not in the audit details
  (section 15).
- Proxy decisions are not audit rows. They are log lines with sandbox id, target, status,
  reason and `gen=`, never the credential, as in v1.

### 10.2 Failure modes

| Condition | Effect | Fails |
|---|---|---|
| `SANDFORT_EGRESS_POLICY_URL` unset on a proxy | v2 CONNECTs get 503. v1 tokens follow their claims with no revocation. Startup warning | closed for v2, v1 behavior for v1 (documented) |
| Api unreachable, timeout, bad or missing response signature | New CONNECTs get 503 once the entry is stale. Tunnels close after M | closed |
| Clock skew above 30 s between proxy and api | Signatures refused, then 503 as above | closed |
| Sandbox deleted or destroying | 407 for v1 and v2 tokens (v1 only with the URL set). Tunnels close at the next sweep | closed |
| Token from before a reset (v2 epoch mismatch, or v1 token on a generation of at least 1) | 407 | closed |
| v1 token whose claims are wider than the row | Decided by the row's rules (URL set) | closed |
| Token expired | 407. Recovery needs a reset (inline mode) | closed |
| Admission outlives its policy entry (slow resolution or connect across a PATCH) | Step 11 refreshes and re-matches. Refused if the new policy does not admit the target | closed |
| Resolver error, empty answer or resolution over 5 s | 502, not pinned | closed |
| An answer in a denied network or translation prefix | 403 | closed |
| Every pinned address unreachable | One re-resolution, then 502 | closed |
| Sink down or not listening | `container`-tier lookups time out. Clients using the proxy are unaffected | closed, slower |
| Sink address unset | v1 DNS behavior on the `container` tier, with a startup warning | open (side channel), documented |
| Jobs mode, no egress-ready node | Create gets 409 | closed |
| Jobs mode, job on a node without egress settings | Sandbox `error`, code `egress_unavailable`, no container | closed |
| Proxy restart | Caches and pins empty, tunnels dropped (as in v1) | closed |
| Concurrent PATCH | Same optimistic version handling as other PATCH fields | n/a |

## 11. Security limits

After v2, egress is still a forward proxy that enforces a list of hostnames and address ranges.
It is not a network firewall, and it is not data-loss prevention. v2 still does not prevent the
following, and these limits must stay in `docs/isolation-tiers.md` and `context/positioning.md`
§7.

1. **Relay through an allowed host.** Anything an allowed host accepts can be passed on:
   uploads, gists, buckets, issue comments, webhook relays, open proxies, and the model
   provider's own file or batch APIs. Allowing a host allows every account on it, including
   accounts an attacker controls.
2. **Zones that tenants control.** A domain rule over a zone where anyone can create names,
   such as a shared hosting or bucket domain, lets code put data into the subdomain it
   connects to. The CONNECT name carries the data, and so does the proxy's own query for that
   name. Domain rules should cover only zones the operator trusts.
3. **CIDR rules admit everything at those addresses.** That includes any SNI and every tenant
   of a shared CDN or cloud range behind the addresses.
4. **Name versus TLS mismatch.** Domain fronting and HTTP/2 coalescing work inside an allowed
   tunnel (section 4.7). No SNI check is made.
5. **No content, volume or rate limits** on allowed destinations beyond the tunnel cap and the
   idle timeout. Timing and connection-count covert channels to allowed hosts stay open.
6. **Propagation is bounded, not instant.** It takes up to C + L (7 s by default) for an
   update, and up to M + C (65 s) for open tunnels while lookups fail. Data already sent
   through a tunnel before it closes is gone.
7. **The credential is visible to sandbox code.** It works only through the proxy and only for
   that sandbox's policy. Another sandbox on the same bridge that obtains it can use that
   sandbox's policy. v2 adds revocation by delete or reset, for v2 tokens and, with the policy
   URL set, for v1 tokens. Snapshots made before 5fa64d8 may still contain v1 tokens
   (the internal known-issues log). With the URL set, such a token stops working once its source
   sandbox is deleted or reset. With the URL unset, it stays valid until it expires, which for
   tokens issued before `LEGACY_TOKEN_CUTOVER` can be up to 400 days after issue.
8. **The egress secret is shared and powerful.** Every api and proxy process holds
   `SANDFORT_EGRESS_SECRET`. A holder can mint a token for any sandbox id. With the policy URL
   set, that token gets only that sandbox's current policy, never an allowlist of the holder's
   choosing. With the URL unset, a holder can mint a v1 token with any allowlist. A holder can
   also sign policy requests and forge policy responses to a proxy on the private network, so
   the secret must stay off sandbox nodes' workloads and out of sandboxes.
9. **Private ranges.** Tenant rules cannot reach internal services. Removing a range from the
   node's denied list opens it for every allowlisted sandbox on that node.
10. **The DNS sink depends on Docker behavior.** If assumptions A1 or A2 fail, or the sink
    address is unset, the `container`-tier side channel remains, and the existing advice
    stands: for regulated data, use `gvisor` or `microvm` with the allowlist.
11. **Host limits are unchanged.** There is no IPv6 INPUT guard, public IPv6 is not filtered on
    the open network, Docker's nftables backend is unsupported, and the host rules are
    Linux-only.
12. **Kernel boundary.** On the `container` tier, a kernel escape bypasses the network
    namespace and every rule above. The egress policy is only as strong as the isolation tier.
13. **Jobs mode has no reset**, so a token in jobs mode cannot be rotated.
14. **Longer slot holding.** The per-phase budgets of section 4.1.1 let one admission hold its
    slots for up to 38 s instead of 15 s, so a sandbox that opens many slow CONNECTs reaches
    its tunnel cap sooner. It cannot exceed the cap or the global ceiling.

Wording rule for positioning (unchanged): do not write "network firewall", "full egress
control" or "DLP". Write "egress proxy enforcing hostnames and address ranges per sandbox".

## 12. Test plan

Layers:

- **H**: hermetic pytest, no Docker. Uses an injected resolver, an injected checker that
  admits documentation ranges, a fake opener, a fake clock, and `httpx.MockTransport` for the
  policy route.
- **Dk**: `@pytest.mark.docker`, skippable when Docker is missing.
- **G**: `examples/gate11.py` on a Linux host with `host-setup.sh` applied (the beta VM). The
  orchestrator runs it. It is not a runner gate.

Each "Allowed" case asserts a 200 and the address that was dialed. Each "Denied" case asserts
the status, the log reason and, where it matters, the number of resolver or lookup calls.

### 12.1 Address and name rules (round 1)

| Id | Rules | CONNECT target | Expected | Layer |
|---|---|---|---|---|
| C1 | `api.example.com` | `api.example.com:443` | Allowed | H |
| C2 | `.example.com` | `a.b.example.com:443` | Allowed | H |
| C3 | `.example.com` | `example.com.evil.test:443` | Denied 403, resolver called 0 times | H |
| C4 | `198.51.100.0/24` | `198.51.100.7:443` | Allowed, no resolver call | H |
| C5 | `198.51.100.0/24` | `198.51.101.7:443` | Denied 403 | H |
| C6 | `198.51.100.0/24` | `name-resolving-into-range.test:443` | Denied 403, resolver called 0 times | H |
| C7 | `2001:db8:10::/48` | `[2001:db8:10::5]:443` | Allowed | H |
| C8 | `2001:db8:10::/48` | `[::ffff:10.0.0.1]:443` | Denied 403 (mapped to IPv4, private) | H |
| C9 | `64:ff9b::/96` (injected past validation) | `[64:ff9b::a00:1]:443` | Denied 403 (translation prefix) | H |
| C10 | `api.example.com` | `api.example.com:22` | Denied 403 (port), no lookup | H |
| C11 | `198.51.100.0/24` | `198.51.100.7:8443` | Denied 403 (port) | H |
| C12 | `api.example.com` | `[fe80::1%eth0]:443` | Denied 400 | H |
| C13 | `api.example.com` | `2130706433:443` | Denied 403, resolver called 0 times | H |
| C14 | `api.example.com`, resolver returns public and `10.0.0.5` | `api.example.com:443` | Denied 403 | H |
| C15 | `198.51.100.0/24`, node denied list includes it | `198.51.100.7:443` | Denied 403 | H |
| C16 | `[]` (PATCHed) | any | Denied 403 | H |

Validation cases (422 unless noted):

- `10.0.0.1/8` (host bits set)
- `10.0.0.0/8` (private)
- `0.0.0.0/0` (prefix too short)
- `2001:DB8::/32` (not canonical)
- `198.51.100.0/24` with the default checker (documentation range, non-global)
- A CIDR overlapping `SANDFORT_EGRESS_DENIED_CIDRS`
- 17 mixed entries with the default cap of 16
- A valid public `/24` is accepted (201)

### 12.2 Pinning (round 4)

| Id | Setup | Expected | Layer |
|---|---|---|---|
| P1 | Two CONNECTs to one name inside the window, resolver answer changes in between | Both dial the first vetted set, resolver called once | H |
| P2 | After the window, the resolver returns `10.0.0.5` | Denied 403 (rebinding caught) | H |
| P3 | Every pinned address refuses the connection, re-resolution gives a new public address | Allowed through the new address, resolver called twice | H |
| P4 | Resolver raises `OSError` | 502, nothing pinned, next CONNECT resolves again | H |
| P5 | Sandboxes A and B connect to the same name | Two resolutions (pins are per sandbox) | H |
| P6 | `SANDFORT_EGRESS_DNS_PIN_S=0` | One resolution per CONNECT (v1 behavior) | H |
| P7 | PATCH removes the name while a pin is live | Pin dropped, next CONNECT 403 | H |
| P8 | The single pinned address hits the 10 s connect timeout, re-resolution gives a new public address | Allowed through the new address within the 38 s admission budget (fake clock) | H |
| P9 | Resolver hangs past `RESOLVE_TIMEOUT_S` | 502 after 5 s, nothing pinned | H |

### 12.3 Policy updates and revocation (rounds 2 and 3)

Clock and timings use the defaults C = 5 and L = 2, under a fake clock.

| Id | Step | Expected | Layer |
|---|---|---|---|
| U1 | PATCH adds `b.example.com` at T | CONNECT at T + 5.1 allowed. CONNECT at T + 1 with a cached entry fetched before T denied | H |
| U2 | PATCH removes `a.example.com`, a tunnel to it is open | Tunnel cancelled by T + 7. Tunnel to a host still allowed stays open | H |
| U3 | PATCH removes the CIDR, a tunnel to a literal in it is open | Tunnel cancelled by T + 7 | H |
| U4 | PATCH `[]` | All tunnels cancelled, every CONNECT 403 | H |
| U5 | Policy route down (transport error) | New CONNECT 503 once stale. Tunnels cancelled at M = 60 s | H |
| U6 | Route answers an unsigned 404 (old api) | 503, never 407 | H |
| U7 | Signature valid but `t` 31 s old | 503 | H |
| U8 | `found: false` | 407, tunnels cancelled at the next sweep | H |
| U9 | Reset: epoch 1 to 2, old container's token used | 407 within C | H |
| U10 | 300 sandboxes with tunnels | Sweep sends 2 batch requests per interval, concurrently | H |
| U11 | Concurrent CONNECTs of one sandbox, cold cache | Exactly one lookup in flight | H |
| U12 | CONNECT passes step 6 at T - 0.1 under the old entry, PATCH removing the name commits at T, the fake opener takes 12 s to connect | Step 11 refreshes, the CONNECT gets 403, upstream closed, no tunnel registered | H |
| U13 | Same as U12, but the PATCH only adds an entry | Step 11 refreshes, CONNECT allowed and registered under the new generation | H |
| U14 | A lookup sent before T lands after a lookup sent after T | Cache keeps the newer entry, generation does not move back | H |
| U15 | A step 11 refresh lands with a new generation while other tunnels of the sandbox are open | Those tunnels are re-checked at once, before the next sweep | H |
| U16 | `SANDFORT_EGRESS_POLICY_TIMEOUT_S=5` with `SANDFORT_EGRESS_POLICY_CACHE_S=5` | Proxy refuses to start (L must be less than C) | H |

### 12.4 API (round 3)

| Id | Request | Expected |
|---|---|---|
| A1 | PATCH a new list on a v2 sandbox | 200, generation + 1, one `sandbox.egress_updated` audit row with old and new lists |
| A2 | PATCH the same list | 200, generation unchanged, no egress audit row |
| A3 | PATCH `null` | 422 |
| A4 | PATCH on a sandbox created without an allowlist | 409 |
| A5 | PATCH on a sandbox created with `[]` | 409 |
| A6 | PATCH on a legacy sandbox (generation 0) | 409 with reset hint. After a reset, generation 1 and the PATCH succeeds |
| A7 | PATCH with `enforce_block_network` | 403 |
| A8 | Audit write fails inside the unit of work | Row unchanged (same transaction) |
| A9 | PATCH egress and labels together | One transaction, both audit rows |
| A10 | Internal route without a MAC, with a bad MAC, or with 257 ids | 401, 401, 422 |
| A11 | Response and OpenAPI | `egress_policy_generation` present, no token anywhere in the body, operation count still 91 |
| A12 | Internal route for a generation-0 row and for a row with `NULL` allowlist | First: `found: true`, generation 0, stored rules. Second: `found: false` |

All A cases are hermetic.

### 12.5 Jobs mode (round 5)

| Id | Setup | Expected |
|---|---|---|
| J1 | Jobs mode, allowlisted create | 201. The job path's spec has `sandfort.egress_restricted`. The node mints before `driver.create` (fake driver call order) |
| J2 | No node with `egress_ready` | 409, the local node not chosen |
| J3 | Job runs on a node with no egress settings | State `error`, code `egress_unavailable`, fake driver `create` called 0 times |
| J4 | Job retried after the mint committed | No second mint, same token kept |
| J5 | PATCH in jobs mode | 200, no driver call |
| J6 | Volumes in jobs mode | Still 422 (regression) |

All J cases are hermetic.

### 12.6 DNS (round 4)

| Id | Setup | Expected | Layer |
|---|---|---|---|
| D1 | Sink receives an A query over udp and over tcp | REFUSED, nothing forwarded, the name never logged | H |
| D2 | `build_host_config`: runc on the egress net with the sink set | `dns == [sink]`. gVisor and Kata unchanged. Open net unchanged | H |
| D3 | runc container on `sf-egress-net` runs `getent hosts example.com` | Fails, sink counter increases, stub upstream receives 0 queries | Dk (Linux) |
| D4 | Same as D3 on the `gvisor` tier | Fails immediately (regression) | Dk (Linux) |
| D5 | Prod probe, runc canary resolves a public name | Reported as a finding | H (fake runner) |
| D6 | `host-setup.sh` dry run | Prints the udp and tcp 53 exception to the sink address only | H |

### 12.7 Compatibility, legacy tokens and warm pool

| Id | Case | Expected |
|---|---|---|
| K1 | v1 `sfe_` token with a claims allowlist, policy URL unset | Allowed per claims, 0 lookups, startup warning logged |
| K2 | v2 token given to the v1 verifier | `InvalidEgressToken` |
| K3 | Old SDK create body with a CIDR string | 201 |
| K4 | Python SDK parses a response with `egress_policy_generation` | No error |
| K5 | v1 token, policy URL set, row generation 0 with the same list | Allowed, one lookup, decided by the row's rules |
| K6 | v1 token whose claims list a host the row does not | That host denied 403, a host in the row allowed |
| K7 | v1 token, row generation 1 (sandbox reset onto v2) | 407. An open v1 tunnel of that sandbox is closed at the next sweep |
| K8 | v1 token, `found: false` (sandbox deleted) | 407. Open v1 tunnels closed at the next sweep |
| K9 | v1 token, policy route answers an unsigned 404 with the URL set | 503, never 407 and never decided by the claims |
| W1 | Allowlisted create | Not eligible for the pool (existing tests stay green) |
| W2 | PATCH that would make a sandbox from the pool restricted | 409 |

All K and W cases are hermetic.

### 12.8 Gate 11 (Linux, real Docker, host rules applied)

Gate 11 is meant to cover the cases gate 8 left out (`docs/egress-allowlist-design.md`,
"Implementation status"). The list below is the plan. `examples/gate11.py` today runs only the
pinned resolution check (P1) and the DNS sink checks (D1, D3), so the other steps are not
automated yet:

1. The `container` tier with allowlist `["example.com", "<A record of example.com resolved on
   the host>/32"]`: an HTTPS fetch of the name succeeds.
2. A CONNECT to the literal succeeds. A CONNECT to another public literal gets 403.
3. Port 22 on the allowed host gets 403.
4. `169.254.169.254` gets 403. `examples/gate11.py` does not check this. The proxy unit test
   `tests/test_egress_proxy_r58.py` covers it for a name that resolves to that address.
5. A direct TCP connect without the proxy fails (host chain). `curl --noproxy '*'` fails.
6. `getent hosts example.com` fails, and the sink counter rises.
7. A PATCH that removes `example.com`: a tunnel held open before the PATCH is closed within
   7 s, and a new CONNECT gets 403.
8. A PATCH that adds `example.org`: it is allowed within 5 s.
9. After a reset, the old token gets 407.
10. Steps 1 to 6 are repeated on `gvisor`.
11. A second run with `SANDFORT_SANDBOX_JOBS_ENABLED=true` on one node passes steps 1 and 7.
12. A legacy sandbox created before the round 3 deploy (v1 token) is reset. Its previous
    token, replayed from the host, gets 407 within 5 s.

## 13. Phased delivery

There are five `cco run` rounds. Each round is one contract, follows the AGENTS.md rules, and
does not change the frozen protocols in `src/sandfort/drivers/base.py`.

Rules shared by every round:

- **Runner gate:** `.venv/bin/python -m pytest -q <listed files>` and
  `.venv/bin/python -m mypy --strict src/sandfort`.
- **Orchestrator checks after each round:** `.venv/bin/ruff check .`,
  `PYTHONPATH=src .venv/bin/lint-imports` and a full `pytest -q`.
- **Every new file stays under 400 lines.**
- **Files already over 400 lines get call-site lines only.** These are `services/sandboxes.py`
  (1179), `config.py` (1011), `api/wiring.py` (573), `drivers/docker/containers.py` (530),
  `services/sandbox_jobs.py` (525), `api/schemas/sandboxes.py` (449),
  `db/repositories/sandboxes.py` (424), `api/routes/sandboxes.py` (402),
  `deploy/host-setup.sh` (584) and the SDK `client.py` (525). Logic goes into new modules.
- **`src/sandfort/egress/proxy.py` (402 lines) must end round 1 under 400** and stay there.
- **Each round updates `CHANGELOG.md`** and this document's "Implementation status".
- **Positioning and marketing copy change only after round 4's gate passes and the CHANGELOG
  is updated** (section 14).

### Round 1: address rules (capability 1, v1 token path)

allowed_files:

- `src/sandfort/domain/egress_entries.py` (new: entry grammar, canonical CIDR, minimum prefix,
  global check, denied overlap. Stdlib only)
- `src/sandfort/domain/sandbox.py` (`check_egress_allowlist` delegates to it, plus an optional
  `denied` parameter)
- `src/sandfort/egress/rules.py` (new: `EgressRules`, literal classification, name and
  address matching, translation prefixes)
- `src/sandfort/egress/upstream.py` (new: resolve, vet and connect, moved out of `proxy.py`,
  plus the literal path)
- `src/sandfort/egress/proxy.py`
- `src/sandfort/egress/proxy_limits.py` (`host_allowed` kept as a wrapper for imports)
- `src/sandfort/services/sandboxes.py` (one call site: pass `egress_denied_cidrs`)
- `src/sandfort/api/schemas/sandboxes.py` (description only)
- `openapi/sandfort.v1.json` (description only)
- `tests/test_egress_rules_v2.py` (new)
- `tests/test_egress_cidr_proxy_v2.py` (new)
- `tests/test_egress_cidr_validation_v2.py` (new)
- `CHANGELOG.md`
- `docs/egress-v2-design.md`

pytest gate:

- `tests/test_egress_rules_v2.py`
- `tests/test_egress_cidr_proxy_v2.py`
- `tests/test_egress_cidr_validation_v2.py`
- `tests/test_egress_proxy.py`
- `tests/test_egress_proxy_r58.py`
- `tests/test_egress_limits_r58.py`
- `tests/test_egress_ports_r63n.py`
- `tests/test_egress_allowlist.py`
- `tests/test_egress_closed_r58.py`
- `tests/test_openapi_contract_r63.py`
- `tests/test_openapi_quality.py`

Covers C1 to C16 and the validation list in section 12.1.

### Round 2: the proxy side of the policy channel (capability 2, first half)

allowed_files:

- `src/sandfort/egress/policy_wire.py` (new: derived keys, request and response MAC, body
  schema)
- `src/sandfort/egress/tokens_v2.py` (new: mint and verify `sfe2_`)
- `src/sandfort/egress/auth.py` (new: credential parsing and v1 or v2 dispatch, moved out of
  `proxy.py`)
- `src/sandfort/egress/policy_client.py` (new: batch lookup, cache, single-flight, staleness,
  newer-request-wins replacement, re-check callback on a changed entry)
- `src/sandfort/egress/admission.py` (new: per-phase budgets of section 4.1.1, the step 11
  re-check, the v1 lookup decision of section 5.5, and registration)
- `src/sandfort/egress/tunnels.py` (new: registry and sweep)
- `src/sandfort/egress/upstream.py` (resolve timeout and connect round budget)
- `src/sandfort/egress/proxy.py` (the single `wait_for` replaced by the request-read timeout)
- `src/sandfort/egress/proxy_limits.py` (policy URL, C, L, M, the `L < C` rule)
- `tests/test_egress_tokens_v2.py` (new)
- `tests/test_egress_policy_wire_v2.py` (new)
- `tests/test_egress_policy_client_v2.py` (new)
- `tests/test_egress_tunnels_v2.py` (new)
- `tests/test_egress_proxy_v2.py` (new)
- `tests/test_egress_admission_v2.py` (new)
- `tests/test_egress_legacy_lookup_v2.py` (new)
- `docs/operations.md` (proxy settings rows, the URL rollout order of section 9.3)
- the internal decisions log (lookup instead of token-carried policy, v1 tokens looked up too)
- `CHANGELOG.md`
- `docs/egress-v2-design.md`

pytest gate: the seven new files, plus `tests/test_egress_proxy.py`,
`tests/test_egress_proxy_r58.py`, `tests/test_egress_tokens_r58.py`,
`tests/test_egress_limits_r58.py` and `tests/test_egress_ports_r63n.py`.

Covers U1 to U16 and P9 against a mock policy route, and K1, K2 and K5 to K9. Nothing mints v2
tokens yet, and deployments leave the policy URL unset until round 3 (section 9.3), so deployed
behavior does not change. That is the "proxies first" step of section 9.3.

### Round 3: server side, PATCH and clients (capability 2, second half)

allowed_files:

- `src/sandfort/migrations/versions/r0027_egress_v2.py` (new)
- `src/sandfort/db/models/sandboxes.py`
- `src/sandfort/db/repositories/sandboxes.py` (mapping lines and the cross-org policy read)
- `src/sandfort/domain/sandbox.py` (two fields)
- `src/sandfort/egress/env.py` (v2 minting, epoch parameter)
- `src/sandfort/services/egress_update.py` (new: PATCH rules, generation, audit note)
- `src/sandfort/services/egress_policy.py` (new: batch read for the route)
- `src/sandfort/services/sandboxes.py` (update keyword argument and call sites, generation 1
  at create)
- `src/sandfort/services/sandbox_jobs.py` (`refresh_egress`: v2 mint, epoch + 1)
- `src/sandfort/api/routes/egress_policy.py` (new, `include_in_schema=False`)
- `src/sandfort/api/app.py` (`include_router` line)
- `src/sandfort/api/routes/sandboxes.py` (pass the field when set)
- `src/sandfort/api/schemas/sandboxes.py` (update field, response field)
- `openapi/sandfort.v1.json`
- `sdk/python/src/sandfort_sdk/egress.py` (new)
- `sdk/python/src/sandfort_sdk/client.py` (attach only)
- `cli/src/sandfort_cli/egress_cmd.py` (new)
- `cli/src/sandfort_cli/main.py` (import line)
- `tests/test_egress_migration_v2.py` (new)
- `tests/test_egress_patch_v2.py` (new)
- `tests/test_egress_policy_route_v2.py` (new)
- `tests/test_egress_mint_v2.py` (new)
- `tests/test_sdk_egress_v2.py` (new)
- `tests/test_cli_egress_v2.py` (new)
- the internal decisions log
- `CHANGELOG.md`
- `docs/egress-v2-design.md`

pytest gate: the six new files, plus `tests/test_api_sandboxes.py`,
`tests/test_egress_create_ttl_r58.py`, `tests/test_egress_remint_r58.py`,
`tests/test_egress_closed_r58.py`, `tests/test_egress_allowlist.py`, `tests/test_sdk_phase3.py`,
`tests/test_cli_phase3.py`, `tests/test_openapi_contract_r63.py`,
`tests/test_openapi_quality.py` and `tests/test_openapi_error_vocabulary.py`.

Covers A1 to A12, U9 end to end, K3 and K4. This is the largest round. If the runner rejects
its size, the SDK and CLI files (four source files and two tests) move to a follow-up contract.
REST is complete without them.

The deploy of round 3 sets `SANDFORT_EGRESS_POLICY_URL` on every proxy in the same step as the
api upgrade (section 9.3). The orchestrator does this on the beta and then runs gate 11 step 12.

### Round 4: controlled DNS (capability 3)

allowed_files:

- `src/sandfort/egress/pinning.py` (new)
- `src/sandfort/egress/dns_sink.py` (new)
- `src/sandfort/egress/upstream.py` (pinned set first, one re-resolution round)
- `src/sandfort/egress/proxy.py` (start the sink when configured)
- `src/sandfort/egress/proxy_limits.py` (pin window, sink listen address)
- `src/sandfort/config.py` (one `Settings` field and its parse line)
- `src/sandfort/drivers/docker/hardening.py` (`dns` for runc on the egress net)
- `src/sandfort/drivers/docker/networks.py` (egress net must be IPv4-only)
- `src/sandfort/drivers/docker/egress_probe_dns.py` (new)
- `src/sandfort/drivers/docker/egress_probe.py` (call site)
- `deploy/egress-dns-sink.sh` (new)
- `deploy/host-setup.sh` (source line and dry-run print)
- `examples/gate11.py` (new)
- `tests/test_egress_pinning_v2.py` (new)
- `tests/test_egress_dns_sink_v2.py` (new)
- `tests/test_hardening_dns_v2.py` (new)
- `tests/test_host_setup_dns_sink_v2.py` (new)
- `tests/test_docker_egress_dns_v2.py` (new, Docker-marked)
- `docs/operations.md`
- `docs/isolation-tiers.md`
- the internal known-issues log
- the internal decisions log
- `CHANGELOG.md`
- `docs/egress-v2-design.md`

pytest gate: the four non-Docker new files, plus `tests/test_host_setup_r58.py`,
`tests/test_host_setup_r59.py`, `tests/test_egress_probe_r58.py`,
`tests/test_docker_networks_r58.py`, `tests/test_hardening_r55.py`,
`tests/test_hardening_phase5.py`, `tests/test_docker_driver_unit.py`,
`tests/test_egress_proxy.py`, `tests/test_egress_proxy_r58.py` and
`tests/test_egress_admission_v2.py`.

Then the orchestrator runs `tests/test_docker_egress_dns_v2.py -m docker` and
`examples/gate11.py` on the beta VM. The known-issues entry (2026-11-04) and the
`isolation-tiers.md` sentence about the `container`-tier side channel change only after D3 and
gate 11 step 6 pass. Otherwise they stay, and the result is recorded.

Covers P1 to P8 and D1 to D6.

### Round 5: jobs mode (capability 4)

allowed_files:

- `src/sandfort/migrations/versions/r0028_node_egress_ready.py` (new)
- `src/sandfort/db/models/nodes.py`
- `src/sandfort/db/repositories/nodes.py`
- `src/sandfort/domain/node.py`
- `src/sandfort/domain/sandbox.py` (`egress_unavailable` in `ERROR_CODES`)
- `src/sandfort/services/node_registry.py` (heartbeat flag, `pick_node(require_egress)`)
- `src/sandfort/services/egress_provision.py` (new: mint before create, or fail)
- `src/sandfort/services/sandbox_jobs.py` (`Lifecycle.spec` labels, provisioning call)
- `src/sandfort/services/sandboxes.py` (remove the jobs refusal, egress-aware `_place`, inline
  mint only, `MountingLifecycle.spec` egress merge removed)
- `src/sandfort/api/wiring.py` (the `NodeRegistry` call site gets the flag)
- `openapi/sandfort.v1.json`
- `tests/test_egress_jobs_v2.py` (new)
- `tests/test_placement_egress_v2.py` (new)
- `docs/operations.md` (remove the refusal sentence, add the requirements in section 7.4)
- `docs/roadmap.md`
- the internal known-issues log
- the internal decisions log
- `CHANGELOG.md`
- `docs/egress-v2-design.md`

pytest gate: the two new files, plus `tests/test_placement.py`, `tests/test_nodes.py`,
`tests/test_egress_remint_r58.py`, `tests/test_egress_allowlist.py`,
`tests/test_egress_create_ttl_r58.py`, `tests/test_api_sandboxes.py` and
`tests/test_openapi_error_vocabulary.py`.

Covers J1 to J6. Gate 11 step 11 is run by the orchestrator.

## 14. Documentation and positioning after delivery

| After | `context/positioning.md` §7 "Egress allowlist je uzak" becomes |
|---|---|
| Round 1 | "Hostnames, leading-dot domains and CIDR ranges (IP-literal targets only, private ranges refused)" |
| Round 3 | "Changeable on a running sandbox (PATCH). New connections follow within 5 s, open tunnels to removed destinations are closed within 7 s (defaults, while the proxy can reach the api). Not possible for sandboxes created without an allowlist or with an empty one" |
| Round 4, gate passed on Linux | The `container`-tier DNS side channel sentence is removed, here and in "Nivoi izolacije na beti" |
| Round 5 | "ne radi u jobs režimu" is removed. The jobs-mode lack of token refresh is added |

These parts of the row stay in every version:

- The proxy-per-hostname framing and the "do not write network firewall or full egress control"
  rule.
- The node-wide port list.
- "Software that ignores the proxy variables has no network."

No competitor egress feature (CIDR, SNI, runtime change, L7) is recorded in positioning §6.
Any comparison needs a new check with a URL and a date first.

## 15. Open questions

1. Minimum CIDR prefixes. Are `/8` and `/32` right, or should they be settings?
2. Should a PATCH that widens the allowlist need its own scope (for example `egress:write`)
   instead of `sandboxes:write`?
3. Should prod require `SANDFORT_EGRESS_DNS_SINK_ADDRESS` (refusing `container`-tier
   allowlisted creates without it) one release after round 4?
4. Should the reset audit row record the new credential epoch?
5. Is an SNI-equals-CONNECT-name check worth adding as optional hardening, given that ECH
   defeats it and the `Host` header stays unchecked?
6. Should the TypeScript SDK's `updateSandbox({ egressAllowlist })` follow-up be scheduled
   right after round 3?
7. When should the proxy stop accepting v1 tokens? A proposal: a dated cutover one release
   after round 3, from which v1 tokens get 407 and legacy sandboxes need a reset to keep
   egress. Until then the lookup of section 5.5 bounds the risk, but only with the policy URL
   set.
8. Should a proxy in the `prod` environment refuse to start without
   `SANDFORT_EGRESS_POLICY_URL` once round 3 is deployed, so v1 tokens can never fall back to
   claims-only decisions?
