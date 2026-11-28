# Security

This page answers the questions a security team asks before a pilot. Each statement is
checked against the server source, `docs/architecture.md`, [operations] or `deploy/`.
Where a protection does not exist, the same section says so. Sandfort is version `0.1.0`
and has no production references; read this page as a description of the code, not as an
assurance.

Paths such as `docs/architecture.md`, `SECURITY.md` and `deploy/` are repository paths, not
published pages: read them in the source repository, the docs site does not serve them.

## 1. Threat model summary

Users and AI agents submit code that Sandfort runs inside sandboxes. That code may be buggy
or hostile. The platform tries to do three things with it:

- keep it contained: one sandbox should not reach the host, the control plane, other
  sandboxes or the platform's secrets;
- keep it resource-bounded: CPU, memory, processes and disk are capped per sandbox (the
  process cap works differently on each tier, see section 2);
- keep the actions around it auditable: lifecycle and toolbox calls are recorded per
  organization.

Hiding the sandbox from the code inside it is not a goal. Code in a sandbox can tell that it
runs in Sandfort and on which tier: gVisor reports its own kernel string, Kata a guest kernel
of its own, and Sandfort adds files, a PID 1 and environment variables of its own (the list is
in [isolation-tiers], "Contained, not hidden"). The tiers contain untrusted code. They do not
make the sandbox undetectable, so Sandfort is not a tool for detonating or analysing evasive
malware that checks for sandbox traces.

The production driver is the Docker driver, and each sandbox runs on one of three isolation
tiers, chosen per sandbox (`isolation` on create). The `container` tier (runc) and the `gvisor`
tier (runsc) share the host kernel: under `gvisor` a user-space kernel handles the sandbox's
system calls, which narrows what reaches the host kernel but is not a hardware boundary. The
`microvm` tier (Kata Containers) gives each sandbox its own guest kernel in a lightweight VM and
needs KVM. On the hosted beta the `microvm` tier runs on nested KVM, and a hypervisor or Kata bug
is in scope for that tier. A kernel or runtime escape from a `container` or `gvisor` sandbox is
therefore in scope for the host, and the controls below reduce that risk without removing it.
The Firecracker driver
in the tree is a skeleton exercised against a mock agent and is not supported
(`src/sandfort/drivers/firecracker/driver.py`).

Tiers are mapped to Docker runtimes by the isolation tier map,
`SANDFORT_ISOLATION_RUNTIMES` (for example `container=runc,gvisor=runsc,microvm=kata`), and the
default tier is `SANDFORT_DEFAULT_ISOLATION`; see [isolation-tiers]. The runtimes must be
installed and registered on each node. Without a map, the only tier is the default one on
`SANDFORT_CONTAINER_RUNTIME` (empty means the daemon's default runtime). In `prod` the server
refuses to start when a configured runtime is not among the daemon's runtimes.

Not covered by this page's protections: a malicious operator or database administrator, a
compromised Docker daemon, and anyone who already holds control of a sandbox node.

## 2. Sandbox isolation as configured by the Docker driver

The container settings are built in `src/sandfort/drivers/docker/hardening.py` and asserted
by unit tests. Every sandbox gets:

| Control | Setting |
|---|---|
| Capabilities | `cap_drop=ALL` |
| Added back | `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID`, `KILL`, `NET_BIND_SERVICE` |
| Privilege | `privileged=False`, `no-new-privileges:true`, `init=True` |
| Processes | `pids_limit=512` (`container`, `microvm`) or 1536 plus an `nproc` ulimit of 512 (`gvisor`), and what they bound differs per tier (see below) |
| CPU | `nano_cpus` from the requested millicores |
| Memory | `mem_limit` from the request, `memswap_limit` equal to it (no swap) |
| Shared memory | `shm_size` is the smaller of 64 MiB and a quarter of memory |
| Open files | `nofile` soft and hard limit 4096 |
| Logs | `local` log driver, 10 MB per file, 3 files |
| Docker socket | not mounted into sandboxes |

What the table does not say:

- **The process limit bounds guest processes on the `container` and `gvisor` tiers (`microvm`
  has none).** On `gvisor` it is an `nproc` ulimit of 512 per uid, and a fork loop stops with
  `EAGAIN` while the sandbox keeps running (measured on the hosted beta on 2026-11-27). On
  `microvm` a fork loop ends the whole VM, not refused at the 513th process (measured
  2026-11-26). The measurement, the caveats, the upstream reasons and the live tests are in
  [isolation-tiers], "Process limits per tier".
- **Seccomp is optional, and two kits set it.** `deploy/seccomp.json` is
  derived from the moby v28.3.3 default profile, with some syscalls removed and extra rules
  on `clone` arguments (see its `_comment`). The driver passes it as a `security_opt` only
  when `SANDFORT_SECCOMP_PROFILE_PATH` points at it. The default is empty, which keeps
  Docker's own default profile. The file is read and validated once at startup.
  - `deploy/k8s/`: the ConfigMap (`configmap.yaml`) sets
    `SANDFORT_SECCOMP_PROFILE_PATH=/etc/sandfort/seccomp/seccomp.json`, and `api.yaml`
    mounts the `sandfort-seccomp` ConfigMap, which kustomize generates from
    `deploy/seccomp.json`, at `/etc/sandfort/seccomp`. Apply the kit with the load
    restrictor lifted (`deploy/k8s/kustomization.yaml`, `deploy/k8s/README.md`).
  - `deploy/selfhost/compose.yml`: sets
    `SANDFORT_SECCOMP_PROFILE_PATH=/etc/sandfort/seccomp/seccomp.json` (line 35) and bind-mounts
    `../seccomp.json` read-only at that path (line 40).
  - `deploy/compose.prod.yml` and `deploy/Dockerfile`: neither sets the path or mounts the
    profile. To use it with compose, add the setting and a bind mount of the file yourself.
  - The driver passes the profile as a security option for every runtime once the path is set
    (`src/sandfort/drivers/docker/hardening.py`): the daemon passes it, but under `runsc` it is
    not applied to the sandboxed processes' syscalls the way `runc` applies it. On the `gvisor`
    tier gVisor's own Sentry filters the syscalls, and the host-side `runsc` processes run
    under gVisor's own seccomp filters ([isolation-tiers]). The Kubernetes kit defaults to
    `gvisor` (`SANDFORT_DEFAULT_ISOLATION`), so the profile there covers the `container` tier.
  - Seccomp does not block `ptrace`. The profile allows it for kernels 4.8 and later, as
    Docker's default profile does (`deploy/seccomp.json`, the rule that names `ptrace`,
    `process_vm_readv` and `process_vm_writev`). A refused trace inside a sandbox comes from
    something else: the dropped capabilities (`CAP_SYS_PTRACE` is not in the add-list above),
    the host's Yama setting on the `container` tier (`kernel.yama.ptrace_scope` was 1 on the beta
    host on 2026-11-26, and Sandfort does not set it), or the runtime boundary on `gvisor` and
    `microvm`.
  - The Kubernetes `api` manifest (`deploy/k8s/api.yaml`) also sets `seccompProfile` to
    `RuntimeDefault` in the pod `securityContext` of the API pod itself. That is a different
    thing from the sandbox profile above: it confines the API process, not the sandboxes.
- **User-namespace remapping and the cgroup parent are opt-in; no AppArmor profile is set.**
  Remapping (`userns-remap`) is a Docker daemon option that is daemon-wide; Sandfort does not
  turn it on, but it reads whether it is active and acts on it. Three server settings
  (`src/sandfort/config.py`): `SANDFORT_USERNS_HOST_TIERS` (default `microvm`; a blank value
  removes the opt-out) lists the tiers created with the host user namespace, because Kata
  cannot run remapped; `SANDFORT_REQUIRE_USERNS_REMAP` (default `false`) makes `prod` refuse
  to start without remapping; `SANDFORT_CGROUP_PARENT` (default empty; must be a systemd slice
  name such as `sandfort.slice`) sets the cgroup parent of every sandbox. Without remapping,
  container root maps to host root for every tier; with it, the tiers not in the opt-out list
  run remapped. Details, validation and the gate texts: `docs/architecture.md`, "Container
  hardening"; node steps in [operations]. The driver sets no AppArmor option, so the
  daemon's default applies where AppArmor is enabled, and no setting feeds the `user` field.
- **Setuid and setgid bits are inert on the `container` tier, and not measured on the
  others.** Every sandbox is created with `no-new-privileges:true` and `cap_drop=ALL` plus the
  add-list above (`NO_NEW_PRIVILEGES` in `src/sandfort/drivers/docker/hardening.py`). Under
  runc the kernel then ignores setuid and setgid bits on exec, and a probe on the `container`
  tier during the hosted beta evaluation showed no change of the effective uid. The `gvisor`
  and `microvm` tiers have not been measured, so this page makes no claim for them. `SETUID`
  and `SETGID` stay in the add-list, so code can still switch its own uid or gid.
- **Disk limits need host support.** The driver sets `storage_opt.size` from `disk_gib`
  when `SANDFORT_ENVIRONMENT=prod`. Docker honours it on `overlay2` over XFS mounted with
  `pquota`, or on btrfs or zfs. The startup check reads `docker info`, which does not show
  mount options, so XFS without `pquota` passes the check and then fails at sandbox create.
  Outside `prod` the driver sets no disk limit unless `SANDFORT_ENFORCE_DISK_QUOTA=true`, which
  enforces it in any environment (the hosted beta uses it; see [isolation-tiers], "Disk
  size").
- **`prod` refuses to start on a weak host.** The startup self-check (`check_isolation` in
  `src/sandfort/api/app.py`) refuses the start when disk quota support is missing, when the
  configured runtime is not registered with the daemon, or when
  `SANDFORT_EGRESS_ACKNOWLEDGED` is not `true`. In `dev` these findings are only logged.
  Two daemon-level findings follow different rules. The user-namespace remapping finding
  refuses a `prod` start only when `SANDFORT_REQUIRE_USERNS_REMAP=true`; with the flag off it
  is logged as a warning (`isolation advisory (does not refuse startup)`), and outside `prod`
  it is logged and tolerated. The default-runtime finding (the daemon default runtime is not
  one of the runtimes the tiers use, so tenant image builds run on it) is advisory in every
  environment: a warning, never a refusal. Both texts are in `docs/architecture.md`,
  "Container hardening".

### Network

All networked sandboxes join the bridge network `sf-net`, created with inter-container
traffic disabled (`enable_icc=false`). Three controls sit on top of that.

- **Cloud metadata and private ranges.** The driver itself does not filter addresses. The
  block comes from `deploy/host-setup.sh`, which installs iptables rules in `DOCKER-USER`
  that reject traffic from the sandbox bridge to `169.254.0.0/16` (including the metadata
  address `169.254.169.254`), `100.64.0.0/10` (carrier-grade NAT space), the Azure wire server
  `168.63.129.16`, and the RFC 1918 ranges. The `100.64.0.0/10` rule covers `100.100.100.0` to
  `100.100.100.255`, so `100.100.100.100` is rejected like any other address in the range. It
  also rejects new connections from sandboxes to the host's own address on the bridge. Without
  the script none of this applies. The egress canary that the driver runs probes
  `169.254.169.254:80`, the bridge gateway on port 22 and `10.255.255.254:80` on every managed
  network, plus `1.1.1.1:443` on the allowlist network (`targets_for` in
  `src/sandfort/drivers/docker/egress_probe.py`). None of these is in `100.64.0.0/10`. With a DNS
  sink configured, one more canary on the allowlist network checks that a public name does not
  resolve (`src/sandfort/drivers/docker/egress_probe_dns.py`).
- **Full block per sandbox.** `network.block_all` at create time runs the sandbox with
  Docker network mode `none`. It takes precedence over everything else, and combining it
  with an egress allowlist is refused.
- **Egress allowlist.** `egress_allowlist` at create time (at most 16 host names by default)
  puts the sandbox on a second bridge, `sf-egress-net`, whose firewall chain admits only the
  egress proxy address (`SF_EGRESS_PROXY`). The proxy is a separate process,
  `python -m sandfort.egress.proxy`, that checks signed tokens made with
  `SANDFORT_EGRESS_SECRET`. If the proxy address or secret is not configured, an allowlisted
  create is refused with 409 and never runs with open egress. When sandboxes are created by
  jobs (multi-node), an allowlisted create goes only to nodes whose heartbeat reports the
  egress stack. Jobs mode has no reset, so the egress token is not refreshed there: an
  allowlisted jobs sandbox that outlives `SANDFORT_EGRESS_TOKEN_TTL_S` (7 days by default)
  loses egress.

Limits of the network controls, stated in `deploy/host-setup.sh` and [operations]:

- The script supports Linux hosts with the iptables backend and a `DOCKER-USER` chain. It
  refuses to run elsewhere, and Docker's nftables firewall backend is not supported. Docker
  Desktop is out of scope.
- The server cannot observe the rules. `prod` relies on the operator setting
  `SANDFORT_EGRESS_ACKNOWLEDGED=true` after running the script. Setting it without running
  the script removes the protection while passing the check.
- IPv6 is filtered only for `fe80::/10` and `fc00::/7`, and only if `ip6tables` exists.
  Public IPv6 destinations are not filtered.
- A sandbox without `block_all` and without an allowlist can reach the public internet. On a
  host where `deploy/host-setup.sh` ran (round 98 or later), each such sandbox address on
  `sf-net` holds at most `SF_SANDBOX_CONN_LIMIT` tracked flows at once (default 512). TCP, UDP
  and ICMP count together, and IPv4 and IPv6 count separately. The next new flow is rejected
  with a TCP reset (`Connection refused`) or ICMP admin-prohibited. Half-open, closing and
  recent UDP flows, DNS included, count until conntrack expires them.
- Image builds on `docker0` and sandboxes on `sf-egress-net` get no host connection cap. The
  egress proxy bounds only concurrent CONNECT tunnels on `sf-egress-net`, not the rate of new
  flows and not DNS packets to the sink, so neither bridge has a host conntrack bound.
- An address that a deleted sandbox used can start with that sandbox's flows still counted,
  for up to the conntrack timeouts (about two minutes for half-open and closing flows).
- The default `SF_EGRESS_PROXY` is `127.0.0.1`, which admits no real destination. Set it to
  the proxy host's address. A proxy on the Docker host itself needs its own INPUT rule.

### Image build runtime

Tenant image builds do not run on a sandbox tier runtime. They run on the Docker daemon's
default runtime, with Docker's default capabilities, no pids limit and no seccomp profile. When
a tier offers a strong runtime (a name containing `runsc` or `kata`) but the daemon default
runtime is not one of them, the capability check reports a build-runtime finding
(`src/sandfort/drivers/docker/capabilities.py`). Nothing is reported while no tier offers a
strong runtime.

- **Production gate.** With `SANDFORT_ENVIRONMENT=prod` and `SANDFORT_REQUIRE_BUILD_RUNTIME`
  on, that finding refuses startup. The setting defaults to `true` when read from the
  environment. Outside prod the finding is a logged warning.
- **Fix.** Set the daemon's `default-runtime` to the strong runtime. Setting
  `SANDFORT_REQUIRE_BUILD_RUNTIME=false` starts the server anyway and accepts that tenant
  builds run with the weaker defaults.

## 3. What is outside the sandbox boundary

- **The Docker socket.** It is never mounted into a sandbox. It is mounted into the server
  pod: `deploy/k8s/api.yaml` mounts `/var/run/docker.sock` and carries a warning that this
  grants host-level control of the node. `deploy/k8s/worker.yaml` is intentionally empty and
  mounts nothing; the supported topology is one pod with `SANDFORT_ROLE=all`. The api
  manifest keeps the pod on a dedicated node with a `nodeSelector`
  (`sandfort.dev/sandbox-node: "true"`) and a matching toleration of the
  `sandfort.dev/sandbox-node=true:NoSchedule` taint. [operations] recommends
  running sandbox workloads on dedicated nodes.
- **Namespace access is node root.** `deploy/k8s/namespace.yaml` sets pod security admission
  to `privileged` for the `sandfort` namespace, because the server pod uses `hostNetwork`
  and a `hostPath` socket. Anyone who is allowed to create pods in the `sandfort` namespace is
  effectively root on the node.
- **Socket holder threat statement.** The socket is never mounted into a sandbox, but any
  code execution in the server process is node root: the process holds the Docker client,
  and the daemon runs as root. Planned mitigations, in order and without dates: a Docker
  daemon authorization plugin next, a node agent later. Neither exists in this repository
  yet, so today the controls are the dedicated node, the namespace access above, and the
  sandbox hardening.
- **Platform environment variables.** Names starting with `SANDFORT_` are reserved. A
  create request that sets one is rejected (422), and the driver rejects them again. The
  server's own settings are not passed to sandboxes, and a test checks that no `SANDFORT_*`
  variable is visible inside one. This protects the server's secrets from sandbox code. It
  does not stop a sandbox from reading anything that was deliberately put into it.
- **Git credentials.** A credential sent with a git call is written to a temporary helper
  for that one operation and removed in a `finally` step
  (`src/sandfort/toolbox/git_credentials.py`). It is not stored, and tests check that the
  token is absent from process environments, audit rows and stored logs.
  - **Any credential handed to a sandbox is disclosed to the code running there.** The
    helper and the git binary both live in the sandbox filesystem. Code in the sandbox can
    read the token while the operation runs, or replace `git` with a program that copies
    the token out. Code can also keep running between calls and wait for the next
    credentialed operation, so one leaked token is not limited to one call. Treat every
    token you send as given to the sandbox code.
  - **Push and pull are bound to the caller's host.** A credentialed push or pull must
    carry `remote_url`. The server reads the repository's remote, refuses with 422
    `UNPROCESSABLE` when its scheme or host differs from `remote_url`, and runs git
    against `remote_url` itself, not the remote name. The helper answers only password
    prompts for that host. A planted remote url or `insteadOf` rule therefore cannot send
    the token to another host through git. This does not protect against the disclosure
    described above.
  - **A snapshot taken during the operation can contain the token.** The helper lives in
    `/tmp/.sandfort-git/`, which is part of the sandbox root filesystem, and a snapshot
    commit (`POST /v1/snapshots/from-sandbox`) pauses the container but copies that
    filesystem as it is. A snapshot committed while a credentialed clone, push or pull is
    running (up to 600 seconds) holds the helper file with the token in it. So does every
    sandbox created from that snapshot and the archive of its export, for as long as the
    snapshot exists. The server does not block this: the commit runs as a background job
    that can run in another process than the git call (for example a `worker` role
    process), so the git call cannot see it. The same holds when removing the helper
    failed. After a successful operation the git call then answers an error and a helper
    may be left behind: 502 `DRIVER_ERROR` for a plain driver failure, and 409, 404 or 504
    when the driver error is a conflict, a missing object or a timeout. After a failed
    operation the failed removal is only written to the server log and the call keeps its
    own error, so the answer does not say that a helper may remain. Do not create a
    snapshot of a sandbox while a credentialed git call on it is running. Wait until the
    call has returned. Treat a snapshot taken during such a call, or after such a call
    that returned any error, as holding the token, delete it, and revoke the token.
  - **Mitigation.** Send only short-lived tokens scoped to the one repository and the
    least permission the operation needs (read-only for clone and pull). Revoke or let
    them expire right after the call. Do not send a credential to a sandbox that runs code
    you would not give that token to. Uncredentialed push and pull by remote name are
    unchanged.
- **Volumes and snapshots.** Their contents are whatever sandbox code wrote. Treat them as
  untrusted data.
- **No encryption at rest beyond the host's.** Sandfort encrypts one thing at rest: webhook
  signing secrets, when `SANDFORT_WEBHOOK_SECRET_KEY` is set (see "Webhook secrets" in
  section 4, `src/sandfort/webhooks/secret_box.py`). Sandbox filesystems, snapshots, volumes,
  command logs and the database are stored the way the host's disk and database store them.
  Use an encrypted disk or volume on the host if you need encryption at rest.

### Preview content

A preview serves whatever the sandbox code answers, so its content is tenant-controlled and
untrusted.

- **Separate origins, same site.** Each preview has its own host,
  `<port>-<sandbox-id>.<preview domain>` (`preview_host` in `src/sandfort/proxy/routing.py`),
  so the browser gives it its own origin, storage and script scope. All previews are still
  same-site with each other and with the other hosts under the same registrable domain,
  unless the preview domain has its own Public Suffix List entry. The hosted beta's preview
  domain has none yet.
- **Cookies reach other previews.** Script in a preview page can set a cookie for the parent
  domain with `document.cookie`, and the browser then sends it to every other preview under
  that domain. The proxy removes `Domain` only from the `Set-Cookie` headers the sandbox
  sends (`strip_cookie_domain` in `src/sandfort/proxy/tokens.py`), which does not stop script
  in the page, and it forwards every cookie except its own token cookie to the app
  (`_request_headers` in `src/sandfort/proxy/app.py`). So one tenant can plant a cookie that
  another tenant's preview app receives. The token cookie is safe from this, because its
  `__Host-` prefix makes browsers refuse a parent-domain cookie of that name. Do not base a
  decision that matters on a cookie value a preview app receives.
- **No CSP or framing headers.** The proxy adds no `Content-Security-Policy`,
  `X-Frame-Options` or `frame-ancestors` to what the app returns. Only the web terminal page
  carries a policy, a `Content-Security-Policy` with `frame-ancestors 'none'`
  (`src/sandfort/proxy/terminal.py`). A default policy would break dev servers and a default
  deny would break embedding, so neither ships. Protection against clickjacking is the app's
  job: set `frame-ancestors` or `X-Frame-Options` in the app itself.

## 4. Control plane

**API keys.** A key has the form `sf_<env>_<prefix8>_<secret43>`, with the secret drawn from
`secrets.token_urlsafe(32)`. The plaintext is returned once. The database stores the lookup
prefix and `v1$<salt>$<HMAC-SHA256(pepper, salt || key)>` with a random salt per key, and
verification is constant-time (`src/sandfort/auth/api_keys.py`). The pepper comes from
`SANDFORT_API_KEY_PEPPER` and is empty by default, so it must be set.

**Scopes and roles.** Each key carries scopes and each route requires scopes; a missing
scope is a 403. Human members have the role `admin`, `developer` or `viewer`, and each role
maps to a set of scopes. Repository methods take `org_id` as a required argument, so
queries are scoped to one organization.

**Key rotation and cascade.** A key records the key that minted it (`created_by`). Revoking a
key (`DELETE /v1/api-keys/{id}`) revokes only that key by default. Its live descendants
(children, grandchildren, and so on) stay valid unless the request sets `cascade=true`, in the
JSON body or the query string. The response always lists those descendants under `dependants`
and carries a `cascade` flag: with `cascade=true` they were just revoked, otherwise they are
still alive. Rotate by minting the new key with the old one, then revoking the old one without
cascade; the new key survives. If you revoke a key because it leaked, use `cascade=true`, or
every key it minted keeps working. The cascade also runs for a key that is already revoked,
to clean up its remaining children. Source: `src/sandfort/services/api_key_admin.py`.

**Child expiry bound.** A key minted by a key that has an `expires_at` must set its own
`expires_at`, and it may not be later than the creator's. Otherwise the create is refused with
422 and `details.max_expires_at` names the bound. A child key therefore never outlives a
creator that expires.

**SSO.** `POST /v1/auth/sso/exchange` verifies an OIDC identity token and returns a signed
session token (`sfs_...`, HMAC-SHA-256 under `SANDFORT_SESSION_SECRET`, at least 32
characters). Its lifetime is configurable between 60 seconds and 24 hours. Verification
accepts RS256 only and checks signature, issuer, audience, expiry, `email_verified`, and a
header type of `JWT`. The key set URL must be `https` (plain `http` only for localhost).
SSO is bound to one organization (`SANDFORT_OIDC_ORG_ID`), and the user must already be a
member.

**SCIM.** Off by default (`SANDFORT_SCIM_ENABLED`). A SCIM token (`sf_scim_...`) belongs to
one organization, is hashed like an API key, is shown once, works only on `/scim/v2`, and
has a `max_role` ceiling: it cannot create or promote a member above that role. An
organization may hold at most 5 active tokens. Tokens do not expire; rotate by minting a
new one and revoking the old one. Removing a member through SCIM does not revoke API keys
that person created earlier.

**Webhook secrets.** A webhook signing secret (`whsec_...`) is shown once and stored encrypted
with a Fernet key (`SANDFORT_WEBHOOK_SECRET_KEY`). Production (`SANDFORT_ENVIRONMENT=prod`)
refuses to start without the key. Outside prod an empty key stores new secrets in plaintext.
Details are in
[the governance page](https://docs.sandfort.dev/governance.html), section "Webhooks". The
repository's security policy, with the reporting
channel and the supported versions, is `SECURITY.md` at the repository root.

**Limits to plan around:**

- **No built-in TLS.** The server runs uvicorn without TLS options (`deploy/Dockerfile`,
  `src/sandfort/main.py`), and the Kubernetes Service is `ClusterIP`. API keys, session
  tokens and sandbox data travel in clear text unless you terminate TLS in front of the API.
- **`/metrics` is open by default.** An optional bearer token (`SANDFORT_METRICS_TOKEN`)
  guards it when set; the runbook says to keep it cluster-internal either way, because the
  token travels in clear text without TLS in front.
- **The node-to-node hop is not encrypted.** With cross-node routing, a request for a
  sandbox on another node is forwarded over plain HTTP. The hop carries a route token
  (HMAC-SHA-256 under `SANDFORT_ROUTING_SECRET`, valid 30 seconds, no principal) that proves
  the sender is a platform node, and the owning node still authenticates the forwarded API
  key. The API key, file contents and command output cross the internal network
  unencrypted, so a private network or an encrypted overlay between nodes is a requirement.
- **No fine-grained revocation for sessions.** Session tokens are stateless and valid
  until they expire; the runbook documents that a removed member's token stops working
  because the membership check fails.
- **No SCIM groups, no per-tenant SSO.** See [operations].
- **Failed authentication is not limited by default.** A well-formed but wrong key costs one
  key lookup by prefix and one HMAC before the 401 (two of each on a toolbox route). Nothing
  counts those failures unless `SANDFORT_AUTH_FAILURE_LIMIT_PER_MINUTE` is set
  (`src/sandfort/api/middleware/auth_failure_limit.py`). The limit counts per client address,
  so behind a proxy it needs `SANDFORT_FORWARDED_ALLOW_IPS` set to that proxy, or one client
  locks out every client behind the same proxy. A caller whose peer address uvicorn trusts for
  `X-Forwarded-For` (every peer under `*`) can set its own forwarded address and is not held
  by it, and a caller with many addresses (an IPv6 prefix, for example) gets a fresh count on
  each. Requests already in flight when an address reaches the limit still run.
  Keys carry 256 random bits, so the limit is about load on the key lookup path, not about
  guessing a key.

## 5. Audit and tamper evidence

The audit log is chained per organization. Each row stores `prev_hash` and
`hash = HMAC-SHA256(key, prev_hash + canonical(row))`, where `key` is
`SANDFORT_AUDIT_CHAIN_KEY` (at least 32 bytes) and the canonical form covers the fixed
fields of the row (`src/sandfort/services/audit_chain.py`). With no key set the hash is plain
`sha256` over the same input; `prod` refuses to start in that state unless
`SANDFORT_UNKEYED_AUDIT_CHAIN_ACKNOWLEDGED=true` accepts the unkeyed chain explicitly. Audit rows are written in the
same transaction as the change they describe. The rule is one event per mutating call, with
named exceptions. A test walks every mutating route the app registers and fails when one has
neither an audited case nor a reasoned exemption (`tests/test_audit_route_coverage_r96.py`).
A call refused after a valid key usually writes a `request.denied` row instead. A create or
start refused for host capacity writes `sandbox.create_refused` or `sandbox.start_refused`, and a
create refused by the key's `max_sandboxes` cap writes `sandbox.create_refused` with `reason`
`key_cap`. Repeats are merged to one row per action, API key and reason per 60 seconds, the
suppressed ones counted in `refusals_coalesced`. Some refusals leave no row: a body that is not
valid JSON, a `RATE_LIMITED` 429, and a missing, malformed or unknown key (see the governance
page). A call that fails after it was accepted adds a failure row (`sandbox.failed`,
`sandbox.reset_failed`). Read (`GET`) calls write no rows, except the few that read sandbox
content. Details are redacted: no request bodies, and `command`, `args`, `cmd`, `stdin`, `code`
and `token` keep only an unsalted `redacted-sha256:` digest and the byte length, so a guessable
value can be confirmed by hashing a guess. Credentials are dropped. A row also stores the
client `ip` and `user_agent`; both are
stored unhashed and are not part of the hash, so they are readable by anyone with `audit:read`.
The full list of actions and the exceptions are on
[the governance page](https://docs.sandfort.dev/governance.html), section Audit.

Two admin commands work on the chain:

```sh
python -m sandfort.admin_cli audit-verify   # re-computes every chain; exit 3 if any row fails
python -m sandfort.admin_cli audit-export   # ndjson with hash fields; --org-id, --output
python -m sandfort.admin_cli audit-verify --head export.ndjson   # also check signed heads
```

`audit-verify` reports a hash mismatch, a broken link or a missing hash, and exits 3 when
there is any finding, so it can run from cron or CI.

Keyed chain. With `SANDFORT_AUDIT_CHAIN_KEY` set, a database writer without the key cannot
recompute the hashes of a rewritten history, so `audit-verify` fails on it. Rows written
before the key was set stay unkeyed. `SANDFORT_AUDIT_CHAIN_ACCEPT_UNKEYED` (default `true`)
lets verify accept and count them, but only before the first keyed row: an unkeyed row after
a keyed one is a finding, and so is a chain whose newest row is unkeyed while the key is
set, whatever the flag says. To migrate: set the key and restart, make one audited write per
org, run `audit-verify` and check it exits 0, then set the flag to `false`. Details are in
[the governance page](https://docs.sandfort.dev/governance.html), section Audit. Hashes read
from the database are compared as bytes in
constant time.

Signed head. With the key set, `audit-export` ends each org's rows with one trailer line of
type `audit_head` (newest row id, its hash, an HMAC over them, and on newer servers the content
binding `row_count`, `first_row_id` and `export_sha256`). Consumers of the export
must skip that line. `audit-verify --head <file>` checks the signature and that the live
chain still reaches the head row, which catches deleting the newest rows.

Ed25519 signature. With `SANDFORT_AUDIT_SIGNING_KEY` set as well, the head also carries `alg`,
`public_key`, `signed_at` (UTC, to the second) and `signature`. The HMAC needs the secret chain
key; the signature needs only the public key, so an auditor with no secret can check it.
`GET /v1/status` (no key needed) publishes `audit_public_key` and `audit_key_fingerprint`
(first 16 hex of sha256 over the raw public key), both `null` unless heads are signed. Pin the
fingerprint out of band, from the release notes or the operator's own channel, not from the
server that is being checked; the `public_key` inside a trailer is not a trust anchor.

`sandfort audit verify-head <file>` checks an export against that key. With a content-bound
head it proves that the signature verifies, that the file is exactly the rows the server signed
(SHA-256, row count and first row), that the last row is the row the head names with the head's
hash, and that each row's `prev_hash` is the hash of the row before it. An edited row then fails
as `content_mismatch` and a removed row as `count_mismatch`. It does not prove that the
database was unchanged before the export, because the server signs the rows it holds at export
time, and an older genuine export still verifies (compare `signed_at`). A legacy head, from an
older server, signs only the last row: it does not prove the rows before it, so a row edited
without touching its hashes passes. Row hashes are keyed, so a client cannot recompute them.
Only the
server-side check (`sandfort audit verify`, `audit-verify`, `GET /v1/audit-events/verify`)
proves the full chain. Details: governance page, section Audit.

The log is tamper-evident, not a guarantee against edits. The key lives outside the database, so
someone with only write access to the audit table cannot forge a consistent history. Someone who
holds the key as well, or any writer while the key is unset (plain SHA-256), can edit rows and
recompute the hashes, and `audit-verify` would then pass. Verification starts from the first row's
stored `prev_hash`, so pruning a prefix by retention is not flagged. To get stronger evidence,
export regularly and keep the exports somewhere the database operators cannot write.

## 6. Operational hardening checklist

Walk this list before a pilot.

- [ ] Run sandboxes on dedicated nodes. The Docker socket gives control of the node.
- [ ] Put a private network or an encrypted overlay between nodes if you use cross-node
      routing, and do not expose `SANDFORT_NODE_INTERNAL_URL` ports to clients.
- [ ] Terminate TLS in front of the API. The server does not.
- [ ] Pin the edge transport policy in the controller instead of relying on its defaults (TLS
      versions with `ssl-protocols`, the HSTS keys, the http to https redirect). See the
      subsection Edge transport policy in `docs/operations.md` for the ConfigMap keys and the
      `curl` and `openssl` probe to run after every controller upgrade and before each release.
- [ ] Keep `/metrics` reachable only from inside the cluster (and set
      `SANDFORT_METRICS_TOKEN` if it must cross a boundary).
- [ ] Use a Docker storage setup that supports disk quotas (`overlay2` on XFS with
      `pquota`) and verify a create succeeds in `prod`.
- [ ] Run `deploy/host-setup.sh` on every sandbox node after the Docker daemon starts and on
      every boot, then set `SANDFORT_EGRESS_ACKNOWLEDGED=true`. Set `SF_EGRESS_PROXY` if you
      use egress allowlists.
- [ ] Decide which isolation tiers to offer and the default: map tiers to runtimes with
      `SANDFORT_ISOLATION_RUNTIMES` (for example `container=runc,gvisor=runsc,microvm=kata`)
      and pick `SANDFORT_DEFAULT_ISOLATION`. Without a map, the only tier runs on
      `SANDFORT_CONTAINER_RUNTIME` (empty is the daemon default). Also decide on the seccomp
      profile (`SANDFORT_SECCOMP_PROFILE_PATH`): the Kubernetes kit sets it, the compose file
      does not, and `runsc` does not enforce it. No runtime map or profile is set by the
      server defaults.
- [ ] Set `SANDFORT_API_KEY_PEPPER`, `SANDFORT_SESSION_SECRET` and the other secrets from a
      secret manager. Never use defaults.
- [ ] Back up the database (`pg_dump`, per the runbook) and store the pepper with it.
- [ ] Keep the pepper stable. Changing it invalidates every API key and every SCIM token.
- [ ] Run `audit-verify` on a schedule and keep `audit-export` files off the database host.

## 7. Reporting a vulnerability

Sandfort is in a design-partner phase. If you suspect a vulnerability, report it privately
to the maintainer and do not open a public issue. `SECURITY.md` at the repository root
states the scope and the supported versions (the latest `v0.1.0-beta.N` tag). Send the report
by email to `office@sandfort.dev`, the public contact address, with "Security" in the subject
and no details in any public place. If you are a design partner, you can use the security or
support contact in your agreement instead. Once the repository is public, GitHub private
vulnerability reporting is an additional channel. There is no published key for
encrypted reports. Sandfort has no certifications: no SOC 2 report, no ISO 27001
certificate and no third-party penetration test.

[isolation-tiers]: https://docs.sandfort.dev/isolation-tiers.html
[operations]: https://docs.sandfort.dev/operations.html
