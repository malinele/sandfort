# Operations runbook

This runbook covers two deployments: Kubernetes (the kit in `deploy/k8s/`) and docker compose
(`deploy/compose.prod.yml`, which the hosted beta VM uses). Sections and commands that apply to
Kubernetes only say so; the `kubectl` commands are Kubernetes-only.

Note on paths: a path in backticks, such as `deploy/k8s/` or `deploy/compose.prod.yml`, is a path in
the repository, not a link on the docs site and not something the server serves.

Placeholders: in a command line, a value you must supply is written in angle brackets
(`--org <org id>`) or as a plain word in capitals (`--operator NAME`), the same way the CLI help
writes it. Curly braces appear only in REST routes (`/v1/api-keys/{key_id}`), where they are the
path templates of the OpenAPI document `openapi/sandfort.v1.json`: replace the braces and the name
with the value.

Manifests live in `deploy/k8s/` (see `deploy/k8s/README.md`). The supported topology is one
dedicated sandbox node running one host-networked pod with `SANDFORT_ROLE=all`: the API, the
background workers and the preview proxy in one process, behind a ClusterIP Service (ports 8000
and 8001), an example Ingress and NetworkPolicy, and example Prometheus alerts. The pod must be
host-networked because the sandbox bridge only admits host-to-sandbox traffic, so a pod on the
cluster network cannot reach sandbox ports (the preview proxy would answer `BAD_GATEWAY`).

The `kubectl` commands below apply to the Kubernetes deployment only. The hosted beta runs under
docker compose on a VM; there the equivalent of a `kubectl logs` command is
`docker compose -f deploy/compose.prod.yml logs api`.

The kit has no separate worker manifest. The `api` role (HTTP without background workers) and
the `worker` role (background workers with only `/healthz` and `/readyz`) are for the
multi-node layout described under "Multi-node" below, which the kit does not cover.

## Supported topology

Sections of this runbook: [Supported topology](#supported-topology) ·
[Prerequisites](#prerequisites) · [Node preparation](#node-preparation) ·
[First deploy](#first-deploy) · [Recovering a lost API key](#recovering-a-lost-api-key-create-key) ·
[Backup](#backup) · [Restore](#restore) ·
[Backup and restore of node data](#backup-and-restore-of-node-data) ·
[Upgrade and rollback](#upgrade-and-rollback) ·
[Monitoring and alerting](#monitoring-and-alerting) ·
[Capacity and sizing](#capacity-and-sizing) · [Multi-node](#multi-node) ·
[Behind a TLS-terminating proxy](#behind-a-tls-terminating-proxy).

One topology is supported and covered by the kit in `deploy/k8s/` (read
`deploy/k8s/README.md` first):

| Part | Where | Notes |
|---|---|---|
| Sandbox node | One dedicated Linux node with Docker (overlay2 on XFS with project quota) and gVisor `runsc` registered; Kata only if you add it | The pod mounts `/var/run/docker.sock`, which gives control of the node, so nothing else is scheduled there. |
| Server | One pod on that node: `hostNetwork: true`, `SANDFORT_ROLE=all`, `replicas: 1`, `strategy: Recreate` | API (8000), preview proxy (8001) and every background worker run in one process. |
| Database | Postgres 16, separate from the node | The only state kept outside the node. Sandbox containers, snapshot images and volumes live on the node (see "Backup and restore of node data"). |

`deploy/compose.prod.yml` runs the same image next to Postgres 16 on one host. It is a
single-host starting point, not the supported production layout, and it differs from the kit in
ways that matter (all read from the file):

- The API container is not host-networked and publishes only `127.0.0.1:8000`. It does not
  enable the preview proxy. A server container on a bridge cannot reach sandbox ports
  (observed 2026-11-03), so run the server host-networked if you need previews.
- It sets `SANDFORT_ENVIRONMENT=prod` (`deploy/compose.prod.yml`). Earlier versions of the file set
  `SANDFORT_ENV=prod` instead; the server reads the production switch only from
  `SANDFORT_ENVIRONMENT` (`dev` or `prod`, `src/sandfort/config.py`) and ignored the old variable,
  so a compose deployment ran without the prod startup checks. With this file the checks are
  active: isolation self-check, egress acknowledgement, webhook secret key and https-only
  webhooks. A compose host that started before now refuses to start until
  `SANDFORT_EGRESS_ACKNOWLEDGED=true`, `SANDFORT_WEBHOOK_SECRET_KEY` and a host that passes the
  self-check are in place.
- It uses the image default command, which runs `alembic upgrade head` and then
  `sandfort-server` (see "Upgrade and rollback").
- It still needs the host steps from "Node preparation" and `deploy/host-setup.sh`.

Multi-node is not the default kit. It needs all of the following (details under "Multi-node"
and "Cross-node toolbox routing"):

- `SANDFORT_SANDBOX_JOBS_ENABLED=true` on every api instance. Jobs mode refuses creates that
  mount volumes or use an egress allowlist, and has no sandbox reset
  (`src/sandfort/services/sandboxes.py`, `src/sandfort/services/sandbox_reset.py`).
- One database shared by every node, and a unique `SANDFORT_NODE_ID` per node.
- For toolbox calls through any api process: the same `SANDFORT_ROUTING_SECRET` (at least 32
  characters) on every node, `SANDFORT_NODE_INTERNAL_URL` on each serving node, and
  synchronized clocks.
- A private network or encrypted overlay between nodes, because the forwarding hop is plain
  HTTP.
- Your own manifests for the `api` and `worker` roles. The kit ships none, and
  `deploy/k8s/worker.yaml` is deliberately empty.

## Prerequisites

- A reachable Postgres 16 database; the URL uses the asyncpg driver, for example
  `postgresql+asyncpg://sandfort:<password>@<host>:5432/sandfort`.
- The image is built from `deploy/Dockerfile` and pushed to a registry. Replace the
  `registry.example.com/sandfort:TAG` placeholder in `api.yaml`.
- The sandbox node exposes `/var/run/docker.sock`. The socket grants host-level control of
  the node, so the node is dedicated: label it `sandfort.dev/sandbox-node=true` and taint it
  `sandfort.dev/sandbox-node=true:NoSchedule` (the Deployment selects and tolerates exactly
  that). Set `supplementalGroups` in `api.yaml` to the socket's group id (default 999).
  Membership of that group (normally `docker`) is root-equivalent on the node: put no human
  account in it unless that person may be root there, and remember that anyone who can
  create pods in the `sandfort` namespace (privileged pod security admission) is
  effectively root on the node as well (`docs/security.md`, section 3).
  `bash deploy/node-setup.sh --check` on the node verifies the prerequisites below (gVisor
  `runsc` registered, overlay2 on XFS with project quota for the disk quota prod enforces),
  prints the group id and the label and taint commands, and changes nothing. Preparing a
  fresh node is described under "Node preparation" below.
- Run `deploy/host-setup.sh` as root on every sandbox node after the Docker daemon starts
  and on every boot (for example a systemd unit ordered `After=docker.service`). It
  rejects sandbox traffic to link-local `169.254.0.0/16` (cloud metadata), `100.64.0.0/10`,
  the Azure wire server `168.63.129.16`, and RFC 1918 ranges, plus IPv6 link-local and
  unique-local ranges when `ip6tables` is present. The server cannot read the rules, but in
  `prod` its egress probe tests them at startup (a canary container on each managed network
  tries to get out) and refuses to start when a target is reachable.
  `SANDFORT_EGRESS_ACKNOWLEDGED=true` is only an override that turns a probe refusal into a
  logged warning.
- The Secret `sandfort-secrets` exists in the `sandfort` namespace:

```sh
kubectl create namespace sandfort
kubectl -n sandfort create secret generic sandfort-secrets \
  --from-literal=SANDFORT_API_KEY_PEPPER="$(openssl rand -hex 32)" \
  --from-literal=SANDFORT_SESSION_SECRET="$(openssl rand -hex 32)" \
  --from-literal=SANDFORT_DATABASE_URL="postgresql+asyncpg://..." \
  --from-literal=SANDFORT_WEBHOOK_SECRET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
```

`SANDFORT_WEBHOOK_SECRET_KEY` is a Fernet key that seals webhook secrets at rest; prod refuses
to start without it. The prod settings (`SANDFORT_ENVIRONMENT=prod`, isolation tiers, seccomp
path, disk quota, node capacity) are in `deploy/k8s/configmap.yaml`; its comments say which
"Production start gate" findings the kit leaves for you to decide (root on runc, build runtime).

Keep the pepper stable: changing it invalidates every issued API key.

## Node preparation

`deploy/node-setup.sh` prepares Docker on a fresh Ubuntu 24.04 sandbox node for the isolation
tiers and the per-sandbox disk quota. Run it as root on the node itself, after installing
Docker Engine (the script does not install Docker). It is a bash script; `sh deploy/node-setup.sh`
re-executes itself under bash. Every step is guarded, so a second run on a prepared node
changes nothing.

```sh
sudo bash deploy/node-setup.sh --dry-run          # print every action and the daemon.json diff
sudo bash deploy/node-setup.sh                    # storage check + gVisor
sudo KATA_SHA256=<sha256> bash deploy/node-setup.sh --with-kata
sudo bash deploy/node-setup.sh --default-runtime-runsc --live-restore --with-slice
sudo bash deploy/node-setup.sh --userns-remap     # maintenance window, see "Daemon settings"
sudo bash deploy/node-setup.sh --rollback
bash deploy/node-setup.sh --check                 # verify only
```

| Flag | Effect |
|---|---|
| `--dry-run` | Prints what each step would do and the `daemon.json` diff; changes nothing. Needs `jq`. A failing storage check is reported and the exit status is still 1. |
| `--with-kata` | Also installs Kata Containers and registers the `kata` runtime. Needs `/dev/kvm` and `KATA_SHA256`. |
| `--default-runtime-runsc` | Merges `"default-runtime": "runsc"` into `daemon.json`, so tenant image builds stop running on plain runc. Applied with a Docker restart (a reload does not apply it). |
| `--userns-remap` | Merges `"userns-remap": "default"`. Moves the daemon data root, so images must be pulled again and existing containers are no longer visible. Applied with a Docker restart. See the procedure under "Daemon settings". |
| `--live-restore` | Merges `"live-restore": true`, so running containers survive a daemon restart. |
| `--with-slice` | Writes `/etc/systemd/system/sandfort.slice` (`SLICE_UNIT` overrides the path), runs `systemctl daemon-reload`, enables and starts the slice. It is the target for `SANDFORT_CGROUP_PARENT=sandfort.slice`. |
| `--rollback` | Restores the `daemon.json` saved before the first change, removes that backup and reloads Docker. Installed binaries (`runsc`, `/opt/kata`) and `sandfort.slice` stay. A `default-runtime` or `userns-remap` key that the restored file no longer has takes effect only after `systemctl restart docker`: the script restarts on its own only when the file it applies sets one of them. |
| `--check` | Verifies storage and the `runsc` runtime; prints the daemon default runtime, whether user-namespace remapping and live-restore are on, the Docker socket group id and the `kubectl label`/`taint` commands. Changes nothing. |

Environment variables: `GVISOR_RELEASE` (default `20261102.0`), `KATA_VERSION` (default
`4.3.1`), `KATA_SHA256` (no default), `NODE_NAME` (Kubernetes node name for the printed
commands; default the hostname).

What the steps do:

1. **Storage.** `/var/lib/docker` (`DOCKER_ROOT` overrides it) must be on XFS mounted with
   `pquota`/`prjquota`. The script never formats or mounts a disk. When the check fails it
   prints how to prepare a data disk (`mkfs.xfs`, an `/etc/fstab` line with
   `defaults,pquota`, mount) and exits 1; run it again afterwards. It then merges
   `"storage-driver": "overlay2"` and `"features": {"containerd-snapshotter": false}` into
   `/etc/docker/daemon.json` with `jq`, keeping existing keys. The original file is saved
   once to `/etc/docker/daemon.json.sandfort-orig` (`{}` when there was none).
2. **gVisor.** Downloads the `runsc` binary of `GVISOR_RELEASE` from
   `https://storage.googleapis.com/gvisor/releases/release/<tag>/<arch>/`, checks it against
   the published `runsc.sha512`, installs it to `/usr/local/bin/runsc` and registers the
   runtime `runsc` with `runtimeArgs ["--overlay2=none", "--file-access=shared"]`.
3. **Kata (optional).** Downloads the official `kata-static-<version>-<arch>.tar.xz` from the
   Kata Containers GitHub releases and refuses to install it unless its sha256 equals
   `KATA_SHA256`, which you must supply from a source you trust. It extracts into `/`
   (`/opt/kata`), links the Rust runtime shim (`runtime-rs`) to
   `/usr/local/bin/containerd-shim-kata-v2`, links the QEMU runtime-rs configuration to
   `/etc/kata-containers/configuration.toml` unless that file already exists, and registers the
   runtime `kata` with `runtimeType` `io.containerd.kata.v2`. `microvm` is Kata on KVM; on a
   virtualized node that means nested KVM (see `docs/isolation-tiers.md` for the measured
   behavior and limits).
4. **Reload and smoke tests.** `systemctl reload docker`. A reload cannot change the storage
   driver or the image store, so when the running daemon differs from `daemon.json` in those
   (a fresh install of a recent Docker may start with the containerd image store) the script warns and
   restarts Docker instead; running containers stop unless `live-restore` is on, and images of
   the previous store become invisible. It also restarts when a reload fails. Then it runs
   `docker run --rm --runtime=runsc alpine:3.20 uname -r` (and the same with `kata`), fails if
   the reported kernel is the host kernel, and prints the storage driver and the registered
   runtimes. When user-namespace remapping is active, the `kata` smoke test runs with
   `--userns=host`, the same opt-out the server applies to the `microvm` tier. The reload step
   restarts Docker (instead of reloading) when the file sets a `default-runtime` or
   `userns-remap` value the running daemon lacks. The final report also prints the daemon
   default runtime, the remap state and the live-restore state.
5. **Rollback.** `--rollback` undoes only `daemon.json`. Storage keys that the restored file
   no longer sets take effect after `systemctl restart docker`.

Afterwards, configure the server for the tiers the node offers (names from
`src/sandfort/config.py`; in the Kubernetes kit they live in `deploy/k8s/configmap.yaml`):

```sh
SANDFORT_ISOLATION_RUNTIMES="container=,gvisor=runsc,microvm=kata"   # drop microvm=kata without Kata
SANDFORT_DEFAULT_ISOLATION=gvisor
```

An empty runtime (`container=`) means the Docker daemon default. Prod checks the default
tier's runtime at startup.

`deploy/node-setup.sh` does not touch the firewall. Run `deploy/host-setup.sh` (sandbox egress
rules) as root after the preparation, and again on every boot, for example from a systemd unit
ordered `After=docker.service`; `deploy/host-setup.sh` rebuilds its chains on each run.
In `prod` the egress probe then checks the result at every start; see "Production start gate".

### Daemon settings beyond node-setup.sh

Three Docker daemon options matter for the hardening described in `docs/architecture.md`
("Container hardening"). `deploy/node-setup.sh` merges each one into `daemon.json` with an
opt-in flag (it keeps any other key you set), and the server reads the result at startup:

| `daemon.json` key | Flag | Why |
|---|---|---|
| `default-runtime`: `"runsc"` | `--default-runtime-runsc` | Image builds (`api.build` in `drivers/docker/build.py`) pass no runtime, so they use the daemon default. With the default `runc`, a build runs its `RUN` steps on plain runc. With `runsc` as default they run under gVisor. |
| `userns-remap`: `"default"` | `--userns-remap` | Maps container root to an unprivileged host uid range. Daemon-wide; see the procedure below. |
| `live-restore`: `true` | `--live-restore` | Keeps containers running while the daemon restarts, which the restarts below need. |

`--with-slice` creates `sandfort.slice` (see the flag table above). `deploy/host-setup.sh`
filters the sandbox bridges `sf-net` and `sf-egress-net` and also the default bridge
`docker0`, where image builds run (`SF_DEFAULT_BRIDGE_IFACE` overrides the interface name):
build containers get the same rejects for link-local, private ranges and host ports. Run it
again after the Docker daemon starts, as for the other bridges.

Server settings that go with them (environment variables of the server process; names,
defaults and validation from `src/sandfort/config.py`):

| Variable | Default | Meaning |
|---|---|---|
| `SANDFORT_CGROUP_PARENT` | empty | Cgroup parent of every sandbox container. Must be a systemd slice name ending in `.slice` (letters, digits, `_`, `.`, `@`, `:`, `-`; no `/`, no `..`, no whitespace); another value fails startup. Use `sandfort.slice` after `--with-slice`. |
| `SANDFORT_USERNS_HOST_TIERS` | `microvm` | Tiers whose containers are created with the host user namespace, because their runtime (Kata) cannot run remapped. Comma-separated tier names; an unknown name fails startup; a blank value removes the opt-out. |
| `SANDFORT_REQUIRE_USERNS_REMAP` | `false` | When `true`, `prod` refuses to start if the daemon has no user-namespace remapping. |

How the startup self-check treats the daemon facts:

- **Remapping finding.** Text: `user-namespace remapping: not active on the daemon (userns-remap in daemon.json); container root maps to host root except for tiers that opt out per container`. With `SANDFORT_REQUIRE_USERNS_REMAP=true` it refuses a `prod` start. With the flag off, `prod` logs it as a warning (`isolation advisory (does not refuse startup)`) at every startup.
- **Default-runtime finding.** Text: `default runtime '<name>' is not among the configured sandbox runtimes [<names>]; tenant image builds run on it (advisory only: logged as a warning, never refuses startup until a separate require flag exists)`. It is advisory in every environment and never refuses a start. It appears when the daemon default runtime is not used by any tier; a tier mapped to an empty runtime counts as the daemon default. Setting `--default-runtime-runsc` while a tier maps to `runsc` clears it.

Two consequences for the tier map:

- With `default-runtime` set to `runsc`, an empty runtime (`container=`) no longer means runc.
  Map the container tier explicitly: `SANDFORT_ISOLATION_RUNTIMES="container=runc,gvisor=runsc,microvm=kata"`
  (`docs/isolation-tiers.md`).
- Legacy single-runtime configuration: with no tier map and `SANDFORT_CONTAINER_RUNTIME` set to
  the Kata runtime, Kata sits on the `container` tier. `container` is not in the default
  `SANDFORT_USERNS_HOST_TIERS`, so on a remapped daemon those sandboxes would stay in the
  remapped user namespace, where Kata cannot run. Set `SANDFORT_USERNS_HOST_TIERS=container`,
  or move Kata to the `microvm` tier with `SANDFORT_ISOLATION_RUNTIMES`.

Enabling user-namespace remapping on a live node is a maintenance window, because the
remapped daemon uses a separate storage directory (`/var/lib/docker/<uid>.<gid>`) and does
not see the existing containers, images or volumes:

1. Announce the window. Sandboxes, snapshots and volumes created before the change are not
   visible afterwards; stop new work first.
2. Preview and apply: `sudo bash deploy/node-setup.sh --dry-run --userns-remap --live-restore`,
   then the same without `--dry-run`. The script restarts Docker because a reload does not
   apply `userns-remap`. By hand, instead:
   `sudo cp -p /etc/docker/daemon.json /etc/docker/daemon.json.pre-userns`, then
   `sudo jq '. + {"userns-remap": "default", "live-restore": true}' /etc/docker/daemon.json.pre-userns | sudo tee /etc/docker/daemon.json`
   and `sudo systemctl restart docker`.
3. Re-pull every image the node needs (base images and anything the snapshots reference).
4. Verify: `docker info --format '{{.SecurityOptions}}'` lists `name=userns`; then create one
   sandbox per tier the node offers (`container`, `gvisor`, and `microvm` if Kata is installed)
   and run a command in each. The `microvm` check is expected to pass: the driver creates
   that tier with the host user namespace (`SANDFORT_USERNS_HOST_TIERS`, default `microvm`),
   which is how Kata runs on a remapped daemon. If it fails, check that the opt-out list was
   not blanked and, in the legacy single-runtime configuration, the note above.
5. Switch the gate on in two steps, so that a missed prerequisite cannot keep the server
   from starting:
   1. Deploy the server with `SANDFORT_REQUIRE_USERNS_REMAP` off (the default). On a node
      that is not remapped, the startup log carries the remapping warning; on a remapped
      node it does not. Check the log and run the one-sandbox-per-tier test above.
   2. When the warning is gone and every tier works, set `SANDFORT_REQUIRE_USERNS_REMAP=true`
      and restart the server. From then on `prod` refuses to start on a daemon without
      remapping.
6. To undo, set `SANDFORT_REQUIRE_USERNS_REMAP` back to `false` first, then restore
   `daemon.json.pre-userns` (or run `deploy/node-setup.sh --rollback`) and restart Docker;
   the pre-change storage directory is untouched.

Break-glass for the planned Docker daemon authorization plugin (not in this repository
yet; the key is `authorization-plugins` in `daemon.json`): if the plugin blocks an
operation you must run, temporarily remove the key from `daemon.json`, `sudo systemctl
restart docker`, do the work, put the key back and restart again. Record the window; while
the plugin is off, the socket is unrestricted node root.

## First deploy

This section is for the Kubernetes kit. On the compose host the `api` container applies
migrations itself when it starts (see "Upgrade and rollback", compose).

1. Run the migrations against the database before rolling anything out, as a one-off pod
   from the same image with the secret's database URL: `python -m sandfort.admin_cli migrate`
   (see "Upgrade and rollback" for a Job sketch). The manifests override the image command,
   so nothing else applies migrations in the kit.
2. Apply the kustomization. The seccomp profile is read from `deploy/seccomp.json`, outside
   the kustomization directory, so lift the load restrictor:
   `kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k8s | kubectl apply -f -`.
3. Watch the rollout: `kubectl -n sandfort rollout status deploy/sandfort-api`.

## Recovering a lost API key: `create-key`

**If the lost key is the bootstrap key or any platform-admin key**, read this first. Only a
platform-admin key can revoke a platform-admin key over the API, so a replacement minted
without `--platform-admin` cannot revoke it. Either mint the replacement with
`create-key --platform-admin`, or revoke the old key from the host with `revoke-key` (below),
which needs no API key at all.

The server stores only a salted hash of each key, so a lost plaintext key cannot be shown
again. Issue a replacement for the existing organisation, then revoke the old key. Run the
command from the same image, with the secret's environment (`SANDFORT_DATABASE_URL` and
`SANDFORT_API_KEY_PEPPER` must be set; the pepper must be the one the server uses, or the new
key will not authenticate):

```sh
python -m sandfort.admin_cli create-key --org-slug acme --name admin-2026-11 > new.key
```

On the compose host (the beta VM), run it inside the running `api` container, which already has
the database URL and the pepper (`-T` turns off the pseudo-terminal, so the redirect receives
the key and nothing else). Set
`umask 077` before the redirect, so the file that receives the plaintext key is created
readable by you alone, and make sure of it with `chmod 600`:

```sh
cd /path/to/sandfort   # the checkout with deploy/compose.prod.yml
( umask 077
  docker compose -f deploy/compose.prod.yml exec -T api \
    python -m sandfort.admin_cli create-key --org-slug acme --name admin-2026-11 > new.key )
chmod 600 new.key
```

- Select the org with `--org-slug` or `--org-id`; give exactly one. An unknown org prints
  `error: unknown organisation <slug>` and exits 1; nothing is written.
- `--name` defaults to `admin`. The replacement key is org-wide (no label scope, no sandbox cap,
  no expiry) and holds the full scope set, whatever the lost key was: if the lost key was
  narrower, the new one is broader. It is a platform-admin key only if you pass
  `--platform-admin`; without the flag it is not.
- The plaintext key goes to stdout exactly once; the two hints go to stderr, as in `create-org`.
  Keep stdout out of shell history and logs.
- The command writes an `api_key.created` audit event in that org (actor type `platform_admin`,
  actor id `sandfort-admin`). The details carry the name, prefix and scopes, never the key.

Then verify the new key before you revoke the old one. A call that needs a scope proves that the
key authenticates with the server's pepper, and the same call lists the org's keys, which gives
you the old key's id:

```sh
export SANDFORT_BASE_URL=https://api.sandfort.dev   # or the partner's own base URL
curl -s -H "Authorization: Bearer $(cat new.key)" "$SANDFORT_BASE_URL/v1/api-keys?status=active"
```

The CLI and the SDK read the same variable: `SANDFORT_BASE_URL` for the server url and
`SANDFORT_API_KEY` for the key, so after the `export` above the CLI works without more setup.

`?status=active` keeps the keys that are neither revoked nor expired; `?status=revoked` lists only
revoked keys, and any other value answers 422.

Caution: `$(cat new.key)` expands into the command line, so the plaintext key is briefly visible
in the process list (`ps`) to other users on a shared host. On such a host keep the key out of
argv: write the header to a file readable by you alone (`umask 077`) and pass it with curl's
`-H @header.txt`, or feed the header on stdin with a here-doc (`curl -H @- ... <<EOF`), then
delete the file.

Only when that answers 200 with the new key in the list, revoke the old key with
`DELETE /v1/api-keys/{key_id}` (repeating the call is a no-op). Use the API with the new key,
which holds the admin scope (if the old key is a platform-admin key, the new key must be one
too; otherwise use `revoke-key` below):

```sh
curl -s -X DELETE -H @header.txt "$SANDFORT_BASE_URL/v1/api-keys/$OLD_KEY_ID"
```

The user CLI has the same call as `sandfort key revoke`, and `sandfort key list` shows the ids.
Both need an authenticating key (the new one), so they cannot help when no working key is left.
`bootstrap` and `create-org` print only the key, never its id, so the id of a lost bootstrap
key comes from the key list (`sandfort key list`, or the `GET /v1/api-keys` call above), or
from `revoke-key --prefix` below.

Here `header.txt` is the header file from the caution above (one line,
`Authorization: Bearer <new key>`).

`OLD_KEY_ID` is the old key's `id` from the list above. Choose it by matching the key's `name` or
`prefix` in that list (the active list) against the lost key: several rows can share a name, and
deleting an already revoked key is a 200 no-op that leaves the real old key live, which is why the
call above filters to `status=active`. Never revoke the key you are authenticating with
(here the new key), and check that the id is not the new key's before you send the `DELETE`.
After you hand the new key over, delete
the transfer file (`shred -u new.key`, or `rm new.key` where `shred` is not installed): it holds
the plaintext key.

If the old key is leaked, not just lost, reverse the order: revoke it first, then mint the new
one, and accept the gap in access. A leaked key that still works is worse than a short outage.
This needs an admin key that still works (any other admin key of the org); if you have none,
revoke the old key from the host with `revoke-key` below, then run `create-key`.

A 401 means the new key does not authenticate (for example the pepper differs from the
server's); do not revoke the old key then, because that would lock the org out.

### Revoking from the host: `revoke-key`

`revoke-key` revokes an API key straight in the database, with no API key. It needs the same
environment as `create-key` (`SANDFORT_DATABASE_URL`, `SANDFORT_API_KEY_PEPPER`), so on the
compose host run it inside the `api` container as shown for `create-key`:

```sh
python -m sandfort.admin_cli revoke-key --org-slug acme --prefix sf_live_ab12cd34
python -m sandfort.admin_cli revoke-key --org-id <org id> --key-id <key id> --cascade
```

- **Org selection.** Give exactly one of `--org-slug` and `--org-id`. An unknown org prints
  `error: unknown organisation <slug>`, exits 1 and changes nothing.
- **Key selection.** Give exactly one of `--key-id` and `--prefix`. The prefix is the key's
  `sf_<env>_<8 characters>`; a pasted whole key is cut down to that. A prefix that matches
  several keys revokes nothing, exits 1 and lists them (id, name, creation time). A blank
  option is a usage error, and an unknown key is `error: unknown api key ...` with exit 1.
- **Already revoked.** Revoking a revoked key is a no-op: it prints `already revoked ...` with
  the time and exits 0, and writes no audit event. With `--cascade` it goes on to revoke the
  key's live descendants.
- **Audit event.** A real revocation writes an `api_key.revoked` audit event in the key's org,
  with actor type `platform_admin` and actor id `sandfort-admin`, the same event the API
  writes. A direct update of `revoked_at` in the database writes none; do not use it.
- **Platform-admin keys.** It can revoke a platform-admin key, the bootstrap key included.
  That is its purpose, since only another platform-admin key can do it over the API. Check
  that another working admin key exists, or mint one first, or you lock yourself out.
- **`--cascade`** also revokes the key's live descendants (the keys it minted), found and
  audited as over the API.
- **Output.** One line on stdout, `revoked <id> name=<name> prefix=<prefix>`. Only the prefix is
  ever echoed: a pasted whole key is cut down to its prefix before any message repeats it, and
  other operator-supplied values are shortened to 32 characters.

## Backup

- Schedule `pg_dump` of the sandfort database (for example nightly, custom format:
  `pg_dump -Fc`), store dumps off-cluster and test restores regularly.
- The dump holds orgs, keys, sandbox records, jobs, audit and metering data.
- NOT in the dump: container state, snapshot images and volume contents. Containers, their
  filesystems and running processes live on the nodes. The reconciler rebuilds the desired
  state from the database and compares it with what the driver reports. What this means for a
  lost node is in "Backup and restore of node data".
- Keep the secret values (pepper, session secret, webhook secret key) in your secret manager.
  Without the pepper restored API keys no longer verify, and SCIM tokens are hashed with it
  too. The webhook secret key is the Fernet key that seals webhook secrets in the database;
  `SANDFORT_EGRESS_SECRET` and `SANDFORT_ROUTING_SECRET` are configuration you set, so keep
  them with the others.

## Restore

1. Scale the Deployment to zero (`kubectl -n sandfort scale deploy/sandfort-api --replicas=0`).
2. Restore the dump into an empty database (`pg_restore --clean --if-exists`).
3. Run `python -m sandfort.admin_cli migrate` with the image you are about to deploy, in case
   the dump predates it.
4. Redeploy (the apply command from "First deploy"; scale back to 1 replica).
5. Let the reconciler converge: it runs at startup and then on its interval, marks
   sandboxes whose container is gone as `error` and removes orphaned containers
   after the grace period (`SANDFORT_ORPHAN_GRACE_S`, default 300).

A dump that is older than the node's current state has a cost. The reconciler removes a
platform container that no sandbox row accounts for, and the garbage collector removes
`sandfort-snapshot:*` images that no snapshot row references and `sf-vol-*` volumes whose row is
gone, both after the same grace period (`src/sandfort/workers/reconciler.py`,
`src/sandfort/workers/gc.py`). Sandboxes, snapshots and volumes created after the dump are
therefore deleted from the node, with their data, a few minutes after the restored server
starts. Copy out anything you need (see below) before you start the server on a restored
database.

## Backup and restore of node data

The database backup records what should exist. Three kinds of data live on the sandbox node
and are in no database dump:

| Data | Where it lives |
|---|---|
| Sandbox filesystems | The writable layer of each sandbox's Docker container, in Docker's data directory (`/var/lib/docker` by default). |
| Committed snapshots and built images | Local images tagged `sandfort-snapshot:<snapshot id>` in the node's Docker image store. A snapshot committed from a sandbox and an image-builder result are both written there (`snapshot_image_reference` in `src/sandfort/services/snapshots.py`). |
| Volumes | Docker named volumes whose names start with `sf-vol-` (`src/sandfort/services/volumes.py`). |

No background worker backs up any of this, and the server has no restore step for it. What a
loss of the node (or of its Docker data directory) means, with Postgres intact:

- **Sandbox filesystems and running processes are gone.** The reconciler moves a `started`
  row whose container is gone to `error`, and `error` leads to `destroying`. Its documented
  repairs do not include a `stopped` row whose container is gone, so treat those sandboxes as
  lost and delete them through the API.
- **Snapshot rows survive, their images do not.** A create from such a snapshot asks Docker
  for `sandfort-snapshot:<id>`, finds nothing, tries a registry pull, and answers a not-found
  ("no such image or snapshot", `src/sandfort/drivers/docker/containers.py`). Delete those
  snapshot rows or restore the images.
- **Volume rows survive, their contents do not.** A create that mounts a volume whose Docker
  volume is missing is refused with "volume ... does not exist"; it is not given a blank one.
- Organizations, API keys, quotas, audit, usage and webhooks are unaffected: they are in
  Postgres.

Options, all manual and none provided by Sandfort. The commands are standard Docker usage
and are not exercised by this repository's tests:

1. **Snapshot images.** For each snapshot you must keep, save its image and store it off the
   node. Either download it through the API (`GET /v1/snapshots/{id}/export`, see "Snapshot
   export"; the tar loads with `docker load`), or on the node:
   `docker save sandfort-snapshot:<snapshot id> | gzip > <snapshot id>.tar.gz`. On a
   replacement node, `gunzip -c <snapshot id>.tar.gz | docker load` restores the image under
   the same tag. List the candidates with `docker images sandfort-snapshot`.
2. **Volumes.** Stop the sandboxes that mount the volume, then archive it from a throwaway
   container, for example
   `docker run --rm -v <volume name>:/data:ro -v "$PWD":/backup alpine tar czf /backup/<volume name>.tgz -C /data .`.
   To restore, `docker volume create <volume name>` under the same name and untar into it. The
   server checks only that the named volume exists. A volume created by hand lacks the
   platform labels, which the garbage collector and the inventory key on, so copy them from
   `docker volume inspect` of a live volume if you want it managed.
3. **Sandbox filesystems.** There is no supported export. Take a snapshot through the API
   for each sandbox whose state matters, then save that image as in option 1. The snapshot
   commit lands on the same node, so it protects against a lost sandbox, not a lost node,
   until you save it elsewhere.
4. **Whole node.** A block-level copy of the volume that holds `/var/lib/docker`, taken while
   Docker is stopped, is the only way to capture everything at once. This repository has not
   tested restoring one.

Before running `deploy/node-setup.sh` on a node that already has data, back up first: if the
daemon's storage driver or image store differs from `daemon.json`, the script restarts Docker
and the images of the previous store become invisible (see "Node preparation").

Rebuilding a node: run `deploy/node-setup.sh`, `deploy/host-setup.sh`, label and taint the
node, load the saved images and volumes, then start the server. `api.yaml` takes
`SANDFORT_NODE_ID` from the Kubernetes node name, and the registry keeps the old node's row
(it shows `stale` in `GET /v1/nodes`). What a vanished node id does to existing rows has not
been verified, so reuse the old node name when you can.

## Upgrade and rollback

Where migrations run depends on how the server is started:

- **Kubernetes kit:** `api.yaml` overrides the container command with
  `python -c "from sandfort.main import main; main()"`, so the pod does not migrate on start.
  Migrations are a deliberate step before the rollout.
- **Compose file, or `docker run` of the image without a command:** the image default is
  `sh -c "alembic upgrade head && exec sandfort-server --host 0.0.0.0 --port 8000"`
  (`deploy/Dockerfile`), so every container start applies pending migrations.

The migrate admin command is `python -m sandfort.admin_cli migrate` (optional
`--revision`, default `head`). It reads `SANDFORT_DATABASE_URL`, maps the asyncpg URL to a
synchronous driver (the image carries `psycopg` for this), prints `database upgraded to head`
on stderr and exits non-zero on failure. `sandfort-admin` is not installed as a console script
(`pyproject.toml` defines only `sandfort-server`).

Upgrade, Kubernetes kit:

1. Write the deploy notice and wait at least two minutes before the restart, so partners who
   poll `GET /v1/status` see it first (see "Deploy notice practice").
2. Take a database backup: `pg_dump -Fc` (see "Backup"). Keep it until the upgrade is
   verified. It is your only rollback.
3. Build and push the new image, then bump the tag in `api.yaml` or pin it in
   `kustomization.yaml`.
4. Run the migrations with the new image, as a one-off Job on any node that can reach
   Postgres. A sketch (not run as part of writing this runbook; the Secret keys are the
   `SANDFORT_*` variable names, so `envFrom` exposes them directly):

   ```yaml
   apiVersion: batch/v1
   kind: Job
   metadata: {name: sandfort-migrate, namespace: sandfort}
   spec:
     backoffLimit: 0
     template:
       spec:
         restartPolicy: Never
         containers:
           - name: migrate
             image: registry.example.com/sandfort:NEWTAG
             command: ["python", "-m", "sandfort.admin_cli", "migrate"]
             envFrom: [{secretRef: {name: sandfort-secrets}}]
   ```

   Wait for it to complete (`kubectl -n sandfort wait --for=condition=complete job/sandfort-migrate`),
   read its log, then delete it.
5. Roll the pod: `kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k8s | kubectl apply -f -`
   and `kubectl -n sandfort rollout status deploy/sandfort-api`. The Deployment uses
   `Recreate`, so the old pod stops (up to its 30 second grace period) before the new one
   starts; the API is unavailable in between.
6. Verify: the rollout finishes only when `/readyz` passes (it checks the database and the
   Docker driver); `curl -fsS http://<node>:8000/readyz` shows `ready`; `GET /v1/nodes` lists
   the node with `"stale": false`; the logs show no startup error.

Upgrade, compose: first write the deploy notice and wait at least two minutes before the
restart (see "Deploy notice practice"). Then back up, rebuild with the new image
(`docker compose -f deploy/compose.prod.yml up -d --build`). The `api` container migrates on
start; read its log for `alembic` errors before you trust it.

Rollback:

- Migrations are forward-only. Each revision file defines a `downgrade()`, but downgrades are
  not part of the supported procedure. The supported rollback is a restore.
- Procedure: scale the Deployment to zero; restore the pre-upgrade dump into an empty database
  (steps 1 and 2 of "Restore"); re-apply the previous image tag; scale back to one replica.
  This is downtime, and every change made after the dump is lost, including the sandbox
  records. Read the warning under "Restore": sandboxes created after the dump are deleted
  from the node after the grace period.
- Running an old server against a newer schema is not supported. The server does not check
  the schema revision at startup (no such check exists in `src/`), so an old image would not
  refuse to start; its behavior against columns or tables it does not know is undefined.
  Never roll back by only re-applying the old tag after the migration has run.
- If the migration itself fails, do not start the new image. Read the error, check the
  revision in the `alembic_version` table, and restore the dump if the schema is in doubt.

Revisions `0017` and `0018` each add one nullable `Text` column to `sandboxes`: `snapshot`
(the snapshot id or image reference a sandbox was created from) and `error_code` (the
machine-readable code next to `error_reason`). Neither needs a backfill: `NULL` is a valid value.
Existing sandboxes keep `snapshot` `NULL`, and an `error` recorded before `0018` keeps `error_code`
`NULL`. Both migrations have a downgrade that drops the column
(`src/sandfort/migrations/versions/r0017_sandbox_snapshot.py`, `r0018_sandbox_error_code.py`).
As above, restoring the dump is the rollback; do not rely on a downgrade of a database that has
served traffic.

Revision `0019` creates the index `ix_audit_events_org_id_request_id` on
`audit_events (org_id, request_id)`, which serves the `request_id` filter of the audit routes; it
changes no rows and needs no backfill. Its downgrade drops the index
(`src/sandfort/migrations/versions/r0019_audit_request_id_index.py`). It is applied by the same
`alembic upgrade head` step as the other revisions; the upgrade procedure above is unchanged.

Revision `0020` adds one nullable `Text` column to `sandboxes`, `stop_cause`. `NULL` is a valid
value and nothing is backfilled: a sandbox that was `stopping` or `stopped` when the migration ran
keeps `NULL`, and the API shows `unknown` for it (see "Sandbox `stop_cause` values"). Its downgrade
drops the column (`src/sandfort/migrations/versions/r0020_sandbox_stop_cause.py`). As above,
restoring the dump is the rollback.

## Monitoring and alerting

### Metrics the server exports

`GET /metrics` on the api (Prometheus text format, no authentication: keep it cluster-internal,
as `deploy/k8s/ingress.yaml` does). The registry holds exactly the catalog below
(`src/sandfort/observability/metrics.py`); there are no process or GC collectors, so node CPU,
memory and disk come from your node exporter. Names are an operator contract: renaming one is a
breaking change that a snapshot test catches. Each process exports its own counters, so with
several processes scrape each one.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sandfort_http_requests_total` | counter | `method`, `route`, `status` | HTTP requests served. `route` is the route template, so `/readyz` appears as `route="/readyz"`. |
| `sandfort_http_request_seconds` | histogram | `method`, `route` | HTTP request duration. |
| `sandfort_sandbox_creates_total` | counter | `outcome` (`ok`, `error`, `cancelled`) | Driver create calls (sandbox provisioning attempts). |
| `sandfort_jobs_processed_total` | counter | `kind`, `outcome` | Job handler executions. |
| `sandfort_jobs_queue_depth` | gauge | none | Jobs in the `queued` state, sampled at scrape time. Stays 0 while lifecycle commands run inline (the kit's default). |
| `sandfort_driver_calls_total` | counter | `operation`, `outcome` | Driver calls by operation. |
| `sandfort_driver_call_seconds` | histogram | `operation` | Driver call duration. |
| `sandfort_webhook_deliveries_total` | counter | `outcome` (`delivered`, `retrying`, `failed`, `disabled`) | Delivery states the dispatcher records. |

Not exported: sandbox counts by state, node capacity, Docker thread-lane saturation (see
"Docker driver threads and shutdown"), node heartbeats, audit-chain health and disk usage.

### Example alert rules

`deploy/k8s/prometheusrule.yaml` ships six example alerts for the Prometheus Operator; it
is in `kustomization.yaml`, so remove it there if the CRD is not installed. Thresholds are
starting points. Your Prometheus `ruleSelector` may need extra labels on the object. Scraping
is not part of the kit: point a ServiceMonitor or scrape job at the `sandfort-api` Service,
port `http`, path `/metrics`.

| Alert | Fires when | Severity |
|---|---|---|
| `SandfortReadyzFailing` | `/readyz` returned 5xx for 5 minutes (database or Docker driver unreachable) | critical |
| `SandfortMetricsAbsent` | no `sandfort_http_requests_total` series for 10 minutes (pod down or not scraped) | critical |
| `SandfortHigh5xxRate` | more than 5% of non-`/readyz` requests were 5xx over 10 minutes | warning |
| `SandfortRequestLatencyP95High` | p95 request duration above 2 s for 10 minutes, excluding `/healthz`, `/readyz` and `/metrics` | warning |
| `SandfortJobsQueueGrowing` | at least 10 jobs queued continuously for 10 minutes (meaningful only with `SANDFORT_SANDBOX_JOBS_ENABLED=true`) | warning |
| `SandfortSandboxCreateFailures` | three or more failed driver creates in 10 minutes | warning |

`SandfortReadyzFailing` counts requests, so it relies on the kubelet readiness probe calling
`/readyz`, which it does in the kit. Streaming and long exec routes can dominate the latency
tail; exclude them with a route regex once you know which templates your clients use.

### What to watch outside metrics

| Signal | How | Why metrics miss it |
|---|---|---|
| Node heartbeats | `GET /v1/nodes` (scope `org:read`) lists each node with `state`, `max_sandboxes`, `running_sandboxes` (the started sandboxes of the caller's org on that node, not the host-wide load), `last_heartbeat_at` and `stale`. A node is `stale` after 90 seconds without a heartbeat (heartbeat every `SANDFORT_NODE_HEARTBEAT_INTERVAL_S`, default 15). Poll it and alert on `stale: true`, for example `curl -fsS -H "Authorization: Bearer $KEY" $URL/v1/nodes` and test `.data[].stale`. | No metric carries heartbeats. |
| Audit chain | A cron job or Kubernetes CronJob around `python -m sandfort.admin_cli audit-verify` (from the image, with the secret's environment). Exit 0 means every row verified; **exit 3 means a finding**; exit 1 means the check could not run (database error). Alert on any non-zero exit. | The check is a command, not a metric. |
| Docker daemon health | `/readyz` returns 503 with `details.component` = `driver` when the driver cannot list its containers. Also watch the daemon on the node itself (`systemctl is-active docker`, your node exporter). | The readiness alert tells you the driver is unreachable, not why. |
| Disk usage of the XFS volume | Alert on free space and inodes of the filesystem holding `/var/lib/docker` with your node exporter. | See below. |

On disk: each sandbox has a project quota, but the host-capacity guard counts only CPU and
memory (`src/sandfort/services/admission.py`). The sum of quotas, stopped sandboxes (their
layers stay on disk), snapshot images, built images and the image cache can exceed the volume
without the server refusing anything.

`audit-verify` caveat: a deployment that ran Postgres before commit `6fe71aa` may report
`link_broken` findings from concurrent audit appends that forked the chain (no row was altered,
so no `hash_mismatch`). Those findings stay in the chain and keep being reported
Establish what the current baseline is before you alert on exit 3.
Verification starts from the first row's stored `prev_hash`, so rows pruned by
`SANDFORT_AUDIT_RETENTION_DAYS` are not flagged (`docs/security.md` §5).

### Keyed audit chain and the export head

Without a key the chain is a plain SHA-256 hash chain, so anyone who can write the database can
rewrite history and recompute every hash. A key closes that gap. Both settings are read by the
server, `audit-verify` and `audit-export` (`src/sandfort/config.py`,
`src/sandfort/services/audit_chain.py`); the signing key is the third (next section):

| Variable | Default | Meaning |
|---|---|---|
| `SANDFORT_AUDIT_CHAIN_KEY` | empty | HMAC key of the chain, at least 32 bytes (a shorter value fails settings load, so the process does not start). Each new row hash is `HMAC-SHA256(key, prev_hash + canonical(row))`. In `prod` an empty key does not refuse the start; it logs a warning at every start and keeps the unkeyed chain. Keep it in the secret store with the other server secrets and keep it stable: the verifier recomputes keyed rows with the configured key, so a different key cannot reproduce the stored hashes. |
| `SANDFORT_AUDIT_SIGNING_KEY` | empty | Ed25519 key that signs heads; needs the chain key. |
| `SANDFORT_AUDIT_CHAIN_ACCEPT_UNKEYED` | `true` | With a key set, `audit-verify` still accepts unkeyed rows written before the key existed, and prints `(N unkeyed row(s) accepted)`. Only rows before an org's first keyed row qualify: an unkeyed row after a keyed one is a finding. With `false`, every unkeyed row in a keyed chain is a finding. |

Setting a key on an existing deployment does not rewrite old rows; they stay unkeyed and are
accepted under the default. Run `audit-verify` before and after the change and compare.

**Export head.** With the key set, `audit-export` follows each organization's rows with one
signed head line: the last row id, its hash and an HMAC over both. Without the key it writes no
head lines. Keep the export file away from the database host (object storage with retention, for
example). Later, `python -m sandfort.admin_cli audit-verify --head <export file>` checks that the
live chain still reaches every head. That catches truncation of the newest rows, which a chain
alone cannot show, because a shortened chain is still internally consistent. A head line whose
HMAC does not verify, or one the live chain no longer reaches, is a finding and exits 3.
`--head` needs the key: without `SANDFORT_AUDIT_CHAIN_KEY` the command exits 1. A head only
covers the rows up to the moment of the export, so export on a schedule if you rely on it.
The HMAC can only be checked with the secret chain key. To let someone without that key check
an export, also set `SANDFORT_AUDIT_SIGNING_KEY` (next section); the head then carries an
Ed25519 signature.

**REST export trailer.** `GET /v1/audit-events/export` also ends with one trailer line, which
has no `id` field. It is the same `audit_head` line as the operator export writes (signed
when the signing key is set) when the server has the chain key and the export holds at least
one row (`src/sandfort/api/routes/audit.py`, `_export_lines`). The head names the last row of
that export and binds its content (`row_count`, `first_row_id`, `export_sha256`); with a
`request_id` or `outcome` filter it is marked `filtered: true`. An empty export, or a server
without the chain key, ends in an `export_summary` line (`rows`, the row count, and `filters`,
the filter names), which names no row and is not signed. The operator `audit-export` already carried the signed head line. A consumer that
parses each line as a row must skip the last line.

### Signing the audit export

With `SANDFORT_AUDIT_SIGNING_KEY` set, every `audit_head` line also carries an Ed25519
signature: `alg` (`ed25519`), `public_key`, `signed_at` (UTC, to the second) and `signature`.
The chain key stays secret on the server. The signature can be checked with the public key
alone, so a customer or auditor can verify an export without any secret
(`src/sandfort/audit_signing.py`, `src/sandfort/services/audit_chain_head.py`). The rule for
reviewers is in `docs/governance.md`, section Audit.

**Generate a key.** The value is an Ed25519 private key in one of two forms: 32 raw bytes in
urlsafe base64, or a PEM block (PKCS#8, no passphrase). Any 32 random bytes are a valid Ed25519
key, so this writes a raw key to a file that only you can read, and prints nothing:

```bash
(umask 077; python3 -c "import os,base64 as b;print(b.urlsafe_b64encode(os.urandom(32)).decode())" \
  > audit-signing.key)
```

The `umask` makes the file mode 600 from the moment it exists. For a PEM key, with OpenSSL
1.1.1 or later: `(umask 077; openssl genpkey -algorithm ed25519 -out audit-signing.pem)`. The
`openssl` that macOS ships is LibreSSL and cannot generate Ed25519 keys: on a Mac use OpenSSL
from Homebrew, or the `python3` command above. In an environment variable a PEM value may
keep real newlines or use the two characters `\n`.
A value that is neither form fails the settings load (the message names the formats, never the
value), so the process does not start.

**Where to put it.** Next to `SANDFORT_AUDIT_CHAIN_KEY`: in the secret store, as an environment
variable of every `api` process (the REST export and `GET /v1/status` read it there) and of
the shell that runs `audit-export`, `audit-verify` and `doctor`. In the Kubernetes kit that is
the `sandfort-secrets` Secret. Keep it out of the database and out of backups of the database.
Restart the processes after setting it. Do not commit the key file.

On Kubernetes the keys must reach the API pod. `deploy/k8s/api.yaml` wires
`SANDFORT_AUDIT_CHAIN_KEY` and `SANDFORT_AUDIT_SIGNING_KEY` from `sandfort-secrets` as
optional `secretKeyRef` entries (`optional: true`), so a cluster without these keys still
starts. Adding the keys to the Secret is not enough on its own: the Deployment must carry the
entries, and the pods must restart to read them. Check with `doctor` (the `audit keys` row)
and `GET /v1/status` (`audit_public_key` is not `null`).

**It depends on the chain key.** A signing key without `SANDFORT_AUDIT_CHAIN_KEY` signs
nothing, because the head line only exists when the chain is keyed. In `prod` the server
refuses to start with that combination; elsewhere it starts with a warning. Set the chain key
first (see the migration steps in `docs/governance.md`), then the signing key.

**Rotation and loss.** The chain hashes do not depend on the signing key, so replacing or
losing it invalidates no row. Heads signed with the old key verify only against the old public
key (`verify-head` reports `key_mismatch` for another key), so keep the public key of every key
you retire next to the exports it signed.

**What `doctor` reports.** The `audit keys` row of `python -m sandfort.admin_cli doctor`
judges both keys and never prints key material:

- Both keys set: `PASS`, `audit heads are signed; signing key fingerprint <16 hex>`.
- Signing key without chain key: `FAIL` where the start refuses it (`prod`), else `WARN`. The
  detail says the signing key needs the chain key.
- Chain key only: `WARN`, exports are HMAC-chained but unsigned.
- Neither key: `WARN`, the audit chain is an unkeyed hash and exports are unsigned.
- Malformed signing key: `FAIL`, with the formats the key may take.

A malformed key is already refused when the settings load, so in practice `doctor` prints that
error on stderr and exits 1. The fingerprint is the first 16 hex characters of the sha256 of
the raw public key. `sandfort audit export` prints the same fingerprint on stderr, and
`sandfort audit verify-head` prints it as `fingerprint`, so the three can be compared.

**How a customer verifies an export.** The customer needs an organization-wide API key with
`audit:read` and the `sandfort` CLI:

1. Pin the public key once, from a source you trust. `GET /v1/status` returns it as
   `data.audit_public_key` and its fingerprint as `data.audit_key_fingerprint`; both are
   published only while heads are signed (`null` otherwise). Pin the fingerprint out of band:
   take it from the release notes or the operator's own channel, or from their `doctor`
   `audit keys` row, never only from the server being checked. Compare it with the
   `fingerprint` that `verify-head` prints (also on stderr after `sandfort audit export`).
2. Export. Every non-empty export ends in a signed head; one cut by `request_id` or `outcome` is
   marked `filtered`, and `verify-head` then skips the neighbour-linkage check. An empty
   export ends with an unsigned `export_summary` line instead:

   ```bash
   sandfort audit export --output audit.ndjson
   ```

3. Check the file against the pinned key:

   ```bash
   sandfort audit verify-head audit.ndjson --public-key "$AUDIT_PUBLIC_KEY"
   ```

   Without `--public-key` the key comes from `audit_public_key` of the server's status (fetched
   without credentials), which proves the file matches that server and nothing more. A later
   export can be checked as a continuation of an earlier one with `--previous <earlier file>`. The key named inside the trailer is
   never trusted on its own.
4. Read the result. Exit 0: the signature verifies, the file's event lines have the SHA-256,
   count and first row the head binds, every row has the head's org, the last row is the row
   the head names with the head's hash, and every row's `prev_hash` is the hash of the row
   before it. Exit 3: a check failed and the reason is printed. The checks run in this order:
   `unsigned`, `signature`, `key_mismatch`, `undated` (a legacy head without a valid
   `signed_at`), `future_signed_at`, `count_mismatch`, `content_mismatch`,
   `first_row_mismatch`, `malformed_row`, `misplaced_trailer`, `org_mismatch`, `truncated`,
   `head_mismatch`, `chain_break`, `unchained_rows` (a row without a hash; `--allow-unchained`
   accepts such rows before the first hashed row) and, with `--previous`, `not_a_continuation`. `no_trailer` replaces them when the file has rows but does not end in a
   usable `audit_head`. Exit 2 is only for a check that cannot run: the file is missing,
   unreadable or empty, it has no valid row and no usable `audit_head` last line, its last
   line is an unsigned `export_summary`, or the key is unusable (not 32 bytes in urlsafe
   base64, or no `--public-key` given and the server publishes none). `--head-only` checks the
   signature alone. The full list is in `docs/governance.md`, section Audit.
5. Run `sandfort audit verify` as well. A head from round 63 on fixes the content of the file
   (a legacy head binds only the last row and the linkage between neighbouring rows). Row
   hashes are keyed, so the customer cannot recompute them, and a server that signs a
   fabricated export passes `verify-head`. An older, genuinely signed export still verifies,
   so check `signed_at`. Only the server-side verification (`sandfort audit verify`, `audit-verify`
   or `GET /v1/audit-events/verify`) proves the full chain.

The operator can check the same file against the live chain with `python -m
sandfort.admin_cli audit-verify --head audit.ndjson --public-key "$AUDIT_PUBLIC_KEY"`; with the
public key an unsigned head or a bad signature is a `head_invalid` finding. A legacy head
without `signed_at` (beta.60 to beta.64) is accepted here, while `verify-head` fails it as
`undated`.

**An unkeyed newest row.** With the chain key set, `audit-verify` reports a chain whose newest
row is unkeyed as a `hash_mismatch` finding and exits 3. It is an alarm: the key was enabled
after the last event, or keyed rows were deleted, and the rows alone cannot say which. Do not
write an event to make it go away. Compare the live chain with an earlier export:
`audit-verify --head <earlier export>`.

### Acknowledging historical audit findings: `audit-reanchor`

Use `audit-reanchor` when an organization's chain has findings you have investigated and accept
as history (the Postgres fork above is the case it exists for), so that `audit-verify` can go
back to alerting only on new breaks:

```
python -m sandfort.admin_cli audit-reanchor --org <org id> --note "forked chain before 6fe71aa, reviewed 2026-11-07" \
  --operator "j.doe" --reason-code incident_acknowledged
```

- `--org` and `--note` are both required. The note is kept in the audit row; it must not be
  empty and is at most 1000 characters (otherwise the command exits 1 with a validation error).
  An unknown organization also exits 1.
- `--operator NAME` and `--reason-code CODE` are optional but go together: giving only one exits
  1 ("--operator and --reason-code must be given together"). The operator is 1 to 255
  characters after trimming. The reason code is one of `incident_acknowledged`, `migration` or
  `other`; any other value is refused by the option parser. Both are stored in the event's
  details next to the note, so the record says who ran the command and why (commit 100d088).
  The name is whatever the person at the console gives, not an authenticated identity (the
  event's actor is `sandfort-admin`). Pass both so the verify reply names them; an event
  written without them reads `null` for both.
- It runs a full verify of that one organization first. With no unacknowledged findings it
  writes nothing and prints `no findings: nothing to re-anchor`.
- Otherwise it appends exactly one chained event, `audit.chain_reanchored` (actor type
  `platform_admin`, actor id `sandfort-admin`, target the org), and prints its id. The details
  hold `acknowledged_through` (the last row with a finding), `findings` (how many), `note` and,
  when given, `operator` and `reason_code`.
- No existing row is changed or removed. Verify now reports the findings on rows up to
  `acknowledged_through` separately and no longer fails on them: `audit-verify` prints
  `ok: N audit rows verified (M acknowledged finding(s))` and exits 0, and
  `GET /v1/audit-events/verify` returns `acknowledged_findings`, `reanchored_by` and the
  `reanchor` object (`event_id`, `operator`, `reason_code`, `acknowledged_through`, `findings`,
  `note`, `occurred_at`); all three are left out while there is no re-anchor. A break after
  that row, or in the re-anchor event itself, still exits 3.
- Only the latest re-anchor event counts, and a re-anchor can only acknowledge rows before
  itself. Run it per organization; it does not touch other organizations.
- The full history, findings included, stays in `audit-export`. See `docs/governance.md` for
  the rule (`src/sandfort/admin_cli.py`, `src/sandfort/services/audit_chain.py`, commit
  d96b196).

### Audit growth and archiving

Every exec, code run, cell and file read writes one audit row, and the rows are kept
indefinitely by design: each row's hash covers the previous one, so the chain is only useful
while it is whole. Nothing prunes the table by default (`SANDFORT_AUDIT_RETENTION_DAYS` is `0`;
see `docs/governance.md` before you change it), so the table only grows. Plan its disk and
backup size from the measured rate, not from a guess.

Measure the growth on Postgres with a count by action per day:

```sql
SELECT date_trunc('day', occurred_at) AS day, action, count(*) AS rows
FROM audit_events
WHERE occurred_at > now() - interval '30 days'
GROUP BY 1, 2
ORDER BY 1 DESC, 3 DESC;
```

Toolbox actions (exec, code run, file reads) usually dominate. `pg_total_relation_size(
'audit_events')` gives the size on disk.

To archive, export first and prove the export is complete, and only then consider any
database-level retention:

1. Export each organization's rows: `sandfort audit export --output audit.ndjson` as an admin
   key, or the operator `python -m sandfort.admin_cli audit-export`. With the chain key set,
   the file ends with a signed head line (see "Keyed audit chain and the export head").
2. Check the file: `sandfort audit verify-head audit.ndjson`, with the pinned `--public-key`
   (see "Signing the audit export"). Run `sandfort audit verify` or `audit-verify` on the live
   chain too.
3. Store the file away from the database host, with the retention your auditors need.
4. Only after steps 1 to 3, decide on retention in the database. Sandfort claims no pruning
   feature: deleting rows yourself breaks the chain at the cut unless the oldest remaining row
   keeps its stored `prev_hash`, and the export is then the only proof of what was removed.

## Capacity and sizing

**No load-tested sizing figure is published.** The repository does not say how many sandboxes
a given node carries, and the example numbers in `deploy/k8s/configmap.yaml` (an 8 vCPU /
16 GiB node: 6000 millicores, 12288 MiB) are labelled conservative examples, not
measurements. Size by measuring your own workload, tier and sandbox shapes.

### Controls that cap a node

All names are read from `SANDFORT_*` by `src/sandfort/config.py`.

| Setting | Default | What it enforces |
|---|---|---|
| `SANDFORT_HOST_CAPACITY_CPU_MILLICORES`, `SANDFORT_HOST_CAPACITY_MEMORY_MIB` | `0` (unguarded) | A create or start whose reservation would push the reserved totals past the capacity is refused with a 503 ("host capacity exhausted"). Disk is not part of this guard. |
| `SANDFORT_HOST_OVERCOMMIT_FACTOR` | `1.0` | Multiplies the capacity above: more than 1 admits more than the host has, less than 1 keeps headroom. |
| `SANDFORT_MAX_SANDBOX_CPU_MILLICORES`, `_MEMORY_MIB`, `_DISK_GIB` | 4000, 8192, 20 | Largest shape one sandbox may request. |
| Org quotas (`PUT /v1/org/quota`) | unlimited | Per-org `max_vcpus`, `max_memory_mib`, `max_disk_gib`, `max_sandboxes`; over the limit is 429 `QUOTA_EXCEEDED`. |
| `SANDFORT_MAX_PTYS_PER_ORG`, `SANDFORT_MAX_ASYNC_COMMANDS_PER_ORG` | 8, 16 | Live terminals and running async commands per org, per process. |
| `SANDFORT_MAX_VOLUME_TRANSFERS_PER_ORG`, `SANDFORT_MAX_VOLUME_TRANSFERS` | 2, 8 | Running volume exports and restores per org and in the process (`0` = no cap); over it is 409 `org_transfer_limit` or `transfer_limit`. |
| `SANDFORT_RATE_LIMIT_REFILL_PER_S`, `SANDFORT_RATE_LIMIT_BURST` | 100, 1000 | Token bucket per API key. |
| `SANDFORT_DOCKER_THREAD_LIMIT`, `SANDFORT_DOCKER_BULK_THREADS` | 64, 48 | Concurrent docker-py calls in the process (see "Docker driver threads and shutdown"). |
| `SANDFORT_VOLUME_MAX_BYTES` | `0` (no limit) | Soft size limit per volume; see below. |

Read these limits as they are implemented:

- **`SANDFORT_VOLUME_MAX_BYTES` is a soft limit, checked at mount time only.** `0` means no
  limit. Volume responses carry `max_bytes` (null when unlimited) and `over_limit`, true when
  the sampled size exceeds the limit. A read-write mount of an over-limit volume is refused
  with 422 `VOLUME_OVER_LIMIT` (details `volume_id`, `size_bytes`, `max_bytes`); a read-only
  mount is allowed. The size is the sampled one, re-sampled through the driver when the last
  sample is older than `SANDFORT_METERING_SAMPLE_INTERVAL_S`. A running sandbox is never
  stopped for filling a volume, and nothing checks the size after the mount.
- **Scratch volumes for image-declared paths.** An image can declare `VOLUME` paths (a snapshot
  of a sandbox with a volume mounted declares its mount path too). For each declared path that
  no requested mount covers, the driver creates a named volume, mounted read-write, instead of
  an anonymous one. These volumes carry the managed label and the sandbox id, are removed with
  the sandbox, and show up in the managed volume listing the reconciler reads. They are named
  `sf-imgvol-*`, not `sf-vol-*`, so the volume GC (which collects `sf-vol-*` only) leaves them
  to the sandbox removal. They live outside `disk_gib`, and the volume limit above does not
  cover them. The sandbox response lists the paths as `image_mounts`.
- **Disk usage (`disk_gib`) is credited for the full started time, like vCPU and memory.**
  The size is sampled every `SANDFORT_METERING_SAMPLE_INTERVAL_S` (a new run is sized within
  about 15 s), and the last sampled size is held as one disk interval per run, from the run's
  start (the first sample covers the time before it). A size change at a tick splits the
  interval. Stop and delete take one final sample first: the size is read from the driver
  before it stops or removes the container (never inside a database transaction) and credited
  in its own short transaction, so a sandbox deleted before its first sample is credited over
  its whole run and a size change since the last tick is credited over the last sample interval
  at most. If the driver cannot answer (container gone, an error), the last sampled size stands
  and a run never sized gets none; error closes the interval at the last sampled size. A run
  that ended before any sample is credited while its container still exists. Reports clip disk
  intervals to the window exactly like vCPU.

- The host guard sums the reservations in the quota ledger. A stopped sandbox releases its
  reservation, so stopped sandboxes do not count toward CPU or memory but still occupy disk.
  The total is read from the whole database (`host_totals` sums every org), so the guard is a
  per-host guard only when one node uses the database.
- **`SANDFORT_NODE_MAX_SANDBOXES` does not refuse creates.** It is published in the node
  registry and shown by `GET /v1/nodes`, and it is read only by node placement, which runs
  only in jobs mode. Placement leaves a node at its cap out of the candidates, and when no
  node qualifies the create lands on the local node anyway (`pick_node` in
  `src/sandfort/services/node_registry.py`). With the kit's defaults (jobs mode off) it caps
  nothing. Use the host capacity settings and org quotas to bound a node.

### Measured facts that exist

- The hosted beta is one VM with 6 vCPU and 24 GiB RAM, shared by all evaluators. QEMU needs
  about 2 GiB of memory above the guest's. On 2026-11-04 the host killed the VM's QEMU for
  exceeding its memory limit during parallel heavy tests (multi-GiB writes and microvm fleets),
  and the beta was down from 15:08 to 15:46. The fix was ops-side: 2 GiB of headroom above the
  guest and a pinned MAC address. Evaluators are asked to keep to about 3 concurrent heavy
  sandboxes on that VM.
- gVisor counts large writes toward the sandbox's memory, and its limits count gVisor's own
  host processes; Kata (`microvm`) uses more memory per sandbox (`docs/isolation-tiers.md`).
  Budget memory for the tier you run, not for the shape you request.
- Latency figures exist for one local macOS host and for the beta VM
  and are single measurements, not capacity or SLO figures.

### A method to size a node

1. **Start capped.** Set `SANDFORT_HOST_CAPACITY_CPU_MILLICORES` and
   `SANDFORT_HOST_CAPACITY_MEMORY_MIB` well below the hardware, leaving room for the OS,
   Docker, the gVisor or QEMU overhead of your tier, and the server pod. Keep
   `SANDFORT_HOST_OVERCOMMIT_FACTOR` at `1.0`. Set per-org quotas.
2. **Measure with the load profile.** `tests/load/test_load_profile.py` creates, runs one
   exec echo round trip in and deletes sandboxes against a real local Docker daemon:
   `SLO_LOAD_SANDBOXES=50 SLO_LOAD_CONCURRENCY=10 .venv/bin/python -m pytest tests/load/test_load_profile.py -m docker -s`
   (defaults 20 and 5; `-s` shows the one summary line). It asserts p95 limits (create 2 s,
   exec 0.4 s, delete 2 s) and is skipped when no daemon is reachable. Know what it is: it
   runs the app in process with SQLite and default settings, so it uses the daemon's default
   runtime, not your tiers or disk quota, and each sandbox is deleted right after its exec.
   It measures daemon and host latency under concurrency. It does not hold sandboxes
   resident, so it says nothing about memory density.
3. **Measure density yourself.** On the target node with its real settings, create sandboxes
   of your representative shape and tier, run your typical workload in them, and watch host
   memory (including Docker, `runsc` and QEMU processes), the XFS volume, and the alerts
   above. Include the heaviest workload you accept, such as multi-GiB writes.
4. **Raise gradually.** Increase the capacity settings in steps, repeat step 3 at each, and
   stop when memory headroom or p95 latency degrades. Keep the last good setting with
   headroom for failure modes you did not test.
5. **Re-measure after changes** to the tier, the shape limits, the isolation runtime or the
   hardware.

## Scaling

- The kit runs exactly one pod (`replicas: 1`, `Recreate`): it binds fixed node ports and
  owns its node's Docker daemon, so do not raise `replicas`. It holds up to pool size plus
  max overflow Postgres connections (10 + 20 by default), so size Postgres
  `max_connections` accordingly.
- Capacity is per node. Bound it with `SANDFORT_HOST_CAPACITY_*` in `configmap.yaml` (see
  "Capacity and sizing" for what each control does and does not enforce); the pod `resources`
  cover only the server process, not the sandbox containers.
- The job runner claims jobs by lease (`lease_owner`, `lease_expires_at`), so several
  workers are safe in a multi-node layout: a job is never run twice concurrently and an
  expired lease is re-claimed. Scaling beyond one node is the "Multi-node" layout below,
  not part of the kit.
- Sandboxes run on the node of the pod that created them.

### Docker driver threads and shutdown

The docker driver runs every docker-py call in a worker thread, in one of two lanes that share
one thread budget. The control lane carries short calls (create, start, stop, inspect, exec
setup). The bulk lane carries calls that wait on a peer or run long: log follows, exec and
terminal output, file uploads and downloads, image pulls, commits and build logs. Both
settings are read per process, so they apply to each `api` and `worker` pod separately.

| Variable | Default | Meaning |
|---|---|---|
| `SANDFORT_DOCKER_THREAD_LIMIT` | 64 | Total worker threads of the driver in this process. |
| `SANDFORT_DOCKER_BULK_THREADS` | 48 | Bulk-lane ceiling inside the total. Integer, at least 1. |

- The bulk ceiling is clamped: the effective value is `min(SANDFORT_DOCKER_BULK_THREADS,
  max(total - 1, 1))`. With the defaults, 16 tokens (64 - 48) can never be taken by bulk calls,
  so `start`, `stop` and `inspect` still run while followers and pulls fill the bulk lane.
  A total of 1 degrades to one shared token, so small configurations stay valid.
- Raising the bulk setting above `total - 1` has no effect; raise the total first. The total
  is also the hard bound: the driver never runs more worker threads than
  `SANDFORT_DOCKER_THREAD_LIMIT`, because a token is freed only when its thread returns.
- A value below 1 is rejected: a bulk value fails at startup with
  `SANDFORT_DOCKER_BULK_THREADS must be at least 1`; a total below 1 fails when the driver is
  built.
- The docker-py connection pool is sized to the total, so the pool is as wide as the thread
  limit. Earlier it stayed at docker-py's default of 10 and extra connections were opened and
  discarded above that.
- When the bulk lane is full, new streams, uploads and pulls wait in order; they are not
  refused. A call stuck in a docker-py request keeps its token until the request returns,
  including after its caller was cancelled; a failure in that case is logged once at warning
  level (`docker call <name> failed after its caller was cancelled`).
- Lane metrics are not exported yet. Judge saturation from slow stream starts and from
  `docker driver closing with calls still running` in the logs.

Shutdown order (every role; the `api` role has no workers, so its first step is empty):

1. The background workers stop, so no new job or reconcile pass starts.
2. The driver is closed with `aclose`. It kills every live terminal, then refuses new driver
   calls (and calls still queued for a token) with `DriverError: docker driver is closed`,
   then drains the lanes: it polls every 50 ms until no call holds a token, for at most 10
   seconds. On timeout it logs how many total and bulk tokens are still borrowed and carries
   on. It then closes the docker-py client.
3. The database engine is disposed.

A job that is mid-call when the pod stops finishes against an open driver. Keep the pod
termination grace period longer than the 10 second drain plus the workers' own stop time. A
driver without `aclose` (the fake driver, third-party drivers) is skipped. A blocked docker-py
call is never interrupted; one that outlasts the drain is left to the process exit, and the
reconciler repairs whatever state it leaves, as after any crash.

## Multi-node

Layout:

- One central api-and-scheduler deployment (`api` role, or `all` for a single-host start)
  that owns the database and decides placement.
- One `worker` process per node, each next to its own Docker daemon and each with a unique
  `SANDFORT_NODE_ID`. Each worker heartbeats into the node registry every
  `SANDFORT_NODE_HEARTBEAT_INTERVAL_S` seconds; `SANDFORT_NODE_MAX_SANDBOXES` (0 means
  unlimited) is the node's advertised maximum for placement. It is not a hard cap: a create
  still lands on the local node when no node qualifies (see "Capacity and sizing").
- Placement and background work follow node ownership automatically: a create is placed on
  the least loaded active, fresh node below capacity, and the jobs of a sandbox run on the
  node that owns it. A node with no heartbeat for 90 seconds is reported `stale` and
  receives no new sandboxes.
- Multi-node operation requires `SANDFORT_SANDBOX_JOBS_ENABLED=true` on every api instance,
  because with the default (off) the sandbox lifecycle runs inline and bypasses placement.
- `GET /v1/nodes` (scope `org:read`, read-only) lists every node with its state, capacity,
  the caller org's running count on it, last heartbeat and staleness flag. The running count
  covers the started sandboxes of the calling org only, never other tenants', so it is not the
  host's load; the node rows themselves are platform-wide (commit da31b5a). `max_sandboxes` is
  the node's `SANDFORT_NODE_MAX_SANDBOXES` (default `0`). `0` means no per-node cap: placement
  never leaves that node out for being full (`pick_node`). A value above `0` is a placement cap
  only, not a limit on creates (see "`SANDFORT_NODE_MAX_SANDBOXES` does not refuse creates"
  above). A key with `sandbox_labels` gets 403. The route is left out of the committed OpenAPI spec on purpose
  (`_IN_SCHEMA = False` in `src/sandfort/api/routes/nodes.py`).
- `examples/gate7.py` checks the layout end to end on one host with a local Docker daemon.

Earlier limitation (lifted when routing is configured): the synchronous toolbox (exec,
filesystem, terminal) is served by the api process against its local Docker daemon, so each
node that should serve toolbox traffic had to run its own co-located api instance behind a
router that sends a sandbox's requests to the node that owns it. With cross-node routing
configured that requirement no longer applies; see the next subsection. Without routing
configured the limitation still holds.

### Cross-node toolbox routing

With routing configured, a toolbox request sent to any api process reaches the node that
owns the sandbox, so SDK and CLI users need one server URL and no router. Design:
`docs/cross-node-routing-design.md`. A process that receives a request for a sandbox it does
not host forwards it once over plain HTTP and streams the answer back. This covers
`/v1/sandboxes/{id}/toolbox/...` (exec, async commands and their logs, files, git, sessions,
terminals). It does not cover container logs, the preview proxy or the web terminal page,
which stay node-local.

Settings (all read with the `SANDFORT_` prefix):

| Variable | Default | Constraint |
|---|---|---|
| `SANDFORT_NODE_INTERNAL_URL` | empty | `http://host:port`, no path, query or userinfo. The address this node advertises in its heartbeat. Empty means the node accepts no forwards. Requires `SANDFORT_ROUTING_SECRET`; without it startup fails. |
| `SANDFORT_ROUTING_SECRET` | empty | At least 32 characters. Empty disables routing entirely. |
| `SANDFORT_ROUTING_TIMEOUT_S` | `5.0` | Positive number. Connect, write and pool timeout of one hop. The read timeout is unbounded, because logs and terminals idle legitimately. |

Rules for operators:

- Every node and every edge uses the same `SANDFORT_ROUTING_SECRET`. Nodes with different
  secrets reject each other (`rejected`). Changing the secret needs a restart of every node.
  Clocks must be synchronized: route tokens live 30 seconds.
- A node that serves toolbox traffic runs role `all` and sets `SANDFORT_NODE_INTERNAL_URL`.
  Role `api` works as a pure edge that forwards and hosts nothing. Role `worker` serves
  health probes only and is not a forward target.
- Routing needs `SANDFORT_SANDBOX_JOBS_ENABLED=true`, like any multi-node setup, and every
  node must share the database.
- Private network only. The hop is plain HTTP: the caller's API key, file contents and
  command output cross the internal network unencrypted. Run nodes on a private network or
  an encrypted overlay, and do not expose `SANDFORT_NODE_INTERNAL_URL` ports to clients.
  Route tokens authenticate the hop as coming from a platform node; the owner still
  authenticates the forwarded API key itself.
- One hop at most. A forwarded request carries the `X-Sandfort-Forwarded` header and a route
  token; the owner never forwards it again. A client that sends that header by hand gets
  503, not an unauthenticated path.
- There is no automatic retry, because exec and writes are not idempotent. The client
  decides whether to repeat a call.

When a hop cannot be made, or the owner refuses it, the caller gets the standard error
envelope with status 503, code `NODE_UNAVAILABLE` and a `Retry-After` header. The
`details.reason` field tells an operator what to check:

| Reason | Meaning | Check |
|---|---|---|
| `stale` | The owning node has sent no heartbeat for 90 seconds. No connection was attempted. | Is the owner process running? Is it reaching the database? |
| `no_address` | The owning node's row has no internal address. | Set `SANDFORT_NODE_INTERNAL_URL` on that node and restart it. |
| `unreachable` | The connection to the advertised address failed. The row can still look fresh for up to 90 seconds after the owner stops. | Address, port and network path between nodes. |
| `timeout` | The connect, write or pool step exceeded `SANDFORT_ROUTING_TIMEOUT_S`. | Network latency or an overloaded owner; raise the timeout if needed. |
| `rejected` | The owner could not verify the route token, or the hop header arrived without a valid token. | The same secret on every node, synchronized clocks. |
| `misrouted` | The token was valid but the database says this node does not own the sandbox. | Node ids are unique per node; no two nodes share a `SANDFORT_NODE_ID`. |

For terminals the edge cannot send the envelope after the upgrade: a refused hop closes the
websocket with code 1013 (try again later). A reused connect token still closes with 4401 from
the owner. The terminal creation reply carries a `websocket_url` built from the host the owner
saw, so connect to the server URL you called, not to that host.

`examples/gate9.py` checks routing end to end on one host: two role `all` processes (nodes
`alpha` and `beta`, one shared database, real Docker), then exec, a file round trip, git,
followed async logs and a terminal against a beta sandbox through alpha only, and a retryable
503 after beta stops.

## Egress proxy

Sandboxes created with `egress_allowlist` reach only the listed hosts, through a CONNECT
proxy (design: `docs/egress-allowlist-design.md`). Run the proxy where sandboxes can reach it:

```sh
SANDFORT_EGRESS_SECRET=<same secret as the api> \
SANDFORT_EGRESS_LISTEN_HOST=0.0.0.0 SANDFORT_EGRESS_LISTEN_PORT=3128 \
python -m sandfort.egress.proxy
```

`SANDFORT_EGRESS_SECRET` is required; the listen host defaults to `127.0.0.1` and the port to
`3128`. The api needs two settings: `SANDFORT_EGRESS_PROXY_ADDRESS` (`host:port` the sandboxes
reach the proxy on) and the same `SANDFORT_EGRESS_SECRET` (at least the session-secret minimum
length). Each node's `deploy/host-setup.sh` creates the `sf-egress-net` bridge and the
`SANDFORT-EGRESS-PROXY` chain, which rejects everything except replies and the proxy endpoint
`SF_EGRESS_PROXY`, the address sandboxes reach the proxy on (see "Egress rules on the host").
Dry-run it with `DRY_RUN=1`. The prod acknowledgement (`SANDFORT_EGRESS_ACKNOWLEDGED=true`)
covers these rules.

**The proxy port must match the INPUT guard port.** `3128` above is an example, not a fixed
value. `deploy/host-setup.sh` opens exactly one tcp port to the proxy, on both INPUT
(`SANDFORT-HOST-GUARD-PROXY`) and FORWARD (`SANDFORT-EGRESS-PROXY`). If the proxy listens on any
other port, give the script the same port, or sandboxes cannot reach the proxy. The script takes
the port from `SF_EGRESS_PROXY` when it carries one (`SF_EGRESS_PROXY=10.0.0.5:3129`), else from
`SF_EGRESS_PROXY_PORT`. With `SF_EGRESS_PROXY` unset the script derives the endpoint (see
"Egress rules on the host") and uses port `3128` unless `SF_EGRESS_PROXY_PORT` says otherwise.
An explicit `SF_EGRESS_PROXY` without any port makes the script stop, and so does a port that
differs between the two variables. `SANDFORT_EGRESS_PROXY_ADDRESS` on the api and
`SANDFORT_EGRESS_LISTEN_PORT` on the proxy must name the same port.

On the hosted beta the proxy is the `egress` service of the compose project, and
`deploy/redeploy-beta.sh api` builds and recreates it together with `api`, then requires the
container to run and its log to show `egress allowed ports:`. `redeploy-beta.sh egress` does only
that part. Deploy any other way and a proxy from an older image keeps its old rules, so restart it
and read that startup line.

Fail-closed behavior: with the proxy address or secret unset, an allowlisted create is refused
(409), never run with open egress. Allowlisted creates are also refused when sandboxes are
created by jobs. If `sf-egress-net` is missing on a node, Docker rejects the create. Sandboxes
without an allowlist are unaffected.

### Egress proxy limits

The proxy process and the api read the same variables (`egress_limits_from` in
`src/sandfort/config.py`). An unset variable takes the default; an invalid value stops the
process at startup.

| Variable | Default | What it limits |
|---|---|---|
| `SANDFORT_EGRESS_DENIED_CIDRS` | `127.0.0.0/8`, `::1/128`, `169.254.0.0/16`, `fe80::/10`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | Comma-separated networks the proxy refuses after it resolves a name (403). The node's own interface addresses are always added. |
| `SANDFORT_EGRESS_ALLOWED_PORTS` | `443,80` | CONNECT target ports; any other port is refused (403). |
| `SANDFORT_EGRESS_MAX_CONNECTIONS_PER_SANDBOX` | `64` (1 to 100000) | Concurrent tunnels one sandbox may hold; the next one gets 429. |
| `SANDFORT_EGRESS_IDLE_TIMEOUT_S` | `300` (1 to 86400) | An idle tunnel is closed after this many seconds. |
| `SANDFORT_EGRESS_TOKEN_TTL_S` | `604800`, 7 days (60 to 34560000) | Lifetime of the egress token minted for a sandbox. The proxy refuses a longer-lived token, except tokens that earlier releases minted for up to 400 days: those are accepted until they expire. |

This release has no setting for a process-wide ceiling on proxy connections and none for a limit
on connections that have not authenticated yet. The only configurable cap is the per-sandbox one
above. The request-read timeout (15 s) and the upstream connect timeout (10 s) are constants in
`src/sandfort/egress/proxy.py`. Bound the proxy from outside, with the host firewall or the
process's file-descriptor limit.

### Egress rules on the host: `host-setup.sh`

`deploy/host-setup.sh` (run as root on each Docker host, again after every reboot or iptables
flush) rebuilds its own chains from scratch, so re-running is safe.

- `sudo sh deploy/host-setup.sh --dry-run` prints the iptables commands and applies nothing
  (`DRY_RUN=1` does the same). In a dry run a missing bridge interface is only a warning; when
  applying, the script stops if a named interface does not exist.
- It creates the two sandbox networks with fixed bridge interface names, so the rules always
  match the interface the sandboxes use: `sf-net` on `sf-br0` (`SF_BRIDGE_IFACE`) and
  `sf-egress-net` on `sf-br1` (`SF_EGRESS_BRIDGE_IFACE`). The names apply only when the script
  creates the network; an existing network is reused and its real interface name is looked up.
- **Run it with `SF_EGRESS_PROXY` set** to the address sandboxes reach the proxy on (an IPv4
  address, optionally `addr:port`), plus `SF_EGRESS_PROXY_PORT` when the address carries no port.
  This is the value of `SANDFORT_EGRESS_PROXY_ADDRESS` in the api's env file. The redeploy
  script (`deploy/redeploy-beta.sh`) prints the exact command, which reads that variable:

  ```sh
  cd /path/to/sandfort/deploy
  sudo SF_EGRESS_PROXY="$(grep '^SANDFORT_EGRESS_PROXY_ADDRESS=' sandfort.env \
    | tail -n 1 | cut -d= -f2-)" sh host-setup.sh
  ```

  See "The proxy port must match the INPUT guard port" above.
- **A bare run derives the endpoint.** With `SF_EGRESS_PROXY` unset the script takes
  `SANDFORT_EGRESS_PROXY_ADDRESS` from the env file (`SF_ENV_FILE`, default `sandfort.env` next
  to the script), else the IPv4 gateway of the egress network, with port `3128` unless
  `SF_EGRESS_PROXY_PORT` is set. It prints the endpoint and where it came from. A loopback
  result stops the script, because sandboxes cannot reach the host's loopback.
- **Hosts without the proxy.** Set `SF_ALLOW_LOOPBACK_PROXY=1` to accept a loopback endpoint;
  the script then prints a warning. Use it only where nothing proxies for sandboxes.
- **The summary names the endpoint and the gateway.** If the rules admit an address other than
  the egress network gateway, it prints a warning with the `SF_EGRESS_PROXY` value to rerun with.
  Ignore it only when the proxy really is on the other address.

The incident behind this: the script used to default to `127.0.0.1`. After a bare run on the
beta VM, the rules admitted loopback only, and every sandbox with an egress allowlist got
`No route to host` when it connected to the proxy. Sandboxes without an allowlist were not
affected. The fix is to rerun the script with the proxy address; it rebuilds its chains.

## Doctor: `python -m sandfort.admin_cli doctor`

`doctor` prints one line per production-readiness check for the node it runs on:

```text
PASS docker daemon: ...
WARN userns remap: ...
FAIL egress probe: ...
summary: 8 pass, 1 warn, 1 fail
```

- **What it reads.** It reads `Settings` from the environment, so run it with the same
  `SANDFORT_*` variables as the server, and it asks the local Docker daemon for its capability
  report. The rows, in the order it prints them:
  - `environment`: `PASS` in `prod`, `WARN` elsewhere (gaps are tolerated).
  - `driver`: `docker` passes. Any other driver has no isolation self-check, so it is a `FAIL`
    in `prod` and a `WARN` elsewhere.
  - `docker daemon`: version and API; `FAIL` when the daemon cannot be probed or does not
    report a version, `WARN` when the disk usage API is unavailable.
  - `storage and disk quota`, `runtimes`, `default runtime`, `userns remap`, and
    `root on shared kernel` (`PASS` when no tier runs container root as host root, or when
    `SANDFORT_ALLOW_ROOT_SHARED_KERNEL` accepts it), then `cgroup driver`.
  - `egress probe` (only when the probe runs) and `egress acknowledged`.
  - `webhook secret`: `FAIL` in `prod` when `SANDFORT_WEBHOOK_SECRET_KEY` is empty, with the
    fernet key command in the detail.
  - `host capacity`: `FAIL` in `prod` when `SANDFORT_HOST_CAPACITY_CPU_MILLICORES` or
    `SANDFORT_HOST_CAPACITY_MEMORY_MIB` is zero, unless `SANDFORT_ALLOW_UNBOUNDED_HOST=true`
    (then `PASS` naming the override). Outside `prod` an unset capacity is a `WARN`.
  - `seccomp profile`, `cgroup parent`, `userns opt-out tiers`, `require userns remap`,
    `database`, `allowed registries`, `build network` and `fault injection` (`FAIL` while
    `SANDFORT_FAULT_INJECTION` is set).
  - **Catch-all rows.** Any other finding the start gate reports gets a row of its own, named
    from the text before the first colon, so nothing the gate refuses on is left out. It is a
    `FAIL` in `prod` and a `WARN` elsewhere (a disk quota gap is a `FAIL` when
    `SANDFORT_ENFORCE_DISK_QUOTA` is on).
- **Same findings as the gate.** It judges the daemon with the same finding functions the
  production start uses (the webhook key and host capacity wording come from
  `sandfort.preflight`, the module the start uses), plus the egress probe (a canary container
  on each managed network tries to get out), so the two cannot disagree. A finding that would
  refuse a `prod` start is a `FAIL`; one the gate only logs is a `WARN`; everything else is
  `PASS`. The probe runs when `SANDFORT_EGRESS_PROBE` is on, which is the default in `prod`
  only. With the probe off, the check reports whether `SANDFORT_EGRESS_ACKNOWLEDGED` covers the
  host rules.
- **The verdict line.** In `prod` the text output ends, after the `summary:` line, with one
  line: `the start gate would refuse: N failing check(s)` when any row is a `FAIL`, else
  `the start gate would start`. Outside `prod` the text output has no such line.
- **`--json`** prints an object instead of text lines: `verdict` holds the same verdict line
  (in every environment) and `checks` is a list of objects with `name`, `status` and `detail`.
- **Exit codes.** `0` when no check is `FAIL` (warnings do not change it). `1` when any check is
  `FAIL`, when the daemon cannot be probed (that is a `FAIL` on `docker daemon`), and when
  `Settings` cannot be read (the error goes to stderr).
- Outside `prod` the gaps are tolerated, and the `environment` check says so as a `WARN`.

## Production start gate

With `SANDFORT_ENVIRONMENT=prod` the server refuses to start while any of the following is
true. Each has an explicit override, named below (except the driver); use an override only
knowing the risk it accepts. The start runs two checks, in this order, and each reports every
finding at once instead of one blocker per attempt.

**1. Preflight (configuration).** The blockers that need no host access: a missing
`SANDFORT_WEBHOOK_SECRET_KEY` and unset host capacity. All of them are reported together.

- `python -m sandfort.main` prints one `error:` line per finding on stderr and exits with
  code `2`, with no traceback. The same exit code covers a settings value that fails to load.
- The webhook finding carries the command that generates the key, so you can copy it:
  `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`.
  The value is a urlsafe base64 fernet key; a malformed one fails when settings load.
- The serve lifespan runs the same preflight, so an application built directly (an embedder,
  the worker app) is refused too, with `prod configuration is not ready` and the findings.
  There the error is an exception rather than the printed lines.

**2. Isolation gate (host).** The Docker daemon's capabilities and the egress check, run
against the live daemon when the app starts. Every finding goes into one refusal, as a single
`host lacks required isolation capabilities` message with the findings separated by `;`, and
the log carries one summary line with the count. A finding names its override where one
exists: `SANDFORT_ALLOW_ROOT_SHARED_KERNEL=true` for root on a shared kernel, and in `prod`
every egress probe finding ends with the hint that `SANDFORT_EGRESS_ACKNOWLEDGED=true` turns
egress probe findings into warnings. With that override set, the start logs the findings as a
warning and continues. Fix the host and unset it when you can.

The doctor reports all of these except the tier family row. It judges the daemon with the
same finding functions as the gate, including the driver, host capacity and the webhook key
(its rows print the preflight wording), and a final line says whether the start gate would
refuse (see "Doctor"). A finding with no row of its own still gets one. The tier family row is
a settings load error, so `doctor` (which reads `Settings` first) prints the error to stderr
and exits 1 without running any check.

| Gate | Refuses when | Variable and default | Override |
|---|---|---|---|
| Driver | The driver is not `docker`. Other drivers have no isolation self-check, so the host gates cannot be verified. | `SANDFORT_DRIVER` | None. |
| Egress probe | A canary on a managed network can reach a target it must not. The probe replaces the old honour-system acknowledgement. | `SANDFORT_EGRESS_PROBE`: on in `prod` unless set false; `SANDFORT_EGRESS_PROBE_IMAGE` (default `alpine:3.20`, needs `sh`, `nc`, `timeout`) | `SANDFORT_EGRESS_ACKNOWLEDGED=true` turns a probe refusal into a logged warning. With the probe off, it is the confirmation that `host-setup.sh` ran, and `prod` requires it. |
| Build runtime | At least one tier is mapped to a runsc or kata runtime (a name containing `runsc` or `kata`, any case) and the daemon default runtime (tenant image builds run on it) is not one of those runtimes. Nothing is reported while no tier offers one. | `SANDFORT_REQUIRE_BUILD_RUNTIME`, default `true` | `SANDFORT_REQUIRE_BUILD_RUNTIME=false`, or set the daemon `default-runtime` to a strong runtime. |
| Root on runc | A tier runs on a runc-class runtime (a name containing neither `runsc` nor `kata`; an empty mapping is the daemon default, and an unreported default counts as `runc`) without user-namespace remapping, or the tier is in `SANDFORT_USERNS_HOST_TIERS`, so container root is host root. | `SANDFORT_ALLOW_ROOT_SHARED_KERNEL`, default `false` | `SANDFORT_ALLOW_ROOT_SHARED_KERNEL=true`; or turn on `userns-remap` in `daemon.json` and keep those tiers out of `SANDFORT_USERNS_HOST_TIERS`; or map the tier to a strong runtime. |
| runc minimum version | The daemon reports a runc older than the floor, or reports none. | `SANDFORT_MIN_RUNC_VERSION`, e.g. `1.1.12` (digits and dots, no `v`); empty = no check | Leave it empty, or upgrade runc on the node. Outside `prod` the finding is only logged. |
| Tier family | A `gvisor` tier is not mapped to a runtime whose name starts with `runsc`, or a `microvm` tier is not mapped to one containing `kata`. This is checked when settings load, so the process does not start in any environment. | `SANDFORT_ISOLATION_RUNTIMES` (or `SANDFORT_CONTAINER_RUNTIME` when no tier map is set) | Fix the mapping. |
| Host capacity | `SANDFORT_HOST_CAPACITY_CPU_MILLICORES` or `SANDFORT_HOST_CAPACITY_MEMORY_MIB` is zero (unguarded). | Both default to `0` | `SANDFORT_ALLOW_UNBOUNDED_HOST=true` starts without a host-wide limit. |

Other gaps also refuse a `prod` start (disk quota support, the egress gate) and so does the
optional `SANDFORT_REQUIRE_USERNS_REMAP`; "Node preparation" covers the daemon side. For the
isolation tiers themselves, see `docs/isolation-tiers.md`.

### Two instances, or a dev box next to a rig, on one Docker daemon

The sandbox networks belong to the daemon, not to a Sandfort instance, and are found by exact
name: `sf-net` and `sf-egress-net`. A second Sandfort instance, or a dev box pointed at the
same daemon as a rig, reuses the networks that already exist and creates them only when
missing. They carry the same names, the same `icc=false` setting and the same host rules, so
the instances share one network each.

- The first instance to create a network fixes its bridge interface name. When the network
  was created by another instance without the fixed names (`sf-br0` and `sf-br1`, or the
  values of `SF_BRIDGE_IFACE` and `SF_EGRESS_BRIDGE_IFACE`), the server logs a bridge-name
  warning, once per network: the rules from `deploy/host-setup.sh` do not match that
  interface. In `prod` next to another instance this warning is expected. Do not recreate
  the network from one instance while the other has sandboxes on it.
- If the host should be covered by the rules, recreate the network with the fixed bridge
  name while no sandbox uses it, then run `deploy/host-setup.sh` again. The `prod` egress
  probe checks the result at every start.
- Host capacity is counted per instance, not per daemon. Choose each instance's
  `SANDFORT_HOST_CAPACITY_*` so that the values add up to what the host has.

## Operator policy settings

Two settings let the operator constrain what tenants can ask for. Both are read by
`src/sandfort/config.py`.

- `SANDFORT_ENFORCE_BLOCK_NETWORK` (default `false`). When `true`, a create that asks for
  `block_all` false, or for an egress allowlist, is refused with 403. Without it, a create may
  choose; `SANDFORT_DEFAULT_BLOCK_NETWORK=true` only changes the default for a create that names
  no network policy.
- Default org quota: `SANDFORT_DEFAULT_ORG_MAX_SANDBOXES`, `SANDFORT_DEFAULT_ORG_MAX_VCPUS`,
  `SANDFORT_DEFAULT_ORG_MAX_MEMORY_MIB` and `SANDFORT_DEFAULT_ORG_MAX_DISK_GIB`. They set the
  quota a new organization starts with, when `admin_cli` bootstraps or creates it. An unset
  variable leaves that dimension unlimited. To change the quota of an organization later, use
  `PUT /v1/org/quota`.

### Fault injection test hook

`SANDFORT_FAULT_INJECTION` (comma separated, default empty) is a test hook for an agreed
fault-injection test of the resize replace path, never for production. `resize_commit_fail` makes
the start of a resized sandbox fail with `500 INTERNAL` instead of the commit, before anything is
touched; `resize_create_fail` does the same instead of the create that follows the old
container's destroy, so the sandbox's files stay in its `sf-resize-<id>` image and the next start,
once the setting is removed, creates the container from it. An unknown name is refused at load.
While it is set the server logs a warning at startup, `GET /v1/status` carries
`fault injection active: <values>` in `notice.message` (appended to the notice file's text when
there is one; no key needed), and `doctor` reports a `FAIL` on the `fault injection` row.

Two more names exist for the agreed fault window around volume restore; like the resize pair they
are for that window only, and they show in the same notice. `restore_extract_hold` stalls the
docker restore upload after its first piece went to the daemon (the request body is not finished,
so the daemon has begun extracting) and holds there until the restore is cancelled, so an operator
can kill the server knowing extraction had begun (`src/sandfort/drivers/docker/volume_transfer.py`).
`volume_recovery_clear_fail` makes the start-up recovery of interrupted restores fail to empty
every marked volume without calling the driver, so the markers stay and export of, and sandbox
creates mounting, those volumes answer 409 `restore_unrecovered` while a new restore of them still
works; remove the name and restart to recover them normally
(`src/sandfort/services/volume_restore_recovery.py`).

## Release page

For what a release is and how it is tagged, see `docs/release.md`.

The maintainer's docs site (`deploy/redeploy-beta.sh docs`) is served from two Kubernetes
ConfigMaps, because one ConfigMap is limited to 1 MiB: `sandfort-docs` holds the pages and
assets, `sandfort-docs-spec` holds `openapi.json`. The `sandfort-docs` Deployment mounts both as
one projected volume. The script creates or replaces both ConfigMaps and patches the Deployment
volume once; later runs find it patched and change nothing.

## SCIM provisioning

An identity provider (Okta, Microsoft Entra ID) can create, re-role and remove the members of
one org through SCIM 2.0. Design and failure modes: `docs/scim-design.md`. SCIM is off by
default: with it off, neither the `/scim/v2` routes nor the token routes are mounted.

Settings (read with the `SANDFORT_` prefix, on every api instance):

| Variable | Default | Constraint |
|---|---|---|
| `SANDFORT_SCIM_ENABLED` | `false` | Boolean. `true` mounts `/scim/v2` and `/v1/org/scim-tokens`. |
| `SANDFORT_SCIM_DEFAULT_ROLE` | `viewer` | `admin`, `developer` or `viewer`; anything else fails startup. The role of a user the provider creates without a role. |

Run `alembic upgrade head` first: revision `0010` adds `org_memberships.external_id` and the
`scim_tokens` table. No new secret exists; the token hash uses `SANDFORT_API_KEY_PEPPER`, so
changing the pepper also invalidates every SCIM token.

### Mint and revoke the SCIM token

The provider authenticates with a per-org bearer token, minted by an org admin (scope
`api_keys:admin`) with an ordinary API key. `max_role` is the ceiling of the token: a token
with `developer` cannot create or promote an admin, and the minting key must itself hold the
scopes of that role (otherwise 403). The plaintext is in the `token` field of the response,
exactly once; only a salted hash is stored and it cannot be recovered.

```sh
curl -sS -X POST "$SANDFORT_BASE_URL/v1/org/scim-tokens" \
  -H "Authorization: Bearer $SANDFORT_API_KEY" -H "Content-Type: application/json" \
  -d '{"name": "okta-prod", "max_role": "developer"}'
# data.id (stk_...), data.prefix, data.max_role, data.token (sf_scim_..., shown once)

curl -sS "$SANDFORT_BASE_URL/v1/org/scim-tokens" -H "Authorization: Bearer $SANDFORT_API_KEY"
curl -sS -X DELETE "$SANDFORT_BASE_URL/v1/org/scim-tokens/$TOKEN_ID" \
  -H "Authorization: Bearer $SANDFORT_API_KEY"
```

The list shows metadata only (id, name, prefix, `max_role`, `created_at`, `last_used_at`,
`revoked_at`), never the token or its hash. Revoking takes effect on the next request and is
idempotent. An org holds at most 5 active tokens and tokens do not expire, so rotate by
minting a new one, switching the provider, then revoking the old one. Mint and revoke are
audited (`scim_token.created`, `scim_token.revoked`) without the token. These routes are not
in the committed OpenAPI spec.

### Identity provider configuration

| Field | Value |
|---|---|
| SCIM base URL | `https://<your-server>/scim/v2` (the `Users` resource is `/scim/v2/Users`) |
| Authentication | HTTP header / bearer token: the `sf_scim_...` token |
| Unique identifier | `userName` (the user's email, stored lowercased) |
| Role | the `roles` attribute, one entry with `primary` true: `admin`, `developer` or `viewer` |

The token works on `/scim/v2` only, and there every other credential is a 401: an API key or
a session token is refused, and the SCIM token is a 401 on the rest of the API. Requests and
responses use `application/scim+json` (`application/json` bodies are accepted). Each request
takes one token from the rate-limit bucket of the SCIM token id, so a provider loop gets 429.
A write fails the same way the members API does: an unknown role or a role above the token
ceiling is refused, and an org cannot lose its last admin (409).

### What is supported

Users only. Stated plainly:

- Supported: `GET/POST /Users`, `GET/PUT/PATCH/DELETE /Users/{id}`, and the discovery
  documents `ServiceProviderConfig`, `ResourceTypes` and `Schemas` (they need the token too).
- One filter form: `userName eq "<value>"`. Any other filter, including `externalId eq`, is
  400 `invalidFilter`. A filter with no match is an empty list. Paging: `startIndex` and
  `count` (at most 100), sliced in memory.
- PATCH accepts three shapes: `active` (by path or in a value object; `"True"` and `"False"`
  strings are accepted), `externalId`, and the role (`roles` with a list of role objects, or
  `roles[primary eq "True"].value`). Everything else is 400 `invalidPath` or `invalidValue`,
  and a patch is applied whole or not at all.
- `userName`, `displayName` and `name` are immutable after create, because a user row is
  shared by every org the person belongs to. A different value is 400 `mutability`.
- Not supported: Groups, Bulk, ETag and versions, sorting, password management, enterprise
  extensions, `lastModified`. There is no SDK or CLI support and no SCIM entry in the OpenAPI
  document; the discovery endpoints describe the surface.
- SSO is still bound to the single `SANDFORT_OIDC_ORG_ID`: a token for another org
  provisions members who cannot sign in through SSO.

### Deactivation

`active` false (PATCH or PUT) and `DELETE` do the same thing: they remove the org membership.
The user row and the audit history remain, and the audit record `membership.removed` carries
the SCIM token id as the actor. A removed member's session token stops working on the next
request, and the SSO exchange needs a membership. Afterwards `GET /Users/{id}` and a repeat
deactivation are 404. API keys the person created before the removal are not revoked.

There is no soft deactivation and no remembered role. A provider that reactivates a user
sends a `POST` for the same `userName`: the user keeps the same `id`, the role is the one
in the request or `SANDFORT_SCIM_DEFAULT_ROLE`, and the provider sends `externalId` again.

`examples/gate10.py` checks all of this end to end on one host (no Docker needed): it mints
a token, plays the provider sequences with plain HTTP, and shows the last-admin refusal, the
role ceiling, the token boundaries and revocation.

## Behind a TLS-terminating proxy

When a proxy or ingress terminates TLS in front of the api, set `SANDFORT_FORWARDED_ALLOW_IPS`
to the proxy's address (comma-separated addresses, or `*`). uvicorn then trusts the
`X-Forwarded-Proto` and `X-Forwarded-For` headers from those addresses only. The default is
`127.0.0.1`: without the setting the server sees plain http, and the websocket URLs it returns
(terminals, PTY) come out with the plain `ws` scheme instead of `wss`. Use `*` only when the api
is reachable solely through the proxy. The Python SDK also upgrades a plain ws URL to wss when
the client's base URL is https on the same host. Preview URLs have their own setting,
`SANDFORT_PUBLIC_PREVIEW_URL`.

## Client-facing errors

What a caller reports from the API, and what to do about it. The same vocabulary is in the
`info.description` of the OpenAPI document (`openapi/sandfort.v1.json`, also served by the api).
Every failure uses the envelope `{"success": false, "data": null, "error": {"code", "message",
"details", "request_id"}}`; switch on `error.code` and, for 409, on `error.details.reason`, not
on the message.

### Codes and statuses

| Status | `error.code` / `details.reason` | What it means | Does a retry help? | What to do |
|---|---|---|---|---|
| 409 | `CONFLICT` / `name_taken` | A sandbox with that name already exists in the org. | No | Pick another name or leave it unset. |
| 409 | `CONFLICT` / `already_exists` | The object (member, external id, file, row id) already exists. | No | Read the existing object instead of creating it again. |
| 409 | `CONFLICT` / `concurrent_update` | Another writer changed the row first (stale version). | Yes | Re-read and repeat the call. A steady stream means two clients fight over one object. |
| 409 | `CONFLICT` / `no_container` | The sandbox has no running container for the call. `details.state` names the sandbox state, and `details.stop_cause` the value the sandbox object shows (`requested`, `auto_stop`, `container_exited`, `oom_killed` or `unknown`; see "Sandbox `stop_cause` values"). While the sandbox is `stopping` or `stopped` and the row holds no cause, for example a sandbox stopped before migration `0020`, the value is `unknown`, as in the sandbox resource. In every other state, including `destroying` and `destroyed`, the key is omitted. `details.stop_cause` adds to `details.state` and does not replace it. The toolbox guard words a sandbox in another non-started state "sandbox is `<state>`; toolbox calls require a started sandbox"; a deleted one (`destroying` or `destroyed`) reads "the sandbox was deleted; create a new one" in the guard too (since 238cd17); where a call finds a sandbox without a container, a `stopped` one reads "sandbox has no container instance; start it first". Switch on `details.state`, not on the message. | For a stopped sandbox, after it is started; for a deleted sandbox, never | Read `details.state`. Start a `stopped` sandbox. Do not start a deleted one (`destroying`, `destroyed`): create a new sandbox. If the sandbox claims to be `started`, look at the server log. |
| 409 | `CONFLICT` / `in_progress` | The same work (an idempotency key, a snapshot) has not finished yet. | Yes, later | Poll the object, or repeat the request with the same key after a short wait. |
| 409 | `CONFLICT` / `in_use` | The object is still used by a sandbox (mounted volume, source snapshot). | After the user is gone | Delete or stop the sandboxes that use the object first. |
| 409 | `CONFLICT` / `closed` | The PTY or session is closed or does not accept the call. | No | Open a new terminal or session. |
| 409 | `CONFLICT` / `operation_failed` | A git or fs command in the sandbox failed. | Depends on the cause | Read `message` and the server log for the request. |
| 409 | `CONFLICT` / `changed_during_reset` | The sandbox changed state while a reset was replacing it. | Yes | Read the sandbox state and repeat the call once the reset has finished. |
| 409 | `CONFLICT` / `unsupported_mode` | The operation is not supported in the configured run mode. | No | Check the server's run-mode settings (`SANDFORT_` variables). |
| 409 | `CONFLICT` / `disk_full` | The runtime reported that the sandbox disk is full. | No | Free space inside the sandbox. |
| 409 | `CONFLICT` / `runtime_conflict` | The runtime refused the operation for another reason. | Maybe | Read the driver message in the server log (search by request id, below). |
| 409 | `CONFLICT` / `conflict` | Fallback when no other reason applies. | Depends | Read `message`; report it with the request id if it is unclear. |
| 409 | `INVALID_STATE` (`details.state`, `details.target`) | The sandbox's current state does not allow the transition, for example resizing a running sandbox. | After the state changes | Read `details.state` and move the sandbox to a state that allows the call. |
| 422 | `IDEMPOTENCY_MISMATCH` | An `Idempotency-Key` was reused with a different request body. | No | Use a new key for a different request, or send the original body again. |
| 422 | `VALIDATION_ERROR` (`details.errors`) | A body field or a query parameter is invalid or unknown. Every list route (sandboxes, isolation, snapshots, volumes, api-keys, webhooks, webhook deliveries, nodes, jobs, usage, and the audit routes) refuses a query parameter it does not declare, with one `extra_forbidden` entry per name (`loc` `["query", name]`, value not echoed). | No | Fix the call; the message lists the accepted parameters. The check runs after authentication. |
| 429 | `RATE_LIMITED` | The API key's token bucket is empty (`SANDFORT_RATE_LIMIT_REFILL_PER_S`, `SANDFORT_RATE_LIMIT_BURST`). Carries `Retry-After`. | Yes, after `Retry-After` seconds | Back off; raise the limits only if one key legitimately needs more. |
| 429 | `QUOTA_EXCEEDED` | The org is over its quota (`PUT /v1/org/quota`), or a label-scoped key is at its `max_sandboxes` cap (`details.limit` `key_max_sandboxes`, with `details.max` and `details.current`). No `Retry-After`. | No, until usage drops; the SDK never resends it | Delete idle sandboxes, raise the quota, or mint the key with a higher cap (1 to 1000). |
| 503 | `NODE_UNAVAILABLE` (`details.reason`, `details.node_id`) | The node that owns the sandbox cannot serve the call now. Carries `Retry-After`. | Yes, after `Retry-After` seconds | See "Cross-node toolbox routing" for the reasons and what to check. |
| 503 | `DNS_UNAVAILABLE` (`details.reason` `dns_unavailable`) | The server could not look up a webhook receiver's host (resolver timeout or failure) when you created or changed an endpoint, even after one retry. It is not a verdict on the URL: the host may well exist. Nothing was created or changed. Carries `Retry-After` (2 s). A host that really does not exist answers 422 `UNPROCESSABLE` with `details.reason` `not_resolved` instead. | Yes, after `Retry-After` seconds | Repeat the call. If it keeps failing, check the server's DNS resolver. |
| 503 | `CAPACITY` | There is no room right now: the host has no capacity for the reservation, an org is at its terminal cap, or `/readyz` found the database or driver unreachable. Carries `Retry-After`: 5 s by default (`DEFAULT_CAPACITY_RETRY_AFTER_S`, `src/sandfort/errors.py`); the per-org live-terminal cap sets 30 s (`TERMINAL_CAP_RETRY_AFTER_S`, `src/sandfort/toolbox/pty.py`), because a slot frees only when a terminal closes. | After capacity frees up; a retry after `Retry-After` seconds is reasonable | See "Controls that cap a node". |

A client that retries should honour `Retry-After` on 429 `RATE_LIMITED` and on 503
`NODE_UNAVAILABLE`, `CAPACITY` and `DNS_UNAVAILABLE`, and send the same `Idempotency-Key` on a retried create. The
Python SDK retries 429 (not `QUOTA_EXCEEDED`), 503 and transport errors on safe requests, with
jittered back-off, and understands `Retry-After` as seconds or an HTTP-date; a keyed create is also
resent on 409 `in_progress`. How the SDK paces a 503 (since d6435d8,
`sdk/python/src/sandfort_sdk/_requests.py`): it waits the longer of its own back-off (0.5 s,
1 s, 2 s, ..., at most 8 s, full jitter) and the `Retry-After` of the answer, with the
`Retry-After` part capped at 30 s. A 503 without the header waits the back-off alone. So a
resent call that gets a `CAPACITY` with `Retry-After: 5` waits about 5 s, and one that gets the
terminal cap (`Retry-After: 30`) waits about 30 s. Only calls that are safe to repeat are
resent. The header value is also on the raised `ServiceUnavailable` or `CapacityExceeded` as
`retry_after_s` (1 if the server sent none), so a caller whose retries ran out sleeps that long
itself before calling again.

### Exec stop reasons

`POST .../toolbox/process/execute` and `.../toolbox/process/code-run` answer 200 even when the
command did not finish normally. `stop_reason` in the result says why; it is `null` for a normal
exit.

| `stop_reason` | Meaning | Action |
|---|---|---|
| `timeout` | The command reached `timeout_s`. | Raise `timeout_s`, at most 3600, or run the command as an async session command. |
| `output_limit` | The output limit was reached and the output is truncated. | Write the output to a file in the sandbox and download it. |
| `sandbox_stopped` | The sandbox stopped under the command: a stop by the caller or auto-stop, or a death under a resource limit (memory or process count) or a main-process exit. Exit code 137, `sandbox_stopped` true. "Sandbox stopped or died" below tells the two apart. | `start()` brings the sandbox back with its files; use `reset()` and then `start()` when the files must be clean. After a death, lower the command's memory or process use. |
| `sandbox_deleted` | Another caller deleted the sandbox while the command ran. Exit code 137, `sandbox_stopped` true. | Nothing to recover; create a new sandbox if the work should continue. The audit log shows who deleted it. |
| `sandbox_reset` | Another caller reset the sandbox while the command ran. Exit code 137, `sandbox_stopped` true. | Repeat the command on the fresh sandbox if it is still wanted. The audit log shows who reset it. |
| `oom_killed` | The sandbox ran out of memory and the server could see it. Either the container died of it (`sandbox_stopped` true, the sandbox `stop_cause` is `oom_killed`), or the kernel killed the process while the sandbox kept running (`sandbox_stopped` false: the cgroup `oom_kill` counter rose during the exec). Exit code 137. Reported on the container isolation tier only, on a host where the server can read the container's cgroup (a local daemon, cgroup v2) for the process case. Under gVisor and the microVM tiers an out-of-memory kill still reads `killed` or `sandbox_stopped`. | Raise the sandbox memory (resize) or reduce the workload. |
| `killed` | The process got SIGKILL (exit code 137) and none of the reasons above applies: user code killing itself, or an out-of-memory kill the server could not see (gVisor, microVM, a remote daemon). | Check the sandbox memory limit; the sandbox itself may still be `started`. |
| `queue_timeout` | Code contexts only. The run waited for another run of the same context for longer than its own `timeout_s` and never started. Exit code 124, `timed_out` true; the context and its state are kept. | Send the cell again once the earlier run has finished, or give it a larger `timeout_s`. |
| `context_lost` | Code contexts only. The context's kernel died or closed the connection during the run, or the context was deleted mid-run. | Create a new context and run the cell again; the state of the old one is gone. |

A code-context run cut short because the sandbox was stopped (a caller's stop, auto-stop) or its
container vanished also answers `sandbox_stopped`, with exit code 137 and `timed_out` false,
instead of `timeout` or the resource-limit wording. The context is gone with the kernel. A
streamed cell ended this way finishes with a normal `result` event that keeps the `stop_reason`;
the `error` event is reserved for driver failures.

**Sandbox stopped or died.** `sandbox_stopped` covers two different events; tell them apart
before you act:

| | Stopped (caller or auto-stop) | Died (resource limit or main-process exit) |
|---|---|---|
| stderr sentence | "the sandbox was stopped while the command was running; start it again" (for a cell: "the sandbox was stopped while the cell was running; the context is gone, create or ensure a new one") | The resource-limit sentence: "the sandbox stopped while running this command (a resource limit was hit or its main process ended); start it again" |
| Sandbox row | `error_code` is null | `error_code` is `container_exited` |
| Sandbox row, `stop_cause` | `requested` (a stop request) or `auto_stop` (the idle timer) | `container_exited` |
| Audit log | `sandbox.stop` recorded for the key that stopped it (`sandbox.auto_stopped` for the idle timer); both carry `details.stop_cause` | `sandbox.drift_detected` with outcome `error` |

The `sandbox_stopped` flag is also true for `sandbox_deleted` and `sandbox_reset`: those two
refine it. A client therefore branches on `stop_reason`, not on the flag alone. `queue_timeout`
and `context_lost` are sent by `POST .../toolbox/code-contexts/{context_id}/run` only; `queue_timeout`
refines a `timeout`, and `context_lost` is kept where nothing else stopped the run.

### Sandbox `error_code` values

A sandbox that failed carries a machine-readable `error_code` next to the free-text
`error_reason` (REST field `error_code`; the list is the `ErrorCode` type of the SDK and
`ERROR_CODES` in `src/sandfort/domain/sandbox.py`). The code is chosen from the kind of failure,
never from the message text. A sandbox in the `error` state is terminal: the only transition out
is deletion, and `start` answers 409 `INVALID_STATE`. So "retry" means the caller deletes the
sandbox and creates a new one. `container_exited` is the exception: the sandbox is `stopped`, not
`error`, and `start` works.

The caller's `request_id` finds the server-log line (see the next section). The daemon text that
a tenant never sees is logged at `WARNING` by the logger `sandfort.drivers.docker.client` (see
"The detail of an unclassified runtime error").

| `error_code` | Retry? | Who sets it | What the operator checks |
|---|---|---|---|
| `image_not_found` | No, not with the same reference | create: the driver did not find the image or snapshot named at create; an image with no variant for the node's CPU architecture also lands here (see the note below the table) | That the reference exists, and that the image publishes a variant for the node's architecture. For a snapshot, that its image `sandfort-snapshot:<snapshot id>` is still in the node's Docker image store (see "Backup and restore of node data"). |
| `registry_unreachable` | Yes, after a pause | create: the network to the image registry failed (resolver, dial, timeout, EOF), the registry throttled the pull (HTTP 429, for example the Docker Hub pull rate limit) or the registry failed on its side (HTTP 5xx) | The node's side, not the API: DNS from the node (`getent hosts <registry host>`), egress to the registry, a registry mirror or proxy. For a 429, the registry's rate limit (authenticate the daemon's pulls or pull through a mirror); for a 5xx, the registry's own status. The image may exist. |
| `registry_tls_error` | No, not until the registry trust or configuration changes | create, reset, snapshot register: the TLS connection to the registry failed validation (an untrusted, expired or wrong-name certificate, or a plain-HTTP registry answering an HTTPS request) | The trust and configuration of the node's Docker daemon, not the network: that the CA which signed the registry certificate is trusted (the node's system certificates, or `/etc/docker/certs.d/<registry host>/ca.crt`), that the certificate has not expired and names the registry host, and, for a registry that serves plain HTTP on purpose, that it is listed under `insecure-registries`. Repeating the create fails the same way until that changes. |
| `image_access_denied` | No, until the reference or the access changes | create, reset, snapshot register: the registry answered and refused the pull | The pull credentials of the Docker daemon on the node (`docker login` or the credential helper config) and that the repository name is right. A private repository and a nonexistent one look the same to the registry. |
| `invalid_image_reference` | No, fix the name | create: the reference cannot be parsed ("invalid reference format") | Nothing on the host; the caller's reference is malformed. |
| `start_failed` | Maybe; read `error_reason` | create or start: any other driver error | The server log for the request id: Docker daemon health (`docker info`), that the configured runtime (`runsc`, Kata) is installed and registered, free disk on the Docker root, and `/readyz`. |
| `timeout` | Yes | create or start: a driver operation ran past its deadline | A slow or hung Docker daemon, host load or disk I/O, a first pull of a large image on a slow link. Repeat once the daemon answers promptly; a steady stream means the node is overloaded (see "Capacity and sizing"). |
| `reset_failed` | No for that sandbox; create a new one | reset: the driver failed after the old container was removed | The `sandbox.reset_failed` audit row and the server log. A reset builds the new container from the sandbox's image, so check that the image is still on the node or can be pulled. What was in the old container is gone; named volumes are kept. |
| `container_missing` | No for that sandbox; create a new one | reconciler: the container of a `started` sandbox is gone, or exists but was never started | The `sandbox.drift_detected` audit row (`reason`, `driver_ref`). Whether something removed containers on the node (a manual `docker rm`, a prune, a Docker root that did not survive a node restart) and whether the daemon restarted. The container's files are lost. |
| `container_exited` | Yes: `start` the sandbox | reconciler, or an exec that saw the container die: the sandbox is moved to `stopped` with this code and a reason | The `sandbox.drift_detected` audit row (`stopped_unexpectedly`) and the node's kernel log for an out-of-memory kill. The sandbox exceeded its memory or process limit; its files are kept and a successful start clears the code. |
| `node_lost` | Not applicable today | Reserved for a lost node; no code path sets it | Nothing, as the code never appears. A node that is down shows as 503 `NODE_UNAVAILABLE` on calls routed to it (see "Cross-node toolbox routing"). If a `node_lost` row ever appears, treat it as `container_missing` and report it. |
| `internal` | Once, with a new sandbox; if it repeats, no | Anything the server does not classify | The server log for the request id. A repeating `internal` is a bug to report with that log line. |

An image with no variant for the node's CPU architecture (an `arm64`-only image on an `amd64` node,
or the reverse) surfaces as `image_not_found`. Docker selects the platform from the manifest list
and reports not-found when no entry matches; the `image_not_found` code is Sandfort's mapping of
the daemon's not-found answer, not the registry's own answer.

Compatibility of `registry_tls_error` with older SDK clients: an older client is unaffected by the
new code. `SandboxInfo.error_code`, `Sandbox.error_code` and `SandboxFailedError.error_code` are
deliberately `str | None`, not the `ErrorCode` Literal, so a client from before `registry_tls_error`
(0.1.0b70 and earlier betas) receives it as a plain string. Nothing fails to parse,
`is_known_error_code()` returns `False` on that client, and code that branches on the constants
falls through to its default branch. Upgrading the SDK adds the constant and the Literal member;
no other change is needed.

How a registry's answer to a pull maps to a code: HTTP 429 (throttling) and HTTP 5xx (a registry
server error) are `registry_unreachable`, retryable after a pause. A TLS validation failure is
`registry_tls_error`, not retryable, because the fix is the registry trust or configuration. An EOF
while reading and a TLS handshake timeout are network conditions and stay `registry_unreachable`.
A registry that answered 401 or 403 is `image_access_denied`, and that beats the TLS, certificate, throttle and 5xx phrases in the same text: the daemon echoes the registry's own answer body after the error code (`unauthorized: <message>` for a 401, `denied: <message>` for a 403), and that message can say anything, for example `unauthorized: x509: certificate has expired` or `denied: x509: certificate has expired`. Only a failure to reach the registry at all, reported in the daemon's own words before the registry's answer text (dial, resolver, timeout, EOF), still wins over such an answer; network words inside the answered body (for example `unauthorized: dial tcp: lookup backend.invalid: no such host`) are the registry's data and keep `image_access_denied`. The precedence, first match wins: (1) the not-found family, including the daemon's "pull access denied ... may require 'docker login'" sentence, is `image_not_found`, unless that sentence is followed by a registry `denied: <message>` that is not the stock one of Docker Hub ("requested access to the resource is denied") or GHCR (a bare "denied"), which is a refusal; (2) an unparsable reference; (3) an answer only a registry gives (`401 Unauthorized` / `403 Forbidden`, a trailing `: denied`, a line that opens with `denied`, "no basic auth credentials"); (4) the registry's own `unauthorized: ...` / `denied: ...` when the daemon's own words before that echo show no hard transport failure: `image_access_denied`; (5) a TLS validation failure: `registry_tls_error`; (6) a transport failure, a throttle or a 5xx: `registry_unreachable`; (7) the remaining anchored refusal phrases: `image_access_denied`. A private Docker Hub repository and a missing one therefore stay indistinguishable (`image_not_found`), because Hub answers both with the stock message. A TLS validation failure is also a plain-HTTP registry answering an HTTPS request (for example "http: server gave HTTP response to HTTPS client" or "tls: first record does not look like a TLS handshake"). For `registry_tls_error`
the `error_reason` is a fixed sentence built from the reference you supplied: "could not pull
<reference>: the TLS connection to the registry failed validation (an untrusted or wrong
certificate, or a plain-HTTP registry); fix the registry trust or configuration". The daemon's own
text goes to the server log at debug level only.

### Sandbox `stop_cause` values

A sandbox that is stopping or stopped carries a `stop_cause` next to `stopped_at` (REST fields
`stop_cause` and `stopped_at`; the list is `STOP_CAUSES` in `src/sandfort/domain/sandbox.py`, the
`StopCause` type of the SDK). It says why the stop happened, so a script can tell a stop someone
asked for from a container that died. Unlike `error_code`, it describes a `stopped` sandbox that
`start` brings back.

| `stop_cause` | Meaning | Who sets it | What a script should do |
|---|---|---|---|
| `requested` | A user or API key asked for the stop. | `SandboxService.stop`, in the write that moves the row to `stopping`. | Leave it. Start the sandbox only when the work should continue. |
| `auto_stop` | The idle timer stopped it after `auto_stop_minutes` without activity. | The auto-stop scanner (`src/sandfort/workers/autostop.py`), in the write that moves the row to `stopping`. | Restart it if the work continues. If the stop was unwanted, raise `auto_stop_minutes` or set it to a negative value (never). |
| `container_exited` | The container exited under the sandbox (a resource limit or the main process ending). The row is `stopped` and `error_code` is `container_exited` too. | The reconciler, or an exec that saw the container die (both settle the row through `mark_stopped_unexpectedly`). | Restart it. Alert when it repeats: lower the memory or process use, and check the node's kernel log for an out-of-memory kill. |
| `oom_killed` | The container was killed for exceeding its memory limit, and the runtime said so (Docker `State.OOMKilled`). Only the container isolation tier (runc) can see it; under gVisor and the microVM tiers the same death reads `container_exited`. | The reconciler, or an exec that saw the container die (both settle the row through `mark_stopped_unexpectedly`, which asks the driver for the verdict). The exec that was running answers `stop_reason` `oom_killed`. | Resize the stopped sandbox to more memory, or reduce the workload, then start it. Alert when it repeats. |
| `unknown` | The sandbox is `stopping` or `stopped` and the row holds no cause. | Never stored; the API shows it in place of a null. It is what a sandbox stopped before migration `0020` shows. | Leave it, or read the audit log for the stop. The cause cannot be recovered; starting it is safe. |

Rules that hold for all values:

- `stop_cause` is `null` unless the state is `stopping` or `stopped`, whatever the row holds. A
  `started`, `error` or `destroyed` sandbox shows `null`. `stopped_at` is `null` unless the state
  is `stopped`.
- A sandbox stopped before migration `0020` has no stored cause and shows `unknown`. There is no
  backfill.
- A successful start clears the cause, together with `error_code` and `error_reason`.
- A second stop request never overwrites the cause. A stop on a `stopped` sandbox is a no-op that
  returns the sandbox unchanged. A stop on a `stopping` sandbox answers 409 `INVALID_STATE`. A
  reset of a `stopped` sandbox keeps the cause and `stopped_at`.
- Only the three paths above set a cause. A reset, a lost node, an operator action and a quota
  never set one today; a sandbox that fails goes to `error` and shows `null` there.
- The audit rows of the three paths carry it in `details.stop_cause`: `sandbox.stop` (value
  `requested`), `sandbox.auto_stopped` (value `auto_stop`, next to `auto_stop_minutes` and
  `idle_seconds`) and `sandbox.drift_detected` with `stopped_unexpectedly` (value
  `container_exited`).
- The `sandbox.stopped` webhook payload carries `stop_cause` next to `reason` and `error_code`. The
  other sandbox events carry the key too, with `null`, because they are sent in states where the
  cause is hidden.

List the sandboxes that died, for an alert or a restart loop. `GET /v1/sandboxes` takes one
`stop_cause` value as a server-side filter (an enum in `openapi/sandfort.v1.json`; an unknown
value answers 422). It combines with `state`, `label`, `order` and `cursor`, so no client-side
filtering is needed:

```bash
export SANDFORT_BASE_URL=https://api.sandfort.dev   # or your own base URL
curl -s "$SANDFORT_BASE_URL/v1/sandboxes?stop_cause=container_exited" \
  -H "Authorization: Bearer $SANDFORT_API_KEY"
```

To find repeat container exits for one sandbox, list its `sandbox.drift_detected` audit rows
(an org-wide key with `audit:read`). `sandbox.drift_detected` is also written for a container that
is gone or was never started, so several rows alone do not mean repeat exits: count only the rows
whose `details.stop_cause` equals `container_exited` (or that carry `details.stopped_unexpectedly`):

```bash
SANDBOX_ID=sbx_...
curl -s "$SANDFORT_BASE_URL/v1/audit-events?action=sandbox.drift_detected&target_id=$SANDBOX_ID" \
  -H "Authorization: Bearer $SANDFORT_API_KEY"
```

When a toolbox call hits a sandbox without a container, the 409 `CONFLICT` with reason
`no_container` carries `details.state` and, while the sandbox is `stopping` or `stopped`,
`details.stop_cause`; the CLI conflict hint then ends with "stopped because: <cause>". The value
is the one the sandbox object shows (`visible_stop_cause` in `src/sandfort/domain/sandbox.py`,
used by `src/sandfort/toolbox/guards.py` and `no_container_conflict` in `src/sandfort/errors.py`):
a stopping or stopped sandbox whose row holds no cause reports `unknown` in the 409, as in the
sandbox body. In every other state, including `destroying` and `destroyed`, the 409 omits the
`stop_cause` key. Exec, code-run,
sessions, fs, git, code contexts and the PTY create call all go through that guard and carry it.
The PTY WebSocket connect has no 409: a bad token closes the socket (it does not use this guard).

The audit rows `sandbox.auto_stopped` and `sandbox.auto_deleted`, both written by the auto-stop
worker without an actor id, now carry actor type `system` (the jobs service `record` helper sets
`system` when the actor id is `None`); earlier builds recorded actor type `api_key` for them.
Filter on the action, not on the actor type, to find these rows in older data.

### The `sandbox.failed` audit row

When a driver error moves a sandbox to `error` during create or start, the same unit of work
writes the audit row `sandbox.failed` (outcome `error`, target type `sandbox`, target id the
sandbox id). Both land or neither does. The details are `phase` (`create` or `start`),
`error_code` and `error_reason`, the values the sandbox row now carries. The actor is the API key
that asked for the operation when it is known (the job payload names it), otherwise the system.
Failures that are not a create or start have their own rows: `sandbox.reset_failed` for a reset
and `sandbox.drift_detected` for the reconciler. List them with
`GET /v1/audit-events?action=sandbox.failed` or, for every failure, `?outcome=error`; the
request id of the failed call is the `request_id` filter (`src/sandfort/services/sandbox_jobs.py`).

### Find a request in the server logs

Every response carries the `x-request-id` header, and an error body repeats it as
`error.request_id`. A client may send its own `X-Request-Id`: when it is 1 to 64 characters of
`[A-Za-z0-9._-]` the server echoes it back unchanged and logs it. When the client sends none, or
sends one that is not valid (empty, longer than 64 characters, or any other character), the
server does not reject the request: it mints an id, `req_` followed by 32 hex digits
(`uuid4().hex`; `src/sandfort/api/middleware/request_id.py`, function `resolve_request_id`, test
`test_malformed_request_id_is_replaced_and_reaches_the_error_envelope`). The application mints
the same `req_` form for a missing id and for an invalid one; it has no separate plain form.
So an id you read from a response header or an `error.request_id` is either `req_` plus 32 hex
digits (server-minted) or a valid string that reached the application in the `X-Request-Id`
request header. That includes a plain 32-hex id: it was set by the client or by a proxy in front
of the server (a proxy that stamps every request, for example), and the server echoed it. Check
which of the two your deployment produces before you write a log filter that assumes a prefix.
A client-chosen id is not checked for uniqueness,
so tell clients to use a fresh value per call, or leave it unset. In a multi-node setup the id
passes through the hop to the node that owns the sandbox, so one id spans both nodes.

Each server log line is one JSON object, and every line logged while a request is served has a
`request_id` field (`src/sandfort/logging.py`):

```bash
# REQUEST_ID is the x-request-id header of the response (or error.request_id), whatever its form:
# a plain 32-hex id as below, or a server-minted req_ + 32 hex.
REQUEST_ID=0123456789abcdef0123456789abcdef
kubectl -n sandfort logs deploy/sandfort-api \
  | jq -R -c --arg id "$REQUEST_ID" 'fromjson? | select(.request_id == $id)'
```

The audit row of a request that writes carries the same id in its `request_id` column. Lines
logged outside a request (background workers, the reconciler) have no `request_id`.

#### The detail of an unclassified runtime error

A driver failure that the server does not classify reaches the tenant as one fixed sentence, "the
sandbox runtime reported an error; the details are in the server log": as `error.message` of a
502 `DRIVER_ERROR` answer and as the `error_reason` of a sandbox. The cleaned daemon text is
logged once at level `WARNING` by the logger `sandfort.drivers.docker.client` (the module name),
in the form `docker <operation> failed (ref=<reference>, sandfort.org_id=<id>,
sandfort.sandbox_id=<id>): <text>`. The two ids are those of the job that was running and are
absent when the failure happened outside a job. `<text>` is the cleaned daemon text truncated to
500 characters, since an OCI error can echo a command line. `<operation>` is the name the call
site gave, in the form `<object>.<action>`: for example `container.create`, `container.start`,
`container.stop`, `container.remove`, `container.inspect`, `container.commit`, `exec.create`,
`exec.start`, `exec.kill`, `exec.inspect`, `image.pull`, `image.inspect`, `image.build`,
`image.export`, `image.remove`, `volume.create`, `volume.inspect`, `volume.remove`,
`network.ensure`, `archive.put`, `archive.get`, `pty.start`, `logs.open`, and the host checks
`inventory.containers`, `inventory.volumes`, `inventory.images`, `daemon.info`, `daemon.version`
and `daemon.df`. The fixed sentence is the same for every operation; only the log line tells
them apart. The same rule applies to two other places:

| Tenant sees | Logger, level | Log line starts with |
|---|---|---|
| "the container log stream failed; the details are in the server log" | `sandfort.drivers.docker.logs`, `WARNING` | `log stream of <ref> failed:` |
| "the microVM agent reported an error; the details are in the server log (status N)" | `sandfort.drivers.firecracker.agent_client`, `WARNING` | `agent answered <status> (ref=<ref>):` |
| "the microVM agent request failed; the details are in the server log" | `sandfort.drivers.firecracker.agent_client`, `WARNING` | `agent <method> <path> failed (ref=<ref>):` |

To find the detail, take `error.request_id` from the answer. For a sandbox whose `error_reason`
shows the sentence, use the `x-request-id` of the call that showed the failed state (the SDK
exposes it as `SandboxFailedError.request_id`); a failure that happened in a background job may
have no `request_id` in its log line, because lines logged outside a request carry none. Then
filter the logs as above, adding the logger name:

```bash
kubectl -n sandfort logs deploy/sandfort-api \
  | jq -R -c --arg id "$REQUEST_ID" \
      'fromjson? | select(.request_id == $id and (.logger | startswith("sandfort.drivers")))'
```

For a job without a `request_id`, search the worker logs by the `ref` (the container name or the
image reference) and the time of the failure. The default log level `INFO` already includes
`WARNING`, so no setting needs to change. Build errors are the exception: the daemon text of a
failed image build is logged at `DEBUG` by `sandfort.drivers.docker.build`
(`image build of <tag> failed: <text>`), so it appears only when the log level is `DEBUG`.

A client that reports a 401 may be using a revoked or expired key. That refusal appears in the
organization's audit (`GET /v1/audit-events?action=request.denied`) as `request.denied` with
`reason` `revoked` or `expired` in the details, written at most once per key per minute per
server process, so a client that retries with the dead key leaves one row per window, not one
per request. A missing, malformed, unknown or wrong-secret key names no organization and leaves
no row; look for it in the server log by request id. See "Audit" in `docs/governance.md`.

## Snapshot export

`GET /v1/snapshots/{id}/export` streams a `ready` snapshot as an image tar
(`application/x-tar`, the archive `docker save` writes for the snapshot's image reference,
`sandfort-snapshot:<id>` for a committed snapshot; `src/sandfort/api/routes/snapshots.py`). The
Python SDK has `client.export_snapshot(snapshot_id, path)` and the CLI
`sandfort snapshot export <id> -o <file>`.

- Scope `snapshots:read`. A label-scoped key sees a snapshot only when its source sandbox is in
  scope, so the same rule applies to the export.
- The body is read from the Docker daemon in chunks and never held in memory by the api. The first
  chunk is read before the response starts, so a missing image is a 404 and not a broken body.
- A snapshot that is not `ready` answers 409 `INVALID_STATE` (`details.state`). A driver that
  cannot export images answers 409 `CONFLICT` with `details.reason` `unsupported_mode`.
- The export is audited as `snapshot.exported` (target type `snapshot`, details: the snapshot
  name) in the caller's org. The row is written before the stream starts, so a download that is
  aborted later is recorded too: the event says an export was requested, not that it completed.
- To restore on another host: `docker load -i <file>` brings the image back under the same
  reference. That makes it a local image, not a snapshot there. Registering needs a registry
  pull: `POST /v1/snapshots` runs a pull and stores the registry digest, and it refuses the
  reserved `sandfort-snapshot` repository, so retag the loaded image, push it to a registry the
  target server can pull from, and register that reference. The export tar is a `docker save`
  of the image by its id, so `docker load` prints only an image id and restores no tag. To
  rebuild the same node, tag the loaded image as `sandfort-snapshot:<id>` yourself (see
  "Backup and restore of node data"); the snapshot row then finds its image.

## Volume export and restore

`GET /v1/volumes/{id}/export` downloads the files of a volume as a gzipped tar and
`POST /v1/volumes/{id}/restore` replaces the files of a volume from one (`src/sandfort/api/routes/volumes.py`,
`src/sandfort/services/volume_transfer.py`). The Python SDK has `client.volumes.export(volume_id, path)` and
`client.volumes.restore(volume_id, source)` (sync and async); the CLI has `sandfort volume export <id|name> -o <file>`
and `sandfort volume restore <id|name> <file>`. The TypeScript SDK has neither. Both operations need the Docker
driver (or the fake test driver); another driver answers 409 `CONFLICT` with `details.reason` `unsupported_mode`.

**A restore is clear-then-extract, not atomic, and it has two phases.** A refusal before extraction starts leaves the
volume untouched and carries no `volume_emptied` key. Once the restore has begun, any failure leaves the volume empty and
says so (`details.volume_emptied`). Extraction starts when the volume is emptied, which happens only after the request is
admitted (volume visible to the key, no mounting sandbox, no other restore, a free transfer slot, a `Content-Length` within
the limit) and the server has decoded the first block of the body: up to 1 MiB of decompressed data, taken from the first
chunks of the request. Everything that shows in that block is a phase-one refusal: an empty body, a body that is not gzip, a
gzip header, deflate or CRC error found while decoding it, or a stream that holds no data (422, volume unchanged). A gzip CRC
is checked only when the end of the stream is decoded, so the same corruption (for example a valid header and a bad CRC) is
refused in phase one for a small archive (its whole body arrives in the first chunks and decompresses to at most 1 MiB) and in
phase two for a larger one (the failure surfaces after the volume was emptied: 422 with `details.volume_emptied` `true`).
Early rejection is kept on purpose: it spares the volume when the body is plainly bad. Tar-level problems (a member the policy
refuses, a duplicate path, an unreadable or cut-short tar) are always phase two, because the tar is read only after the volume
is emptied. A client that must know which phase it hit reads the error: `volume_emptied` is present only in phase two (`true`;
`false` means emptying itself failed). Export first when you need a copy to come back to.

**A crash of the server during extraction is recovered at the next API start.** A restore records `volumes.restoring_since`
once the first block is decoded and before the driver extracts, and clears it when the restore ended with the volume complete
or empty. A SIGKILL leaves no time for the in-request cleanup, so until the server starts again the volume may hold part of
the archive. At start, before it serves requests, the `api` and `all` roles (not `worker`) find every volume with the marker
still set, empty it and clear the marker; each recovery is an audit row `volume.restore` with outcome `error`, actor
`system`, `details.reason` `recovered_after_crash` and `details.volume_emptied`
(`src/sandfort/services/volume_restore_recovery.py`). If the driver cannot empty the volume the marker stays and the next
start tries again. While a volume carries the marker, an export of it and a sandbox create that mounts it answer 409 `CONFLICT` with `details.reason` `restore_unrecovered`; a new restore of it is still accepted and replaces the contents. Recovery clears the marker only where it still holds the value it read, so it never erases the marker of a newer restore. The marker names no process, so a server that starts while another one is mid-restore on the same
volume empties it: run one API process per node that holds volumes. A second process sharing the daemon would not only have its marked volumes emptied by the other's recovery, it could also have its live exports and restores destroyed, because the orphan-helper sweep cannot see another process's in-flight transfers.

### Examples

```bash
# Export: scope volumes:read. The file name is <volume name>.tar.gz.
curl -fsS -o dataset.tar.gz -H "Authorization: Bearer $SANDFORT_API_KEY" \
  "$SANDFORT_BASE_URL/v1/volumes/$VOLUME_ID/export"
sandfort volume export dataset -o dataset.tar.gz          # prints: exported vol_... to dataset.tar.gz: N bytes

# Restore: scope volumes:write; the raw gzipped tar is the request body (at most 256 MiB).
curl -fsS -X POST -H "Authorization: Bearer $SANDFORT_API_KEY" -H "Content-Type: application/gzip" \
  --data-binary @dataset.tar.gz "$SANDFORT_BASE_URL/v1/volumes/$VOLUME_ID/restore"
# {"success":true,"data":{"volume_id":"vol_...","name":"dataset","restored_bytes":10240},"error":null,"meta":null}
sandfort volume restore dataset dataset.tar.gz            # prints: restored vol_... from dataset.tar.gz: N bytes
```

`--json` on either command prints `{id, path, bytes}` (export) or `{volume_id, name, restored_bytes}` (restore).
`restored_bytes` counts decompressed tar bytes, headers included, not file bytes.

### Semantics

| Topic | Behaviour | Source |
|---|---|---|
| Format | Export: gzip of the tar the Docker daemon returns for the whole volume, `application/gzip`, `Content-Disposition: attachment; filename="<name>.tar.gz"` (characters outside `[A-Za-z0-9._-]` become `-`; the volume id when nothing is left). Restore accepts gzip (several members in a row are read as one stream, at most 1000: more is 422, `MAX_GZIP_MEMBERS`) holding a tar. | `drivers/docker/volume_transfer.py` (`export_volume`), `services/volume_transfer.py` (`archive_file_name`, `gunzip_counted`) |
| Existing volume | The volume must exist (`POST /v1/volumes`); restore never creates one. It empties the volume (removes it and creates it again with the same name, driver, options and labels, so labels and id survive) and then extracts. Nothing is merged and nothing is kept. | `drivers/docker/volumes.py` (`recreate_volume`), `tests/test_docker_volume_transfer_r67.py` (`test_restore_replaces_what_the_volume_held_and_keeps_name_and_labels`) |
| Not a sandbox mount | 409 `CONFLICT`, `details.reason` `in_use`, while any sandbox of the organization that is not deleted mounts the volume (stopped ones count). Nothing is changed. Another restore of the same volume running in the same server process: 409 `restore_in_progress` (export is refused the same way during a restore). | `services/volume_transfer.py`, `services/volumes.py` (`refuse_if_mounted`), `tests/test_volume_transfer_r67.py` |
| Size limits | Compressed body: at most 256 MiB. A `Content-Length` above it answers 413 before the body is read and changes nothing; a chunked body that grows past it answers 413 too, and once extraction began the volume is left empty (`details.volume_emptied`). Decompressed tar bytes are counted as they are extracted and must stay within the volume size limit `SANDFORT_VOLUME_MAX_BYTES` when one is set (413, `details.limit_bytes`, volume left empty); whatever that limit says (`0` = none), the decompressed size is also capped at 64 times the compressed size (`EXPANSION_RATIO`), never below 16 MiB (`EXPANSION_FLOOR_BYTES`, because a small tar is padded to 10 KiB records): the size of reference is the declared `Content-Length`, or the bytes received so far for a chunked body, and over it is 413 with `details.max_expansion_ratio` and the volume left empty (256 MiB of gzipped zeros would otherwise be about 256 GiB). The organization quota is not consulted by export or restore. A crash of the server during extraction is recovered at the next API start: the volume is emptied and the recovery is audited; until that start the volume may hold partial content. | `api/routes/volumes.py` (`_refuse_declared_oversize`), `services/volume_transfer.py` (`gunzip_counted`), `services/volume_restore_recovery.py`, `tests/test_volume_transfer_r67.py`, `tests/test_volume_transfer_limits_r67.py`, `tests/test_volume_restore_marker_r71.py` |
| Concurrent transfers | Each export (until its stream is closed) and each restore holds one slot. At most `SANDFORT_MAX_VOLUME_TRANSFERS_PER_ORG` (default 2) per organization and `SANDFORT_MAX_VOLUME_TRANSFERS` (default 8) in the server process, `0` = no cap; over it answers 409 `CONFLICT` with `details.reason` `org_transfer_limit` or `transfer_limit` and changes nothing. Counted per process, next to the per-volume `restore_in_progress` claim. | `services/transfer_slots.py`, `tests/test_volume_transfer_limits_r67.py` |
| Permissions and ownership | Kept as the tar records them: mode (setuid, setgid and sticky bits included), uid, gid and modification time, for files and directories. Extended attributes (including `security.capability`) are not restored. The mode and owner of the volume's top-level directory (the `.` entry) are not guaranteed and no test covers them. Setuid bits are kept on purpose: every sandbox container runs with `no-new-privileges`. | `drivers/docker/tar_policy.py` (module docstring, `_rebuilt`), `tests/test_docker_volume_transfer_r67.py` (`test_restore_round_trips_content_modes_owners_and_internal_symlinks`), `tests/test_tar_policy_r67.py` |
| Symlinks | Only symlinks with a relative target that stays inside the volume are restored. Absolute targets, targets that leave the volume, and any entry below a symlink of the archive are refused (table below). | `drivers/docker/tar_policy.py` |
| Interrupted or invalid import | The volume is emptied again and the answer says so (`details.volume_emptied`). A body that is empty, not gzip, or holds no data, or whose first decoded block (up to 1 MiB) shows a gzip error such as a bad CRC on a small archive, is refused before anything is emptied (422, volume unchanged, no `volume_emptied` key). A gzip stream that is corrupt later (a large archive whose bad CRC is found at its end) or cut short, a tar that is unreadable, cut inside a member, lacks the end-of-archive marker or carries data after it: 422 `UNPROCESSABLE`, message `the archive is not a readable tar` or a gzip message, `; the volume was emptied`, `details.volume_emptied` `true`. A connection dropped by the client mid-upload also empties the volume (the cleanup is shielded from cancellation). If emptying itself fails, `volume_emptied` is `false` and the message says the volume may hold part of the archive. | `services/volume_transfer.py` (`_restore_claimed`, `_annotated`), `drivers/docker/tar_policy.py` (`checked_tar`), `tests/test_docker_volume_transfer_r67.py`, `tests/test_volume_transfer_r67.py` |
| Audit | `volume.export` is written after the stream opened and before the first byte (details: the volume name only; the byte count is unknown). `volume.restore` is written once, after the outcome: restored bytes, or the failure reason, restored bytes counted so far and `volume_emptied`. | `services/volume_transfer.py`, `tests/test_volume_restore_policy_r67.py` |
| Tenant isolation | Both routes find the volume by organization (a volume of another organization is a 404, as is one the key's labels do not show). A label-scoped key must own the volume through its own labels: a volume reached only through `shared_volume_labels` answers 403, for export too. The driver mounts only volumes that carry the platform `sandfort.managed` label; any other volume on the daemon (host, other tools) is a 404 and is never mounted. | `services/volumes.py` (`authorize_transfer`), `drivers/docker/volumes.py` (`inspect_platform_volume`), `tests/test_volume_transfer_r67.py`, `tests/test_docker_volume_transfer_r67.py` (`test_a_volume_the_platform_did_not_create_is_never_mounted`) |

### Archive policy on restore

Every member of the uploaded tar is checked before it reaches the Docker daemon. The server writes a new tar from the
approved headers (names normalised; pax and GNU extensions, extended attributes, device numbers and sparse maps are
dropped), so the daemon never sees what was checked differently. Allowed members: regular files, directories, and
symlinks with a relative target inside the volume. The first refused member stops the upload; the members before it
were already extracted, and the volume is then emptied. The answer is 422 `UNPROCESSABLE` with `details.reason`
`forbidden_entry`, `details.violation`, `details.entry` (the member name, control characters removed) and
`details.volume_emptied` `true`.

| `details.violation` | Refused member |
|---|---|
| `path_traversal` | a `..` segment anywhere in the name |
| `absolute_path` | a name that starts with `/` |
| `invalid_name` | an empty name, one over 4096 bytes, or one with a control character (NUL and anything below a space, and DEL) |
| `invalid_link_target` | a symlink target over 4096 bytes or with a control character |
| `hardlink` | any hard link, even to a file of the same archive |
| `symlink_absolute` | a symlink whose target starts with `/` |
| `symlink_escape` | a symlink whose target leaves the volume, resolved from the symlink's directory (`..` is accepted only as a leading run, `../../x`, never after a name) |
| `symlink_through` | a member below a symlink of the archive (`link/file`) |
| `duplicate_entry` | a second entry whose normalised path equals an earlier entry's, whatever the types (two files of one name, a file then a directory, a symlink then a file; `./a` and `a` are the same path); the first one is never replaced |
| `special_file` | a character or block device, or a FIFO |
| `unsupported_entry` | anything else: sparse files, vendor types, a symlink with an empty target |
| `header_too_large` | a pax or GNU long-name header over 1 MiB (`tarfile` would hold it whole in memory; the upload is cut after reading about that much) |
| `too_many_entries` | more than 100000 members |

Every rebuilt header is also parsed back and its name and link target must equal what was checked, so a name that the
daemon would read differently (it reads C strings: a NUL ends a name) is never written. User and group names are
not carried over.

Source: `drivers/docker/tar_policy.py`; every code is exercised in `tests/test_tar_policy_r67.py`,
`tests/test_tar_policy_hardening_r67.py` and `tests/test_volume_restore_policy_r67.py`. `tests/test_docker_volume_transfer_r67.py` checks against a real daemon that a
traversal archive writes nothing outside the volume.

**Round-trip limit.** Export is a faithful read and applies no policy. A volume that holds an absolute symlink (for
example a Python venv's `bin/python -> /usr/bin/python3`) or a hard link exports without error, but restoring that
archive is refused with 422 `forbidden_entry` naming the entry, and the volume is left empty. Remove or rewrite such
entries (relative symlinks only) before you export if you need the archive to restore.

### Export notes and failures

- The daemon reads the volume through a helper container that is created and never started (no process runs, network
  `none`, `cap_drop=ALL`, `no-new-privileges`), with the volume at `/volume-data`, read-only and `nocopy` for export and
  read-write and `nocopy` for restore. The helper is force-removed when the transfer ends or the stream is closed. It uses
  the egress probe image (`egress_probe_image`, `alpine:3.20` by default), pulled when missing. A helper left by a crash
  carries the label `sandfort.volume_transfer=helper`, the name prefix `sf-vxfer-`, no sandbox id label and an old
  timestamp label, and is removed by the next transfer once it is older than 6 hours (`drivers/docker/volume_helper.py`);
  a container that merely carries the helper label (an image can bake in a `LABEL`) is never removed.
- A volume that a running sandbox mounts can be exported, but it is read while the sandbox may write: the archive is not a
  point-in-time copy. Stop the sandboxes first when you need a consistent copy.
- The first chunk is read before the response starts, so a missing volume is a 404 and not a broken body. A read that
  fails after the first bytes ends the body early. The export carries no checksum or trailer, so a client cannot tell a
  truncated body from a complete one except by checking the gzip stream (`gzip -t`) or the tar.
- A restore that starts while an export still streams the same volume is refused with 409 `CONFLICT`
  (`DriverConflict`: the export's helper still references the volume) and changes nothing
  (`tests/test_docker_volume_transfer_r67.py`, `test_clear_is_refused_while_a_container_still_mounts_the_volume`).
- Known race: the "not mounted" check and the claim that blocks a second restore are per server process. A sandbox
  created right after the scan can mount the volume while the restore runs (the same window a volume delete has). Do
  not create sandboxes that mount a volume while you restore it.
- Recovery after a failed restore: the volume exists, is empty, and keeps its id, name and labels. Restore again, or
  restore from an export you took earlier. There is no automatic rollback.

## Status notice

`GET /v1/status` is public (no API key) and answers, in the usual envelope:
`status` (`ok` or `degraded`), `version` (the installed package version, `unknown` without
package metadata), `build_sha` (`null` when unset), `started_at` (when this process started,
UTC) and `notice` (`null` or `{message, updated_at}`). It is declared in the OpenAPI document
without a security scheme. The Python SDK reads it with `client.status()`. `HEAD /v1/status`
answers 200 with the status and headers of the `GET` answer, content length included, and no
body, for uptime probes; it is not listed in the OpenAPI document.

Two settings feed it (`src/sandfort/config.py`, `src/sandfort/api/routes/health.py`):

| Variable | Default | Effect |
|---|---|---|
| `SANDFORT_BUILD_SHA` | empty | The commit of the running build, shown as `build_sha`. Empty reports `null`. Set it from the image build or the deploy pipeline. |
| `SANDFORT_STATUS_NOTICE_FILE` | empty | Path of a text file with the operator notice. Empty means no notice feature. |

The notice file is read on every request, so editing it takes effect at once and needs no restart:

- A missing or empty (after trimming) file means no notice; `status` stays `ok`.
- Only the first 2048 bytes are read, decoded as UTF-8 (invalid bytes are replaced) and trimmed.
- If the text starts with `degraded:` the prefix is removed from `message` and `status` becomes
  `degraded`. Any other text is a plain notice and `status` stays `ok`.
- `updated_at` is the file's modification time, so touching the file changes it.
- A file that exists but cannot be read (for example a permission error) is logged as a warning
  and treated as no notice.

```bash
echo "degraded: upgrading the node, sandboxes restart between 14:00 and 14:30 UTC" \
  > /etc/sandfort/notice/notice.txt        # post
: > /etc/sandfort/notice/notice.txt        # clear (or delete the file)
```

The path is the container path used on the hosted beta (next paragraphs); set
`SANDFORT_STATUS_NOTICE_FILE` to wherever your deployment puts the file.

In Kubernetes, mount the file from a ConfigMap or a volume that the api pod can read and point the
variable at the mounted path. Note that a ConfigMap mounted as a volume updates after a delay, and
that a `subPath` mount does not update at all.

On the hosted beta (the compose VM) the notice lives in the file
`/home/sandfort/sandfort-notice/notice.txt` on the VM. It is mounted read-only into the `api`
container at `/etc/sandfort/notice/notice.txt`, and `SANDFORT_STATUS_NOTICE_FILE` in the beta
compose overlay names that path. The overlay is operator tooling outside this repository. The
bind mount is the directory `/home/sandfort/sandfort-notice` mounted at `/etc/sandfort/notice`
(read-only), not the single file, so replacing the file inside it with an editor or `sed -i` is
safe: the container sees the new inode. Edit the file on the VM: a `degraded:` prefix marks an
incident, and an empty or missing file means no notice. On the VM, post with
`echo "degraded: <what and when>" > /home/sandfort/sandfort-notice/notice.txt` and clear with
`: > /home/sandfort/sandfort-notice/notice.txt`. The repository's production compose file
(`deploy/compose.prod.yml`) intentionally carries no notice wiring, so without an overlay like
that one the feature is off.
<!-- Rewrapped in round 40 -->

### Deploy notice practice

The hosted beta's guide tells partners that the operator sets a notice before planned deploys, so
follow this order for a planned deploy or upgrade (the "Upgrade and rollback" steps above):

1. Before you roll the pod, write a `degraded:` notice that says what happens and when, for
   example "upgrading the node, sandboxes restart between 14:00 and 14:30 UTC". A plain notice
   without the prefix keeps `status` at `ok`; use the prefix when sandboxes or calls will be
   interrupted.
2. Wait two minutes after writing the notice, so partners who poll `GET /v1/status` can see it
   before the API restarts. The deploy script performs this wait itself (`NOTICE_LEAD_S`,
   default 120 seconds); when you deploy by hand, wait at least that long.
3. Deploy. A recent `started_at` in `GET /v1/status` then shows partners that the process
   restarted, and `build_sha` shows which build runs.
4. When the deploy is done and checked (`/readyz`, one sandbox create), clear the notice by
   emptying or deleting the file.

The notice and wait automation lives in the maintainer's deploy tooling, outside this
repository. A deploy by hand does not get it: do the first two steps (write the notice, wait)
yourself before the restart.

The notice is written by hand and read per request; the server cannot tell a planned deploy
from an unplanned restart, and an unplanned one has no notice until you write it. Partners are
told that absence of a notice is not a guarantee (the beta has no SLA).

## Where to look

- Metrics: `GET /metrics` on the api (Prometheus text format, no authentication, keep
  it cluster-internal). It includes HTTP, job, driver, queue depth and webhook delivery
  metrics; the full list and the example alerts are under "Monitoring and alerting".
- Logs: structured JSON on stdout with request ids:
  `kubectl -n sandfort logs deploy/sandfort-api`. The `kubectl` commands in this runbook apply
  to the Kubernetes deployment only; the hosted beta runs under docker compose on a VM, where
  the equivalent is `docker compose -f deploy/compose.prod.yml logs api`.
- Audit trail: the audit API routes list who did what per org; the same rows are in
  the database audit table. A failed create or start is the row `sandbox.failed` (see "The
  `sandbox.failed` audit row"). For a lost API key see "Recovering a lost API key: `create-key`".
- Probes: `/readyz` checks the database and the Docker driver; a failing readiness
  probe names the failing component in the error details.

## MCP server

`mcp_server/sandfort_mcp.py` is a stdio MCP server that exposes sandboxes as tools
(`create_sandbox`, `run_code`, `run_command`, `upload_text_file`, `download_text_file`,
`list_sandboxes`, `delete_sandbox`, `create_snapshot`) to any MCP client. It needs the
`mcp` package (the dev extra) and two environment variables:

- `SANDFORT_BASE_URL`: the Sandfort server url.
- `SANDFORT_API_KEY`: an API key (`sf_...`).

The server exits with an error on stderr if either is missing. Register it with a client
using the command line below (adjust paths), for example in an `mcpServers` entry:

```json
{
  "mcpServers": {
    "sandfort": {
      "command": "/path/to/sandfort/.venv/bin/python",
      "args": ["/path/to/sandfort/mcp_server/sandfort_mcp.py"],
      "env": {"SANDFORT_BASE_URL": "http://127.0.0.1:8000", "SANDFORT_API_KEY": "sf_..."}
    }
  }
}
```

Tool errors from the SDK are returned as `error: <message>` text, and files over 1 MiB are
not returned by `download_text_file`. stdout carries the protocol; logs go to stderr.
