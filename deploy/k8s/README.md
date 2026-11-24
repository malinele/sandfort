# Sandfort on Kubernetes: single sandbox node

This kit deploys Sandfort in one topology, and only that one:

- **One dedicated sandbox node** running **one pod** with `SANDFORT_ROLE=all` (API, background
  workers and preview proxy in one process).
- The pod is host-networked (`hostNetwork: true`, `dnsPolicy: ClusterFirstWithHostNet`). Sandbox
  networks are created with `icc=false`, so only the node itself can reach sandbox ports. A pod on
  the cluster network cannot, and the preview proxy would answer `BAD_GATEWAY`.
- It mounts the node's Docker socket, which gives control of the whole node. The pod is therefore
  pinned to a node labelled `sandfort.dev/sandbox-node=true` that carries a matching `NoSchedule`
  taint, and the namespace is labelled for privileged Pod Security.
- Replicas are fixed at 1 with `strategy: Recreate`, because the pod binds node ports 8000 and
  8001. There is no separate worker pod (see the comment in `worker.yaml`).
- The state is in Postgres. Containers live on the node and are rebuilt by the reconciler.

Not covered: multiple sandbox nodes (see "Multi-node" in `docs/operations.md`), the egress
allowlist proxy (`python -m sandfort.egress.proxy`; allowlisted creates are refused without it),
Kata (`microvm` tier), and scraping configuration (ServiceMonitor).

## Prerequisites

1. **The sandbox node.** Linux with Docker (iptables backend), gVisor's `runsc` registered as a
   Docker runtime, and Docker's data directory on XFS mounted with project quota (`prjquota`).
   Check it with `sh deploy/node-setup.sh` on the node (it changes nothing). It prints the Docker
   socket group id (set `supplementalGroups` in `api.yaml` to it) and the label and taint commands:

   ```sh
   kubectl label node <node> sandfort.dev/sandbox-node=true
   kubectl taint node <node> sandfort.dev/sandbox-node=true:NoSchedule
   ```

2. **Host firewall.** Run `sudo sh deploy/host-setup.sh` on the node after Docker starts and after
   every reboot (for example a systemd unit ordered `After=docker.service`). It blocks sandbox
   traffic to cloud metadata and private ranges. In `prod` the egress probe is the gate: at
   startup a canary container on each managed network tries to reach targets it must not, and
   the server refuses to start if any succeeds. The probe needs `SANDFORT_EGRESS_PROBE_IMAGE`
   (default `alpine:3.20`) on the node. `SANDFORT_EGRESS_ACKNOWLEDGED: "true"` is only an
   override that downgrades a probe refusal to a logged warning. It is **not** preset in
   `configmap.yaml`; add it only knowingly, never as a substitute for running the script.

   The script expects the bridge interfaces the Docker driver creates with fixed names: `sf-br0`
   for the `sf-net` network and `sf-br1` for the `sf-egress-net` network (allowlist sandboxes).
   It creates the networks itself if they do not exist yet, with the same names, and reuses
   existing ones. A network recreated under a generated `br-<id>` name would match no rule.
   **Isolation choices for `prod`.** The kit maps the container tier to `runc` and sets neither
   `SANDFORT_ALLOW_ROOT_SHARED_KERNEL` nor `SANDFORT_REQUIRE_BUILD_RUNTIME=false`, so with the
   defaults a `prod` start is refused by two gates until you choose:

   - *Root on runc* (container root is host root on a runc tier without user-namespace
     remapping): enable remap in the node setup (`sudo bash deploy/node-setup.sh
     --userns-remap`, a maintenance window, see "Daemon settings beyond node-setup.sh" in
     `docs/operations.md`), or knowingly add `SANDFORT_ALLOW_ROOT_SHARED_KERNEL: "true"` to
     `configmap.yaml` and accept that risk.
   - *Build runtime* (tenant image builds run on the daemon default runtime): set the daemon
     default to `runsc` (`--default-runtime-runsc`), or knowingly add
     `SANDFORT_REQUIRE_BUILD_RUNTIME: "false"`.

   Run `python -m sandfort.admin_cli doctor` with the pod's environment to see these findings
   before the rollout. The doctor does not check host capacity or the driver.
3. **Postgres 16** reachable from the node, with a URL of the form
   `postgresql+asyncpg://sandfort:<password>@<host>:5432/sandfort`.
4. **The image**. `api.yaml` names the published image `ghcr.io/malinele/sandfort:v0.1.0-beta.81`
   (public, anonymous pull). To deploy another build, build `deploy/Dockerfile`, push it to a
   registry the node can pull from, and change the tag in `api.yaml` (or pin it in
   `kustomization.yaml`).
5. **Cluster add-ons you use**: an ingress controller (the examples are for ingress-nginx and a TLS
   secret), a CNI that enforces NetworkPolicy on host-networked pods if you rely on
   `networkpolicy.yaml`, and the Prometheus Operator CRD for `prometheusrule.yaml`.
6. **Placeholders to replace** in `configmap.yaml` and `ingress.yaml`: the public hostnames, the
   preview domain (its first label must be `preview`), `SANDFORT_FORWARDED_ALLOW_IPS` (pod CIDR or
   the ingress controller's addresses), and the node capacity values for your hardware.
   `SANDFORT_HOST_CAPACITY_CPU_MILLICORES` and `SANDFORT_HOST_CAPACITY_MEMORY_MIB` are required in
   `prod` (the server refuses to start with either at zero); the values in the file are
   placeholders. `SANDFORT_ALLOW_UNBOUNDED_HOST: "true"` starts without a host-wide limit and is
   not preset.

## Apply order

```sh
# 1. Namespace and secrets
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n sandfort create secret generic sandfort-secrets \
  --from-literal=SANDFORT_API_KEY_PEPPER="$(openssl rand -hex 32)" \
  --from-literal=SANDFORT_SESSION_SECRET="$(openssl rand -hex 32)" \
  --from-literal=SANDFORT_DATABASE_URL="postgresql+asyncpg://..." \
  --from-literal=SANDFORT_WEBHOOK_SECRET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

# 2. Migrations, before the first rollout (one-off pod from the same image;
#    see docs/operations.md, "Upgrade and rollback"). The pod command overrides the
#    image default, so nothing else applies migrations:
#    python -m sandfort.admin_cli migrate

# 3. Everything else. The load restrictor is lifted so kustomize can read deploy/seccomp.json,
#    which lives outside this directory.
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k8s | kubectl apply -f -

# 4. Watch the rollout
kubectl -n sandfort rollout status deploy/sandfort-api
```

Keep the pepper stable: changing it invalidates every issued API key. Keep the secret values in
your secret manager.

If the Prometheus Operator CRD is missing, the apply reports an error for `PrometheusRule` after
creating the rest; remove `prometheusrule.yaml` from `kustomization.yaml` in that case.

## Operating notes

- **Sandboxes are not pod resources.** `resources` in `api.yaml` cover the server process only.
  Sandboxes are Docker containers outside the pod's cgroup. Bound them with
  `SANDFORT_HOST_CAPACITY_*` and org quotas. `SANDFORT_NODE_MAX_SANDBOXES` is only the node's
  advertised maximum for multi-node placement and refuses no create (see "Capacity and sizing"
  in `docs/operations.md`; no sizing figure is published).
- **Shutdown.** `terminationGracePeriodSeconds: 30` is longer than the driver's 10 second drain.
- **NetworkPolicy.** Most CNIs do not enforce it on host-networked pods, and it cannot match the
  `/metrics` path (served unauthenticated on port 8000). Restrict node ports 8000 and 8001 in the
  node firewall as well, and keep `/metrics` unpublished at the ingress.
- **Probes.** Startup and liveness use `/healthz`; readiness uses `/readyz` (database and Docker
  driver).
- **Changing the seccomp profile** (`deploy/seccomp.json`) changes the generated ConfigMap name and
  rolls the pod. The profile applies to the container tier only, not to gVisor.
- Upgrade and rollback, backup and restore (including the node data a database dump does not
  cover), monitoring, capacity and the Docker driver thread limits are in
  `docs/operations.md`.
