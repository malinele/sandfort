# Roadmap

## Where the product is

Phases 1-6 and 9-11 are complete. Phases 7 and 8 are still marked in progress in CHANGELOG.md, and a hardening phase is in progress.

The product today is a self-hosted sandbox platform with a REST API, a Python SDK, and a
CLI. It uses a Docker driver, supports multi-tenant governance, provides OIDC single
sign-on, and includes a Kubernetes kit.

## Design stance

A sandbox lives on one node. The multi-node MVP exists: a node registry with heartbeats,
placement at create, node affinity, and cross-node toolbox routing.

- **Placement at create.** A create is placed on the least loaded active node that has a fresh
  heartbeat and free capacity. With an empty registry it lands on the local node, so a single
  host behaves as before.
- **The sandbox stays there.** After placement, the jobs, auto-stop, reconciler and garbage
  collection of a sandbox run on the node that owns it. There is no rescheduling and no live
  migration. A node with no heartbeat for 90 seconds is `stale` and receives no new sandboxes;
  toolbox requests for its sandboxes answer 503 `NODE_UNAVAILABLE` (reason `stale`).
- **API and workers scale horizontally.** Any `api` process accepts a toolbox request and
  forwards it once to the owning node, so clients use one server URL.
- **Capacity is per node.** `SANDFORT_NODE_MAX_SANDBOXES` is the maximum a node advertises for
  placement; it is an input to placement, not a hard cap. The operations runbook describes
  sizing and the multi-node layout (`docs/operations.md`, "Multi-node").

What remains open:

- Multi-node needs jobs mode (`SANDFORT_SANDBOX_JOBS_ENABLED=true`), which refuses creates that
  mount volumes or use an egress allowlist, and has no sandbox reset.
- The forwarding hop is plain HTTP, so nodes need a private network.
- Container logs, the preview proxy and the web terminal page stay node-local.
- The Kubernetes kit covers one sandbox node; a multi-node deployment needs your own `api` and
  `worker` manifests.
- Per-org caps on terminals and async commands are counted per node.
- Rescheduling, live migration and rebalancing of running sandboxes are not planned.

## Near-term: the current phase

The remaining hardening items are:

- Webhook signing secrets encrypted at rest.
- Concurrent webhook dispatch.
- Per-org caps on live streams and terminals.
- User-namespace remapping guidance.

Done in this phase:

- Cross-node toolbox routing (2026-11-02): exec, filesystem and terminal requests reach the
  node that owns the sandbox without a router in front of per-node api instances.
- SCIM provisioning (2026-11-02): an identity provider manages the members of one org through
  SCIM 2.0 Users with a per-org bearer token (no groups, no bulk, no etag).

The phase also includes exposing single sign-on and member administration through the Python
SDK and the CLI. It also includes a TypeScript SDK covering the core agent workflow.

## Later: explicitly unscheduled

The following items are explicitly unscheduled:

- Rescheduling or live migration of sandboxes between nodes.
- A second production driver.
- Certifications.

None of these is a commitment. No dates are set for these items.

Design partners can help shape these priorities; reach the maintainer to discuss them.
