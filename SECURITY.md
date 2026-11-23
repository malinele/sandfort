# Security policy

## Reporting a vulnerability

Report a suspected vulnerability privately. Do not open a public issue, pull request or
discussion, and do not post details anywhere public.

Use one of these channels:

- Email `office@sandfort.dev`. This is the public contact address for Sandfort and the
  channel for anyone who does not have one of the channels below. Put "Security" in the
  subject line and keep the details out of any public place.
- The security or support contact in your pilot (design-partner) agreement, if you have one.
- The maintainer's private channel that you were given when you got access to Sandfort, if
  you have one.
- Once the repository is public, GitHub private vulnerability reporting is an additional
  channel. It is not available before then.

This repository does not publish a key for encrypted reports. If you need an encrypted
channel, say so in a first message to `office@sandfort.dev` that contains no details, and
agree on one before you send them.

Include what you can:

- the Sandfort version or commit, and the deployment (self-hosted, or the hosted beta);
- the isolation tier of the sandbox involved (`container`, `gvisor` or `microvm`);
- the steps to reproduce, and the impact you observed;
- whether you have shared the finding with anyone else.

Sandfort is a design-partner project with no support SLA, so there is no committed response
time. Reports are handled on a best-effort basis.

## Scope

In scope, for a supported version:

- Escape from a sandbox to the host, to the Docker daemon, or to another sandbox, including
  reaching the network ranges that `deploy/host-setup.sh` is meant to block.
- Access across organizations: reading or changing another org's sandboxes, snapshots,
  volumes, keys, usage, audit rows or webhooks.
- Authentication or authorization bypass: API keys and their scopes, label-scoped keys, user
  sessions, OIDC SSO exchange, SCIM tokens, role checks.
- Platform secrets reaching a sandbox (for example `SANDFORT_*` variables, the API key
  pepper or git credentials).
- Bypass of the egress allowlist, the preview proxy, webhook SSRF protection, or the
  per-sandbox resource and disk limits.
- Forging, hiding or silently altering audit rows in a way `audit-verify` does not report
  beyond the limits stated in `docs/security.md` section 5.

Out of scope:

- Behavior that `docs/security.md` and `docs/isolation-tiers.md` already state as a limit:
  the `container` tier shares the host kernel, gVisor is a user-space kernel and not a
  hardware boundary, the DNS side channel on the `container` tier with an allowlist, the
  unauthenticated `/metrics` endpoint, the plain-HTTP node-to-node hop in multi-node routing,
  and the fact that the audit log is tamper-evident, not immutable.
- Control of a sandbox node by someone who already has access to its Docker socket or its
  host, and a malicious operator or database administrator.
- The Firecracker driver, which is a skeleton and is not supported.
- Findings that need a misconfigured deployment which the runbook warns against, such as
  exposing node ports 8000 and 8001 or `/metrics` to untrusted networks.
- Vulnerabilities in third-party dependencies, Docker, gVisor or Kata with no Sandfort-specific
  impact. Report those to the upstream project.
- Social engineering and physical attacks.

Test only against your own deployment, or against the hosted beta organization you were
invited to. The hosted beta is a shared evaluation instance: do not run tests that could
disrupt other evaluators, and do not put production secrets or sensitive data on it.

## Supported versions

| Version | Supported |
|---|---|
| Latest `v0.1.0-beta.N` tag | Yes |
| Any other version | No |

The package version is `0.1.0`, and beta releases are tagged `v0.1.0-beta.N` on the exact
deployed commit (`docs/beta-terms.md` section 5). Only the latest beta tag is supported.
Sandfort has no certifications (no SOC 2 report, no ISO 27001 certificate, no third-party
penetration test).

## More information

`docs/security.md` describes the threat model, the isolation controls, authentication, audit
tamper evidence and a hardening checklist for operators. `docs/operations.md` is the
operations runbook.
