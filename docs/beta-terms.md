# Hosted beta: terms

These are the terms of the Sandfort hosted beta. They were set by the operator on 2026-11-08,
amended on 2026-11-23 (operator identification in section 7, the personal-data rule in
section 4 and the privacy notice in section 10), and
apply to every organisation that uses the hosted beta: design partners and clients who request
access on their own. The beta is a shared evaluation instance at
`https://api.sandfort.dev`, invite-only, run by the maintainer. The beta is served only at
`sandfort.dev` (`api.sandfort.dev`, `docs.sandfort.dev`, `sandfort.dev` and
`*.preview.sandfort.dev`). A future change of an endpoint gets at least 30 days' notice via the
status notice and the support address (`office@sandfort.dev`). In production
Sandfort runs self-hosted on your own infrastructure. How to connect and use the API is in
the [connect guide](https://docs.sandfort.dev/guide.html).

## 1. Pricing

The hosted beta is free of charge for the whole beta period. Paid plans come after the beta, once
the market is understood. No prices are quoted in this document or anywhere else in the beta
material.

## 2. Availability

- There is no uptime guarantee during the beta. The beta runs on one VM in one region and is
  operated on a best-effort basis.
- Planned deploys are announced through the status notice (`notice` in the answer of
  `GET /v1/status`, which needs no API key) at least two minutes before the API restarts.
- A restart takes under a minute. Running sandboxes keep running through it.
- The running build is identified by `build_sha` in the same `GET /v1/status` answer. A recent
  `started_at` in that answer shows that the server restarted.
- An unplanned restart or outage has no notice until the maintainer writes one.

```bash
curl -s https://api.sandfort.dev/v1/status
```

## 3. Support

- The support contact for every beta organisation is `office@sandfort.dev`.
- The response target is the next business day (Monday to Friday, CET). It is a target on a
  best-effort basis, not a guarantee.
- Include the `request_id` of the failing call. Every error answer carries it as
  `error.request_id`, and every response has it in the `x-request-id` header. You cannot read the
  server logs; the maintainer finds the call by that id. Also send the time, the sandbox id, what
  you expected and what happened.

## 4. Data

- Sandboxes are ephemeral: nothing in a sandbox survives its deletion, and a stopped sandbox is
  not guaranteed to be restartable after a host change. Do not keep state in a sandbox you
  cannot recreate. Until it is deleted, a stopped sandbox keeps its files and its environment
  values.
- `auto_delete_minutes` defaults to never (`-1`), and `auto_stop_minutes` defaults to 15. Set
  `auto_delete_minutes` (and `auto_stop_minutes`) on every sandbox you do not want to keep, so
  stopped sandboxes do not pile up.
- Snapshots and volumes persist until you delete them.
- An organisation's data is deleted on request within five business days. Audit events are
  deleted together with the organisation's data, so export them first with
  `GET /v1/audit-events/export`. Audit events on the beta are not pruned (the retention setting
  is unset, which means off); they stay until the organisation's data is deleted on request.
- Image build logs echo the build steps, including `ENV` values, to every API key of the
  organisation, so image specs must not carry secrets.
- The hash chain of the audit events is verifiable with `GET /v1/audit-events/verify`. Export and
  verify need the `audit:read` scope and an organisation-wide key (a key with `sandbox_labels`
  gets 403).
- Do not process production secrets or sensitive data in the beta.
- Do not put personal data of any person into sandboxes, files, snapshots, volumes, image specs
  or environment values; use synthetic data instead. The beta is an evaluation instance and
  comes with no data-processing agreement, so content you run on it must not contain personal
  data. The personal data the operator itself keeps about you is listed in section 10.

## 5. Releases

- Every deployed build is tagged `v0.1.0-beta.<round>` on the exact commit. No document in the
  repository names the current tag, because a file inside the tagged commit cannot name its own
  tag and would always be one deploy behind. Read the deployed build from `GET /v1/status` as
  `build_sha`. It must equal the commit of the newest `v0.1.0-beta.<round>` tag (peel annotated
  tags to their commit with `git rev-parse <tag>^{commit}`). The release note of your delivery,
  the plain-text file `RELEASE.txt`, names the same tag and commit.
- Without a repository checkout, compare `build_sha` from `GET /v1/status` with the commit named
  in `RELEASE.txt`, the release note delivered next to your wheels; the tag-peel instruction
  above is for readers who have a checkout.
- From `v0.1.0-beta.40` on, the SDK reports its own build:
  `import sandfort_sdk; sandfort_sdk.build_info()` returns the commit, the tag and the build time
  of the wheel (`commit`, `tag`, `built_at`). All three are `None` for a source checkout without
  the build file.
- No container image is published yet. The API is built from the tagged commit (compose on the
  host, `deploy/compose.prod.yml`).
- The SDK and the CLI ship as wheels built from the same tag.
- The wheels come with two more files: `SHA256SUMS` (the SHA-256 checksums of the files you
  receive) and a plain-text release note, `RELEASE.txt`. The note names the commit and the build
  time; from `v0.1.0-beta.38` on it also names the tag. Verify the files before you install
  them, in the directory that holds them: `shasum -a 256 -c SHA256SUMS`. Every line must print
  `OK`.

## 6. Isolation

- Isolation is chosen per sandbox with the `isolation` field of `POST /v1/sandboxes`. The tiers
  are `container`, `gvisor` and `microvm`; `GET /v1/isolation` returns the default and the tiers
  available on the instance.
- `gvisor` is the default isolation tier of the beta (the deployment sets
  `SANDFORT_DEFAULT_ISOLATION=gvisor`). A create that names no tier gets `gvisor`.
- The `microvm` tier (Kata Containers on the beta VM's nested KVM) is the hardware-virtualization
  tier for evaluation. If `GET /v1/isolation` does not list it for your organisation, ask the
  maintainer.
- The Firecracker driver in the repository is a skeleton tested against a mock agent. It is not a
  tier and is not offered on the beta.
- The limits of each tier (shared host kernel on `container`, a user-space kernel on `gvisor`, a
  virtualized host for `microvm`) are on the
  [isolation tiers page](https://docs.sandfort.dev/isolation-tiers.html). The beta is a shared
  evaluation instance either way, so do not run your highest-risk code on it.

## 7. Operator

- The operator of the hosted beta is Polygon Consulting d.o.o. Beograd-Savski Venac, Kozara 1,
  Beograd (Savski Venac), Serbia, registered with the Serbian Business Registers Agency (APR),
  company registration number (matični broj) 21466352, tax identification number (PIB)
  111345107.
- The contact for support, security reports and requests under these terms is
  `office@sandfort.dev`.
- The copyright in the Sandfort code stays with its author, Nenad Mitrovic, as stated in
  `LICENSE.md`. The operator runs the hosted instance; it does not own the code by running it.

## 8. Acceptable use

- Run only code and data you are allowed to run.
- Do not use the instance to attack systems you do not own or have no permission to test, to
  scan networks, to mine cryptocurrency, to send spam, or to host or distribute illegal content.
- The beta is a shared instance. The operator may revoke a key, stop sandboxes or suspend an
  organisation at once when its use endangers the instance or other organisations, and tells you
  at the contact address you gave.
- Sandboxes have open outbound network access by default. Use `egress_allowlist` or
  `block_network` when your code does not need the network.

## 9. Operator access

- The operator holds an organisation-wide key for every organisation on the beta. With it the
  operator can read and manage the organisation's sandboxes, files, audit events and keys.
- The operator uses that access to run the beta: quota changes, support you ask for, abuse
  handling under section 8 and offboarding. Audit events record calls made with that key like
  any other call.
- Your own keys do not carry this access. A key issued to you cannot change the organisation's
  quota.

## 10. Personal data

This section is the privacy notice for the hosted beta under the Serbian data protection act
(Zakon o zaštiti podataka o ličnosti, "ZZPL").

- Controller: the operator named in section 7, Polygon Consulting d.o.o. Beograd-Savski Venac,
  Kozara 1, Beograd (Savski Venac), Serbia (matični broj 21466352, PIB 111345107). Privacy
  requests go to `office@sandfort.dev`.
- What is kept: the contact details you send (name, work email, organisation name); the name and
  email of members your admin adds through the members API or SSO; and the IP address and user
  agent of every API call, which are recorded in your organisation's audit events and in the
  server logs on the beta VM.
- Purpose and legal basis: the operator uses this data to run the beta, to answer you, and for
  the security and abuse handling in section 8. The legal basis is the operator's legitimate
  interest (ZZPL čl. 12 st. 1 t. 6) in operating and securing a shared B2B evaluation service;
  you can object to that processing (see rights below). Giving contact details is a condition
  for getting a beta key.
- Recipients: the hosting provider Hetzner Online GmbH (the beta VM runs in Finland, in the EU)
  and Google (Google Workspace handles mail to and from `office@sandfort.dev`). The operator
  makes no other disclosure.
- Transfer abroad: the data is stored on the beta VM in Finland. EU member states count as
  adequate destinations under Serbian law (ZZPL čl. 64), so the transfer needs no separate
  approval.
- Retention: contact details and audit events are kept for as long as the organisation is on
  the beta (section 4). Server logs stay on the beta VM, are not archived anywhere else, and
  are gone at the latest when the beta VM is rebuilt or the beta ends.
- Your rights under ZZPL čl. 26-37: access, rectification, erasure, restriction, objection to
  legitimate-interest processing, and portability. Write to `office@sandfort.dev`; the operator
  answers within 30 days, in practice within five business days. You can also complain to the
  Serbian supervisory authority, the Poverenik za informacije od javnog značaja i zaštitu
  podataka o ličnosti (`www.poverenik.rs`).
- On request the operator deletes your contact details and your organisation's data (section 4).
  Automatic deletion of an organisation's data waits for an operator command that does not exist
  yet (`delete-org`). Until it does, the operator deletes the data on request by hand: it revokes
  the keys, deletes sandboxes, snapshots and volumes, and removes the organisation as far as the
  audit hash chain allows. Export your audit events first (section 4).

## 11. No warranty

- The hosted beta is provided as is, without warranty of any kind, express or implied, and
  without any service level.
- To the extent the law allows, the operator is not liable for loss of data, downtime or any
  other loss that comes from using the beta.
- The SDKs and the CLI are licensed under Apache-2.0 and the server under FSL-1.1-Apache-2.0.
  Those licenses cover the software, not this hosted service, and this section does not rely on
  them.
