# SCIM user provisioning: design decision

Status: implemented (all ten delivery slices; status checked against the code on 2026-11-10).
This was a decision document for the first phase-ten package. It names a mechanism, its
failure modes and the delivery slices; the sections below keep the original design text,
including the "What exists today" and "The gap" descriptions of the code before this work, and
"Implementation status" says what exists now.

## Implementation status (2026-11-10)

Implemented, with sources:

- Routes under `/scim/v2` for Users: list (with `userName eq`, `startIndex`, `count`), get,
  create, replace, patch, delete, plus `ServiceProviderConfig`, `ResourceTypes` and `Schemas`
  discovery (`src/sandfort/api/routes/scim.py`, `src/sandfort/api/scim/`). Every mutation goes
  through `UserAdminService`, so the last-admin guard, the role ceiling and the audit record
  apply (`src/sandfort/services/user_admin.py`).
- Per-org SCIM bearer tokens: `POST`, `GET` and `DELETE` under `/v1/org/scim-tokens`, stored
  as a hash, shown once, valid on SCIM paths only, at most five active per org
  (`src/sandfort/api/routes/scim_tokens.py`, `src/sandfort/services/scim_tokens.py`,
  `src/sandfort/auth/scim.py`).
- Storage: `scim_tokens` table and an `external_id` on the membership
  (`src/sandfort/migrations/versions/r0010_scim.py`).
- Configuration: `SANDFORT_SCIM_ENABLED` (default off; when off neither the SCIM routes nor the
  token routes are mounted) and `SANDFORT_SCIM_DEFAULT_ROLE` (default `viewer`)
  (`src/sandfort/config.py`).
- Gate: `examples/gate10.py` plays Okta and Entra request sequences against a live server
  (CHANGELOG, phase 10, passed locally 2026-11-02).

Boundaries that hold today:

- SCIM covers Users only: no Groups, no Bulk, no ETag, no sorting, and the only filter is
  `userName eq`.
- The SCIM and SCIM-token routes are not in `openapi/sandfort.v1.json`
  (`_IN_SCHEMA = False`), so they are not counted in the operation and path counts taken from
  that spec. Identity providers read the discovery endpoints instead.
- There are no SCIM methods in the Python SDK, the TypeScript SDK or the CLI.
- SSO is still bound to one organization (`oidc_org_id`).

## 1. Goal and constraint

Goal: an identity provider (Okta, Microsoft Entra ID) creates, updates, re-roles and removes
the members of one Sandfort org through SCIM 2.0, so an enterprise identity team does not
call `/v1/org/members` from a script or edit members by hand.

Problem: member lifecycle is manual. `/v1/org/members` is an admin-key API with its own
envelope, ids and error codes; identity providers speak SCIM only. A person who leaves the
company keeps their membership until someone remembers to delete it. `docs/roadmap.md`
lists SCIM as unscheduled and the positioning documents say it does not exist.

### What exists today

- Members API: `api/routes/users.py` under `/v1/org/members` has create, list, patch (role
  only) and delete. Writes need `api_keys:admin`, listing needs `org:read`. All logic is in
  `UserAdminService` (`services/user_admin.py`): `create_member`, `list_members`,
  `change_member_role` and `remove_member`.
- Guards inside that service: the last-admin guard (`_ensure_another_admin`, `InvalidState`
  409), the role ceiling (`_require_grantable`: the caller must hold every scope in
  `role_scopes(role)`, else `ScopeEscalation` 403), one audit record per change written
  through `AuditRecorder` in the same unit of work (`user.created`, `membership.added`,
  `membership.role_changed`, `membership.removed`).
- Domain: `User` (`domain/user.py`) has `id`, `email`, `display_name`, `created_at` and
  `disabled_at`. `OrgMembership` has `user_id`, `org_id`, `role`, `created_at`. A user row is
  global: the same email is one user in many orgs (`UserRow.email` is unique). Nothing sets
  `disabled_at` today; `authenticate._session_principal` and `SsoService` only read it.
- Storage: `db/models/users.py` (`users`, `org_memberships` keyed by `(user_id, org_id)`),
  `db/repositories/users.py` (`SqlUserRepository`, `SqlMembershipRepository`). There is no
  column for an external identifier anywhere.
- Access cut-off: a session token is checked against the membership on every request
  (`authenticate._session_principal`), and the SSO exchange needs an existing membership.
  Deleting a membership therefore ends access at once.
- Credentials: `auth/api_keys.py` generates `sf_<env>_<prefix8>_<secret43>` keys stored as
  `v1$<salt>$<HMAC-SHA256(pepper, salt || key)>` and verifies in constant time.
  `auth/authenticate.py` resolves a key by prefix and writes `last_used_at` debounced.
  `services/api_key_admin.py` mints and revokes keys with scope attenuation.
- Errors: `errors.py` defines the taxonomy (`ValidationFailed` 400, `Unauthorized` 401,
  `Forbidden` 403, `NotFound` 404, `Conflict` 409, `InvalidState` 409). `api/errors.py`
  renders it into the Sandfort envelope for every route.
- Spec: `api/openapi.py` calls `app.openapi()` and writes `openapi/sandfort.v1.json`; a drift
  test (`tests/test_idempotency_openapi.py`) compares the committed bytes with a fresh
  export. FastAPI lists a route unless it sets `include_in_schema=False`. `api/routes/nodes.py`
  and `api/routes/console.py` use `_IN_SCHEMA = False` and the metrics route sets it inline,
  so the pinned spec stays valid without regeneration.
- Settings: `config.py` loads `SANDFORT_` variables with `text`, `integer` and `boolean`
  helpers and fails at startup on a bad value (see `ROUTING_SECRET` validation).
- Migrations: the newest is `migrations/versions/r0009_node_internal_url.py` (revision
  `0009`), a batch alter in the style used for SQLite.

### The gap

There is no SCIM surface, no credential an identity provider may hold without also holding
an admin key, and no place to store the identifier the provider assigns to a user.

## 2. Hard constraints

- No second implementation of member logic. Every SCIM mutation calls `UserAdminService`, so
  the last-admin guard, the role ceiling and the audit record hold unchanged.
- The SCIM credential works on SCIM paths only. On the rest of the API it is a plain 401.
  An admin API key or a session token does not work on SCIM paths either.
- The credential is stored hashed exactly like API keys, shown once, and never logged,
  never written to audit details, never echoed in an error.
- Fail closed. An unknown, revoked or wrong-org token, an unsupported filter or an
  unsupported patch operation is refused; nothing is guessed.
- Off by default. A deployment that does not enable SCIM mounts no route and pays nothing.
- No change to the pinned `openapi/sandfort.v1.json`.
- SCIM wire format is honored where identity providers check it: media type
  `application/scim+json`, the `urn:ietf:params:scim:api:messages:2.0:Error` body, the
  `ListResponse` envelope, string status codes in errors.
- Every new file stays under 400 lines (AGENTS.md); layers stay `api` over `services` over
  `auth` over `db` over `domain` (import-linter).

## 3. Candidate mechanisms

### (a) A SCIM 2.0 subset in the server, backed by `UserAdminService` (chosen)

A `/scim/v2` router serving `Users` plus discovery, a per-org SCIM bearer token, and a
single service entry point for all writes. See section 4.

Failure modes:
- Reactivation after deactivation looks like a new user to the provider (section 4,
  deactivation); a provider that insists on `PATCH active=true` for the old id gets 404.
- The token is a long-lived bearer secret. Anyone holding it can add members up to its
  `max_role`; the cap and revocation are the controls.
- Identity providers differ in small ways (boolean sent as a string, patch without `path`).
  The parser accepts the documented shapes only and refuses the rest with a SCIM error.
- A user row is global, so attributes of a user shared by several orgs cannot be rewritten
  by one org's provider; they are immutable after create (section 4).

### (b) Make `/v1/org/members` speak SCIM

Dismissed: it would break the pinned envelope and the SDK and CLI that use it, and SCIM
needs different status codes, ids in `Resources` and PATCH semantics.

### (c) Just-in-time provisioning in the OIDC exchange

Dismissed: it creates members at first login but never removes them, and the exchange is
deliberately limited to existing members (`services/sso.py`).

### (d) Full SCIM with Groups, Bulk and ETag

Dismissed for the first version: Groups need a group entity and a mapping to roles that the
domain does not have; Okta and Entra user lifecycle does not call Bulk; ETag is optional.

### (e) A separate bridge service that translates SCIM into `/v1/org/members`

Dismissed: a second deployable that must hold an admin API key with `api_keys:admin`, which
is more power than the provider needs.

### (f) Reuse ordinary API keys with a new `scim` scope

Dismissed: the scope catalog is a frozen enum (`domain/org.py`), and such a key would also
authenticate on every other route with whatever other scopes it carries.

### (g) Poll the directory (LDAP or a provider API) from a worker

Dismissed: it needs outbound credentials into the customer directory and a sync schedule,
the opposite of the push model both providers already implement.

## 4. Recommendation

Use (a): a SCIM 2.0 Users subset, one hashed per-org bearer token, one service entry point.

### Configuration

New fields on `Settings` (`config.py`), read with the existing `SANDFORT_` prefix:

- `SANDFORT_SCIM_ENABLED` (`scim_enabled`, default `false`), parsed by `boolean`. When
  false, neither the `/scim/v2` routes nor the token management routes are mounted.
- `SANDFORT_SCIM_DEFAULT_ROLE` (`scim_default_role`, default `viewer`): the role given to a
  created user whose request carries no role. Must be a value of `OrgRole`; anything else
  is a startup error. Least privilege is the default on purpose.

`scim_enabled` with an empty `api_key_pepper` is already impossible: the app refuses to
build without a pepper, and the token hash uses the same pepper. No new secret exists, so
there is nothing new to rotate or leak. Page size limits are constants, not settings.

### The SCIM token

- Table `scim_tokens` (new `db/models/scim_tokens.py`): `id` (`stk_` id), `org_id`, `name`,
  `prefix` (unique), `secret_hash`, `max_role`, `created_at`, `last_used_at`, `revoked_at`,
  `created_by`. There is no expiry; revocation is explicit.
- The token is produced by `generate_api_key(pepper, env="scim")`, so it looks like
  `sf_scim_<prefix8>_<secret43>`, and is stored and verified with `hash_api_key` and
  `verify_api_key` unchanged. No new crypto code.
- Why it is useless elsewhere: `authenticate` looks the prefix up in `api_keys`, finds
  nothing and answers 401. The SCIM dependency looks the prefix up in `scim_tokens` only, so
  an API key or session token is a 401 on SCIM paths.
- `max_role` is the role ceiling of the token. The management endpoint requires the minting
  admin to hold `role_scopes(max_role)` (attenuation, like `ApiKeyAdminService`).
- At most `MAX_ACTIVE_SCIM_TOKENS = 5` active tokens per org, so rotation (mint, switch the
  provider, revoke) works and the table stays bounded.
- `auth/scim.py` verifies the bearer token like `authenticate` does, including the dummy
  hash for an unknown prefix and the debounced `last_used_at` write, and returns a
  `Principal` with `org_id`, `key_id` set to the token id, and `scopes` set to
  `role_scopes(max_role)`. That principal exists only inside SCIM handlers. Because
  `UserAdminService` checks grants against `principal.scopes`, the ceiling is enforced by
  existing code: a token with `max_role` `developer` cannot create or promote an admin.
- If `app.state` carries a rate limiter (`RATE_LIMITER_ATTR`), the SCIM dependency in
  `api/routes/scim.py` takes one token from the bucket keyed by the token id, so a
  misconfigured provider loop answers 429.

### Token management

Under `/v1/org/scim-tokens`, standard envelope, `api_keys:admin` scope, mounted only when
enabled and kept out of the exported spec:

- `POST` with `name` and `max_role` returns the plaintext token once, plus its metadata.
- `GET` lists metadata (id, name, prefix, `max_role`, timestamps), never a hash.
- `DELETE /{token_id}` revokes; revoking a revoked token is idempotent and records no
  second audit event.

`services/scim_tokens.py` (`ScimTokenService`) mirrors `ApiKeyAdminService`. It writes audit
actions `scim_token.created` and `scim_token.revoked` with the name, prefix and `max_role`
in the details, never the token or its hash. These actions use `ActorType.API_KEY` with the
caller's key id, so `ActorType` and the audit schema do not change.

### Endpoints

All under the prefix `/scim/v2`, media type `application/scim+json` in both directions
(a request body sent as `application/json` or `application/scim+json` is parsed). Handlers
take the body as a plain mapping and the translators validate it, because provider payloads
vary and SCIM errors must name the problem in SCIM terms.

| Method and path | Meaning |
|---|---|
| `GET /Users` | list, `filter`, `startIndex`, `count` |
| `GET /Users/{id}` | one member of the token's org |
| `POST /Users` | create (201), existing member is 409 `uniqueness` |
| `PUT /Users/{id}` | replace the mutable attributes |
| `PATCH /Users/{id}` | partial update (200 with the resource) |
| `DELETE /Users/{id}` | remove the membership (204) |
| `GET /ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | static discovery |

Discovery requires the token too, so an anonymous caller learns nothing. An unknown path
under `/scim/v2` falls through to the ordinary 404 envelope.

### Attribute mapping

| SCIM | Sandfort | Notes |
|---|---|---|
| `id` | `User.id` (`usr_...`) | stable across deactivation cycles |
| `userName` | `User.email`, lowercased | immutable after create |
| `emails` | derived from `userName` | on input, a work or primary value must equal it |
| `displayName`, `name` | `User.display_name` | create only (immutable), see below |
| `active` | membership exists | see deactivation |
| `roles` | `OrgMembership.role` | one primary value from `OrgRole`; see below |
| `externalId` | `OrgMembership.external_id` | per org, see below |
| `meta` | `resourceType`, `created`, `location` | no `lastModified`, no version |

`displayName` is taken from `displayName`, else `name.formatted`, else given plus family
name, else the local part of `userName`. A user row is shared by every org the person
belongs to, so one org's provider must not rewrite it: an existing user keeps its display
name, a later replace or patch of `displayName`, `name` or `userName` is a no-op when the
value is unchanged and a 400 `mutability` when it differs. The schema document declares
these attributes `immutable`.

Roles: the resource exposes `roles` as a list with one entry, `{"value": "<role>",
"primary": true}`. On input the first entry with `primary` true (or the only entry) names
the role; its value must be `admin`, `developer` or `viewer`, else 400 `invalidValue`. More
than one distinct value is 400 `invalidValue`. No role on create means `scim_default_role`;
no role on replace keeps the current role (it never silently demotes).

### Deactivation: remove the membership, no flag

`active=false` (by PATCH or PUT) calls the remove path of the service; `DELETE` does the
same. The user row stays. Alternatives weighed:

- A disabled flag on the membership: keeps the role and lets `GET` show `active=false`, but
  needs a column and a new check in every path that grants access
  (`auth/authenticate.py`, `services/sso.py`, the last-admin count and `list_members`). One
  missed path keeps a deprovisioned person signed in. Rejected.
- `User.disabled_at`: already present, but it is global across orgs, so one org's provider
  would lock the person out of every other org. Rejected; SCIM never writes it.

Removal needs no new access code: a session token is checked against the membership on
each request, and the SSO exchange already needs one. A removed member's session stops
working at the next request. The migration for `externalId` (below) is needed either way;
the choice here is about not widening it.

Consequences, stated plainly: `GET /Users/{id}` after deactivation is 404; a repeat
deactivation is 404; the role is lost, so a reactivating `POST` carries it again (the
default is `scim_default_role`). Because the user row survives, a `POST` for the same
`userName` reuses the same `id`. The `PATCH` that deactivates answers 200 with the resource
as it was, `active` false. `active` on a listed member is true unless the global
`User.disabled_at` is set, in which case it reads false and `PATCH active=true` is 409.
API keys that the person created before removal are not revoked (non-goals).

### externalId

New nullable column `org_memberships.external_id` (`String(255)`), with a unique constraint
on `(org_id, external_id)` (NULLs do not collide). It is per membership, not per user,
because a user spans orgs that may use different providers. `OrgMembership` gains
`external_id: str | None = None`. A duplicate value in the org is 409 `uniqueness`. It is
set on create, replaced by PUT or PATCH, cleared by a PATCH `remove`, and dropped with the
membership on deactivation (the provider sends it again on reactivation). Changes record
audit action `membership.external_id_changed` with the old and new value. This is the one
schema change on existing tables, in migration `r0010_scim.py` (revision `0010`): it adds
the column and the constraint and creates `scim_tokens`.

### Filter and pagination

Only `userName eq "<value>"` is supported; attribute name and `eq` are matched
case-insensitively, the value is compared lowercased. Any other filter, `and`, `or`, `co`,
`sw` or an `externalId` filter is 400 `invalidFilter`. A match is looked up through a new
`UserAdminService.find_member_by_email`; no match is an empty `ListResponse`, not 404.

Without a filter the list is `list_members` (oldest membership first, stable), sliced in
memory: `startIndex` is 1-based (lower values are 1), `count` defaults to and is capped at
`SCIM_MAX_COUNT = 100`, `count=0` returns only `totalResults`. The envelope carries
`schemas`, `totalResults`, `startIndex`, `itemsPerPage` and `Resources`. In-memory slicing
is acceptable because an org's member list is small; a keyset query is a later change.

### PATCH shapes

Body `schemas` must contain `urn:ietf:params:scim:api:messages:2.0:PatchOp` and
`Operations` is a non-empty list. Operation names are matched case-insensitively. Three
shapes are accepted (Okta sends the value form without `path`, Entra sends `path`, and
boolean values may arrive as the strings `"True"` and `"False"`):

1. Replace active: `{"op": "replace", "path": "active", "value": false}` or
   `{"op": "replace", "value": {"active": false}}`.
2. Replace a top-level attribute: `path` or an object `value` naming `externalId`,
   `displayName`, `name` or `userName` (the last three follow the immutability rule).
3. Add or replace the role: path `roles`, value `[{"value": "viewer", "primary": true}]`,
   or path `roles[primary eq "True"].value` with a string value.

`remove` is accepted for `externalId` only. Everything else (other paths, other filters in
a path, `add` of other attributes, `remove` of other attributes) is 400 `invalidPath` or
`invalidValue`. All operations are parsed first, folded into one change, and applied in a
single unit of work, so a failing patch changes nothing (SCIM requires atomic patch).

### Service entry points

`UserAdminService` (`services/user_admin.py`) gains, additively:

- `create_member(..., external_id: str | None = None)`, keyword with a default, so the
  members API call sites are untouched.
- `get_member(org_id, user_id)` and `find_member_by_email(org_id, email)`, read only.
- `update_member(principal, user_id, *, role=None, external_id=UNSET, deactivate=False)`:
  one unit of work that applies role, external id or removal with the existing helpers
  (`_require_grantable`, `_ensure_another_admin`, `_audit`). `deactivate` ignores the other
  fields. `Member` gains `external_id`.

Repository changes are additive: `MembershipRepository` in `db/repositories/ports.py` gains
`set_external_id`, and `SqlMembershipRepository` maps the new field. The new
`ScimTokenRepository` joins `UnitOfWorkPort` and `UnitOfWork` as `scim_tokens`.

### Errors

`api/scim/errors.py` defines `ScimRoute`, an `APIRoute` subclass set as `route_class` on the
SCIM router. It wraps the handler (dependencies included) and turns exceptions into the SCIM
error body: `schemas`, `status` as a string, `scimType` where the RFC defines one, `detail`.

| Raised | HTTP | scimType |
|---|---|---|
| `Unauthorized` | 401 | none |
| `Forbidden`, `ScopeEscalation` | 403 | none |
| `NotFound` | 404 | none |
| `Conflict` (member exists, external id taken) | 409 | `uniqueness` |
| `InvalidState` (last admin) | 409 | none |
| `ValidationFailed`, request validation, bad JSON | 400 | `invalidValue`, `invalidSyntax` |
| unsupported filter, path, immutable change | 400 | `invalidFilter`, `invalidPath`, `mutability` |
| any other exception | 500 | none, generic detail |

`detail` is the message the service already produced. The 500 detail is generic; the cause
goes to the server log without the Authorization header or any token.

### Audit

Mutations record the audit events the service already writes, with the SCIM token id as
`actor_id`, in the same unit of work as the change. Reads are not audited, as with the
members API. Token creation and revocation are audited as above. The audit chain and
`audit-verify` are unchanged.

### Discovery

Static documents built from constants in `api/scim/discovery.py`, honest about the limits:
`ServiceProviderConfig` has `patch.supported` true, `bulk.supported` false, `filter`
supported true with `maxResults` 100, `changePassword`, `sort` and `etag` false, and one
authentication scheme of type `oauthbearertoken`. `ResourceTypes` lists `User` at `/Users`
only. `Schemas` lists the core user schema with the attributes in the mapping table and
their mutability. There is no `Group`, no enterprise extension, and the documents say so by
omission; the filter description names `userName eq` as the only supported form.

### OpenAPI export policy

The export decides inclusion through FastAPI: `build_document` calls `app.openapi()`, which
lists every route whose `include_in_schema` is not false. Policy: all `/scim/v2` routes and
all `/v1/org/scim-tokens` routes are excluded, with `_IN_SCHEMA = False` in
`api/routes/scim.py` and `api/routes/scim_tokens.py`, the same way `api/routes/nodes.py`
does it. Reasons: the committed `openapi/sandfort.v1.json` and the drift test stay valid
with no regeneration, the documented operation count does not change, and SCIM is described
by its own discovery endpoints, which is the contract identity providers read. A test
asserts that no exported path starts with `/scim` or `/v1/org/scim-tokens`. Including them
later is one flag flip plus an owner-side regeneration. Note that the export builds the app
with default settings, where SCIM is off, so the routes would be absent even without the
flag; the flag keeps the policy true when someone exports with SCIM enabled.

### Delivery slices

Each slice is at most five files, one contract, and ends with its gate.

1. Schema. Files: `src/sandfort/migrations/versions/r0010_scim.py`,
   `src/sandfort/db/models/scim_tokens.py`, `src/sandfort/db/models/users.py`,
   `src/sandfort/db/models/__init__.py`, `tests/test_scim_migration.py`. Gate: migration up
   and down on SQLite, the unique constraint rejects a duplicate `(org_id, external_id)` and
   allows two NULLs, and the existing `tests/test_db.py` still passes.
2. Token store. Files: `src/sandfort/domain/scim.py`,
   `src/sandfort/db/repositories/scim_tokens.py`, `src/sandfort/db/repositories/ports.py`,
   `src/sandfort/db/unit_of_work.py`, `tests/test_scim_token_repo.py`. Gate: add, get by
   prefix, list for org, revoke, touch last used; a token of another org is not listed;
   `mypy --strict src/sandfort` is clean.
3. Membership external id. Files: `src/sandfort/domain/user.py`,
   `src/sandfort/db/repositories/users.py`, `src/sandfort/db/repositories/ports.py`,
   `tests/test_membership_external_id.py`. Gate: round trip, set and clear, duplicate in
   one org conflicts, the same value in two orgs is fine; `tests/test_users.py` passes
   untouched.
4. Settings and token service. Files: `src/sandfort/config.py`, `src/sandfort/ids.py`,
   `src/sandfort/services/scim_tokens.py`, `tests/test_scim_config.py`,
   `tests/test_scim_token_service.py`. Gate: defaults off and `viewer`, a bad default role
   is a startup error; the token is shown once and only a hash is stored; attenuation
   refuses a `max_role` the minter lacks; the sixth active token is refused; revoke is
   idempotent and audits once; audit details never contain the token.
5. User admin extension. Files: `src/sandfort/services/user_admin.py`,
   `tests/test_user_admin_scim.py`. Gate: `update_member` is atomic (a refused role leaves
   the external id unchanged), keeps the last-admin guard and the role ceiling, audits each
   change, and `tests/test_users.py` and `tests/test_api_users.py` pass untouched.
6. Filter and patch parsing. Files: `src/sandfort/api/scim/__init__.py`,
   `src/sandfort/api/scim/filters.py`, `src/sandfort/api/scim/patch.py`,
   `tests/test_scim_filters.py`, `tests/test_scim_patch.py`. Gate: pure unit tests for
   `userName eq`, every refused filter, the three patch shapes from both providers
   including the string booleans, atomic folding, and every refused operation.
7. Resources, errors, discovery. Files: `src/sandfort/api/scim/resources.py`,
   `src/sandfort/api/scim/errors.py`, `src/sandfort/api/scim/discovery.py`,
   `tests/test_scim_resources.py`, `tests/test_scim_discovery.py`. Gate: member to resource
   and back, `ListResponse` paging arithmetic, every row of the error table, discovery
   documents state no bulk, no etag, no groups and a single filter form.
8. Token management routes. Files: `src/sandfort/auth/scim.py`,
   `src/sandfort/api/routes/scim_tokens.py`, `src/sandfort/api/wiring.py`,
   `src/sandfort/api/app.py`, `tests/test_scim_tokens_api.py`. Gate: with the setting off
   the routes are absent; with it on, an admin mints, lists and revokes; a developer key
   gets 403; the response never contains a hash; an unknown or revoked token is refused by
   `auth/scim.py`.
9. SCIM routes and spec policy. Files: `src/sandfort/api/routes/scim.py`,
   `src/sandfort/api/app.py`, `tests/test_scim_api.py`, `tests/test_scim_auth.py`,
   `tests/test_scim_openapi.py`. Gate: create, get, filter, page, replace, the three patch
   shapes, deactivate and delete through HTTP with a `application/scim+json` body; an API
   key, a session token and a revoked token are 401 on SCIM paths, and a SCIM token is 401
   on `/v1/sandboxes`; a `developer` ceiling cannot create an admin; deactivating the last
   admin is 409; a deactivated member's session token stops working; no SCIM path in
   `build_document()` and the committed spec drift test passes unchanged.
10. Real gate and docs. Files: `examples/gate10.py`, `docs/operations.md`,
    `docs/roadmap.md`, `CHANGELOG.md`. Gate: `examples/gate10.py`
    starts the server with SCIM enabled, mints a token, then plays the Okta and Entra
    request sequences with plain HTTP: discovery, filter miss, create, filter hit, patch
    role, deactivate, reactivate by create (same id), delete, and a last-admin refusal; it
    exits non-zero on any failure. Positioning and ICP documents change only after this
    gate passes, in a separate marketing contract.

## 5. Non-goals for the first version

These items are out of scope:

- No Groups resource and no mapping of groups to roles; one primary role attribute only.
- No Bulk, no ETag or version precondition, no sorting, no password management.
- No filters beyond `userName eq`, including `externalId eq`; the provider's matching
  attribute must be `userName`.
- No enterprise or custom schema extension, and no `lastModified`.
- No SCIM for sandboxes, API keys or any resource except org members.
- No disabled flag, no soft deactivation, no remembered role after deactivation.
- No revocation of API keys or sessions minted before a user was removed, beyond the
  session check against the membership that already exists.
- No SCIM-driven change to the global user row after create (display name, email).
- No change to SSO: the OIDC exchange stays bound to the single `oidc_org_id`, so a token
  for another org provisions members who cannot sign in through SSO until that changes.
- No SDK or CLI methods for SCIM and no entry in the exported OpenAPI document.
- No token expiry, no IP allowlist for tokens and no automatic rotation.
- No pagination by keyset; the list is sliced in memory.
