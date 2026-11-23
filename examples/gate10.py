"""Gate 10: SCIM user provisioning, end to end over plain HTTP.

Proves phase ten live (design: ``docs/scim-design.md``). One server process (role ``all``,
``SANDFORT_SCIM_ENABLED=true``) runs on a temporary sqlite database with the fake driver, so no
Docker daemon is needed. The org admin mints a per-org SCIM token through ``/v1/org/scim-tokens``
with the platform key; then this script plays an identity provider against ``/scim/v2`` with the
SCIM bearer token and the ``application/scim+json`` media type:

* ``ServiceProviderConfig`` states the limits (patch yes; bulk, etag and sort no);
* a ``userName eq`` filter that misses is an empty list, then a create, then a filter that hits;
* get by id, a duplicate create (409 ``uniqueness``), an immutable ``displayName`` (400);
* the role changes with each accepted shape (``roles[primary eq "True"].value``, ``roles`` as a
  replace and as an add) and ``externalId`` with the value-object shape that has no path;
* the ``active`` false patch removes the membership (the member is gone from SCIM and from
  ``/v1/org/members``), a create for the same ``userName`` brings back the same id, DELETE;
* the last admin cannot be deactivated, deleted or demoted (409 in the SCIM error shape);
* a token whose ceiling is ``viewer`` cannot create an admin, an admin key is a 401 on SCIM
  paths, the SCIM token is a 401 on ``/v1/sandboxes``, and a revoked token stops working.

Run: .venv/bin/python examples/gate10.py
A fresh temporary sqlite database is migrated and bootstrapped in-process. Prints one progress
line per step and exits non-zero on any failure; the server process and the database are removed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

API_PORT = 4210
API = f"http://127.0.0.1:{API_PORT}"
SCIM_PREFIX = "/scim/v2"
SCIM_JSON = "application/scim+json"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ADMIN_NAME = "root@example.com"
USER_NAME = "ada@example.com"
HEALTH_TIMEOUT_S = 40.0
REQUEST_TIMEOUT_S = 30.0


def check(condition: bool, message: str) -> None:
    """Fail the gate (non-zero exit) unless ``condition`` holds."""
    if not condition:
        raise SystemExit(f"GATE10 FAIL: {message}")


def step(message: str) -> None:
    print(f"CHECK {message}", flush=True)


def wait_health(base: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.time() + HEALTH_TIMEOUT_S
    while time.time() < deadline:
        check(process.poll() is None, "server process exited at startup")
        try:
            if httpx.get(f"{base}/healthz", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise SystemExit(f"GATE10 FAIL: {base} did not become healthy")


def provision(env: dict[str, str]) -> str:
    """Migrate and bootstrap in-process; return the platform key."""
    os.environ.update(env)
    from sandfort import admin_cli

    admin_cli.migrate()
    key = admin_cli.bootstrap("Gate10", "gate10")
    check(key.startswith("sf_"), "bootstrap did not return an sf_ key")
    return key


def spawn_server(env: dict[str, str]) -> subprocess.Popen[bytes]:
    server_env = {
        **env,
        "SANDFORT_ROLE": "all",
        "SANDFORT_PORT": str(API_PORT),
        "SANDFORT_SCIM_ENABLED": "true",
    }
    return subprocess.Popen(
        [str(REPO / ".venv" / "bin" / "python"), "-m", "sandfort.main"],
        cwd=REPO,
        env=server_env,
    )


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


# --- request helpers ---------------------------------------------------------------------


def platform(
    client: httpx.Client, key: str, method: str, path: str, body: dict[str, Any] | None = None
) -> httpx.Response:
    """A call to the ordinary api with the platform key."""
    headers = {"Authorization": f"Bearer {key}"}
    return client.request(method, path, headers=headers, json=body)


def scim(
    client: httpx.Client,
    token: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
) -> httpx.Response:
    """A call the way an identity provider makes it: bearer token, SCIM media type."""
    headers = {"Authorization": f"Bearer {token}", "Accept": SCIM_JSON}
    content = None
    if body is not None:
        headers["Content-Type"] = SCIM_JSON
        content = json.dumps(body)
    return client.request(
        method, f"{SCIM_PREFIX}{path}", headers=headers, content=content, params=params
    )


def expect(response: httpx.Response, status: int, what: str) -> httpx.Response:
    """Check the status and, when there is a body, the SCIM media type."""
    check(response.status_code == status, f"{what} -> {response.status_code} {response.text}")
    if response.content:
        media_type = response.headers.get("content-type", "").partition(";")[0].strip()
        check(media_type == SCIM_JSON, f"{what}: content type is {media_type!r}")
    return response


def expect_error(
    response: httpx.Response, status: int, scim_type: str | None, what: str
) -> dict[str, Any]:
    """Check a SCIM Error body: schema, string status, scimType (``None`` means absent)."""
    expect(response, status, what)
    body: dict[str, Any] = response.json()
    check(body.get("schemas") == [ERROR_SCHEMA], f"{what}: not a SCIM error body: {body}")
    check(body.get("status") == str(status), f"{what}: status field is {body.get('status')!r}")
    check(body.get("scimType") == scim_type, f"{what}: scimType is {body.get('scimType')!r}")
    check(bool(body.get("detail")), f"{what}: the error has no detail")
    return body


def user_body(user_name: str, **extra: Any) -> dict[str, Any]:
    return {"schemas": [USER_SCHEMA], "userName": user_name, **extra}


def patch_body(*operations: dict[str, Any]) -> dict[str, Any]:
    return {"schemas": [PATCH_SCHEMA], "Operations": list(operations)}


def role_of(resource: dict[str, Any]) -> str:
    roles = resource["roles"]
    check(len(roles) == 1 and roles[0]["primary"] is True, f"unexpected roles: {roles}")
    return str(roles[0]["value"])


def find(client: httpx.Client, token: str, user_name: str) -> dict[str, Any]:
    """The list response of the one supported filter form."""
    params = {"filter": f'userName eq "{user_name}"'}
    response = expect(scim(client, token, "GET", "/Users", params=params), 200, "filter")
    body: dict[str, Any] = response.json()
    check(body["schemas"] == [LIST_SCHEMA], f"not a ListResponse: {body}")
    return body


# --- steps -------------------------------------------------------------------------------


def mint(client: httpx.Client, key: str, name: str, max_role: str) -> tuple[str, str]:
    """Mint a SCIM token with the platform key; return its id and the plaintext (shown once)."""
    request = {"name": name, "max_role": max_role}
    response = platform(client, key, "POST", "/v1/org/scim-tokens", request)
    check(response.status_code == 201, f"mint -> {response.status_code} {response.text}")
    data = response.json()["data"]
    token = str(data["token"])
    check(token.startswith("sf_scim_"), "the minted token does not start with sf_scim_")
    check(data["max_role"] == max_role and data["revoked_at"] is None, f"bad metadata: {data}")
    check("secret_hash" not in data, "the mint response carries a hash")
    return str(data["id"]), token


def check_token_listing(client: httpx.Client, key: str, token_id: str, token: str) -> None:
    response = platform(client, key, "GET", "/v1/org/scim-tokens")
    check(response.status_code == 200, f"list tokens -> {response.status_code}")
    check(token not in response.text, "the token listing repeats the plaintext token")
    rows = [row for row in response.json()["data"] if row["id"] == token_id]
    check(len(rows) == 1, "the minted token is not listed")
    check("token" not in rows[0] and "secret_hash" not in rows[0], "the listing leaks a secret")


def check_discovery(client: httpx.Client, token: str) -> None:
    response = expect(scim(client, token, "GET", "/ServiceProviderConfig"), 200, "discovery")
    config = response.json()
    check(config["patch"]["supported"] is True, "patch is not advertised")
    for name in ("bulk", "etag", "sort", "changePassword"):
        check(config[name]["supported"] is False, f"{name} is advertised as supported")
    advertised = config["filter"]
    check(advertised == {"supported": True, "maxResults": 100}, f"filter: {advertised}")
    bare = client.get(f"{SCIM_PREFIX}/ServiceProviderConfig")
    expect_error(bare, 401, None, "discovery without a token")


def seed_admin(client: httpx.Client, token: str) -> str:
    """The bootstrap org has an admin key but no admin member: SCIM creates the only one."""
    body = user_body(ADMIN_NAME, roles=[{"value": "admin", "primary": True}])
    created = expect(scim(client, token, "POST", "/Users", body), 201, "create admin").json()
    check(role_of(created) == "admin", f"the admin has role {role_of(created)}")
    return str(created["id"])


def create_user(client: httpx.Client, token: str) -> str:
    body = user_body(
        "Ada@Example.com", displayName="Ada Lovelace", externalId="idp-ada-1", active=True
    )
    response = expect(scim(client, token, "POST", "/Users", body), 201, "create")
    created = response.json()
    check(created["userName"] == USER_NAME, f"userName is {created['userName']!r}")
    check(role_of(created) == "viewer", "a create without roles must get the default role")
    check(created["externalId"] == "idp-ada-1", "externalId was not stored")
    check(created["active"] is True, "a new member is not active")
    location = response.headers.get("location")
    check(location == created["meta"]["location"], f"Location header is {location!r}")
    return str(created["id"])


def check_read_paths(client: httpx.Client, token: str, user_id: str) -> None:
    got = expect(scim(client, token, "GET", f"/Users/{user_id}"), 200, "get").json()
    check(got["id"] == user_id and got["userName"] == USER_NAME, f"get returned {got}")
    hit = find(client, token, "ADA@example.com")
    check(hit["totalResults"] == 1 and hit["itemsPerPage"] == 1, f"filter hit: {hit}")
    check(hit["Resources"][0]["id"] == user_id, "the filter hit is a different user")
    dup = scim(client, token, "POST", "/Users", user_body(USER_NAME))
    expect_error(dup, 409, "uniqueness", "duplicate create")
    wrong = patch_body({"op": "replace", "path": "displayName", "value": "Someone Else"})
    changed = scim(client, token, "PATCH", f"/Users/{user_id}", wrong)
    expect_error(changed, 400, "mutability", "displayName change")
    other = scim(client, token, "GET", "/Users", params={"filter": 'userName co "ada"'})
    expect_error(other, 400, "invalidFilter", "unsupported filter")


def patch_role(client: httpx.Client, token: str, user_id: str, operation: dict[str, Any]) -> str:
    response = scim(client, token, "PATCH", f"/Users/{user_id}", patch_body(operation))
    return role_of(expect(response, 200, "patch role").json())


def check_role_shapes(client: httpx.Client, token: str, user_id: str) -> None:
    entra = {"op": "Replace", "path": 'roles[primary eq "True"].value', "value": "developer"}
    check(patch_role(client, token, user_id, entra) == "developer", "roles[primary].value")
    step('role patched: path roles[primary eq "True"].value with a string')
    as_list = [{"value": "viewer", "primary": True}]
    replace = {"op": "replace", "path": "roles", "value": as_list}
    check(patch_role(client, token, user_id, replace) == "viewer", "replace roles")
    step("role patched: replace on path roles with a list")
    add = {"op": "add", "path": "roles", "value": [{"value": "developer", "primary": True}]}
    check(patch_role(client, token, user_id, add) == "developer", "add roles")
    step("role patched: add on path roles with a list")
    no_path = patch_body({"op": "replace", "value": {"externalId": "idp-ada-2"}})
    moved = expect(scim(client, token, "PATCH", f"/Users/{user_id}", no_path), 200, "externalId")
    check(moved.json()["externalId"] == "idp-ada-2", "externalId was not replaced")
    step("externalId replaced: value object without a path")


def check_deactivation(client: httpx.Client, key: str, token: str, user_id: str) -> str:
    off = patch_body({"op": "replace", "path": "active", "value": "False"})
    response = scim(client, token, "PATCH", f"/Users/{user_id}", off)
    answered = expect(response, 200, "deactivate").json()
    check(answered["active"] is False and answered["id"] == user_id, f"answer: {answered}")
    step("deactivated with the active false patch (the string False, as Entra sends it)")
    expect_error(scim(client, token, "GET", f"/Users/{user_id}"), 404, None, "get after off")
    check(find(client, token, USER_NAME)["totalResults"] == 0, "the member is still listed")
    members = platform(client, key, "GET", "/v1/org/members").json()["data"]
    check(USER_NAME not in {m["email"] for m in members}, "the member is still in the members api")
    again = scim(client, token, "PATCH", f"/Users/{user_id}", off)
    expect_error(again, 404, None, "repeat deactivation")
    step("the member is gone from SCIM and from /v1/org/members; the user row is kept")
    body = user_body(USER_NAME, displayName="Ada Lovelace", externalId="idp-ada-3")
    back = expect(scim(client, token, "POST", "/Users", body), 201, "create again").json()
    check(back["id"] == user_id, f"a create for the same userName got a new id {back['id']}")
    check(role_of(back) == "viewer", "the role is not the default after a new create")
    step(f"created again with the same userName: same id {user_id}, default role")
    return str(back["id"])


def check_delete(client: httpx.Client, token: str, user_id: str) -> None:
    removed = scim(client, token, "DELETE", f"/Users/{user_id}")
    check(removed.status_code == 204, f"delete -> {removed.status_code} {removed.text}")
    expect_error(scim(client, token, "GET", f"/Users/{user_id}"), 404, None, "get after delete")
    expect_error(scim(client, token, "DELETE", f"/Users/{user_id}"), 404, None, "repeat delete")
    step("deleted: 204, then 404 for get and for a second delete")


def check_last_admin(client: httpx.Client, token: str, admin_id: str) -> None:
    path = f"/Users/{admin_id}"
    off = patch_body({"op": "replace", "value": {"active": False}})
    first = expect_error(scim(client, token, "PATCH", path, off), 409, None, "deactivate admin")
    check("admin" in first["detail"], f"the refusal does not name the admin rule: {first}")
    expect_error(scim(client, token, "DELETE", path), 409, None, "delete the last admin")
    demote = patch_body({"op": "replace", "path": "roles", "value": [{"value": "viewer"}]})
    expect_error(scim(client, token, "PATCH", path, demote), 409, None, "demote the last admin")
    still = expect(scim(client, token, "GET", path), 200, "get admin").json()
    check(role_of(still) == "admin", "the last admin lost its role")
    step("the last admin cannot be deactivated, deleted or demoted: 409 in the SCIM error shape")


def check_token_boundaries(client: httpx.Client, key: str, token: str) -> None:
    viewer_id, viewer_token = mint(client, key, "gate10-viewer", "viewer")
    roles = [{"value": "admin", "primary": True}]
    body = user_body("mallory@example.com", roles=roles)
    expect_error(scim(client, viewer_token, "POST", "/Users", body), 403, None, "ceiling")
    step("a token with ceiling viewer cannot create an admin: 403")
    expect_error(scim(client, key, "GET", "/Users"), 401, None, "api key on SCIM")
    step("the platform admin key is a 401 on /scim/v2")
    sandboxes = client.get("/v1/sandboxes", headers={"Authorization": f"Bearer {token}"})
    check(sandboxes.status_code == 401, f"scim token on /v1/sandboxes -> {sandboxes.status_code}")
    step("the SCIM token is a 401 on /v1/sandboxes")
    check(find(client, viewer_token, ADMIN_NAME)["totalResults"] == 1, "viewer token cannot read")
    revoked = platform(client, key, "DELETE", f"/v1/org/scim-tokens/{viewer_id}")
    check(revoked.status_code == 200, f"revoke -> {revoked.status_code} {revoked.text}")
    check(revoked.json()["data"]["revoked_at"] is not None, "revoked_at was not set")
    expect_error(scim(client, viewer_token, "GET", "/Users"), 401, None, "revoked token")
    again = platform(client, key, "DELETE", f"/v1/org/scim-tokens/{viewer_id}")
    check(again.status_code == 200, f"second revoke -> {again.status_code}")
    check(find(client, token, ADMIN_NAME)["totalResults"] == 1, "the other token stopped too")
    step("a revoked token is a 401 at once; revoking again is a 200; other tokens keep working")


def run_gate(key: str) -> None:
    with httpx.Client(base_url=API, timeout=REQUEST_TIMEOUT_S) as client:
        token_id, token = mint(client, key, "gate10-idp", "admin")
        step(f"SCIM token {token_id} minted with ceiling admin (plaintext shown once)")
        check_token_listing(client, key, token_id, token)
        step("token listing carries metadata only: no plaintext, no hash")
        check_discovery(client, token)
        step("ServiceProviderConfig: patch yes; bulk, etag, sort no; one filter; token required")
        check(find(client, token, USER_NAME)["totalResults"] == 0, "filter miss is not empty")
        step("filter miss: an empty ListResponse, not a 404")
        admin_id = seed_admin(client, token)
        step(f"the org's only admin {admin_id} created through SCIM")
        user_id = create_user(client, token)
        step(f"created {USER_NAME} as {user_id}: 201, default role viewer, Location header")
        check_read_paths(client, token, user_id)
        step("filter hit, get by id, duplicate 409 uniqueness, immutable name, bad filter 400")
        check_role_shapes(client, token, user_id)
        user_id = check_deactivation(client, key, token, user_id)
        check_delete(client, token, user_id)
        check_last_admin(client, token, admin_id)
        check_token_boundaries(client, key, token)


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sandfort-gate10-")
    db_path = os.path.join(tmp, "gate10.db")
    server: subprocess.Popen[bytes] | None = None
    try:
        env = {
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "SANDFORT_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
            "SANDFORT_DRIVER": "fake",
            "SANDFORT_API_KEY_PEPPER": os.urandom(16).hex(),
        }
        key = provision(env)
        step("database migrated and org bootstrapped")

        server = spawn_server(env)
        wait_health(API, server)
        step(f"server healthy on {API} with SANDFORT_SCIM_ENABLED=true")

        run_gate(key)
        print("GATE10 PASS", flush=True)
        return 0
    finally:
        if server is not None:
            stop(server)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
