"""SDK phase 3: image DSL, snapshot/build and volume clients against respx-mocked endpoints."""

import dataclasses
import inspect
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_sdk import (  # noqa: E402
    AsyncClient,
    AsyncSnapshots,
    AsyncVolumes,
    BuildLogEvent,
    Client,
    Conflict,
    Image,
    InvalidResponseError,
    NotFound,
    SandboxFailedError,
    SandboxTimeoutError,
    SnapshotInfo,
    Snapshots,
    TransportError,
    VolumeInfo,
    VolumeMount,
    Volumes,
)
from sandfort_sdk._requests import create_body  # noqa: E402

from sandfort.images.sdk_dsl_schema import (  # noqa: E402
    IMAGE_SPEC_SCHEMA,
    SCHEMA_VERSION,
    validate_image_spec_payload,
)

BASE = "http://sandfort.test"
KEY = "sf_test_key"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SNAP_ID = "snap_01HZZZZZZZZZZZZZZZZZZZZZZ"
VOL_ID = "vol_01HZZZZZZZZZZZZZZZZZZZZZZZ"
CREATED = "2026-10-30T19:26:00Z"
SSE = "text/event-stream"
SNAPSHOTS_URL = "/v1/snapshots"
SNAPSHOT_URL = f"{SNAPSHOTS_URL}/{SNAP_ID}"
FROM_SANDBOX_URL = f"{SNAPSHOTS_URL}/from-sandbox"
BUILDS_URL = "/v1/images/builds"
BUILD_LOGS_URL = f"{BUILDS_URL}/{SNAP_ID}/logs"
VOLUMES_URL = "/v1/volumes"
VOLUME_URL = f"{VOLUMES_URL}/{VOL_ID}"

SNAPSHOT = {
    "id": SNAP_ID,
    "name": "py",
    "state": "ready",
    "image_ref": "python:3.12-slim",
    "digest": "sha256:abc",
    "layer_count": 3,
    "source_sandbox_id": None,
    "created_at": CREATED,
}
VOLUME = {
    "id": VOL_ID,
    "name": "data",
    "state": "ready",
    "size_bytes": 4096,
    "created_at": CREATED,
}
SANDBOX = {
    "id": SID,
    "name": "demo",
    "state": "creating",
    "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
    "network": {"block_all": False},
}

# Server-shaped build log: a keepalive, two lines (one CRLF-framed), the final state event,
# then a late frame that must never be surfaced.
BUILD_SSE = (
    ": keepalive\n\n"
    'event: log\nid: 0\ndata: {"line":"Step 1/3 : FROM python:3.12-slim"}\n\n'
    'event: log\r\nid: 1\r\ndata: {"line":"pip install requests"}\r\n\r\n'
    f'event: state\ndata: {{"state":"ready","snapshot_id":"{SNAP_ID}",'
    '"digest":"sha256:abc","reason":null}\n\n'
    'event: log\nid: 2\ndata: {"line":"late"}\n\n'
).encode()
EXPECTED_BUILD_EVENTS = [
    BuildLogEvent("log", line="Step 1/3 : FROM python:3.12-slim", index=0),
    BuildLogEvent("log", line="pip install requests", index=1),
    BuildLogEvent("state", state="ready", snapshot_id=SNAP_ID, digest="sha256:abc"),
]


def envelope(data: object, next_cursor: str | None = None) -> dict[str, object]:
    meta = {"next_cursor": next_cursor} if next_cursor is not None else None
    return {"success": True, "data": data, "error": None, "meta": meta}


def error_envelope(code: str, message: str = "boom") -> dict[str, object]:
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


async def call(fn, *args, **kwargs):  # type: ignore[no-untyped-def]
    """Invoke a sync or async SDK callable and return its result."""
    result = fn(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


async def drain(iterable):  # type: ignore[no-untyped-def]
    if hasattr(iterable, "__aiter__"):
        return [item async for item in iterable]
    return list(iterable)


async def close(instance) -> None:  # type: ignore[no-untyped-def]
    await call(instance.close if isinstance(instance, Client) else instance.aclose)


def representative() -> Image:
    return (
        Image.debian_slim()
        .pip_install(["requests", "httpx"])
        .apt_install("git", "curl")
        .add_file("/etc/app.conf", "mode=prod\n")
        .add_file("/app/README", "hello ✓\n")
        .env({"APP_ENV": "prod"}, LOG_LEVEL="info")
        .workdir("/app")
    )


@pytest.fixture
def api():  # type: ignore[no-untyped-def]
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router
        for recorded in router.calls:
            assert recorded.request.headers["authorization"] == f"Bearer {KEY}"


@pytest.fixture(params=["sync", "async"])
async def client(request):  # type: ignore[no-untyped-def]
    instance = (Client if request.param == "sync" else AsyncClient)(BASE, KEY)
    yield instance
    await close(instance)


# --- image DSL -----------------------------------------------------------------------------


def test_dsl_serializes_to_the_full_wire_form():
    assert representative().serialize() == {
        "schema_version": "1",
        "base_image": "python:3.12-slim",
        "pip_packages": ["requests", "httpx"],
        "apt_packages": ["git", "curl"],
        "env": {"APP_ENV": "prod", "LOG_LEVEL": "info"},
        "workdir": "/app",
        "files": [
            {"destination": "/etc/app.conf", "content": "mode=prod\n"},
            {"destination": "/app/README", "content": "hello ✓\n"},
        ],
    }


def test_dsl_chaining_never_mutates_the_receiver():
    base = Image.debian_slim()
    before = base.serialize()
    derived = [
        base.pip_install("requests"),
        base.apt_install("git"),
        base.add_file("/a", "x"),
        base.env(A="1"),
        base.workdir("/w"),
    ]

    assert base.serialize() == before
    assert all(item is not base and item.serialize() != before for item in derived)
    step = base.pip_install("a")
    assert step.pip_install("b").pip_packages == ("a", "b")
    assert step.pip_packages == ("a",)
    with pytest.raises(dataclasses.FrozenInstanceError):
        base.base_image = "alpine"  # type: ignore[misc]


def test_dsl_from_image_dedupes_packages_and_replaces_files_at_the_same_path():
    image = (
        Image.from_image("debian:bookworm-slim")
        .pip_install("a")
        .pip_install("a", "b")
        .add_file("/f", "old")
        .add_file("/f", "new")
        .env(A="1")
        .env(A="2")
    )

    wire = image.serialize()
    assert wire["base_image"] == "debian:bookworm-slim"
    assert wire["pip_packages"] == ["a", "b"]
    assert wire["files"] == [{"destination": "/f", "content": "new"}]
    assert wire["env"] == {"A": "2"}
    assert wire["workdir"] is None


@pytest.mark.parametrize(
    "build",
    [
        lambda: Image.from_image(" "),
        lambda: Image.debian_slim().pip_install(""),
        lambda: Image.debian_slim().apt_install(["git", ""]),
        lambda: Image.debian_slim().add_file("", "x"),
        lambda: Image.debian_slim().env({"": "x"}),
        lambda: Image.debian_slim().workdir(""),
    ],
)
def test_dsl_rejects_values_that_can_never_be_valid(build):
    with pytest.raises(ValueError):
        build()


def test_dsl_serialization_passes_the_server_schema_exactly():
    payload = representative().serialize()

    spec = validate_image_spec_payload(payload)

    assert set(payload) == set(IMAGE_SPEC_SCHEMA["properties"])
    assert payload["schema_version"] == SCHEMA_VERSION
    assert spec.model_dump() == {k: v for k, v in payload.items() if k != "schema_version"}


def test_reordered_but_equal_dsl_produces_an_identical_canonical_hash():
    reordered = (
        Image.debian_slim()
        .workdir("/app")
        .env(LOG_LEVEL="info")
        .add_file("/app/README", "hello ✓\n")
        .apt_install("curl")
        .pip_install("httpx")
        .env(APP_ENV="prod")
        .add_file("/etc/app.conf", "mode=prod\n")
        .apt_install("git")
        .pip_install("requests")
    )
    original = representative()

    assert reordered.serialize() != original.serialize()  # list order differs on the wire
    first = validate_image_spec_payload(original.serialize())
    second = validate_image_spec_payload(reordered.serialize())
    assert first.spec_hash == second.spec_hash
    changed = validate_image_spec_payload(original.pip_install("rich").serialize())
    assert changed.spec_hash != first.spec_hash


# --- snapshot and volume REST calls --------------------------------------------------------

PENDING_FROM_SANDBOX = {**SNAPSHOT, "state": "pending", "digest": None, "source_sandbox_id": SID}
REGISTER_BODY = {"image": "python:3.12-slim"}
REST_CASES = [
    ("snapshots", "register", ("python:3.12-slim",), {"name": "py"}, "POST", SNAPSHOTS_URL,
     {**REGISTER_BODY, "name": "py"}, 201, SNAPSHOT),
    ("snapshots", "register", ("python:3.12-slim",), {}, "POST", SNAPSHOTS_URL,
     REGISTER_BODY, 201, SNAPSHOT),
    ("snapshots", "create_from_sandbox", (SID, "mine"), {}, "POST", FROM_SANDBOX_URL,
     {"sandbox_id": SID, "name": "mine"}, 202, PENDING_FROM_SANDBOX),
    ("snapshots", "get", (SNAP_ID,), {}, "GET", SNAPSHOT_URL, None, 200, SNAPSHOT),
    ("snapshots", "delete", (SNAP_ID,), {}, "DELETE", SNAPSHOT_URL, None, 200,
     {**SNAPSHOT, "state": "deleting"}),
    ("volumes", "create", ("data",), {}, "POST", VOLUMES_URL, {"name": "data"}, 201, VOLUME),
    ("volumes", "get", (VOL_ID,), {}, "GET", VOLUME_URL, None, 200, VOLUME),
    ("volumes", "delete", (VOL_ID,), {}, "DELETE", VOLUME_URL, None, 200,
     {**VOLUME, "state": "deleting", "size_bytes": None}),
]  # fmt: skip


@pytest.mark.parametrize(
    ("area", "method", "args", "kwargs", "verb", "path", "body", "status", "data"), REST_CASES
)
async def test_rest_call_shape_and_typed_result(
    api, client, area, method, args, kwargs, verb, path, body, status, data
):
    route = api.request(verb, path).respond(status, json=envelope(data))

    result = await call(getattr(getattr(client, area), method), *args, **kwargs)

    request = route.calls.last.request
    assert route.call_count == 1
    if body is None:
        assert request.content == b""
    else:
        assert json.loads(request.content) == body
    assert isinstance(result, SnapshotInfo if area == "snapshots" else VolumeInfo)
    assert (result.id, result.state) == (data["id"], data["state"])
    assert result.created_at.isoformat() == "2026-10-30T19:26:00+00:00"


async def test_clients_expose_snapshot_and_volume_clients():
    sync, other = Client(BASE, KEY), AsyncClient(BASE, KEY)

    assert isinstance(sync.snapshots, Snapshots) and isinstance(sync.volumes, Volumes)
    assert isinstance(other.snapshots, AsyncSnapshots)
    assert isinstance(other.volumes, AsyncVolumes)
    assert sync.snapshots is sync.snapshots
    sync.close()
    await other.aclose()


@pytest.mark.parametrize(
    ("area", "path", "item"),
    [("snapshots", SNAPSHOTS_URL, SNAPSHOT), ("volumes", VOLUMES_URL, VOLUME)],
)
async def test_list_pages_and_iter_follows_cursors(api, client, area, path, item):
    route = api.get(path)
    route.side_effect = [
        httpx.Response(200, json=envelope([item], next_cursor="c1")),
        httpx.Response(200, json=envelope([{**item, "id": "second"}])),
        httpx.Response(200, json=envelope([item], next_cursor="c9")),
    ]
    facade = getattr(client, area)

    items = await drain(facade.iter(limit=1))
    page = await call(facade.list, cursor="c2", limit=5)

    assert [entry.id for entry in items] == [item["id"], "second"]
    assert route.calls[1].request.url.params["cursor"] == "c1"
    assert dict(route.calls.last.request.url.params) == {"cursor": "c2", "limit": "5"}
    assert page.next_cursor == "c9" and page.items[0].id == item["id"]


async def test_list_rejects_a_non_list_payload(api, client):
    api.get(VOLUMES_URL).respond(200, json=envelope({"id": VOL_ID}))

    with pytest.raises(InvalidResponseError):
        await call(client.volumes.list)


async def test_volume_delete_while_mounted_raises_conflict(api, client):
    api.delete(VOLUME_URL).respond(409, json=error_envelope("CONFLICT", "volume is mounted"))

    with pytest.raises(Conflict, match="mounted"):
        await call(client.volumes.delete, VOL_ID)


@pytest.mark.parametrize(
    ("area", "method", "args"),
    [
        ("snapshots", "register", (" ",)),
        ("snapshots", "create_from_sandbox", (SID, "")),
        ("volumes", "create", ("",)),
    ],
)
async def test_invalid_arguments_fail_before_any_request(api, client, area, method, args):
    with pytest.raises(ValueError):
        await call(getattr(getattr(client, area), method), *args)

    assert api.calls.call_count == 0


# --- builds --------------------------------------------------------------------------------


async def test_build_posts_the_serialized_dsl_image(api, client):
    pending = {**SNAPSHOT, "state": "pending", "digest": None, "spec_hash": "h1", "reused": False}
    route = api.post(BUILDS_URL).respond(202, json=envelope(pending))
    image = representative()

    info = await call(client.snapshots.build, image, name="py-app")

    assert json.loads(route.calls.last.request.content) == {
        "spec": image.serialize(),
        "name": "py-app",
    }
    assert (info.state, info.spec_hash, info.reused) == ("pending", "h1", False)


async def test_build_posts_a_raw_spec_mapping_unchanged(api, client):
    raw = {"schema_version": "1", "base_image": "alpine:3.20", "apt_packages": ["git"]}
    route = api.post(BUILDS_URL).respond(
        200, json=envelope({**SNAPSHOT, "spec_hash": "h2", "reused": True})
    )

    info = await call(client.snapshots.build, raw)

    assert json.loads(route.calls.last.request.content) == {"spec": raw}
    assert info.reused and info.state == "ready"


async def test_follow_build_logs_yields_lines_until_the_final_state(api, client):
    route = api.get(BUILD_LOGS_URL).respond(200, content=BUILD_SSE, headers={"content-type": SSE})

    stream = await call(client.snapshots.follow_build_logs, SNAP_ID)
    events = await drain(stream)

    assert events == EXPECTED_BUILD_EVENTS
    assert events[-1].is_final and events[-1].succeeded
    assert not events[0].is_final
    assert stream.closed
    assert route.calls.last.request.headers["accept"] == SSE


async def test_follow_build_logs_without_final_state_raises_transport_error(api, client):
    body = BUILD_SSE.split(b"event: state")[0]
    api.get(BUILD_LOGS_URL).respond(200, content=body, headers={"content-type": SSE})
    stream = await call(client.snapshots.follow_build_logs, SNAP_ID)

    with pytest.raises(TransportError, match="before the final state"):
        await drain(stream)

    assert stream.closed


async def test_follow_build_logs_rejects_malformed_event_data(api, client):
    body = b"event: log\nid: 0\ndata: not-json\n\n"
    api.get(BUILD_LOGS_URL).respond(200, content=body, headers={"content-type": SSE})
    stream = await call(client.snapshots.follow_build_logs, SNAP_ID)

    with pytest.raises(InvalidResponseError, match="not JSON"):
        await drain(stream)


async def test_follow_build_logs_for_an_unknown_build_raises_not_found(api, client):
    api.get(BUILD_LOGS_URL).respond(404, json=error_envelope("NOT_FOUND", "no such snapshot"))

    with pytest.raises(NotFound):
        await call(client.snapshots.follow_build_logs, SNAP_ID)


# --- sandbox mounts ------------------------------------------------------------------------


async def test_create_sandbox_passes_mounts_through(api, client):
    route = api.post("/v1/sandboxes").respond(201, json=envelope(SANDBOX))
    mounts = [VolumeMount(VOL_ID, "/data"), ("vol_2", "/cache")]

    await call(client.create_sandbox, name="demo", mounts=mounts, wait=False)
    await call(client.create_sandbox, name="plain", wait=False)

    with_mounts, without = (json.loads(c.request.content) for c in route.calls)
    assert with_mounts["volumes"] == [
        {"volume_id": VOL_ID, "mount_path": "/data"},
        {"volume_id": "vol_2", "mount_path": "/cache"},
    ]
    assert "volumes" not in without


async def test_create_sandbox_rejects_an_empty_mount_before_any_request(api, client):
    with pytest.raises(ValueError, match="mount"):
        await call(client.create_sandbox, mounts=[(VOL_ID, "")], wait=False)

    assert api.calls.call_count == 0


# --- egress allowlist ----------------------------------------------------------------------


def body_with_allowlist(allowlist):  # type: ignore[no-untyped-def]
    return create_body(
        name=None,
        snapshot=None,
        resources=None,
        env=None,
        labels=None,
        block_network=None,
        auto_stop_minutes=None,
        auto_delete_minutes=None,
        public=None,
        egress_allowlist=allowlist,
    )


def test_create_body_lists_the_allowlist_only_when_not_none():
    assert body_with_allowlist(None) == {}
    assert body_with_allowlist(["a.example"]) == {"egress_allowlist": ["a.example"]}
    assert body_with_allowlist(()) == {"egress_allowlist": []}


def test_create_body_keeps_an_explicit_false_block_network():
    def body(block_network):  # type: ignore[no-untyped-def]
        return create_body(
            name=None,
            snapshot=None,
            resources=None,
            env=None,
            labels=None,
            block_network=block_network,
            auto_stop_minutes=None,
            auto_delete_minutes=None,
            public=None,
        )

    assert body(False) == {"network": {"block_all": False}}
    assert body(True) == {"network": {"block_all": True}}
    assert body(None) == {}


def test_create_sandbox_sends_the_egress_allowlist_exactly_when_given(api):
    route = api.post("/v1/sandboxes").respond(201, json=envelope(SANDBOX))
    hosts = ("pypi.org", "files.pythonhosted.org")

    with Client(BASE, KEY) as sync:
        sync.create_sandbox(name="locked", egress_allowlist=hosts, wait=False)
        sync.create_sandbox(name="plain", wait=False)

    with_list, without = (json.loads(c.request.content) for c in route.calls)
    assert with_list["egress_allowlist"] == ["pypi.org", "files.pythonhosted.org"]
    assert "egress_allowlist" not in without


# --- snapshot wait -------------------------------------------------------------------------


def snapshot_in(state: str) -> httpx.Response:
    return httpx.Response(200, json=envelope({**PENDING_FROM_SANDBOX, "state": state}))


async def test_create_from_sandbox_without_wait_returns_pending_and_never_polls(api, client):
    api.post(FROM_SANDBOX_URL).respond(202, json=envelope(PENDING_FROM_SANDBOX))
    poll = api.get(SNAPSHOT_URL).respond(200, json=envelope(SNAPSHOT))

    info = await call(client.snapshots.create_from_sandbox, SID, "mine")

    assert info.state == "pending"
    assert poll.call_count == 0


async def test_create_from_sandbox_wait_returns_once_the_snapshot_is_ready(api, client):
    post = api.post(FROM_SANDBOX_URL).respond(202, json=envelope(PENDING_FROM_SANDBOX))
    poll = api.get(SNAPSHOT_URL)
    poll.side_effect = [snapshot_in("pending"), snapshot_in("ready"), snapshot_in("deleting")]

    info = await call(
        client.snapshots.create_from_sandbox, SID, "mine", wait=True, poll_interval_s=0
    )

    assert (info.id, info.state) == (SNAP_ID, "ready")
    assert post.call_count == 1 and poll.call_count == 2


async def test_create_from_sandbox_wait_returns_at_once_when_the_reply_is_ready(api, client):
    api.post(FROM_SANDBOX_URL).respond(202, json=envelope({**SNAPSHOT, "state": "ready"}))
    poll = api.get(SNAPSHOT_URL).respond(200, json=envelope(SNAPSHOT))

    info = await call(client.snapshots.create_from_sandbox, SID, "mine", wait=True)

    assert info.state == "ready" and poll.call_count == 0


async def test_create_from_sandbox_wait_raises_when_the_snapshot_errors(api, client):
    api.post(FROM_SANDBOX_URL).respond(202, json=envelope(PENDING_FROM_SANDBOX))
    poll = api.get(SNAPSHOT_URL)
    poll.side_effect = [snapshot_in("pending"), snapshot_in("error")]

    with pytest.raises(SandboxFailedError, match=SNAP_ID) as raised:
        await call(client.snapshots.create_from_sandbox, SID, "mine", wait=True, poll_interval_s=0)

    assert (raised.value.sandbox_id, raised.value.state) == (SID, "error")
    assert poll.call_count == 2


async def test_create_from_sandbox_wait_raises_when_the_deadline_passes(api, client):
    api.post(FROM_SANDBOX_URL).respond(202, json=envelope(PENDING_FROM_SANDBOX))
    poll = api.get(SNAPSHOT_URL).respond(200, json=envelope(PENDING_FROM_SANDBOX))

    with pytest.raises(SandboxTimeoutError, match="still pending"):
        await call(
            client.snapshots.create_from_sandbox,
            SID,
            "mine",
            wait=True,
            wait_timeout_s=0.05,
            poll_interval_s=0.01,
        )

    assert poll.call_count >= 1


def test_snapshot_info_parses_the_isolation_tier_when_present():
    info = SnapshotInfo.from_payload({**SNAPSHOT, "isolation": "gvisor"})

    assert info.isolation == "gvisor"


def test_snapshot_info_isolation_is_none_when_the_field_is_absent():
    assert "isolation" not in SNAPSHOT

    assert SnapshotInfo.from_payload(SNAPSHOT).isolation is None
