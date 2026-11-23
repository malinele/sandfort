"""Round 59: volume labels and read-only mounts in the Python SDK and the CLI."""

import inspect
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.sandboxes import parse_mount  # noqa: E402
from sandfort_sdk import AsyncClient, Client, VolumeInfo, VolumeMount  # noqa: E402
from sandfort_sdk.models import SandboxInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
VOL_ID = "vol_1"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
CREATED = "2026-11-10T19:26:00Z"
VOLUMES_URL = "/v1/volumes"
SANDBOXES_URL = "/v1/sandboxes"
EXIT_USAGE = 2
RUNNER = CliRunner()


def envelope(data, next_cursor=None):
    meta = {"next_cursor": next_cursor} if next_cursor is not None else None
    return {"success": True, "data": data, "error": None, "meta": meta}


def volume_json(**extra):
    base = {"id": VOL_ID, "name": "data", "state": "ready", "created_at": CREATED}
    return {**base, **extra}


def sandbox_json(**extra):
    base = {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return {**base, **extra}


async def call(fn, *args, **kwargs):
    result = fn(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


async def drain(iterable):
    if hasattr(iterable, "__aiter__"):
        return [item async for item in iterable]
    return list(iterable)


@pytest.fixture
def api():
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        yield router


@pytest.fixture(params=["sync", "async"])
async def client(request):
    instance = (Client if request.param == "sync" else AsyncClient)(BASE, KEY)
    yield instance
    closed = instance.close() if request.param == "sync" else instance.aclose()
    if inspect.isawaitable(closed):
        await closed


def body_of(route, index=-1):
    return json.loads(route.calls[index].request.content)


# --- SDK: volume labels --------------------------------------------------------------------


async def test_volume_create_sends_labels_when_given(api, client):
    route = api.post(VOLUMES_URL).respond(201, json=envelope(volume_json(labels={"env": "ci"})))

    info = await call(client.volumes.create, "data", labels={"env": "ci", "team": "a"})

    assert body_of(route) == {"name": "data", "labels": {"env": "ci", "team": "a"}}
    assert info.labels == {"env": "ci"}


async def test_volume_create_without_labels_sends_only_the_name(api, client):
    route = api.post(VOLUMES_URL).respond(201, json=envelope(volume_json()))

    await call(client.volumes.create, "data")

    assert body_of(route) == {"name": "data"}


@pytest.mark.parametrize(
    "labels",
    [{"": "v"}, {"  ": "v"}, {"k": 1}, {1: "v"}, {"k": None}],
)
async def test_volume_create_rejects_bad_labels_before_any_request(api, client, labels):
    with pytest.raises(ValueError, match="label"):
        await call(client.volumes.create, "data", labels=labels)

    assert api.calls.call_count == 0


@pytest.mark.parametrize("labels", [{"k": ""}, {"k": "  "}])
async def test_volume_create_sends_blank_label_values(api, client, labels):
    route = api.post(VOLUMES_URL).respond(201, json=envelope(volume_json(labels=labels)))

    await call(client.volumes.create, "data", labels=labels)

    assert body_of(route) == {"name": "data", "labels": labels}


async def test_volume_info_labels_are_empty_when_the_server_omits_them(api, client):
    api.get(f"{VOLUMES_URL}/{VOL_ID}").respond(200, json=envelope(volume_json()))
    api.get(VOLUMES_URL).respond(
        200, json=envelope([volume_json(labels={"a": "b"}), volume_json(id="vol_2")])
    )

    got = await call(client.volumes.get, VOL_ID)
    page = await call(client.volumes.list)

    assert isinstance(got, VolumeInfo)
    assert got.labels == {}
    assert [item.labels for item in page.items] == [{"a": "b"}, {}]


async def test_volume_list_sends_the_label_filter_as_repeated_query_values(api, client):
    route = api.get(VOLUMES_URL).respond(200, json=envelope([]))

    await call(client.volumes.list, labels={"env": "ci", "team": "a"})
    await call(client.volumes.list)

    with_filter, without = (c.request.url.params for c in route.calls)
    assert with_filter.get_list("label") == ["env=ci", "team=a"]
    assert "label" not in without


async def test_volume_iter_passes_the_label_filter_on_every_page(api, client):
    route = api.get(VOLUMES_URL).mock(
        side_effect=[
            respx.MockResponse(200, json=envelope([volume_json()], next_cursor="c2")),
            respx.MockResponse(200, json=envelope([volume_json(id="vol_2")])),
        ]
    )

    items = await drain(client.volumes.iter(labels={"env": "ci"}))

    assert [item.id for item in items] == [VOL_ID, "vol_2"]
    assert [c.request.url.params.get_list("label") for c in route.calls] == [["env=ci"]] * 2


async def test_volume_list_rejects_a_bad_label_filter(api, client):
    with pytest.raises(ValueError, match="label"):
        await call(client.volumes.list, labels={"": "x"})

    assert api.calls.call_count == 0


# --- SDK: read-only mounts -----------------------------------------------------------------


def test_volume_mount_defaults_to_read_write_and_compares_by_value():
    plain = VolumeMount(VOL_ID, "/data")

    assert plain.read_only is False
    assert plain == VolumeMount(VOL_ID, "/data")
    assert plain != VolumeMount(VOL_ID, "/data", read_only=True)
    assert tuple(plain) == (VOL_ID, "/data")


async def test_read_write_mounts_keep_the_wire_shape(api, client):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))
    mounts = [VolumeMount(VOL_ID, "/data"), ("vol_2", "/cache")]

    await call(client.create_sandbox, name="demo", mounts=mounts, wait=False)

    assert body_of(route)["volumes"] == [
        {"volume_id": VOL_ID, "mount_path": "/data"},
        {"volume_id": "vol_2", "mount_path": "/cache"},
    ]


def test_sync_create_sends_read_only_only_for_read_only_mounts(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))
    mounts = [VolumeMount(VOL_ID, "/data", read_only=True), VolumeMount("vol_2", "/rw")]

    with Client(BASE, KEY) as client:
        client.create_sandbox(name="demo", mounts=mounts, wait=False)

    assert body_of(route)["volumes"] == [
        {"volume_id": VOL_ID, "mount_path": "/data", "read_only": True},
        {"volume_id": "vol_2", "mount_path": "/rw"},
    ]


def test_sync_create_still_rejects_an_empty_mount_before_any_request(api):
    with Client(BASE, KEY) as client, pytest.raises(ValueError, match="mount"):
        client.create_sandbox(mounts=[VolumeMount(VOL_ID, " ", read_only=True)], wait=False)

    assert api.calls.call_count == 0


async def test_async_create_sends_read_only_only_for_read_only_mounts(api):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))
    mounts = [VolumeMount(VOL_ID, "/data", read_only=True), VolumeMount("vol_2", "/rw")]

    async with AsyncClient(BASE, KEY) as client:
        await client.create_sandbox(name="demo", mounts=mounts, wait=False)

    assert body_of(route)["volumes"] == [
        {"volume_id": VOL_ID, "mount_path": "/data", "read_only": True},
        {"volume_id": "vol_2", "mount_path": "/rw"},
    ]


async def test_legacy_pair_mounts_still_work_on_both_clients(api, client):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    await call(client.create_sandbox, name="demo", mounts=[(VOL_ID, "/data")], wait=False)

    assert body_of(route)["volumes"] == [{"volume_id": VOL_ID, "mount_path": "/data"}]


async def test_async_create_rejects_an_empty_mount_before_any_request(api):
    async with AsyncClient(BASE, KEY) as client:
        with pytest.raises(ValueError, match="mount"):
            await client.create_sandbox(mounts=[VolumeMount(VOL_ID, " ", read_only=True)])
        with pytest.raises(ValueError, match="mount"):
            await client.create_sandbox(mounts=[(" ", "/data")])

    assert api.calls.call_count == 0


def test_sandbox_info_parses_read_only_and_defaults_to_false():
    info = SandboxInfo.from_payload(
        sandbox_json(
            volumes=[
                {"volume_id": VOL_ID, "mount_path": "/data", "read_only": True},
                {"volume_id": "vol_2", "mount_path": "/old"},
            ]
        )
    )

    assert [(m.volume_id, m.mount_path, m.read_only) for m in info.volumes] == [
        (VOL_ID, "/data", True),
        ("vol_2", "/old", False),
    ]
    assert SandboxInfo.from_payload(sandbox_json()).volumes == ()


def test_sandbox_info_parses_image_mounts_and_defaults_to_empty():
    with_mounts = SandboxInfo.from_payload(sandbox_json(image_mounts=["/opt/tools", "/srv/x"]))

    assert with_mounts.image_mounts == ("/opt/tools", "/srv/x")
    assert SandboxInfo.from_payload(sandbox_json()).image_mounts == ()
    assert SandboxInfo.from_payload(sandbox_json(image_mounts=None)).image_mounts == ()


# --- CLI helpers ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def profile(monkeypatch, tmp_path):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router():
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def invoke(args, *, as_json=False):
    return RUNNER.invoke(create_app(), (["--json"] if as_json else []) + args)


# --- CLI: volume labels --------------------------------------------------------------------


def test_volume_create_sends_repeated_labels(router):
    route = router.post(VOLUMES_URL).respond(201, json=envelope(volume_json(labels={"a": "1"})))

    result = invoke(["volume", "create", "data", "--label", "a=1", "-l", "b=two=2"])

    assert result.exit_code == 0, result.output
    assert body_of(route) == {"name": "data", "labels": {"a": "1", "b": "two=2"}}


def test_cli_volume_create_without_labels_sends_only_the_name(router):
    route = router.post(VOLUMES_URL).respond(201, json=envelope(volume_json()))

    result = invoke(["volume", "create", "data"])

    assert result.exit_code == 0, result.output
    assert body_of(route) == {"name": "data"}


@pytest.mark.parametrize(
    ("labels", "message"),
    [
        (["novalue"], "expected KEY=VALUE"),
        (["=v"], "expected KEY=VALUE"),
        (["a=1", "a=2"], "more than once"),
    ],
)
def test_volume_create_label_usage_errors(router, labels, message):
    route = router.post(VOLUMES_URL).respond(201, json=envelope(volume_json()))
    args = [item for label in labels for item in ("--label", label)]

    result = invoke(["volume", "create", "data", *args])

    assert result.exit_code == EXIT_USAGE
    assert message in " ".join(result.output.split())
    assert route.call_count == 0


def test_volume_get_and_list_show_labels_in_text(router):
    router.get(f"{VOLUMES_URL}/{VOL_ID}").respond(
        200, json=envelope(volume_json(labels={"env": "ci"}))
    )
    router.get(VOLUMES_URL).respond(200, json=envelope([volume_json(labels={"env": "ci"})]))

    got = invoke(["volume", "get", VOL_ID])
    listed = invoke(["volume", "list"])

    assert got.exit_code == 0, got.output
    assert "labels" in got.output
    assert "env=ci" in got.output
    assert listed.exit_code == 0, listed.output
    assert "LABELS" in listed.output
    assert "env=ci" in listed.output


def test_volume_get_and_list_json_carry_labels(router):
    router.get(f"{VOLUMES_URL}/{VOL_ID}").respond(
        200, json=envelope(volume_json(labels={"env": "ci"}))
    )
    router.get(VOLUMES_URL).respond(
        200, json=envelope([volume_json(labels={"env": "ci"}), volume_json(id="vol_2")])
    )

    got = invoke(["volume", "get", VOL_ID], as_json=True)
    listed = invoke(["volume", "list"], as_json=True)

    assert json.loads(got.stdout)["labels"] == {"env": "ci"}
    assert [item["labels"] for item in json.loads(listed.stdout)] == [{"env": "ci"}, {}]


# --- CLI: mount parsing --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("vol_1:/data", VolumeMount("vol_1", "/data", False)),
        ("vol_1:/data:ro", VolumeMount("vol_1", "/data", True)),
        ("vol_1:/data:rw", VolumeMount("vol_1", "/data", False)),
        (" vol_1 : /data :ro", VolumeMount("vol_1", "/data", True)),
    ],
)
def test_parse_mount_reads_the_trailing_mode(value, expected):
    assert parse_mount(value) == expected


SHAPE = "expected VOLUME:PATH[:ro|rw]"
MODE_TYPO = f"mode must be ro or rw; {SHAPE}"
COLON_IN_PATH = f"contains ':' which is not allowed in a mount path; {SHAPE}"


@pytest.mark.parametrize(
    ("value", "problem"),
    [
        ("vol_1:/data:", MODE_TYPO),
        ("vol_1:/data:RO", MODE_TYPO),
        ("vol_1:/data:readonly", COLON_IN_PATH),
        ("vol_1:/data:Rw", MODE_TYPO),
        ("vol_1::ro", f"; {SHAPE}"),
        ("vol_1:/srv/a:b", COLON_IN_PATH),
    ],
)
def test_a_bad_mount_mode_is_a_usage_error_naming_the_shape(router, value, problem):
    route = router.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo", "--mount", value])

    assert result.exit_code == EXIT_USAGE
    flat = " ".join(re.sub(r"[│╭╮╰╯─]", " ", result.output).split())
    assert "Invalid value for --mount: invalid mount" in flat
    assert problem in flat
    assert route.call_count == 0


def test_sandbox_create_sends_read_only_for_a_ro_mount(router):
    route = router.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "create", "demo", "-m", "vol_1:/data:ro", "-m", "vol_2:/rw"])

    assert result.exit_code == 0, result.output
    assert body_of(route)["volumes"] == [
        {"volume_id": "vol_1", "mount_path": "/data", "read_only": True},
        {"volume_id": "vol_2", "mount_path": "/rw"},
    ]


# --- CLI: sandbox views --------------------------------------------------------------------

MOUNTED = sandbox_json(
    volumes=[
        {"volume_id": "vol_1", "mount_path": "/data", "read_only": True},
        {"volume_id": "vol_2", "mount_path": "/rw", "read_only": False},
        {"volume_id": "vol_3", "mount_path": "/old"},
    ]
)


def test_sandbox_get_text_marks_read_only_mounts(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(MOUNTED))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    flat = " ".join(result.output.split())
    assert "vol_1:/data (ro)" in flat
    assert "vol_2:/rw" in flat
    assert "vol_2:/rw (ro)" not in flat
    assert "vol_3:/old (ro)" not in flat


def test_sandbox_get_text_without_mounts_has_no_volumes_row(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(sandbox_json()))

    result = invoke(["sandbox", "get", SID])

    assert result.exit_code == 0, result.output
    assert "volumes" not in result.output


def test_sandbox_get_and_list_json_carry_read_only(router):
    router.get(f"{SANDBOXES_URL}/{SID}").respond(200, json=envelope(MOUNTED))
    router.get(SANDBOXES_URL).respond(200, json=envelope([MOUNTED, sandbox_json(id="sbx_2")]))

    got = invoke(["sandbox", "get", SID], as_json=True)
    listed = invoke(["sandbox", "list"], as_json=True)

    expected = [
        {"volume_id": "vol_1", "mount_path": "/data", "read_only": True},
        {"volume_id": "vol_2", "mount_path": "/rw", "read_only": False},
        {"volume_id": "vol_3", "mount_path": "/old", "read_only": False},
    ]
    assert json.loads(got.stdout)["volumes"] == expected
    first, second = json.loads(listed.stdout)
    assert first["volumes"] == expected
    assert second["volumes"] == []


# --- SDK: volume limit fields --------------------------------------------------------------


def test_volume_info_parses_max_bytes_and_over_limit():
    info = VolumeInfo.from_payload(volume_json(size_bytes=300, max_bytes=200, over_limit=True))

    assert info.max_bytes == 200
    assert info.over_limit is True


def test_volume_info_limit_fields_default_when_the_server_omits_them():
    info = VolumeInfo.from_payload(volume_json())

    assert info.max_bytes is None
    assert info.over_limit is False


@pytest.mark.parametrize("bad", [None, "100", True, 1.5, [1]])
def test_volume_info_ignores_a_malformed_max_bytes(bad):
    assert VolumeInfo.from_payload(volume_json(max_bytes=bad)).max_bytes is None


@pytest.mark.parametrize("bad", [None, "true", 1, 0, "yes"])
def test_volume_info_over_limit_is_true_only_for_a_json_true(bad):
    assert VolumeInfo.from_payload(volume_json(over_limit=bad)).over_limit is False


async def test_volume_get_and_list_carry_the_limit_fields(api, client):
    limited = volume_json(max_bytes=200, over_limit=True)
    api.get(f"{VOLUMES_URL}/{VOL_ID}").respond(200, json=envelope(limited))
    api.get(VOLUMES_URL).respond(200, json=envelope([limited, volume_json(id="vol_2")]))

    got = await call(client.volumes.get, VOL_ID)
    page = await call(client.volumes.list)

    assert (got.max_bytes, got.over_limit) == (200, True)
    assert [(i.max_bytes, i.over_limit) for i in page.items] == [(200, True), (None, False)]


# --- SDK: one mount wire list for both clients ---------------------------------------------


async def test_list_pair_tuple_pair_and_read_only_mount_on_both_clients(api, client):
    route = api.post(SANDBOXES_URL).respond(201, json=envelope(sandbox_json()))
    mounts = [[VOL_ID, "/a"], ("vol_2", "/b"), VolumeMount("vol_3", "/c", read_only=True)]

    await call(client.create_sandbox, name="demo", mounts=mounts, wait=False)

    assert body_of(route)["volumes"] == [
        {"volume_id": VOL_ID, "mount_path": "/a"},
        {"volume_id": "vol_2", "mount_path": "/b"},
        {"volume_id": "vol_3", "mount_path": "/c", "read_only": True},
    ]


@pytest.mark.parametrize(
    "bad",
    [(VOL_ID, "/data", True), [VOL_ID, "/data", "extra"], (VOL_ID,), "ab", (VOL_ID, 5), 7],
)
async def test_other_mount_shapes_are_refused_on_both_clients(api, client, bad):
    with pytest.raises(ValueError, match="VolumeMount") as caught:
        await call(client.create_sandbox, name="demo", mounts=[bad], wait=False)

    assert "volume_id, mount_path" in str(caught.value)
    assert api.calls.call_count == 0


# --- CLI: volume limit views through real VolumeInfo objects -------------------------------


def line_with(text, needle):
    return next(line for line in text.splitlines() if needle in line)


def test_cli_volume_get_text_and_json_show_the_limit(router):
    body = volume_json(size_bytes=300, max_bytes=200, over_limit=True)
    router.get(f"{VOLUMES_URL}/{VOL_ID}").respond(200, json=envelope(body))

    text = invoke(["volume", "get", VOL_ID])
    as_json = invoke(["volume", "get", VOL_ID], as_json=True)

    assert text.exit_code == 0, text.output
    assert "200" in line_with(text.output, "limit")
    assert "true" in line_with(text.output, "over_limit")
    payload = json.loads(as_json.stdout)
    assert (payload["max_bytes"], payload["over_limit"]) == (200, True)


def test_cli_volume_list_text_and_json_show_the_limit(router):
    over = volume_json(max_bytes=200, over_limit=True)
    router.get(VOLUMES_URL).respond(
        200, json=envelope([over, volume_json(id="vol_2", max_bytes=4096)])
    )

    text = invoke(["volume", "list"])
    as_json = invoke(["volume", "list"], as_json=True)

    assert text.exit_code == 0, text.output
    first = line_with(text.output, VOL_ID)
    second = line_with(text.output, "vol_2")
    assert "200" in first
    assert "over" in first
    assert "4096" in second
    assert "over" not in second
    rows = json.loads(as_json.stdout)
    assert [(r["max_bytes"], r["over_limit"]) for r in rows] == [(200, True), (4096, False)]
