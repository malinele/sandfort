"""Snapshot labels in the SDK (sync and async) and the CLI (round 64); no network (respx)."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_sdk import AsyncClient, Client, SnapshotInfo  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
SNAPSHOTS = "/v1/snapshots"
FROM_SANDBOX = f"{SNAPSHOTS}/from-sandbox"
SANDBOX_ID = "sbx_01"
CREATED = "2026-11-11T10:00:00Z"
EXIT_USAGE = 2
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def snapshot_json(**extra):
    base = {
        "id": "snap_1",
        "name": "base",
        "state": "ready",
        "image_ref": "alpine@sha256:ab",
        "layer_count": 1,
        "created_at": CREATED,
    }
    return {**base, **extra}


def body_of(route):
    return json.loads(route.calls[-1].request.content)


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


# --- SDK ---------------------------------------------------------------------------------------


def test_snapshot_info_reads_labels_and_defaults_to_empty():
    labelled = SnapshotInfo.from_payload(snapshot_json(labels={"team": "a"}))
    bare = SnapshotInfo.from_payload(snapshot_json())

    assert labelled.labels == {"team": "a"}
    assert bare.labels == {}


def test_sdk_register_sends_labels_only_when_given(router):
    route = router.post(SNAPSHOTS).respond(201, json=envelope(snapshot_json(labels={"t": "a"})))

    with Client(BASE, KEY) as client:
        plain = client.snapshots.register("alpine:3.20", name="base")
        assert body_of(route) == {"image": "alpine:3.20", "name": "base"}
        tagged = client.snapshots.register("alpine:3.20", labels={"t": "a", "blank": ""})

    assert body_of(route) == {"image": "alpine:3.20", "labels": {"t": "a", "blank": ""}}
    assert plain.labels == {"t": "a"} and tagged.labels == {"t": "a"}


def test_sdk_create_from_sandbox_sends_labels(router):
    route = router.post(FROM_SANDBOX).respond(202, json=envelope(snapshot_json(state="pending")))

    with Client(BASE, KEY) as client:
        client.snapshots.create_from_sandbox(SANDBOX_ID, "snap", labels={"env": "ci"})

    assert body_of(route) == {"sandbox_id": SANDBOX_ID, "name": "snap", "labels": {"env": "ci"}}


@pytest.mark.parametrize("labels", [{"": "v"}, {"  ": "v"}, {"k": None}, {"k": 1}])
def test_sdk_refuses_bad_labels_before_sending(router, labels):
    with Client(BASE, KEY) as client:
        with pytest.raises(ValueError, match="label"):
            client.snapshots.register("alpine:3.20", labels=labels)
        with pytest.raises(ValueError, match="label"):
            client.snapshots.create_from_sandbox(SANDBOX_ID, "snap", labels=labels)
        with pytest.raises(ValueError, match="label"):
            client.snapshots.list(labels=labels)

    assert router.calls.call_count == 0


def test_sdk_list_and_iter_send_repeated_label_params(router):
    route = router.get(SNAPSHOTS).respond(200, json=envelope([snapshot_json()]))

    with Client(BASE, KEY) as client:
        client.snapshots.list(labels={"team": "a", "blank": ""})
        listed = route.calls[-1].request.url.params.get_list("label")
        items = list(client.snapshots.iter(labels={"env": "ci"}))
        client.snapshots.list()

    assert listed == ["team=a", "blank="]
    assert len(items) == 1
    assert "label" not in route.calls[-1].request.url.params


async def test_async_sdk_register_create_and_list_use_labels(router):
    register = router.post(SNAPSHOTS).respond(201, json=envelope(snapshot_json()))
    create = router.post(FROM_SANDBOX).respond(202, json=envelope(snapshot_json()))
    listing = router.get(SNAPSHOTS).respond(200, json=envelope([snapshot_json()]))

    async with AsyncClient(BASE, KEY) as client:
        await client.snapshots.register("alpine:3.20", labels={"a": "1"})
        await client.snapshots.create_from_sandbox(SANDBOX_ID, "snap", labels={"b": "2"})
        page = await client.snapshots.list(labels={"c": "3"})
        items = [item async for item in client.snapshots.iter(labels={"c": "3"})]
        with pytest.raises(ValueError, match="label"):
            await client.snapshots.register("alpine:3.20", labels={"": "x"})

    assert body_of(register) == {"image": "alpine:3.20", "labels": {"a": "1"}}
    assert body_of(create)["labels"] == {"b": "2"}
    assert listing.calls[0].request.url.params.get_list("label") == ["c=3"]
    assert len(page.items) == 1 and len(items) == 1


# --- CLI ---------------------------------------------------------------------------------------


def test_cli_snapshot_create_sends_repeated_labels(router):
    router.get("/v1/sandboxes/sbx_01").respond(200, json=envelope({"id": SANDBOX_ID}))
    route = router.post(FROM_SANDBOX).respond(
        202, json=envelope(snapshot_json(state="pending", labels={"team": "a", "env": "ci"}))
    )

    result = invoke(["snapshot", "create", SANDBOX_ID, "snap", "-l", "team=a", "--label", "env=ci"])

    assert result.exit_code == 0, result.output
    assert body_of(route)["labels"] == {"team": "a", "env": "ci"}
    assert "team=a" in result.output and "env=ci" in result.output


def test_cli_snapshot_register_sends_labels_and_json_shows_them(router):
    route = router.post(SNAPSHOTS).respond(201, json=envelope(snapshot_json(labels={"team": "a"})))

    result = invoke(["snapshot", "register", "alpine:3.20", "-l", "team=a"], as_json=True)

    assert result.exit_code == 0, result.output
    assert body_of(route)["labels"] == {"team": "a"}
    assert json.loads(result.stdout)["labels"] == {"team": "a"}


def test_cli_snapshot_list_filters_and_shows_a_labels_column(router):
    route = router.get(SNAPSHOTS).respond(
        200, json=envelope([snapshot_json(labels={"team": "a"}), snapshot_json(id="snap_2")])
    )

    result = invoke(["snapshot", "list", "-l", "team=a", "--label", "blank="])

    assert result.exit_code == 0, result.output
    assert route.calls[-1].request.url.params.get_list("label") == ["team=a", "blank="]
    assert "LABELS" in result.output and "team=a" in result.output


def test_cli_snapshot_list_json_has_labels_for_every_item(router):
    router.get(SNAPSHOTS).respond(200, json=envelope([snapshot_json()]))

    result = invoke(["snapshot", "list"], as_json=True)

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)[0]["labels"] == {}
    assert "label" not in router.calls[-1].request.url.params


@pytest.mark.parametrize("label", ["=v", "  =v", "novalue"])
@pytest.mark.parametrize("command", [["list"], ["register", "alpine:3.20"]])
def test_cli_bad_label_is_a_usage_error_and_sends_nothing(router, command, label):
    result = invoke(["snapshot", *command, "-l", label])

    assert result.exit_code == EXIT_USAGE
    assert "Traceback" not in result.output
    assert router.calls.call_count == 0


def test_cli_snapshot_list_duplicate_key_is_a_usage_error(router):
    result = invoke(["snapshot", "list", "-l", "a=1", "-l", "a=2"])

    assert result.exit_code == EXIT_USAGE
    assert router.calls.call_count == 0
