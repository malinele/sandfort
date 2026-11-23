"""Round 60: blank volume label values, ``volume list -l``, read_only in the create audit row."""

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
from sandfort_sdk import Client  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

from sandfort.services.sandboxes import CreateSandboxCommand, SandboxService  # noqa: E402
from sandfort.services.volumes import MountRequest  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
VOL_ID = "vol_1"
CREATED = "2026-11-10T19:26:00Z"
VOLUMES_URL = "/v1/volumes"
EXIT_USAGE = 2
RUNNER = CliRunner()


def envelope(data):
    return {"success": True, "data": data, "error": None, "meta": None}


def volume_json(**extra):
    base = {"id": VOL_ID, "name": "data", "state": "ready", "created_at": CREATED}
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


# --- SDK -----------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["", " ", "\t "])
def test_sdk_volume_create_accepts_and_sends_a_blank_label_value(router, value):
    route = router.post(VOLUMES_URL).respond(201, json=envelope(volume_json()))

    with Client(BASE, KEY) as client:
        client.volumes.create("data", labels={"env": value})

    assert body_of(route) == {"name": "data", "labels": {"env": value}}


@pytest.mark.parametrize("labels", [{"": "v"}, {"  ": "v"}, {"k": None}, {"k": 1}, {1: "v"}])
def test_sdk_volume_create_still_refuses_bad_keys_and_non_string_values(router, labels):
    with Client(BASE, KEY) as client, pytest.raises(ValueError, match="label"):
        client.volumes.create("data", labels=labels)

    assert router.calls.call_count == 0


def test_sdk_volume_list_sends_a_blank_label_value(router):
    route = router.get(VOLUMES_URL).respond(200, json=envelope([]))

    with Client(BASE, KEY) as client:
        client.volumes.list(labels={"env": ""})

    assert route.calls[-1].request.url.params.get_list("label") == ["env="]


# --- CLI: create ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["env=", "env=  "])
@pytest.mark.parametrize("as_json", [False, True])
def test_cli_volume_create_sends_a_blank_label_value(router, raw, as_json):
    route = router.post(VOLUMES_URL).respond(201, json=envelope(volume_json()))

    result = invoke(["volume", "create", "data", "--label", raw], as_json=as_json)

    assert result.exit_code == 0, result.output
    assert "Traceback" not in result.output
    assert body_of(route) == {"name": "data", "labels": {"env": raw.partition("=")[2]}}


@pytest.mark.parametrize("label", ["=v", "  =v", "novalue"])
def test_cli_volume_create_blank_key_is_a_text_usage_error(router, label):
    route = router.post(VOLUMES_URL).respond(201, json=envelope(volume_json()))

    result = invoke(["volume", "create", "data", "--label", label])

    assert result.exit_code == EXIT_USAGE
    assert "Traceback" not in result.output
    shown = " ".join(result.output.replace("│", " ").split())
    assert ("blank or invisible" if label == "  =v" else "KEY=VALUE") in shown
    assert route.call_count == 0


@pytest.mark.parametrize("label", ["=v", "  =v", "novalue"])
def test_cli_volume_create_blank_key_is_a_json_usage_error(router, label):
    route = router.post(VOLUMES_URL).respond(201, json=envelope(volume_json()))

    result = invoke(["volume", "create", "data", "--label", label], as_json=True)

    assert result.exit_code == EXIT_USAGE
    assert "Traceback" not in result.output
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "USAGE_ERROR"
    assert error["source"] == "client"
    assert route.call_count == 0


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_turns_an_sdk_label_value_error_into_a_usage_error(router, monkeypatch, as_json):
    from sandfort_sdk.volumes import Volumes

    def refuse(self, name, labels=None):
        raise ValueError("label keys must be non-empty strings")

    monkeypatch.setattr(Volumes, "create", refuse)

    result = invoke(["volume", "create", "data", "--label", "a=1"], as_json=as_json)

    assert result.exit_code == EXIT_USAGE
    assert "Traceback" not in result.output
    assert "label keys must be non-empty" in " ".join(result.output.split())
    if as_json:
        assert json.loads(result.stdout)["error"]["code"] == "USAGE_ERROR"


# --- CLI: list filter ----------------------------------------------------------------------


def test_cli_volume_list_filters_by_repeated_labels(router):
    route = router.get(VOLUMES_URL).respond(200, json=envelope([volume_json()]))

    result = invoke(["volume", "list", "-l", "env=ci", "--label", "team=a", "-l", "blank="])

    assert result.exit_code == 0, result.output
    params = route.calls[-1].request.url.params
    assert params.get_list("label") == ["env=ci", "team=a", "blank="]


def test_cli_volume_list_without_a_filter_sends_no_label(router):
    route = router.get(VOLUMES_URL).respond(200, json=envelope([]))

    result = invoke(["volume", "list"])

    assert result.exit_code == 0, result.output
    assert "label" not in route.calls[-1].request.url.params


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("labels", [["=v"], ["novalue"], ["a=1", "a=2"]])
def test_cli_volume_list_bad_filter_is_a_usage_error(router, labels, as_json):
    route = router.get(VOLUMES_URL).respond(200, json=envelope([]))
    args = ["volume", "list"] + [item for label in labels for item in ("-l", label)]

    result = invoke(args, as_json=as_json)

    assert result.exit_code == EXIT_USAGE
    assert "Traceback" not in result.output
    assert route.call_count == 0
    if as_json:
        assert json.loads(result.stdout)["error"]["code"] == "USAGE_ERROR"


# --- server: the create audit row ----------------------------------------------------------


def test_create_audit_details_carry_read_only_on_every_mount():
    command = CreateSandboxCommand(
        volumes=(MountRequest("vol_1", "/data", True), MountRequest("vol_2", "/rw"))
    )

    note = SandboxService._create_note("key_1", command)

    assert note.action == "sandbox.create"
    assert note.details["volumes"] == [
        {"volume_id": "vol_1", "mount_path": "/data", "read_only": True},
        {"volume_id": "vol_2", "mount_path": "/rw", "read_only": False},
    ]


def test_create_audit_details_without_mounts_list_no_volumes():
    note = SandboxService._create_note("key_1", CreateSandboxCommand())

    assert note.details["volumes"] == []
