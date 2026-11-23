"""CLI review r63n: ``volume rm`` / ``volume delete`` accept a volume name like ``--mount``.

A value that starts with ``vol_`` is an id and is sent as given; any other value is a volume
name, resolved with the same lookup as ``--mount`` (one exact match gives the id, none or
several are a usage error with the same messages), all before the DELETE request.
"""

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
USAGE = 2
VOLUMES_URL = "/v1/volumes"
CREATED = "2026-11-11T10:00:00Z"
RUNNER = CliRunner()
COMMANDS = ["rm", "delete"]


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


def volume_json(volume_id: str, name: str, state: str = "ready") -> dict[str, Any]:
    return {"id": volume_id, "name": name, "state": state, "created_at": CREATED}


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def run(command: str, value: str, *, as_json: bool = False) -> Any:
    args = ["--json"] if as_json else []
    return RUNNER.invoke(create_app(None), [*args, "volume", command, value])


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


def serve(router: Any, *volumes: dict[str, Any]) -> None:
    router.get(VOLUMES_URL).mock(return_value=httpx.Response(200, json=envelope(list(volumes))))


def deletes(router: Any) -> list[str]:
    return [call.request.url.path for call in router.calls if call.request.method == "DELETE"]


@pytest.mark.parametrize("command", COMMANDS)
def test_a_name_is_resolved_to_the_one_matching_id(router: Any, command: str) -> None:
    serve(router, volume_json("vol_1", "other"), volume_json("vol_2", "data"))
    router.delete(f"{VOLUMES_URL}/vol_2").mock(
        return_value=httpx.Response(200, json=envelope(volume_json("vol_2", "data", "deleting")))
    )

    result = run(command, "data")

    assert result.exit_code == 0, result.output
    assert deletes(router) == [f"{VOLUMES_URL}/vol_2"]


def test_an_id_is_sent_as_given_without_a_lookup(router: Any) -> None:
    list_route = router.get(VOLUMES_URL)
    router.delete(f"{VOLUMES_URL}/vol_9").mock(
        return_value=httpx.Response(200, json=envelope(volume_json("vol_9", "x", "deleting")))
    )

    result = run("rm", "vol_9")

    assert result.exit_code == 0, result.output
    assert not list_route.called
    assert deletes(router) == [f"{VOLUMES_URL}/vol_9"]


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_an_unknown_name_is_a_usage_error_and_nothing_is_deleted(
    router: Any, as_json: bool
) -> None:
    serve(router, volume_json("vol_1", "data-2"))

    result = run("rm", "data", as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert deletes(router) == []
    text = json.loads(result.output)["error"]["message"] if as_json else flat(result.output)
    assert "no volume named data (volume create data, or pass its vol_ id)" in text


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_an_ambiguous_name_lists_the_ids_and_deletes_nothing(router: Any, as_json: bool) -> None:
    serve(router, volume_json("vol_1", "data"), volume_json("vol_2", "data"))

    result = run("rm", "data", as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert deletes(router) == []
    text = json.loads(result.output)["error"]["message"] if as_json else flat(result.output)
    assert "more than one volume is named data: vol_1, vol_2; pass the vol_ id" in text


def test_a_name_with_control_characters_is_sanitised_in_the_error(router: Any) -> None:
    serve(router)

    result = run("rm", "bad\x1b[31mname")

    assert result.exit_code == USAGE, result.output
    assert "\x1b" not in result.output
    assert deletes(router) == []


def test_an_empty_value_is_still_refused_before_any_request(router: Any) -> None:
    result = run("rm", "")

    assert result.exit_code == USAGE, result.output
    assert router.calls.call_count == 0
