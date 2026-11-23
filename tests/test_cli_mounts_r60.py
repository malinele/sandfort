"""CLI round 60: ``--mount VOLUME_ID:PATH[:ro|rw]`` takes at most three colon-separated parts.

A fourth part, or a mode that is not exactly ``ro`` or ``rw``, is a usage error naming the
expected shape (exit 2) and no request is sent, instead of a path ending in ``:ro:x`` reaching
the server. A path itself can no longer hold a colon (the server refuses it, Docker bind syntax).
"""

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
import typer  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.mounts import split_mount_mode  # noqa: E402
from sandfort_cli.sandboxes import parse_mount  # noqa: E402
from sandfort_sdk import VolumeMount  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
USAGE = 2
EXPECTED_SHAPE = "expected VOLUME:PATH[:ro|rw]"
NOT_FOUND = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}
RUNNER = CliRunner()
BAD_MOUNTS = [
    pytest.param("vol_1:/data:ro:x", id="four-parts"),
    pytest.param("vol_1:/data:ro:ro", id="mode-twice"),
    pytest.param("vol_1:/data:rw:ro", id="two-modes"),
    pytest.param("vol_1:/a:b:c:d", id="five-parts"),
    pytest.param("vol_1:/data:x", id="unknown-mode"),
    pytest.param("vol_1:/data:RO", id="upper-case-mode"),
    pytest.param("vol_1:/data:readonly", id="long-mode"),
    pytest.param("vol_1:/data:", id="empty-mode"),
    pytest.param("vol_1:/srv/a:b", id="colon-in-path"),
    pytest.param("vol_1:", id="empty-path"),
    pytest.param("vol_1::ro", id="empty-path-with-mode"),
    pytest.param("vol_1: :rw", id="blank-path-with-mode"),
    pytest.param("vol_1:\t", id="tab-path"),
]
EMPTY_PATH_TAILS = ["", ":ro", ":rw", " ", " :ro", "\t:rw"]


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    """Every request is answered with a NOT_FOUND envelope and counted."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.route().mock(return_value=httpx.Response(404, json=NOT_FOUND))
        yield mock


@pytest.mark.parametrize("value", BAD_MOUNTS)
def test_parse_mount_refuses_extra_parts_and_unknown_modes(value: str) -> None:
    with pytest.raises(typer.BadParameter) as caught:
        parse_mount(value)

    assert EXPECTED_SHAPE in caught.value.message
    assert caught.value.param_hint == "--mount"


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("value", BAD_MOUNTS)
def test_a_bad_mount_is_a_usage_error_and_sends_no_request(
    router: Any, value: str, as_json: bool
) -> None:
    args = (["--json"] if as_json else []) + ["sandbox", "create", "demo", "--mount", value]

    result = RUNNER.invoke(create_app(None), args)

    assert result.exit_code == USAGE, result.output
    assert router.calls.call_count == 0
    assert "Traceback" not in result.output
    assert "Invalid value for --mount: invalid mount" in flat(result.output)
    assert EXPECTED_SHAPE in flat(result.output)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("vol_1:/data", VolumeMount("vol_1", "/data", False)),
        ("vol_1:/data:ro", VolumeMount("vol_1", "/data", True)),
        ("vol_1:/data:rw", VolumeMount("vol_1", "/data", False)),
        (" vol_1 : /data :ro", VolumeMount("vol_1", "/data", True)),
    ],
)
def test_the_three_part_shape_still_parses(value: str, expected: VolumeMount) -> None:
    assert parse_mount(value) == expected


@pytest.mark.parametrize("rest", EMPTY_PATH_TAILS)
def test_split_mount_mode_refuses_an_empty_path(rest: str) -> None:
    assert split_mount_mode(rest) is None


@pytest.mark.parametrize(
    ("rest", "expected"),
    [("/data", ("/data", False)), ("/data:ro", ("/data", True)), ("/data:rw", ("/data", False))],
)
def test_split_mount_mode_keeps_a_real_path(rest: str, expected: tuple[str, bool]) -> None:
    assert split_mount_mode(rest) == expected


def test_a_valid_mount_still_reaches_the_server(router: Any) -> None:
    result = RUNNER.invoke(
        create_app(None), ["sandbox", "create", "demo", "--mount", "vol_1:/data:rw"]
    )

    assert router.calls.call_count == 1, result.output
    assert result.exit_code != USAGE, result.output
