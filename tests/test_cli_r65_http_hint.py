"""Round 65: an http:// base URL that gets a non-envelope answer names the likely cause."""

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE_MESSAGE = "response is not a Sandfort envelope"
HINT = "the server answers only https; check SANDFORT_BASE_URL"
KEY = "sf_test_key_do_not_print"
RUNNER = CliRunner()
BOTH_MODES = pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])


def run_with_base(base_url: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, as_json: bool):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(base_url, KEY)
    with respx.mock(base_url=base_url, assert_all_called=False) as router:
        router.get("/v1/volumes").respond(301, headers={"location": "https://x.test/v1/volumes"})
        return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + ["volume", "list"])


def message_of(result: Any, as_json: bool) -> str:
    if as_json:
        return str(json.loads(result.stdout)["error"]["message"])
    return " ".join(result.stderr.split())


@pytest.fixture
def tmp(tmp_path: Path) -> Iterator[Path]:
    yield tmp_path


@BOTH_MODES
def test_http_base_url_with_a_non_envelope_answer_gets_the_https_hint(
    monkeypatch: pytest.MonkeyPatch, tmp: Path, as_json: bool
) -> None:
    result = run_with_base("http://sandfort.test", monkeypatch, tmp, as_json)

    assert result.exit_code == 1
    text = message_of(result, as_json)
    assert BASE_MESSAGE in text
    assert text.count(HINT) == 1


@BOTH_MODES
def test_https_base_url_with_a_non_envelope_answer_gets_no_hint(
    monkeypatch: pytest.MonkeyPatch, tmp: Path, as_json: bool
) -> None:
    result = run_with_base("https://sandfort.test", monkeypatch, tmp, as_json)

    assert result.exit_code == 1
    text = message_of(result, as_json)
    assert BASE_MESSAGE in text
    assert HINT not in text
