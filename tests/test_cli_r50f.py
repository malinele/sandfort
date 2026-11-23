"""CLI round 50, batch 6: review follow-up.

* Displayed text keeps its combining marks, joiners and variation selectors (Thai, Devanagari,
  Hebrew niqqud, Arabic harakat, decomposed accents, emoji sequences); secrets hidden with them
  are still masked through the matching view.
* A name that matches no sandbox answers the not-found code with no ``source`` field on every
  command that takes a sandbox reference (the lookup reached the server).
* Text and json share one rule for ``details``: sanitising, nesting depth, the entry cap (a pure
  collection, the cut only counted) and keys that sanitise to the same text.
* The ``<...>`` usage placeholders come from a subclass installed by ``sandfort_cli.output``,
  not from a patched typer class; the SDK logger the create pre-check silences still exists.
"""

import importlib
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Annotated

ROOT = Path(__file__).resolve().parents[1]
SDK_SRC = ROOT / "sdk" / "python" / "src"
CLI_SRC = ROOT / "cli" / "src"
sys.path.insert(0, str(SDK_SRC))
sys.path.insert(0, str(CLI_SRC))

import pytest  # noqa: E402
import respx  # noqa: E402
import typer  # noqa: E402
from sandfort_cli import config, output, sandboxes  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import describe_error, error_payload, relay_value  # noqa: E402
from sandfort_cli.sanitise import (  # noqa: E402
    ELLIPSIS,
    MASK,
    MAX_RELAYED_DEPTH,
    MAX_RELAYED_ENTRIES,
    sanitise_text,
    scrub_local,
)
from sandfort_sdk import InternalError  # noqa: E402
from typer import main as typer_main  # noqa: E402
from typer.core import TyperArgument  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
FOREIGN = "sf_foreign9b7c3e1d5a0f2468ace"
PASSWORD = "S3cr3tPassw0rd"
SANDBOXES_URL = "/v1/sandboxes"
PLATFORM_ERROR = 125
RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router():
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        yield mock


# 1) displayed text keeps its marks -----------------------------------------------------------

DISPLAY_TEXTS = {
    "thai": "สวัสดีครับ ภาษาไทย",
    "hindi": "नमस्ते दुनिया, हिन्दी",
    "hebrew-niqqud": "שָׁלוֹם",
    "arabic-harakat": "مَرْحَبًا",
    "decomposed-accent": "café naïve",
    "emoji-variation-selector": "heart ❤️ ok",
    "emoji-joiner-sequence": "family \U0001f468‍\U0001f469‍\U0001f467 ok",
    "keycap-enclosing-mark": "press 1️⃣ now",
    "persian-non-joiner": "می‌خواهم",
}


@pytest.mark.parametrize("text", list(DISPLAY_TEXTS.values()), ids=list(DISPLAY_TEXTS))
def test_server_text_keeps_its_marks_joiners_and_selectors(text: str) -> None:
    assert sanitise_text(text) == text
    assert sanitise_text(text, api_key=KEY) == text
    assert scrub_local(text, KEY) == text


@pytest.mark.parametrize("text", list(DISPLAY_TEXTS.values()), ids=list(DISPLAY_TEXTS))
def test_an_error_line_and_json_object_keep_the_marks(text: str) -> None:
    exc = InternalError(f"bad {text}", code="E", details={"note": text})

    shown = error_payload(exc)["error"]
    line = describe_error(exc)

    assert shown["message"] == f"bad {text}"
    assert shown["details"] == {"note": text}
    assert f"bad {text}" in line and f"note={text}" in line


def test_format_characters_and_fillers_are_still_removed_from_display() -> None:
    hostile = "a​b‮c⁠d­e⠀fㅤg\U000e0041h"

    assert sanitise_text(hostile) == "abcdefgh"


@pytest.mark.parametrize("mark", ["́", "⃝", "‍", "️", "ั"])
def test_a_key_hidden_with_marks_is_masked_and_its_neighbours_keep_theirs(mark: str) -> None:
    hidden = mark.join(KEY)

    result = sanitise_text(f"café {hidden} ok", api_key=KEY)

    assert result == f"café {MASK} ok"


@pytest.mark.parametrize("mark", ["́", "⃝", "‍", "️"])
def test_a_key_shaped_token_hidden_with_marks_is_masked(mark: str) -> None:
    result = sanitise_text(f"bad {mark.join(FOREIGN)} now")

    assert result == f"bad {MASK} now"


@pytest.mark.parametrize("mark", ["́", "‍", "️"])
def test_userinfo_hidden_with_marks_is_masked_and_the_marks_stay(mark: str) -> None:
    credentials = mark.join(f"admin:{PASSWORD}")

    result = sanitise_text(f"see ht{mark}tps://{credentials}@host.test:8443/x now")

    assert PASSWORD[:6] not in result and "admin" not in result
    assert result == f"see ht{mark}tps://host.test:8443/x now"


def test_a_fragment_behind_a_marked_scheme_separator_is_masked() -> None:
    result = sanitise_text("see http:/́/host.test/p#tok_value ok")

    assert "tok_value" not in result
    assert result == f"see http:/́/host.test/p#{MASK} ok"


# 2) a name miss: not-found code, no source, on every command --------------------------------


class FakeTerminal:
    """The part of the terminal seam ``shell`` touches before the lookup."""

    def require_interactive(self) -> None:
        return None


def invoke(args: list[str], *, as_json: bool = True):
    app = create_app(FakeTerminal())  # type: ignore[arg-type]
    return RUNNER.invoke(app, (["--json"] if as_json else []) + args)


def no_such_name(router) -> None:
    router.get(SANDBOXES_URL).respond(
        200, json={"success": True, "data": [], "error": None, "meta": None}
    )


NAME_MISS_COMMANDS = {
    "snapshot": (["snapshot", "create", "missing", "snap1"], 1),
    "cp-upload": (["cp", "{local}", "missing:/w/a.txt"], PLATFORM_ERROR),
    "cp-download": (["cp", "missing:/w/a.txt", "{local}.out"], PLATFORM_ERROR),
    "shell": (["shell", "missing"], PLATFORM_ERROR),
}


def command_for(name: str, tmp_path: Path) -> tuple[list[str], int]:
    local = tmp_path / "a.txt"
    local.write_text("hi")
    args, exit_code = NAME_MISS_COMMANDS[name]
    return [arg.replace("{local}", str(local)) for arg in args], exit_code


@pytest.mark.parametrize("name", list(NAME_MISS_COMMANDS))
def test_every_name_miss_has_the_not_found_code_and_no_source(
    router, tmp_path: Path, name: str
) -> None:
    no_such_name(router)
    args, exit_code = command_for(name, tmp_path)

    result = invoke(args)

    error = json.loads(result.stdout)["error"]
    assert result.exit_code == exit_code
    assert error["code"] == "NOT_FOUND"
    assert "source" not in error
    assert error["message"].startswith("no sandbox named 'missing'")
    assert result.stderr == ""


@pytest.mark.parametrize("name", list(NAME_MISS_COMMANDS))
def test_a_name_miss_keeps_its_text_line_and_exit_code(router, tmp_path: Path, name: str) -> None:
    no_such_name(router)
    args, exit_code = command_for(name, tmp_path)

    result = invoke(args, as_json=False)

    assert result.exit_code == exit_code
    assert result.stdout == ""
    assert result.stderr.startswith("error: NOT_FOUND: no sandbox named 'missing'")


# 3) text and json share one rule for details -------------------------------------------------


def test_text_and_json_details_share_one_depth_rule() -> None:
    deep = {"a": {"b": {"c": {"d": {"e": "x"}}}}}
    exc = InternalError("boom", code="E", details={"nested": deep, "plain": "v"})

    in_json = error_payload(exc)["error"]["details"]
    in_text = describe_error(exc)

    assert ELLIPSIS in json.dumps(in_json, ensure_ascii=False)
    assert '"x"' not in in_text
    for name, value in in_json.items():
        compact = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert f"{name}={value if isinstance(value, str) else compact}" in in_text


def test_the_depth_limit_is_counted_from_the_details_mapping() -> None:
    value: object = "leaf"
    for _ in range(MAX_RELAYED_DEPTH + 1):
        value = {"k": value}

    cleaned, _ = relay_value(value, "")

    for _ in range(MAX_RELAYED_DEPTH):
        assert isinstance(cleaned, dict)
        cleaned = cleaned["k"]
    assert cleaned == ELLIPSIS


def test_a_mapping_cut_to_the_cap_stays_pure_and_counts_the_rest() -> None:
    many = {f"k{index:03d}": index for index in range(MAX_RELAYED_ENTRIES + 25)}

    cleaned, omitted = relay_value(many, "")

    assert len(cleaned) == MAX_RELAYED_ENTRIES
    assert ELLIPSIS not in cleaned
    assert omitted == 25
    assert cleaned["k000"] == 0 and f"k{MAX_RELAYED_ENTRIES - 1:03d}" in cleaned


def test_a_list_cut_to_the_cap_stays_pure_and_counts_the_rest() -> None:
    cleaned, omitted = relay_value(list(range(MAX_RELAYED_ENTRIES + 10)), "")

    assert cleaned == list(range(MAX_RELAYED_ENTRIES))
    assert omitted == 10


def test_a_collection_at_the_cap_is_not_cut() -> None:
    full_map = {f"k{index:03d}": index for index in range(MAX_RELAYED_ENTRIES)}
    full_list = list(range(MAX_RELAYED_ENTRIES))

    assert relay_value(full_map, "") == (full_map, 0)
    assert relay_value(full_list, "") == (full_list, 0)


def test_the_text_line_names_the_cut_too() -> None:
    details = {f"k{index:03d}": index for index in range(MAX_RELAYED_ENTRIES + 5)}

    text = describe_error(InternalError("boom", code="E", details=details))

    assert "; and 5 more)" in text
    assert f"{ELLIPSIS}=" not in text
    assert f"k{MAX_RELAYED_ENTRIES + 4:03d}" not in text


def test_keys_that_sanitise_to_the_same_text_are_all_kept() -> None:
    details = {"a": 1, "a​": 2, "a​​": 3}

    assert relay_value(details, "")[0] == {"a": 1, "a#2": 2, "a#3": 3}


def test_masked_keys_do_not_overwrite_each_other() -> None:
    details = {f"{FOREIGN}1": "x", f"{FOREIGN}2": "y"}

    assert relay_value(details, "")[0] == {MASK: "x", f"{MASK}#2": "y"}


def test_a_real_ellipsis_key_is_kept_as_data_when_the_mapping_is_cut() -> None:
    count = MAX_RELAYED_ENTRIES + 10
    details = {ELLIPSIS: 0, **{f"‧{index:03d}": index for index in range(count)}}

    cleaned, omitted = relay_value(details, "")

    assert len(cleaned) == MAX_RELAYED_ENTRIES
    assert cleaned[ELLIPSIS] == 0
    assert f"{ELLIPSIS}#2" not in cleaned
    assert omitted == 1 + count - MAX_RELAYED_ENTRIES


# 4) the usage placeholders come from a subclass, installed by the output module --------------


def test_typer_own_argument_class_is_not_patched() -> None:
    assert TyperArgument.make_metavar.__qualname__ == "TyperArgument.make_metavar"
    assert typer_main.TyperArgument is output.AngleArgument
    assert issubclass(output.AngleArgument, TyperArgument)


def test_installing_twice_changes_nothing() -> None:
    output.install_angle_arguments()
    output.install_angle_arguments()

    assert typer_main.TyperArgument is output.AngleArgument


def test_importing_only_the_output_module_installs_the_subclass(tmp_path: Path) -> None:
    code = (
        f"import sys; sys.path[:0] = [{str(SDK_SRC)!r}, {str(CLI_SRC)!r}]\n"
        "import sandfort_cli.output\n"
        "import typer.main\n"
        "print(typer.main.TyperArgument.__name__, 'sandfort_cli.sandboxes' in sys.modules)\n"
    )

    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=tmp_path, check=False
    )

    assert done.returncode == 0, done.stderr
    assert done.stdout.split() == ["AngleArgument", "False"]


def test_usage_shows_angle_placeholders_for_required_and_optional_arguments() -> None:
    app = typer.Typer()

    @app.command()
    def first(
        thing: Annotated[str, typer.Argument(metavar="<thing>")],
        other: Annotated[str | None, typer.Argument(metavar="<other>")] = None,
    ) -> None:
        """First."""

    help_text = " ".join(RUNNER.invoke(app, ["--help"]).output.split())

    assert "<thing> [<other>]" in help_text
    assert "{<thing>}" not in help_text


# 5) the SDK logger the create pre-check silences still exists --------------------------------


def test_the_sdk_logger_that_the_create_pre_check_silences_still_exists() -> None:
    module = importlib.import_module(sandboxes.NAME_CHECK_LOGGER)

    assert isinstance(module.logger, logging.Logger)
    assert module.logger.name == sandboxes.NAME_CHECK_LOGGER


def test_the_quiet_name_check_filters_exactly_that_logger() -> None:
    module = importlib.import_module(sandboxes.NAME_CHECK_LOGGER)
    before = list(module.logger.filters)

    with sandboxes.quiet_name_check():
        assert len(module.logger.filters) == len(before) + 1

    assert module.logger.filters == before
