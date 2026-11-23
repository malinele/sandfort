"""CLI round 61: mount path characters are named, and ``-m NAME:/path`` resolves a volume name.

A mount path holding ``:``, ``,`` or a backslash is a usage error that names the character
(exit 2, no request sent); the server rules stay authoritative, the CLI only mirrors these three.
A mount whose volume part does not start with ``vol_`` is a volume name: the org's volumes are
listed once per distinct name, exactly one exact match gives its id, none or several are a usage
error, and all of it happens before the create request.
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
import typer  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.sandboxes import parse_mount  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
USAGE = 2
FAILURE = 1
MAX_PAGE = "100"
VOLUMES_URL = "/v1/volumes"
SANDBOXES_URL = "/v1/sandboxes"
CREATED = "2026-11-11T10:00:00Z"
SHAPE = "expected VOLUME:PATH[:ro|rw]"
RUNNER = CliRunner()


def envelope(data: Any, next_cursor: str | None = None) -> dict[str, Any]:
    meta = None if next_cursor is None else {"next_cursor": next_cursor}
    return {"success": True, "data": data, "error": None, "meta": meta}


def volume_json(volume_id: str, name: str, state: str = "ready") -> dict[str, Any]:
    return {"id": volume_id, "name": name, "state": state, "created_at": CREATED}


def failure_json(code: str, message: str) -> dict[str, Any]:
    error = {"code": code, "message": message, "details": {}, "request_id": "req_1"}
    return {"success": False, "data": None, "error": error, "meta": None}


def sandbox_json() -> dict[str, Any]:
    return {
        "id": "sbx_1",
        "name": "demo",
        "state": "creating",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }


def flat(text: str) -> str:
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", text).split())


def create(*mounts: str, as_json: bool = False) -> Any:
    args = ["--json"] if as_json else []
    args += ["sandbox", "create", "demo"]
    for mount in mounts:
        args += ["-m", mount]
    return RUNNER.invoke(create_app(None), args)


def sent_volumes(router: Any) -> list[dict[str, Any]]:
    return json.loads(router.calls.last.request.content)["volumes"]


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    config.save_profile(BASE, KEY)


@pytest.fixture
def router() -> Iterator[Any]:
    created = httpx.Response(201, json=envelope(sandbox_json()))
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.post(SANDBOXES_URL).mock(return_value=created)
        yield mock


def serve_volumes(router: Any, *volumes: dict[str, Any]) -> Any:
    reply = httpx.Response(200, json=envelope(list(volumes)))
    return router.get(VOLUMES_URL).mock(return_value=reply)


def message_of(result: Any, as_json: bool) -> str:
    return json.loads(result.output)["error"]["message"] if as_json else flat(result.output)


def requests_to(router: Any, method: str, path: str) -> list[Any]:
    return [
        call.request
        for call in router.calls
        if call.request.method == method and call.request.url.path == path
    ]


# 1. Named characters ------------------------------------------------------------------------

CHARACTER_CASES = [
    pytest.param("vol_1:/a:b", ":", "/a:b", id="colon"),
    pytest.param("vol_1:/a,b", ",", "/a,b", id="comma"),
    pytest.param("vol_1:/a\\b", "\\", "/a\\\\b", id="backslash"),
    pytest.param("vol_1:/a,b:ro", ",", "/a,b", id="comma-with-mode"),
    pytest.param("vol_1:/a\\b:rw", "\\", "/a\\\\b", id="backslash-with-mode"),
    pytest.param("my-data:/a,b", ",", "/a,b", id="comma-with-volume-name"),
]


@pytest.mark.parametrize(("value", "char", "shown"), CHARACTER_CASES)
def test_parse_mount_names_the_offending_character(value: str, char: str, shown: str) -> None:
    with pytest.raises(typer.BadParameter) as caught:
        parse_mount(value)

    expected = f"mount path '{shown}' contains '{char}' which is not allowed in a mount path"
    assert expected in caught.value.message
    assert caught.value.param_hint == "--mount"


def test_the_colon_message_keeps_the_shape_and_the_invalid_mount_prefix() -> None:
    with pytest.raises(typer.BadParameter) as caught:
        parse_mount("vol_1:/a:b")

    assert caught.value.message.startswith("invalid mount")
    assert SHAPE in caught.value.message


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
@pytest.mark.parametrize(("value", "char", "shown"), CHARACTER_CASES)
def test_a_forbidden_path_character_is_a_usage_error_before_any_request(
    router: Any, value: str, char: str, shown: str, as_json: bool
) -> None:
    result = create(value, as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert router.calls.call_count == 0
    assert "Traceback" not in result.output
    text = json.loads(result.output)["error"]["message"] if as_json else flat(result.output)
    assert f"contains '{char}' which is not allowed in a mount path" in text


def test_a_path_without_those_characters_still_parses() -> None:
    mount = parse_mount("vol_1:/srv/data-1_x.y:ro")

    assert (mount.volume_id, mount.mount_path, mount.read_only) == (
        "vol_1",
        "/srv/data-1_x.y",
        True,
    )


# 2. Volume names ----------------------------------------------------------------------------


def test_a_vol_id_is_used_as_given_without_a_lookup(router: Any) -> None:
    result = create("vol_abc:/data")

    assert result.exit_code == 0, result.output
    assert requests_to(router, "GET", VOLUMES_URL) == []
    assert sent_volumes(router) == [{"volume_id": "vol_abc", "mount_path": "/data"}]


def test_a_name_resolves_to_the_id_of_its_single_exact_match(router: Any) -> None:
    serve_volumes(router, volume_json("vol_1", "data-2"), volume_json("vol_2", "data"))

    result = create("data:/data")

    assert result.exit_code == 0, result.output
    assert sent_volumes(router) == [{"volume_id": "vol_2", "mount_path": "/data"}]


def test_the_ro_suffix_works_with_a_name(router: Any) -> None:
    serve_volumes(router, volume_json("vol_2", "data"))

    result = create("data:/data:ro")

    assert result.exit_code == 0, result.output
    assert sent_volumes(router) == [
        {"volume_id": "vol_2", "mount_path": "/data", "read_only": True}
    ]


def test_a_name_and_an_id_can_be_mixed_and_keep_their_order(router: Any) -> None:
    serve_volumes(router, volume_json("vol_9", "cache"))

    result = create("vol_1:/a", "cache:/b", "vol_3:/c:ro")

    assert result.exit_code == 0, result.output
    assert [item["volume_id"] for item in sent_volumes(router)] == ["vol_1", "vol_9", "vol_3"]


def test_each_distinct_name_is_looked_up_once(router: Any) -> None:
    serve_volumes(router, volume_json("vol_1", "a"), volume_json("vol_2", "b"))

    result = create("a:/one", "b:/two", "a:/three:ro")

    assert result.exit_code == 0, result.output
    assert len(requests_to(router, "GET", VOLUMES_URL)) == 2
    assert [item["volume_id"] for item in sent_volumes(router)] == ["vol_1", "vol_2", "vol_1"]


def test_the_lookup_follows_pagination(router: Any) -> None:
    pages = [
        httpx.Response(200, json=envelope([volume_json("vol_1", "other")], "cur_2")),
        httpx.Response(200, json=envelope([volume_json("vol_2", "data")])),
    ]
    router.get(VOLUMES_URL).mock(side_effect=pages)

    result = create("data:/data")

    assert result.exit_code == 0, result.output
    assert sent_volumes(router) == [{"volume_id": "vol_2", "mount_path": "/data"}]


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_an_unknown_name_is_a_usage_error_and_no_sandbox_is_created(
    router: Any, as_json: bool
) -> None:
    serve_volumes(router, volume_json("vol_1", "data-2"), volume_json("vol_2", "Data"))

    result = create("data:/data", as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert requests_to(router, "POST", SANDBOXES_URL) == []
    assert "no volume named data (volume create data, or pass its vol_ id)" in flat(result.output)


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_an_ambiguous_name_lists_the_ids_and_creates_nothing(router: Any, as_json: bool) -> None:
    serve_volumes(router, volume_json("vol_1", "data"), volume_json("vol_2", "data"))

    result = create("data:/data", as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert requests_to(router, "POST", SANDBOXES_URL) == []
    text = flat(result.output)
    assert "more than one volume is named data" in text
    assert "vol_1" in text
    assert "vol_2" in text


def test_a_failing_name_stops_the_run_before_the_create_request(router: Any) -> None:
    serve_volumes(router, volume_json("vol_1", "a"))

    result = create("a:/one", "missing:/two")

    assert result.exit_code == USAGE, result.output
    assert requests_to(router, "POST", SANDBOXES_URL) == []


# 3. Sanitising what the usage errors echo --------------------------------------------------

DIRTY_NAMES = [
    pytest.param("bad\x1b[31mname", id="escape-sequence"),
    pytest.param("bad\rname", id="carriage-return"),
    pytest.param("bad\u202ename", id="right-to-left-override"),
    pytest.param("bad\x07name", id="bell"),
]
DIRTY_CHARS = ("\x1b", "\r", "\u202e", "\x07")


def assert_no_dirty_chars(text: str) -> None:
    for char in DIRTY_CHARS:
        assert char not in text


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("name", DIRTY_NAMES)
def test_the_name_in_the_unknown_name_error_is_sanitised(
    router: Any, name: str, as_json: bool
) -> None:
    serve_volumes(router)

    result = create(f"{name}:/data", as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert_no_dirty_chars(result.output)
    assert "no volume named bad" in message_of(result, as_json)
    assert requests_to(router, "POST", SANDBOXES_URL) == []


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("name", DIRTY_NAMES)
def test_the_name_in_the_ambiguous_ids_error_is_sanitised(
    router: Any, name: str, as_json: bool
) -> None:
    serve_volumes(router, volume_json("vol_1", name), volume_json("vol_2", name))

    result = create(f"{name}:/data", as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert_no_dirty_chars(result.output)
    message = message_of(result, as_json)
    assert "more than one volume is named bad" in message
    assert "vol_1, vol_2" in message
    assert requests_to(router, "POST", SANDBOXES_URL) == []


# 4. Mode typos get the mode message, not the colon message ---------------------------------

MODE_MESSAGE = "mode must be ro or rw"
COLON_MESSAGE = "contains ':'"
MODE_TYPOS = [
    pytest.param("vol_1:/ok:RO", id="upper-case-ro"),
    pytest.param("vol_1:/ok:Rw", id="mixed-case-rw"),
    pytest.param("vol_1:/a:", id="empty-mode"),
    pytest.param("vol_1:/a: ", id="blank-mode"),
    pytest.param("my-data:/a:RO", id="name-upper-case-ro"),
]


@pytest.mark.parametrize("value", MODE_TYPOS)
def test_a_mode_typo_says_the_mode_must_be_ro_or_rw(value: str) -> None:
    with pytest.raises(typer.BadParameter) as caught:
        parse_mount(value)

    assert MODE_MESSAGE in caught.value.message
    assert COLON_MESSAGE not in caught.value.message
    assert caught.value.message.startswith("invalid mount")
    assert SHAPE in caught.value.message


def test_a_mode_followed_by_more_parts_keeps_the_generic_shape_error() -> None:
    with pytest.raises(typer.BadParameter) as caught:
        parse_mount("vol_1:/a:rw:ro")

    assert COLON_MESSAGE not in caught.value.message
    assert MODE_MESSAGE not in caught.value.message
    assert SHAPE in caught.value.message


def test_a_forbidden_character_is_still_named_before_a_mode_typo() -> None:
    with pytest.raises(typer.BadParameter) as caught:
        parse_mount("vol_1:/a,b:RO")

    assert "contains ','" in caught.value.message


NOT_MODE_LIKE = [
    "vol_1:/a:readonly",
    "vol_1:/a:x",
    "vol_1:/a:b:ro",
    "vol_1:/a:ro/",
    "vol_1:/a:rw/x",
    "vol_1:/a:/ro",
    "vol_1:/a:ro,",
]


@pytest.mark.parametrize("value", NOT_MODE_LIKE)
def test_a_tail_that_is_not_mode_like_still_gets_the_colon_message(value: str) -> None:
    with pytest.raises(typer.BadParameter) as caught:
        parse_mount(value)

    assert COLON_MESSAGE in caught.value.message
    assert MODE_MESSAGE not in caught.value.message


@pytest.mark.parametrize("value", ["C:\\data:/p", "c:\\data"])
def test_a_windows_like_source_gets_a_message_about_the_source(value: str) -> None:
    with pytest.raises(typer.BadParameter) as caught:
        parse_mount(value)

    assert "drive letter" in caught.value.message
    assert COLON_MESSAGE not in caught.value.message
    assert "path '" not in caught.value.message
    assert SHAPE in caught.value.message


@pytest.mark.parametrize("value", ["C:\\data:/p", "c:\\data"])
def test_a_windows_like_source_in_json_mode_names_the_drive_letter(
    router: Any, value: str
) -> None:
    result = create(value, as_json=True)

    assert result.exit_code == USAGE, result.output
    assert router.calls.call_count == 0
    message = json.loads(result.output)["error"]["message"]
    assert "drive letter" in message
    assert COLON_MESSAGE not in message
    assert SHAPE in message


PARSED_MOUNTS = [
    pytest.param("vol_x:/data:ro", ("vol_x", "/data", True), id="vol-id-read-only"),
    pytest.param("VOLUME:/path", ("VOLUME", "/path", False), id="name-without-mode"),
    pytest.param("C:/x", ("C", "/x", False), id="single-letter-name"),
]


@pytest.mark.parametrize(("value", "expected"), PARSED_MOUNTS)
def test_these_mounts_parse_to_volume_path_and_mode(
    value: str, expected: tuple[str, str, bool]
) -> None:
    mount = parse_mount(value)

    assert (mount.volume_id, mount.mount_path, mount.read_only) == expected


def test_the_shape_in_the_usage_error_does_not_say_volume_id() -> None:
    with pytest.raises(typer.BadParameter) as caught:
        parse_mount("vol_1")

    assert SHAPE in caught.value.message
    assert "VOLUME_ID" not in caught.value.message


def test_a_single_letter_name_with_a_slash_path_is_a_volume_name(router: Any) -> None:
    serve_volumes(router, volume_json("vol_7", "C"))

    result = create("C:/x")

    assert result.exit_code == 0, result.output
    assert sent_volumes(router) == [{"volume_id": "vol_7", "mount_path": "/x"}]


def test_a_single_letter_name_that_does_not_exist_is_an_unknown_name(router: Any) -> None:
    serve_volumes(router)

    result = create("C:/x")

    assert result.exit_code == USAGE, result.output
    assert "no volume named C" in flat(result.output)
    assert requests_to(router, "POST", SANDBOXES_URL) == []


# 5. The lookup: page size, early stop, volume state ----------------------------------------


def test_the_lookup_asks_for_the_maximum_page_size(router: Any) -> None:
    route = serve_volumes(router, volume_json("vol_1", "data"))

    result = create("data:/data")

    assert result.exit_code == 0, result.output
    assert route.calls.last.request.url.params["limit"] == MAX_PAGE


def test_the_lookup_stops_after_the_second_match(router: Any) -> None:
    first = [volume_json("vol_1", "data"), volume_json("vol_2", "data")]
    pages = [
        httpx.Response(200, json=envelope(first, "cur_2")),
        httpx.Response(200, json=envelope([volume_json("vol_3", "data")])),
    ]
    router.get(VOLUMES_URL).mock(side_effect=pages)

    result = create("data:/data")

    assert result.exit_code == USAGE, result.output
    assert len(requests_to(router, "GET", VOLUMES_URL)) == 1
    assert "vol_1, vol_2" in flat(result.output)
    assert "vol_3" not in result.output


def test_a_deleting_volume_does_not_match(router: Any) -> None:
    serve_volumes(router, volume_json("vol_1", "data", state="deleting"))

    result = create("data:/data")

    assert result.exit_code == USAGE, result.output
    assert "no volume named data" in flat(result.output)
    assert requests_to(router, "POST", SANDBOXES_URL) == []


def test_a_deleting_volume_does_not_make_a_name_ambiguous(router: Any) -> None:
    serve_volumes(
        router,
        volume_json("vol_1", "data", state="deleting"),
        volume_json("vol_2", "data"),
        volume_json("vol_3", "data", state="deleting"),
    )

    result = create("data:/data")

    assert result.exit_code == 0, result.output
    assert sent_volumes(router) == [{"volume_id": "vol_2", "mount_path": "/data"}]


# 6. A value starting with vol_ is always an id ---------------------------------------------


def test_a_volume_named_like_an_id_cannot_be_mounted_by_name(router: Any) -> None:
    serve_volumes(router, volume_json("vol_real", "vol_data"))

    result = create("vol_data:/data")

    assert result.exit_code == 0, result.output
    assert requests_to(router, "GET", VOLUMES_URL) == []
    assert sent_volumes(router) == [{"volume_id": "vol_data", "mount_path": "/data"}]


def test_a_mistyped_id_reaches_the_server(router: Any) -> None:
    gone = httpx.Response(404, json=failure_json("NOT_FOUND", "no such volume"))
    router.post(SANDBOXES_URL).mock(return_value=gone)

    result = create("vol_tpyo:/data")

    assert result.exit_code != USAGE, result.output
    assert requests_to(router, "GET", VOLUMES_URL) == []
    assert len(requests_to(router, "POST", SANDBOXES_URL)) == 1


def test_the_mount_help_documents_the_shape_and_the_vol_prefix_rule() -> None:
    wide = {"COLUMNS": "240", "TERMINAL_WIDTH": "240"}  # a narrow help column crops long tokens

    result = RUNNER.invoke(create_app(None), ["sandbox", "create", "--help"], env=wide)

    assert result.exit_code == 0, result.output
    full = flat(result.output)
    start = full.index("--mount")
    text = full[start : start + 600]
    assert "VOLUME:PATH[:ro|rw]" in text, text
    assert "volume name" in text, text
    assert "starting with vol_ is always an id" in text, text
    assert "VOLUME_ID" not in text, text
    own = text[: text.index("--egress")]  # the help of --mount only, not the next option's
    assert own.count("(") == 1, own
    assert own.rstrip().endswith("(repeatable)."), own


# 7. Lookup failures ------------------------------------------------------------------------


def serve_lookup_failure(router: Any, kind: str) -> None:
    if kind == "connect-error":
        router.get(VOLUMES_URL).mock(side_effect=httpx.ConnectError("refused"))
        return
    status, code = {"401": (401, "UNAUTHORIZED"), "500": (500, "INTERNAL")}[kind]
    reply = httpx.Response(status, json=failure_json(code, "lookup failed"))
    router.get(VOLUMES_URL).mock(return_value=reply)


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("kind", ["401", "500", "connect-error"])
def test_a_failing_lookup_fails_the_command_and_creates_nothing(
    router: Any, kind: str, as_json: bool
) -> None:
    serve_lookup_failure(router, kind)

    result = create("data:/data", as_json=as_json)

    assert result.exit_code == FAILURE, result.output
    assert "Traceback" not in result.output
    assert requests_to(router, "POST", SANDBOXES_URL) == []
    assert KEY not in result.output


# 8. A blank volume part is a usage error before any request --------------------------------

BLANK_SOURCES = [
    pytest.param(" :/data", id="spaces"),
    pytest.param("\t:/data", id="tab"),
    pytest.param("\x1b[31m:/data", id="escape-only"),
    pytest.param("\x07\x08:/data", id="control-only"),
    pytest.param("\u202e:/data", id="override-only"),
]


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("value", BLANK_SOURCES)
def test_a_blank_volume_part_is_a_usage_error_before_any_request(
    router: Any, value: str, as_json: bool
) -> None:
    result = create(value, as_json=as_json)

    assert result.exit_code == USAGE, result.output
    assert router.calls.call_count == 0
    assert "Traceback" not in result.output
