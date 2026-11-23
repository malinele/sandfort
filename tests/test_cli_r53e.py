"""CLI round 53, batch e: the shared output sanitiser on the remaining success views.

``volume`` (list, get, create, rm), ``snapshot`` (list, get, create, register, rm and the build
log lines), ``key`` (list, create, revoke), ``members`` (list, add, set-role, remove), ``cmd
start``, ``cmd kill`` and ``preview`` print server text through the same helpers as the sandbox
views: terminal sequences, invisible characters and url credentials are gone in text and in
json; ordinary non-ASCII text is unchanged; the json keys and types are unchanged. Two values
are credentials and are printed exactly as the server returned them: the one-time secret of
``key create`` and the preview token.
"""

import json
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "cli" / "src"))

import click  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402
from sandfort_cli import config  # noqa: E402
from sandfort_cli.main import create_app  # noqa: E402
from sandfort_cli.output import shown, strip_dangerous_terminal  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

BASE = "http://sandfort.test"
KEY = "sf_test_key_do_not_print"
RUNNER = CliRunner()
CREATED = "2026-11-10T12:00:00Z"
SID = "sbx_01HZZZZZZZZZZZZZZZZZZZZZZZ"
SNAP_ID = "snap_01HZZZZZZZZZZZZZZZZZZZZZZ"
VOL_ID = "vol_01HZZZZZZZZZZZZZZZZZZZZZZ"
KEY_ID = "key_01HZZZZZZZZZZZZZZZZZZZZZZ"
USER_ID = "usr_01HZZZZZZZZZZZZZZZZZZZZZZ"
SECRET = "sf_Ab9Ab9Ab9Ab9Ab9Ab9Ab9_-Zz"
PREVIEW_TOKEN = "pvt_AbC123xyz"
TOKEN_PARAM = "sandfort_preview_token"
KEY_ARGS = ["key", "create", "ci", "--scope", "sandboxes:read"]
PREVIEW_ARGS = ["preview", SID, "3000"]

CLEAN = "clean"
HOSTILE = "hostile"
UNICODE = "unicode"
THAI_HINDI_EMOJI = "สวัสดี नमस्ते 👨‍👩‍👧"
# Strings that must never reach the terminal or a json document after sanitising.
FORBIDDEN = ("\x1b", "\x07", "‮", "​", "hunter2", "token=abc")

NOT_FOUND = {
    "success": False,
    "data": None,
    "error": {"code": "NOT_FOUND", "message": "gone", "details": {}, "request_id": "req_1"},
    "meta": None,
}

Route = tuple[str, str, Any]


def text(tag: str, variant: str) -> str:
    """``tag`` as a clean value, with terminal sequences, invisible characters and a url with
    credentials appended, or followed by Thai, Hindi and an emoji with joiners."""
    if variant == HOSTILE:
        return f"{tag}\x1b[31m\x1b]0;x\x07‮​ https://u:hunter2@evil.test/p?token=abc"
    if variant == UNICODE:
        return f"{tag} {THAI_HINDI_EMOJI}"
    return tag


@dataclass(frozen=True)
class Built:
    """The mocked replies of one command and the raw strings its views must show sanitised."""

    routes: list[Route]
    json_strings: list[str] = field(default_factory=list)
    text_strings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Case:
    name: str
    args: list[str]
    build: Callable[[str], Built]
    variants: tuple[str, ...] = (CLEAN, HOSTILE, UNICODE)


def envelope(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None, "meta": None}


@pytest.fixture(autouse=True)
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    monkeypatch.delenv(config.BASE_URL_ENV, raising=False)
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    config.save_profile(BASE, KEY)


@pytest.fixture
def serve() -> Iterator[Callable[[list[Route]], None]]:
    """Answer requests from a route list: (method, path suffix, data or a ready response)."""
    routes: list[Route] = []

    def handler(request: httpx.Request) -> httpx.Response:
        for method, suffix, payload in routes:
            if request.method == method and request.url.path.endswith(suffix):
                if isinstance(payload, httpx.Response):
                    return payload
                return httpx.Response(200, json=envelope(payload))
        return httpx.Response(404, json=NOT_FOUND)

    def install(new_routes: list[Route]) -> None:
        routes[:] = new_routes

    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.route().mock(side_effect=handler)
        yield install


def invoke(args: list[str], *, as_json: bool = False) -> Any:
    return RUNNER.invoke(create_app(None), (["--json"] if as_json else []) + args)


def leaves(value: Any) -> Iterator[str]:
    """Every string in a json document: the values and the keys."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from leaves(item)
    elif isinstance(value, list):
        for item in value:
            yield from leaves(item)


def shape(value: Any) -> Any:
    """The json keys and the type of every value, without the values."""
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [shape(item) for item in value]
    return type(value).__name__


def assert_clean(content: str) -> None:
    for marker in FORBIDDEN:
        assert marker not in content, (marker, content)


def run_ok(args: list[str], *, as_json: bool = False) -> Any:
    result = invoke(args, as_json=as_json)
    assert result.exit_code == 0, result.output
    return result


def json_out(result: Any) -> Any:
    return json.loads(result.stdout)


# --- the mocked replies ---------------------------------------------------------------------


def one_or_many(data: dict[str, Any], many: bool) -> Any:
    return [data] if many else data


def volume_built(
    variant: str, method: str, suffix: str, many: bool, *, id_only_text: bool = False
) -> Built:
    data = {
        "id": text("vol", variant),
        "name": text("name", variant),
        "state": text("ready", variant),
        "size_bytes": 42,
        "created_at": CREATED,
    }
    strings = [data["id"], data["name"], data["state"]]
    # r65: `volume rm` prints the id alone in text mode; --json still has every field.
    text_strings = [data["id"]] if id_only_text else strings
    return Built([(method, suffix, one_or_many(data, many))], strings, text_strings)


def snapshot_data(variant: str) -> dict[str, Any]:
    return {
        "id": text("snap", variant),
        "name": text("name", variant),
        "state": text("ready", variant),
        "image_ref": text("python:3.12", variant),
        "digest": text("sha256:abc", variant),
        "layer_count": 3,
        "source_sandbox_id": text("sbx_src", variant),
        "spec_hash": text("spec", variant),
        "created_at": CREATED,
    }


def snapshot_built(variant: str, method: str, suffix: str, many: bool) -> Built:
    data = snapshot_data(variant)
    strings = [data["id"], data["name"], data["state"], data["image_ref"]]
    if not many:
        strings += [data["digest"], data["source_sandbox_id"], data["spec_hash"]]
    return Built([(method, suffix, one_or_many(data, many))], strings, strings)


def key_data(variant: str) -> dict[str, Any]:
    return {
        "id": text("key", variant),
        "name": text("name", variant),
        "prefix": "sf_abcd",
        "scopes": ["sandboxes:read"],
        "sandbox_labels": {"team": text("lab", variant)},
        "max_sandboxes": 3,
        "created_at": CREATED,
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
        "created_by": text("owner", variant),
        "status": "active",
    }


def key_built(variant: str, method: str, suffix: str, many: bool) -> Built:
    data = key_data(variant)
    team = data["sandbox_labels"]["team"]
    json_strings = [data["id"], data["name"], data["created_by"], team]
    return Built([(method, suffix, one_or_many(data, many))], json_strings, [data["id"]])


def key_created_built(variant: str) -> Built:
    data = {**key_data(variant), "key": SECRET}
    return Built([("POST", "/v1/api-keys", data)], [data["id"], data["name"]], [])


def member_built(variant: str, method: str, suffix: str, many: bool) -> Built:
    data = {
        "user_id": text("usr", variant),
        "email": text("mail", variant),
        "display_name": text("display", variant),
        "role": text("admin", variant),
        "created_at": CREATED,
    }
    strings = [data["user_id"], data["email"], data["display_name"], data["role"]]
    return Built([(method, suffix, one_or_many(data, many))], strings, strings)


def sandbox_route() -> Route:
    data = {
        "id": SID,
        "name": "demo",
        "state": "started",
        "resources": {"cpu_millicores": 1000, "memory_mib": 512, "disk_gib": 3},
        "network": {"block_all": False},
    }
    return ("GET", SID, data)


def command_data(variant: str, state: str) -> dict[str, Any]:
    return {
        "id": text("cmd", variant),
        "session_id": text("ses", variant),
        "state": text(state, variant),
        "exit_code": None,
        "created_at": CREATED,
    }


def cmd_start_built(variant: str) -> Built:
    session = {
        "id": text("ses", variant),
        "sandbox_id": SID,
        "state": "open",
        "created_at": CREATED,
    }
    command = command_data(variant, "running")
    routes = [
        sandbox_route(),
        ("POST", "/sessions", session),
        ("POST", "/commands", {"mode": "async", "command": command}),
    ]
    strings = [session["id"], command["id"]]
    return Built(routes, strings, strings)


def cmd_kill_built(variant: str) -> Built:
    command = command_data(variant, "killed")
    strings = [command["id"], command["state"]]
    return Built([sandbox_route(), ("POST", "/kill", command)], strings, strings)


def preview_routes(url: str, token: str) -> list[Route]:
    data = {"url": url, "token": token, "port": 3000, "expires_at": CREATED}
    return [sandbox_route(), ("POST", "/preview-tokens", data)]


def preview_built(variant: str) -> Built:
    url = f"http://3000-{SID}.preview.test?{TOKEN_PARAM}={PREVIEW_TOKEN}"
    if variant == HOSTILE:
        url = text("http://x.preview.test/p", variant) + f"&{TOKEN_PARAM}={PREVIEW_TOKEN}"
    return Built(preview_routes(url, PREVIEW_TOKEN))


def volumes(
    method: str, suffix: str, many: bool, *, id_only_text: bool = False
) -> Callable[[str], Built]:
    return lambda variant: volume_built(variant, method, suffix, many, id_only_text=id_only_text)


def snapshots(method: str, suffix: str, many: bool) -> Callable[[str], Built]:
    return lambda variant: snapshot_built(variant, method, suffix, many)


def keys(method: str, suffix: str, many: bool) -> Callable[[str], Built]:
    return lambda variant: key_built(variant, method, suffix, many)


def members(method: str, suffix: str, many: bool) -> Callable[[str], Built]:
    return lambda variant: member_built(variant, method, suffix, many)


ADD_ARGS = ["members", "add", "a@b.test", "Ann", "--role", "admin"]
CASES = [
    Case("volume-create", ["volume", "create", "data"], volumes("POST", "/v1/volumes", False)),
    Case("volume-list", ["volume", "list"], volumes("GET", "/v1/volumes", True)),
    Case("volume-get", ["volume", "get", VOL_ID], volumes("GET", VOL_ID, False)),
    Case(
        "volume-rm",
        ["volume", "rm", VOL_ID],
        volumes("DELETE", VOL_ID, False, id_only_text=True),
    ),
    Case(
        "snapshot-register",
        ["snapshot", "register", "python:3.12"],
        snapshots("POST", "/v1/snapshots", False),
    ),
    Case(
        "snapshot-create",
        ["snapshot", "create", SID, "snap"],
        snapshots("POST", "/from-sandbox", False),
    ),
    Case("snapshot-list", ["snapshot", "list"], snapshots("GET", "/v1/snapshots", True)),
    Case("snapshot-get", ["snapshot", "get", SNAP_ID], snapshots("GET", SNAP_ID, False)),
    Case("snapshot-rm", ["snapshot", "rm", SNAP_ID], snapshots("DELETE", SNAP_ID, False)),
    Case("key-list", ["key", "list"], keys("GET", "/v1/api-keys", True)),
    Case("key-revoke", ["key", "revoke", KEY_ID], keys("DELETE", KEY_ID, False)),
    Case("members-list", ["members", "list"], members("GET", "/v1/org/members", True)),
    Case("members-add", ADD_ARGS, members("POST", "/v1/org/members", False)),
    Case(
        "members-set-role",
        ["members", "set-role", USER_ID, "--role", "viewer"],
        members("PATCH", USER_ID, False),
    ),
    Case("cmd-start", ["cmd", "start", SID, "--", "sleep", "9"], cmd_start_built),
    Case("cmd-kill", ["cmd", "kill", SID, "ses_1", "cmd_1"], cmd_kill_built),
    Case("preview", PREVIEW_ARGS, preview_built, variants=(CLEAN, HOSTILE)),
]
CASE_IDS = [case.name for case in CASES]
UNICODE_CASES = [case for case in CASES if UNICODE in case.variants]


def arrange(serve: Callable[[list[Route]], None], case: Case, variant: str) -> Built:
    built = case.build(variant)
    serve(built.routes)
    return built


# --- text and json of every view ------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_hostile_reply_comes_out_clean_in_text(serve: Any, case: Case) -> None:
    built = arrange(serve, case, HOSTILE)

    result = run_ok(case.args)

    assert_clean(result.stdout)
    assert_clean(result.stderr)
    flat = " ".join(result.stdout.split())
    for raw in built.text_strings:
        assert shown(raw, KEY) in flat, (raw, result.stdout)


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_hostile_reply_comes_out_clean_in_json_like_the_sandbox_views(
    serve: Any, case: Case
) -> None:
    built = arrange(serve, case, HOSTILE)

    result = run_ok(case.args, as_json=True)

    found = list(leaves(json_out(result)))
    for leaf in found:
        assert_clean(leaf)
    for raw in built.json_strings:
        assert shown(raw, KEY) in found, raw


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_json_keys_and_types_do_not_change_with_hostile_values(serve: Any, case: Case) -> None:
    arrange(serve, case, CLEAN)
    clean = json_out(run_ok(case.args, as_json=True))
    arrange(serve, case, HOSTILE)

    hostile = json_out(run_ok(case.args, as_json=True))

    assert shape(hostile) == shape(clean)


@pytest.mark.parametrize("case", UNICODE_CASES, ids=[case.name for case in UNICODE_CASES])
def test_ordinary_non_ascii_text_is_unchanged(serve: Any, case: Case) -> None:
    built = arrange(serve, case, UNICODE)

    as_text = run_ok(case.args)
    as_json = run_ok(case.args, as_json=True)

    flat = " ".join(as_text.stdout.split())
    found = list(leaves(json_out(as_json)))
    for raw in built.text_strings:
        assert shown(raw, KEY) == raw
        assert raw in flat, (raw, as_text.stdout)
    for raw in built.json_strings:
        assert raw in found, raw


# --- the credentials that are printed as returned -------------------------------------------


def test_key_create_prints_the_secret_exactly_as_returned(serve: Any) -> None:
    serve(key_created_built(HOSTILE).routes)
    assert shown(SECRET, KEY) != SECRET  # the sanitiser would mask this shape

    result = run_ok(KEY_ARGS)

    assert result.stdout == SECRET + "\n"


def test_key_create_json_keeps_the_secret_and_cleans_the_other_fields(serve: Any) -> None:
    serve(key_created_built(CLEAN).routes)
    clean = json_out(run_ok(KEY_ARGS, as_json=True))
    built = key_created_built(HOSTILE)
    serve(built.routes)

    payload = json_out(run_ok(KEY_ARGS, as_json=True))

    assert payload["key"] == SECRET
    assert shape(payload) == shape(clean)
    others = {name: value for name, value in payload.items() if name != "key"}
    found = list(leaves(others))
    for leaf in found:
        assert_clean(leaf)
    for raw in built.json_strings:
        assert shown(raw, KEY) in found


def test_key_list_json_never_carries_a_secret_field(serve: Any) -> None:
    serve(key_built(HOSTILE, "GET", "/v1/api-keys", True).routes)

    listed = json_out(run_ok(["key", "list"], as_json=True))

    assert all("key" not in item for item in listed)


def hostile_preview_url(token: str) -> str:
    query = f"?a=secret&{TOKEN_PARAM}={token}#frag"
    return "http://u:hunter2@3000-sbx.preview.test/\x1b[31mpath" + query


def test_preview_prints_an_ordinary_url_and_token_exactly_as_returned(serve: Any) -> None:
    url = f"http://3000-{SID}.preview.test?{TOKEN_PARAM}={PREVIEW_TOKEN}"
    serve(preview_routes(url, PREVIEW_TOKEN))

    as_text = run_ok(PREVIEW_ARGS)
    as_json = json_out(run_ok(PREVIEW_ARGS, as_json=True))

    assert as_text.stdout == url + "\n"
    assert as_json["url"] == url
    assert as_json["token"] == PREVIEW_TOKEN
    assert as_json["port"] == 3000
    assert set(as_json) == {"url", "token", "port", "expires_at"}


def test_preview_keeps_the_token_usable_and_cleans_the_rest_of_the_url(serve: Any) -> None:
    serve(preview_routes(hostile_preview_url(PREVIEW_TOKEN), PREVIEW_TOKEN))

    as_text = run_ok(PREVIEW_ARGS)
    as_json = json_out(run_ok(PREVIEW_ARGS, as_json=True))

    for url in (as_text.stdout.strip(), as_json["url"]):
        assert f"{TOKEN_PARAM}={PREVIEW_TOKEN}" in url
        assert_clean(url)
        assert "secret" not in url
    assert as_json["token"] == PREVIEW_TOKEN


def test_preview_token_with_terminal_sequences_is_json_exact_and_never_spliced_into_text(
    serve: Any,
) -> None:
    token = "pvt_ab\x1b[31mcd"
    serve(preview_routes(hostile_preview_url(token), token))

    as_text = run_ok(PREVIEW_ARGS)
    as_json = json_out(run_ok(PREVIEW_ARGS, as_json=True))

    assert as_json["token"] == token
    assert_clean(as_text.stdout)
    assert_clean(as_json["url"])


# --- the other mutation outputs and the build log -------------------------------------------


def test_members_remove_prints_the_id_it_removed(serve: Any) -> None:
    serve([("DELETE", USER_ID, httpx.Response(204))])

    as_text = run_ok(["members", "remove", USER_ID])
    as_json = json_out(run_ok(["members", "remove", USER_ID], as_json=True))

    assert as_text.stdout == f"removed {USER_ID}\n"
    assert as_json == {"removed": USER_ID}


def build_events(line: str, digest: str) -> bytes:
    log = json.dumps({"line": line})
    state = {"state": "ready", "snapshot_id": SNAP_ID, "digest": digest, "reason": None}
    final = json.dumps(state)
    return f"event: log\nid: 0\ndata: {log}\n\nevent: state\ndata: {final}\n\n".encode()


def build_routes(line: str, digest: str) -> list[Route]:
    pending = {**snapshot_data(CLEAN), "id": SNAP_ID, "state": "pending", "digest": None}
    stream = httpx.Response(
        200, content=build_events(line, digest), headers={"content-type": "text/event-stream"}
    )
    return [("POST", "/v1/images/builds", pending), ("GET", f"/{SNAP_ID}/logs", stream)]


def write_spec(directory: Path) -> str:
    spec = directory / "spec.json"
    spec.write_text('{"base": "python:3.12"}', encoding="utf-8")
    return str(spec)


def test_build_log_lines_are_program_output_and_the_outcome_is_sanitised(
    serve: Any, tmp_path: Path
) -> None:
    line, digest = text("step", HOSTILE), text("sha256:abc", HOSTILE)
    serve(build_routes(line, digest))

    result = run_ok(["snapshot", "build", write_spec(tmp_path)])

    # A log line is program output: only dangerous terminal sequences are removed, nothing is
    # masked. The outcome line is CLI output and goes through the full display sanitiser.
    # click.echo drops the colour (CSI) codes itself when stdout is not a terminal.
    log_line, outcome = result.stdout.splitlines()
    assert log_line == click.unstyle(strip_dangerous_terminal(line))
    assert strip_dangerous_terminal(log_line) == log_line
    assert "\x1b]" not in log_line
    assert "\x07" not in log_line
    assert_clean(outcome)
    assert outcome == f"build {SNAP_ID} ready: {shown(digest, KEY)}"


def test_build_json_outcome_is_sanitised_and_keeps_its_shape(serve: Any, tmp_path: Path) -> None:
    args = ["snapshot", "build", write_spec(tmp_path)]
    serve(build_routes("step", "sha256:abc"))
    clean = json_out(run_ok(args, as_json=True))
    digest = text("sha256:abc", HOSTILE)
    serve(build_routes("step", digest))

    payload = json_out(run_ok(args, as_json=True))

    assert payload["digest"] == shown(digest, KEY)
    assert payload["reason"] is None
    assert shape(payload) == shape(clean)
    for leaf in leaves(payload):
        assert_clean(leaf)


def test_build_log_lines_keep_non_ascii_text(serve: Any, tmp_path: Path) -> None:
    line = text("step", UNICODE)
    serve(build_routes(line, "sha256:abc"))

    result = run_ok(["snapshot", "build", write_spec(tmp_path)])

    assert result.stdout.splitlines()[0] == line
