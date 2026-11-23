"""Request validation, round 59 (API contract fuzzing, round 58 findings).

1. ``VolumeMountSpec.mount_path`` refuses control and invisible characters, relative paths,
   empty, dot and dot-dot segments, a trailing slash, the exact system directories and
   anything under proc, sys, dev and boot, the system binary trees (bin, sbin, lib*, usr/bin,
   usr/sbin, usr/lib*, usr/libexec) at any depth, and the Docker-managed /etc files (hosts,
   hostname, resolv.conf, passwd, group, shadow). Other deeper paths (/root/work, /etc/app/data,
   /usr/local/x) are fine.
2. The reserved-label refusal has one shape on every schema that rejects reserved labels.
3. No request-model message starts with pydantic's ``Value error, `` prefix.
4. Api-key ``sandbox_labels`` keys and values are bounded like the sandbox labels.

Models are checked directly; the mount path also goes through the app on the fake driver and a
temp SQLite database (the schema refuses before any volume is looked up). No network.
"""

import inspect
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from pydantic import BaseModel, ValidationError

from sandfort.api.app import create_app
from sandfort.api.schemas import api_keys, sandboxes, text_checks
from sandfort.api.schemas.api_keys import CreateApiKeyRequest
from sandfort.api.schemas.sandboxes import (
    CreateSandboxRequest,
    ResizeSandboxRequest,
    UpdateSandboxRequest,
    VolumeMountSpec,
)
from sandfort.api.schemas.text_checks import (
    MAX_LABEL_KEY_LENGTH,
    MAX_LABEL_VALUE_LENGTH,
)
from sandfort.api.schemas.volumes import CreateVolumeRequest
from sandfort.auth.api_keys import generate_api_key
from sandfort.config import Settings
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.org import ApiKey, Org, Scope
from sandfort.ids import new_api_key_id, new_org_id

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
PEPPER = "test-pepper"
SANDBOXES = "/v1/sandboxes"
VALIDATION_STATUS = 422
PYDANTIC_PREFIX = "Value error"
VOLUME_ID = "vol_0123456789abcdef"
SCOPES = frozenset({Scope.SANDBOXES_WRITE, Scope.SANDBOXES_READ, Scope.VOLUMES_WRITE})
RESERVED_PREFIX_TEXT = "label names starting with sandfort. are reserved: "
RESERVED_SHAPE = RESERVED_PREFIX_TEXT + "sandfort.a, sandfort.b"
RESERVED_LABELS = {"sandfort.b": "1", "team": "x", "sandfort.a": "2"}

NUL_GUARD = "must not contain a NUL character"
CONTROL = "must not contain control characters"
FORMAT = "must not contain invisible format characters"
SEPARATOR = "must not contain line or paragraph separators"

# (character, the class the refusal names)
BAD_CHARACTERS = [
    pytest.param("\x1b", CONTROL, id="esc"),
    pytest.param("\t", CONTROL, id="tab"),
    pytest.param("\n", CONTROL, id="newline"),
    pytest.param("\x07", CONTROL, id="bel"),
    pytest.param("\x7f", CONTROL, id="del"),
    pytest.param("\x00", CONTROL, id="nul"),
    pytest.param("\x85", CONTROL, id="c1-nel"),
    pytest.param("\x9b", CONTROL, id="c1-csi"),
    pytest.param("‎", FORMAT, id="bidi-lrm"),
    pytest.param("‮", FORMAT, id="bidi-rlo"),
    pytest.param("⁦", FORMAT, id="bidi-lri"),
    pytest.param("​", FORMAT, id="zero-width-space"),
    pytest.param("⁠", FORMAT, id="word-joiner"),
    pytest.param(" ", SEPARATOR, id="line-separator"),
    pytest.param(" ", SEPARATOR, id="paragraph-separator"),
]

# (path, a fragment the refusal must name)
BAD_STRUCTURE = [
    pytest.param("data", "absolute", id="relative"),
    pytest.param("/", "root", id="root"),
    pytest.param("/data/", "trailing", id="trailing-slash"),
    pytest.param("/a//b", "empty segment", id="empty-middle"),
    pytest.param("//a", "empty segment", id="empty-leading"),
    pytest.param("/a/./b", "'.'", id="dot"),
    pytest.param("/a/../b", "'..'", id="dot-dot"),
    pytest.param("/..", "'..'", id="leading-dot-dot"),
    pytest.param("/.", "'.'", id="only-dot"),
    pytest.param("/ ", "visible", id="blank-segment"),
]

SYSTEM_DIRECTORIES = [
    "bin",
    "boot",
    "dev",
    "etc",
    "lib",
    "lib64",
    "proc",
    "root",
    "run",
    "sbin",
    "sys",
    "usr",
    "var",
]
# Anything below these is refused too: the kernel and device trees and the boot files.
GUARDED_TREES = ["proc", "sys", "dev", "boot"]
SYSTEM_PATHS = [
    *(f"/{name}" for name in SYSTEM_DIRECTORIES),
    *(f"/{name}/nested/dir" for name in GUARDED_TREES),
    "/var/run",
]
# Hiding these breaks every exec: refused at any depth, the directory itself included.
BINARY_TREES = [
    "bin",
    "sbin",
    "lib",
    "lib32",
    "lib64",
    "usr/bin",
    "usr/sbin",
    "usr/lib",
    "usr/lib32",
    "usr/lib64",
    "usr/libexec",
]
BINARY_PATHS = [
    *(f"/{tree}/nested/dir" for tree in BINARY_TREES),
    *(f"/{tree}" for tree in BINARY_TREES if tree.startswith("usr/")),
]
# Files Docker manages (or the image needs) in the container: refused as exact paths.
DOCKER_FILES = [
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
]
ALLOWED_PATHS = [
    "/root/work",
    "/usr/local/share/x",
    "/usr/local/bin/tool",
    "/usr/share/doc",
    "/usr/libx/y",
    "/usr/binaries",
    "/etc/app/data",
    "/etc/hosts.d",
    "/etc/hosts/x",  # the Docker-managed files are refused as exact paths only
    "/etc/passwd.d/x",
    "/etc/ssl/certs",
    "/var/lib/app/data",
    "/run/app",
    "/var/run/docker",
    "/data",
    "/workspace",
    "/home/user",
    "/opt/tool",
    "/srv/files",
    "/tmp/scratch",
    "/mnt/shared",
    "/var/lib/app",
    "/var/data",
    "/usrdata",
    "/etcetera",
    "/runner",
    "/binaries",
    "/a b",
    "/données",
    "/data/v1.2/x-y_z",
    "/.hidden",
    "/a/.b",
]


def mount_body(path: str) -> dict[str, Any]:
    return {"volumes": [{"volume_id": VOLUME_ID, "mount_path": path}]}


def problems_of(model: type[BaseModel], data: dict[str, Any]) -> list[dict[str, Any]]:
    with pytest.raises(ValidationError) as caught:
        model.model_validate(data)
    return list(caught.value.errors())


def mount_problems(path: str) -> list[dict[str, Any]]:
    return problems_of(VolumeMountSpec, {"volume_id": VOLUME_ID, "mount_path": path})


def key_body(**extra: Any) -> dict[str, Any]:
    return {"name": "scoped", "scopes": ["sandboxes:read"], **extra}


@pytest.fixture
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    pytest.importorskip("aiosqlite")
    pytest.importorskip("greenlet")
    url = f"sqlite+aiosqlite:///{tmp_path / 'validation59.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    application = create_app(Settings(driver="fake", database_url=url, api_key_pepper=PEPPER))
    try:
        yield application
    finally:
        await application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def headers(app: FastAPI) -> dict[str, str]:
    org = Org(id=new_org_id(), name="Validation", slug="validation", created_at=NOW)
    generated = generate_api_key(PEPPER)
    key = ApiKey(
        id=new_api_key_id(),
        org_id=org.id,
        name="validation",
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scopes=SCOPES,
        created_at=NOW,
    )
    async with UnitOfWork(app.state.session_factory) as uow:
        await uow.orgs.add(org)
        await uow.api_keys.add(key)
        await uow.commit()
    return {"Authorization": f"Bearer {generated.key}", "Content-Type": "application/json"}


# --- 1. mount path ----------------------------------------------------------------------------


@pytest.mark.parametrize(("char", "expected"), BAD_CHARACTERS)
async def test_mount_path_with_a_control_or_invisible_character_is_422(
    client: httpx.AsyncClient, headers: dict[str, str], char: str, expected: str
) -> None:
    response = await client.post(SANDBOXES, json=mount_body(f"/da{char}ta"), headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    issues = response.json()["error"]["details"]["errors"]
    assert len(issues) == 1, issues
    assert issues[0]["loc"] == ["body", "volumes", "0", "mount_path"]
    # Over HTTP the generic text guard (round 53) refuses NUL first, with its own wording.
    wanted = NUL_GUARD if char == "\x00" else expected
    assert wanted in issues[0]["msg"], issues[0]["msg"]
    assert PYDANTIC_PREFIX not in issues[0]["msg"]
    assert char not in issues[0]["msg"]  # the character is never echoed raw
    listed = await client.get(SANDBOXES, headers=headers)
    assert listed.json()["data"] == []


@pytest.mark.parametrize(("char", "expected"), BAD_CHARACTERS)
def test_mount_path_refusal_names_the_class_and_does_not_echo_the_character(
    char: str, expected: str
) -> None:
    issue = mount_problems(f"/a{char}b")[0]

    assert issue["msg"].startswith("mount path " + expected), issue["msg"]
    assert char not in issue["msg"]
    assert issue["type"] == "value_error"


@pytest.mark.parametrize(("char", "expected"), BAD_CHARACTERS)
def test_a_bad_character_is_refused_in_any_segment_and_at_either_end(
    char: str, expected: str
) -> None:
    for path in (f"/{char}", f"/data/{char}", f"/data{char}/x", f"/x/y{char}"):
        issue = mount_problems(path)[0]
        assert expected in issue["msg"], (path, issue["msg"])


@pytest.mark.parametrize(("path", "fragment"), BAD_STRUCTURE)
def test_mount_path_must_be_absolute_and_normalised(path: str, fragment: str) -> None:
    issues = mount_problems(path)

    assert len(issues) == 1, issues
    assert fragment in issues[0]["msg"], issues[0]["msg"]
    assert PYDANTIC_PREFIX not in issues[0]["msg"]


DOCKER_BIND_CHARACTERS = [
    pytest.param(":", "colon", id="colon"),
    pytest.param(",", "comma", id="comma"),
    pytest.param("\\", "backslash", id="backslash"),
]


@pytest.mark.parametrize(("char", "name"), DOCKER_BIND_CHARACTERS)
def test_mount_path_with_a_docker_bind_character_is_refused_and_names_it(
    char: str, name: str
) -> None:
    for path in (f"/data{char}x", f"/a/b{char}", f"/{char}data"):
        issues = mount_problems(path)

        assert len(issues) == 1, (path, issues)
        message = issues[0]["msg"]
        assert message.startswith("mount path must not contain"), message
        assert name in message, message
        assert repr(char) in message, message
        assert PYDANTIC_PREFIX not in message


def test_a_colon_mode_suffix_in_the_path_is_refused() -> None:
    issues = mount_problems("/data:ro:x")

    assert len(issues) == 1, issues
    assert "colon" in issues[0]["msg"], issues[0]["msg"]


@pytest.mark.parametrize(("char", "name"), DOCKER_BIND_CHARACTERS)
async def test_mount_path_with_a_docker_bind_character_is_422_over_http(
    client: httpx.AsyncClient, headers: dict[str, str], char: str, name: str
) -> None:
    response = await client.post(SANDBOXES, json=mount_body(f"/da{char}ta"), headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    issues = response.json()["error"]["details"]["errors"]
    assert len(issues) == 1, issues
    assert issues[0]["loc"] == ["body", "volumes", "0", "mount_path"]
    assert name in issues[0]["msg"], issues[0]["msg"]
    listed = await client.get(SANDBOXES, headers=headers)
    assert listed.json()["data"] == []


@pytest.mark.parametrize("path", SYSTEM_PATHS)
def test_system_directories_and_the_guarded_trees_are_refused(path: str) -> None:
    issues = mount_problems(path)

    assert len(issues) == 1, issues
    assert "system directory" in issues[0]["msg"], issues[0]["msg"]
    assert PYDANTIC_PREFIX not in issues[0]["msg"]


def test_the_refusal_names_the_exact_directory_or_the_tree() -> None:
    assert "cannot be the system directory /etc" in mount_problems("/etc")[0]["msg"]
    assert "cannot be under the system directory /proc" in mount_problems("/proc/x")[0]["msg"]
    assert "cannot be under the system directory /dev" in mount_problems("/dev/shm/x")[0]["msg"]


@pytest.mark.parametrize("path", BINARY_PATHS)
def test_system_binary_trees_are_refused_at_any_depth(path: str) -> None:
    issues = mount_problems(path)

    assert len(issues) == 1, issues
    assert "system binaries" in issues[0]["msg"], issues[0]["msg"]
    assert path in issues[0]["msg"]
    assert PYDANTIC_PREFIX not in issues[0]["msg"]


def test_the_binary_refusal_names_the_tree_that_matched() -> None:
    assert "under the system binaries /usr/lib64" in mount_problems("/usr/lib64/x/y")[0]["msg"]
    assert "the system binaries /usr/bin:" in mount_problems("/usr/bin")[0]["msg"]
    assert "under the system binaries /sbin" in mount_problems("/sbin/tools")[0]["msg"]
    assert "under the system binaries /lib" in mount_problems("/lib/modules-extra")[0]["msg"]


@pytest.mark.parametrize("path", DOCKER_FILES)
def test_docker_managed_files_are_refused_as_exact_paths(path: str) -> None:
    issues = mount_problems(path)

    assert len(issues) == 1, issues
    assert f"cannot be the docker-managed file {path}" in issues[0]["msg"], issues[0]["msg"]
    assert PYDANTIC_PREFIX not in issues[0]["msg"]


@pytest.mark.parametrize("path", [*BINARY_PATHS, *DOCKER_FILES])
async def test_binary_and_docker_paths_are_422_over_http(
    client: httpx.AsyncClient, headers: dict[str, str], path: str
) -> None:
    response = await client.post(SANDBOXES, json=mount_body(path), headers=headers)

    assert response.status_code == VALIDATION_STATUS, response.text
    issues = response.json()["error"]["details"]["errors"]
    assert issues[0]["loc"] == ["body", "volumes", "0", "mount_path"]


@pytest.mark.parametrize("path", ALLOWED_PATHS)
def test_ordinary_mount_paths_stay_accepted(path: str) -> None:
    spec = VolumeMountSpec.model_validate({"volume_id": VOLUME_ID, "mount_path": path})

    assert spec.mount_path == path


def test_a_dot_segment_message_names_the_segment() -> None:
    assert "'..'" in mount_problems("/a/../b")[0]["msg"]
    assert "'.'" in mount_problems("/a/./b")[0]["msg"]


def test_create_request_carries_a_valid_mount() -> None:
    request = CreateSandboxRequest.model_validate(mount_body("/workspace"))

    assert request.volumes[0].mount_path == "/workspace"


# --- 2. one reserved-label shape --------------------------------------------------------------

RESERVED_CASES = [
    pytest.param(CreateSandboxRequest, {"labels": RESERVED_LABELS}, "labels", id="sandbox"),
    pytest.param(
        CreateApiKeyRequest,
        key_body(sandbox_labels=RESERVED_LABELS),
        "sandbox_labels",
        id="api-key",
    ),
    pytest.param(
        CreateVolumeRequest, {"name": "v", "labels": RESERVED_LABELS}, "labels", id="volume"
    ),
    pytest.param(UpdateSandboxRequest, {"labels": RESERVED_LABELS}, "labels", id="sandbox-patch"),
]


def reserved_issue(model: type[BaseModel], data: dict[str, Any]) -> dict[str, Any]:
    issues = problems_of(model, data)
    assert len(issues) == 1, issues
    return issues[0]


@pytest.mark.parametrize(("model", "data", "field"), RESERVED_CASES)
def test_reserved_labels_are_refused_with_the_one_shape(
    model: type[BaseModel], data: dict[str, Any], field: str
) -> None:
    issue = reserved_issue(model, data)

    assert issue["msg"] == RESERVED_SHAPE
    assert issue["type"] == "value_error"
    assert issue["ctx"]["code"] == text_checks.RESERVED_LABEL_CODE == "RESERVED_LABEL"
    assert issue["ctx"]["names"] == ["sandfort.a", "sandfort.b"]
    assert field in [str(part) for part in issue["loc"]]


def test_the_reserved_label_error_is_one_helper_in_text_checks() -> None:
    error = text_checks.reserved_label_error(["sandfort.z", "sandfort.y"])

    assert error.message_template == RESERVED_PREFIX_TEXT + "sandfort.y, sandfort.z"
    assert error.context == {"code": "RESERVED_LABEL", "names": ["sandfort.y", "sandfort.z"]}


@pytest.mark.parametrize(("model", "data", "field"), RESERVED_CASES)
def test_a_label_name_with_braces_is_shown_as_it_is(
    model: type[BaseModel], data: dict[str, Any], field: str
) -> None:
    issue = reserved_issue(model, {**data, field: {"sandfort.{x}": "1"}})

    assert issue["msg"] == RESERVED_PREFIX_TEXT + "sandfort.{x}"


# --- 3. no pydantic prefix --------------------------------------------------------------------

BAD_INPUTS: dict[str, list[dict[str, Any]]] = {
    "VolumeMountSpec": [
        {},
        {"volume_id": VOLUME_ID, "mount_path": "relative"},
        {"volume_id": VOLUME_ID, "mount_path": "/a\x1bb"},
        {"volume_id": VOLUME_ID, "mount_path": "/a​b"},
        {"volume_id": VOLUME_ID, "mount_path": "/usr"},
        {"volume_id": VOLUME_ID, "mount_path": "/a/../b"},
        {"volume_id": VOLUME_ID, "mount_path": "/a/", "read_only": "yes"},
    ],
    "ResourceSpecRequest": [
        {"cpu_millicores": True},
        {"memory_mib": -1},
        {"unknown": 1},
    ],
    "CreateSandboxRequest": [
        {"labels": {" ": "v"}},
        {"labels": {"a\tb": "v"}},
        {"labels": RESERVED_LABELS},
        {"labels": {"k" * 64: "v"}},
        {"labels": {"k": "v" * 257}},
        {"name": "bad name"},
        {"auto_stop_minutes": True},
        {"volumes": [{"volume_id": VOLUME_ID, "mount_path": "/etc"}]},
        {"network": 5},
        {"unknown": 1},
    ],
    "UpdateSandboxRequest": [
        {"labels": {" ": "v"}},
        {"labels": {"a\x1bb": "v"}},
        {"labels": {"k" * 64: "v"}},
        {"labels": RESERVED_LABELS},
        {"public": "maybe"},
        {"auto_stop_minutes": -2},
    ],
    "ResizeSandboxRequest": [
        {},
        {"cpu_millicores": None},
        {"disk_gib": 0},
        {"memory_mib": False},
    ],
    "CreateApiKeyRequest": [
        key_body(sandbox_labels={" ": "v"}),
        key_body(sandbox_labels={"a\tb": "v"}),
        key_body(sandbox_labels=RESERVED_LABELS),
        key_body(sandbox_labels={"k" * 64: "v"}),
        key_body(sandbox_labels={"k": "v" * 257}),
        key_body(max_sandboxes=3),
        key_body(max_sandboxes=3, sandbox_labels={}),
        {**key_body(), "name": " "},
        {**key_body(), "name": "a\x1bb"},
        {**key_body(), "name": "​"},
        {**key_body(), "scopes": []},
        {**key_body(), "unknown": 1},
    ],
    "RevokeApiKeyRequest": [{"cascade": "yes"}, {"unknown": 1}],
    "CreateVolumeRequest": [{"name": "v", "labels": RESERVED_LABELS}, {"name": "-bad"}],
}


def request_models() -> dict[str, type[BaseModel]]:
    """Every request model defined in the three schema modules, by class name."""
    found: dict[str, type[BaseModel]] = {}
    for module in (sandboxes, api_keys, text_checks):
        for name, cls in inspect.getmembers(module, inspect.isclass):
            is_request = name.endswith(("Request", "Spec")) and cls.__module__ == module.__name__
            if is_request and issubclass(cls, BaseModel):
                found[name] = cls
    return found


def test_every_request_model_in_the_schema_modules_has_known_bad_inputs() -> None:
    assert request_models(), "no request model found"
    missing = sorted(set(request_models()) - set(BAD_INPUTS))
    assert not missing, f"add known-bad inputs for {missing}"


@pytest.mark.parametrize("name", sorted(BAD_INPUTS))
def test_no_request_model_message_starts_with_value_error(name: str) -> None:
    model = {**request_models(), "CreateVolumeRequest": CreateVolumeRequest}[name]

    for data in BAD_INPUTS[name]:
        issues = problems_of(model, data)
        assert issues, data
        for issue in issues:
            assert not issue["msg"].startswith(PYDANTIC_PREFIX), (name, data, issue["msg"])
            assert PYDANTIC_PREFIX not in issue["msg"], (name, data, issue["msg"])


def test_a_visible_text_refusal_has_no_prefix() -> None:
    issues = problems_of(CreateApiKeyRequest, {**key_body(), "name": "a\x1bb"})

    assert issues[0]["msg"] == CONTROL


def test_the_resize_and_label_cap_refusals_read_plainly() -> None:
    resize = problems_of(ResizeSandboxRequest, {})[0]["msg"]
    cap = problems_of(CreateApiKeyRequest, key_body(max_sandboxes=3))[0]["msg"]

    assert resize.startswith("at least one of cpu_millicores")
    assert cap.startswith("max_sandboxes requires a non-empty sandbox_labels")


def test_check_visible_text_still_raises_a_value_error_for_plain_callers() -> None:
    with pytest.raises(ValueError, match="control characters"):
        text_checks.check_visible_text("a\x1bb")


# --- 4. api-key label bounds ------------------------------------------------------------------


def test_api_key_labels_take_a_key_and_a_value_at_the_bound() -> None:
    labels = {"k" * MAX_LABEL_KEY_LENGTH: "v" * MAX_LABEL_VALUE_LENGTH}

    request = CreateApiKeyRequest.model_validate(key_body(sandbox_labels=labels))

    assert request.sandbox_labels == labels


def test_api_key_label_key_one_past_the_bound_is_refused_naming_the_limit() -> None:
    labels = {"k" * (MAX_LABEL_KEY_LENGTH + 1): "v"}

    issues = problems_of(CreateApiKeyRequest, key_body(sandbox_labels=labels))

    assert len(issues) == 1, issues
    assert issues[0]["loc"][0] == "sandbox_labels"
    assert str(MAX_LABEL_KEY_LENGTH) in issues[0]["msg"]
    assert PYDANTIC_PREFIX not in issues[0]["msg"]
    assert "k" * 20 not in issues[0]["msg"]  # a long key is not echoed


def test_api_key_label_value_one_past_the_bound_is_refused_naming_the_limit() -> None:
    labels = {"team": "v" * (MAX_LABEL_VALUE_LENGTH + 1)}

    issues = problems_of(CreateApiKeyRequest, key_body(sandbox_labels=labels))

    assert len(issues) == 1, issues
    assert str(MAX_LABEL_VALUE_LENGTH) in issues[0]["msg"]
    assert "team" in issues[0]["msg"]
    assert PYDANTIC_PREFIX not in issues[0]["msg"]
    assert "v" * 20 not in issues[0]["msg"]


def test_the_shared_label_bounds_check() -> None:
    assert (text_checks.MAX_LABELS, MAX_LABEL_KEY_LENGTH, MAX_LABEL_VALUE_LENGTH) == (32, 63, 256)
    text_checks.check_label_bounds({"k" * 63: "v" * 256})
    with pytest.raises(ValueError, match="63"):
        text_checks.check_label_bounds({"k" * 64: "v"})
    with pytest.raises(ValueError, match="256"):
        text_checks.check_label_bounds({"k": "v" * 257})
    with pytest.raises(ValueError, match="32"):
        text_checks.check_label_bounds({f"k{index}": "v" for index in range(33)})


def test_update_request_keeps_its_published_label_bounds() -> None:
    issues = problems_of(UpdateSandboxRequest, {"labels": {"k" * 64: "v"}})

    assert str(MAX_LABEL_KEY_LENGTH) in issues[0]["msg"]
