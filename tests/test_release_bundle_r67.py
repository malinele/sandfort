"""Self-host install bundle (round 67): `deploy/release-bundle.sh` and the files it ships.

No Docker and no network. The script runs against a fake wheels directory signed with an
ed25519 key generated in a temporary directory; the image and the compose stack are never built.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

from sandfort.config import Settings

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "deploy" / "release-bundle.sh"
SELFHOST = ROOT / "deploy" / "selfhost"
TAG = "v0.1.0-beta.99"
NAME = f"sandfort-selfhost-{TAG}"
PRINCIPAL = "release@sandfort.dev"
NAMESPACE = "sandfort-release"
SERVER_WHEEL = "sandfort-0.1.0b99-py3-none-any.whl"
SDK_WHEEL = "sandfort_sdk-0.1.0b99-py3-none-any.whl"
CLI_WHEEL = "sandfort_cli-0.1.0b99-py3-none-any.whl"
WHEELS = (SERVER_WHEEL, SDK_WHEEL, CLI_WHEEL)
EXPECTED_PATHS = {
    SERVER_WHEEL,
    SDK_WHEEL,
    CLI_WHEEL,
    "SHA256SUMS",
    "SHA256SUMS.sig",
    "release-allowed-signers",
    "RELEASE.txt",
    "BUNDLE-SHA256SUMS",
    "BUNDLE-SHA256SUMS.sig",
    "INSTALL.md",
    "deploy/host-setup.sh",
    "deploy/node-setup.sh",
    "deploy/seccomp.json",
    "deploy/selfhost/Dockerfile",
    "deploy/selfhost/compose.yml",
    "deploy/selfhost/sandfort.env.example",
}
SIGNED_AWAY = {"BUNDLE-SHA256SUMS", "BUNDLE-SHA256SUMS.sig"}
MAX_LINE = 100

needs_tools = pytest.mark.skipif(
    shutil.which("bash") is None
    or shutil.which("ssh-keygen") is None
    or shutil.which("shasum") is None,
    reason="needs bash, ssh-keygen and shasum",
)


def _run(
    args: list[str], cwd: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, check=False)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_signature(directory: Path, name: str, signers: Path | None = None) -> None:
    signers_file = signers or directory / "release-allowed-signers"
    with (directory / name).open("rb") as stream:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(signers_file),
                "-I",
                PRINCIPAL,
                "-n",
                NAMESPACE,
                "-s",
                str(directory / f"{name}.sig"),
            ],
            stdin=stream,
            capture_output=True,
            text=True,
            check=False,
        )
    assert result.returncode == 0, result.stderr


@pytest.fixture(scope="module")
def signing_key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if shutil.which("ssh-keygen") is None:
        pytest.skip("needs ssh-keygen")
    key = tmp_path_factory.mktemp("key") / "release-key"
    done = _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], key.parent)
    assert done.returncode == 0, done.stderr
    return key


def _make_wheels_dir(base: Path, key: Path, commit: str = "0" * 40) -> Path:
    """A directory shaped like the output of release-wheels.sh, signed with the fake key."""
    wheels = base / "wheels"
    wheels.mkdir()
    for wheel in WHEELS:
        (wheels / wheel).write_bytes(f"fake wheel {wheel}\n".encode())
    public = key.with_suffix(".pub").read_text().split()
    (wheels / "release-allowed-signers").write_text(f"{PRINCIPAL} {public[0]} {public[1]}\n")
    sums = "".join(f"{_sha256(wheels / wheel)}  {wheel}\n" for wheel in WHEELS)
    (wheels / "SHA256SUMS").write_text(sums)
    (wheels / "RELEASE.txt").write_text(
        f"built from sandfort main {commit} (tag {TAG}) on 2026-11-13T00:00:00Z\n"
        f"server wheel: {SERVER_WHEEL}\n"
        "signing key fingerprint: test\n"
    )
    signed = _run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", NAMESPACE, "SHA256SUMS"], wheels
    )
    assert signed.returncode == 0, signed.stderr
    return wheels


def _env(key: Path, **extra: str) -> dict[str, str]:
    env = {**os.environ, "SANDFORT_RELEASE_KEY": str(key)}
    env.pop("SANDFORT_BUNDLE_UNSAFE", None)
    env.update(extra)
    return env


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory, signing_key: Path) -> dict[str, Path]:
    """Run the script once; the tests read the tarball and the unpacked tree."""
    base = tmp_path_factory.mktemp("bundle")
    wheels = _make_wheels_dir(base, signing_key)
    out = base / "out"
    done = _run(
        ["bash", str(SCRIPT), TAG, str(wheels), str(out)],
        base,
        _env(signing_key, SANDFORT_BUNDLE_UNSAFE="1"),
    )
    assert done.returncode == 0, done.stdout + done.stderr
    unpacked = base / "unpacked"
    unpacked.mkdir()
    with tarfile.open(out / f"{NAME}.tar.gz") as tar:
        tar.extractall(unpacked, filter="data")
    return {"out": out, "tree": unpacked / NAME, "wheels": wheels, "stdout": Path(done.stdout)}


def _tree_files(tree: Path) -> set[str]:
    return {p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file()}


# --- the script -------------------------------------------------------------------------------


def test_script_is_valid_bash_and_executable() -> None:
    if shutil.which("bash") is None:
        pytest.skip("needs bash")
    assert _run(["bash", "-n", str(SCRIPT)], ROOT).returncode == 0
    assert os.access(SCRIPT, os.X_OK)


def test_script_reuses_the_signing_conventions() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'NAMESPACE="sandfort-release"' in text
    assert 'PRINCIPAL="release@sandfort.dev"' in text
    assert "SANDFORT_RELEASE_KEY" in text
    assert "BUNDLE-SHA256SUMS" in text


@needs_tools
def test_tarball_contains_every_expected_path(bundle: dict[str, Path]) -> None:
    with tarfile.open(bundle["out"] / f"{NAME}.tar.gz") as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
    names = {m.name for m in members}
    assert {n.split("/", 1)[0] for n in names} == {NAME}
    assert {n.split("/", 1)[1] for n in names} == EXPECTED_PATHS
    assert not [n for n in names if "/._" in n or n.endswith(".DS_Store")]


@needs_tools
def test_shipped_files_match_the_checkout_and_keep_exec_bits(bundle: dict[str, Path]) -> None:
    tree = bundle["tree"]
    for rel in (
        "deploy/host-setup.sh",
        "deploy/node-setup.sh",
        "deploy/seccomp.json",
        "deploy/selfhost/Dockerfile",
        "deploy/selfhost/compose.yml",
        "deploy/selfhost/sandfort.env.example",
    ):
        assert (tree / rel).read_bytes() == (ROOT / rel).read_bytes(), rel
    assert (tree / "INSTALL.md").read_bytes() == (SELFHOST / "INSTALL.md").read_bytes()
    for wheel in WHEELS:
        assert (tree / wheel).read_bytes() == (bundle["wheels"] / wheel).read_bytes()


@needs_tools
def test_bundle_sums_cover_every_file_and_verify(bundle: dict[str, Path]) -> None:
    tree = bundle["tree"]
    listed: dict[str, str] = {}
    for line in (tree / "BUNDLE-SHA256SUMS").read_text().splitlines():
        digest, _, path = line.partition("  ")
        listed[path] = digest
    assert set(listed) == _tree_files(tree) - SIGNED_AWAY
    for path, digest in listed.items():
        assert _sha256(tree / path) == digest, path
    # The wheels' own signature files are covered, so the one signature vouches for them too.
    assert {"SHA256SUMS", "SHA256SUMS.sig", "RELEASE.txt", "INSTALL.md"} <= set(listed)
    _verify_signature(tree, "BUNDLE-SHA256SUMS")
    done = _run(["shasum", "-a", "256", "-c", "BUNDLE-SHA256SUMS"], tree)
    assert done.returncode == 0, done.stderr


@needs_tools
def test_the_wheel_signature_still_verifies_inside_the_bundle(bundle: dict[str, Path]) -> None:
    tree = bundle["tree"]
    _verify_signature(tree, "SHA256SUMS")
    assert _run(["shasum", "-a", "256", "-c", "SHA256SUMS"], tree).returncode == 0


@needs_tools
def test_bundle_signature_rejects_a_changed_file_and_a_wrong_namespace(
    bundle: dict[str, Path], tmp_path: Path
) -> None:
    tree = tmp_path / "copy"
    shutil.copytree(bundle["tree"], tree)
    (tree / "deploy" / "seccomp.json").write_text("{}\n")
    assert _run(["shasum", "-a", "256", "-c", "BUNDLE-SHA256SUMS"], tree).returncode != 0
    with (tree / "BUNDLE-SHA256SUMS").open("rb") as stream:
        wrong = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(tree / "release-allowed-signers"),
                "-I",
                PRINCIPAL,
                "-n",
                "other-namespace",
                "-s",
                str(tree / "BUNDLE-SHA256SUMS.sig"),
            ],
            stdin=stream,
            capture_output=True,
            check=False,
        )
    assert wrong.returncode != 0


@needs_tools
def test_release_txt_names_the_bundle_verify_recipe(bundle: dict[str, Path]) -> None:
    text = (bundle["tree"] / "RELEASE.txt").read_text()
    assert f"bundle: {NAME}.tar.gz" in text
    assert f"-n {NAMESPACE}" in text and "BUNDLE-SHA256SUMS.sig" in text
    assert f"server wheel: {SERVER_WHEEL}" in text  # the release-wheels.sh lines are kept


@needs_tools
def test_signature_copies_sit_beside_the_tarball(bundle: dict[str, Path]) -> None:
    out = bundle["out"]
    assert (out / "BUNDLE-SHA256SUMS").read_bytes() == (
        bundle["tree"] / "BUNDLE-SHA256SUMS"
    ).read_bytes()
    assert (out / "BUNDLE-SHA256SUMS.sig").is_file()


@needs_tools
def test_script_refuses_wheels_that_do_not_match_their_signature(
    tmp_path: Path, signing_key: Path
) -> None:
    wheels = _make_wheels_dir(tmp_path, signing_key)
    (wheels / SERVER_WHEEL).write_bytes(b"tampered\n")
    done = _run(
        ["bash", str(SCRIPT), TAG, str(wheels), str(tmp_path / "out")],
        tmp_path,
        _env(signing_key, SANDFORT_BUNDLE_UNSAFE="1"),
    )
    assert done.returncode != 0
    assert "do not match their signature" in done.stderr
    assert not (tmp_path / "out" / f"{NAME}.tar.gz").exists()


@needs_tools
def test_script_refuses_a_missing_server_wheel(tmp_path: Path, signing_key: Path) -> None:
    wheels = _make_wheels_dir(tmp_path, signing_key)
    (wheels / SERVER_WHEEL).unlink()
    done = _run(
        ["bash", str(SCRIPT), TAG, str(wheels), str(tmp_path / "out")],
        tmp_path,
        _env(signing_key, SANDFORT_BUNDLE_UNSAFE="1"),
    )
    assert done.returncode != 0
    assert "exactly one server wheel" in done.stderr


@needs_tools
def test_script_needs_the_signing_key_and_a_safe_tag(tmp_path: Path, signing_key: Path) -> None:
    wheels = _make_wheels_dir(tmp_path, signing_key)
    env = {k: v for k, v in os.environ.items() if k != "SANDFORT_RELEASE_KEY"}
    no_key = _run(["bash", str(SCRIPT), TAG, str(wheels)], tmp_path, env)
    assert no_key.returncode != 0 and "SANDFORT_RELEASE_KEY is not set" in no_key.stderr
    bad_tag = _run(["bash", str(SCRIPT), "../x", str(wheels)], tmp_path, _env(signing_key))
    assert bad_tag.returncode != 0 and "tag may hold only" in bad_tag.stderr


@needs_tools
@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_script_refuses_deploy_files_from_another_commit(tmp_path: Path, signing_key: Path) -> None:
    wheels = _make_wheels_dir(tmp_path, signing_key, commit="deadbeef" * 5)
    done = _run(
        ["bash", str(SCRIPT), TAG, str(wheels), str(tmp_path / "out")],
        tmp_path,
        _env(signing_key),
    )
    assert done.returncode != 0
    assert "is not the wheels' commit" in done.stderr


# --- the image --------------------------------------------------------------------------------


def _dockerfile() -> str:
    return (SELFHOST / "Dockerfile").read_text(encoding="utf-8")


def test_dockerfile_copies_only_the_server_wheel_by_glob() -> None:
    copies = re.findall(r"^COPY\s+(\S+)\s+(\S+)\s*$", _dockerfile(), re.MULTILINE)
    assert copies == [("sandfort-[0-9]*.whl", "/wheels/")]
    pattern = copies[0][0]
    assert fnmatch.fnmatch(SERVER_WHEEL, pattern)
    assert not fnmatch.fnmatch(SDK_WHEEL, pattern)
    assert not fnmatch.fnmatch(CLI_WHEEL, pattern)


def test_dockerfile_installs_that_glob_and_adds_the_database_drivers() -> None:
    text = _dockerfile()
    assert "pip install --no-cache-dir /wheels/sandfort-[0-9]*.whl" in text
    assert "asyncpg" in text and "psycopg[binary]" in text
    assert "COPY src" not in text and "COPY pyproject" not in text  # no source build


def test_dockerfile_keeps_the_runtime_user_and_entrypoint_of_the_source_image() -> None:
    text = _dockerfile()
    source = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    for line in (
        "RUN useradd --create-home --uid 10001 sandfort",
        "USER sandfort",
        "EXPOSE 8000",
        "FROM python:3.12-slim",
    ):
        assert line in text and line in source, line
    assert "exec sandfort-server --host 0.0.0.0 --port 8000" in text
    assert "exec sandfort-server --host 0.0.0.0 --port 8000" in source
    assert "sandfort.admin_cli migrate" in text  # alembic.ini does not ship; the wheel carries them


# --- the compose file -------------------------------------------------------------------------


def _compose() -> dict:
    return yaml.safe_load((SELFHOST / "compose.yml").read_text(encoding="utf-8"))


def test_compose_parses_and_has_the_two_services() -> None:
    compose = _compose()
    assert set(compose["services"]) == {"api", "postgres"}
    assert compose["services"]["postgres"]["image"] == "postgres:16"
    assert "pgdata" in compose["volumes"]


def test_compose_names_only_shipped_files(bundle: dict[str, Path]) -> None:
    api = _compose()["services"]["api"]
    tree = bundle["tree"]
    compose_dir = tree / "deploy" / "selfhost"
    context = (compose_dir / api["build"]["context"]).resolve()
    assert context == tree.resolve()  # the wheels sit in the build context root
    assert (context / api["build"]["dockerfile"]).is_file()
    host_paths = [
        entry.split(":")[0]
        for entry in api["volumes"]
        if not entry.startswith("/var/run/docker.sock")
    ]
    assert host_paths == ["../seccomp.json"]
    for rel in host_paths:
        assert (compose_dir / rel).resolve().is_file(), rel
    assert any(entry.startswith("/var/run/docker.sock:") for entry in api["volumes"])


def test_compose_env_file_is_a_copy_of_the_shipped_example() -> None:
    api = _compose()["services"]["api"]
    assert api["env_file"] == ["./sandfort.env"]
    assert (SELFHOST / "sandfort.env.example").is_file()
    assert "cp sandfort.env.example sandfort.env" in (SELFHOST / "INSTALL.md").read_text()


def test_compose_keeps_the_hardening_relevant_settings() -> None:
    api = _compose()["services"]["api"]
    env = api["environment"]
    assert env["SANDFORT_ENVIRONMENT"] == "prod"
    assert env["SANDFORT_SECCOMP_PROFILE_PATH"] == "/etc/sandfort/seccomp/seccomp.json"
    assert "/etc/sandfort/seccomp/seccomp.json:ro" in api["volumes"][1]
    assert api["ports"] == ["127.0.0.1:8000:8000"]
    assert any("DOCKER_GID" in entry for entry in api["group_add"])
    assert api["build"]["network"] == "host"
    assert api["image"] == "sandfort-api"


def test_compose_notice_mount_is_optional() -> None:
    text = (SELFHOST / "compose.yml").read_text(encoding="utf-8")
    assert "# - /etc/sandfort/notice:/etc/sandfort/notice:ro" in text
    assert not [v for v in _compose()["services"]["api"]["volumes"] if "notice" in v]


# --- the settings example ---------------------------------------------------------------------


def _example_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (SELFHOST / "sandfort.env.example").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key] = value
    return values


def test_example_secrets_are_empty() -> None:
    values = _example_env()
    for name in (
        "SANDFORT_API_KEY_PEPPER",
        "SANDFORT_WEBHOOK_SECRET_KEY",
        "SANDFORT_AUDIT_CHAIN_KEY",
    ):
        assert values[name] == "", name


def test_example_covers_every_variable_prod_requires() -> None:
    values = _example_env()
    text = (SELFHOST / "sandfort.env.example").read_text(encoding="utf-8")
    for name in (
        "SANDFORT_API_KEY_PEPPER",
        "SANDFORT_WEBHOOK_SECRET_KEY",
        "SANDFORT_HOST_CAPACITY_CPU_MILLICORES",
        "SANDFORT_HOST_CAPACITY_MEMORY_MIB",
        "SANDFORT_ISOLATION_RUNTIMES",
        "SANDFORT_DEFAULT_ISOLATION",
        "SANDFORT_ENFORCE_DISK_QUOTA",
    ):
        assert name in values, name
    assert "microvm=kata" in text and "SANDFORT_STATUS_NOTICE_FILE" in text


def test_example_loads_into_settings_once_the_secrets_are_filled() -> None:
    values = _example_env()
    values["SANDFORT_API_KEY_PEPPER"] = "p" * 32
    values["SANDFORT_AUDIT_CHAIN_KEY"] = "a" * 32
    values["SANDFORT_WEBHOOK_SECRET_KEY"] = "w" * 43 + "="
    values["SANDFORT_ENVIRONMENT"] = "prod"  # compose sets these four
    values["SANDFORT_SECCOMP_PROFILE_PATH"] = "/etc/sandfort/seccomp/seccomp.json"
    values["SANDFORT_DATABASE_URL"] = "postgresql+asyncpg://sandfort:x@postgres:5432/sandfort"
    settings = Settings.from_env(values)
    assert settings.host_capacity_cpu_millicores == 6000
    assert settings.host_capacity_memory_mib == 12288
    assert settings.default_isolation == "gvisor"
    assert dict(settings.isolation_runtimes) == {"gvisor": "runsc"}


# --- INSTALL.md -------------------------------------------------------------------------------


def _install() -> str:
    return (SELFHOST / "INSTALL.md").read_text(encoding="utf-8")


def test_install_has_no_em_dash_and_short_lines() -> None:
    text = _install()
    assert "—" not in text and "–" not in text
    long = [n for n, line in enumerate(text.splitlines(), 1) if len(line) > MAX_LINE]
    assert long == []


def test_install_names_the_beta_host_requirements() -> None:
    text = _install()
    for needle in (
        "Ubuntu 24.04",
        "Docker Engine",
        "/var/lib/docker",
        "XFS",
        "pquota",
        "prjquota",
        "overlay2",
        "runsc",
        "Kata",
        "Postgres 16",
        "findmnt",
    ):
        assert needle in text, needle


def test_install_has_the_verify_and_setup_commands() -> None:
    text = _install()
    assert f"-n {NAMESPACE}" in text and f"-I {PRINCIPAL}" in text
    assert "BUNDLE-SHA256SUMS.sig" in text and "sha256sum -c BUNDLE-SHA256SUMS" in text
    assert "bash deploy/node-setup.sh --check" in text
    assert "sudo sh deploy/host-setup.sh" in text
    assert "docker compose up -d --build" in text
    assert "admin_cli migrate" in text and "admin_cli bootstrap" in text
    assert "/v1/status" in text and "sandbox create" in text
    assert "sandfort-api:previous" in text and "pg_dump" in text


def test_install_snapshot_recovery_chapter_follows_the_order() -> None:
    text = _install()
    chapter = text[text.index("## 8. Snapshot recovery through a registry") :]
    chapter = chapter[: chapter.index("\n## 9.")]
    steps = [
        "snapshot export",
        "docker load -i",
        "docker tag",
        "docker push",
        "snapshot register",
        "@sha256:",
        "sandbox create restored",
        "sha256sum /root/data.bin",
    ]
    positions = [chapter.index(step) for step in steps[:-1]]
    positions.append(chapter.rindex(steps[-1]))  # the hash is taken once before, once after
    assert positions == sorted(positions)


def test_install_webhook_chapter_enables_before_redelivering() -> None:
    text = _install()
    chapter = text[text.index("## 9. Webhook endpoints that got disabled") :]
    chapter = chapter[: chapter.index("\n## 10.")]
    assert chapter.index("webhook update <endpoint-id> --enable") < chapter.index(
        "webhook redeliver"
    )
    assert '"enabled": true' in chapter and "resets the failure counter" in chapter
    assert "409" in chapter


def test_install_lists_only_files_the_bundle_ships() -> None:
    text = _install()
    layout = text[text.index("```text") : text.index("```", text.index("```text") + 7)]
    for rel in sorted(EXPECTED_PATHS - {SERVER_WHEEL, SDK_WHEEL, CLI_WHEEL}):
        if "BUNDLE-SHA256SUMS" in rel:
            continue
        assert rel in layout or rel.split("/")[-1] in layout, rel
