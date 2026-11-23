"""Release engineering polish (round 59): server version, signers file, release docs page."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
DOCKERFILE = DEPLOY / "Dockerfile"
REDEPLOY = DEPLOY / "redeploy-beta.sh"

needs_private_ops = pytest.mark.skipif(
    not REDEPLOY.is_file(),
    reason="private ops script not present in public tree",
)
RELEASE_SCRIPT = DEPLOY / "release-wheels.sh"
SCRIPTS = ROOT / "scripts"
VERSION_ARG = "SANDFORT_VERSION"
# hatch-vcs honours only the unscoped variable; the Dockerfile keeps it in the shell of the
# step that builds the project wheel, so dependencies built from an sdist are not stamped.
PRETEND = "SETUPTOOLS_SCM_PRETEND_VERSION"
SIGNERS_NAME = "release-allowed-signers"

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _build_stage(dockerfile: str) -> str:
    return dockerfile.split("FROM python:3.12-slim\n")[0]


# --- 1. server version string -------------------------------------------------------------


def test_dockerfile_declares_version_argument_with_empty_default() -> None:
    assert re.search(rf'^ARG {VERSION_ARG}=""$', _text(DOCKERFILE), re.MULTILINE)


def test_dockerfile_declares_the_argument_in_the_stage_that_builds_the_wheel() -> None:
    build = _build_stage(_text(DOCKERFILE))
    assert f'ARG {VERSION_ARG}=""' in build
    assert "pip wheel" in build
    assert build.index(f"ARG {VERSION_ARG}") < build.index("pip wheel")


def test_dockerfile_sets_pretend_version_only_when_the_argument_is_set() -> None:
    build = _build_stage(_text(DOCKERFILE))
    run = build[build.index("RUN if") :]
    assert f'[ -n "${{{VERSION_ARG}}}" ]' in run
    assert f'export {PRETEND}="${{{VERSION_ARG}}}"' in run
    assert run.index("[ -n") < run.index(f"export {PRETEND}") < run.index("pip wheel")
    # Not an unconditional ENV: an empty value would override the git-derived version.
    assert not re.search(rf"^ENV .*{PRETEND}", _text(DOCKERFILE), re.MULTILINE)


def test_dockerfile_stamps_only_the_project_wheel() -> None:
    build = _build_stage(_text(DOCKERFILE))
    steps = [step for step in build.split("\nRUN ") if "pip wheel" in step]
    assert len(steps) == 2, steps
    project, deps = steps
    assert PRETEND in project and "--no-deps" in project and project.rstrip().endswith(".")
    assert PRETEND not in deps and "uvicorn" in deps and "/wheels/sandfort-*.whl" in deps


def test_dockerfile_notes_the_build_argument_for_the_ci_workflow() -> None:
    comments = "\n".join(ln for ln in _text(DOCKERFILE).splitlines() if ln.startswith("#"))
    assert VERSION_ARG in comments
    assert "workflow" in comments.lower()


@needs_private_ops
def test_redeploy_script_passes_the_version_next_to_the_build_sha() -> None:
    text = _text(REDEPLOY)
    assert f"{VERSION_ARG}=" in text
    assert "git describe" in text
    assert f"--build-arg {VERSION_ARG}=" in text


def _version_from_describe(describe: str) -> str:
    result = subprocess.run(
        ["bash", "-c", 'source "$1"; version_from_describe "$2"', "_", str(REDEPLOY), describe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@needs_private_ops
@needs_bash
@pytest.mark.parametrize(
    ("describe", "expected"),
    [
        ("v0.1.0-beta.61-0-g1fbee7c", "0.1.0b61"),
        ("v0.1.0-beta.61-41-g1fbee7c", "0.1.0b62.dev41"),
        ("v0.1.0-beta.9-3-gabcdef0", "0.1.0b10.dev3"),
        ("v0.2.0-beta.1-0-gabcdef0", "0.2.0b1"),
        ("not-a-release-tag-5-gabcdef0", ""),
        ("", ""),
    ],
)
def test_redeploy_version_follows_the_setuptools_scm_scheme(describe: str, expected: str) -> None:
    assert _version_from_describe(describe) == expected


@needs_private_ops
@needs_bash
def test_redeploy_script_can_be_sourced_without_running_main() -> None:
    result = subprocess.run(
        ["bash", "-c", 'source "$1"; echo sourced', "_", str(REDEPLOY)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "sourced"


# --- 2. allowed signers next to the wheels ------------------------------------------------


def test_release_script_copies_the_signers_file_into_the_output_directory() -> None:
    text = _text(RELEASE_SCRIPT)
    assert re.search(rf'cp .*"\$SIGNERS" "\$OUT/{SIGNERS_NAME}"', text)


def test_release_script_verifies_with_the_delivered_signers_copy() -> None:
    text = _text(RELEASE_SCRIPT)
    verify = text[text.index("# 4) verify") :]
    verify = verify[: verify.index("# 5)")]
    assert f"-f {SIGNERS_NAME}" in verify
    assert text.index(f'"$OUT/{SIGNERS_NAME}"') < text.index("# 3) sign")


def test_release_script_writes_fingerprint_and_verify_command_into_the_note() -> None:
    text = _text(RELEASE_SCRIPT)
    assert "ssh-keygen -lf" in text
    assert "signing key fingerprint" in text
    assert "verify with:" in text
    assert f"ssh-keygen -Y verify -f {SIGNERS_NAME} -I $PRINCIPAL -n $NAMESPACE" in text
    assert "-s SHA256SUMS.sig < SHA256SUMS" in text
    # The lines are written by the block that redirects into RELEASE.txt.
    note_block = text[text.index("printf 'built from sandfort main") :]
    note_block = note_block[: note_block.index("} > RELEASE.txt")]
    assert "signing key fingerprint" in note_block
    assert "verify with:" in note_block
    assert '"$VERIFY_CMD"' in note_block and '"$FINGERPRINT"' in note_block


KEY_TYPE_PROGRAM = re.compile(r"^KEY_AWK='([^']*)'$", re.MULTILINE)
SIGNER_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIHiw6MNxs1v4hrNGr1EgS5SXXXXXXXXXXXXX"


def _key_program() -> str:
    match = KEY_TYPE_PROGRAM.search(_text(RELEASE_SCRIPT))
    assert match is not None, "KEY_AWK program not found"
    assert 'awk "$KEY_AWK" "$SIGNERS"' in _text(RELEASE_SCRIPT)
    return match.group(1)


@pytest.mark.skipif(shutil.which("awk") is None, reason="needs awk")
@pytest.mark.parametrize(
    "line",
    [
        f"release@sandfort.dev ssh-ed25519 {SIGNER_KEY}",
        f'release@sandfort.dev namespaces="sandfort-release" ssh-ed25519 {SIGNER_KEY}',
        f"release@sandfort.dev cert-authority,namespaces=\"a\" ssh-ed25519 {SIGNER_KEY}",
        f"release@sandfort.dev ssh-ed25519 {SIGNER_KEY} release key 2026",
    ],
    ids=["plain", "options", "two-options", "trailing-comment"],
)
def test_release_script_reads_the_key_with_or_without_an_options_field(
    tmp_path: Path, line: str
) -> None:
    signers = tmp_path / "signers"
    signers.write_text(f"# comment\n\n{line}\n")

    result = subprocess.run(
        ["awk", _key_program(), str(signers)], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["ssh-ed25519", SIGNER_KEY]


def test_release_script_removes_the_temporary_key_file_in_the_exit_trap() -> None:
    text = _text(RELEASE_SCRIPT)
    cleanup = text[text.index("cleanup() {") :]
    cleanup = cleanup[: cleanup.index("\n}\n")]
    assert "KEY_FILE" in cleanup
    assert 'KEY_FILE=""' in text[: text.index("cleanup() {")]
    created = text.index('KEY_FILE="$(mktemp ')
    assert text.index("trap cleanup EXIT") < created
    after = text[created:]
    assert 'rm -f "$KEY_FILE"' not in after.split("VERIFY_CMD=", 1)[0]


@needs_bash
def test_release_script_leaves_no_key_file_when_the_fingerprint_fails(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "deploy").mkdir(parents=True)
    shutil.copy(RELEASE_SCRIPT, repo / "deploy" / "release-wheels.sh")
    key = f"ssh-ed25519 {SIGNER_KEY}"
    (repo / "deploy" / SIGNERS_NAME).write_text(f"release@sandfort.dev {key}\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool, body in {
        "ssh-keygen": "exit 1",
        "pip": "exit 0",
        "shasum": "exit 0",
        "python3": "exit 0",
    }.items():
        (bin_dir / tool).write_text(f"#!/bin/sh\n{body}\n")
        (bin_dir / tool).chmod(0o755)
    git_env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/local/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    for args in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "x"], ["tag", "v1"]):
        subprocess.run(["git", *args], cwd=repo, env=git_env, check=True, capture_output=True)
    signing_key = tmp_path / "key"
    signing_key.write_text("not a real key\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    result = subprocess.run(
        ["bash", str(repo / "deploy" / "release-wheels.sh"), "v1"],
        cwd=repo,
        env={**git_env, "TMPDIR": str(scratch), "SANDFORT_RELEASE_KEY": str(signing_key)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode != 0
    assert "cannot read a public key" in result.stderr
    assert list(scratch.iterdir()) == []


@needs_bash
@pytest.mark.parametrize(
    "script", [p for p in (RELEASE_SCRIPT, REDEPLOY) if p.is_file()], ids=lambda p: p.name
)
def test_deploy_scripts_are_valid_bash(script: Path) -> None:
    result = subprocess.run(
        ["bash", "-n", str(script)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def _reminder_value(tmp_path: Path, env_line: str) -> str:
    """Run the SF_EGRESS_PROXY pipeline of the printed reminder against one env file line."""
    (tmp_path / "sandfort.env").write_bytes((env_line + "\n").encode())
    printed = subprocess.run(
        ["bash", str(REDEPLOY), "--print-host-setup-command"],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout.strip()
    pipeline = printed.split('SF_EGRESS_PROXY="$(', 1)[1].rsplit(')" sh host-setup.sh', 1)[0]
    result = subprocess.run(
        ["sh", "-c", pipeline],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
        timeout=30,
        check=True,
    )
    return result.stdout.rstrip("\n")


REMINDER_KEY = "SANDFORT_EGRESS_PROXY_ADDRESS"


@needs_private_ops
@needs_bash
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.20.30.40", "10.20.30.40:3128"),
        ("10.20.30.40:3129", "10.20.30.40:3129"),
        ("http://10.20.30.40", "10.20.30.40:3128"),
        ("http://10.20.30.40:3129", "10.20.30.40:3129"),
        ("https://10.20.30.40:3129/", "10.20.30.40:3129"),
        ("https://10.20.30.40/", "10.20.30.40:3128"),
        ("10.20.30.40 # proxy on the host", "10.20.30.40:3128"),
        ("10.20.30.40:3129  # it's the host proxy", "10.20.30.40:3129"),
        ('"10.20.30.40:3129" # quoted', "10.20.30.40:3129"),
        ("'http://10.20.30.40'", "10.20.30.40:3128"),
        ('  " 10.20.30.40 "  ', "10.20.30.40:3128"),
        ("10.20.30.40#no-space", "10.20.30.40:3128"),
        ("# only a comment", ""),
        ("", ""),
    ],
)
def test_redeploy_reminder_normalises_the_proxy_value(
    tmp_path: Path, value: str, expected: str
) -> None:
    assert _reminder_value(tmp_path, f"{REMINDER_KEY}={value}") == expected


@needs_private_ops
def test_redeploy_reminder_tests_for_a_trailing_port_not_any_colon() -> None:
    text = _text(REDEPLOY)
    command = text[text.index("host_setup_command() {") :]
    command = command[: command.index("\n}\n")]
    assert ":[0-9][0-9]*" in command
    assert "/^[^:][^:]*" not in command


def test_connect_guide_verify_recipe_matches_the_delivered_file_name() -> None:
    guide = _text(ROOT / "docs" / "connect-guide.md")
    assert f"-f {SIGNERS_NAME} -I release@sandfort.dev" in guide
    assert (DEPLOY / SIGNERS_NAME).is_file()


# --- 3. release page on the docs site -----------------------------------------------------


sys.path.insert(0, str(SCRIPTS))
import build_docs_site  # noqa: E402
import docs_theme  # noqa: E402

RELEASE_PAGE = "release.html"


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("docs-site-release")
    build_docs_site.build(out)
    return out


def test_markdown_pages_include_the_release_document() -> None:
    pages = {page.source: page.output for page in build_docs_site.MARKDOWN_PAGES}
    assert pages.get("docs/release.md") == RELEASE_PAGE


def test_documentation_links_include_the_release_page() -> None:
    assert RELEASE_PAGE in {href for href, _ in docs_theme.DOC_LINKS}


def test_docs_build_publishes_the_release_page(built: Path) -> None:
    page = (built / RELEASE_PAGE).read_text(encoding="utf-8")
    assert "<h1" in page
    assert "Releases" in page
    assert '<link rel="canonical" href="https://docs.sandfort.dev/release">' in page
    assert 'href="/release"' in page[page.index("<footer>") :]


def test_sitemap_and_not_found_page_list_the_release_page(built: Path) -> None:
    assert "https://docs.sandfort.dev/release" in (built / "sitemap.xml").read_text("utf-8")
    assert 'href="/release"' in (built / "404.html").read_text("utf-8")


@needs_private_ops
def test_deploy_key_list_includes_the_release_page() -> None:
    assert f'"{RELEASE_PAGE}=$d/{RELEASE_PAGE}"' in _text(REDEPLOY)


def test_release_document_describes_the_new_behaviour() -> None:
    doc = _text(ROOT / "docs" / "release.md")
    assert VERSION_ARG in doc
    assert SIGNERS_NAME in doc
    assert "fingerprint" in doc


def test_all_lines_in_new_and_changed_files_fit_the_limit() -> None:
    checked = (DOCKERFILE, REDEPLOY, RELEASE_SCRIPT, Path(__file__))
    for path in (p for p in checked if p.is_file()):
        for number, line in enumerate(_text(path).splitlines(), start=1):
            assert len(line) <= 100, f"{path.name}:{number}"
