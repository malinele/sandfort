"""Release wheels (round 61): the server wheel ships next to the SDK and CLI wheels.

Static checks of `deploy/release-wheels.sh` and `docs/release.md`; the release is not run.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RELEASE_SCRIPT = ROOT / "deploy" / "release-wheels.sh"
RELEASE_DOC = ROOT / "docs" / "release.md"
SERVER_STAMP = '"src/sandfort/$STAMP_NAME"'
SERVER_BUILD = 'pip wheel --no-deps --wheel-dir "$OUT" .'
SDK_BUILD = 'pip wheel --no-deps --wheel-dir "$OUT" ./sdk/python'
CLI_BUILD = 'pip wheel --no-deps --wheel-dir "$OUT" ./cli'

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _script() -> str:
    return RELEASE_SCRIPT.read_text(encoding="utf-8")


def _doc() -> str:
    return RELEASE_DOC.read_text(encoding="utf-8")


def _section(text: str, start: str, end: str) -> str:
    body = text[text.index(start) :]
    return body[: body.index(end)]


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


# --- build and stamp ----------------------------------------------------------------------


def test_server_package_is_stamped_like_the_sdk_and_cli() -> None:
    stamps = _section(_script(), "STAMPS=(", ")")
    assert SERVER_STAMP in stamps
    assert '"sdk/python/src/sandfort_sdk/$STAMP_NAME"' in stamps
    assert '"cli/src/sandfort_cli/$STAMP_NAME"' in stamps


def test_server_wheel_is_built_between_stamping_and_unstamping() -> None:
    text = _script()
    stamped = text.index('> "$stamp"')
    unstamped = text.index('rm -f "${STAMPS[@]}"', stamped)
    for build in (SERVER_BUILD, SDK_BUILD, CLI_BUILD):
        assert re.search(rf"^{re.escape(build)}$", text, re.MULTILINE), build
        assert stamped < text.index(build) < unstamped, build


def test_stamp_carries_commit_tag_and_build_time_for_every_package() -> None:
    loop = _section(_script(), 'for stamp in "${STAMPS[@]}"; do', "done")
    assert '"commit": "%s", "tag": "%s", "built_at": "%s"' in loop
    assert '"$COMMIT" "$TAG" "$BUILT_AT"' in loop


def test_server_wheel_version_comes_from_the_tag() -> None:
    # The wheel is built on the tag's commit by hatch-vcs, like the SDK and CLI; no override.
    text = _script()
    assert "SETUPTOOLS_SCM_PRETEND_VERSION" not in text
    assert text.index('[ "$COMMIT" = "$TAG_COMMIT" ]') < text.index(SERVER_BUILD)


# --- selection, checksums, signature ------------------------------------------------------


def test_server_wheel_is_selected_by_its_distribution_name() -> None:
    text = _script()
    assert "sandfort-[0-9]*.whl) SERVER_WHEELS+=" in text
    assert re.search(r'\[ "\$\{#SERVER_WHEELS\[@\]\}" -eq 1 \] \|\| die ', text)
    assert 'SERVER_WHEEL="${SERVER_WHEELS[0]}"' in text
    assert '[ "${#WHEELS[@]}" -ge 2 ] || die "expected at least two wheels in $OUT"' in text


@needs_bash
@pytest.mark.parametrize(
    ("name", "server"),
    [
        ("sandfort-0.1.0b64-py3-none-any.whl", True),
        ("sandfort_sdk-0.1.0b64-py3-none-any.whl", False),
        ("sandfort_cli-0.1.0b64-py3-none-any.whl", False),
    ],
)
def test_server_wheel_pattern_matches_only_the_root_package(name: str, server: bool) -> None:
    match = re.search(r"^\s*(sandfort-\[0-9\]\*\.whl)\)", _script(), re.MULTILINE)
    assert match is not None
    program = f'case "$1" in {match.group(1)}) echo server ;; *) echo other ;; esac'
    result = subprocess.run(
        ["bash", "-c", program, "_", name], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("server" if server else "other")


def test_checksums_cover_the_server_wheel_so_the_signature_does() -> None:
    text = _script()
    assert 'shasum -a 256 "${WHEELS[@]}" "$SERVER_WHEEL" > SHA256SUMS' in text
    assert text.index("> SHA256SUMS") < text.index("# 3) sign")
    sign = _section(text, "# 3) sign", "# 4) verify")
    assert '-n "$NAMESPACE" SHA256SUMS' in sign


def test_release_note_names_the_server_wheel() -> None:
    note = _section(_script(), "printf 'built from sandfort main", "} > RELEASE.txt")
    assert "printf 'server wheel: %s\\n' \"$SERVER_WHEEL\"" in note


# --- unchanged verify steps ---------------------------------------------------------------


def test_signature_and_sum_verification_is_unchanged() -> None:
    verify = _section(_script(), "# 4) verify the signature and the sums", "# 5)")
    assert _lines(verify) == [
        "# 4) verify the signature and the sums",
        "(",
        'cd "$OUT"',
        "# The delivered copy, so the recipe in RELEASE.txt is what was just checked.",
        'ssh-keygen -Y verify -f release-allowed-signers -I "$PRINCIPAL" -n "$NAMESPACE" \\',
        "-s SHA256SUMS.sig < SHA256SUMS",
        "shasum -a 256 -c SHA256SUMS",
        ")",
    ]


def test_install_check_is_unchanged_and_installs_the_sdk_and_cli_wheels() -> None:
    install = _section(_script(), "# 5) install", 'echo "release ok: $OUT"')
    assert 'for wheel in "${WHEELS[@]}"; do WHEEL_PATHS+=("$OUT/$wheel"); done' in install
    assert '"$VENV_DIR/bin/pip" install --quiet "${WHEEL_PATHS[@]}"' in install
    assert 'VERSION_OUT="$("$VENV_DIR/bin/sandfort" version)"' in install
    assert '*"${COMMIT:0:12}"*) ;;' in install
    assert "SERVER_WHEEL" not in install


@needs_bash
def test_release_script_is_valid_bash() -> None:
    result = subprocess.run(
        ["bash", "-n", str(RELEASE_SCRIPT)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


# --- documentation ------------------------------------------------------------------------


def test_script_header_lists_three_wheels() -> None:
    header = _script().split("set -euo pipefail", 1)[0]
    assert "server" in header
    assert "three wheels" in header


def test_release_doc_lists_the_server_wheel_as_an_artifact() -> None:
    intro = _section(_doc(), "## What a release is", "## How artifacts")
    assert "server wheel" in intro


def test_release_doc_shows_the_server_wheel_line_of_the_note() -> None:
    note = _section(_doc(), "```text\nbuilt from sandfort main", "```\n")
    assert "server wheel: sandfort-<version>-py3-none-any.whl" in note


def test_release_doc_documents_self_hosting_from_the_server_wheel() -> None:
    doc = _doc()
    selfhost = _section(doc, "## Self-host from the server wheel", "\n## ")
    assert "pip install sandfort-<version>" in selfhost
    assert "python -m sandfort.main" in selfhost
    assert "python -m sandfort.admin_cli migrate" in selfhost
    assert "SHA256SUMS" in selfhost
    assert "image" in selfhost


def test_release_doc_keeps_the_verify_recipe() -> None:
    doc = _doc()
    assert "ssh-keygen -Y verify -f release-allowed-signers -I release@sandfort.dev \\" in doc
    assert "shasum -a 256 -c SHA256SUMS" in doc


def test_all_lines_in_changed_files_fit_the_limit() -> None:
    for path in (RELEASE_SCRIPT, RELEASE_DOC, Path(__file__)):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            assert len(line) <= 100, f"{path.name}:{number}"
