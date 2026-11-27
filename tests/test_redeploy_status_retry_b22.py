"""Round 98 (B22): the public status read after a deploy retries until the api answers.

The api needs a moment after ``docker compose up`` before ``/v1/status`` answers. The one-shot
read crashed on the empty body during the beta.87 deploy (``set -o pipefail`` turned the JSON
error into exit 1) and the script's own checks after it never ran.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REDEPLOY = ROOT / "deploy" / "redeploy-beta.sh"
PRIVATE_OPS_REASON = "private ops script not present in public tree"

pytestmark = [
    pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash"),
    pytest.mark.skipif(not REDEPLOY.is_file(), reason=PRIVATE_OPS_REASON),
]


def _run(tmp_path: Path, snippet: str) -> str:
    script = f'source "$1"; BACKUP_DIR="{tmp_path}"; DRY_RUN=1; {snippet}'
    result = subprocess.run(
        ["bash", "-c", script, "_", str(REDEPLOY)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_wait_build_sha_retries_until_the_api_answers(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    calls.touch()
    out = _run(
        tmp_path,
        f'curl() {{ echo x >> "{calls}";'
        f' if [ "$(grep -c x "{calls}")" -ge 3 ];'
        " then printf '{\"data\":{\"build_sha\":\"abc123\"}}'; fi; };"
        " STATUS_RETRY_DELAY_S=0;"
        ' sha="$(wait_build_sha)";'
        f' echo "sha=$sha calls=$(grep -c x "{calls}")"',
    )
    assert "sha=abc123 calls=3" in out


def test_wait_build_sha_gives_up_with_no_output_and_a_failure_code(tmp_path: Path) -> None:
    out = _run(
        tmp_path,
        "curl() { :; };"
        " STATUS_RETRIES=3; STATUS_RETRY_DELAY_S=0;"
        ' set +e; sha="$(wait_build_sha)"; rc=$?; set -e;'
        ' echo "rc=$rc sha=[$sha]"',
    )
    assert "sha=[]" in out
    assert "rc=0" not in out


def test_wait_build_sha_survives_a_body_that_is_not_json(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    calls.touch()
    out = _run(
        tmp_path,
        f'curl() {{ echo x >> "{calls}";'
        f' if [ "$(grep -c x "{calls}")" -ge 2 ];'
        " then printf '{\"data\":{\"build_sha\":\"def456\"}}';"
        " else printf '<html>starting</html>'; fi; };"
        " STATUS_RETRY_DELAY_S=0;"
        ' sha="$(wait_build_sha)";'
        ' echo "sha=$sha"',
    )
    assert "sha=def456" in out


def test_the_api_target_uses_the_retrying_read_and_a_clear_failure_message() -> None:
    text = REDEPLOY.read_text(encoding="utf-8")
    assert 'live="$(wait_build_sha)"' in text
    assert "did not answer with a build_sha" in text


def test_the_rollback_target_still_tolerates_an_unavailable_status() -> None:
    text = REDEPLOY.read_text(encoding="utf-8")
    assert 'live="$(wait_build_sha || true)"' in text


def test_no_one_shot_status_read_is_left() -> None:
    text = REDEPLOY.read_text(encoding="utf-8")
    one_shot = 'curl -s -m 10 "$PUBLIC_API"'
    inside_helper = text.split("wait_build_sha()")[-1].split("\n}")[0]
    assert text.count(one_shot) == 1
    assert one_shot in inside_helper
