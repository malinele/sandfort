"""The api deploy also rebuilds and recreates the egress proxy and checks its startup line.

Finding on the beta VM: the egress container had run for days from an old image, because
`redeploy-beta.sh api` built and recreated only the api service. The functions are sourced and
run with DRY_RUN=1, so nothing touches a host.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REDEPLOY = ROOT / "deploy" / "redeploy-beta.sh"
STARTUP_LINE = "egress allowed ports:"
PROXY_SOURCE = (ROOT / "src" / "sandfort" / "egress" / "proxy.py").read_text(encoding="utf-8")
LONGEST_LINE = 100

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


def test_startup_line_checked_by_the_script_is_the_one_the_proxy_logs() -> None:
    assert STARTUP_LINE in PROXY_SOURCE
    assert STARTUP_LINE in REDEPLOY.read_text(encoding="utf-8")


def test_api_target_builds_both_images_from_the_same_checkout(tmp_path: Path) -> None:
    out = _run(tmp_path, "deploy_api")

    build = [ln for ln in out.splitlines() if " build " in ln and "dry-run" in ln]
    assert len(build) == 1
    assert build[0].rstrip().endswith("api egress")
    assert "--build-arg SANDFORT_VERSION=" in build[0]


def test_api_target_recreates_egress_together_with_api(tmp_path: Path) -> None:
    out = _run(tmp_path, "deploy_api")

    assert "up -d --force-recreate api egress" in out


def test_api_target_checks_the_egress_container_and_its_startup_line(tmp_path: Path) -> None:
    out = _run(tmp_path, "deploy_api")

    assert "sandfort-egress-1" in out
    assert STARTUP_LINE in out


def test_api_target_no_longer_tells_the_operator_to_restart_the_proxy_by_hand(
    tmp_path: Path,
) -> None:
    out = _run(tmp_path, "deploy_api")

    assert "restart it from the new image" not in out
    assert "remind_proxy_restart" not in REDEPLOY.read_text(encoding="utf-8")


def test_api_target_tags_the_running_egress_image_as_previous(tmp_path: Path) -> None:
    out = _run(tmp_path, "deploy_api")

    assert "sandfort-egress:previous" in out


def test_image_deploy_builds_egress_and_recreates_both_without_building_api(
    tmp_path: Path,
) -> None:
    out = _run(tmp_path, "IMAGE_REF=registry.example/sandfort-api:ci; deploy_api")

    assert "up -d --force-recreate --no-build api egress" in out
    build = [ln for ln in out.splitlines() if " build " in ln and "dry-run" in ln]
    assert len(build) == 1
    assert build[0].rstrip().endswith("egress")
    assert not build[0].rstrip().endswith("api egress")


def test_egress_target_is_accepted_and_is_not_part_of_all(tmp_path: Path) -> None:
    only = _run(tmp_path, "parse_args egress --dry-run; echo \"${TARGETS[*]}\"")
    everything = _run(tmp_path, "parse_args all; echo \"${TARGETS[*]}\"")

    assert only.strip() == "egress"
    assert "egress" not in everything.split()


def test_egress_target_does_only_the_egress_part(tmp_path: Path) -> None:
    out = _run(tmp_path, "deploy_egress")

    assert "up -d --force-recreate egress" in out
    assert "api egress" not in out
    assert "--force-recreate api" not in out
    assert "admin_cli migrate" not in out
    assert STARTUP_LINE in out
    assert "sandfort-egress:previous" in out


def test_rollback_covers_the_egress_image_when_a_previous_one_exists(tmp_path: Path) -> None:
    out = _run(tmp_path, "deploy_rollback")

    assert "sandfort-egress:previous" in out


def test_help_and_usage_list_the_egress_target() -> None:
    result = subprocess.run(
        ["bash", str(REDEPLOY), "--help"], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0
    assert "redeploy-beta.sh egress" in result.stdout


def test_new_test_file_fits_the_line_limit() -> None:
    lines = Path(__file__).read_text(encoding="utf-8").splitlines()
    assert all(len(line) <= LONGEST_LINE for line in lines)
