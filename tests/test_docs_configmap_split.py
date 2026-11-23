"""The docs site is two ConfigMaps; the deploy script builds both and patches the Deployment."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEPLOY_SCRIPT = ROOT / "deploy" / "redeploy-beta.sh"

needs_private_ops = pytest.mark.skipif(
    not DEPLOY_SCRIPT.is_file(),
    reason="private ops script not present in public tree",
)
PATCH_SCRIPT = ROOT / "scripts" / "docs_volume_patch.py"
PAGES = "sandfort-docs"
SPEC = "sandfort-docs-spec"

sys.path.insert(0, str(ROOT / "scripts"))
import docs_volume_patch as dvp  # noqa: E402

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _deployment(volume: dict[str, Any]) -> dict[str, Any]:
    other = {"name": "tmp", "emptyDir": {}}
    return {"spec": {"template": {"spec": {"volumes": [other, volume]}}}}


def _apply(deployment: dict[str, Any], patch: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply the three-operation subset of RFC 6902 that the patch uses."""
    result = json.loads(json.dumps(deployment))
    for op in patch:
        *parents, last = op["path"].strip("/").split("/")
        node: Any = result
        for part in parents:
            node = node[int(part)] if isinstance(node, list) else node[part]
        if last == "-":
            node.append(op["value"])
        elif isinstance(node, list):
            node[int(last)] = op["value"]
        else:
            node[last] = op["value"]
    return result


def _volume_sources(deployment: dict[str, Any]) -> list[str]:
    volume = deployment["spec"]["template"]["spec"]["volumes"][1]
    return [s["configMap"]["name"] for s in volume["projected"]["sources"]]


def test_plain_configmap_volume_becomes_a_projected_volume_with_both() -> None:
    plain = {"name": "site", "configMap": {"name": PAGES, "defaultMode": 420}}
    deployment = _deployment(plain)
    patch = dvp.build_patch(deployment)
    assert patch == [
        {
            "op": "replace",
            "path": "/spec/template/spec/volumes/1",
            "value": {
                "name": "site",
                "projected": {
                    "sources": [{"configMap": {"name": PAGES}}, {"configMap": {"name": SPEC}}],
                    "defaultMode": 420,
                },
            },
        }
    ]
    assert _volume_sources(_apply(deployment, patch)) == [PAGES, SPEC]


def test_patch_is_idempotent() -> None:
    deployment = _deployment({"name": "site", "configMap": {"name": PAGES}})
    patched = _apply(deployment, dvp.build_patch(deployment))
    assert dvp.build_patch(patched) == []


def test_projected_volume_with_only_the_pages_gets_the_spec_added() -> None:
    volume = {"name": "site", "projected": {"sources": [{"configMap": {"name": PAGES}}]}}
    deployment = _deployment(volume)
    patch = dvp.build_patch(deployment)
    assert _volume_sources(_apply(deployment, patch)) == [PAGES, SPEC]


def test_deployment_without_the_pages_volume_is_refused() -> None:
    with pytest.raises(dvp.PatchError):
        dvp.build_patch(_deployment({"name": "site", "configMap": {"name": "other"}}))


def test_command_line_reads_the_deployment_from_stdin() -> None:
    deployment = _deployment({"name": "site", "configMap": {"name": PAGES}})
    result = subprocess.run(
        [sys.executable, str(PATCH_SCRIPT)],
        input=json.dumps(deployment),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)[0]["op"] == "replace"
    bad = subprocess.run(
        [sys.executable, str(PATCH_SCRIPT)],
        input="not json",
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode == 1 and "docs_volume_patch" in bad.stderr


@needs_private_ops
@needs_bash
def test_docs_dry_run_builds_both_configmaps_and_patches_the_volume() -> None:
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; DRY_RUN=1; BACKUP_DIR=/nonexistent; deploy_docs',
            "_",
            str(DEPLOY_SCRIPT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert f"create configmap {SPEC} --from-file=openapi.json=" in out
    assert f"create configmap {PAGES} --from-file=index.html=" in out
    pages_line = next(
        line for line in out.splitlines() if f"get configmap {PAGES} >" in line
    )
    assert "openapi.json" not in pages_line  # the spec lives only in its own ConfigMap
    assert "patch deploy/sandfort-docs" in out
    assert out.index(f"create configmap {SPEC}") < out.index("patch deploy/sandfort-docs")
    assert "rollout restart deploy/sandfort-docs" in out
    assert "https://docs.sandfort.dev/index.html" in out
    assert "https://docs.sandfort.dev/openapi.json" in out


@needs_private_ops
def test_script_header_documents_the_split() -> None:
    header = DEPLOY_SCRIPT.read_text(encoding="utf-8").split("set -euo pipefail", 1)[0]
    for fragment in (PAGES, SPEC, "projected", "docs_volume_patch.py"):
        assert fragment in header, fragment


def test_operations_guide_documents_the_split() -> None:
    text = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
    assert SPEC in text and "projected volume" in text
