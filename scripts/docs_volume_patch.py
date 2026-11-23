"""Print the JSON patch that makes the sandfort-docs Deployment mount both docs ConfigMaps.

The docs site is split across two ConfigMaps so each stays under the Kubernetes size limit:
the pages (default `sandfort-docs`) and the OpenAPI spec (default `sandfort-docs-spec`).
The Deployment lives outside the repository, so deploy/redeploy-beta.sh reads it and applies
the patch this script prints. The patch is idempotent: when the volume already combines both
ConfigMaps the output is `[]`, which the caller treats as nothing to do.

    kubectl -n NS get deploy sandfort-docs -o json | python3 scripts/docs_volume_patch.py

Standard library only. Exit 1 with a message on stderr when the Deployment has no volume that
uses the pages ConfigMap (the Deployment does not look like the one this script knows).
"""

from __future__ import annotations

import json
import sys
from typing import Any

PAGES_CONFIGMAP = "sandfort-docs"
SPEC_CONFIGMAP = "sandfort-docs-spec"
VOLUMES_PATH = "/spec/template/spec/volumes"


class PatchError(Exception):
    """The Deployment cannot be patched by this script."""


def _projected_names(volume: dict[str, Any]) -> set[str]:
    sources = (volume.get("projected") or {}).get("sources") or []
    return {s["configMap"]["name"] for s in sources if s.get("configMap", {}).get("name")}


def _uses(volume: dict[str, Any], name: str) -> bool:
    return (volume.get("configMap") or {}).get("name") == name or name in _projected_names(
        volume
    )


def _to_projected(volume: dict[str, Any], pages: str, spec: str) -> dict[str, Any]:
    """A projected copy of a plain ConfigMap volume, with the spec ConfigMap added."""
    config_map = dict(volume["configMap"])
    default_mode = config_map.pop("defaultMode", None)
    projected: dict[str, Any] = {
        "sources": [{"configMap": config_map}, {"configMap": {"name": spec}}]
    }
    if default_mode is not None:
        projected["defaultMode"] = default_mode
    return {"name": volume["name"], "projected": projected}


def build_patch(
    deployment: dict[str, Any], pages: str = PAGES_CONFIGMAP, spec: str = SPEC_CONFIGMAP
) -> list[dict[str, Any]]:
    """JSON patch operations (RFC 6902) for the Deployment; empty when it is already patched."""
    volumes = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("volumes") or []
    for index, volume in enumerate(volumes):
        if not _uses(volume, pages):
            continue
        path = f"{VOLUMES_PATH}/{index}"
        names = _projected_names(volume)
        if pages in names and spec in names:
            return []
        if pages in names:
            return [
                {
                    "op": "add",
                    "path": f"{path}/projected/sources/-",
                    "value": {"configMap": {"name": spec}},
                }
            ]
        return [{"op": "replace", "path": path, "value": _to_projected(volume, pages, spec)}]
    raise PatchError(f"no volume of the Deployment uses the ConfigMap {pages}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    pages, spec = (args + [PAGES_CONFIGMAP, SPEC_CONFIGMAP][len(args) :])[:2]
    try:
        deployment = json.load(sys.stdin)
        patch = build_patch(deployment, pages, spec)
    except (PatchError, json.JSONDecodeError) as exc:
        print(f"docs_volume_patch: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(patch, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
