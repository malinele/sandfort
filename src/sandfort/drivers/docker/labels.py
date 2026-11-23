"""Label schema, selectors and container naming for managed objects."""

from collections.abc import Mapping

LABEL_MANAGED = "sandfort.managed"
LABEL_SANDBOX_ID = "sandfort.sandbox_id"
LABEL_ORG_ID = "sandfort.org_id"
LABEL_DISK_GIB = "sandfort.disk_gib"

NAME_PREFIX = "sf-"


def container_name(sandbox_id: str) -> str:
    """Deterministic ``sf-<sandbox_id>`` name so retries adopt the container."""
    return f"{NAME_PREFIX}{sandbox_id}"


def build_labels(sandbox_id: str, org_id: str, extra: Mapping[str, str]) -> dict[str, str]:
    """Merge caller labels with the identity labels; identity labels always win."""
    return {
        **extra,
        LABEL_MANAGED: "true",
        LABEL_SANDBOX_ID: sandbox_id,
        LABEL_ORG_ID: org_id,
    }


def managed_filters(org_id: str | None = None) -> dict[str, list[str]]:
    """Docker ``filters`` selecting managed objects, optionally of one org."""
    selectors = [f"{LABEL_MANAGED}=true"]
    if org_id is not None:
        selectors.append(f"{LABEL_ORG_ID}={org_id}")
    return {"label": selectors}
