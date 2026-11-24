"""Pure helper for ``inherit_resources``: adopt the resources a snapshot recorded.

A create that sets ``inherit_resources`` takes every resource field the request did not set
from the snapshot's record; a field the request did set always wins. "Set" is read from
``model_fields_set`` of the request's resources model, so an explicit value equal to the
default still counts. No clamping happens here: the caller re-checks the merged values
against the per-sandbox maximum.
"""

from sandfort.domain.resources import ResourceSpec

RESOURCE_FIELDS = ("cpu_millicores", "memory_mib", "disk_gib")


def merge_recorded(requested: ResourceSpec, recorded: ResourceSpec) -> ResourceSpec:
    """``requested`` with every field it left unset replaced by the ``recorded`` value."""
    explicit = requested.model_fields_set
    merged: dict[str, int] = {
        name: getattr(requested if name in explicit else recorded, name)
        for name in RESOURCE_FIELDS
    }
    return ResourceSpec(**merged)
