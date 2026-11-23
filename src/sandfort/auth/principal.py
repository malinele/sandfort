"""The authenticated caller attached to every request."""

from collections.abc import Mapping
from dataclasses import dataclass

from sandfort.domain.org import Scope


@dataclass(frozen=True, slots=True)
class Principal:
    org_id: str
    key_id: str
    scopes: frozenset[Scope]
    is_platform_admin: bool = False
    user_id: str | None = None  # set only for principals built from a user session token
    sandbox_labels: Mapping[str, str] | None = None  # None = not scoped to labelled sandboxes
    max_sandboxes: int | None = None  # None = no cap on the sandboxes inside the label scope
    # None = no shared volumes; otherwise volumes carrying these labels are readable and
    # mountable read-only next to the key's own scope.
    shared_volume_labels: Mapping[str, str] | None = None
