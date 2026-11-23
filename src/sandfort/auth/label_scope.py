"""Request-scoped sandbox label scope of the authenticated principal.

``authenticate`` sets the scope right after it builds the principal, so FastAPI dependencies
and the endpoint can read it with ``current_label_scope``. ``None`` means unscoped. This module
only carries the value; enforcement on sandboxes is a separate step.

The key's optional sandbox cap (``max_sandboxes``) travels next to the scope: it counts the
sandboxes inside that scope, so it is only ever set together with one.

The key's optional ``shared_volume_labels`` also travel here: volumes carrying them are readable
and mountable read-only by the scoped key, next to the volumes of its own scope.
"""

from collections.abc import Mapping
from contextvars import ContextVar, Token

_LABEL_SCOPE: ContextVar[Mapping[str, str] | None] = ContextVar("sandbox_label_scope", default=None)
_KEY_SANDBOX_CAP: ContextVar[int | None] = ContextVar("key_sandbox_cap", default=None)
_SHARED_VOLUME_LABELS: ContextVar[Mapping[str, str] | None] = ContextVar(
    "shared_volume_labels", default=None
)


def current_shared_volume_labels() -> Mapping[str, str] | None:
    """The shared-volume labels of the current request's key; ``None`` when it has none."""
    return _SHARED_VOLUME_LABELS.get()


def set_shared_volume_labels(labels: Mapping[str, str] | None) -> Token[Mapping[str, str] | None]:
    """Make ``labels`` the current shared-volume labels; returns the restoring token."""
    return _SHARED_VOLUME_LABELS.set(labels or None)


def current_key_sandbox_cap() -> int | None:
    """The sandbox cap of the current request's key; ``None`` when the key has no cap."""
    return _KEY_SANDBOX_CAP.get()


def set_key_sandbox_cap(cap: int | None) -> Token[int | None]:
    """Make ``cap`` the current cap and return the token that restores the previous one."""
    return _KEY_SANDBOX_CAP.set(cap)


def current_label_scope() -> Mapping[str, str] | None:
    """The label scope of the current request's principal; ``None`` when unscoped."""
    return _LABEL_SCOPE.get()


def set_label_scope(scope: Mapping[str, str] | None) -> Token[Mapping[str, str] | None]:
    """Make ``scope`` the current scope and return the token that restores the previous one."""
    return _LABEL_SCOPE.set(scope)


def matches(labels: Mapping[str, str], scope: Mapping[str, str] | None) -> bool:
    """True when ``scope`` is ``None`` or every scope pair appears in ``labels`` unchanged."""
    if scope is None:
        return True
    return all(name in labels and labels[name] == value for name, value in scope.items())
