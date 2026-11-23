"""Driver error hierarchy. Drivers raise only these; services map them to API errors."""

from typing import Any


class DriverError(Exception):
    """Base class for all driver failures.

    ``message`` (also ``str(exc)``) is the only text a tenant may see. ``daemon_text`` is the
    backend's own explanation, kept out of band for server-side classification and logging; it
    is never part of ``message`` and never reaches an API answer. ``daemon_text`` must never be
    serialised: ``__reduce__`` drops it, so a pickled or copied error comes back without it.
    """

    def __init__(
        self, message: str, *, ref: str | None = None, daemon_text: str | None = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.ref = ref
        self.daemon_text = daemon_text

    @property
    def classification_text(self) -> str:
        """The text classifiers read: ``daemon_text`` when known, else ``message``."""
        return self.daemon_text if self.daemon_text is not None else self.message

    def __reduce__(self) -> tuple[Any, ...]:
        """Pickle the type, the message and the ref only; ``daemon_text`` is never serialised."""
        return (_restore_driver_error, (type(self), self.message, self.ref))


def _restore_driver_error(
    cls: type[DriverError], message: str, ref: str | None
) -> DriverError:
    """Rebuild a driver error from its tenant-safe parts (the unpickling half of ``__reduce__``)."""
    return cls(message, ref=ref)


class DriverNotFound(DriverError):
    """The container, image or volume does not exist."""


class DriverConflict(DriverError):
    """The object exists or is in a state that forbids the operation."""


class DriverUnsupported(DriverError):
    """The driver or host lacks a required capability."""


class DriverTimeout(DriverError):
    """A driver operation exceeded its deadline."""


class DriverRegistryUnreachable(DriverError):
    """The network to the image registry failed; the image may well exist (retryable)."""


class DriverRegistryTlsError(DriverError):
    """The registry's TLS connection failed validation (an untrusted or wrong certificate, or a
    plain-HTTP registry); not retryable, the registry trust or configuration must change.

    A direct ``DriverError`` subclass, deliberately not a ``DriverRegistryUnreachable``: a retry
    loop that catches the unreachable class must not repeat a pull that cannot succeed.
    """


class DriverAccessDenied(DriverError):
    """The image registry answered and refused the pull (denied, unauthorized)."""


class DriverInvalidReference(DriverError):
    """The image reference cannot be parsed (the daemon's "invalid reference format")."""


class DriverInvalidArchive(DriverError):
    """The archive handed to a volume restore is not a readable tar."""


class DriverForbiddenEntry(DriverInvalidArchive):
    """The archive is a readable tar but holds an entry the archive policy forbids.

    ``violation`` is a stable code (``path_traversal``, ``hardlink``, ...) and ``entry`` the
    member name as the archive spelled it (control characters removed). Both are plain
    keyword arguments with defaults, so ``__reduce__`` (message and ref only) can rebuild it.
    """

    def __init__(
        self,
        message: str,
        *,
        ref: str | None = None,
        daemon_text: str | None = None,
        violation: str = "",
        entry: str = "",
    ) -> None:
        super().__init__(message, ref=ref, daemon_text=daemon_text)
        self.violation = violation
        self.entry = entry
