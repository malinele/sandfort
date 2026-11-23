"""``verify_head`` and ``verify_export`` of the audit facades, as mixins.

``Audit`` and ``AsyncAudit`` inherit these; each facade supplies ``public_key``.
"""

from collections.abc import AsyncIterable, Iterable, Mapping
from typing import TYPE_CHECKING, Any

from sandfort_sdk.audit_export import (
    ExportVerification,
    export_result,
    scan_export,
    scan_export_async,
)
from sandfort_sdk.audit_head import (
    NO_STATUS_KEY,
    STATUS_KEY,
    HeadVerification,
    parse_head,
    verify_head,
)


class AuditVerifyMixin:
    """The synchronous verification methods; needs ``public_key()`` from the facade."""

    if TYPE_CHECKING:

        def public_key(self) -> str | None: ...

    def verify_head(
        self, head_line: str | Mapping[str, Any], public_key: str | bytes
    ) -> HeadVerification:
        """Check the Ed25519 signature of an export's ``audit_head`` line.

        ``public_key`` is the required trust anchor: a key you hold (urlsafe base64 or 32 raw
        bytes), or the text ``"status"`` to read ``audit_public_key`` from ``GET /v1/status`` of
        this client's server (one request, made only for ``"status"``). The key the line names
        is never trusted; it is only compared, and another key returns ``ok=False`` with reason
        ``"key_mismatch"``. A malformed line or key, or ``"status"`` with no published key,
        raises ``ValueError``; an unsigned head, a wrong key or a tampered line returns
        ``ok=False`` with reason ``"unsigned"`` or ``"signature"``. ``ok`` needs a valid
        ``signed_at``: a signed head without one (beta.60 to beta.64 heads) returns ``ok=False``
        with reason ``"undated"``. ``HeadVerification.anchored`` was removed.

        Contract change: ``public_key`` has no default and is required (a call without it is a
        ``TypeError``), so the caller always names the trust anchor.
        """
        if isinstance(public_key, str) and public_key == STATUS_KEY:
            parse_head(head_line)
            key = self.public_key()
            if key is None:
                raise ValueError(NO_STATUS_KEY)
            return verify_head(head_line, key)
        return verify_head(head_line, public_key)

    def verify_export(
        self,
        lines: str | Iterable[str],
        public_key: str | bytes,
        *,
        allow_unchained: bool = False,
        previous: str | Iterable[str] | None = None,
    ) -> ExportVerification:
        """:func:`~sandfort_sdk.audit_export.verify_export`; ``public_key`` as for
        :meth:`verify_head` (``"status"`` is read after the file was scanned).

        A head from round 63 on binds the export's content (line count, first row and a SHA-256 of
        every event line), so the file is checked as a whole against what the server signed
        (``content_bound``). Against a legacy head the client check binds only the last row (to
        the signed head) and the linkage between neighbouring rows: rows before the last can be
        replaced or removed by someone who rewrites ``prev_hash`` and ``hash`` consistently, and
        an older genuinely signed export still verifies (check ``signed_at``). Row hashes are
        keyed, so a server that signs a fabricated export verifies; only the server-side check
        proves the keyed hashes and the full chain: ``sandfort audit verify`` or ``audit-verify``
        of the admin CLI. Rows without a ``hash`` fail with ``"unchained_rows"`` unless
        ``allow_unchained`` is true. ``previous`` is an earlier export of the same org (text or
        lines): its event lines must be an exact byte prefix of this one's
        (``"not_a_continuation"`` otherwise), and ``new_rows`` counts the lines added since.
        """
        scan = scan_export(lines, previous)
        key = self.public_key() if public_key == STATUS_KEY else public_key
        if key is None:
            raise ValueError(NO_STATUS_KEY)
        return export_result(scan, key, allow_unchained=allow_unchained)


class AsyncAuditVerifyMixin:
    """The asynchronous verification methods; needs ``public_key()`` from the facade."""

    if TYPE_CHECKING:

        async def public_key(self) -> str | None: ...

    async def verify_head(
        self, head_line: str | Mapping[str, Any], public_key: str | bytes
    ) -> HeadVerification:
        """Check the Ed25519 signature of an export's ``audit_head`` line.

        Same as :meth:`Audit.verify_head`. Contract change: it is a coroutine (``await`` it),
        because ``public_key="status"`` reads the key from ``GET /v1/status``; an explicit key
        makes no request. ``public_key`` has no default and is required, as on the sync facade.
        """
        if isinstance(public_key, str) and public_key == STATUS_KEY:
            parse_head(head_line)
            key = await self.public_key()
            if key is None:
                raise ValueError(NO_STATUS_KEY)
            return verify_head(head_line, key)
        return verify_head(head_line, public_key)

    async def verify_export(
        self,
        lines: str | Iterable[str] | AsyncIterable[str],
        public_key: str | bytes,
        *,
        allow_unchained: bool = False,
        previous: str | Iterable[str] | None = None,
    ) -> ExportVerification:
        """Same as :meth:`Audit.verify_export`, as a coroutine (``"status"`` reads the key from
        the server). ``lines`` may also be an asynchronous iterable of lines, such as
        :meth:`export_lines`; ``previous`` is a plain text or an iterable of lines.

        Against a legacy head the client check binds only the last row and the linkage between
        neighbouring rows (rows before the last can be replaced by someone who rewrites
        ``prev_hash`` and ``hash``; check ``signed_at`` for an older export); a head that binds
        the content also fixes every event line. The row hashes are keyed: only ``sandfort audit
        verify`` or ``audit-verify`` proves them, and the full chain.
        """
        if isinstance(lines, AsyncIterable):
            scan = await scan_export_async(lines, previous)
        else:
            scan = scan_export(lines, previous)
        key = await self.public_key() if public_key == STATUS_KEY else public_key
        if key is None:
            raise ValueError(NO_STATUS_KEY)
        return export_result(scan, key, allow_unchained=allow_unchained)
