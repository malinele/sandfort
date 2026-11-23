"""Re-export of ``sandfort.audit_signing`` for existing importers (services, routes, CLI).

The signing leaf moved to ``sandfort.audit_signing`` so ``sandfort.config`` does not depend on
``sandfort.services`` (import-linter layers). New code imports the leaf directly.
"""

from sandfort.audit_signing import (
    ALG,
    AUDIT_SIGNING_KEY_ENV,
    KEY_BYTES,
    UNSIGNED_FIELDS,
    HeadSigner,
    b64encode,
    canonical_payload,
    format_signed_at,
    load_public_key,
    parse_signed_at,
    parse_signing_key,
    public_key_text,
    public_key_to_text,
    signer_from_text,
    verify_payload,
)

__all__ = [
    "ALG",
    "AUDIT_SIGNING_KEY_ENV",
    "KEY_BYTES",
    "UNSIGNED_FIELDS",
    "HeadSigner",
    "b64encode",
    "canonical_payload",
    "format_signed_at",
    "load_public_key",
    "parse_signed_at",
    "parse_signing_key",
    "public_key_text",
    "public_key_to_text",
    "signer_from_text",
    "verify_payload",
]
