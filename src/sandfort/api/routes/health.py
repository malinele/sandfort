"""``/healthz``, ``/readyz`` and ``/v1/status`` (no authentication)."""

import base64
import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from sandfort.api.deps import get_driver, get_settings, get_uow
from sandfort.api.envelope import Envelope, ok
from sandfort.api.schemas.status import StatusResponse
from sandfort.config import Settings
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.drivers.base import SandboxDriver
from sandfort.errors import CapacityExceeded
from sandfort.services.audit_chain import ChainPolicy

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)

PROBE_ORG_ID = "org_readyz_probe"
STATUS_PATH = "/v1/status"
PACKAGE_NAME = "sandfort"
UNKNOWN_VERSION = "unknown"
NOTICE_MAX_BYTES = 2048
DEGRADED_PREFIX = "degraded:"
FAULT_NOTICE_PREFIX = "fault injection active: "
STATUS_OK = "ok"
STATUS_DEGRADED = "degraded"
FINGERPRINT_CHARS = 16

NOTICE_CACHE_TTL_S = 1.0
BUILD_FILE_MAX_BYTES = 256

STARTED_AT = datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class _CachedNotice:
    mtime_ns: int | None  # mtime seen when the file was read; None when it could not be stat'ed
    value: tuple[str, datetime] | None
    checked_at: float  # clock reading of the last read or unchanged-mtime check


_NOTICE_CACHE: dict[str, _CachedNotice] = {}


# (build file path, build_sha) -> baked value. The file is read once per pair: the image does not
# change while the process runs, and the mismatch warning is logged on that first read only.
_IMAGE_SHA_CACHE: dict[tuple[str, str], str | None] = {}


def read_image_sha(build_file: str) -> str | None:
    """The commit baked into the image (stripped file text), None when absent or empty."""
    if not build_file:
        return None
    try:
        with Path(build_file).open("rb") as handle:
            raw = handle.read(BUILD_FILE_MAX_BYTES)
    except FileNotFoundError:
        return None
    except OSError as exc:
        logger.warning("baked build file unreadable: %s", type(exc).__name__)
        return None
    return raw.decode("utf-8", errors="replace").strip() or None


def image_sha(settings: Settings) -> str | None:
    """The baked build commit, read once; warns when it differs from the configured build_sha."""
    key = (settings.build_sha_file, settings.build_sha)
    if key in _IMAGE_SHA_CACHE:
        return _IMAGE_SHA_CACHE[key]
    baked = read_image_sha(settings.build_sha_file)
    if baked is not None and settings.build_sha and baked != settings.build_sha:
        logger.warning(
            "build_sha %s differs from the commit baked into the image (%s)",
            settings.build_sha,
            baked,
        )
    _IMAGE_SHA_CACHE[key] = baked
    return baked


def package_version() -> str:
    """The installed package version, ``unknown`` when the metadata is missing."""
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        return UNKNOWN_VERSION


def read_notice(notice_file: str) -> tuple[str, datetime] | None:
    """The stripped notice text (at most 2 KiB) and the file mtime, or None for no notice.

    A missing or empty file means no notice; any other read error is logged and also means none.
    """
    if not notice_file:
        return None
    path = Path(notice_file)
    try:
        with path.open("rb") as handle:
            raw = handle.read(NOTICE_MAX_BYTES)
            modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        logger.warning("status notice file unreadable: %s", type(exc).__name__)
        return None
    text = raw.decode("utf-8", errors="replace").strip()
    return (text, modified) if text else None


def _mtime_ns(notice_file: str) -> int | None:
    """The notice file's mtime in nanoseconds, None when it cannot be stat'ed."""
    try:
        return Path(notice_file).stat().st_mtime_ns
    except OSError:
        return None


def cached_notice(
    notice_file: str, clock: Callable[[], float] = time.monotonic
) -> tuple[str, datetime] | None:
    """``read_notice`` behind a 1 s cache keyed on the path (the status route is unthrottled).

    Within ``NOTICE_CACHE_TTL_S`` of the last check the cached value is returned without
    touching the file. After that the file is stat'ed and re-read only when its mtime changed.
    """
    if not notice_file:
        return None
    now = clock()
    entry = _NOTICE_CACHE.get(notice_file)
    if entry is not None and now - entry.checked_at < NOTICE_CACHE_TTL_S:
        return entry.value
    mtime_ns = _mtime_ns(notice_file)
    if entry is not None and entry.mtime_ns == mtime_ns:
        _NOTICE_CACHE[notice_file] = replace(entry, checked_at=now)
        return entry.value
    value = read_notice(notice_file)
    _NOTICE_CACHE[notice_file] = _CachedNotice(mtime_ns, value, now)
    return value


def fault_notice(faults: tuple[str, ...], notice: dict[str, str] | None) -> dict[str, str]:
    """The notice with ``fault injection active: <faults>`` appended (alone without a notice)."""
    line = f"{FAULT_NOTICE_PREFIX}{', '.join(faults)}"
    if notice is None:
        return {"message": line, "updated_at": STARTED_AT.isoformat()}
    return {**notice, "message": f"{notice['message']}; {line}"}


def status_payload(
    settings: Settings, clock: Callable[[], float] = time.monotonic
) -> dict[str, Any]:
    """The public status document: version, build, start time, notice and audit public key.

    ``audit_public_key`` is the Ed25519 public key (urlsafe base64) that verifies the signed
    audit head (the key of ``Settings.audit_signer``, the one exports sign with). It is
    published only when heads are actually signed, that is when both
    ``SANDFORT_AUDIT_SIGNING_KEY`` and ``SANDFORT_AUDIT_CHAIN_KEY`` are set (the chain key as
    the export route reads it, see ``audit_public_key``); otherwise it is
    ``None`` (a signing key alone signs nothing, so its public key would verify nothing). An
    auditor fetches it here, independently of an export, and checks heads with
    ``verify_head_signature``. ``audit_key_fingerprint`` is the short form to pin out of band
    (``None`` exactly when the key is).
    """
    found = cached_notice(settings.status_notice_file, clock)
    public_key = audit_public_key(settings)
    status = STATUS_OK
    notice: dict[str, str] | None = None
    if found is not None:
        text, modified = found
        if text.startswith(DEGRADED_PREFIX):
            status = STATUS_DEGRADED
            text = text[len(DEGRADED_PREFIX) :].strip()
        notice = {"message": text, "updated_at": modified.isoformat()}
    if settings.fault_injection:  # the partner's keyless on/off signal for the test hook
        notice = fault_notice(settings.fault_injection, notice)
    build_sha = settings.build_sha or None
    baked = image_sha(settings)
    return {
        "status": status,
        "version": package_version(),
        "build_sha": build_sha,
        "image_sha": baked,
        "build_matches_image": None if build_sha is None or baked is None else build_sha == baked,
        "started_at": STARTED_AT.isoformat(),
        "notice": notice,
        "audit_public_key": public_key,
        "audit_key_fingerprint": None if public_key is None else key_fingerprint(public_key),
    }


def key_fingerprint(public_key: str) -> str | None:
    """First 16 hex characters of sha256 over the raw public key (as the CLI and doctor print).

    ``None`` when the text is not urlsafe base64; the key came from the signer, so it is.
    """
    text = public_key.strip()
    try:
        raw = base64.b64decode((text + "=" * (-len(text) % 4)).encode("ascii"), altchars=b"-_")
    except ValueError:
        return None
    return hashlib.sha256(raw).hexdigest()[:FINGERPRINT_CHARS]


def audit_public_key(settings: Settings) -> str | None:
    """The public key of the signer exports use (``Settings.audit_signer``); never raises.

    ``None`` unless heads are actually signed, that is when a signer exists and the export
    route has a chain key. The chain key has one source here: the process environment through
    ``ChainPolicy.from_env``, exactly what the export route (``GET /v1/audit/export``) reads
    to decide whether it signs. ``Settings.audit_chain_key`` is deliberately not consulted: for
    settings built in code it can differ from the environment, and then the export would not
    sign, so status must not publish a key that verifies nothing. Status therefore publishes
    the key exactly when exports are signed. (The doctor judges the settings it was given,
    which equal the environment for settings loaded with ``Settings.from_env``.)

    ``Settings`` validates the signing key at load, so a failure here means the value was
    altered after load: the status route still answers, reporting no key, and logs no key
    material. An unusable chain key in the environment also reports no key.
    """
    try:
        signer = settings.audit_signer()
    except ValueError:
        logger.warning("audit signing key unusable; /v1/status reports no audit_public_key")
        return None
    if signer is None or not _export_has_chain_key():
        return None
    return signer.public_key


def _export_has_chain_key() -> bool:
    """Whether the export route has a chain key (``ChainPolicy.from_env``), False if unusable."""
    try:
        return ChainPolicy.from_env().key is not None
    except ValueError:
        return False


@router.get("/healthz")
async def healthz() -> Envelope[dict[str, str]]:
    return ok({"status": "ok"})


@router.get("/readyz")
async def readyz(
    uow: Annotated[UnitOfWorkPort, Depends(get_uow)],
    driver: Annotated[SandboxDriver, Depends(get_driver)],
) -> Envelope[dict[str, str]]:
    try:
        async with uow:
            await uow.orgs.get(PROBE_ORG_ID)
    except Exception as exc:
        raise CapacityExceeded("not ready", details={"component": "database"}) from exc
    try:
        await driver.list_managed(org_id=PROBE_ORG_ID)
    except Exception as exc:
        raise CapacityExceeded("not ready", details={"component": "driver"}) from exc
    return ok({"status": "ready"})


@router.get(STATUS_PATH)
def status(settings: Annotated[Settings, Depends(get_settings)]) -> Envelope[StatusResponse]:
    """Version, build, start time and the operator notice; no authentication."""
    return ok(StatusResponse.model_validate(status_payload(settings)))


@router.head(STATUS_PATH, include_in_schema=False)
def status_head(settings: Annotated[Settings, Depends(get_settings)]) -> Response:
    """The GET answer's status and headers (content length included) without a body.

    Uptime probes often use HEAD. It is out of the schema: the document lists GET only.
    """
    body = JSONResponse(jsonable_encoder(ok(status_payload(settings)))).body
    return Response(
        status_code=200,
        media_type="application/json",
        headers={"content-length": str(len(body))},
    )
