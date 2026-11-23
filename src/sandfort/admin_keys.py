"""``sandfort-admin revoke-key``: revoke an API key from the host, without an API key.

The lost-key runbook mints a replacement and revokes the old key over the API. A
platform-admin key (the bootstrap key) can only be revoked by another platform-admin key, so
when it is the lost one the operator revokes it here, straight in the database. Like
``create-key`` this uses the provisioning settings and a unit of work, and audits as the
``platform_admin`` actor ``sandfort-admin``. ``--cascade`` reuses ``ApiKeyAdminService.revoke``
with a platform-admin principal, so descendants are found and audited exactly as over the API.
"""

from dataclasses import dataclass
from typing import Any

from sandfort.auth.api_keys import PREFIX_LENGTH, parse_prefix
from sandfort.auth.principal import Principal
from sandfort.auth.scopes import ALL_SCOPES
from sandfort.clock import SystemClock
from sandfort.config import Settings
from sandfort.db.engine import create_engine, create_session_factory
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.db.unit_of_work import UnitOfWork
from sandfort.domain.events import ActorType, AuditEvent
from sandfort.domain.org import ApiKey, Org
from sandfort.errors import NotFound, ValidationFailed
from sandfort.services.api_key_admin import ApiKeyAdminService
from sandfort.services.audit import AuditRecorder

PREFIX_PARTS = 3  # scheme, env and the short id: ``sf_<env>_<prefix8>``
MAX_ECHO_LENGTH = 32  # the most of an operator-supplied value any message repeats


@dataclass(frozen=True, slots=True)
class RevokeOutcome:
    """The key as it stands afterwards, whether it was already revoked, and the cascade size."""

    key: ApiKey
    already_revoked: bool
    cascaded: int


class _OperatorRecorder(AuditRecorder):
    """Records every event as the host operator, whatever actor the service passes."""

    def __init__(self, actor_id: str) -> None:
        super().__init__(SystemClock())
        self._actor_id = actor_id

    async def record(self, uow: UnitOfWorkPort, **fields: Any) -> AuditEvent:
        fields.update(actor_type=ActorType.PLATFORM_ADMIN, actor_id=self._actor_id)
        return await super().record(uow, **fields)


class BlankSelector(ValidationFailed):
    """A selector option was given but is empty or whitespace: a usage error, not a lookup."""


Selectors = tuple[str | None, str | None, str | None, str | None]


def _strip_selector(flag: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not value.strip():
        raise BlankSelector(f"{flag} must not be blank")
    return value.strip()


def check_selectors(
    org_slug: str | None, org_id: str | None, key_id: str | None, prefix: str | None
) -> Selectors:
    """The stripped selectors: none blank, exactly one org selector and one key selector."""
    org_slug = _strip_selector("--org-slug", org_slug)
    org_id = _strip_selector("--org-id", org_id)
    key_id = _strip_selector("--key-id", key_id)
    prefix = _strip_selector("--prefix", prefix)
    if (org_slug is None) == (org_id is None):
        raise ValidationFailed("give exactly one of --org-slug and --org-id")
    if (key_id is None) == (prefix is None):
        raise ValidationFailed("give exactly one of --key-id and --prefix")
    return org_slug, org_id, key_id, prefix


def reduce_to_prefix(value: str) -> str:
    """The lookup prefix of ``value``: a pasted key is cut down to ``sf_<env>_<prefix8>``."""
    try:
        return parse_prefix(value)
    except ValueError:
        pass
    parts = value.split("_", 3)[:3]  # scheme, env, prefix8: nothing after that is echoed
    if len(parts) == PREFIX_PARTS:
        parts[-1] = parts[-1][:PREFIX_LENGTH]
    return "_".join(parts)[:MAX_ECHO_LENGTH]


def pick_key(keys: list[ApiKey], key_id: str | None, prefix: str | None) -> ApiKey:
    """The one key selected by id or prefix; none or several is an error naming the cause."""
    wanted = reduce_to_prefix(prefix) if prefix is not None else ""
    if key_id is not None:
        found = [key for key in keys if key.id == key_id]
    else:
        found = [key for key in keys if key.prefix == wanted]
        found = found or [key for key in keys if key.prefix.startswith(wanted)]
    if not found:
        raise NotFound(f"unknown api key {key_id or wanted}")
    if len(found) > 1:
        listing = "; ".join(
            f"{key.id} name={key.name} created {key.created_at.isoformat()}" for key in found
        )
        raise ValidationFailed(
            f"prefix {wanted} matches {len(found)} keys, nothing revoked: {listing}"
        )
    return found[0]


async def _select(
    uow: UnitOfWorkPort,
    org_slug: str | None,
    org_id: str | None,
    key_id: str | None,
    prefix: str | None,
) -> tuple[Org, ApiKey]:
    if org_slug is not None:
        org = await uow.orgs.get_by_slug(org_slug)
    else:
        org = await uow.orgs.get(org_id or "")
    if org is None:
        raise NotFound(f"unknown organisation {org_slug or org_id}")
    keys = list(await uow.api_keys.list_for_org(org.id))
    return org, pick_key(keys, key_id, prefix)


async def revoke_key_async(
    settings: Settings,
    org_slug: str | None,
    org_id: str | None,
    key_id: str | None,
    prefix: str | None,
    *,
    cascade: bool,
    actor_id: str,
) -> RevokeOutcome:
    """Revoke the selected key (and, with ``cascade``, its live descendants)."""
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    try:
        async with UnitOfWork(factory) as uow:
            org, key = await _select(uow, org_slug, org_id, key_id, prefix)
        was_revoked = key.revoked_at is not None
        if was_revoked and not cascade:
            return RevokeOutcome(key, already_revoked=True, cascaded=0)
        service = ApiKeyAdminService(
            lambda: UnitOfWork(factory),
            settings.api_key_pepper,
            SystemClock(),
            _OperatorRecorder(actor_id),
        )
        principal = Principal(
            org_id=org.id, key_id=actor_id, scopes=ALL_SCOPES, is_platform_admin=True
        )
        revoked = await service.revoke(principal, key.id, cascade=cascade)
    finally:
        await engine.dispose()
    cascaded = len(revoked.dependants) if cascade else 0
    return RevokeOutcome(revoked.record, already_revoked=was_revoked, cascaded=cascaded)


def describe(outcome: RevokeOutcome) -> str:
    """The one stdout line: the key's id, name and prefix, or when it was already revoked."""
    key = outcome.key
    ident = f"{key.id} name={key.name} prefix={key.prefix}"
    if outcome.already_revoked:
        at = key.revoked_at.isoformat() if key.revoked_at else "an unrecorded time"
        return f"already revoked {ident} at {at}"
    return f"revoked {ident}"
