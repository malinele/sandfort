"""API key administration: create with scope attenuation, list metadata, revoke (WP 4.4).

A caller can only hand out scopes it already holds: asking for any scope outside the creating
principal's set raises ``ScopeEscalation`` (403), so keys attenuate and never amplify, and a
key created here is never a platform-admin key. ``create`` returns the plaintext key exactly
once; only its salted hash is stored. Revoking is idempotent: revoking a revoked key returns it
unchanged and records no second audit event. Audit details carry the name, prefix and scopes,
never the key or its hash.

A key minted by another key never outlives it: when the creating key has an ``expires_at`` the
child's must exist and not be later (``Unprocessable``, 422, naming the bound). The creator's id
is stored in ``created_by``, and revoking a key also revokes its live descendants (children,
grandchildren, ...) only when the revoke asks for ``cascade`` (default false), in the same
transaction and each with its own audit event. Without it the response lists those live
``dependants`` and leaves them alone, so rotating (mint the new key with the old one, then
revoke the old one) keeps the new key. The cascade also runs for an already revoked key.
"""

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sandfort.auth.api_keys import generate_api_key
from sandfort.auth.label_scope import matches
from sandfort.auth.principal import Principal
from sandfort.clock import Clock
from sandfort.db.repositories.ports import UnitOfWorkPort
from sandfort.domain.events import ActorType
from sandfort.domain.org import ApiKey, Scope
from sandfort.errors import Forbidden, InvalidRequest, NotFound, Unprocessable, ValidationFailed
from sandfort.ids import new_api_key_id
from sandfort.services.audit import AuditRecorder

KEY_CREATED = "api_key.created"
KEY_REVOKED = "api_key.revoked"
TARGET_TYPE = "api_key"


class ScopeEscalation(Forbidden):
    """The requested scopes are not a subset of the creating principal's scopes."""


class LabelScopeEscalation(Forbidden):
    """The requested label scope is unscoped or wider than the creating principal's."""


class SandboxCapEscalation(Forbidden):
    """The requested sandbox cap is missing or larger than the creating principal's."""


@dataclass(frozen=True, slots=True)
class CreatedApiKey:
    """The stored metadata plus the plaintext ``key``, which exists only in this value."""

    record: ApiKey
    key: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RevokedApiKey:
    """The revoked key plus its live descendants: revoked if ``cascade``, else left alive."""

    record: ApiKey
    dependants: Sequence[ApiKey]
    cascade: bool


def _sorted_values(scopes: Iterable[Scope]) -> list[str]:
    return sorted(scope.value for scope in scopes)


def _require_label_attenuation(principal: Principal, requested: Mapping[str, str] | None) -> None:
    """A label-scoped creator may only mint keys whose scope keeps every one of its pairs."""
    creator = principal.sandbox_labels
    held = requested or {}
    if creator is None or matches(held, creator):
        return
    lacking = {name: creator[name] for name in sorted(creator) if held.get(name) != creator[name]}
    raise LabelScopeEscalation(
        "a key created by a label-scoped key must keep the creator's sandbox labels: "
        + ", ".join(f"{name}={value}" for name, value in lacking.items()),
        details={"excess_labels": lacking},
    )


def _require_shared_attenuation(principal: Principal, requested: Mapping[str, str] | None) -> None:
    """A label-scoped creator may only share volumes it can already reach.

    Every volume the child could see through ``requested`` carries those labels, so the creator
    reaches it too when the request holds all the creator's own scope pairs or all the
    creator's shared pairs. An org-wide creator may share any labels.
    """
    scope = principal.sandbox_labels
    if scope is None or not requested:
        return
    reach = principal.shared_volume_labels
    if matches(requested, scope) or (reach is not None and matches(requested, reach)):
        return
    raise LabelScopeEscalation(
        "a key created by a label-scoped key may only set shared_volume_labels that include all "
        "of the creator's sandbox labels or all of its own shared_volume_labels",
        details={"sandbox_labels": dict(scope), "shared_volume_labels": reach},
    )


def _require_cap_attenuation(principal: Principal, requested: int | None) -> None:
    """A capped creator may only mint keys with a cap no larger than its own."""
    creator = principal.max_sandboxes
    if creator is None or (requested is not None and requested <= creator):
        return
    raise SandboxCapEscalation(
        f"a key created by a key capped at {creator} sandboxes must carry a max_sandboxes "
        f"of at most {creator}",
        details={"max_sandboxes": creator},
    )


def _require_same_scope_as_capped_creator(
    principal: Principal, requested: Mapping[str, str] | None
) -> None:
    """A capped creator may only mint keys whose labels equal its own, pair for pair.

    The cap counts the live sandboxes carrying every pair of the key's labels. A child that added
    a pair would count only its narrower scope, so each such child would get a fresh allowance and
    the creator's cap would bound nothing. With identical labels every descendant counts the same
    sandboxes as the creator, so the creator's cap bounds them all.
    """
    labels = principal.sandbox_labels
    if principal.max_sandboxes is None or labels is None or (requested or {}) == labels:
        return
    pairs = ", ".join(f"{name}={value}" for name, value in sorted(labels.items()))
    raise SandboxCapEscalation(
        "a key created by a key with max_sandboxes must carry exactly the creator's sandbox "
        f"labels ({pairs}), no extra pairs, so that the creator's cap counts every key it "
        "mints; mint a key with those labels and a max_sandboxes no larger than the creator's",
        details={"sandbox_labels": dict(labels), "max_sandboxes": principal.max_sandboxes},
    )


def _require_expiry_within_creator(creator: ApiKey | None, requested: datetime | None) -> None:
    """A child key may not outlive a creator that expires: its expiry must be set and no later."""
    bound = None if creator is None else creator.expires_at
    if bound is None or (requested is not None and requested <= bound):
        return
    raise Unprocessable(
        f"expires_at must be at or before the creating key's expiry ({bound.isoformat()}); "
        "a key cannot outlive the key that minted it",
        details={"max_expires_at": bound.isoformat()},
    )


def _live_descendants(keys: Iterable[ApiKey], root_id: str) -> list[ApiKey]:
    """Unrevoked keys reachable from ``root_id`` through ``created_by``, nearest first."""
    all_keys = list(keys)
    found: list[ApiKey] = []
    seen = {root_id}
    frontier = [root_id]
    while frontier:
        parents, frontier = set(frontier), []
        for key in all_keys:
            if key.created_by in parents and key.id not in seen:
                seen.add(key.id)
                frontier.append(key.id)
                if key.revoked_at is None:
                    found.append(key)
    return found


def _in_scope(key: ApiKey, caller_scope: Mapping[str, str] | None) -> bool:
    """True for an unscoped caller, else when the key's own labels keep every caller pair."""
    return matches(key.sandbox_labels or {}, caller_scope)


class ApiKeyAdminService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWorkPort],
        pepper: str,
        clock: Clock,
        recorder: AuditRecorder | None = None,
    ) -> None:
        if not pepper:
            raise ValueError("an API key pepper is required to issue keys")
        self._uow_factory = uow_factory
        self._pepper = pepper
        self._clock = clock
        self._recorder = recorder or AuditRecorder(clock)

    async def create(
        self,
        principal: Principal,
        name: str,
        scopes: Iterable[Scope],
        expires_at: datetime | None = None,
        sandbox_labels: Mapping[str, str] | None = None,
        max_sandboxes: int | None = None,
        recorder: AuditRecorder | None = None,
        shared_volume_labels: Mapping[str, str] | None = None,
    ) -> CreatedApiKey:
        """Issue a key in the caller's org holding ``scopes`` (a subset of the caller's).

        ``recorder`` overrides the service's recorder for this call; the route passes the app's
        request-correlated one so the event carries the request id, client ip and user agent.

        ``sandbox_labels`` scopes the new key to sandboxes carrying every pair; an empty
        mapping means unscoped. A label-scoped caller must keep all of its own pairs.
        ``max_sandboxes`` caps the sandboxes inside that scope and needs one; a capped caller
        must pass a cap no larger than its own and labels equal to its own (no extra pairs).
        ``shared_volume_labels`` lets a label-scoped key also list, get and mount read-only the
        volumes carrying every pair; it needs ``sandbox_labels`` and, from a label-scoped
        creator, labels that creator can already reach.
        A creator key with an ``expires_at`` bounds the child's: a later or missing expiry is 422.
        """
        requested = frozenset(scopes)
        excess = _sorted_values(requested - principal.scopes)
        if excess:
            raise ScopeEscalation(
                f"a key cannot grant scope(s) its creator lacks: {', '.join(excess)}",
                details={"excess_scopes": excess},
            )
        label_scope = dict(sandbox_labels) if sandbox_labels else None
        _require_label_attenuation(principal, label_scope)
        if max_sandboxes is not None and label_scope is None:
            raise ValidationFailed("max_sandboxes requires sandbox_labels")
        shared = dict(shared_volume_labels) if shared_volume_labels else None
        if shared is not None and label_scope is None:
            raise ValidationFailed("shared_volume_labels requires sandbox_labels")
        _require_shared_attenuation(principal, shared)
        _require_cap_attenuation(principal, max_sandboxes)
        _require_same_scope_as_capped_creator(principal, label_scope)
        now = self._clock.now()
        if expires_at is not None and expires_at <= now:
            raise InvalidRequest(
                "expires_at must be in the future",
                details={
                    "errors": [
                        {
                            "type": "value_error",
                            "loc": ["body", "expires_at"],
                            "msg": "expires_at must be in the future",
                        }
                    ]
                },
            )
        generated = generate_api_key(self._pepper)
        record = ApiKey(
            id=new_api_key_id(),
            org_id=principal.org_id,
            name=name,
            prefix=generated.prefix,
            secret_hash=generated.secret_hash,
            scopes=requested,
            sandbox_labels=label_scope,
            max_sandboxes=max_sandboxes,
            shared_volume_labels=shared,
            expires_at=expires_at,
            created_by=principal.key_id,
            created_at=now,
        )
        details = {
            "name": name,
            "prefix": record.prefix,
            "scopes": _sorted_values(requested),
            "sandbox_labels": label_scope,
            "max_sandboxes": max_sandboxes,
            "shared_volume_labels": shared,
            "expires_at": None if expires_at is None else expires_at.isoformat(),
            "is_platform_admin": record.is_platform_admin,
        }
        async with self._uow_factory() as uow:
            org_keys = await uow.api_keys.list_for_org(principal.org_id)
            creator = next((key for key in org_keys if key.id == principal.key_id), None)
            _require_expiry_within_creator(creator, expires_at)
            await uow.api_keys.add(record)
            await self._audit(uow, principal, KEY_CREATED, record.id, details, recorder)
            await uow.commit()
        return CreatedApiKey(record=record, key=generated.key)

    async def list_keys(self, principal: Principal) -> Sequence[ApiKey]:
        """Every key of the caller's org, revoked ones included, oldest first.

        A label-scoped caller sees only the keys inside its own scope (itself included).
        """
        async with self._uow_factory() as uow:
            keys = await uow.api_keys.list_for_org(principal.org_id)
        return [key for key in keys if _in_scope(key, principal.sandbox_labels)]

    async def revoke(
        self,
        principal: Principal,
        key_id: str,
        recorder: AuditRecorder | None = None,
        cascade: bool = False,
    ) -> RevokedApiKey:
        """Revoke ``key_id`` in the caller's org; revoking a revoked key is a no-op.

        ``recorder`` overrides the service's recorder for this call (see ``create``).

        A label-scoped caller cannot see keys outside its scope, so those answer not found.
        Without ``cascade`` only the key itself is revoked and ``dependants`` lists the live
        descendants (children, grandchildren, ...) that were left alone. With ``cascade`` they
        are revoked in the same transaction, each with its own audit event, and listed. The
        cascade also runs when the key is already revoked, to clean up its remaining children.
        The key's own audit event records the dependant count and the ``cascade`` flag.
        """
        now = self._clock.now()
        async with self._uow_factory() as uow:
            current = await self._require(uow, principal, key_id)
            if current.is_platform_admin and not principal.is_platform_admin:
                raise Forbidden(
                    "only a platform-admin key can revoke a platform-admin key; mint the "
                    "replacement with create-key --platform-admin, or revoke it from the host "
                    "with the admin CLI's revoke-key command"
                )
            keys = await uow.api_keys.list_for_org(principal.org_id)
            dependants = _live_descendants(keys, key_id)
            record = current
            if current.revoked_at is None:
                if not await uow.api_keys.revoke(principal.org_id, key_id, now):
                    # A concurrent revoke won; report the key as that call left it.
                    return RevokedApiKey(await self._require(uow, principal, key_id), [], cascade)
                details = {
                    "name": current.name,
                    "prefix": current.prefix,
                    "cascade": cascade,
                    "dependants": len(dependants),
                }
                await self._audit(uow, principal, KEY_REVOKED, key_id, details, recorder)
                record = current.model_copy(update={"revoked_at": now})
            elif not (cascade and dependants):
                return RevokedApiKey(current, dependants, cascade)
            if cascade:
                for child in dependants:
                    if await uow.api_keys.revoke(principal.org_id, child.id, now):
                        details = {
                            "name": child.name,
                            "prefix": child.prefix,
                            "cascade_from": key_id,
                        }
                        await self._audit(uow, principal, KEY_REVOKED, child.id, details, recorder)
            await uow.commit()
        if cascade:
            dependants = [key.model_copy(update={"revoked_at": now}) for key in dependants]
        return RevokedApiKey(record, dependants, cascade)

    async def _require(self, uow: UnitOfWorkPort, principal: Principal, key_id: str) -> ApiKey:
        """The key in the caller's org and label scope; anything else is the same 404."""
        for key in await uow.api_keys.list_for_org(principal.org_id):
            if key.id == key_id and _in_scope(key, principal.sandbox_labels):
                return key
        raise NotFound(f"api key {key_id} not found")

    async def _audit(
        self,
        uow: UnitOfWorkPort,
        principal: Principal,
        action: str,
        key_id: str,
        details: Mapping[str, Any],
        recorder: AuditRecorder | None = None,
    ) -> None:
        await (recorder or self._recorder).record(
            uow,
            org_id=principal.org_id,
            actor_type=ActorType.API_KEY,
            actor_id=principal.key_id,
            action=action,
            target_type=TARGET_TYPE,
            target_id=key_id,
            details=details,
        )
