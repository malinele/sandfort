"""Member administration (``client.members``) and the single sign-on exchange.

Creating, re-roling and removing a member needs the admin scope; listing needs ``org:read``.
``exchange_sso`` on the clients trades an OIDC identity token for a short-lived session.
"""

from typing import Any

from sandfort_sdk._requests import segment
from sandfort_sdk._transport import AsyncTransport, Reply, SyncTransport
from sandfort_sdk.models import Member, SsoSession, _as_list

MEMBERS_PATH = "/v1/org/members"
SSO_EXCHANGE_PATH = "/v1/auth/sso/exchange"


def member_path(user_id: str) -> str:
    return f"{MEMBERS_PATH}/{segment(user_id)}"


def _text(value: str, name: str) -> str:
    if not value.strip():
        raise ValueError(f"{name!r} must not be empty")
    return value


def member_create_body(email: str, display_name: str, role: str) -> dict[str, Any]:
    return {
        "email": _text(email, "email"),
        "display_name": _text(display_name, "display_name"),
        "role": _text(role, "role"),
    }


def member_role_body(role: str) -> dict[str, Any]:
    return {"role": _text(role, "role")}


def sso_exchange_body(id_token: str) -> dict[str, Any]:
    return {"id_token": _text(id_token, "id_token")}


def sso_session(reply: Reply) -> SsoSession:
    return SsoSession.from_payload(reply.data)


def _members(reply: Reply) -> tuple[Member, ...]:
    return tuple(Member.from_payload(item) for item in _as_list(reply.data, "members"))


class Members:
    """Synchronous member client."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def create(self, email: str, display_name: str, role: str) -> Member:
        """Add a member; a second membership of the same user in the org is a 409."""
        body = member_create_body(email, display_name, role)
        reply = self._transport.request("POST", MEMBERS_PATH, json=body)
        return Member.from_payload(reply.data)

    def list(self) -> tuple[Member, ...]:
        return _members(self._transport.request("GET", MEMBERS_PATH))

    def set_role(self, user_id: str, role: str) -> Member:
        """Change a role; the server refuses a change that leaves the org without an admin."""
        body = member_role_body(role)
        reply = self._transport.request("PATCH", member_path(user_id), json=body)
        return Member.from_payload(reply.data)

    def remove(self, user_id: str) -> None:
        """Remove a member (the server answers 204 with no envelope, so nothing is unwrapped)."""
        self._transport.open_stream("DELETE", member_path(user_id)).close()


class AsyncMembers:
    """Asynchronous member client."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def create(self, email: str, display_name: str, role: str) -> Member:
        """Add a member; a second membership of the same user in the org is a 409."""
        body = member_create_body(email, display_name, role)
        reply = await self._transport.request("POST", MEMBERS_PATH, json=body)
        return Member.from_payload(reply.data)

    async def list(self) -> tuple[Member, ...]:
        return _members(await self._transport.request("GET", MEMBERS_PATH))

    async def set_role(self, user_id: str, role: str) -> Member:
        """Change a role; the server refuses a change that leaves the org without an admin."""
        body = member_role_body(role)
        reply = await self._transport.request("PATCH", member_path(user_id), json=body)
        return Member.from_payload(reply.data)

    async def remove(self, user_id: str) -> None:
        """Remove a member (the server answers 204 with no envelope, so nothing is unwrapped)."""
        response = await self._transport.open_stream("DELETE", member_path(user_id))
        await response.aclose()
