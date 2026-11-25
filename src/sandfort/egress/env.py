"""The proxy environment of an allowlisted sandbox (docs/egress-allowlist-design.md).

One function composes the four standard proxy variables (lowercase and uppercase forms for
http and https) plus ``no_proxy``. The proxy url carries the sandbox id and the signed egress
token as userinfo, which clients send as ``Proxy-Authorization`` on ``CONNECT``. The token
lifetime is the settings value ``ttl_s`` (``Settings.egress_token_ttl_s``), shortened to the
sandbox's auto-delete horizon plus one day when one is set (``token_lifetime_s``). The token is
a v2 token (``sfe2_``): it carries the sandbox id and the credential ``epoch`` but no allowlist,
which the proxy reads from the policy route.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import quote

from sandfort.egress.tokens import token_lifetime_s
from sandfort.egress.tokens_v2 import mint_egress_token_v2

PROXY_VARIABLES = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")
NO_PROXY_VARIABLES = ("no_proxy", "NO_PROXY")
NO_PROXY_HOSTS = "localhost,127.0.0.1"


@dataclass(frozen=True, slots=True)
class EgressReminting:
    """What re-minting a sandbox's egress token needs: the proxy, the secret, the max lifetime.

    Built from ``Settings.egress_proxy_address``, ``egress_secret`` and ``egress_token_ttl_s``.
    """

    proxy_address: str
    secret: str = field(repr=False)
    max_ttl_s: int


def compose_proxy_env(
    proxy_address: str,
    secret: str,
    sandbox_id: str,
    now: datetime,
    *,
    epoch: int,
    ttl_s: int | None = None,
    auto_delete_minutes: int | None = None,
) -> dict[str, str]:
    """Environment variables that route a sandbox's traffic through its egress proxy.

    ``ttl_s`` is the configured maximum lifetime; without it the minter's own default applies
    and ``auto_delete_minutes`` is ignored.
    """
    lifetime = None if ttl_s is None else token_lifetime_s(ttl_s, auto_delete_minutes)
    token = mint_egress_token_v2(
        secret, sandbox_id=sandbox_id, epoch=epoch, now=now, ttl_s=lifetime
    )
    userinfo = f"{quote(sandbox_id, safe='')}:{quote(token, safe='')}"
    url = f"http://{userinfo}@{proxy_address}"
    env = dict.fromkeys(PROXY_VARIABLES, url)
    env.update(dict.fromkeys(NO_PROXY_VARIABLES, NO_PROXY_HOSTS))
    return env


def reminted_proxy_env(
    env: Mapping[str, str],
    reminting: EgressReminting,
    sandbox_id: str,
    now: datetime,
    auto_delete_minutes: int | None,
    *,
    epoch: int,
) -> dict[str, str]:
    """``env`` with its proxy variables replaced by ones carrying a freshly minted token."""
    managed = (*PROXY_VARIABLES, *NO_PROXY_VARIABLES)
    kept = {name: value for name, value in env.items() if name not in managed}
    fresh = compose_proxy_env(
        reminting.proxy_address,
        reminting.secret,
        sandbox_id,
        now,
        ttl_s=reminting.max_ttl_s,
        auto_delete_minutes=auto_delete_minutes,
        epoch=epoch,
    )
    return {**kept, **fresh}
