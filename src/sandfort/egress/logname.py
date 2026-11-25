"""How the proxy writes a name it has not admitted into a log line.

A CONNECT target the policy refuses is attacker-controlled text of up to ~16 KiB, and the host
logs are exactly where data smuggled in a name must not land. Such a name is logged as its length
and a short keyed digest (HMAC-SHA256 under the egress secret, first ``DIGEST_HEX_CHARS`` hex
digits): enough to tell two refusals apart or to match a name someone already knows, nothing
that carries content. A name that matched a rule is logged as before.
"""

import hashlib
import hmac

DIGEST_HEX_CHARS = 12
_DOMAIN = b"sandfort-egress-log-name-v1\x00"


def redacted_name(secret: str, name: str) -> str:
    """``(len=<n> mac=<12 hex>)`` for ``name``; never any part of the name itself."""
    mac = hmac.new(secret.encode(), _DOMAIN + name.encode(errors="replace"), hashlib.sha256)
    return f"(len={len(name)} mac={mac.hexdigest()[:DIGEST_HEX_CHARS]})"
