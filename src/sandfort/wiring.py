"""Startup wiring that builds shared service settings from ``Settings``.

``egress_reminting`` turns the egress settings into the helper that re-mints a sandbox's egress
token; it is the one copy (the sandbox service builds its reset core with it). ``wire_egress``
also installs it for the job handlers (``install_job_egress``) and returns it;
``sandfort.api.wiring.install_services`` calls it once at startup and hands the result to the
auto-stop scanner. A re-mint only matters when a container is recreated (a reset): a start
reuses the container and its original environment.
"""

from sandfort.config import Settings
from sandfort.egress.env import EgressReminting
from sandfort.services.sandbox_jobs import install_job_egress


def egress_reminting(settings: Settings) -> EgressReminting | None:
    """The re-minting settings, or ``None`` when the egress proxy or its secret is not set."""
    if not (settings.egress_proxy_address and settings.egress_secret):
        return None
    return EgressReminting(
        settings.egress_proxy_address, settings.egress_secret, settings.egress_token_ttl_s
    )


def wire_egress(settings: Settings) -> EgressReminting | None:
    """Build the re-minting settings and install them for the job handlers; return them."""
    reminting = egress_reminting(settings)
    install_job_egress(reminting)
    return reminting
