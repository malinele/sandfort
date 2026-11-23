"""Shared pytest options: ``--driver`` picks the target of the driver certification test.

``fake`` (default), ``docker`` (needs a daemon, skipped otherwise), ``firecracker`` (the
skeleton against an in-process mock agent) or any installed ``sandfort.drivers`` entry point.
"""

from collections.abc import Iterator

import pytest

DRIVER_OPTION = "--driver"
DEFAULT_DRIVER = "fake"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        DRIVER_OPTION,
        action="store",
        default=DEFAULT_DRIVER,
        help="driver certified by tests/test_driver_contract.py: fake, docker, firecracker "
        "or a sandfort.drivers entry point name",
    )


@pytest.fixture(scope="session", autouse=True)
def plain_typer_help() -> Iterator[None]:
    """Keep Typer's help and usage-error rendering plain text for the whole session.

    GitHub Actions sets ``GITHUB_ACTIONS`` (and some runners ``FORCE_COLOR`` or ``PY_COLORS``);
    Typer's ``rich_utils`` then sets ``FORCE_TERMINAL`` and renders every ``--help`` and usage
    error with ANSI codes and box-drawing panels. The CLI tests assert the plain text a non-tty
    user sees, so the flag is switched off here. Typer reads the module global when it builds
    its console, so the patch takes effect at call time.
    """
    import typer.rich_utils

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(typer.rich_utils, "FORCE_TERMINAL", False)
        yield


@pytest.fixture(autouse=True)
def reopen_docker_lanes() -> Iterator[None]:
    """Undo a test's ``close_lanes``: the closed flag is process-wide and leaks by file order."""
    yield
    from sandfort.drivers.docker.lanes import reopen_lanes

    reopen_lanes()


@pytest.fixture
def selected_driver(request: pytest.FixtureRequest) -> str:
    """The ``--driver`` value."""
    return str(request.config.getoption(DRIVER_OPTION))
