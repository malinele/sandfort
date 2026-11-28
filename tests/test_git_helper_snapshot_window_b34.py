"""Round 100 (B34): the askpass helper lives in the sandbox filesystem,
so a snapshot can hold it.
"""

from pathlib import Path

import pytest

import sandfort.toolbox.git_credentials as git_credentials
from sandfort.api.schemas.toolbox_git import GitCredential
from sandfort.drivers.base import ExecRequest, ExecResult
from sandfort.drivers.errors import DriverError
from sandfort.toolbox.git import REMOTE_TIMEOUT_S
from sandfort.toolbox.git_credentials import ASKPASS_DIR, ephemeral_askpass

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "ghp_SandfortUnitTestToken0123456789"
URL = "https://git.example.test/acme/app.git"
USERNAME = "deploy-bot"
SECURITY_DOC = ROOT / "docs" / "security.md"
HEADING = "**A snapshot taken during the operation can contain the token.**"


class FsDriver:
    """Tracks which helper files exist in a pretend sandbox filesystem."""

    def __init__(self, *, fail_rm: bool = False) -> None:
        self.fail_rm = fail_rm
        self.files: set[str] = set()

    async def exec(self, ref: str, request: ExecRequest) -> ExecResult:
        program = request.argv[0]
        if program == "sh":
            self.files.add(request.argv[-1])
        elif program == "rm":
            if self.fail_rm:
                return ExecResult(exit_code=1)
            self.files.discard(request.argv[-1])
        return ExecResult(exit_code=0)


def credential() -> GitCredential:
    return GitCredential(username=USERNAME, token=TOKEN)


def security_section() -> str:
    text = SECURITY_DOC.read_text(encoding="utf-8")
    start = text.index(HEADING)
    end = text.index("**Mitigation.**", start)
    return text[start:end]


async def test_helper_is_in_the_sandbox_filesystem_only_while_the_operation_runs() -> None:
    driver = FsDriver()

    async with ephemeral_askpass(driver, "ref-1", credential(), URL) as askpass:
        assert askpass.path.startswith(f"{ASKPASS_DIR}/")
        assert askpass.path in driver.files

    assert driver.files == set()


async def test_helper_stays_when_removal_fails_after_a_successful_operation() -> None:
    driver = FsDriver(fail_rm=True)

    with pytest.raises(DriverError):
        async with ephemeral_askpass(driver, "ref-1", credential(), URL) as askpass:
            pass

    assert askpass.path in driver.files


async def test_helper_stays_when_removal_fails_after_a_failed_operation() -> None:
    driver = FsDriver(fail_rm=True)

    with pytest.raises(RuntimeError, match="git failed"):
        async with ephemeral_askpass(driver, "ref-1", credential(), URL) as askpass:
            raise RuntimeError("git failed")

    assert askpass.path in driver.files


def test_window_length_is_the_remote_timeout() -> None:
    assert REMOTE_TIMEOUT_S == 600.0


def test_security_doc_names_the_snapshot_window() -> None:
    section = security_section()

    for expected in (
        f"{ASKPASS_DIR}/",
        "POST /v1/snapshots/from-sandbox",
        "600 seconds",
        "another process",
        "502",
        "revoke",
    ):
        assert expected in section


def test_security_doc_window_section_has_no_dash_or_semicolon() -> None:
    section = security_section()

    assert chr(0x2014) not in section
    assert chr(0x2013) not in section
    assert ";" not in section


def test_git_credentials_docstring_mentions_snapshots() -> None:
    doc = git_credentials.__doc__ or ""

    assert "snapshot" in doc
    assert "docs/security.md" in doc


def test_security_doc_covers_a_failed_call_whose_removal_failed() -> None:
    flat = " ".join(security_section().split())

    for expected in (
        "502 `DRIVER_ERROR` for a plain driver failure",
        "409, 404 or 504",
        "only written to the server log",
        "after such a call that returned any error",
    ):
        assert expected in flat, expected
    assert "after a 502 from one" not in flat
