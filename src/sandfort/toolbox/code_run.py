"""Language -> interpreter argv; upload the code to a private /tmp directory, then exec it.

The code travels as a small tar (a 0700 directory plus ``main<suffix>``) through
``put_archive`` (never through a shell command line). The interpreter gets the absolute
script path, while the exec working directory is the caller's ``cwd`` or, when none is
given, the container's default working directory. Relative reads therefore see the user's
files and relative writes persist. Python runs go through a short ``python3 -c`` loader
that compiles the file under the display name ``main.py``, so tracebacks show ``main.py``
instead of the random private directory (``__file__`` stays the real absolute path and
``sys.path[0]`` is the working directory). The code runs as the ``__main__`` module itself,
so pickling and ``multiprocessing`` work on functions defined in the script. Other languages
show the absolute path ending in ``main<suffix>``. The private directory is removed afterwards
on a best-effort basis.
"""

import io
import tarfile
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence

from sandfort.domain.sandbox import Sandbox, visible_stop_cause
from sandfort.drivers.base import ExecRequest, ExecResult, SandboxDriver
from sandfort.drivers.errors import DriverError
from sandfort.errors import Unprocessable, no_container_conflict
from sandfort.toolbox.process import execute, validate_env

SUPPORTED_LANGUAGES = ("python", "javascript", "typescript", "bash")

UPLOAD_DIR = "/tmp"  # a path inside the sandbox, not on the host
RUN_DIR_PREFIX = ".sandfort-run-"
FILE_STEM = "main"
CLEANUP_TIMEOUT_S = 10.0
_FILE_MODE = 0o600
_DIR_MODE = 0o700
PYTHON_SUFFIX = ".py"
DISPLAY_NAME = f"{FILE_STEM}{PYTHON_SUFFIX}"  # the name python tracebacks show
MAIN_MODULE_REPR = f"<module '__main__' from '{DISPLAY_NAME}'>"  # never the run directory

# Runs as ``python3 -c PYTHON_LOADER <script> [argv...]`` (Python 3.8+). The user's code runs
# in a real module named ``__main__`` installed in ``sys.modules`` (``__file__`` is the real
# absolute path), so ``pickle`` and ``multiprocessing`` find functions defined in the script.
# An uncaught exception loses the loader's own frame, so the user's code is the first frame
# shown; the source is registered in linecache under DISPLAY_NAME so the traceback still
# prints the offending lines. A custom sys.excepthook set by the user's code is honoured.
# The module is a ModuleType subclass whose repr shows DISPLAY_NAME, so pickle errors such as
# "Can't get attribute 'M' on <module '__main__' ...>" do not leak the private run directory.
PYTHON_LOADER = f"""\
import linecache, os, sys, types
path = sys.argv[1]
sys.argv = [{DISPLAY_NAME!r}, *sys.argv[2:]]
cwd = os.getcwd()
if sys.path and sys.path[0] == "":
    sys.path[0] = cwd
else:
    sys.path.insert(0, cwd)
with open(path, "rb") as handle:
    source = handle.read()
text = source.decode("utf-8", "replace")
lines = text.splitlines(True)
linecache.cache[{DISPLAY_NAME!r}] = (len(text), None, lines, {DISPLAY_NAME!r})
loader_main = sys.modules["__main__"]
class UserMain(types.ModuleType):
    def __repr__(self):
        return {MAIN_MODULE_REPR!r}
user_main = UserMain("__main__")
user_main.__file__ = path
sys.modules["__main__"] = user_main
try:
    exec(compile(source, {DISPLAY_NAME!r}, "exec"), user_main.__dict__)
except Exception as error:
    if isinstance(error, SyntaxError) and error.filename == {DISPLAY_NAME!r}:
        if error.lineno and 0 < error.lineno <= len(lines):
            error.text = lines[error.lineno - 1]
    trace = error.__traceback__.tb_next
    if sys.excepthook is sys.__excepthook__:
        import traceback
        traceback.print_exception(type(error), error, trace)
    else:
        sys.excepthook(type(error), error, trace)
    raise SystemExit(1)
"""

_INTERPRETERS: dict[str, tuple[list[str], str]] = {
    "python": (["python3", "-c", PYTHON_LOADER], PYTHON_SUFFIX),
    "javascript": (["node"], ".js"),
    "typescript": (["npx", "--yes", "tsx"], ".ts"),
    "bash": (["bash"], ".sh"),
}


def interpreter_argv(language: str, path: str) -> list[str]:
    try:
        prefix, _ = _INTERPRETERS[language]
    except KeyError:
        raise Unprocessable(
            f"unsupported language {language!r}",
            details={"supported": list(SUPPORTED_LANGUAGES)},
        ) from None
    return [*prefix, path]


async def run_code(
    driver: SandboxDriver,
    sandbox: Sandbox,
    language: str,
    code: str,
    *,
    argv: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
    timeout_s: float = 60.0,
    cwd: str | None = None,
) -> ExecResult:
    if sandbox.driver_ref is None:
        raise no_container_conflict(sandbox.state.value, visible_stop_cause(sandbox))
    suffix = _INTERPRETERS[language][1] if language in _INTERPRETERS else ""
    dir_name = f"{RUN_DIR_PREFIX}{uuid.uuid4().hex}"
    run_dir = f"{UPLOAD_DIR}/{dir_name}"
    file_name = f"{FILE_STEM}{suffix}"
    script = f"{run_dir}/{file_name}"
    command = interpreter_argv(language, script)  # validates the language before any upload
    merged_env = dict(env or {})
    validate_env(merged_env)

    archive = _tar_run_dir(dir_name, file_name, code.encode())
    await driver.put_archive(sandbox.driver_ref, UPLOAD_DIR, _single_chunk(archive))
    try:
        request = ExecRequest(
            argv=[*command, *argv],
            cwd=cwd,
            env=merged_env,
            timeout_s=timeout_s,
        )
        return await execute(driver, sandbox, request)
    finally:
        await _remove(driver, sandbox.driver_ref, run_dir)


def _tar_run_dir(dir_name: str, file_name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        directory = tarfile.TarInfo(dir_name)
        directory.type = tarfile.DIRTYPE
        directory.mode = _DIR_MODE
        archive.addfile(directory)
        info = tarfile.TarInfo(f"{dir_name}/{file_name}")
        info.size = len(content)
        info.mode = _FILE_MODE
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


async def _single_chunk(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _remove(driver: SandboxDriver, ref: str, path: str) -> None:
    try:
        await driver.exec(ref, ExecRequest(argv=["rm", "-rf", path], timeout_s=CLEANUP_TIMEOUT_S))
    except DriverError:
        pass  # best-effort cleanup; the run's own outcome is what the caller needs
