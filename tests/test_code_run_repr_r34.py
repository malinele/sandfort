"""The user's ``__main__`` module repr shows the display name, never the private run dir."""

import shutil
import subprocess
from pathlib import Path

import pytest

from sandfort.toolbox import code_run

PYTHON3 = shutil.which("python3")
needs_python3 = pytest.mark.skipif(PYTHON3 is None, reason="python3 is not on PATH")
RUN_DIR_NAME = ".sandfort-run-abc123"
DISPLAY_REPR = f"<module '__main__' from '{code_run.DISPLAY_NAME}'>"


def run_loader(tmp_path: Path, source: str) -> subprocess.CompletedProcess[str]:
    run_dir = tmp_path / RUN_DIR_NAME
    run_dir.mkdir()
    script = run_dir / code_run.DISPLAY_NAME
    script.write_text(source)
    argv = code_run.interpreter_argv("python", str(script))
    assert PYTHON3 is not None
    return subprocess.run(
        [PYTHON3, *argv[1:]],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_main_module_repr_constant_uses_the_display_name_only() -> None:
    assert code_run.MAIN_MODULE_REPR == DISPLAY_REPR


@needs_python3
def test_main_module_repr_is_the_display_form(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "import sys\nprint(repr(sys.modules['__main__']))\n")

    assert (result.returncode, result.stderr) == (0, "")
    assert result.stdout.strip() == DISPLAY_REPR
    assert RUN_DIR_NAME not in result.stdout


@needs_python3
def test_file_is_still_the_real_path(tmp_path: Path) -> None:
    result = run_loader(
        tmp_path, "import sys\nprint(__file__)\nprint(sys.modules['__main__'].__file__)\n"
    )

    expected = str(tmp_path / RUN_DIR_NAME / code_run.DISPLAY_NAME)
    assert result.stdout.splitlines() == [expected, expected]


@needs_python3
def test_unpickling_a_missing_attribute_names_the_display_name(tmp_path: Path) -> None:
    source = (
        "import pickle\nclass M:\n    pass\ndata = pickle.dumps(M())\ndel M\npickle.loads(data)\n"
    )

    result = run_loader(tmp_path, source)

    assert result.returncode == 1
    assert "Can't get attribute 'M'" in result.stderr
    assert DISPLAY_REPR in result.stderr
    assert RUN_DIR_NAME not in result.stderr


@needs_python3
def test_a_function_defined_in_the_script_can_be_pickled(tmp_path: Path) -> None:
    source = (
        "import pickle\ndef f(x):\n    return x + 1\nprint(pickle.loads(pickle.dumps(f))(41))\n"
    )

    result = run_loader(tmp_path, source)

    assert (result.returncode, result.stdout, result.stderr) == (0, "42\n", "")


@needs_python3
def test_spawn_pool_with_a_main_guard_still_works(tmp_path: Path) -> None:
    source = (
        "import multiprocessing\n"
        "def square(x):\n"
        "    return x * x\n"
        "if __name__ == '__main__':\n"
        "    ctx = multiprocessing.get_context('spawn')\n"
        "    with ctx.Pool(2) as pool:\n"
        "        print(pool.map(square, [1, 2, 3]))\n"
    )

    result = run_loader(tmp_path, source)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[1, 4, 9]"
