"""Python code runs go through a loader so tracebacks show ``main.py``, not the run dir."""

import shutil
import subprocess
from pathlib import Path

import pytest

from sandfort.toolbox import code_run

PYTHON3 = shutil.which("python3")
needs_python3 = pytest.mark.skipif(PYTHON3 is None, reason="python3 is not on PATH")


def run_loader(
    tmp_path: Path, source: str, *args: str, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    run_dir = tmp_path / ".sandfort-run-abc123"
    run_dir.mkdir()
    script = run_dir / code_run.DISPLAY_NAME
    script.write_text(source)
    argv = code_run.interpreter_argv("python", str(script))
    assert PYTHON3 is not None
    return subprocess.run(
        [PYTHON3, *argv[1:], *args],
        cwd=cwd or tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_display_name_is_the_uploaded_python_file_name() -> None:
    assert code_run.DISPLAY_NAME == "main.py"


def test_python_argv_runs_the_loader_with_the_script_path() -> None:
    argv = code_run.interpreter_argv("python", "/tmp/.sandfort-run-x/main.py")

    assert argv == ["python3", "-c", code_run.PYTHON_LOADER, "/tmp/.sandfort-run-x/main.py"]


@pytest.mark.parametrize(
    ("language", "prefix"),
    [("javascript", ["node"]), ("typescript", ["npx", "--yes", "tsx"]), ("bash", ["bash"])],
)
def test_other_languages_keep_the_script_as_the_direct_argument(
    language: str, prefix: list[str]
) -> None:
    assert code_run.interpreter_argv(language, "/tmp/d/main.x") == [*prefix, "/tmp/d/main.x"]


@needs_python3
def test_uncaught_exception_shows_the_display_name_and_exits_1(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "x = 1\nraise ValueError('boom')\n")

    assert result.returncode == 1
    assert 'File "main.py", line 2, in <module>' in result.stderr
    assert "raise ValueError('boom')" in result.stderr
    assert "ValueError: boom" in result.stderr
    assert ".sandfort-run-" not in result.stderr
    assert "<string>" not in result.stderr


@needs_python3
def test_chained_exceptions_show_the_display_name_in_every_part(tmp_path: Path) -> None:
    source = (
        "def f():\n"
        "    try:\n"
        "        1 / 0\n"
        "    except ZeroDivisionError as error:\n"
        "        raise KeyError('k') from error\n"
        "f()\n"
    )

    result = run_loader(tmp_path, source)

    assert result.returncode == 1
    assert 'File "main.py", line 3, in f' in result.stderr
    assert 'File "main.py", line 5, in f' in result.stderr
    assert "direct cause of the following exception" in result.stderr
    assert ".sandfort-run-" not in result.stderr


@needs_python3
def test_a_custom_excepthook_set_by_the_user_is_used(tmp_path: Path) -> None:
    source = (
        "import sys\n"
        "sys.excepthook = lambda kind, error, trace: print('hooked', kind.__name__)\n"
        "raise RuntimeError('x')\n"
    )

    result = run_loader(tmp_path, source)

    assert (result.returncode, result.stdout) == (1, "hooked RuntimeError\n")


@needs_python3
def test_syntax_error_shows_the_display_name_and_exits_1(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "def broken(:\n")

    assert result.returncode == 1
    assert 'File "main.py", line 1' in result.stderr
    assert "SyntaxError" in result.stderr
    assert ".sandfort-run-" not in result.stderr


@needs_python3
def test_system_exit_keeps_its_code(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "raise SystemExit(3)\n")

    assert result.returncode == 3
    assert result.stderr == ""


@needs_python3
def test_stdout_and_success_exit_are_unchanged(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "print(6 * 7)\n")

    assert (result.returncode, result.stdout, result.stderr) == (0, "42\n", "")


@needs_python3
def test_file_is_the_real_absolute_path(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "print(__file__)\nprint(__name__)\n")

    expected = tmp_path / ".sandfort-run-abc123" / "main.py"
    assert result.stdout.splitlines() == [str(expected), "__main__"]


@needs_python3
def test_argv_zero_is_the_display_name_followed_by_user_args(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "import sys\nprint(sys.argv)\n", "--flag", "x")

    assert result.stdout.strip() == "['main.py', '--flag', 'x']"


@needs_python3
def test_imports_from_the_working_directory_keep_working(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "helper.py").write_text("VALUE = 7\n")
    source = "import os, sys\nimport helper\nprint(helper.VALUE, sys.path[0] == os.getcwd())\n"

    result = run_loader(tmp_path, source, cwd=work)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "7 True"


@needs_python3
def test_user_code_does_not_see_loader_variables(tmp_path: Path) -> None:
    source = "print(sorted(k for k in globals() if not k.startswith('__')))\n"

    result = run_loader(tmp_path, source)

    assert result.stdout.strip() == "[]"


@needs_python3
def test_the_code_runs_in_the_main_module(tmp_path: Path) -> None:
    source = (
        "import sys\n"
        "print(sys.modules['__main__'].__file__ == __file__)\n"
        "print(sys.modules['__main__'].__dict__ is globals())\n"
        "print(__name__)\n"
    )

    result = run_loader(tmp_path, source)

    assert result.stdout.splitlines() == ["True", "True", "__main__"]


@needs_python3
def test_a_function_defined_in_the_script_can_be_pickled(tmp_path: Path) -> None:
    source = (
        "import pickle\n"
        "def f(x):\n"
        "    return x + 1\n"
        "data = pickle.dumps(f)\n"
        "print(pickle.loads(data)(41))\n"
    )

    result = run_loader(tmp_path, source)

    assert (result.returncode, result.stdout, result.stderr) == (0, "42\n", "")


@needs_python3
def test_multiprocessing_pool_map_on_a_module_level_function(tmp_path: Path) -> None:
    source = (
        "import multiprocessing\n"
        "def square(x):\n"
        "    return x * x\n"
        "if __name__ == '__main__':\n"
        "    with multiprocessing.Pool(2) as pool:\n"
        "        print(pool.map(square, [1, 2, 3]))\n"
    )

    result = run_loader(tmp_path, source)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[1, 4, 9]"


@needs_python3
def test_the_traceback_names_the_display_name_and_has_no_loader_frame(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "def f():\n    raise ValueError('boom')\nf()\n")

    assert result.returncode == 1
    assert f'File "{code_run.DISPLAY_NAME}", line 3, in <module>' in result.stderr
    assert f'File "{code_run.DISPLAY_NAME}", line 2, in f' in result.stderr
    assert "<string>" not in result.stderr
    assert "TypeError" not in result.stderr
    assert result.stderr.count("Traceback (most recent call last)") == 1


@needs_python3
def test_system_exit_three_still_exits_three(tmp_path: Path) -> None:
    result = run_loader(tmp_path, "import sys\nsys.exit(3)\n")

    assert (result.returncode, result.stderr) == (3, "")


UNRELATED_FILE = "unrelated = 1\nnot the uploaded code\nstill not the uploaded code\n"


def cwd_with_unrelated_file(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    (work / code_run.DISPLAY_NAME).write_text(UNRELATED_FILE)
    return work


@needs_python3
def test_a_syntax_error_shows_the_uploaded_line_not_a_file_of_the_same_name_in_the_cwd(
    tmp_path: Path,
) -> None:
    source = "ok = 1\nalso_fine = 2\ndef broken(:\n"

    result = run_loader(tmp_path, source, cwd=cwd_with_unrelated_file(tmp_path))

    assert result.returncode == 1
    assert f'File "{code_run.DISPLAY_NAME}", line 3' in result.stderr
    assert "def broken(:" in result.stderr
    assert "SyntaxError" in result.stderr
    assert "uploaded code" not in result.stderr
    assert "unrelated" not in result.stderr


@needs_python3
def test_a_runtime_error_shows_the_uploaded_line_not_a_file_of_the_same_name_in_the_cwd(
    tmp_path: Path,
) -> None:
    source = "def f():\n    raise ValueError('boom')\nf()\n"

    result = run_loader(tmp_path, source, cwd=cwd_with_unrelated_file(tmp_path))

    assert result.returncode == 1
    assert "raise ValueError('boom')" in result.stderr
    assert "uploaded code" not in result.stderr


@needs_python3
def test_the_source_is_registered_in_linecache_under_the_display_name(tmp_path: Path) -> None:
    source = "import linecache\nprint(linecache.getline('main.py', 1), end='')\n"

    result = run_loader(tmp_path, source, cwd=cwd_with_unrelated_file(tmp_path))

    assert result.stdout == "import linecache\n"


def test_the_loader_only_uses_the_three_argument_print_exception() -> None:
    assert "print_exception(type(error), error, trace)" in code_run.PYTHON_LOADER
