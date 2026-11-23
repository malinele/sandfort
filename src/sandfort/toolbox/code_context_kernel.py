"""Sources uploaded into the sandbox for a code context, and the ``sh -c`` scripts around them.

``KERNEL_SOURCE`` and ``CLIENT_SOURCE`` are the stdlib-only programs ``code_contexts`` uploads
(and describes); the scripts are the housekeeping calls (start, ready, probe, list, interrupt,
idle, kill, delete) it execs. Protocol: the client sends one JSON line ``{"code", "timeout_s",
"seq"}``; the kernel answers with output frames ``{"s": "o"|"e", "d": text}`` (a stream's writes,
sent in chunks) and one reply ``{"x": status, "r": repr or null, "err": {"type", "message"} or
null}`` (cut to ``RESULT_MAX_CHARS``). With a per-run token (fifth argument; the sixth is
``seq``) the client ends stdout with a trailer line: ``OUTCOME_MARK``, the token, a space and
``{"x", "r", "err", "lost"}`` (``lost``: the kernel was unreachable or closed the connection),
which ``code_contexts.split_outcome`` removes; ``TRAILER_RESERVE_BYTES`` of the cap stay free.
"""

import io
import tarfile

_FILE_MODE, _DIR_MODE = 0o600, 0o700

KERNEL_SOURCE = r'''"""Sandfort code-context kernel: persistent globals behind a unix socket."""
import ast
import collections
import json
import linecache
import os
import signal
import socket
import sys
import threading
import traceback
import types

PARSE_NAME = "<cell>"  # what the parser calls a cell, so a SyntaxError names "<cell>"
MAX_CELLS = 100  # recent cells whose source stays in linecache; the oldest are pruned
RESULT_MAX_CHARS = 4096  # longest result repr, error type or message in a reply; longer is cut
CUT_MARK = "... [truncated]"
SIGINT_ONLY, HELD = {signal.SIGINT}, {signal.SIGINT, signal.SIGALRM}  # HELD: while sending
FLUSH_CHARS = 64 * 1024  # a stream's collected writes go out as one frame at this size,
FLUSH_S = 0.05  # every FLUSH_S (flusher thread), on flush() and at the cell's end
SPAWN_HINT = ("hint: functions defined in cells are not importable by spawn/forkserver children;"
              ' use multiprocessing.get_context("fork") or put the function in a module file')
STATE = {
    "running": False,  # a cell's code is executing (the only time SIGINT may interrupt)
    "seq": 0,  # number of the running or last cell (0: the request carried none)
    "skip": None,  # number of a cell an interrupt named before it started
    "interrupted": False, "spawn": False,  # SIGINT stopped the cell; spawn children lived then
    "busy_path": None, "interrupt_path": None, "cells": 0, "recent": collections.deque(),
}

def bounded(text):
    """``text``, cut to RESULT_MAX_CHARS (marker included) when it is longer."""
    cut = text[: RESULT_MAX_CHARS - len(CUT_MARK)] + CUT_MARK
    return text if len(text) <= RESULT_MAX_CHARS else cut

def send(conn, frame):
    held = signal.pthread_sigmask(signal.SIG_BLOCK, HELD)  # a signal never cuts a frame
    try:
        conn.sendall(json.dumps(frame).encode("utf-8") + b"\n")
    except OSError:
        pass  # the client went away; the cell still runs until it ends or times out
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, held)

class Frames(object):
    """File-like object that collects a stream's writes, in order, and sends them in chunks."""

    def __init__(self, conn, tag):
        self.conn, self.tag, self.parts, self.size = conn, tag, [], 0
        self.lock, self.pid = threading.RLock(), os.getpid()  # the flusher and cell threads

    def write(self, text):
        text = str(text)
        with self.lock:
            self.parts.append(text)
            self.size += len(text)
            if self.size >= FLUSH_CHARS or os.getpid() != self.pid:  # forked child: no flusher
                self.flush()
        return len(text)

    def flush(self):
        if not self.parts:
            return  # the lock is only taken with output to send, so a fork rarely inherits it
        with self.lock:
            text, self.parts, self.size = "".join(self.parts), [], 0
            if text:  # empty when another thread's flush came first
                send(self.conn, {"s": self.tag, "d": text})

    isatty = lambda self: None  # falsy

def flush_until(stop, streams):
    signal.pthread_sigmask(signal.SIG_BLOCK, HELD)  # signals keep going to the main thread
    while not stop.wait(FLUSH_S):  # slow output is not held back while the cell runs
        for stream in streams:
            stream.flush()

def cell_traceback(tb):
    """``tb`` without the kernel's own frames, so tracebacks only show the cell."""
    kept = []
    while tb is not None:
        if tb.tb_frame.f_code.co_filename != __file__:
            kept.append(tb)
        tb = tb.tb_next
    for earlier, later in zip(kept, kept[1:] + [None]):
        earlier.tb_next = later
    return kept[0] if kept else None

def report(exc):
    traceback.print_exception(type(exc), exc, cell_traceback(exc.__traceback__), file=sys.stderr)

def register_cell(code):
    """Name the cell ``<cell-N>``; its source stays in linecache for the last MAX_CELLS cells."""
    STATE["cells"] += 1
    name = "<cell-%d>" % STATE["cells"]
    linecache.cache[name] = (len(code), None, code.splitlines(True), name)
    STATE["recent"].append(name)
    while len(STATE["recent"]) > MAX_CELLS:
        linecache.cache.pop(STATE["recent"].popleft(), None)
    return name

def execute(namespace, code):
    """Run the cell; answer the repr of a trailing expression that is not None (also printed)."""
    cell = register_cell(code)
    tree = ast.parse(code, PARSE_NAME, "exec")
    last = None
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        last = ast.Expression(tree.body.pop().value)
    exec(compile(tree, cell, "exec"), namespace)
    value = None if last is None else eval(compile(last, cell, "eval"), namespace)
    if value is None:
        return None
    namespace["_"], text = value, repr(value)
    print(text)
    return bounded(text)

def describe(exc, hint=False):
    """The exception as {"type", "message"}, each bounded; ``hint`` appends a SPAWN_HINT line."""
    try:
        message = str(exc)
    except Exception:
        message = ""
    if hint:
        message = (message + "\n" if message else "") + SPAWN_HINT
    return {"type": bounded(type(exc).__name__), "message": bounded(message)}

def spawn_children():
    """True when live children started by spawn or forkserver exist (from signal handlers)."""
    mp = sys.modules.get("multiprocessing")
    try:  # a process's own start method, else that of the default context it started from
        default = mp.get_start_method(allow_none=True)
        methods = {getattr(p, "_start_method", None) or default for p in mp.active_children()}
    except Exception:  # multiprocessing never imported (mp is None), or not as expected
        return False
    return not methods.isdisjoint(("spawn", "forkserver"))

def take_target():
    """The cell number a targeted interrupt named (``kernel.interrupt``), else None."""
    try:  # TypeError: no interrupt path (None)
        with open(STATE["interrupt_path"]) as target:
            number = int(target.read())
        os.remove(STATE["interrupt_path"])
        return number
    except (OSError, ValueError, TypeError):
        return None

def on_interrupt(signum, frame):
    """SIGINT: stop the running (or named) cell once; a named one not begun goes to "skip"."""
    target = take_target()
    if STATE["running"] and target in (None, STATE["seq"]):
        STATE["running"] = False
        STATE["interrupted"], STATE["spawn"] = True, spawn_children()
        raise KeyboardInterrupt()
    if target is not None and target > STATE["seq"]:
        STATE["skip"] = target

def set_running(flag):
    """Set the running flag and the busy marker (the cell's number, renamed into place)."""
    path = STATE["busy_path"]
    try:
        if path is not None and flag:
            with open(path + ".tmp", "w") as marker:
                marker.write(str(STATE["seq"]))
            os.replace(path + ".tmp", path)
        elif path is not None:
            os.remove(path)
    except OSError:
        pass
    STATE["running"] = flag  # last: a cell counts as running once its marker is in place

def begin(seq):
    """Mark cell ``seq`` running; KeyboardInterrupt when an interrupt named it beforehand."""
    signal.pthread_sigmask(signal.SIG_BLOCK, SIGINT_ONLY)
    try:  # blocked, so the number and the flag change together
        STATE["seq"], STATE["interrupted"], STATE["spawn"] = seq, False, False
        set_running(True)
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, SIGINT_ONLY)
    skip = STATE["skip"]
    if skip is not None and skip <= seq:
        STATE["skip"] = None
        if skip == seq:
            STATE["interrupted"] = True
            raise KeyboardInterrupt()

def run_cell(namespace, conn, code, timeout_s, seq=0):
    """Run one cell; returns (status, result, error) with SIGINT still blocked (see handle)."""
    saved, streams = (sys.stdout, sys.stderr), (Frames(conn, "o"), Frames(conn, "e"))
    stop = threading.Event()
    flusher = threading.Thread(target=flush_until, args=(stop, streams), daemon=True)
    flusher.start()  # first: when it fails nothing has changed yet
    sys.stdout, sys.stderr = streams

    def on_alarm(signum, frame):
        fired.append(True)
        STATE["spawn"] = spawn_children()  # now: a pool's exit would end its children
        raise TimeoutError("cell exceeded %s s" % timeout_s)

    previous = signal.signal(signal.SIGALRM, on_alarm)
    status, result, error, fired = 0, None, None, []  # fired: set before any alarm is armed
    try:
        try:
            begin(seq)
            signal.alarm(timeout_s)
            result = execute(namespace, code)
            signal.pthread_sigmask(signal.SIG_BLOCK, SIGINT_ONLY)  # before the body is left
        finally:  # the cell's code returned or raised: no interrupt may reach this frame now
            signal.pthread_sigmask(signal.SIG_BLOCK, SIGINT_ONLY)
            STATE["running"] = False
            signal.alarm(0)
    except BaseException as exc:
        status = 124 if fired and isinstance(exc, TimeoutError) else 1
        stopped = status == 124 or (STATE["interrupted"] and isinstance(exc, KeyboardInterrupt))
        hinted = bool(stopped and STATE["spawn"])
        result, error = None, describe(exc, hinted)
        report(exc)
        if hinted:  # stderr agrees with error.message: the hint is the last line
            sys.stderr.write(SPAWN_HINT + "\n")
    finally:
        signal.alarm(0)  # again: an interrupt may have skipped the inner one (late SIGINT)
        signal.signal(signal.SIGALRM, previous)
        stop.set()
        flusher.join()
        for stream in streams:  # the cell's last writes go out before its reply
            stream.flush()
        sys.stdout, sys.stderr = saved
        set_running(False)
    return status, result, error

def handle(namespace, conn):
    """Serve one request: run its cell and always answer with a reply frame."""
    try:
        reply = {"x": 1, "r": None, "err": None}
        try:
            line = conn.makefile("rb").readline()
            if not line:
                return
            request = json.loads(line.decode("utf-8"))
            seq, timeout_s = int(request.get("seq", 0)), int(request["timeout_s"])
            status, result, error = run_cell(namespace, conn, request["code"], timeout_s, seq)
            reply = {"x": status, "r": result, "err": error}
        except BaseException as exc:  # a reply goes out whatever happened
            if isinstance(exc, KeyboardInterrupt) and STATE["interrupted"]:
                reply["err"] = describe(exc)  # the cell itself was interrupted
            else:
                send(conn, {"s": "e", "d": traceback.format_exc()})
        send(conn, reply)
    finally:  # SIGINT stayed blocked since the cell ended; a held-back one is now a no-op
        signal.pthread_sigmask(signal.SIG_UNBLOCK, SIGINT_ONLY)

def new_main():
    """The cells' globals: a fresh module named __main__; the kernel's own code stays out."""
    cells = sys.modules["__main__"] = types.ModuleType("__main__")
    return cells.__dict__

def own_directory_off_path():
    """Put the working directory first on sys.path, as ``code_run`` and Jupyter do.

    Run as a script, sys.path[0] is the kernel's private directory; cells import modules from
    the context's cwd instead, and the kernel's own files stop being importable from cells."""
    private = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
    kept = [entry for entry in sys.path if os.path.realpath(entry or ".") != private]
    sys.path[:] = [os.getcwd()] + kept

def serve(directory):
    own_directory_off_path()
    signal.signal(signal.SIGINT, on_interrupt)
    STATE["busy_path"] = os.path.join(directory, "kernel.busy")
    STATE["interrupt_path"] = os.path.join(directory, "kernel.interrupt")
    for name, text in (("kernel.pid", str(os.getpid())), ("kernel.cwd", os.getcwd())):
        with open(os.path.join(directory, name), "w") as handle_:
            handle_.write(text)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    staging = os.path.join(directory, "kernel.sock.tmp")
    server.bind(staging)
    os.chmod(staging, 0o600)
    server.listen(16)
    os.rename(staging, os.path.join(directory, "kernel.sock"))  # clients see it only when ready
    namespace = new_main()
    while True:
        conn, _ = server.accept()
        try:
            handle(namespace, conn)
        except KeyboardInterrupt:
            pass  # an interrupt that landed outside the cell's own handler; the kernel stays up
        finally:
            conn.close()

if __name__ == "__main__":
    serve(sys.argv[1])
'''

CLIENT_SOURCE = r'''"""Sandfort code-context client: run one cell file against the kernel socket."""
import json
import socket
import sys

OUTCOME_MARK = "\x1esandfort-outcome "

def emit(stream, text):
    stream.buffer.write(text.encode("utf-8", "replace"))
    stream.buffer.flush()

def finish(token, status, result=None, error=None, lost=False):
    """Return ``status``; with a token, first end stdout with the outcome trailer line."""
    if token:
        fields = {"x": status, "r": result, "err": error, "lost": lost}
        emit(sys.stdout, OUTCOME_MARK + token + " " + json.dumps(fields, ensure_ascii=False) + "\n")
    return status

def main(argv):
    sock_path, code_path, timeout = argv[1], argv[2], float(argv[3])
    token = argv[4] if len(argv) > 4 else ""
    seq = int(argv[5]) if len(argv) > 5 else 0  # the run's cell number, for targeted interrupts
    with open(code_path, "rb") as handle:
        code = handle.read().decode("utf-8", "replace")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.connect(sock_path)
    except OSError as exc:
        emit(sys.stderr, "cannot reach the context kernel (%s); create a new context\n" % exc)
        return finish(token, 1, lost=True)
    request = {"code": code, "timeout_s": max(1, int(-(-timeout // 1))), "seq": seq}
    try:
        conn.sendall(json.dumps(request).encode("utf-8") + b"\n")
        for line in conn.makefile("rb"):
            frame = json.loads(line.decode("utf-8"))
            if "x" in frame:
                return finish(token, int(frame["x"]), frame.get("r"), frame.get("err"))
            emit(sys.stdout if frame["s"] == "o" else sys.stderr, frame["d"])
    except OSError:
        pass  # the kernel died mid-cell (connection reset): reported like a closed connection
    emit(sys.stderr, "the context kernel closed the connection; its state is lost\n")
    return finish(token, 1, lost=True)

sys.exit(main(sys.argv))
'''

# ``sh -c`` scripts; the directory (and other values) arrive as positional arguments.
# ``is_kernel DIR PID``: /proc/PID/cmdline has ``DIR/kernel.py`` as an argument (/tmp outlives a
# stopped sandbox's processes; an old pid may be another process, even a client naming DIR).
_IS_KERNEL = (
    'is_kernel() { case "$2" in ""|*[!0-9]*) return 1;; esac; '
    'case " $(tr \'\\0\' \' \' <"/proc/$2/cmdline" 2>/dev/null)" in '
    '*" $1/kernel.py "*) return 0;; esac; return 1; }; '
)
_KILL_KERNEL = (
    'pid="$(cat "$1/kernel.pid" 2>/dev/null)"; '
    'if is_kernel "$1" "$pid"; then { kill -9 "$pid"; kill -9 -- "-$pid"; } 2>/dev/null; fi; '
)
_START_SCRIPT = 'setsid python3 "$1/kernel.py" "$1" >"$1/kernel.log" 2>&1 </dev/null &'
_READY_SCRIPT = '[ -S "$1/kernel.sock" ] && cat "$1/kernel.cwd"'
_PROBE_SCRIPT = (
    _IS_KERNEL + '[ -S "$1/kernel.sock" ] && is_kernel "$1" "$(cat "$1/kernel.pid" 2>/dev/null)"'
)
_LIST_SCRIPT = (
    _IS_KERNEL + 'for d in /tmp/.sandfort-ctx-*; do [ -S "$d/kernel.sock" ] || continue; '
    'is_kernel "$d" "$(cat "$d/kernel.pid" 2>/dev/null)" || continue; '
    'printf "%s\\t%s\\n" "${d##*/.sandfort-ctx-}" "$(cat "$d/kernel.cwd" 2>/dev/null)"; done'
)
_KILL_SCRIPT = _IS_KERNEL + _KILL_KERNEL + "exit 0"
_DELETE_SCRIPT = _IS_KERNEL + '[ -d "$1" ] || exit 44; ' + _KILL_KERNEL + 'rm -rf "$1"; exit 0'
_NOT_FOUND_EXIT_CODE = 44
# SIGINT to the kernel pid (only when /proc names its script): exit 0 sent, 1 no live kernel, 44
# no directory. A cell number as $2 (kernel.interrupt, written first) stops only that cell.
_INTERRUPT_SCRIPT = (
    _IS_KERNEL + '[ -d "$1" ] || exit 44; pid="$(cat "$1/kernel.pid" 2>/dev/null)"; '
    'is_kernel "$1" "$pid" || exit 1; '
    'if [ -n "$3" ] && [ ! -e "$1/kernel.busy" ]; then exit 2; fi; rm -f "$1/kernel.interrupt"; '
    'if [ -n "$2" ]; then printf %s "$2" >"$1/kernel.interrupt.tmp" '
    '&& mv "$1/kernel.interrupt.tmp" "$1/kernel.interrupt"; fi; '
    'kill -INT "$pid" 2>/dev/null || exit 1; exit 0'
)
# Exit 0 when the kernel runs no cell (no busy marker, or one holding another number than $2).
_IDLE_SCRIPT = (
    '[ ! -e "$1/kernel.busy" ] && exit 0; '
    '[ -n "$2" ] && [ "$(cat "$1/kernel.busy" 2>/dev/null)" != "$2" ]'
)
# Stdout cap kept for the trailer: result and error text (RESULT_MAX_CHARS, <= 6 bytes each).
TRAILER_RESERVE_BYTES = 64 * 1024


def _tar(entries: dict[str, bytes], *, directory: str | None = None) -> bytes:
    """A tar of ``entries`` (name -> content), inside a 0700 ``directory`` when one is given."""
    buffer = io.BytesIO()
    prefix = "" if directory is None else directory + "/"
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        if directory is not None:
            info = tarfile.TarInfo(directory)
            info.type, info.mode = tarfile.DIRTYPE, _DIR_MODE
            archive.addfile(info)
        for name, content in entries.items():
            member = tarfile.TarInfo(prefix + name)
            member.size, member.mode = len(content), _FILE_MODE
            archive.addfile(member, io.BytesIO(content))
    return buffer.getvalue()
