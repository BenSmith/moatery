"""Request filters: the document that names them, and running one.

A filter is a program the operator names for a host pattern. The
inspector holds a request's body, runs the filter with the body on its
stdin, and forwards what it writes to stdout, or answers for it. The
document is read like the policy, strictly, and is checked against the
policy it is loaded beside. `run_filter` runs one filter once and says
what happened; what the guest is answered is the caller's.
"""

import errno
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import threading
import time
from typing import NamedTuple

from .inspect_document import (
    RequestFilter,
    RequestFilters,
    inspect_policy_digest,
    pattern_covers,
    patterns_overlap,
)


# The largest body a filter is given, and the largest it may write back.
FILTER_BODY_MAX = 64 << 20

# What every held body and filter output together may hold at once.
FILTER_INFLIGHT_MAX = 256 << 20

# How long one filter may run, in seconds, from the request's turn.
FILTER_TIMEOUT = 10.0

# How many filters run at once: the body budget bounds memory, not
# processes.
FILTER_PROCESSES_MAX = 8

# How much of a filter's stderr is kept, for the refusal reason alone.
FILTER_STDERR_MAX = 4096

# The exit status by which a filter refuses a request. Not 1, which an
# uncaught exception and a wrapper's own failure both exit with.
EXIT_REFUSE = 77

# A refusal's reason, as the first line of stderr spells it.
REASON_TOKEN = re.compile(r"[a-z0-9._-]{1,64}")

FILTER_PATH = "/usr/bin:/bin"

# The key the listener reports its loaded filter document's digest under.
REQUEST_FILTERS_DIGEST_KEY = "request_filters_digest"

# The one piece a pipe is read or written in.
_PIECE = 65536


def load_request_filters(path, policy) -> RequestFilters:
    """Read the filter document, checked against `policy`, or raise.

    `policy` is the one it will be enforced beside, so a reload checks the
    new pair, not the new document against the old policy.
    """
    with open(path) as f:
        text = f.read()
    digest = inspect_policy_digest(text)
    try:
        doc = json.loads(text)
    except ValueError as exc:
        # Named, so a reload's warning says which of the pair it was.
        raise ValueError(f"{path}: {exc}") from None
    if not isinstance(doc, dict):
        raise ValueError(
            f"{path}: expected a JSON object, got {type(doc).__name__}")
    _refuse_unknown_keys(path, "the document", doc, ("filters",))
    if "filters" not in doc:
        raise ValueError(f"{path}: 'filters' is missing")
    if not isinstance(doc["filters"], list):
        raise ValueError(f"{path}: 'filters' is not a list")
    filters = []
    for i, item in enumerate(doc["filters"]):
        where = f"filter {i}"
        if not isinstance(item, dict):
            raise ValueError(f"{path}: {where} is not an object")
        _refuse_unknown_keys(path, where, item, ("host", "run"))
        for key in ("host", "run"):
            value = item.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"{path}: {where} {key!r} is {value!r}, not a "
                    f"non-empty string")
        _check_run(path, item["run"])
        filters.append(RequestFilter(item["host"], item["run"]))
    for i, a in enumerate(filters):
        for b in filters[i + 1:]:
            if a.run != b.run and patterns_overlap(a.host, b.host):
                raise ValueError(
                    f"{path}: filters {a.host!r} and {b.host!r} overlap "
                    f"and run different programs ({a.run!r}, {b.run!r}), "
                    f"so the order of entries would decide. Give them one "
                    f"program or patterns that do not overlap")
    if filters and policy.tls == "splice":
        raise ValueError(
            f"{path}: filters with the policy's tls 'splice': a spliced "
            f"connection is never decrypted, so no filter could run")
    for i, entry in enumerate(filters):
        for pattern in policy.splice:
            if pattern_covers(pattern, entry.host):
                raise ValueError(
                    f"{path}: filter {entry.host!r} is covered by the "
                    f"policy's 'splice' entry {pattern!r}: a spliced host "
                    f"is never read as an HTTP request, so the filter "
                    f"could never run")
        filters[i] = entry._replace(spliced=tuple(
            p for p in policy.splice if patterns_overlap(entry.host, p)))
    return RequestFilters(tuple(filters), digest)


def _refuse_unknown_keys(path, where, obj, known):
    for key in obj:
        if key not in known:
            raise ValueError(
                f"{path}: {where} has the unknown key {key!r}; it takes "
                + ", ".join(repr(k) for k in known))


def _check_run(path, run):
    """Refuse a program the inspector can't exec, or that anyone but its
    owner could replace."""
    if not os.path.isabs(run):
        raise ValueError(f"{path}: run {run!r} is not an absolute path")
    try:
        st = os.stat(run)
    except OSError as exc:
        raise ValueError(
            f"{path}: run {run!r}: {exc.strerror}") from None
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{path}: run {run!r} is not a regular file")
    if not os.access(run, os.X_OK):
        raise ValueError(f"{path}: run {run!r} is not executable")
    if st.st_mode & 0o022:
        raise ValueError(
            f"{path}: run {run!r} is group- or world-writable")


# --- Running one filter ---

PASSED = "passed"
REWROTE = "rewrote"
REFUSED = "refused"
FAILED = "failed"
TIMED_OUT = "timed out"
UNAVAILABLE = "unavailable"

# Spawn failures that say the host is short of something, not that the
# filter is wrong.
_SPAWN_UNAVAILABLE = frozenset((errno.EAGAIN, errno.ENOMEM, errno.ETXTBSY))

# Spawn failures that say `run` itself can't be run.
_SPAWN_REFUSED = frozenset((errno.ENOENT, errno.EACCES, errno.ENOEXEC))


class Budget:
    """Bytes held across every request at once, taken and given back."""

    def __init__(self, limit):
        self.limit = limit
        self.used = 0
        self._lock = threading.Lock()

    def take(self, n) -> bool:
        with self._lock:
            if self.used + n > self.limit:
                return False
            self.used += n
            return True

    def give(self, n):
        with self._lock:
            self.used -= n


class Outcome(NamedTuple):
    """What one run of a filter came to.

    `body` is the output to forward, and empty unless `kind` is PASSED or
    REWROTE. `fields` are the journal's classification (`exit=N`,
    `signal=SEGV`, ...). `spawn_refused` says `run` could not be exec'd at
    all, which the operator is told about.
    """

    kind: str
    body: bytes
    reason: str | None
    fields: tuple
    ms: int
    spawn_refused: bool = False


def filter_env(cid, seq, req, length) -> dict:
    """The filter's whole environment. No header is ever in it."""
    ctype = next((v for n, v in req.headers if n == "content-type"), "")
    return {
        "MOAT_ID": str(cid),
        "MOAT_REQ": str(seq),
        "MOAT_HOST": req.host,
        "MOAT_METHOD": req.method,
        "MOAT_PATH": req.path,
        "MOAT_CONTENT_TYPE": ctype,
        "MOAT_LENGTH": str(length),
        "PATH": FILTER_PATH,
    }


def _spawn(run, env):
    # restore_signals stays True: the child gets SIGPIPE's default back.
    return subprocess.Popen(
        [run], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, cwd="/", close_fds=True,
        start_new_session=True, bufsize=0)


def run_filter(run, body, env, *, budget, slots, timeout, cap,
               spawn=_spawn) -> Outcome:
    """Run `run` once over `body` and classify how it ended.

    The output is taken from `budget` as it arrives; on PASSED and REWROTE
    it stays taken, and the caller gives back len(outcome.body) with the
    body's own. `slots` is a semaphore of processes that may run at once.
    """
    t0 = time.monotonic()
    deadline = t0 + timeout

    def done(kind, fields=(), *, out=b"", reason=None, refused=False):
        ms = round((time.monotonic() - t0) * 1000)
        return Outcome(kind, out, reason, tuple(fields), ms, refused)

    if not slots.acquire(timeout=timeout):
        return done(UNAVAILABLE, ("slots=busy",))
    try:
        try:
            proc = spawn(run, env)
        except OSError as exc:
            name = errno.errorcode.get(exc.errno, str(exc.errno))
            kind = (UNAVAILABLE if exc.errno in _SPAWN_UNAVAILABLE
                    else FAILED)
            return done(kind, (f"errno={name}",),
                        refused=exc.errno in _SPAWN_REFUSED)
        pump = _Pump(proc, body, budget, cap)
        try:
            stopped = pump.run(deadline)
        finally:
            _kill_group(proc.pid)
            proc.wait()
            pump.close()
        out = b"".join(pump.out)
        if stopped is not None:
            budget.give(len(out))
            return done(*stopped)
        rc = proc.returncode
        if rc == 0:
            return done(PASSED if out == body else REWROTE, out=out)
        budget.give(len(out))
        if rc == EXIT_REFUSE:
            return done(REFUSED, reason=_reason(bytes(pump.err)))
        if rc in (-signal.SIGKILL, 128 + signal.SIGKILL):
            return done(UNAVAILABLE, ("signal=KILL",))
        if rc < 0:
            return done(FAILED, (f"signal={_signal_name(-rc)}",))
        return done(FAILED, (f"exit={rc}",))
    finally:
        slots.release()


def _reason(stderr):
    line = stderr.split(b"\n", 1)[0].strip()
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        return "unnamed"
    return text if REASON_TOKEN.fullmatch(text) else "unnamed"


def _signal_name(num):
    try:
        return signal.Signals(num).name.removeprefix("SIG")
    except ValueError:
        return str(num)


def _kill_group(pid):
    """SIGKILL the filter's session, which clears anything it left behind.
    Before the wait, so the zombie still holds the group's id."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class _Stop(Exception):
    """The pump ending a run early, with the outcome's kind and fields."""


class _Pump:
    """Writes the body to a filter while reading its stdout and stderr,
    until it exits or a bound is reached.

    The filter's exit is watched through a pidfd, not stdout's EOF, so a
    process it leaves holding stdout open can't hold up the request.
    """

    def __init__(self, proc, body, budget, cap):
        self.proc, self.body, self.budget, self.cap = proc, body, budget, cap
        self.out, self.held, self.err = [], 0, bytearray()
        self.sent = 0
        self.sel = selectors.DefaultSelector()
        self.pidfd = None

    def run(self, deadline):
        """None once the filter has exited, or (kind, fields) if it was
        stopped first."""
        try:
            self.pidfd = os.pidfd_open(self.proc.pid)
            if self.body:
                os.set_blocking(self.proc.stdin.fileno(), False)
                self.sel.register(self.proc.stdin, selectors.EVENT_WRITE)
            else:
                self.proc.stdin.close()
            for f in (self.proc.stdout, self.proc.stderr):
                os.set_blocking(f.fileno(), False)
                self.sel.register(f, selectors.EVENT_READ)
            self.sel.register(self.pidfd, selectors.EVENT_READ)
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return TIMED_OUT, ("timeout",)
                for key, _ in self.sel.select(left):
                    if key.fileobj is self.pidfd:
                        # What it wrote before exiting is in the pipes.
                        self._drain(self.proc.stdout, self._read_out)
                        self._drain(self.proc.stderr, self._read_err)
                        return None
                    if key.fileobj is self.proc.stdin:
                        self._write_in()
                    elif key.fileobj is self.proc.stdout:
                        self._read_out()
                    else:
                        self._read_err()
        except _Stop as stop:
            return stop.args

    def _registered(self, f):
        try:
            self.sel.get_key(f)
        except KeyError:
            return False
        return True

    def _drain(self, f, read):
        while self._registered(f) and read():
            pass

    def _write_in(self):
        f = self.proc.stdin
        try:
            self.sent += os.write(
                f.fileno(),
                memoryview(self.body)[self.sent:self.sent + _PIECE])
        except BlockingIOError:
            return
        except BrokenPipeError:
            self.sent = len(self.body)
        if self.sent == len(self.body):
            self.sel.unregister(f)
            f.close()

    def _read(self, f, n):
        """Up to n bytes, or None when nothing is readable now."""
        try:
            data = os.read(f.fileno(), n)
        except BlockingIOError:
            return None
        if not data:
            self.sel.unregister(f)
        return data

    def _read_out(self):
        """True while there may be more to read now."""
        data = self._read(self.proc.stdout,
                          min(_PIECE, self.cap + 1 - self.held))
        if not data:
            return False
        if not self.budget.take(len(data)):
            raise _Stop(UNAVAILABLE, ("budget=spent",))
        self.out.append(data)
        self.held += len(data)
        if self.held > self.cap:
            raise _Stop(FAILED, ("output=over",))
        return True

    def _read_err(self):
        data = self._read(self.proc.stderr, _PIECE)
        if not data:
            return False
        room = FILTER_STDERR_MAX - len(self.err)
        if room > 0:
            self.err += data[:room]
        return True

    def close(self):
        self.sel.close()
        if self.pidfd is not None:
            os.close(self.pidfd)
        for f in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            f.close()
