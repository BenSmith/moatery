"""Request filters: the document's loader, and run_filter against real
tiny filters written into a temp dir."""

import errno
import json
import os
import tempfile
import threading
import time
import unittest

from moatery.http_request import parse_request
from moatery.inspect_document import (
    NO_REQUEST_FILTERS, RequestFilter, inspect_policy_digest,
)
from moatery.inspect_policy import Policy
from moatery.request_filter import (
    EXIT_REFUSE,
    FAILED,
    FILTER_PATH,
    PASSED,
    REFUSED,
    REWROTE,
    TIMED_OUT,
    UNAVAILABLE,
    Budget,
    filter_env,
    load_request_filters,
    run_filter,
)

POLICY = Policy("inspect", ("*",))

ENV_NAMES = {"MOAT_ID", "MOAT_REQ", "MOAT_HOST", "MOAT_METHOD", "MOAT_PATH",
             "MOAT_CONTENT_TYPE", "MOAT_LENGTH", "PATH"}


class _Dir(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        os.chmod(self.dir, 0o755)
        self.addCleanup(self._tmp.cleanup)

    def script(self, name, text, mode=0o755):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, mode)
        return path


class TestTheDocument(_Dir):

    def setUp(self):
        super().setUp()
        self.run_path = self.script("f", "#!/bin/sh\nexec cat\n")

    def load(self, doc, policy=POLICY):
        text = doc if isinstance(doc, str) else json.dumps(doc)
        path = os.path.join(self.dir, "request-filters.json")
        with open(path, "w") as f:
            f.write(text)
        return load_request_filters(path, policy)

    def refused(self, doc, needle, policy=POLICY):
        with self.assertRaises(ValueError) as cm:
            self.load(doc, policy)
        self.assertIn(needle, str(cm.exception))

    def test_a_good_document_loads_and_matches(self):
        got = self.load({"filters": [
            {"host": "api.example.com", "run": self.run_path},
            {"host": "*.other.example", "run": self.run_path}]})
        self.assertEqual(got.filters[0],
                         RequestFilter("api.example.com", self.run_path))
        self.assertEqual(got.filter_for("API.example.com."), self.run_path)
        self.assertEqual(got.filter_for("a.other.example"), self.run_path)
        self.assertIsNone(got.filter_for("example.com"))
        self.assertEqual(got.summary, "filters=2")

    def test_the_empty_document_filters_nothing(self):
        got = self.load({"filters": []})
        self.assertEqual(got.filters, ())
        self.assertIsNone(got.filter_for("api.example.com"))
        self.assertIsNone(NO_REQUEST_FILTERS.filter_for("api.example.com"))

    def test_the_digest_is_over_the_text(self):
        text = '{"filters": [ ]}\n'
        self.assertEqual(self.load(text).digest, inspect_policy_digest(text))

    def test_an_unknown_key_is_refused_at_each_level(self):
        self.refused({"filters": [], "extra": 1}, "'extra'")
        self.refused({"filters": [{"host": "a", "run": self.run_path,
                                   "timeout": 3}]}, "'timeout'")

    def test_types_are_refused(self):
        for doc, needle in (
                ([], "JSON object"),
                ({}, "'filters' is missing"),
                ({"filters": {}}, "not a list"),
                ({"filters": ["a"]}, "not an object"),
                ({"filters": [{"host": "a"}]}, "'run'"),
                ({"filters": [{"run": self.run_path}]}, "'host'"),
                ({"filters": [{"host": " ", "run": self.run_path}]},
                 "'host'"),
                ({"filters": [{"host": 3, "run": self.run_path}]}, "'host'"),
                ({"filters": [{"host": "a", "run": ""}]}, "'run'")):
            with self.subTest(doc=doc):
                self.refused(doc, needle)

    def test_overlap_with_the_same_run_is_allowed(self):
        got = self.load({"filters": [
            {"host": "*.example.com", "run": self.run_path},
            {"host": "api.example.com", "run": self.run_path}]})
        self.assertEqual(len(got.filters), 2)

    def test_overlap_with_a_different_run_is_refused_naming_both(self):
        other = self.script("g", "#!/bin/sh\nexec cat\n")
        self.refused({"filters": [
            {"host": "*.example.com", "run": self.run_path},
            {"host": "api.example.com", "run": other}]},
            "'*.example.com' and 'api.example.com'")

    def test_a_star_overlaps_every_name(self):
        other = self.script("g", "#!/bin/sh\nexec cat\n")
        self.refused({"filters": [
            {"host": "api.example.com", "run": self.run_path},
            {"host": "*", "run": other}]}, "overlap")

    def test_overlap_with_a_splice_entry_is_refused(self):
        policy = Policy("inspect", (), splice=("*.example.com",))
        self.refused({"filters": [
            {"host": "api.example.com", "run": self.run_path}]},
            "'splice' entry '*.example.com'", policy)

    def test_tls_splice_refuses_any_filter_and_admits_none(self):
        policy = Policy("splice", ("*",))
        self.refused({"filters": [
            {"host": "api.example.com", "run": self.run_path}]},
            "tls 'splice'", policy)
        self.assertEqual(self.load({"filters": []}, policy).filters, ())

    def test_each_run_refusal(self):
        not_exec = self.script("n", "#!/bin/sh\n", 0o644)
        group = self.script("gw", "#!/bin/sh\n", 0o775)
        world = self.script("ww", "#!/bin/sh\n", 0o757)
        for run, needle in (
                ("f", "not an absolute path"),
                (os.path.join(self.dir, "missing"), "No such file"),
                (self.dir, "not a regular file"),
                (not_exec, "not executable"),
                (group, "group- or world-writable"),
                (world, "group- or world-writable")):
            with self.subTest(run=run):
                self.refused({"filters": [{"host": "a", "run": run}]},
                             needle)

    def test_a_link_to_a_good_file_is_allowed(self):
        link = os.path.join(self.dir, "link")
        os.symlink(self.run_path, link)
        got = self.load({"filters": [{"host": "a", "run": link}]})
        self.assertEqual(got.filter_for("a"), link)


def _req(head=b"POST /v1/x?q=secret HTTP/1.1\r\nHost: api.example.com\r\n"
              b"Content-Type: application/json\r\n"
              b"Authorization: Bearer no\r\nContent-Length: 5\r\n\r\n"):
    return parse_request(head)


class _Runs(_Dir):

    def go(self, run, body=b"hello", *, budget=None, slots=None,
           timeout=5.0, cap=1 << 20, **kw):
        self.budget = budget or Budget(1 << 30)
        return run_filter(
            run, body, filter_env(7, 3, _req(), len(body)),
            budget=self.budget, slots=slots or threading.BoundedSemaphore(8),
            timeout=timeout, cap=cap, **kw)


class TestTheEnvironment(_Runs):

    def test_filter_env_is_exactly_the_eight_names(self):
        env = filter_env(7, 3, _req(), 5)
        self.assertEqual(set(env), ENV_NAMES)
        self.assertEqual(env, {
            "MOAT_ID": "7", "MOAT_REQ": "3",
            "MOAT_HOST": "api.example.com", "MOAT_METHOD": "POST",
            "MOAT_PATH": "/v1/x", "MOAT_CONTENT_TYPE": "application/json",
            "MOAT_LENGTH": "5", "PATH": FILTER_PATH})

    def test_the_filter_process(self):
        """Its environment, cwd, argv, descriptors, session and signal
        dispositions, as the filter itself sees them."""
        probe = self.script("probe", """#!/usr/bin/python3
import json, os, sys
sys.stdin.buffer.read()
fds = []
for fd in range(256):
    try:
        os.fstat(fd)
    except OSError:
        continue
    fds.append(fd)
with open("/proc/self/environ", "rb") as f:
    environ = f.read()
json.dump({"environ": environ.decode(), "cwd": os.getcwd(),
           "argv": sys.argv, "fds": fds,
           "sid": os.getsid(0) == os.getpid()}, sys.stdout)
""")
        held = os.open("/dev/null", os.O_RDONLY)
        self.addCleanup(os.close, held)
        os.set_inheritable(held, True)
        self.assertLess(held, 256)
        out = self.go(probe)
        self.assertEqual(out.kind, REWROTE, out)
        got = json.loads(out.body)
        environ = dict(kv.split("=", 1)
                       for kv in got["environ"].split("\0") if kv)
        self.assertEqual(environ, filter_env(7, 3, _req(), 5))
        self.assertEqual(got["cwd"], "/")
        self.assertEqual(got["argv"], [probe])
        self.assertEqual(got["fds"], [0, 1, 2])
        self.assertTrue(got["sid"])

    def test_the_filter_starts_with_sigpipe_at_its_default(self):
        """Read by a shell's exec, since python3 sets its own at start."""
        out = self.go(self.script(
            "sig", "#!/bin/sh\nexec grep SigIgn /proc/self/status\n"))
        sigign = int(out.body.split()[1], 16)
        with open("/proc/self/status") as f:
            ours = next(int(line.split()[1], 16) for line in f
                        if line.startswith("SigIgn"))
        # SIGPIPE and SIGXFSZ, which this interpreter ignores and the
        # child gets back. Anything the test runner inherited stays.
        restored = (1 << 12) | (1 << 24)
        self.assertEqual(sigign, ours & ~restored)
        self.assertFalse(sigign & (1 << 12))


class TestTheRoundTrip(_Runs):

    def test_cat_passes_and_its_output_stays_taken(self):
        out = self.go(self.script("cat", "#!/bin/sh\nexec cat\n"))
        self.assertEqual((out.kind, out.body), (PASSED, b"hello"))
        self.assertEqual(out.fields, ())
        self.assertIsNone(out.reason)
        self.assertEqual(self.budget.used, 5)

    def test_a_fixed_output_is_rewrote(self):
        out = self.go(self.script(
            "fixed", "#!/bin/sh\ncat >/dev/null\nprintf MARK\n"))
        self.assertEqual((out.kind, out.body), (REWROTE, b"MARK"))

    def test_an_empty_output_is_rewrote(self):
        out = self.go(self.script("empty", "#!/bin/sh\ncat >/dev/null\n"))
        self.assertEqual((out.kind, out.body), (REWROTE, b""))

    def test_an_empty_body_reaches_the_filter_as_eof(self):
        out = self.go(self.script("cat", "#!/bin/sh\nexec cat\n"), b"")
        self.assertEqual((out.kind, out.body), (PASSED, b""))


class TestARefusal(_Runs):

    def refuse(self, stderr):
        return self.go(self.script("r", "#!/bin/sh\ncat >/dev/null\n"
                                   f"{stderr}\nexit {EXIT_REFUSE}\n"))

    def test_a_token_is_the_reason(self):
        out = self.refuse("printf 'not-json\\nmore\\n' >&2")
        self.assertEqual((out.kind, out.reason), (REFUSED, "not-json"))
        self.assertEqual(out.body, b"")
        self.assertEqual(self.budget.used, 0)

    def test_a_reason_that_is_not_a_token_is_unnamed(self):
        for stderr in ("echo 'Not A Token' >&2",
                       "printf '%065d\\n' 0 >&2",
                       "printf 'caf\\303\\251\\n' >&2"):
            with self.subTest(stderr):
                self.assertEqual(self.refuse(stderr).reason, "unnamed")

    def test_no_stderr_is_unnamed(self):
        self.assertEqual(self.refuse(":").reason, "unnamed")


class TestEveryOtherRow(_Runs):

    def row(self, text, **kw):
        out = self.go(self.script("f", text), **kw)
        self.assertEqual(out.body, b"")
        return out.kind, out.fields

    def test_exit_codes(self):
        for code in (1, 3, 139):
            with self.subTest(code):
                self.assertEqual(
                    self.row(f"#!/bin/sh\nprintf out\nexit {code}\n"),
                    (FAILED, (f"exit={code}",)))
                self.assertEqual(self.budget.used, 0)

    def test_signals_it_sends_itself(self):
        for sig, want in (("SEGV", (FAILED, ("signal=SEGV",))),
                          ("ABRT", (FAILED, ("signal=ABRT",))),
                          ("KILL", (UNAVAILABLE, ("signal=KILL",)))):
            with self.subTest(sig):
                self.assertEqual(self.row(
                    "#!/usr/bin/python3\nimport os, resource, signal\n"
                    "resource.setrlimit(resource.RLIMIT_CORE, (0, 0))\n"
                    f"os.kill(os.getpid(), signal.SIG{sig})\n"), want)

    def test_a_kill_through_a_wrapper_is_unavailable(self):
        self.assertEqual(self.row("#!/bin/sh\nexit 137\n"),
                         (UNAVAILABLE, ("signal=KILL",)))

    def test_the_deadline(self):
        t0 = time.monotonic()
        self.assertEqual(self.row("#!/bin/sh\nexec sleep 5\n", timeout=0.2),
                         (TIMED_OUT, ("timeout",)))
        self.assertLess(time.monotonic() - t0, 2)

    def test_output_past_the_cap(self):
        self.assertEqual(
            self.row("#!/usr/bin/python3\nimport sys\n"
                     "sys.stdout.buffer.write(b'x' * 2048)\n", cap=1024),
            (FAILED, ("output=over",)))
        self.assertEqual(self.budget.used, 0)

    def test_a_run_deleted_after_load(self):
        path = self.script("gone", "#!/bin/sh\n")
        os.unlink(path)
        out = self.go(path)
        self.assertEqual((out.kind, out.fields, out.spawn_refused),
                         (FAILED, ("errno=ENOENT",), True))

    def test_a_run_that_is_not_an_executable_format(self):
        out = self.go(self.script("noexec", "no shebang\n"))
        self.assertEqual((out.kind, out.fields, out.spawn_refused),
                         (FAILED, ("errno=ENOEXEC",), True))

    def test_spawn_errors_from_an_injected_spawner(self):
        for code in (errno.ETXTBSY, errno.EAGAIN, errno.ENOMEM, errno.EIO):
            def spawn(run, env, code=code):
                raise OSError(code, os.strerror(code))
            with self.subTest(errno.errorcode[code]):
                out = self.go("/nonexistent", spawn=spawn)
                want = FAILED if code == errno.EIO else UNAVAILABLE
                self.assertEqual(
                    (out.kind, out.fields, out.spawn_refused),
                    (want, (f"errno={errno.errorcode[code]}",), False))


class TestBounds(_Runs):

    def test_yes_ends_at_the_cap_with_the_budget_given_back(self):
        taken = []
        budget = Budget(1 << 30)
        take = budget.take
        budget.take = lambda n: taken.append(n) or take(n)
        t0 = time.monotonic()
        out = self.go(self.script("yes", "#!/bin/sh\nexec yes\n"), cap=1024,
                      budget=budget)
        self.assertEqual((out.kind, out.fields), (FAILED, ("output=over",)))
        self.assertEqual(sum(taken), 1025)
        self.assertEqual(budget.used, 0)
        self.assertLess(time.monotonic() - t0, 2)

    def test_a_filter_that_never_reads_stdin_does_not_deadlock(self):
        out = self.go(self.script(
            "w", "#!/usr/bin/python3\nimport sys\n"
            "sys.stdout.buffer.write(b'y' * (1 << 20))\n"),
            b"x" * (1 << 20), timeout=5)
        self.assertEqual((out.kind, len(out.body)), (REWROTE, 1 << 20))

    def test_a_child_holding_stdout_does_not_hold_up_the_request(self):
        t0 = time.monotonic()
        out = self.go(self.script(
            "bg", "#!/bin/sh\ncat\nsleep 30 &\nexit 0\n"))
        self.assertEqual((out.kind, out.body), (PASSED, b"hello"))
        self.assertLess(time.monotonic() - t0, 1)

    def test_no_slot_free_is_unavailable(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        self.addCleanup(slots.release)
        out = self.go(self.script("cat", "#!/bin/sh\nexec cat\n"),
                      slots=slots, timeout=0.1)
        self.assertEqual((out.kind, out.fields),
                         (UNAVAILABLE, ("slots=busy",)))

    def test_a_slot_is_released_every_way(self):
        slots = threading.BoundedSemaphore(1)
        for text in ("#!/bin/sh\nexec cat\n", "#!/bin/sh\nexit 77\n"):
            self.go(self.script("f", text), slots=slots)
        self.go("/nonexistent", slots=slots)
        self.assertTrue(slots.acquire(blocking=False))

    def test_a_full_budget_is_unavailable(self):
        budget = Budget(10)
        self.assertTrue(budget.take(10))
        out = self.go(self.script("cat", "#!/bin/sh\nexec cat\n"),
                      budget=budget)
        self.assertEqual((out.kind, out.fields),
                         (UNAVAILABLE, ("budget=spent",)))
        self.assertEqual(budget.used, 10)

    def test_the_deadline_kill_reaches_the_group(self):
        pidfile = os.path.join(self.dir, "pid")
        out = self.go(self.script(
            "fork", f"#!/bin/sh\nsleep 30 &\necho $! > {pidfile}.new\n"
            f"mv {pidfile}.new {pidfile}\nexec sleep 30\n"), timeout=1.0)
        self.assertEqual(out.kind, TIMED_OUT)
        with open(pidfile) as f:
            pid = int(f.read())
        # Generous: a killed process on a loaded host can take a while to
        # be seen gone.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and _alive(pid):
            time.sleep(0.02)
        self.assertFalse(_alive(pid), f"sleeper {pid} outlived the kill: "
                         + _describe(pid))


def _alive(pid):
    """Running, not a zombie waiting for init to reap it."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            state = f.read().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"


def _describe(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            stat_line = f.read()
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return stat_line + repr(f.read())
    except OSError as exc:
        return str(exc)


class TestBudget(unittest.TestCase):

    def test_take_and_give(self):
        budget = Budget(10)
        self.assertTrue(budget.take(6))
        self.assertFalse(budget.take(5))
        budget.give(6)
        self.assertTrue(budget.take(10))
        self.assertEqual(budget.used, 10)


if __name__ == "__main__":
    unittest.main()
