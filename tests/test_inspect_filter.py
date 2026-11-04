"""moat-inspect: a request filter on the inspector's path.

Real sockets on both legs and real filter programs: the guest on a
socketpair through serve_cleartext, a plain HTTP origin (and a broker on a
unix socket) recording every byte it reads, and filters written as tiny
shell scripts. The listener's reload of the policy and the filters as a
pair, and moat-inspect's flag, are here too.
"""

import contextlib
import io
import json
import shutil
import signal
import socket
import tempfile
import threading
import unittest
import unittest.mock
import uuid
from pathlib import Path

from tests import load_script
from moatery import egress_relay, inspect_http
from moatery.egress_record import (
    DROP_FILTER_FAILED, DROP_FILTER_REFUSED, DROP_FILTER_TIMED_OUT,
    DROP_FILTER_UNAVAILABLE, DROP_NOT_FILTERABLE, DROP_TIMED_OUT,
    DROP_UNREADABLE_REQUEST, LOG_ID_FIELD, Where,
)
from moatery.inspect_document import (
    RequestFilter, RequestFilters, VmPolicyEntry, inspect_policy_digest,
)
from moatery.inspect_http import serve_cleartext
from moatery.inspect_listener import Listener
from moatery.inspect_policy import Policy
from moatery.inspect_scope import Inspection
from moatery.request_filter import (
    REQUEST_FILTERS_DIGEST_KEY, Budget, load_request_filters,
)


FILTERED = "api.example"
PLAIN = "plain.example"
BROKERED = "brokered.example"

_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
_REAL_CREATE_CONNECTION = socket.create_connection


def _tmpdir(case):
    d = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return Path(d)


def _script(d, name, body):
    path = Path(d, name)
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return str(path)


def _post(host, body, *, extra=b"", chunked=False):
    if chunked:
        framed = b"".join(b"%x\r\n%s\r\n" % (len(p), p)
                          for p in (body[:3], body[3:]) if p)
        framed += b"0\r\nx-trailer: t\r\n\r\n"
        framing = b"Transfer-Encoding: chunked\r\n"
    else:
        framed = body
        framing = b"Content-Length: %d\r\n" % len(body)
    return (b"POST /v1/things?q=1 HTTP/1.1\r\nHost: " + host.encode()
            + b"\r\nContent-Type: application/json\r\n" + framing + extra
            + b"\r\n" + framed)


class _Origin:
    """A plain HTTP/1.1 origin, on loopback or a unix socket, answering
    every request 200 and keeping each one's raw head and body."""

    def __init__(self, unix_path=None):
        if unix_path is None:
            self.sock = socket.socket()
            self.sock.bind(("127.0.0.1", 0))
        else:
            self.sock = socket.socket(socket.AF_UNIX)
            self.sock.bind(unix_path)
        self.sock.listen(8)
        self.connections = 0
        self.requests = []
        self._lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.sock.close()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with self._lock:
                self.connections += 1
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(5.0)
        buf = b""

        def fill():
            nonlocal buf
            data = conn.recv(65536)
            if not data:
                raise EOFError
            buf += data

        def take(n):
            nonlocal buf
            while len(buf) < n:
                fill()
            out, buf = buf[:n], buf[n:]
            return out

        def line():
            nonlocal buf
            while b"\r\n" not in buf:
                fill()
            out, _, buf = buf.partition(b"\r\n")
            return out

        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    fill()
                head, _, buf = buf.partition(b"\r\n\r\n")
                headers = {}
                for ln in head.split(b"\r\n")[1:]:
                    name, _, value = ln.partition(b":")
                    headers[name.strip().lower()] = value.strip()
                body = b""
                if b"content-length" in headers:
                    body = take(int(headers[b"content-length"]))
                elif headers.get(b"transfer-encoding") == b"chunked":
                    while True:
                        size = int(line().split(b";")[0], 16)
                        body += take(size + 2)
                        if size == 0:
                            break
                with self._lock:
                    self.requests.append((head + b"\r\n\r\n", body))
                conn.sendall(_OK)
        except (EOFError, OSError):
            pass
        finally:
            conn.close()


class _FilterRig(unittest.TestCase):
    """One guest connection through the cleartext plane, with the filters
    this test writes."""

    def setUp(self):
        self.dir = _tmpdir(self)
        self.origin = _Origin()
        self.addCleanup(self.origin.close)
        self.broker = _Origin(str(self.dir / "broker.sock"))
        self.addCleanup(self.broker.close)
        for name, value in (("RELAY_IDLE_TIMEOUT", 2.0),
                            ("CONNECTION_TIMEOUT", 2.0)):
            patcher = unittest.mock.patch.object(egress_relay, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def policy(self, run, *, host=FILTERED):
        filters = (RequestFilters((RequestFilter(host, run),), "d" * 64)
                   if run is not None else RequestFilters((), ""))
        return Policy(tls="inspect", hosts=(FILTERED, PLAIN),
                      policy=(VmPolicyEntry(BROKERED, None, None,
                                            credential="example"),),
                      request_filters=filters)

    def inspection(self, policy):
        out = io.StringIO()
        insp = Inspection(policy, out=out,
                          record_path=str(self.dir / "requests.log"),
                          broker_endpoint=str(self.dir / "broker.sock"))
        self.addCleanup(insp.record.close)
        return insp

    def exchange(self, insp, payload, *, shut=True):
        """The guest's whole answer to `payload`, after which the budget
        must be whole again. `shut=False` leaves the guest's side open."""
        ours, guest = socket.socketpair()
        self.addCleanup(guest.close)
        guest.settimeout(10.0)
        port = self.origin.sock.getsockname()[1]

        def dial(addr, timeout=None, *args):
            return _REAL_CREATE_CONNECTION(("127.0.0.1", port), timeout)

        def serve():
            try:
                with unittest.mock.patch.object(
                        socket, "create_connection", side_effect=dial):
                    serve_cleartext(
                        insp, ours,
                        Where(f"{LOG_ID_FIELD}=c0ffee plane=cleartext",
                              cid="c0ffee", plane="cleartext"))
            finally:
                ours.close()

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        guest.sendall(payload)
        if shut:
            guest.shutdown(socket.SHUT_WR)
        answer = b""
        while True:
            data = guest.recv(65536)
            if not data:
                break
            answer += data
        server.join(15)
        self.assertFalse(server.is_alive())
        self.assertEqual(insp.filter_budget.used, 0,
                         "the body budget was not given back")
        return answer

    def records(self):
        with open(self.dir / "requests.log") as f:
            return [json.loads(line) for line in f]

    def assert_nothing_sent(self):
        self.assertEqual(self.origin.connections, 0,
                         "the origin was dialled")
        self.assertEqual(self.origin.requests, [])
        self.assertEqual(self.broker.connections, 0,
                         "the broker was dialled")

    def _refused(self, insp, payload, status, reason, *, shut=True):
        answer = self.exchange(insp, payload, shut=shut)
        if status is None:
            self.assertEqual(answer, b"")
        else:
            self.assertTrue(answer.startswith(b"HTTP/1.1 %d " % status),
                            answer)
        self.assert_nothing_sent()
        rec = self.records()[0]
        self.assertEqual((rec["decision"], rec["reason"], rec["status"]),
                         ("drop", reason, status))
        snap = insp.counters.snapshot(open_now=0, refused=0)
        self.assertEqual(snap["drop_reasons"][reason], 1)
        self.assertEqual(snap["dispositions"]["dropped"], 1)
        self.assertEqual(snap["filtered"], {"passed": 0, "rewrote": 0})
        return answer, rec, insp.out.getvalue()


class TestTheFilteredBodyGoesUp(_FilterRig):

    def test_the_origin_receives_the_filters_bytes(self):
        """The wiring test: a mark no input can equal, written by the
        filter, is what the origin reads, framed by its own length.

        Broken on purpose both ways and seen red: filter_for's call in
        serve_request replaced with None (the guest's chunked body went
        up), and copy_body kept for the send (the held body was read from
        a guest with nothing left, and the request failed)."""
        mark = f"MOATERY-FILTER-MARK-{uuid.uuid4()}".encode()
        run = _script(self.dir, "mark",
                      f"cat >/dev/null\nprintf '%s' '{mark.decode()}'\n")
        insp = self.inspection(self.policy(run))
        answer = self.exchange(
            insp, _post(FILTERED, b'{"a": 1}', chunked=True))
        self.assertTrue(answer.startswith(b"HTTP/1.1 200"), answer)
        self.assertEqual(len(self.origin.requests), 1)
        head, body = self.origin.requests[0]
        self.assertEqual(body, mark)
        self.assertIn(b"Content-Length: %d\r\n" % len(mark), head)
        self.assertNotIn(b"transfer-encoding", head.lower())

    def test_a_chunked_body_is_decoded_and_expect_gets_one_100(self):
        run = _script(self.dir, "cat", "exec cat\n")
        insp = self.inspection(self.policy(run))
        answer = self.exchange(insp, _post(
            FILTERED, b'{"chunked": true}', chunked=True,
            extra=b"Expect: 100-continue\r\n"))
        self.assertEqual(answer.count(b"100 Continue"), 1, answer)
        self.assertIn(b"200 OK", answer)
        self.assertEqual(self.origin.requests[0][1], b'{"chunked": true}')
        self.assertNotIn(b"expect", self.origin.requests[0][0].lower())

    def test_the_filter_is_given_the_request_it_judges(self):
        run = _script(self.dir, "env",
                      "cat >/dev/null\nprintf '%s %s %s %s %s' "
                      "\"$MOAT_ID\" \"$MOAT_REQ\" \"$MOAT_HOST\" "
                      "\"$MOAT_PATH\" \"$MOAT_LENGTH\"\n")
        insp = self.inspection(self.policy(run))
        self.exchange(insp, _post(FILTERED, b"12345"))
        self.assertEqual(self.origin.requests[0][1],
                         b"c0ffee 1 api.example /v1/things 5")

    def test_the_record_journal_and_counters_say_what_it_did(self):
        same = _script(self.dir, "cat", "exec cat\n")
        insp = self.inspection(self.policy(same))
        self.exchange(insp, _post(FILTERED, b"same") * 2)
        rec = self.records()
        self.assertEqual([r["filter"] for r in rec], ["passed"] * 2)
        self.assertIsInstance(rec[0]["filter_ms"], int)
        journal = insp.out.getvalue()
        self.assertIn("filter=passed filter_ms=", journal)
        snap = insp.counters.snapshot(open_now=0, refused=0)
        self.assertEqual(snap["filtered"], {"passed": 2, "rewrote": 0})
        self.assertEqual(snap["dispositions"]["forwarded"], 2)

    def test_a_rewrite_is_counted_as_one(self):
        run = _script(self.dir, "upper", "tr a-z A-Z\n")
        insp = self.inspection(self.policy(run))
        self.exchange(insp, _post(FILTERED, b"shout"))
        self.assertEqual(self.origin.requests[0][1], b"SHOUT")
        self.assertEqual(self.records()[0]["filter"], "rewrote")
        self.assertIn("filter=rewrote", insp.out.getvalue())
        snap = insp.counters.snapshot(open_now=0, refused=0)
        self.assertEqual(snap["filtered"], {"passed": 0, "rewrote": 1})

    def test_a_brokered_host_sends_the_broker_the_filtered_body(self):
        run = _script(self.dir, "upper", "tr a-z A-Z\n")
        insp = self.inspection(self.policy(run, host=BROKERED))
        answer = self.exchange(insp, _post(BROKERED, b"key me"))
        self.assertIn(b"200 OK", answer)
        self.assertEqual(self.broker.requests[0][1], b"KEY ME")
        self.assertEqual(self.origin.connections, 0)
        self.assertEqual(self.records()[0]["credential"], "example")

    def test_an_unfiltered_host_goes_up_byte_for_byte_as_before(self):
        run = _script(self.dir, "upper", "tr a-z A-Z\n")
        payload = _post(PLAIN, b"lower", chunked=True)
        self.exchange(self.inspection(self.policy(None)), payload)
        self.exchange(self.inspection(self.policy(run)), payload)
        self.assertEqual(len(self.origin.requests), 2)
        self.assertEqual(self.origin.requests[0], self.origin.requests[1])
        self.assertIsNone(self.records()[1]["filter"])

    def test_a_request_with_no_body_is_not_filtered(self):
        ran = self.dir / "ran"
        run = _script(self.dir, "touch", f"touch '{ran}'\nexec cat\n")
        insp = self.inspection(self.policy(run))
        answer = self.exchange(
            insp,
            b"GET / HTTP/1.1\r\nHost: api.example\r\n\r\n"
            + _post(FILTERED, b""))
        self.assertEqual(answer.count(b"200 OK"), 2)
        self.assertFalse(ran.exists(), "the filter ran on a bodyless request")
        self.assertEqual(len(self.origin.requests), 2)
        self.assertEqual([r["filter"] for r in self.records()], [None] * 2)


class TestNothingGoesUpUnlessTheFilterPasses(_FilterRig):

    def test_every_outcome_gets_its_status_and_sends_nothing(self):
        canary = f"CANARY-{uuid.uuid4()}"
        cases = (
            ("refuse", "cat >/dev/null\necho not-json >&2\nexit 77\n",
             403, DROP_FILTER_REFUSED, "filter_reason=not-json"),
            ("unnamed", "cat >/dev/null\necho 'Not A Token' >&2\nexit 77\n",
             403, DROP_FILTER_REFUSED, "filter_reason=unnamed"),
            ("exit3", f"cat >/dev/null\necho {canary} >&2\nexit 3\n",
             502, DROP_FILTER_FAILED, "exit=3"),
            ("segv", f"echo {canary} >&2\nkill -SEGV $$\n",
             502, DROP_FILTER_FAILED, "signal=SEGV"),
            ("over", "yes\n", 502, DROP_FILTER_FAILED, "output=over"),
            ("killed", "kill -KILL $$\n",
             503, DROP_FILTER_UNAVAILABLE, "signal=KILL"),
        )
        for name, body, status, reason, field in cases:
            with self.subTest(name):
                self.setUp()
                run = _script(self.dir, name, body)
                insp = self.inspection(self.policy(run))
                with unittest.mock.patch.object(
                        inspect_http, "FILTER_BODY_MAX", 4096):
                    _, rec, journal = self._refused(
                        insp, _post(FILTERED, b'{"a": 1}'), status, reason)
                self.assertIn(field, journal)
                self.assertNotIn(canary, journal)
                self.assertNotIn(canary, json.dumps(rec))
                self.assertEqual(rec["filter"],
                                 "refused" if status == 403 else None)
                self.assertIsInstance(rec["filter_ms"], int)

    def test_a_filter_past_its_deadline_is_504(self):
        run = _script(self.dir, "slow", "exec sleep 5\n")
        insp = self.inspection(self.policy(run))
        with unittest.mock.patch.object(inspect_http, "FILTER_TIMEOUT", 0.3):
            self._refused(insp, _post(FILTERED, b"x"), 504,
                          DROP_FILTER_TIMED_OUT)

    def test_no_free_slot_is_503_and_keeps_the_connection(self):
        run = _script(self.dir, "cat", "exec cat\n")
        insp = self.inspection(self.policy(run))
        insp.filter_slots = threading.BoundedSemaphore(1)
        insp.filter_slots.acquire()
        with unittest.mock.patch.object(inspect_http, "FILTER_TIMEOUT", 0.2):
            answer, _, journal = self._refused(
                insp, _post(FILTERED, b"x"), 503, DROP_FILTER_UNAVAILABLE)
        self.assertIn("slots=busy", journal)
        self.assertIn(b"Connection: keep-alive", answer)

    def test_a_spent_budget_is_503_and_closes(self):
        run = _script(self.dir, "cat", "exec cat\n")
        insp = self.inspection(self.policy(run))
        insp.filter_budget = Budget(3)
        answer, _, journal = self._refused(
            insp, _post(FILTERED, b"four"), 503, DROP_FILTER_UNAVAILABLE)
        self.assertIn("budget=spent", journal)
        self.assertIn(b"Connection: close", answer)

    def test_a_run_that_cannot_be_execd_warns_once_per_document(self):
        run = str(self.dir / "gone")
        insp = self.inspection(self.policy(run))
        answer = self.exchange(insp, _post(FILTERED, b"a") * 2)
        self.assertEqual(answer.count(b"502 Bad Gateway"), 2)
        self.assert_nothing_sent()
        journal = insp.out.getvalue()
        self.assertEqual(journal.count(
            f"WARNING: request filter {run} cannot be run (ENOENT)"), 1)
        self.assertEqual(journal.count("errno=ENOENT"), 2)

    def test_a_second_request_after_a_refusal_works(self):
        run = _script(self.dir, "refuse", "cat >/dev/null\nexit 77\n")
        insp = self.inspection(self.policy(run))
        answer = self.exchange(
            insp, _post(FILTERED, b"no") + _post(PLAIN, b"yes"))
        self.assertTrue(answer.startswith(b"HTTP/1.1 403 "), answer)
        self.assertIn(b"200 OK", answer)
        self.assertEqual([b for _, b in self.origin.requests], [b"yes"])

    def test_an_upgrade_is_403(self):
        run = _script(self.dir, "cat", "exec cat\n")
        self._refused(
            self.inspection(self.policy(run)),
            b"GET /ws HTTP/1.1\r\nHost: api.example\r\nConnection: upgrade"
            b"\r\nUpgrade: websocket\r\n\r\n", 403, DROP_NOT_FILTERABLE)

    def test_an_encoded_body_is_415(self):
        run = _script(self.dir, "cat", "exec cat\n")
        self._refused(
            self.inspection(self.policy(run)),
            _post(FILTERED, b"\x1f\x8b", extra=b"Content-Encoding: gzip\r\n"),
            415, DROP_NOT_FILTERABLE)

    def test_a_declared_length_over_the_cap_is_413(self):
        run = _script(self.dir, "cat", "exec cat\n")
        answer, _, _ = self._refused(
            self.inspection(self.policy(run)),
            b"POST / HTTP/1.1\r\nHost: api.example\r\n"
            b"Content-Length: %d\r\n\r\n" % (65 << 20),
            413, DROP_NOT_FILTERABLE)

    def test_a_chunked_body_over_the_cap_is_413_and_closes(self):
        run = _script(self.dir, "cat", "exec cat\n")
        insp = self.inspection(self.policy(run))
        with unittest.mock.patch.object(inspect_http, "FILTER_BODY_MAX", 8):
            answer, _, _ = self._refused(
                insp, _post(FILTERED, b"0123456789", chunked=True)
                + _post(PLAIN, b"never read"), 413, DROP_NOT_FILTERABLE)
        self.assertIn(b"Connection: close", answer)
        self.assertEqual(answer.count(b"HTTP/1.1 "), 1)


class TestABodyNotReadWhole(_FilterRig):
    """The filter never runs on part of a body."""

    def setUp(self):
        super().setUp()
        self.ran = self.dir / "ran"
        self.run = _script(self.dir, "touch",
                           f"touch '{self.ran}'\nexec cat\n")

    def _cut(self):
        return _post(FILTERED, b"0123456789")[:-7]

    def test_a_body_cut_short_is_unreadable(self):
        self._refused(self.inspection(self.policy(self.run)), self._cut(),
                      400, DROP_UNREADABLE_REQUEST)
        self.assertFalse(self.ran.exists())

    def test_a_body_that_stops_arriving_times_out(self):
        with unittest.mock.patch.object(
                egress_relay, "RELAY_IDLE_TIMEOUT", 0.3):
            self._refused(self.inspection(self.policy(self.run)),
                          self._cut(), None, DROP_TIMED_OUT, shut=False)
        self.assertFalse(self.ran.exists())


class TestTheFiltersReloadWithThePolicy(unittest.TestCase):
    """SIGUSR1 swaps the policy and the filter document as a pair, or
    neither, and the status file names what is enforced."""

    def setUp(self):
        self.dir = _tmpdir(self)
        self.run_a = _script(self.dir, "a", "exec cat\n")
        self.run_b = _script(self.dir, "b", "exec cat\n")
        self.policy_path = self.dir / "policy.json"
        self.filters_path = self.dir / "filters.json"
        self.status = self.dir / "status.json"
        self.write_policy({"hosts": [FILTERED]})
        self.write_filters(self.run_a)
        policy = Policy(tls="inspect", hosts=(FILTERED,))
        policy = policy._replace(request_filters=load_request_filters(
            self.filters_path, policy))
        self.listener = Listener(
            [], io.StringIO(), policy=policy, status_path=str(self.status),
            policy_path=str(self.policy_path),
            request_filters_path=str(self.filters_path))

    def write_policy(self, doc):
        self.policy_path.write_text(json.dumps({"tls": "inspect", **doc}))

    def write_filters(self, run, host=FILTERED):
        self.filters_path.write_text(json.dumps(
            {"filters": [{"host": host, "run": run}]}))

    def enforced(self):
        self.listener.reload_policy()
        policy = self.listener.inspection.policy
        status = json.loads(self.status.read_text())
        self.assertEqual(status[REQUEST_FILTERS_DIGEST_KEY],
                         policy.request_filters.digest)
        self.assertEqual(status["lists"]["request_filters"],
                         [{"host": f.host, "run": f.run,
                           "spliced": list(f.spliced)}
                          for f in policy.request_filters.filters])
        return policy

    def test_a_good_pair_swaps_both(self):
        self.write_policy({"hosts": [FILTERED, PLAIN]})
        self.write_filters(self.run_b)
        policy = self.enforced()
        self.assertEqual(policy.hosts, (FILTERED, PLAIN))
        self.assertEqual(policy.request_filters.filter_for(FILTERED),
                         self.run_b)
        self.assertEqual(policy.request_filters.digest,
                         inspect_policy_digest(self.filters_path.read_text()))
        self.assertIn(f"request filters reloaded from {self.filters_path}: "
                      f"filters=1", self.listener.inspection.out.getvalue())

    def _kept(self):
        before = self.listener.inspection.policy
        policy = self.enforced()
        self.assertIs(policy, before)
        self.assertIn("WARNING: policy not reloaded",
                      self.listener.inspection.out.getvalue())
        return self.listener.inspection.out.getvalue()

    def test_bad_filters_keep_both(self):
        self.write_policy({"hosts": [FILTERED, PLAIN]})
        self.filters_path.write_text('{"filters": [], "extra": 1}')
        self.assertIn(str(self.filters_path), self._kept())

    def test_unparseable_filters_name_their_file(self):
        self.write_policy({"hosts": [FILTERED, PLAIN]})
        self.filters_path.write_text("{")
        self.assertIn(str(self.filters_path), self._kept())

    def test_a_bad_policy_keeps_both(self):
        self.write_filters(self.run_b)
        self.policy_path.write_text('{"tls": "inspect", "hosts": "x"}')
        self._kept()

    def test_a_policy_splicing_a_filtered_host_is_refused(self):
        self.write_policy({"hosts": [FILTERED], "splice": ["*.example"]})
        self.assertIn("splice", self._kept())

    def test_a_policy_splicing_part_of_a_filter_is_enforced_and_named(self):
        """The reload that leaves a host unfiltered says so in its line and
        the status file."""
        self.write_filters(self.run_b, host="*")
        self.write_policy({"hosts": ["*"], "splice": ["updates.example"]})
        policy = self.enforced()
        self.assertEqual(policy.splice, ("updates.example",))
        self.assertEqual(policy.request_filters.filters[0].spliced,
                         ("updates.example",))
        self.assertIn(f"request filters reloaded from {self.filters_path}: "
                      f"filters=1 spliced=updates.example",
                      self.listener.inspection.out.getvalue())


class TestTheFlag(unittest.TestCase):
    """moat-inspect --request-filters: read at start beside the policy,
    and handed to the listener for its reloads."""

    def setUp(self):
        self.dir = _tmpdir(self)
        self.policy = self.dir / "policy.json"
        self.policy.write_text('{"tls": "inspect", "hosts": ["api.example"]}')
        self.filters = self.dir / "filters.json"
        run = _script(self.dir, "cat", "exec cat\n")
        self.filters.write_text(json.dumps(
            {"filters": [{"host": FILTERED, "run": run}]}))
        saved = {s: signal.getsignal(s)
                 for s in (signal.SIGHUP, signal.SIGTERM, signal.SIGUSR1)}
        self.addCleanup(
            lambda: [signal.signal(s, h) for s, h in saved.items()])

    def main(self, *extra):
        mod = load_script("libexec/moat-inspect")
        seen = {}

        class Capture(Listener):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                seen["listener"] = self

            def accept_loop(self):
                pass

        out, err = io.StringIO(), io.StringIO()
        patch = unittest.mock.patch.object
        with patch(mod, "build_minter", return_value=None), \
                patch(mod, "inherited_listening_sockets", return_value=[]), \
                patch(mod, "Listener", Capture), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            rc = mod.main(["x", "--name", "wl", "--policy", str(self.policy),
                           "--state-dir", str(self.dir),
                           "--status", str(self.dir / "status.json"),
                           "--record", str(self.dir / "requests.log"),
                           *extra])
        return rc, seen.get("listener"), out.getvalue(), err.getvalue()

    def test_the_filters_are_loaded_and_handed_to_the_listener(self):
        rc, listener, out, _ = self.main(
            "--request-filters", str(self.filters))
        self.assertEqual(rc, 0)
        self.assertEqual(listener._request_filters_path, str(self.filters))
        self.assertIsNotNone(
            listener.inspection.policy.request_filters.filter_for(FILTERED))
        self.assertIn(f"request filters loaded from {self.filters}: "
                      f"filters=1", out)
        status = json.loads((self.dir / "status.json").read_text())
        self.assertEqual(status[REQUEST_FILTERS_DIGEST_KEY],
                         inspect_policy_digest(self.filters.read_text()))

    def test_a_bad_document_fails_the_start(self):
        self.filters.write_text('{"filters": [{"host": "a", "run": "rel"}]}')
        rc, listener, _, err = self.main(
            "--request-filters", str(self.filters))
        self.assertEqual(rc, 1)
        self.assertIsNone(listener)
        self.assertIn(f"error: could not read {self.filters}", err)

    def test_without_the_flag_nothing_is_filtered(self):
        rc, listener, out, _ = self.main()
        self.assertEqual(rc, 0)
        self.assertIsNone(listener._request_filters_path)
        self.assertEqual(listener.inspection.policy.request_filters.filters,
                         ())
        self.assertNotIn("request filters", out)


if __name__ == "__main__":
    unittest.main()
