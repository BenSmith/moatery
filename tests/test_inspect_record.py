"""The per-request record and its join key.

The listener logs a decision per connection and per request, and `peer=`
cannot say which connection a line belongs to: a source port repeats
across the requests on one keep-alive connection and is reused by the
kernel after close, so grouping by it merges unrelated connections and
splits one connection's own requests apart.

A connection id leads `where` -- which every decision path in the
listener interpolates -- and a request ordinal is added in the two
request loops. The record file carries one JSON object per request, and
nothing in it is a header or a body.
"""

import contextlib
import io
import json
import os
import re
import secrets
import socket
import stat
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

from moatery import egress_record
from moatery.egress_plane import CLEARTEXT, TLS, plane_for_port
from moatery.egress_record import (
    DROP_NOT_ALLOWLISTED,
    DROP_NOT_TLS,
    DROP_UNREADABLE_REQUEST,
    LOG_ID_FIELD,
    LOG_REQ_FIELD,
    RECORD_FIELDS,
    RequestLog,
    Where,
    format_endpoint,
)
from moatery.inspect_listener import Listener
from moatery.inspect_policy import Policy

ID = re.compile(r"\bid=([0-9a-f]{12})\b")
REQ = re.compile(r"\breq=(\d+)\b")

# The two ends the tests accept on, one per plane.
CLEARTEXT_LOCAL = ("198.18.1.1", CLEARTEXT.inspect_port)
TLS_LOCAL = ("198.18.1.1", TLS.inspect_port)


def _listener_with(local):
    m = unittest.mock.Mock()
    m.getsockname.return_value = local
    return m


def _where(local, peer):
    """(where, plane) as _handle builds them for a fresh connection."""
    plane = plane_for_port(local[1])
    cid = secrets.token_hex(6)
    where = Where(f"{LOG_ID_FIELD}={cid} plane={plane.label} "
                  f"local={format_endpoint(local)} "
                  f"peer={format_endpoint(peer)}",
                  cid=cid, plane=plane.label)
    return where, plane


class _Harness(unittest.TestCase):

    def _pair(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.settimeout(3.0)
        b.settimeout(3.0)
        return a, b

    def _serve(self, feed, *, local=CLEARTEXT_LOCAL, hosts=(),
               peer=("192.0.2.1", 1024)):
        """One connection, driven through _serve — the function _handle's
        thread calls, so the lines are the real ones and the assertion is not
        a race against a daemon thread."""
        out = io.StringIO()
        listener = Listener(
            [_listener_with(local)], out,
            policy=Policy(tls="splice", hosts=tuple(hosts)))
        ours, guest = self._pair()
        guest.sendall(feed)
        guest.shutdown(socket.SHUT_WR)
        listener._serve(ours, *_where(local, peer))
        return out.getvalue()

    def _lines(self, log):
        return [ln for ln in log.splitlines() if ln.strip()]


class TestEveryLineCarriesTheId(_Harness):
    """`where` leads with the id, so every path that interpolates it gets one
    — which is the whole reason the field went there rather than onto the
    handful of lines someone remembered to edit."""

    def test_a_refused_request_carries_one(self):
        log = self._serve(b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
        self.assertRegex(log, ID)

    def test_a_forwarded_request_carries_one(self):
        origin = []

        def dial(addr, timeout=None):
            near, far = self._pair()
            far.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            origin.append(far)
            return near

        with unittest.mock.patch.object(
                socket, "create_connection", side_effect=dial):
            log = self._serve(
                b"GET / HTTP/1.1\r\nHost: ok.example\r\nConnection: close\r\n\r\n",
                hosts=("ok.example",))
        self.assertIn("forward ", log)
        self.assertRegex(log, ID)

    def test_a_tls_connection_with_no_readable_name_carries_one(self):
        log = self._serve(b"\x16\x03\x01\x00\x05rubbish", local=TLS_LOCAL)
        self.assertIn("drop ", log)
        self.assertRegex(log, ID)

    def test_the_id_leads_the_line_after_the_verb(self):
        """Anchored, not merely present. A reader grepping one connection out
        of a file wants a fixed position to cut on, and a field that drifted
        to the end of the line would still pass a bare `assertIn`."""
        log = self._serve(b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
        for line in self._lines(log):
            self.assertRegex(line, r"^\w+ id=[0-9a-f]{12} plane=")

    def test_a_connection_the_ceiling_rejects_carries_one(self):
        """The rejection path never reaches _serve, which is exactly why the
        id is minted in _handle: a guest reporting a stall it got no answer to
        is correlated through these two lines or through nothing."""
        out = io.StringIO()
        listener = Listener([_listener_with(CLEARTEXT_LOCAL)], out,
                                limit=0)
        conn = unittest.mock.MagicMock()
        conn.recv.return_value = b""
        listener._handle(conn, ("192.0.2.1", 1024),
                         _listener_with(CLEARTEXT_LOCAL))
        # The serving ceiling is met in the connection's thread, after the
        # caller is looked up.
        deadline = time.monotonic() + 5
        while ("rejected " not in out.getvalue()
               and time.monotonic() < deadline):
            time.sleep(0.01)
        self.assertIn("rejected ", out.getvalue())
        self.assertRegex(out.getvalue(), ID)

    def test_a_connection_no_thread_could_be_started_for_carries_one(self):
        out = io.StringIO()
        listener = Listener([_listener_with(CLEARTEXT_LOCAL)], out)
        conn = unittest.mock.MagicMock()
        conn.recv.return_value = b""
        with unittest.mock.patch.object(
                threading.Thread, "start",
                side_effect=RuntimeError("can't start new thread")):
            listener._handle(conn, ("192.0.2.1", 1024),
                             _listener_with(CLEARTEXT_LOCAL))
        self.assertIn("cannot start thread", out.getvalue())
        self.assertRegex(out.getvalue(), ID)


class TestTheIdGroupsOneConnection(_Harness):

    def test_every_line_of_one_connection_shares_it(self):
        """Three requests, two of them refused, on one connection. If the id
        were minted per request rather than per connection this passes each
        line individually and groups nothing."""
        log = self._serve(
            b"GET /a HTTP/1.1\r\nHost: nobody.example\r\n\r\n"
            b"GET /b HTTP/1.1\r\nHost: other.example\r\n\r\n"
            b"GET /c HTTP/1.1\r\nHost: third.example\r\n\r\n")
        found = set(ID.findall(log))
        self.assertEqual(len(self._lines(log)), 3)
        self.assertEqual(len(found), 1, f"one connection, one id: {log!r}")

    def test_two_connections_do_not_share_it(self):
        feed = b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n"
        first = set(ID.findall(self._serve(feed)))
        second = set(ID.findall(self._serve(feed)))
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first, second)

    def test_the_id_is_not_a_counter(self):
        """Restarts are the case. The listener is socket-activated, so a
        counter begins again at zero every time the socket re-triggers it,
        while the record file it keys outlives that restart — two unrelated
        connections would collide on the one key a reader joins on.

        _handle hands each connection to a thread, which writes its line;
        the threads are joined before the output is read."""
        out = io.StringIO()
        listener = Listener([_listener_with(CLEARTEXT_LOCAL)], out,
                                limit=0)
        started, real = [], threading.Thread

        def spawn(*args, **kwargs):
            started.append(real(*args, **kwargs))
            return started[-1]

        with unittest.mock.patch.object(threading, "Thread",
                                        side_effect=spawn):
            for _ in range(4):
                conn = unittest.mock.MagicMock()
                conn.recv.return_value = b""
                listener._handle(conn, ("192.0.2.1", 1024),
                                 _listener_with(CLEARTEXT_LOCAL))
        self.assertEqual(len(started), 4)
        for thread in started:
            thread.join(5)
        found = ID.findall(out.getvalue())
        self.assertEqual(len(found), 4)
        self.assertEqual(len(set(found)), 4)
        self.assertNotIn("000000000000", found)


class TestTheRequestOrdinal(_Harness):

    def test_it_counts_the_requests_on_one_connection(self):
        log = self._serve(
            b"GET /a HTTP/1.1\r\nHost: nobody.example\r\n\r\n"
            b"GET /b HTTP/1.1\r\nHost: other.example\r\n\r\n"
            b"GET /c HTTP/1.1\r\nHost: third.example\r\n\r\n")
        self.assertEqual(REQ.findall(log), ["1", "2", "3"])

    def test_a_connection_level_line_has_none(self):
        """The TLS front takes its decision before any request exists, so a
        `req=` there would be inventing an ordinal for something that is not a
        request — and a reader joining on it would attribute a connection's
        refusal to whichever request happened to be numbered 1."""
        log = self._serve(b"\x16\x03\x01\x00\x05rubbish", local=TLS_LOCAL)
        self.assertNotRegex(log, REQ)


if __name__ == "__main__":
    unittest.main()


class TestTheRecordFile(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.dir, ignore_errors=True))
        self.path = os.path.join(self.dir, "requests.log")

    def _log(self, path=None, out=None, on_failure=None):
        log = RequestLog(self.path if path is None else path,
                                out=out, on_failure=on_failure)
        self.addCleanup(log.close)
        return log

    def _lines(self):
        with open(self.path) as f:
            return [json.loads(ln) for ln in f if ln.strip()]

    def test_it_writes_one_json_object_per_line(self):
        log = self._log()
        log.write({"id": "a", "host": "one.example"})
        log.write({"id": "b", "host": "two.example"})
        self.assertEqual([r["host"] for r in self._lines()],
                         ["one.example", "two.example"])

    def test_a_short_write_is_finished_not_left_short(self):
        real = os.write

        def short(fd, data):
            return real(fd, data[:7])
        log = self._log()
        with unittest.mock.patch.object(egress_record.os, "write", short):
            log.write({"id": "a", "host": "one.example"})
        self.assertEqual(self._lines(), [{"id": "a", "host": "one.example"}])
        self.assertEqual(log._size, os.path.getsize(self.path))

    def test_a_line_torn_by_a_failure_costs_that_line_alone(self):
        """The disk filling mid-line leaves it without its newline; the
        next line starts on its own, so the reader loses one, not two."""
        from moathut import record
        real = os.write
        calls = []

        def fill(fd, data):
            calls.append(data)
            if len(calls) == 1:
                return real(fd, data[:9])
            raise OSError(28, "No space left on device")
        log = self._log(out=io.StringIO())
        with unittest.mock.patch.object(egress_record.os, "write", fill):
            log.write({"id": "a", "host": "one.example"})
        log.write({"id": "b", "host": "two.example"})
        self.assertEqual([d["id"] for d in record.lines(Path(self.path))],
                         ["b"])
        self.assertEqual(log._size, os.path.getsize(self.path))

    def test_a_new_file_is_0600(self):
        """The mode IS the access decision here: root and the workload uid,
        nobody else, which is the whole reason the record is not in a
        journal."""
        old = os.umask(0o000)
        self.addCleanup(os.umask, old)
        self._log().write({"id": "a"})
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_a_file_that_already_exists_is_tightened(self):
        """What the fchmod is actually for, and the case that makes it not
        redundant with the open mode: O_CREAT's mode applies to a file being
        CREATED and is ignored for one already there. A record left behind at
        0644 by an operator, by an older build, or by a logrotate `create` line
        someone adds back would otherwise stay world-readable for the life of
        the file while every test of a fresh one passes."""
        with open(self.path, "w"):
            pass
        os.chmod(self.path, 0o644)
        self._log().write({"id": "a"})
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_it_appends_to_an_existing_file(self):
        """A restart must not discard the record the previous instance wrote —
        the socket unit re-triggers the listener freely."""
        with open(self.path, "w") as f:
            f.write('{"id": "old"}\n')
        self._log().write({"id": "new"})
        self.assertEqual([r["id"] for r in self._lines()], ["old", "new"])

    def test_a_reopen_after_a_rotation_writes_to_a_new_file(self):
        log = self._log()
        log.write({"id": "before"})
        rotated = self.path + ".1"
        os.rename(self.path, rotated)
        log.reopen()
        log.write({"id": "after"})
        self.assertEqual([r["id"] for r in self._lines()], ["after"])
        with open(rotated) as f:
            self.assertIn("before", f.read())

    def test_without_a_reopen_the_writes_follow_the_renamed_file(self):
        """The half that makes the HUP necessary rather than decorative: a
        rename does not move an open fd, so a rotation with no signal leaves
        every later record in a file logrotate is about to compress away."""
        log = self._log()
        log.write({"id": "before"})
        rotated = self.path + ".1"
        os.rename(self.path, rotated)
        log.write({"id": "after"})
        self.assertFalse(os.path.exists(self.path))
        with open(rotated) as f:
            self.assertIn("after", f.read())

    def test_reopening_does_no_io(self):
        """reopen() runs in a SIGNAL HANDLER, on whichever thread the kernel
        picks. Doing the close-and-open there deadlocks against a thread
        already inside write(), which is why it only sets a flag."""
        log = self._log()
        log.write({"id": "a"})
        os.rename(self.path, self.path + ".1")
        log.reopen()
        self.assertFalse(os.path.exists(self.path),
                         "reopen() opened the file itself")

    def test_a_sink_that_cannot_be_written_never_raises(self):
        """The standing rule for every diagnostic here, and it binds harder on
        this one: these run on the CONNECTION threads, so an escape takes a
        guest request down per failure."""
        log = self._log(path=os.path.join(self.dir, "nope", "requests.log"))
        log.write({"id": "a"})          # must not raise

    def test_a_failure_is_counted(self):
        """The permanent reading. The warning is emitted once per process, so a
        sink broken since boot is invisible to anyone not tailing at the moment
        it failed — and a reader must know the record is incomplete before
        concluding a guest made no requests."""
        seen = []
        log = self._log(path=os.path.join(self.dir, "nope", "requests.log"),
                        on_failure=lambda: seen.append(1))
        log.write({"id": "a"})
        log.write({"id": "b"})
        self.assertEqual(len(seen), 2)

    def test_only_the_first_failure_is_logged(self):
        """A line per failed record would put exactly the volume the private
        sink exists to keep out of the journal back into it."""
        out = io.StringIO()
        log = self._log(path=os.path.join(self.dir, "nope", "requests.log"),
                        out=out)
        for _ in range(5):
            log.write({"id": "a"})
        self.assertEqual(out.getvalue().count("WARNING"), 1)

    def test_an_unserialisable_field_degrades_to_a_missing_record(self):
        """A later rung adding a field json cannot take must lose the record,
        never the request."""
        seen = []
        log = self._log(on_failure=lambda: seen.append(1))
        log.write({"id": object()})
        log.write({"id": "b"})
        self.assertEqual([r["id"] for r in self._lines()], ["b"])
        self.assertEqual(len(seen), 1)

    def test_no_path_writes_nothing(self):
        """The convention _status_path already uses: the shape tests construct
        a Listener with no workload name and no directory to write into, and a
        diagnostic that made those impossible would decide which tests exist."""
        RequestLog(None).write({"id": "a"})

    def test_concurrent_writers_produce_whole_lines(self):
        """O_APPEND fixes the offset but does not make a partial write atomic;
        the lock is what keeps one record on one line.

        The write is instrumented to yield MID-RECORD, which is what the
        scheduler is free to do and what a bare `os.write` per fragment would
        expose. Without the instrumentation a single os.write of a small line
        never interleaves in practice and the test passes with no lock at
        all."""
        log = self._log()
        real = os.write

        def torn(fd, data):
            if fd == log._fd and data.endswith(b"\n"):
                done = real(fd, data[:8])
                time.sleep(0.001)
                return done + real(fd, data[8:])
            return real(fd, data)

        with unittest.mock.patch.object(egress_record.os, "write", torn):
            record = {"id": "x", "pad": "y" * 400}
            threads = [threading.Thread(target=log.write, args=(record,))
                       for _ in range(16)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)
        self.assertEqual(len(self._lines()), 16)


class TestTheListenerHoldsOne(unittest.TestCase):

    def test_a_failure_shows_up_in_the_status_document(self):
        listener = Listener([], io.StringIO(),
                                record_path="/nonexistent/dir/requests.log")
        self.addCleanup(listener.inspection.record.close)
        self.assertEqual(
            listener.inspection.counters.snapshot(open_now=0, refused=0)["record_failures"],
            0)
        listener.inspection.record.write({"id": "a"})
        self.assertEqual(
            listener.inspection.counters.snapshot(open_now=0, refused=0)["record_failures"],
            1)

    def test_the_counter_exists_even_when_nothing_is_written(self):
        """A figure that only accumulates when someone is watching is a figure
        nobody can trust — the reason the listener's other counters are
        unconditional."""
        listener = Listener([], io.StringIO())
        self.assertIn("record_failures",
                      listener.inspection.counters.snapshot(open_now=0, refused=0))


# ---------------------------------------------------------------------------
# T1c — the record's fields
# ---------------------------------------------------------------------------


class _Records(_Harness):
    """A listener whose record file is real, driven through _serve."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="record-fields-")
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "requests.log"

    def _drive(self, feed, *, local=CLEARTEXT_LOCAL, policy=None,
               peer=("192.0.2.1", 1024), origin=None):
        """One connection. Returns (journal text, [record dicts])."""
        out = io.StringIO()
        listener = Listener(
            [_listener_with(local)], out,
            policy=policy or Policy(tls="splice", hosts=()),
            record_path=self.path)
        ours, guest = self._pair()
        guest.sendall(feed)
        guest.shutdown(socket.SHUT_WR)
        ctx = (unittest.mock.patch.object(
                   socket, "create_connection", side_effect=origin)
               if origin else contextlib.nullcontext())
        with ctx:
            listener._serve(ours, *_where(local, peer))
        listener.inspection.record.close()
        return out.getvalue(), self._records()

    def _records(self):
        if not self.path.exists():
            return []
        return [json.loads(ln) for ln in
                self.path.read_text().splitlines() if ln.strip()]

    def _origin(self, response=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"):
        kept = []

        def dial(addr, timeout=None):
            near, far = self._pair()
            far.sendall(response)
            kept.append(far)
            return near
        return dial


class TestTheRecordOfAnAllowedRequest(_Records):
    """The shape every other case is a variation on."""

    def _one(self):
        _log, records = self._drive(
            b"GET /v1/messages?stream=true HTTP/1.1\r\nHost: ok.example\r\n"
            b"Connection: close\r\n\r\n",
            policy=Policy(tls="splice", hosts=("ok.example",)),
            origin=self._origin())
        self.assertEqual(len(records), 1, records)
        return records[0]

    def test_every_field_is_present(self):
        """A field absent and a field null are different facts. A reader that
        has to tell "not measured" from "measured as nothing" cannot, if the
        writer drops keys whose value is None."""
        self.assertEqual(sorted(self._one()), sorted(RECORD_FIELDS))

    def test_the_decision_and_mode(self):
        rec = self._one()
        self.assertEqual(rec["decision"], "forward")
        self.assertEqual(rec["mode"], "forward")
        self.assertEqual(rec["plane"], "cleartext")

    def test_the_path_and_query_are_split(self):
        """Two different kinds of evidence. `paths` policy is matched against
        the path alone, and a query can carry a credential outright — merged
        into one field a reader cannot ask about either."""
        rec = self._one()
        self.assertEqual(rec["path"], "/v1/messages")
        self.assertEqual(rec["query"], "stream=true")

    def test_the_request_line_fields(self):
        rec = self._one()
        self.assertEqual(rec["method"], "GET")
        self.assertEqual(rec["host"], "ok.example")
        self.assertEqual(rec["http"], "HTTP/1.1")

    def test_the_status_is_the_one_the_origin_sent(self):
        self.assertEqual(self._one()["status"], 200)

    def test_a_request_with_no_query_records_null_not_empty(self):
        """"" would say the guest sent a bare `?`. It did not."""
        _log, records = self._drive(
            b"GET /plain HTTP/1.1\r\nHost: ok.example\r\n"
            b"Connection: close\r\n\r\n",
            policy=Policy(tls="splice", hosts=("ok.example",)),
            origin=self._origin())
        self.assertIsNone(records[0]["query"])

    def test_the_timestamp_is_wall_clock_utc_to_milliseconds(self):
        """Not monotonic(). The record exists to be joined against a journal
        line and a person's memory of when something happened, and a monotonic
        reading joins to neither."""
        rec = self._one()
        self.assertRegex(rec["ts"],
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_the_duration_is_a_number_of_milliseconds(self):
        self.assertIsInstance(self._one()["duration_ms"], float)

    def test_the_upstream_is_the_address_actually_dialled(self):
        """§11's other half of the join: the name was resolved by THIS process,
        so nothing else on the host knows which address a policy name became.

        A REAL TCP ORIGIN, not the socketpair the other cases use. A unix
        socket has no address pair to report, so a mocked upstream would leave
        this field null and the assertion would be measuring the mock.
        """
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        self.addCleanup(server.close)
        addr = server.getsockname()

        def serve():
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                conn.recv(65536)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3.0)

        def dial(_addr, timeout=None):
            sock = socket.create_connection(addr, timeout=timeout)
            self.addCleanup(sock.close)
            return sock

        real = socket.create_connection
        with unittest.mock.patch.object(
                socket, "create_connection",
                side_effect=lambda a, timeout=None: real(addr, timeout=timeout)):
            _log, records = self._drive(
                b"GET / HTTP/1.1\r\nHost: ok.example\r\n"
                b"Connection: close\r\n\r\n",
                policy=Policy(tls="splice", hosts=("ok.example",)))
        self.assertEqual(records[0]["upstream"],
                         f"{addr[0]}:{addr[1]}")

    def test_the_id_joins_it_to_the_journal(self):
        log, records = self._drive(
            b"GET / HTTP/1.1\r\nHost: ok.example\r\nConnection: close\r\n\r\n",
            policy=Policy(tls="splice", hosts=("ok.example",)),
            origin=self._origin())
        self.assertEqual(records[0][LOG_ID_FIELD],
                         ID.search(log).group(1))
        self.assertEqual(records[0][LOG_REQ_FIELD], 1)


class TestNoHeaderOrBodyEverReachesIt(_Records):
    """The standing constraint, met at CONSTRUCTION. There is no redaction step
    because there is nothing to redact — a record redacted at rendering time is
    one --verbose away from being the thing it was written not to be."""

    def test_neither_a_header_value_nor_a_body_byte_appears(self):
        body = b"tok_SECRETBODY"
        self._drive(
            b"POST /x HTTP/1.1\r\nHost: ok.example\r\n"
            b"Authorization: Bearer tok_SECRETHEADER\r\n"
            b"X-Custom: tok_SECRETCUSTOM\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n%s"
            % (len(body), body),
            policy=Policy(tls="splice", hosts=("ok.example",)),
            origin=self._origin())
        text = self.path.read_text()
        for secret in (b"SECRETHEADER", b"SECRETCUSTOM", b"SECRETBODY"):
            self.assertNotIn(secret.decode(), text)
        self.assertIn("/x", text)


class TestARefusalIsRecorded(_Records):

    def test_a_403_carries_the_reason_and_the_status(self):
        _log, records = self._drive(
            b"GET /secret?k=v HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
        self.assertEqual(len(records), 1, records)
        rec = records[0]
        self.assertEqual(rec["decision"], "drop")
        self.assertEqual(rec["status"], 403)
        self.assertEqual(rec["reason"], DROP_NOT_ALLOWLISTED)

    def test_a_denied_path_is_recorded_too(self):
        """The split is by CONTENT, not by outcome. A denied path is evidence
        of what the agent was trying to do, which is exactly the question the
        record exists to answer."""
        _log, records = self._drive(
            b"GET /secret?k=v HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
        self.assertEqual(records[0]["path"], "/secret")
        self.assertEqual(records[0]["query"], "k=v")

    def test_a_refusal_never_dialled_an_upstream(self):
        _log, records = self._drive(
            b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
        self.assertIsNone(records[0]["upstream"])


class TestAHeadThatCouldNotBeRead(_Records):

    def test_it_is_recorded_with_no_host_and_no_path(self):
        """A pass that never got a parseable head still leaves a line — the
        record's coverage is the counters' coverage. What it must NOT do is
        guess a name out of bytes it refused to read."""
        _log, records = self._drive(b"NOT-A-REQUEST\r\n\r\n")
        self.assertEqual(len(records), 1, records)
        rec = records[0]
        self.assertEqual(rec["decision"], "drop")
        self.assertEqual(rec["reason"], DROP_UNREADABLE_REQUEST)
        self.assertEqual(rec["status"], 400)
        self.assertIsNone(rec["host"])
        self.assertIsNone(rec["path"])
        self.assertIsNone(rec["method"])


class TestWhatIsNotARequest(_Records):
    """Two passes end without a decision, and neither may invent a request."""

    def test_a_guest_that_closes_between_requests_records_nothing(self):
        _log, records = self._drive(
            b"GET / HTTP/1.1\r\nHost: ok.example\r\n\r\n",
            policy=Policy(tls="splice", hosts=("ok.example",)),
            origin=self._origin())
        # One request, then EOF. The second pass reads nothing and is not one.
        self.assertEqual(len(records), 1, records)


class TestTheConnectionLevelRecords(_Records):
    """Two paths carry requests this design never decodes, and one denial is
    taken before a request exists. All three are named rather than left to look
    like silence."""

    def _tls_listener(self, policy):
        out = io.StringIO()
        return Listener([_listener_with(TLS_LOCAL)], out, policy=policy,
                            record_path=self.path), out

    def test_a_spliced_connection_is_recorded_as_an_exemption(self):
        listener, _out = self._tls_listener(
            Policy(tls="splice", hosts=("ok.example",)))
        ours, guest = self._pair()
        from tests.test_inspect_listener import _hello_bytes
        guest.sendall(_hello_bytes(server_name="ok.example"))
        guest.shutdown(socket.SHUT_WR)
        with unittest.mock.patch.object(
                socket, "create_connection", side_effect=self._origin(b"")):
            listener._serve(ours, *_where(TLS_LOCAL, ("192.0.2.1", 1024)))
        listener.inspection.record.close()
        records = self._records()
        self.assertEqual(len(records), 1, records)
        rec = records[0]
        self.assertEqual(rec["mode"], "splice")
        self.assertEqual(rec["decision"], "forward")
        self.assertEqual(rec["host"], "ok.example")
        self.assertIsNone(rec["path"], "a splice decodes nothing")
        self.assertIsNone(rec["status"])
        self.assertIsNone(rec[LOG_REQ_FIELD])

    def test_an_unreadable_hello_is_recorded(self):
        listener, _out = self._tls_listener(Policy(tls="splice", hosts=()))
        ours, guest = self._pair()
        guest.sendall(b"\x16\x03\x01\x00\x05rubbish")
        guest.shutdown(socket.SHUT_WR)
        listener._serve(ours, *_where(TLS_LOCAL, ("192.0.2.1", 1024)))
        listener.inspection.record.close()
        records = self._records()
        self.assertEqual(len(records), 1, records)
        self.assertEqual(records[0]["decision"], "drop")
        self.assertEqual(records[0]["reason"], DROP_NOT_TLS)
        self.assertIsNone(records[0]["host"])


if __name__ == "__main__":
    unittest.main()
