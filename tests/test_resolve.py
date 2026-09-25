"""customs-resolve: the wire details that present as "DNS is slow", and the
one property that is not a wire detail.

Every failure guarded here looks like something else from inside the
workload. A REFUSED where NODATA belongs costs a full retry schedule per
lookup on a resolver list with one entry; a TTL that is not the stated
constant turns one lookup into thousands; a TCP reply without its length
prefix hangs every client that reads one. None of them produce an error
naming DNS.

The property: the responder has no upstream socket at all. That is what
closes DNS rather than filtering it, and it is a property of the source
text, so it is checked as one.

Ported with the responder from workloadctl's tests/test_vm_resolve.py; the
static map and the UDP truncation it needed did not come across.
"""

import ast
import json
import os
import random
import shutil
import signal
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import dns_wire
import resolve_server
from inspect_policy import load_policy
from resolve_policy import RESOLVE_TTL, Policy
from sd_listen import NotSocketActivated
from tests import REPO_ROOT, load_script

TYPE_A = 1
TYPE_AAAA = 28
TYPE_MX = 15
TYPE_TXT = 16
TYPE_HTTPS = 65
CLASS_IN = 1
CLASS_CH = 3

ADDRESS = "169.254.1.3"
ADDRESS6 = "fd00::3"


def encode_name(name):
    """Presentation form to wire form. A trailing root dot does not exist on
    the wire: the zero-length label is the terminator."""
    name = name[:-1] if name.endswith(".") else name
    out = bytearray()
    for label in name.split(".") if name else []:
        out.append(len(label))
        out += label.encode("ascii")
    out.append(0)
    return bytes(out)


def query(name, qtype, ident=0x1234, rd=True, opcode=0, qdcount=1, opt=False,
          qclass=CLASS_IN):
    """A DNS query on the wire, with the knobs the tests vary."""
    flags = (opcode << 11) | (0x0100 if rd else 0)
    msg = struct.pack("!HHHHHH", ident, flags, qdcount, 0, 0,
                      1 if opt else 0)
    msg += encode_name(name) + struct.pack("!HH", qtype, qclass)
    if opt:
        # OPT: root name, type 41, class = advertised payload size, no
        # options. The shape systemd-resolved sends.
        msg += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return msg


class Reply:
    """A parsed response, so assertions read as claims about DNS."""

    def __init__(self, raw):
        self.raw = raw
        (self.id, self.flags, self.qdcount, self.ancount,
         self.nscount, self.arcount) = struct.unpack("!HHHHHH", raw[:12])
        self.rcode = self.flags & 0x000F
        self.qr = bool(self.flags & 0x8000)
        self.aa = bool(self.flags & 0x0400)
        self.tc = bool(self.flags & 0x0200)
        self.rd = bool(self.flags & 0x0100)
        self.ra = bool(self.flags & 0x0080)
        self.opcode = (self.flags >> 11) & 0xF
        self.records = []
        offset = 12
        for _ in range(self.qdcount):
            offset = self._skip_name(offset) + 4
        for _ in range(self.ancount):
            offset = self._skip_name(offset)
            rtype, rclass, ttl, rdlen = struct.unpack(
                "!HHIH", raw[offset:offset + 10])
            offset += 10
            self.records.append((rtype, rclass, ttl,
                                 raw[offset:offset + rdlen]))
            offset += rdlen

    def _skip_name(self, offset):
        while True:
            length = self.raw[offset]
            if length & 0xC0:
                return offset + 2
            offset += 1
            if length == 0:
                return offset
            offset += length

    def addresses(self):
        return [socket.inet_ntop(
                    socket.AF_INET6 if rtype == TYPE_AAAA else socket.AF_INET,
                    rdata)
                for rtype, _rclass, _ttl, rdata in self.records]


def _silenced_log():
    """The per-query log, captured rather than printed, through both
    bindings: build_answer logs through dns_wire's name, the serve loop
    through the copy it imported."""
    logged = []
    dns_wire.log = resolve_server.log = logged.append
    return logged


def _admits(*patterns):
    """An inspector policy's `admits`, over `hosts` alone."""
    from inspect_document import hostname_match
    return lambda name: hostname_match(name, patterns)


def _policy(address6=ADDRESS6, admits=None):
    return Policy(ADDRESS, address6, admits=admits or _admits())


def _answer(policy, *args, **kwargs):
    return Reply(dns_wire.build_answer(query(*args, **kwargs), policy))


class TestSynthesis(unittest.TestCase):
    """Every A and AAAA, for any name, answered with the one address."""

    @classmethod
    def setUpClass(cls):
        cls.logged = _silenced_log()
        cls.policy = _policy()

    def test_an_a_query_gets_the_address(self):
        reply = _answer(self.policy, "example.com", TYPE_A)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.addresses(), [ADDRESS])

    def test_an_aaaa_query_gets_the_v6_address(self):
        self.assertEqual(
            _answer(self.policy, "example.com", TYPE_AAAA).addresses(),
            [ADDRESS6])

    def test_with_no_v6_address_an_aaaa_query_gets_no_records(self):
        """Not an address the redirect does not cover, which a dual-stack
        client would try first and wait on."""
        reply = _answer(_policy(address6=None), "example.com", TYPE_AAAA)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.ancount, 0)
        self.assertEqual(reply.qdcount, 1)

    def test_any_name_at_all_is_answered(self):
        """There are no names this does not serve. One that answered only
        listed names would need a fallback for the rest, and a fallback is
        an upstream socket."""
        for name in ("a.b.c.d.example", "nonexistent.invalid", "x"):
            self.assertEqual(
                _answer(self.policy, name, TYPE_A).addresses(), [ADDRESS],
                name)

    def test_the_ttl_on_the_wire_is_the_stated_constant(self):
        _t, _c, ttl, _r = _answer(self.policy, "example.com",
                                  TYPE_A).records[0]
        self.assertEqual(ttl, RESOLVE_TTL)
        self.assertEqual(RESOLVE_TTL, 3600)

    def test_the_id_and_question_are_echoed(self):
        raw = dns_wire.build_answer(
            query("example.com", TYPE_A, ident=0xBEEF), self.policy)
        self.assertEqual(Reply(raw).id, 0xBEEF)
        self.assertEqual(Reply(raw).qdcount, 1)
        self.assertEqual(raw[12:12 + len(encode_name("example.com")) + 4],
                         encode_name("example.com")
                         + struct.pack("!HH", TYPE_A, CLASS_IN))

    def test_the_answer_is_a_response_and_authoritative(self):
        reply = _answer(self.policy, "example.com", TYPE_A)
        self.assertTrue(reply.qr)
        self.assertTrue(reply.aa)
        self.assertFalse(reply.tc)

    def test_recursion_desired_is_echoed_and_available_is_set(self):
        """A stub that sees RD honoured with RA clear can decide the server
        is no use for recursion and stop asking it, and it has no other."""
        self.assertTrue(_answer(self.policy, "example.com", TYPE_A,
                                rd=True).rd)
        self.assertFalse(_answer(self.policy, "example.com", TYPE_A,
                                 rd=False).rd)
        self.assertTrue(_answer(self.policy, "example.com", TYPE_A).ra)

    def test_a_mixed_case_name_is_answered_the_same(self):
        """Some resolvers randomise the case of a query (0x20)."""
        self.assertEqual(
            _answer(self.policy, "ExAmPle.CoM", TYPE_A).addresses(),
            [ADDRESS])


class TestNodata(unittest.TestCase):
    """NODATA, never REFUSED, for everything that is not an address."""

    @classmethod
    def setUpClass(cls):
        cls.logged = _silenced_log()
        cls.policy = _policy()

    def test_https_gets_nodata_not_refused(self):
        """The type browsers and curl ask before every connection. Its
        empty answer also withholds an ECH configuration, which would hide
        the name from the inspector."""
        reply = _answer(self.policy, "example.com", TYPE_HTTPS)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.ancount, 0)

    def test_mx_and_txt_get_nodata(self):
        for qtype in (TYPE_MX, TYPE_TXT):
            reply = _answer(self.policy, "example.com", qtype)
            self.assertEqual((reply.rcode, reply.ancount), (0, 0), qtype)

    def test_nodata_echoes_the_question(self):
        """An empty answer with no question is a reply a stub cannot match
        to anything it asked."""
        self.assertEqual(
            _answer(self.policy, "example.com", TYPE_MX).qdcount, 1)

    def test_no_reply_is_ever_refused(self):
        for qtype in (TYPE_A, TYPE_AAAA, TYPE_MX, TYPE_TXT, TYPE_HTTPS, 99):
            self.assertNotEqual(
                _answer(self.policy, "example.com", qtype).rcode, 5, qtype)

    def test_a_non_internet_class_gets_nodata(self):
        reply = _answer(self.policy, "version.bind", TYPE_TXT,
                        qclass=CLASS_CH)
        self.assertEqual((reply.rcode, reply.ancount), (0, 0))
        self.assertEqual(_answer(self.policy, "example.com", TYPE_A,
                                 qclass=CLASS_CH).ancount, 0)


class TestEdns(unittest.TestCase):
    """A query carrying OPT gets a well-formed answer without an OPT."""

    @classmethod
    def setUpClass(cls):
        cls.logged = _silenced_log()
        cls.policy = _policy()

    def test_an_opt_query_is_answered_without_an_opt(self):
        reply = _answer(self.policy, "example.com", TYPE_A, opt=True)
        self.assertEqual(reply.addresses(), [ADDRESS])
        self.assertEqual(reply.arcount, 0)

    def test_the_answer_is_identical_with_and_without_opt(self):
        with_opt = dns_wire.build_answer(
            query("example.com", TYPE_A, opt=True), self.policy)
        without = dns_wire.build_answer(
            query("example.com", TYPE_A), self.policy)
        self.assertEqual(with_opt[2:], without[2:])


class TestMalformed(unittest.TestCase):
    """Defined replies to queries no stub sends."""

    @classmethod
    def setUpClass(cls):
        cls.logged = _silenced_log()
        cls.policy = _policy()

    def test_a_non_query_opcode_gets_notimp(self):
        reply = _answer(self.policy, "example.com", TYPE_A, opcode=5)
        self.assertEqual((reply.rcode, reply.opcode), (4, 5))

    def test_a_query_with_no_question_gets_formerr(self):
        raw = struct.pack("!HHHHHH", 0x1234, 0x0100, 0, 0, 0, 0)
        self.assertEqual(
            Reply(dns_wire.build_answer(raw, self.policy)).rcode, 1)

    def test_a_compression_pointer_in_the_question_is_refused(self):
        raw = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        raw += b"\xc0\x0c" + struct.pack("!HH", TYPE_A, CLASS_IN)
        with self.assertRaises(dns_wire.Malformed):
            dns_wire.build_answer(raw, self.policy)

    def test_a_name_ending_exactly_at_the_message_boundary_is_refused(self):
        """Found by the fuzz in workloadctl, pinned here. Without read_name's
        end-of-message guard it is an IndexError, which the loop does not
        catch, and the workload's only nameserver exits on one packet."""
        raw = bytes.fromhex("00010100000100000000b9000100")
        with self.assertRaises(dns_wire.Malformed):
            dns_wire.build_answer(raw, self.policy)

    def test_a_truncated_header_is_refused(self):
        with self.assertRaises(dns_wire.Malformed):
            dns_wire.build_answer(b"\x12\x34", self.policy)

    def test_a_name_running_past_the_message_is_refused(self):
        raw = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x09abc"
        with self.assertRaises(dns_wire.Malformed):
            dns_wire.build_answer(raw, self.policy)

    def test_a_question_without_type_and_class_is_refused(self):
        raw = (struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
               + encode_name("example.com") + b"\x00")
        with self.assertRaises(dns_wire.Malformed):
            dns_wire.build_answer(raw, self.policy)

    def test_a_response_is_not_answered(self):
        """Its own FORMERR would be a response too, so an error reply is
        no way out of a loop; there is no reply at all."""
        raw = bytearray(query("example.com", TYPE_A))
        raw[2] |= 0x80
        with self.assertRaises(dns_wire.NotAQuery):
            dns_wire.build_answer(bytes(raw), self.policy)
        answered = dns_wire.build_answer(query("example.com", TYPE_A),
                                         self.policy)
        with self.assertRaises(dns_wire.NotAQuery):
            dns_wire.build_answer(answered, self.policy)

    def test_an_error_response_carries_the_queried_id(self):
        raw = dns_wire.error_response(
            query("example.com", TYPE_A, ident=0x4242), 1)
        self.assertEqual(Reply(raw).id, 0x4242)
        self.assertTrue(Reply(raw).qr)


class _OneDatagram:
    """One datagram in, one out: enough of a socket for serve_datagram."""

    def __init__(self, payload):
        self._payload = payload
        self.sent = None

    def recvfrom(self, _n):
        return self._payload, ("127.0.0.1", 5300)

    def sendto(self, data, _peer):
        self.sent = data


class TestLogInjectionViaLabel(unittest.TestCase):
    """A label the workload wrote must not write a line of this log.

    A label is length-prefixed, so it can carry a bare LF, and the name
    reaches a print() whose destination is the journal. Refused as
    malformed: FORMERR and the malformed counter.
    """

    _forged = "evil\n  allowed.example A -> 1 record(s)"

    def setUp(self):
        self.logged = _silenced_log()
        self.policy = _policy(admits=_admits("allowed.example"))

    def test_a_label_with_a_newline_is_malformed(self):
        with self.assertRaises(dns_wire.Malformed):
            dns_wire.build_answer(query(self._forged, TYPE_A), self.policy)

    def test_it_is_refused_before_it_is_logged_or_counted(self):
        counters = resolve_server.Counters()
        with self.assertRaises(dns_wire.Malformed):
            dns_wire.build_answer(query(self._forged, TYPE_A), self.policy,
                                  counters=counters)
        self.assertEqual(self.logged, [])
        self.assertEqual(counters.snapshot()["unlisted_names"], {})

    def test_the_forged_text_appears_in_no_line_the_responder_writes(self):
        """serve_datagram logs the refusal itself, so the property has to
        hold over that path too."""
        sock = _OneDatagram(query(self._forged, TYPE_A))
        counters = resolve_server.Counters()
        resolve_server.serve_datagram(sock, self.policy, counters=counters)
        self.assertEqual(Reply(sock.sent).rcode, 1)
        self.assertEqual(counters.snapshot()["queries"]["malformed"], 1)
        self.assertTrue(self.logged)
        for line in self.logged:
            self.assertNotIn("evil", line)
            self.assertNotIn("\n", line)

    def test_every_control_character_goes_with_the_newline(self):
        for ch in ("\n", "\r", "\x00", "\x7f", "\t", "\x1b"):
            with self.subTest(ch=ch):
                with self.assertRaises(dns_wire.Malformed):
                    dns_wire.build_answer(
                        query(f"a{ch}b.example", TYPE_A), self.policy)

    def test_an_ordinary_name_still_answers(self):
        reply = _answer(self.policy, "api-1.allowed.example", TYPE_A)
        self.assertEqual((reply.rcode, reply.ancount), (0, 1))


class TestUdpSurvivesABugInItself(unittest.TestCase):
    """A query this program cannot answer must not end it: the process
    would exit, restart, and exit again on the same query, a crash loop in
    the workload's only nameserver."""

    def setUp(self):
        self.logged = _silenced_log()

    def _serve(self, msg=None):
        sock = _OneDatagram(msg or query("broken.example", TYPE_A))
        counters = resolve_server.Counters()
        with mock.patch.object(resolve_server, "build_answer",
                               side_effect=ZeroDivisionError("boom")):
            resolve_server.serve_datagram(sock, _policy(), counters=counters)
        return sock, counters

    def test_it_is_servfail_and_not_formerr(self):
        """The query was fine; this program was not."""
        sock, _ = self._serve()
        self.assertEqual(Reply(sock.sent).rcode, 2)

    def test_the_failure_is_not_counted_as_malformed(self):
        _, counters = self._serve()
        self.assertEqual(counters.snapshot()["queries"]["malformed"], 0)

    def test_the_journal_carries_the_exception_type(self):
        self._serve()
        self.assertTrue(any("ZeroDivisionError" in line
                            for line in self.logged))

    def test_a_query_too_short_to_reply_to_is_dropped_not_answered(self):
        sock, _ = self._serve(msg=b"\x01")
        self.assertIsNone(sock.sent)


class TestAResponseGetsNoReply(unittest.TestCase):
    """A response sent to the responder, its own reply looped back
    included, is dropped on both transports: no reply and no log line,
    which a loop would fill, but counted."""

    def setUp(self):
        self.logged = _silenced_log()
        self.response = dns_wire.build_answer(
            query("example.com", TYPE_A), _policy())
        self.logged.clear()

    def test_over_udp(self):
        sock = _OneDatagram(self.response)
        counters = resolve_server.Counters()
        resolve_server.serve_datagram(sock, _policy(), counters=counters)
        self.assertIsNone(sock.sent)
        self.assertEqual(self.logged, [])
        self.assertEqual(counters.snapshot()["queries"]["malformed"], 1)

    def test_over_tcp_the_next_query_is_still_answered(self):
        near, far = socket.socketpair()
        self.addCleanup(far.close)
        ask = query("example.com", TYPE_A, ident=0x4242)
        far.sendall(struct.pack("!H", len(self.response)) + self.response
                    + struct.pack("!H", len(ask)) + ask)
        far.shutdown(socket.SHUT_WR)
        resolve_server.handle_stream(near, _policy(),
                                     deadline=time.monotonic() + 2)
        replies = b""
        while chunk := far.recv(4096):
            replies += chunk
        (length,) = struct.unpack("!H", replies[:2])
        self.assertEqual(len(replies), 2 + length)
        self.assertEqual(Reply(replies[2:]).id, 0x4242)


class TestNoUpstream(unittest.TestCase):
    """The property that closes DNS rather than filtering it."""

    # The program is the entrypoint and the modules it answers through. A
    # scan of the script alone would pass while the answering path, in a
    # module beside it, grew a fallback.
    RESPONDER_FILES = (
        "libexec/customs-resolve",
        "lib/dns_wire.py",
        "lib/resolve_policy.py",
        "lib/resolve_server.py",
    )

    @staticmethod
    def _tree(relative):
        return ast.parse((Path(REPO_ROOT) / relative).read_text())

    def test_the_responder_never_calls_out(self):
        """Parsed, not grepped: the words appear in the prose saying no
        such call is made. If a "fallback for names we don't serve" is ever
        added, this fails, since the fallback is the channel."""
        forbidden = {
            "connect", "connect_ex", "create_connection", "getaddrinfo",
            "gethostbyname", "gethostbyname_ex", "getnameinfo", "urlopen",
        }
        for relative in self.RESPONDER_FILES:
            with self.subTest(file=relative):
                called = set()
                for node in ast.walk(self._tree(relative)):
                    if isinstance(node, ast.Call):
                        func = node.func
                        name = (func.attr if isinstance(func, ast.Attribute)
                                else getattr(func, "id", None))
                        if name:
                            called.add(name)
                self.assertEqual(sorted(called & forbidden), [])

    def _socket_constructions(self, relative):
        return [node for node in ast.walk(self._tree(relative))
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "socket"]

    def test_the_program_constructs_no_socket_at_all(self):
        for relative in self.RESPONDER_FILES:
            with self.subTest(file=relative):
                found = self._socket_constructions(relative)
                self.assertEqual(found, [], [ast.unparse(c) for c in found])

    def test_the_shared_constructor_only_adopts_an_inherited_fd(self):
        """sd_listen's socket.socket() appears once, with `fileno=` alone.
        Without it the call would create a socket, and this is the one
        module outside the list above that the responder's sockets come
        from."""
        found = self._socket_constructions("lib/sd_listen.py")
        self.assertEqual(len(found), 1, [ast.unparse(c) for c in found])
        self.assertEqual([kw.arg for kw in found[0].keywords], ["fileno"])
        self.assertEqual(found[0].args, [])

    def test_the_only_socket_call_is_address_formatting(self):
        self.assertEqual(dns_wire.pack_address("192.0.2.1"),
                         b"\xc0\x00\x02\x01")
        self.assertEqual(len(dns_wire.pack_address("2001:db8::1")), 16)


class TestOnTheWire(unittest.TestCase):
    """Both transports through real sockets, and specifically the TCP
    length prefix: a reply written without it looks well-formed to a test
    of the message and hangs every client."""

    @classmethod
    def setUpClass(cls):
        cls.logged = _silenced_log()
        cls.policy = _policy()

    def _listener(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        return listener, listener.getsockname()

    @staticmethod
    def _ask(client, name):
        payload = query(name, TYPE_A)
        client.sendall(struct.pack("!H", len(payload)) + payload)
        length = struct.unpack("!H", client.recv(2))[0]
        raw = b""
        while len(raw) < length:
            raw += client.recv(length - len(raw))
        return Reply(raw)

    def test_a_udp_query_is_answered_to_the_sender(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with server, client:
            server.bind(("127.0.0.1", 0))
            client.settimeout(5)
            client.sendto(query("example.com", TYPE_A), server.getsockname())
            resolve_server.serve_datagram(server, self.policy)
            raw, _peer = client.recvfrom(4096)
        self.assertEqual(Reply(raw).addresses(), [ADDRESS])

    def test_a_tcp_connection_carries_more_than_one_query(self):
        """RFC 7766 clients reuse the connection."""
        listener, address = self._listener()
        with socket.create_connection(address, timeout=5) as client:
            resolve_server.serve_stream(listener, self.policy)
            replies = [self._ask(client, name)
                       for name in ("one.example", "two.example")]
        self.assertEqual([r.addresses() for r in replies],
                         [[ADDRESS], [ADDRESS]])


class TestTcpDoesNotHoldTheLoop(unittest.TestCase):
    """A TCP peer must not stop UDP being answered: the loop hands the
    connection off, a connection has a lifetime and not just an idle
    timeout, and there is a ceiling on how many exist."""

    @classmethod
    def setUpClass(cls):
        cls.logged = _silenced_log()
        cls.policy = _policy()

    def _listener(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        return listener, listener.getsockname()

    def test_a_silent_peer_does_not_hold_the_loop(self):
        listener, address = self._listener()
        with socket.create_connection(address, timeout=5):
            started = time.monotonic()
            resolve_server.serve_stream(listener, self.policy)
            self.assertLess(time.monotonic() - started,
                            resolve_server.TCP_IDLE_TIMEOUT / 2)

    def test_a_dribbling_peer_is_ended_by_the_lifetime(self):
        """A length prefix promising more than will arrive. The deadline is
        checked before every recv, not once per message."""
        near, far = socket.socketpair()
        self.addCleanup(far.close)
        payload = query("example.com", TYPE_A)
        far.sendall(struct.pack("!H", len(payload) + 64) + payload)
        started = time.monotonic()
        resolve_server.handle_stream(near, self.policy,
                                     deadline=time.monotonic() + 0.3)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0)
        self.assertGreaterEqual(elapsed, 0.2)

    def test_a_peer_pipelining_forever_is_ended_by_the_lifetime(self):
        near, far = socket.socketpair()
        self.addCleanup(far.close)
        payload = query("example.com", TYPE_A)
        far.sendall((struct.pack("!H", len(payload)) + payload) * 50)
        resolve_server.handle_stream(near, self.policy,
                                     deadline=time.monotonic() + 0.3)
        self.assertTrue(far.recv(2))

    def test_connections_past_the_ceiling_are_closed_not_queued(self):
        listener, address = self._listener()
        slots = resolve_server._TcpSlots(limit=1)
        clients = []
        for _ in range(2):
            client = socket.create_connection(address, timeout=5)
            self.addCleanup(client.close)
            clients.append(client)
            resolve_server.serve_stream(listener, self.policy, slots=slots)
        payload = query("example.com", TYPE_A)
        clients[1].sendall(struct.pack("!H", len(payload)) + payload)
        self.assertEqual(clients[1].recv(4096), b"")
        self.assertEqual(TestOnTheWire._ask(clients[0],
                                            "example.com").addresses(),
                         [ADDRESS])

    def test_a_finished_connection_gives_its_slot_back(self):
        listener, address = self._listener()
        slots = resolve_server._TcpSlots(limit=1)
        for _ in range(3):
            with socket.create_connection(address, timeout=5) as client:
                resolve_server.serve_stream(listener, self.policy,
                                            slots=slots)
                self.assertEqual(
                    TestOnTheWire._ask(client, "example.com").addresses(),
                    [ADDRESS])
            for _ in range(50):
                if slots.take():
                    slots.give_back()
                    break
                time.sleep(0.02)
            else:
                self.fail("the slot was never given back")

    def test_counters_are_taken_under_a_lock(self):
        counters = resolve_server.Counters()
        errors = []

        def hammer():
            try:
                for _ in range(2000):
                    counters.record_answer("a.example", 1, False)
                    counters.record_malformed()
                    counters.snapshot()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(errors, [])
        snap = counters.snapshot()
        self.assertEqual(snap["queries"]["synthesised"], 8000)
        self.assertEqual(snap["queries"]["malformed"], 8000)
        self.assertEqual(snap["unlisted"], 8000)


class TestFuzz(unittest.TestCase):
    """Arbitrary bytes in, a reply or Malformed out, never anything else.

    The wire parser is this program's own, and build_answer is pure, so it
    is fed garbage in bulk. Any exception but Malformed escapes into the
    serve loop. Seeded, so the same inputs every run; in workloadctl a
    deleted end-of-message guard was found at 10,000 cases and not at
    5,000, hence 50,000.
    """

    ITERATIONS = 50000

    @classmethod
    def setUpClass(cls):
        cls.logged = _silenced_log()
        cls.policy = _policy()

    @staticmethod
    def _corpus():
        names = ("example.com", "", "a" * 63 + ".com",
                 ".".join("ab" for _ in range(120)))
        corpus = []
        for name in names:
            labels = b"".join(bytes([len(label)]) + label.encode()
                              for label in name.split(".") if label) + b"\0"
            for qtype in (TYPE_A, TYPE_AAAA, TYPE_MX, TYPE_HTTPS):
                corpus.append(
                    struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + labels
                    + struct.pack("!HH", qtype, CLASS_IN))
        return corpus

    @staticmethod
    def _mutate(rng, corpus):
        if rng.randint(0, 2) == 0:
            return bytes(rng.getrandbits(8)
                         for _ in range(rng.randint(0, 80)))
        data = bytearray(rng.choice(corpus))
        for _ in range(rng.randint(1, 6)):
            op = rng.randint(0, 2)
            if op == 0 and data:
                data[rng.randrange(len(data))] = rng.getrandbits(8)
            elif op == 1:
                data.insert(rng.randint(0, len(data)), rng.getrandbits(8))
            elif data:
                del data[rng.randrange(len(data))]
        return bytes(data)

    def test_no_input_escapes_as_an_unexpected_exception(self):
        rng = random.Random(0)
        corpus = self._corpus()
        for _ in range(self.ITERATIONS):
            data = self._mutate(rng, corpus)
            try:
                reply = dns_wire.build_answer(data, self.policy)
            except (dns_wire.Malformed, dns_wire.NotAQuery):
                continue
            except Exception as exc:  # noqa: BLE001
                self.fail(f"{type(exc).__name__}: {exc} on {data.hex()}")
            self.assertGreaterEqual(len(reply), 12, data.hex())
            self.assertTrue(struct.unpack("!H", reply[2:4])[0] & 0x8000,
                            data.hex())
            self.assertEqual(reply[:2], data[:2], data.hex())
            self.assertLessEqual(len(reply), dns_wire.UDP_BUDGET,
                                 data.hex())


class TestCounters(unittest.TestCase):
    """`unlisted` is the figure that is not a health metric: evidence that
    something is trying, never that anything left."""

    def setUp(self):
        self.logged = _silenced_log()
        self.policy = _policy(admits=_admits("allowed.example",
                                             "*.ok.example"))
        self.counters = resolve_server.Counters()

    def answer(self, *args, **kwargs):
        return dns_wire.build_answer(query(*args, **kwargs), self.policy,
                                     counters=self.counters)

    def test_a_query_for_an_unlisted_name_is_counted_as_unlisted(self):
        self.answer("encoded-data-1.attacker.example", TYPE_A)
        snap = self.counters.snapshot()
        self.assertEqual(snap["unlisted"], 1)
        self.assertEqual(snap["queries"]["synthesised"], 1)
        self.assertIn("encoded-data-1.attacker.example",
                      snap["unlisted_names"])

    def test_it_is_answered_exactly_as_a_listed_one(self):
        """A responder that withheld an answer for an unlisted name would
        tell the workload which names are on the list."""
        listed = Reply(self.answer("allowed.example", TYPE_A))
        unlisted = Reply(self.answer("nowhere.example", TYPE_A))
        self.assertEqual(listed.raw[2:], unlisted.raw[2:].replace(
            encode_name("nowhere.example"), encode_name("allowed.example")))

    def test_listed_and_wildcard_names_are_not_unlisted(self):
        self.answer("allowed.example", TYPE_A)
        self.answer("api.ok.example", TYPE_A)
        self.assertEqual(self.counters.snapshot()["unlisted"], 0)

    def test_the_apex_under_a_wildcard_is_unlisted(self):
        """`*.` needs a label before the dot. A rule that put everything on
        a list would pass the test above on its own."""
        self.answer("ok.example", TYPE_A)
        self.assertEqual(self.counters.snapshot()["unlisted"], 1)

    def test_a_nodata_type_is_counted_as_nodata_and_not_unlisted(self):
        self.answer("nowhere.example", TYPE_HTTPS)
        snap = self.counters.snapshot()
        self.assertEqual(snap["queries"]["nodata"], 1)
        self.assertEqual(snap["unlisted"], 0)

    def test_an_aaaa_with_no_v6_address_is_nodata(self):
        policy = _policy(address6=None, admits=_admits("allowed.example"))
        dns_wire.build_answer(query("allowed.example", TYPE_AAAA), policy,
                              counters=self.counters)
        snap = self.counters.snapshot()
        self.assertEqual(snap["queries"], {"synthesised": 0, "nodata": 1,
                                           "malformed": 0})

    def test_the_unlisted_name_map_is_bounded(self):
        for i in range(200):
            self.answer(f"h{i}.attacker.example", TYPE_A)
        snap = self.counters.snapshot()
        self.assertLessEqual(len(snap["unlisted_names"]), 21)
        self.assertEqual(snap["unlisted"], 200)

    def test_counters_are_optional_and_the_bytes_do_not_change(self):
        self.assertEqual(self.answer("allowed.example", TYPE_A),
                         dns_wire.build_answer(query("allowed.example",
                                                     TYPE_A), self.policy))

    def test_the_names_are_logged_with_their_type(self):
        self.answer("allowed.example", TYPE_A)
        self.answer("elsewhere.example", TYPE_AAAA)
        self.assertEqual(self.logged,
                         ["  allowed.example A -> 1 record(s)",
                          "  elsewhere.example AAAA -> 1 record(s)"])


class TestStatusFile(unittest.TestCase):

    def setUp(self):
        self.logged = _silenced_log()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "resolve-status.json")

    def test_it_writes_the_counters(self):
        counters = resolve_server.Counters()
        counters.record_answer("a.example", 1, True)
        resolve_server.emit_status(self.path, counters)
        doc = json.loads(Path(self.path).read_text())
        self.assertEqual(doc["queries"]["synthesised"], 1)
        self.assertIn("written_at", doc)

    def test_an_unwritable_path_never_takes_the_responder_down(self):
        resolve_server.emit_status(
            os.path.join(self.dir, "no", "such", "s.json"),
            resolve_server.Counters())

    def test_an_unserialisable_counter_never_takes_the_responder_down(self):
        counters = resolve_server.Counters()
        counters.snapshot = lambda: {"later": object()}
        resolve_server.emit_status(self.path, counters)
        self.assertFalse(Path(self.path).exists())

    def test_the_loop_writes_before_the_first_query(self):
        """Observed at the loop's first turn: serve writes again on its way
        out, so the file existing afterwards proves nothing."""
        seen = []

        def stop():
            seen.append(Path(self.path).exists())
            return True

        resolve_server.serve([], _policy(), resolve_server.Counters(),
                             self.path, stop=stop)
        self.assertEqual(seen, [True])


class TestEntrypoint(unittest.TestCase):
    """main() end to end on a real socket, stopped by its own SIGTERM
    handler: which policy it counts against, where the status goes, that
    its Counters are the ones serve counts into, and that the flag is the
    stop the loop reads."""

    def setUp(self):
        self.logged = _silenced_log()
        self.mod = load_script("libexec/customs-resolve")
        self.mod.log = self.logged.append
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.policy = os.path.join(self.dir, "policy.json")
        self.status = os.path.join(self.dir, "status.json")
        Path(self.policy).write_text(json.dumps(
            {"hosts": ["allowed.example"]}))

    def argv(self, *extra):
        return ["customs-resolve", "--name", "demo", "--address", ADDRESS,
                "--policy", self.policy, "--status", self.status, *extra]

    def test_a_query_is_answered_and_counted_into_the_status_file(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind(("127.0.0.1", 0))
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(client.close)
        client.settimeout(5)
        seen = {}

        def poke():
            for name in ("allowed.example", "exfil.example"):
                client.sendto(query(name, TYPE_A), sock.getsockname())
                seen[name] = Reply(client.recv(512))
            os.kill(os.getpid(), signal.SIGTERM)

        saved = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, saved)
        with mock.patch.object(self.mod, "inherited_listening_sockets",
                               return_value=[sock]):
            threading.Thread(target=poke, daemon=True).start()
            rc = self.mod.main(self.argv())
        self.assertEqual(rc, 0)
        self.assertEqual(seen["exfil.example"].addresses(), [ADDRESS])
        status = json.loads(Path(self.status).read_text())
        self.assertEqual(status["queries"]["synthesised"], 2)
        self.assertEqual(status["unlisted_names"], {"exfil.example": 1})

    def test_the_policy_is_the_inspectors_reader(self):
        """Read by inspect_policy.load_policy, so a document the inspector
        refuses is refused here too, and `admits` is the inspector's."""
        lists = load_policy(self.policy)
        self.assertTrue(lists.admits("allowed.example"))
        Path(self.policy).write_text("{")
        with mock.patch("sys.stderr"):
            self.assertEqual(self.mod.main(self.argv()), 1)

    def test_an_address_of_the_wrong_family_is_refused(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(self.mod.main(
                ["customs-resolve", "--name", "demo", "--address", ADDRESS6,
                 "--policy", self.policy, "--status", self.status]), 2)
            self.assertEqual(self.mod.main(self.argv("--address6", ADDRESS)),
                             2)
            self.assertEqual(self.mod.main(self.argv("--address6", "x")), 2)

    def test_no_activation_environment_is_a_refusal_not_a_bind(self):
        with mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch("sys.stderr") as err:
            self.assertEqual(self.mod.main(self.argv()), 1)
        written = "".join(c.args[0] for c in err.write.call_args_list)
        self.assertIn("LISTEN_PID", written)
        self.assertIn("nothing redirects to", written)

    def test_no_sockets_is_a_refusal(self):
        with mock.patch.object(self.mod, "inherited_listening_sockets",
                               return_value=[]), \
                mock.patch("sys.stderr"):
            self.assertEqual(self.mod.main(self.argv()), 1)

    def test_another_processes_activation_environment_is_refused(self):
        env = {"LISTEN_PID": str(os.getpid() + 1), "LISTEN_FDS": "2"}
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(NotSocketActivated):
                self.mod.inherited_listening_sockets()


if __name__ == "__main__":
    unittest.main()
