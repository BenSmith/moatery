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

Ported with the responder from workloadctl's tests/test_vm_resolve.py.
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

from customs import resolve_serve
from customs import resolve_wire
from customs.inspect_policy import load_policy
from customs.resolve_policy import RESOLVE_TTL, Policy, load_static
from customs.sd_listen import NotSocketActivated
from tests import REPO_ROOT, load_script
from tests.test_closure import RESOLVER, _closure, _lib_modules

TYPE_A = 1
TYPE_AAAA = 28
TYPE_MX = 15
TYPE_TXT = 16
TYPE_SVCB = 64
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
    bindings: build_answer logs through resolve_wire's name, the serve loop
    through the copy it imported."""
    logged = []
    resolve_wire.log = resolve_serve.log = logged.append
    return logged


def _admits(*patterns):
    """An inspector policy's `admits`, over `hosts` alone."""
    from customs.inspect_document import hostname_match
    return lambda name: hostname_match(name, patterns)


def _policy(address6=ADDRESS6, admits=None, static=None):
    return Policy(ADDRESS, address6, admits=admits or _admits(),
                  static=static)


def _answer(policy, *args, **kwargs):
    return Reply(resolve_wire.build_answer(query(*args, **kwargs), policy))


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
        raw = resolve_wire.build_answer(
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


class TestStaticMap(unittest.TestCase):
    """A name in --static is answered from it, never synthesised."""

    @classmethod
    def setUpClass(cls):
        cls.logged = _silenced_log()
        cls.policy = _policy(static={
            "git.local": ["192.0.2.9"],
            "dual.local": ["192.0.2.10", "2001:db8::10"],
        })

    def test_a_static_name_wins_over_synthesis(self):
        """A destination past the inspector, on a port it does not serve,
        hangs at the synthesised address instead of being refused."""
        self.assertEqual(_answer(self.policy, "git.local", TYPE_A).addresses(),
                         ["192.0.2.9"])

    def test_a_name_not_in_the_map_is_still_synthesised(self):
        self.assertEqual(
            _answer(self.policy, "elsewhere.example", TYPE_A).addresses(),
            [ADDRESS])

    def test_the_map_wins_completely_for_a_family_it_lacks(self):
        """git.local has no v6 address, so AAAA is NODATA, not the
        synthesised address: that would send a dual-stack client to the
        listener that does not serve its port."""
        reply = _answer(self.policy, "git.local", TYPE_AAAA)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.ancount, 0)

    def test_a_name_with_no_addresses_is_nodata_in_both_families(self):
        """Listed with nothing to answer, it is still not synthesised."""
        policy = _policy(static={"gone.local": []})
        for qtype in (TYPE_A, TYPE_AAAA):
            reply = _answer(policy, "gone.local", qtype)
            self.assertEqual((reply.rcode, reply.ancount), (0, 0))

    def test_a_dual_stack_name_answers_each_family_from_the_map(self):
        self.assertEqual(
            _answer(self.policy, "dual.local", TYPE_A).addresses(),
            ["192.0.2.10"])
        self.assertEqual(
            _answer(self.policy, "dual.local", TYPE_AAAA).addresses(),
            ["2001:db8::10"])

    def test_the_lookup_is_case_insensitive(self):
        """Some resolvers randomise the case of a query (0x20), so a
        case-sensitive lookup misses for exactly those, intermittently."""
        for spelling in ("GIT.local", "Git.Local", "git.LOCAL"):
            self.assertEqual(
                _answer(self.policy, spelling, TYPE_A).addresses(),
                ["192.0.2.9"], spelling)

    def test_a_map_key_is_normalised(self):
        policy = _policy(static={"GIT.Local.": ["192.0.2.9"]})
        self.assertEqual(_answer(policy, "git.local", TYPE_A).addresses(),
                         ["192.0.2.9"])

    def test_a_static_name_is_on_a_list(self):
        """The workload's filter admits it, so a query for it is not the
        signature `unlisted` counts, though no inspector list names it."""
        counters = resolve_serve.Counters()
        resolve_wire.build_answer(query("git.local", TYPE_A), self.policy,
                                  counters=counters)
        snap = counters.snapshot()
        self.assertEqual(snap["unlisted"], 0)
        self.assertEqual(snap["queries"]["static"], 1)
        self.assertEqual(snap["queries"]["synthesised"], 0)

    def test_a_static_answer_with_no_record_is_counted_static(self):
        counters = resolve_serve.Counters()
        resolve_wire.build_answer(query("git.local", TYPE_AAAA), self.policy,
                                  counters=counters)
        self.assertEqual(counters.snapshot()["queries"]["static"], 1)
        self.assertEqual(counters.snapshot()["queries"]["nodata"], 0)

    def test_the_source_is_logged(self):
        self.logged.clear()
        _answer(self.policy, "git.local", TYPE_A)
        self.assertEqual(self.logged,
                         ["  git.local A -> static: 1 record(s)"])


class TestLoadStatic(unittest.TestCase):
    """The file --static names is refused whole at start, so a bad entry
    stops the responder rather than SERVFAILing its name on every query."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "static.json")

    def load(self, document):
        Path(self.path).write_text(json.dumps(document))
        return load_static(self.path)

    def test_a_map_loads_with_canonical_addresses(self):
        self.assertEqual(
            self.load({"git.local": ["192.0.2.9", "2001:DB8:0::9"]}),
            {"git.local": ["192.0.2.9", "2001:db8::9"]})

    def test_an_empty_map_loads(self):
        self.assertEqual(self.load({}), {})

    def test_what_is_refused(self):
        for document in (["git.local"],
                         {"git.local": "192.0.2.9"},
                         {"git.local": ["not-an-ip"]},
                         {"git.local": [5]},
                         {"git.local": [None]}):
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    self.load(document)

    def test_the_refusal_names_the_entry(self):
        with self.assertRaisesRegex(ValueError, "git.local"):
            self.load({"git.local": ["not-an-ip"]})


class TestUdpBudget(unittest.TestCase):
    """The one answer that sets the truncate bit, and the retry it
    invites."""

    @classmethod
    def setUpClass(cls):
        cls.logged = _silenced_log()
        # More v4 addresses than fit in 512 bytes at 16 bytes a record.
        cls.policy = _policy(static={
            "many.local": [f"192.0.2.{n}" for n in range(1, 60)]})

    def test_a_synthesised_answer_never_truncates(self):
        reply = Reply(resolve_wire.build_answer(
            query("example.com", TYPE_A), self.policy,
            budget=resolve_wire.UDP_BUDGET))
        self.assertFalse(reply.tc)

    def test_an_oversized_answer_truncates_rather_than_being_clipped(self):
        """What does not fit is dropped with the bit set, which sends the
        client to TCP. Dropped quietly, the answer is partial and the
        client cannot know it."""
        reply = Reply(resolve_wire.build_answer(
            query("many.local", TYPE_A), self.policy,
            budget=resolve_wire.UDP_BUDGET))
        self.assertTrue(reply.tc)
        self.assertLess(reply.ancount, 59)
        self.assertEqual(len(reply.addresses()), reply.ancount)
        self.assertLessEqual(len(reply.raw), resolve_wire.UDP_BUDGET)

    def test_tcp_carries_the_whole_answer(self):
        reply = Reply(resolve_wire.build_answer(query("many.local", TYPE_A),
                                                self.policy))
        self.assertFalse(reply.tc)
        self.assertEqual(reply.ancount, 59)

    def test_the_udp_path_passes_the_budget(self):
        """The bound lives in build_answer, and only the datagram path
        can apply it; without it the kernel sends what it likes."""
        sock = _OneDatagram(query("many.local", TYPE_A))
        resolve_serve.serve_datagram(sock, self.policy)
        reply = Reply(sock.sent)
        self.assertTrue(reply.tc)
        self.assertLessEqual(len(reply.raw), resolve_wire.UDP_BUDGET)


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
        with_opt = resolve_wire.build_answer(
            query("example.com", TYPE_A, opt=True), self.policy)
        without = resolve_wire.build_answer(
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
            Reply(resolve_wire.build_answer(raw, self.policy)).rcode, 1)

    def test_a_compression_pointer_in_the_question_is_refused(self):
        raw = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        raw += b"\xc0\x0c" + struct.pack("!HH", TYPE_A, CLASS_IN)
        with self.assertRaises(resolve_wire.Malformed):
            resolve_wire.build_answer(raw, self.policy)

    def test_a_name_ending_exactly_at_the_message_boundary_is_refused(self):
        """Found by the fuzz in workloadctl, pinned here. Without read_name's
        end-of-message guard it is an IndexError, which the loop does not
        catch, and the workload's only nameserver exits on one packet."""
        raw = bytes.fromhex("00010100000100000000b9000100")
        with self.assertRaises(resolve_wire.Malformed):
            resolve_wire.build_answer(raw, self.policy)

    def test_a_truncated_header_is_refused(self):
        with self.assertRaises(resolve_wire.Malformed):
            resolve_wire.build_answer(b"\x12\x34", self.policy)

    def test_a_name_running_past_the_message_is_refused(self):
        raw = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x09abc"
        with self.assertRaises(resolve_wire.Malformed):
            resolve_wire.build_answer(raw, self.policy)

    def test_a_question_without_type_and_class_is_refused(self):
        raw = (struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
               + encode_name("example.com") + b"\x00")
        with self.assertRaises(resolve_wire.Malformed):
            resolve_wire.build_answer(raw, self.policy)

    def test_a_response_is_not_answered(self):
        """Its own FORMERR would be a response too, so an error reply is
        no way out of a loop; there is no reply at all."""
        raw = bytearray(query("example.com", TYPE_A))
        raw[2] |= 0x80
        with self.assertRaises(resolve_wire.NotAQuery):
            resolve_wire.build_answer(bytes(raw), self.policy)
        answered = resolve_wire.build_answer(query("example.com", TYPE_A),
                                         self.policy)
        with self.assertRaises(resolve_wire.NotAQuery):
            resolve_wire.build_answer(answered, self.policy)

    def test_an_error_response_carries_the_queried_id(self):
        raw = resolve_wire.error_response(
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

    _forged = "evil\n  allowed.example A -> synthesised: 1 record(s)"

    def setUp(self):
        self.logged = _silenced_log()
        self.policy = _policy(admits=_admits("allowed.example"))

    def test_a_label_with_a_newline_is_malformed(self):
        with self.assertRaises(resolve_wire.Malformed):
            resolve_wire.build_answer(query(self._forged, TYPE_A), self.policy)

    def test_it_is_refused_before_it_is_logged_or_counted(self):
        counters = resolve_serve.Counters()
        with self.assertRaises(resolve_wire.Malformed):
            resolve_wire.build_answer(query(self._forged, TYPE_A), self.policy,
                                  counters=counters)
        self.assertEqual(self.logged, [])
        self.assertEqual(counters.snapshot()["unlisted_names"], {})

    def test_the_forged_text_appears_in_no_line_the_responder_writes(self):
        """serve_datagram logs the refusal itself, so the property has to
        hold over that path too."""
        sock = _OneDatagram(query(self._forged, TYPE_A))
        counters = resolve_serve.Counters()
        resolve_serve.serve_datagram(sock, self.policy, counters=counters)
        self.assertEqual(Reply(sock.sent).rcode, 1)
        self.assertEqual(counters.snapshot()["queries"]["malformed"], 1)
        self.assertTrue(self.logged)
        for line in self.logged:
            self.assertNotIn("evil", line)
            self.assertNotIn("\n", line)

    def test_every_control_character_goes_with_the_newline(self):
        for ch in ("\n", "\r", "\x00", "\x7f", "\t", "\x1b"):
            with self.subTest(ch=ch):
                with self.assertRaises(resolve_wire.Malformed):
                    resolve_wire.build_answer(
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
        counters = resolve_serve.Counters()
        with mock.patch.object(resolve_serve, "build_answer",
                               side_effect=ZeroDivisionError("boom")):
            resolve_serve.serve_datagram(sock, _policy(), counters=counters)
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
        self.response = resolve_wire.build_answer(
            query("example.com", TYPE_A), _policy())
        self.logged.clear()

    def test_over_udp(self):
        sock = _OneDatagram(self.response)
        counters = resolve_serve.Counters()
        resolve_serve.serve_datagram(sock, _policy(), counters=counters)
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
        resolve_serve.handle_stream(near, _policy(),
                                     deadline=time.monotonic() + 2)
        replies = b""
        while chunk := far.recv(4096):
            replies += chunk
        (length,) = struct.unpack("!H", replies[:2])
        self.assertEqual(len(replies), 2 + length)
        self.assertEqual(Reply(replies[2:]).id, 0x4242)


class TestNoUpstream(unittest.TestCase):
    """The property that closes DNS rather than filtering it."""

    # The program is the entrypoint and every module in its closure, as
    # test_closure computes it. A list kept by hand would pass while a
    # module it missed grew a fallback.
    @staticmethod
    def _responder_files():
        mods = _lib_modules()
        return [RESOLVER] + sorted(mods[m] for m in _closure(RESOLVER, mods))

    @staticmethod
    def _tree(path):
        return ast.parse(Path(path).read_text())

    def test_the_scan_reads_the_whole_closure(self):
        names = [p.name for p in self._responder_files()]
        self.assertIn("customs-resolve", names)
        self.assertIn("inspect_policy.py", names)
        self.assertEqual(len(names), 8)

    def test_the_responder_never_calls_out(self):
        """Parsed, not grepped: the words appear in the prose saying no
        such call is made. If a "fallback for names we don't serve" is ever
        added, this fails, since the fallback is the channel."""
        forbidden = {
            "connect", "connect_ex", "create_connection", "getaddrinfo",
            "gethostbyname", "gethostbyname_ex", "getnameinfo", "urlopen",
        }
        for path in self._responder_files():
            with self.subTest(file=path.name):
                called = set()
                for node in ast.walk(self._tree(path)):
                    if isinstance(node, ast.Call):
                        func = node.func
                        name = (func.attr if isinstance(func, ast.Attribute)
                                else getattr(func, "id", None))
                        if name:
                            called.add(name)
                self.assertEqual(sorted(called & forbidden), [])

    def _socket_constructions(self, path):
        return [node for node in ast.walk(self._tree(path))
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "socket"]

    def test_the_program_constructs_no_socket_at_all(self):
        for path in self._responder_files():
            if path.name == "sd_listen.py":
                continue
            with self.subTest(file=path.name):
                found = self._socket_constructions(path)
                self.assertEqual(found, [], [ast.unparse(c) for c in found])

    def test_the_shared_constructor_only_adopts_an_inherited_fd(self):
        """sd_listen's socket.socket() appears once, with `fileno=` alone.
        Without it the call would create a socket; it is the one module
        of the closure the test above leaves to this one."""
        found = self._socket_constructions(
            Path(REPO_ROOT) / "customs" / "sd_listen.py")
        self.assertEqual(len(found), 1, [ast.unparse(c) for c in found])
        self.assertEqual([kw.arg for kw in found[0].keywords], ["fileno"])
        self.assertEqual(found[0].args, [])

    def test_the_only_socket_call_is_address_formatting(self):
        self.assertEqual(resolve_wire.pack_address("192.0.2.1"),
                         b"\xc0\x00\x02\x01")
        self.assertEqual(len(resolve_wire.pack_address("2001:db8::1")), 16)


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
            resolve_serve.serve_datagram(server, self.policy)
            raw, _peer = client.recvfrom(4096)
        self.assertEqual(Reply(raw).addresses(), [ADDRESS])

    def test_a_tcp_connection_carries_more_than_one_query(self):
        """RFC 7766 clients reuse the connection."""
        listener, address = self._listener()
        with socket.create_connection(address, timeout=5) as client:
            resolve_serve.serve_stream(listener, self.policy)
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
            resolve_serve.serve_stream(listener, self.policy)
            self.assertLess(time.monotonic() - started,
                            resolve_serve.TCP_IDLE_TIMEOUT / 2)

    def test_a_dribbling_peer_is_ended_by_the_lifetime(self):
        """A length prefix promising more than will arrive. The deadline is
        checked before every recv, not once per message."""
        near, far = socket.socketpair()
        self.addCleanup(far.close)
        payload = query("example.com", TYPE_A)
        far.sendall(struct.pack("!H", len(payload) + 64) + payload)
        started = time.monotonic()
        resolve_serve.handle_stream(near, self.policy,
                                     deadline=time.monotonic() + 0.3)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0)
        self.assertGreaterEqual(elapsed, 0.2)

    def test_a_peer_pipelining_forever_is_ended_by_the_lifetime(self):
        near, far = socket.socketpair()
        self.addCleanup(far.close)
        payload = query("example.com", TYPE_A)
        far.sendall((struct.pack("!H", len(payload)) + payload) * 50)
        resolve_serve.handle_stream(near, self.policy,
                                     deadline=time.monotonic() + 0.3)
        self.assertTrue(far.recv(2))

    def test_connections_past_the_ceiling_are_closed_not_queued(self):
        listener, address = self._listener()
        slots = resolve_serve._TcpSlots(limit=1)
        clients = []
        for _ in range(2):
            client = socket.create_connection(address, timeout=5)
            self.addCleanup(client.close)
            clients.append(client)
            resolve_serve.serve_stream(listener, self.policy, slots=slots)
        payload = query("example.com", TYPE_A)
        clients[1].sendall(struct.pack("!H", len(payload)) + payload)
        self.assertEqual(clients[1].recv(4096), b"")
        self.assertEqual(TestOnTheWire._ask(clients[0],
                                            "example.com").addresses(),
                         [ADDRESS])

    def test_a_finished_connection_gives_its_slot_back(self):
        listener, address = self._listener()
        slots = resolve_serve._TcpSlots(limit=1)
        for _ in range(3):
            with socket.create_connection(address, timeout=5) as client:
                resolve_serve.serve_stream(listener, self.policy,
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
        counters = resolve_serve.Counters()
        errors = []

        def hammer():
            try:
                for _ in range(2000):
                    counters.record_answer("a.example", "synthesised", 1, False)
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
        # More addresses than fit a UDP answer, in both families, so the
        # packing and the budget are on the fuzz's path and not skipped by
        # a one-record answer.
        cls.policy = _policy(static={
            "git.local": [f"192.0.2.{n}" for n in range(1, 60)]
                         + [f"2001:db8::{n}" for n in range(1, 40)]})

    @staticmethod
    def _corpus():
        names = ("git.local", "example.com", "", "a" * 63 + ".com",
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
        for i in range(self.ITERATIONS):
            data = self._mutate(rng, corpus)
            budget = resolve_wire.UDP_BUDGET if i % 2 else None
            try:
                reply = resolve_wire.build_answer(data, self.policy,
                                                  budget=budget)
            except (resolve_wire.Malformed, resolve_wire.NotAQuery):
                continue
            except Exception as exc:  # noqa: BLE001
                self.fail(f"{type(exc).__name__}: {exc} on {data.hex()}")
            self.assertGreaterEqual(len(reply), 12, data.hex())
            self.assertTrue(struct.unpack("!H", reply[2:4])[0] & 0x8000,
                            data.hex())
            self.assertEqual(reply[:2], data[:2], data.hex())
            if budget is not None:
                self.assertLessEqual(len(reply), budget, data.hex())


class TestCounters(unittest.TestCase):
    """`unlisted` is the figure that is not a health metric: evidence that
    something is trying, never that anything left."""

    def setUp(self):
        self.logged = _silenced_log()
        self.policy = _policy(admits=_admits("allowed.example",
                                             "*.ok.example"))
        self.counters = resolve_serve.Counters()

    def answer(self, *args, **kwargs):
        return resolve_wire.build_answer(query(*args, **kwargs), self.policy,
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

    def test_https_and_svcb_are_counted_apart(self):
        """The one sign in-process of a client that would take HTTP/3 or
        ECH if offered: QUIC itself is dropped in the kernel."""
        self.answer("a.example", TYPE_HTTPS)
        self.answer("_dns.a.example", TYPE_SVCB)
        self.answer("a.example", TYPE_MX)
        snap = self.counters.snapshot()
        self.assertEqual(snap["https"], 2)
        self.assertEqual(snap["queries"]["nodata"], 3)

    def test_a_nodata_question_is_logged_with_its_type(self):
        self.logged.clear()
        self.answer("a.example", TYPE_HTTPS)
        self.answer("a.example", 99)
        self.answer("version.bind", TYPE_TXT, qclass=CLASS_CH)
        self.assertEqual(self.logged, [
            "  a.example HTTPS -> nodata",
            "  a.example TYPE99 -> nodata",
            "  version.bind TXT CLASS3 -> nodata"])

    def test_an_aaaa_with_no_v6_address_is_nodata(self):
        policy = _policy(address6=None, admits=_admits("allowed.example"))
        resolve_wire.build_answer(query("allowed.example", TYPE_AAAA), policy,
                              counters=self.counters)
        snap = self.counters.snapshot()
        self.assertEqual(snap["queries"], {"synthesised": 0, "static": 0,
                                           "nodata": 1, "malformed": 0})

    def test_the_unlisted_name_map_is_bounded(self):
        for i in range(200):
            self.answer(f"h{i}.attacker.example", TYPE_A)
        snap = self.counters.snapshot()
        self.assertLessEqual(len(snap["unlisted_names"]), 21)
        self.assertEqual(snap["unlisted"], 200)

    def test_counters_are_optional_and_the_bytes_do_not_change(self):
        self.assertEqual(self.answer("allowed.example", TYPE_A),
                         resolve_wire.build_answer(query("allowed.example",
                                                     TYPE_A), self.policy))

    def test_the_names_are_logged_with_their_type(self):
        self.answer("allowed.example", TYPE_A)
        self.answer("elsewhere.example", TYPE_AAAA)
        self.assertEqual(self.logged,
                         ["  allowed.example A -> synthesised: 1 record(s)",
                          "  elsewhere.example AAAA -> synthesised: "
                          "1 record(s)"])


class TestStatusFile(unittest.TestCase):

    def setUp(self):
        self.logged = _silenced_log()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "resolve-status.json")

    def test_it_writes_the_counters(self):
        counters = resolve_serve.Counters()
        counters.record_answer("a.example", "synthesised", 1, True)
        resolve_serve.emit_status(self.path, counters)
        doc = json.loads(Path(self.path).read_text())
        self.assertEqual(doc["queries"]["synthesised"], 1)
        self.assertIn("written_at", doc)

    def test_an_unwritable_path_never_takes_the_responder_down(self):
        resolve_serve.emit_status(
            os.path.join(self.dir, "no", "such", "s.json"),
            resolve_serve.Counters())

    def test_an_unserialisable_counter_never_takes_the_responder_down(self):
        counters = resolve_serve.Counters()
        counters.snapshot = lambda: {"later": object()}
        resolve_serve.emit_status(self.path, counters)
        self.assertFalse(Path(self.path).exists())

    def test_the_loop_writes_before_the_first_query(self):
        """Observed at the loop's first turn: serve writes again on its way
        out, so the file existing afterwards proves nothing."""
        seen = []

        def stop():
            seen.append(Path(self.path).exists())
            return True

        resolve_serve.serve([], _policy(), resolve_serve.Counters(),
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

    def test_usr1_reads_the_policy_again(self):
        """A name counted as unlisted is not once the reloaded policy
        admits it; a document that does not load keeps the one loaded."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind(("127.0.0.1", 0))
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(client.close)
        client.settimeout(5)

        def ask(name):
            client.sendto(query(name, TYPE_A), sock.getsockname())
            client.recv(512)

        def reload(text, words):
            Path(self.policy).write_text(text)
            os.kill(os.getpid(), signal.SIGUSR1)
            deadline = time.monotonic() + 5
            while (not any(words in line for line in self.logged)
                   and time.monotonic() < deadline):
                time.sleep(0.01)

        def poke():
            ask("new.example")
            reload("{", "not reloaded")
            ask("new.example")
            reload(json.dumps({"hosts": ["new.example"]}), "reloaded from")
            ask("new.example")
            os.kill(os.getpid(), signal.SIGTERM)

        for sig in (signal.SIGTERM, signal.SIGUSR1):
            self.addCleanup(signal.signal, sig, signal.getsignal(sig))
        with mock.patch.object(self.mod, "inherited_listening_sockets",
                               return_value=[sock]):
            threading.Thread(target=poke, daemon=True).start()
            rc = self.mod.main(self.argv())
        self.assertEqual(rc, 0)
        status = json.loads(Path(self.status).read_text())
        self.assertEqual(status["unlisted_names"], {"new.example": 2})

    def test_a_usr1_before_the_handler_is_ignored(self):
        """The unit may be reloaded while the policy is being read, and
        USR1's default would end the process."""
        self.addCleanup(signal.signal, signal.SIGUSR1,
                        signal.getsignal(signal.SIGUSR1))
        Path(self.policy).write_text("{")
        with mock.patch("sys.stderr"):
            self.assertEqual(self.mod.main(self.argv()), 1)
        self.assertEqual(signal.getsignal(signal.SIGUSR1), signal.SIG_IGN)

    def test_a_static_name_is_answered_from_the_file(self):
        static = os.path.join(self.dir, "static.json")
        Path(static).write_text(json.dumps({"git.local": ["192.0.2.9"]}))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind(("127.0.0.1", 0))
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(client.close)
        client.settimeout(5)
        seen = []

        def poke():
            client.sendto(query("git.local", TYPE_A), sock.getsockname())
            seen.append(Reply(client.recv(512)))
            os.kill(os.getpid(), signal.SIGTERM)

        saved = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, saved)
        with mock.patch.object(self.mod, "inherited_listening_sockets",
                               return_value=[sock]):
            threading.Thread(target=poke, daemon=True).start()
            rc = self.mod.main(self.argv("--static", static))
        self.assertEqual(rc, 0)
        self.assertEqual(seen[0].addresses(), ["192.0.2.9"])
        status = json.loads(Path(self.status).read_text())
        self.assertEqual(status["queries"]["static"], 1)
        self.assertEqual(status["unlisted"], 0)

    def test_a_bad_static_file_is_refused_at_start(self):
        static = os.path.join(self.dir, "static.json")
        for text in ("{", '{"git.local": ["not-an-ip"]}'):
            Path(static).write_text(text)
            with self.subTest(text=text), mock.patch("sys.stderr") as err, \
                    mock.patch.object(self.mod, "inherited_listening_sockets",
                                      return_value=[object()]):
                self.assertEqual(self.mod.main(self.argv("--static", static)),
                                 1)
            written = "".join(c.args[0] for c in err.write.call_args_list)
            self.assertIn(static, written)

    def test_a_missing_static_file_is_refused_at_start(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(self.mod.main(self.argv(
                "--static", os.path.join(self.dir, "absent.json"))), 1)

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
