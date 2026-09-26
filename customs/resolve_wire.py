"""The DNS wire format the synthesising responder speaks.

build_answer is bytes in, bytes out, with no I/O behind it, so the tests
can feed it garbage in bulk. It contains no call that could reach a
nameserver: pack_address is inet_pton, never getaddrinfo, and
tests/test_resolve.py parses this file to keep it that way.
"""

import socket
import struct

from .inspect_document import hostname_control_character, normalise_hostname

FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_RA = 0x0080
OPCODE_MASK = 0x7800
OPCODE_QUERY = 0

RCODE_NOERROR = 0
RCODE_FORMERR = 1
# The query was fine and this program was not: see serve_datagram.
RCODE_SERVFAIL = 2
RCODE_NOTIMP = 4

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1

HEADER = struct.Struct("!HHHHHH")
HEADER_LEN = HEADER.size

# The classic UDP message size. A synthesised answer is one record, well
# inside it; a static name with many addresses is not, and what does not
# fit is dropped with the truncate bit set, which sends the client to TCP.
# A datagram is read into four times as much.
UDP_BUDGET = 512

# Bound on one TCP message, which carries its own 16-bit length prefix. A
# query is a question and an optional OPT; anything near this is not one.
TCP_MAX = 4096


class Malformed(Exception):
    """The query could not be parsed far enough to answer it."""


class NotAQuery(Exception):
    """The message is a response. It gets no reply, not even an error: a
    responder that answers responses talks forever with another one, or
    with itself given its own address as the source.
    """


def log(msg):
    print(msg, flush=True)


def read_name(msg, offset):
    """Read a QNAME. Returns (name, next_offset).

    A compression pointer is refused, not followed: in a question there is
    nothing earlier for it to point at, and following one is how a peer
    that controls every byte walks a parser into a loop.
    """
    labels = []
    while True:
        if offset >= len(msg):
            raise Malformed("name runs past the end of the message")
        length = msg[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise Malformed("compression pointer in the question section")
        end = offset + length
        if end > len(msg):
            raise Malformed("label runs past the end of the message")
        labels.append(msg[offset:end])
        offset = end
    try:
        name = ".".join(label.decode("ascii") for label in labels)
    except UnicodeDecodeError:
        raise Malformed("non-ASCII label") from None
    # A label may carry any byte, a bare LF included, and this name is
    # logged and written into the status file, where an LF starts a second
    # record the workload wrote. The character is named and the name is not.
    ch = hostname_control_character(name)
    if ch is not None:
        raise Malformed(
            f"label carries the control character {ch!r}, which forges a "
            f"line in this log")
    return normalise_hostname(name), offset


def pack_address(text):
    """Wire form of an address literal, without a name-resolution call.

    inet_pton, never getaddrinfo: this program must contain no call that
    could consult a resolver, and getaddrinfo on a literal is still that
    call.
    """
    if ":" in text:
        return socket.inet_pton(socket.AF_INET6, text)
    return socket.inet_pton(socket.AF_INET, text)


def build_answer(query, policy, budget=None, counters=None):
    """The response to one query, as the full message.

    `budget` bounds the message, for UDP; None is unbounded, for TCP.
    `counters` is optional, and a response is never shaped by whether
    anyone is counting.
    """
    if len(query) < HEADER_LEN:
        raise Malformed("shorter than a DNS header")
    ident, flags, qdcount, _an, _ns, _ar = HEADER.unpack(query[:HEADER_LEN])
    if flags & FLAG_QR:
        raise NotAQuery()

    # The opcode echoed and RD preserved. RA is set because, from the
    # client's side, recursion is available: every name is answered, with
    # no referral. A stub that sees RD honoured with RA clear can decide
    # the server is no use for recursion, and it has no other.
    opcode = flags & OPCODE_MASK
    base = FLAG_QR | opcode | FLAG_AA | FLAG_RA | (flags & FLAG_RD)

    if opcode != (OPCODE_QUERY << 11):
        # An UPDATE or a NOTIFY is not a question about a name, so no empty
        # answer means anything.
        return HEADER.pack(ident, base | RCODE_NOTIMP, 0, 0, 0, 0)
    if qdcount != 1:
        return HEADER.pack(ident, base | RCODE_FORMERR, 0, 0, 0, 0)

    name, offset = read_name(query, HEADER_LEN)
    if offset + 4 > len(query):
        raise Malformed("question is missing its type and class")
    qtype, qclass = struct.unpack("!HH", query[offset:offset + 4])
    question = query[HEADER_LEN:offset + 4]

    # Everything past the question, an OPT included, is not read, and no
    # OPT is emitted: the shape that cannot echo a malformed one back.

    if qclass != CLASS_IN or qtype not in (TYPE_A, TYPE_AAAA):
        # NODATA: NOERROR, the question echoed, no records. HTTPS, SVCB,
        # TXT, PTR, MX, SRV and a CHAOS-class version.bind land here.
        if counters is not None:
            counters.record_nodata()
        return HEADER.pack(ident, base | RCODE_NOERROR, 1, 0, 0, 0) + question

    addresses, source = policy.answers(name, qtype)
    records = bytearray()
    count = 0
    truncated = False
    for text in addresses:
        rdata = pack_address(text)
        # 0xC00C: the answer's name as a pointer to the question's, which is
        # at offset 12 in every message built here.
        record = struct.pack("!HHHIH", 0xC00C, qtype, CLASS_IN,
                             policy.ttl, len(rdata)) + rdata
        if budget is not None and \
                HEADER_LEN + len(question) + len(records) + len(record) \
                > budget:
            truncated = True
            break
        records += record
        count += 1

    if counters is not None:
        counters.record_answer(name, source, count, policy.on_a_list(name))
    log(f"  {name or '.'} {'AAAA' if qtype == TYPE_AAAA else 'A'} -> "
        f"{source}: {count} record(s)"
        + (" (truncated; retry over TCP)" if truncated else ""))
    flags_out = base | RCODE_NOERROR | (FLAG_TC if truncated else 0)
    return (HEADER.pack(ident, flags_out, 1, count, 0, 0)
            + question + bytes(records))


def error_response(query, rcode):
    """A header-only reply, for a query too malformed to echo. The caller
    drops a query of under two bytes, which has no id to reply to."""
    ident = struct.unpack("!H", query[:2])[0]
    return HEADER.pack(ident, FLAG_QR | rcode, 0, 0, 0, 0)
