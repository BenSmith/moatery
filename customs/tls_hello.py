"""
Reading a server name out of a TLS ClientHello, and no more.

Enough of RFC 8446 §4.1.2 to read the server name and the ALPN offer, and see
which extensions are present. It is not a TLS implementation and must not
become one: every field it does not need is skipped by its length, so an
extension shape it has never seen costs it nothing.

The hello is PEEKED, never consumed. A terminated connection's hello must
still be on the socket for ssl's wrap_socket, and a spliced one is relayed
from the socket unchanged, so neither path wants the bytes taken off it. A
peek is bounded by the receive buffer, which CLIENTHELLO_MAX sits well
inside.
"""

import socket
import time
from typing import NamedTuple

from .inspect_document import (
    hostname_bad_character, hostname_control_character, normalise_hostname,
)

# The ceiling on a ClientHello, in bytes. A post-quantum one spans more
# than a segment and is nowhere near this; the bound is there because every
# length in the hello is the guest's.
CLIENTHELLO_MAX = 16384

# How long a peek that found nothing new waits before asking again, in
# seconds. Under a socket timeout MSG_WAITALL does not wait, and a hello
# larger than one segment is often peeked between its segments, so no
# progress means wait. The socket's timeout bounds the whole hello.
PEEK_POLL = 0.01

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_EXT_SERVER_NAME = 0x0000
TLS_SNI_HOST_NAME = 0x00
TLS_EXT_ALPN = 0x0010

# How many of the protocols an ALPN offer names are kept. A client offers
# two or three; the rest of a longer list is the guest's to fill.
ALPN_KEPT = 8

# RFC 9460 encrypted_client_hello, read by the ECH figures and the splice
# refusal; the parser skips it by its length like any other extension.
TLS_EXT_ECH = 0xfe0d


class HelloUnreadable(Exception):
    """The first bytes are not a ClientHello this can read a name out of.

    Counted apart from a name that is not allowlisted: something that is not
    TLS on the TLS port is the tunnelling signature. This class itself is a
    hello that arrived and does not parse.
    """


class HelloNotTls(HelloUnreadable):
    """The first bytes are not a handshake record opening a ClientHello."""


class HelloIncomplete(HelloUnreadable):
    """The ClientHello did not arrive whole: the peer closed, the read
    failed, or the time ran out."""


class ClientHello(NamedTuple):
    """What the peek extracts. `server_name` is None for a hello with no
    SNI. `extensions` is every extension type in wire order, for the ECH
    figures. `alpn` is the protocols offered, in the client's order, for the
    journal and the figures: nothing is decided by it.
    """

    server_name: str
    extensions: tuple
    alpn: tuple = ()


class _Reader:
    """A length-checked cursor over a byte string. Every length is the
    peer's, and Python's slicing returns a short result silently, so a short
    read raises instead.
    """

    def __init__(self, buf):
        self._buf = buf
        self._pos = 0

    def remaining(self) -> int:
        return len(self._buf) - self._pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.remaining() < n:
            raise HelloUnreadable(
                f"a length field claims {n} bytes with {self.remaining()} "
                f"left")
        out = self._buf[self._pos:self._pos + n]
        self._pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")


def _parse_server_name(data: bytes):
    """The first host_name in a server_name extension, or None.

    Non-ASCII is refused, since a name on the wire is punycode (RFC 6066).
    So is a control character, or any character no name is spelled with,
    since this name goes into journal lines.
    """
    r = _Reader(data)
    entries = _Reader(r.take(r.u16()))
    while entries.remaining():
        kind = entries.u8()
        value = entries.take(entries.u16())
        if kind == TLS_SNI_HOST_NAME:
            try:
                name = value.decode("ascii")
            except UnicodeDecodeError:
                raise HelloUnreadable(
                    "the server_name is not ASCII, so it is not a name as "
                    "RFC 6066 puts one on the wire") from None
            ch = hostname_control_character(name)
            if ch is not None:
                # Only the character is quoted: the whole name would put
                # the injected bytes into the line.
                raise HelloUnreadable(
                    f"the server_name carries the control character {ch!r}, "
                    "which no name has and which forges a line in this log")
            ch = hostname_bad_character(normalise_hostname(name))
            if ch is not None:
                raise HelloUnreadable(
                    f"the server_name carries {ch!r}, which no host name is "
                    "spelled with")
            return name
    return None


def _parse_alpn(data: bytes) -> tuple:
    """The first ALPN_KEPT protocol names an RFC 7301 offer carries.

    Kept as text with anything outside ASCII escaped. The journal quotes
    them, since they are the guest's bytes.
    """
    r = _Reader(data)
    entries = _Reader(r.take(r.u16()))
    names = []
    while entries.remaining():
        value = entries.take(entries.u8())
        if len(names) < ALPN_KEPT:
            names.append(value.decode("ascii", "backslashreplace"))
    return tuple(names)


def parse_client_hello(msg: bytes) -> ClientHello:
    """Parse a ClientHello handshake body (the 4-byte header already stripped).

    GREASE needs no case of its own: it is a well-formed extension, skipped
    by its length. An ECH hello parses like any other and yields its cover
    name.
    """
    r = _Reader(msg)
    r.take(2)              # legacy_version
    r.take(32)             # random
    r.take(r.u8())         # legacy_session_id
    r.take(r.u16())        # cipher_suites
    r.take(r.u8())         # legacy_compression_methods
    if r.remaining() == 0:
        # No extension block, which is legal before TLS 1.3: no SNI.
        return ClientHello(None, ())
    exts = _Reader(r.take(r.u16()))
    name = None
    alpn = None
    seen = []
    while exts.remaining():
        etype = exts.u16()
        data = exts.take(exts.u16())
        seen.append(etype)
        if etype == TLS_EXT_SERVER_NAME and name is None:
            name = _parse_server_name(data)
        elif etype == TLS_EXT_ALPN and alpn is None:
            alpn = _parse_alpn(data)
    return ClientHello(name, tuple(seen), alpn or ())


def read_client_hello(conn, max_bytes=CLIENTHELLO_MAX):
    """Peek until a whole ClientHello is on the socket, and parse it.

    The handshake message is reassembled across records: a large hello (a
    post-quantum key share, say) legitimately spans more than one TLS
    record. The socket's timeout bounds the whole read, not each peek.
    """
    timeout = conn.gettimeout()
    deadline = None if timeout is None else time.monotonic() + timeout
    raw = b""
    pos = 0          # how much of `raw` has been consumed as complete records
    body = b""       # handshake bytes, record framing stripped
    want = None      # the handshake message length, once its header is in hand
    while True:
        raw = _peek_at_least(conn, raw, pos + 5, max_bytes, deadline)
        if raw[pos] != TLS_HANDSHAKE:
            raise HelloNotTls(
                f"record type 0x{raw[pos]:02x} is not a TLS handshake record")
        length = int.from_bytes(raw[pos + 3:pos + 5], "big")
        raw = _peek_at_least(conn, raw, pos + 5 + length, max_bytes, deadline)
        body += raw[pos + 5:pos + 5 + length]
        pos += 5 + length
        if want is None and len(body) >= 4:
            if body[0] != TLS_CLIENT_HELLO:
                raise HelloNotTls(
                    f"handshake type 0x{body[0]:02x} is not a ClientHello")
            want = int.from_bytes(body[1:4], "big")
        if want is not None and len(body) >= 4 + want:
            return parse_client_hello(body[4:4 + want])


def _peek_at_least(conn, raw, n, max_bytes, deadline):
    """The socket's queue from its start, once it holds at least n bytes.

    A peek that comes back no longer than `raw` is the rest of the hello not
    having arrived yet (see PEEK_POLL), and is asked again until `deadline`.
    A peer that closed mid-hello looks the same and ends the same way.
    """
    while len(raw) < n:
        if n > max_bytes:
            raise HelloUnreadable(
                f"a ClientHello over {max_bytes} bytes is not one we read")
        try:
            chunk = conn.recv(n, socket.MSG_PEEK | socket.MSG_WAITALL)
        except OSError as exc:
            raise HelloIncomplete(f"read failed: {exc}") from None
        if not chunk:
            raise HelloIncomplete("the connection closed mid-ClientHello")
        if len(chunk) <= len(raw):
            if deadline is not None and time.monotonic() >= deadline:
                raise HelloIncomplete(
                    "the ClientHello did not arrive whole in time")
            time.sleep(PEEK_POLL)
            continue
        raw = chunk
    return raw
