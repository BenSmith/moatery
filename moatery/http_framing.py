"""
http_framing: where one HTTP/1.1 message ends and the next begins, by refusal.

The framing that says where a guest's request ends is the guest's, and a
request read two ways by two parsers is a request smuggled past the one in
front of it. So where a message has two readings nothing here picks one: it
raises RequestUnreadable and the message is declined.

The request parser (`_split_head`) is strict for that reason. The response
parser (`_split_response_head`) is lenient: that head comes from an origin
the policy authorised and is read only for where its body ends. It is
relayed as it came, except for the lines RFC 9112 has a proxy repair, so
the guest reads the head this read did.
"""

import email.utils
import time
from typing import NamedTuple

# The buffer size the relay moves in each direction, in bytes.
RELAY_CHUNK = 65536


# The ceiling on a request or response head, in bytes: a peer can otherwise
# never send the blank line.
MESSAGE_HEAD_MAX = 32768


# The ceiling on one chunk-size line, in bytes.
CHUNK_LINE_MAX = 4096


# How many bytes of a method is_http_request_start waits for before deciding
# the connection is not HTTP, plus the space after it. BASELINE-CONTROL (RFC
# 3253), the longest registered method, fits. The parser still refuses what
# is not a method; this only bounds the wait.
HTTP_METHOD_MAX = 16
HTTP_START_MAX = HTTP_METHOD_MAX + 1


# How much of a refused request's body is read and discarded, in bytes. Past
# it the connection is closed instead.
DRAIN_MAX = 1 << 20


_BODYLESS_STATUSES = frozenset((204, 304))


# The largest length this relay re-emits, a Content-Length or a chunk size.
# An origin that parses a larger one into a fixed-width integer or a double
# reads another number, and the difference is read as the next request.
# 2^53 - 1 is exact in all of them.
LENGTH_MAX = (1 << 53) - 1


# The ceiling on trailer lines after a zero chunk.
MAX_TRAILER_LINES = 64


# RFC 9110 §5.6.2 tchar.
_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

# The headers that say where a message's body ends.
_FRAMING_NAMES = frozenset(("content-length", "transfer-encoding"))


class RequestUnreadable(Exception):
    """The guest's bytes are not a request we will act on. A refusal,
    never a repair."""


class ReadTimedOut(RequestUnreadable):
    """A read that reached its timeout with nothing to show for it.

    `idle` is True when the wait was for a first byte: a kept-alive
    connection with no next request, which is not a failure.
    """

    def __init__(self, message, *, idle=False):
        super().__init__(message)
        self.idle = idle


class ResetWhileIdle(RequestUnreadable):
    """A reset where a kept-alive connection waits for its next request:
    the client ending the connection without closing it, which some HTTP
    clients do after every response."""


class Framing(NamedTuple):
    """Where a message body ends. `length` is meaningful only for "length"."""

    kind: str          # "none" | "length" | "chunked" | "close"
    length: int = 0


class _Stream:
    """A socket plus the bytes already read past the end of the last message,
    which under pipelining are the start of the next request."""

    def __init__(self, sock, prefill=b""):
        self.sock = sock
        # Bytes taken off the socket before the stream existed: the upstream
        # dial's early read.
        self._buf = prefill
        self.eof = False

    def take_buffered(self):
        """Everything read past the last message, removed from this stream,
        for a connection that stops being messages (a 101)."""
        out, self._buf = self._buf, b""
        return out

    def holds_unread(self):
        """Whether bytes past the last message wait in the buffer."""
        return bool(self._buf)

    def _fill(self, timeout=None, *, idle=False):
        """One recv, appended to the buffer. False at a clean EOF.

        `timeout` overrides the socket's own for this one read. `idle` says
        the wait was for a first byte.
        """
        if timeout is not None:
            previous = self.sock.gettimeout()
            self.sock.settimeout(timeout)
        try:
            chunk = self.sock.recv(RELAY_CHUNK)
        except TimeoutError:
            # Before the OSError arm, which would catch it too.
            waited = timeout if timeout is not None else self.sock.gettimeout()
            raise ReadTimedOut(
                f"nothing was readable within {waited}s",
                idle=idle) from None
        except OSError as exc:
            if idle and isinstance(exc, ConnectionError):
                raise ResetWhileIdle(f"read failed: {exc}") from exc
            # Chained, so a TLS alert can still be told by its reason.
            raise RequestUnreadable(f"read failed: {exc}") from exc
        finally:
            if timeout is not None:
                self.sock.settimeout(previous)
        if not chunk:
            self.eof = True
            return False
        self._buf += chunk
        return True

    def read_head(self, max_bytes=MESSAGE_HEAD_MAX, idle_timeout=None):
        """A whole message head, or b"" if the peer closed cleanly first.

        The terminator is CRLFCRLF only: bare-LF line endings are what two
        parsers disagree about.

        `idle_timeout`, when given, bounds the wait for the first byte, which
        is how a kept-alive connection may sit idle between requests. From the
        first byte the socket's own timeout bounds the rest of the head as one
        wait, not each read, so a peer sending a byte at a time cannot hold
        the connection past it.
        """
        deadline = None
        while True:
            idx = self._buf.find(b"\r\n\r\n")
            if idx != -1:
                head, self._buf = self._buf[:idx + 4], self._buf[idx + 4:]
                return head
            if len(self._buf) > max_bytes:
                raise RequestUnreadable(
                    f"a message head over {max_bytes} bytes is not one we "
                    f"read")
            if not self._buf:
                got = self._fill(idle_timeout, idle=idle_timeout is not None)
            else:
                limit = self.sock.gettimeout()
                if deadline is None and limit is not None:
                    deadline = time.monotonic() + limit
                left = None
                if deadline is not None:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise ReadTimedOut(
                            f"the head did not arrive whole within {limit}s")
                got = self._fill(left)
            if not got:
                if not self._buf:
                    return b""
                raise RequestUnreadable("the connection closed mid-head")

    def read_exactly(self, n):
        while len(self._buf) < n:
            if not self._fill():
                raise RequestUnreadable("the connection closed mid-body")
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def read_line(self, max_bytes=CHUNK_LINE_MAX):
        """One CRLF-terminated line, returned without its CRLF."""
        while True:
            idx = self._buf.find(b"\r\n")
            if idx != -1:
                line, self._buf = self._buf[:idx], self._buf[idx + 2:]
                return line
            if len(self._buf) > max_bytes:
                raise RequestUnreadable(
                    f"a line over {max_bytes} bytes is not one we read")
            if not self._fill():
                raise RequestUnreadable("the connection closed mid-line")

    def read_some(self):
        if self._buf:
            out, self._buf = self._buf, b""
            return out
        if not self._fill():
            return b""
        out, self._buf = self._buf, b""
        return out

    def peek_start(self, n=HTTP_START_MAX, until=None):
        """Up to n bytes from the front of the stream, left in the buffer.

        `until` is asked after each read whether the bytes so far settle the
        question; the first True ends the wait. A short read, b"" included,
        is returned rather than raised: read_head, which runs next, has the
        dispositions for it.
        """
        while len(self._buf) < n:
            if until is not None and self._buf and until(self._buf):
                break
            try:
                if not self._fill():
                    break
            except RequestUnreadable:
                break
        return self._buf[:n]


def _reject_controls(text, what, *, tab_ok):
    """Refuse a control character in a field we will re-emit.

    A bare LF inside a field survives a CRLF split and reaches an origin
    that reads it as a line ending: a second request line, smuggled.
    Refused rather than stripped, since stripping picks a reading.
    """
    for ch in text:
        if ch == "\t" and tab_ok:
            continue
        if ch < " " or ch == "\x7f":
            raise RequestUnreadable(
                f"{what} carries the control character {ch!r}: a field with "
                "a line ending inside it is read as one field here and as two "
                "by anything that accepts bare LF")


def _split_head(head):
    """(start line, [(name, value)]) from a request head, or raise.

    Refused: non-ASCII, a control character in any field, obs-fold, and
    whitespace before a header's colon.
    """
    try:
        text = head[:-4].decode("ascii")
    except UnicodeDecodeError:
        raise RequestUnreadable(
            "the head is not ASCII, so it is not one every parser on this "
            "path would read the same way") from None
    lines = text.split("\r\n")
    _reject_controls(lines[0], "the start line", tab_ok=False)
    headers = []
    for line in lines[1:]:
        _reject_controls(line, "a header line", tab_ok=True)
        if line[:1] in (" ", "\t"):
            raise RequestUnreadable(
                "an obs-fold continuation line lets a header hide inside "
                "another header's value")
        name, sep, value = line.partition(":")
        if not sep:
            raise RequestUnreadable(f"header line {line!r} has no colon")
        if not name or any(c not in _TOKEN_CHARS for c in name):
            raise RequestUnreadable(
                f"header name {name!r} is not a token")
        headers.append((name.lower(), value.strip(" \t")))
    return lines[0], tuple(headers)


def _split_response_head(head):
    """(status line, [(name, value)], the head to relay) from a response
    head. Lenient.

    Real origins send raw UTF-8 in a filename, folded headers and names
    outside tchar, and none of it moves where the body ends, so none of it
    is refused: latin-1, a non-token name dropped. Two repairs are RFC
    9112's for a proxy, made in the head relayed so the guest reads what
    this read did: whitespace before a colon removed (§5.1), and obs-fold
    joined with a space (§5.2). A whitespace-led line before the first
    field is dropped (§2.2). Refused: a control character, which moves
    where the message ends, and a dropped line that is a framing header
    once trimmed (`Content-Length\xa0: 5`), which a guest that trims
    would frame the body by.
    """
    text = head[:-4].decode("latin-1")
    lines = text.split("\r\n")
    _reject_controls(lines[0], "the status line", tab_ok=False)
    relayed = [lines[0]]
    for line in lines[1:]:
        _reject_controls(line, "a response header line", tab_ok=True)
        if line[:1] in (" ", "\t"):
            if len(relayed) > 1:
                relayed[-1] = (relayed[-1].rstrip(" \t") + " "
                               + line.strip(" \t"))
            continue
        name, sep, value = line.partition(":")
        if sep and name != name.rstrip(" \t"):
            name = name.rstrip(" \t")
            line = name + ":" + value
        relayed.append(line)
    headers = []
    for line in relayed[1:]:
        name, sep, value = line.partition(":")
        if not sep or not name or any(c not in _TOKEN_CHARS for c in name):
            _refuse_hidden_framing(line)
            continue
        headers.append((name.lower(), value.strip(" \t")))
    if relayed != lines:
        head = ("\r\n".join(relayed) + "\r\n\r\n").encode("latin-1")
    return lines[0], tuple(headers), head


def _refuse_hidden_framing(line):
    """Raise if a response line this parser does not read as a header is
    a framing header to one that trims."""
    name, sep, _ = line.partition(":")
    # Every whitespace, not only SP and HTAB: a parser that trims with
    # str.strip() or String.trim() drops a latin-1 NBSP as well.
    name = name.strip().lower()
    if sep and name in _FRAMING_NAMES:
        raise RequestUnreadable(
            f"a dropped header line is a {name} header to a parser that "
            "trims it")


def _get_all(headers, name):
    return [v for n, v in headers if n == name]


def _is_count(text):
    """Whether `text` is a plain ASCII decimal.

    Not str.isdigit() alone: a latin-1 response head can carry `²`,
    which isdigit accepts and int() refuses.
    """
    return text.isascii() and text.isdigit()


def request_framing(headers):
    """Where the request body ends, or raise.

    Both Content-Length and Transfer-Encoding, duplicates of either, and
    any coding but a single `chunked` are refused: each is a message two
    parsers frame differently.
    """
    lengths = _get_all(headers, "content-length")
    encodings = _get_all(headers, "transfer-encoding")
    if lengths and encodings:
        raise RequestUnreadable(
            "both Content-Length and Transfer-Encoding: which of the two says "
            "where the body ends is exactly what a smuggled request lives in")
    if encodings:
        if len(encodings) > 1 or encodings[0].strip().lower() != "chunked":
            raise RequestUnreadable(
                f"Transfer-Encoding {', '.join(encodings)!r} is not a single "
                "'chunked', and this relay implements no other coding")
        return Framing("chunked")
    if lengths:
        if len(lengths) > 1:
            raise RequestUnreadable(
                f"{len(lengths)} Content-Length headers: duplicates are "
                "refused whether or not they agree, because agreeing today "
                "makes the disagreeing case the untested path")
        value = lengths[0]
        if not _is_count(value):
            raise RequestUnreadable(
                f"Content-Length {value!r} is not a plain decimal count")
        if int(value) > LENGTH_MAX:
            raise RequestUnreadable(
                f"a Content-Length over {LENGTH_MAX} is read as another "
                "number by an origin that parses it into a fixed width")
        return Framing("length", int(value))
    return Framing("none")


def is_http_request_start(start):
    """Whether these first bytes begin an HTTP/1.1 request line: True, False,
    or None for not enough bytes to say yet.

    A heuristic, not a parser: a method spelled A-Z and `-`, then a space.
    It only has to tell a request line from another protocol's first bytes
    on a terminated connection, and undecided counts as HTTP, since the
    parser that follows can answer 400.
    """
    for i, ch in enumerate(start):
        if ch == 0x20:
            return i > 0            # a method, then the space that ends it
        if not (0x41 <= ch <= 0x5A or ch == 0x2D):
            return False
    return None if len(start) < HTTP_METHOD_MAX else False


def response_framing(status, method, headers):
    """Where a response body ends.

    The status and method first: a HEAD response and a 304 carry a
    Content-Length for a body they do not send.
    """
    if method == "HEAD" or status in _BODYLESS_STATUSES or 100 <= status < 200:
        return Framing("none")
    encodings = _get_all(headers, "transfer-encoding")
    lengths = _get_all(headers, "content-length")
    if encodings and lengths:
        raise RequestUnreadable(
            "the origin framed its response both ways at once")
    if encodings:
        if len(encodings) > 1 or encodings[0].strip().lower() != "chunked":
            raise RequestUnreadable(
                f"response Transfer-Encoding {', '.join(encodings)!r} is not "
                "a single 'chunked'")
        return Framing("chunked")
    if lengths:
        if len(lengths) > 1 or not _is_count(lengths[0]):
            raise RequestUnreadable(
                "the origin's Content-Length is duplicated or not a count")
        return Framing("length", int(lengths[0]))
    # No framing header: the body ends with the connection.
    return Framing("close")


def copy_chunked(src, dst):
    """Relay a chunked body, re-emitting each chunk header ourselves.

    Chunk extensions and trailers are dropped, not forwarded.
    """
    while True:
        line = src.read_line()
        size_field = line.split(b";", 1)[0].strip()
        if not size_field or any(c not in b"0123456789abcdefABCDEF"
                                 for c in size_field):
            raise RequestUnreadable(
                f"chunk size {size_field!r} is not plain hex")
        size = int(size_field, 16)
        if size > LENGTH_MAX:
            raise RequestUnreadable(
                f"a chunk size over {LENGTH_MAX} is read as another number "
                "by an origin that parses it into a fixed width")
        if size == 0:
            for _ in range(MAX_TRAILER_LINES):
                if not src.read_line():
                    break
            else:
                raise RequestUnreadable(
                    f"more than {MAX_TRAILER_LINES} trailer lines")
            dst.sendall(b"0\r\n\r\n")
            return
        # Streamed in pieces: the size is the peer's number, and reading a
        # whole chunk first would let it set this process's memory.
        dst.sendall(b"%x\r\n" % size)
        left = size
        while left:
            piece = src.read_exactly(min(left, RELAY_CHUNK))
            dst.sendall(piece)
            left -= len(piece)
        if src.read_exactly(2) != b"\r\n":
            raise RequestUnreadable("a chunk is not CRLF-terminated")
        dst.sendall(b"\r\n")


def copy_body(src, dst, framing):
    """Relay a body of the given framing. `dst` may be None to discard it."""
    if framing.kind == "none":
        return
    if framing.kind == "chunked":
        copy_chunked(src, _Discard() if dst is None else dst)
        return
    if framing.kind == "close":
        while True:
            data = src.read_some()
            if not data:
                return
            if dst is not None:
                dst.sendall(data)
        return
    left = framing.length
    while left:
        data = src.read_exactly(min(left, RELAY_CHUNK))
        left -= len(data)
        if dst is not None:
            dst.sendall(data)


class _Discard:
    """A sink for a drained chunked body, which has no length to check in
    advance, so the ceiling is spent as the bytes arrive."""

    def __init__(self, limit=DRAIN_MAX):
        self._left = limit

    def sendall(self, data):
        self._left -= len(data)
        if self._left < 0:
            raise RequestUnreadable(
                f"a refused body over the {DRAIN_MAX}-byte drain ceiling")


def http_response(status, reason, *, close):
    """One refusal of ours, as an origin would write it: the status line,
    a `Date`, and the reason phrase as the whole body."""
    body = f"{reason}\n".encode()
    head = (f"HTTP/1.1 {status} {reason}\r\n"
            f"Date: {email.utils.formatdate(usegmt=True)}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: {'close' if close else 'keep-alive'}\r\n"
            "\r\n")
    return head.encode("ascii") + body


def drain(client, framing):
    """Read a refused request's body to its end. False if it was too much."""
    if framing.kind == "none":
        return True
    if framing.kind == "length" and framing.length > DRAIN_MAX:
        return False
    try:
        copy_body(client, None, framing)
    except (RequestUnreadable, OSError):
        return False
    return True


def send_response(conn, status, reason, *, close):
    """Write one refusal to the guest, and nothing about why.

    The body is the status phrase: a sentence of ours would tell the guest
    its egress is mediated. `Date` is there because every origin sends one.
    """
    try:
        conn.sendall(http_response(status, reason, close=close))
    except OSError:
        pass
