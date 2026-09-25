"""The synthesising responder's serve loop, and what it reports.

Counters is the status file's source; serve is the loop over the sockets
the unit passed in, answering UDP inline and TCP on a bounded number of
threads. Nothing here creates a socket and nothing speaks upstream:
tests/test_resolve.py parses this file to keep it that way.
"""

import selectors
import socket
import struct
import threading
import time

from dns_wire import (
    RCODE_FORMERR,
    RCODE_SERVFAIL,
    TCP_MAX,
    UDP_BUDGET,
    Malformed,
    NotAQuery,
    build_answer,
    error_response,
    log,
)
from egress_status import STATUS_TOP_N, BoundedCounts, write_status

# How long a TCP peer may hold a connection with nothing on it. Clients
# reuse connections (RFC 7766), but an idle one must not pin a slot.
TCP_IDLE_TIMEOUT = 10.0

# The whole life of one TCP connection, in seconds. The idle timeout is per
# recv, so a peer sending a byte every nine seconds, or pipelining queries
# forever, is never idle. Answers come from memory, so a real client is
# done in milliseconds.
TCP_LIFETIME = 30.0

# How many TCP connections may be answered at once. Past it one is closed at
# accept, not queued: a client that loses a TCP attempt retries, and UDP,
# which nearly every lookup uses, is unaffected.
TCP_MAX_CONNECTIONS = 16

# How long the loop blocks before checking the clock and the stop flag.
_SELECT_POLL = 0.5

# The status file's tick while the responder is idle; the inspector's.
STATUS_INTERVAL = 30.0


class Counters:
    """What the responder reports.

    `unlisted` counts queries for names no list admits. The channel is
    closed either way, since every name is answered here and nothing is
    asked onward, so a rising count is evidence that something in the
    workload is trying, never that anything left.
    """

    def __init__(self, top_n: int = STATUS_TOP_N):
        # TCP is answered on its own threads, so every observation and the
        # snapshot are taken under one lock: a status file assembled from a
        # half-applied observation has figures that do not add up.
        self._lock = threading.Lock()
        self.synthesised = 0
        self.nodata = 0
        self.unlisted = 0
        self.malformed = 0
        # Bounded: the keys are names the workload chose, and this is the
        # map a name-encoding workload is trying to fill.
        self.unlisted_names = BoundedCounts(top_n)

    def record_answer(self, name: str, count: int, on_a_list: bool) -> None:
        with self._lock:
            if count:
                self.synthesised += 1
            else:
                self.nodata += 1
            if not on_a_list:
                self.unlisted += 1
                self.unlisted_names.add(name or ".")

    def record_nodata(self) -> None:
        """A question that was never about an address.

        Not classified against the lists: an HTTPS query usually names a
        host the workload is about to look up properly, so counting it too
        would double every ordinary miss.
        """
        with self._lock:
            self.nodata += 1

    def record_malformed(self) -> None:
        with self._lock:
            self.malformed += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "queries": {
                    "synthesised": self.synthesised,
                    "nodata": self.nodata,
                    "malformed": self.malformed,
                },
                "unlisted": self.unlisted,
                "unlisted_names": self.unlisted_names.snapshot(),
            }


def serve_datagram(sock, policy, counters=None):
    try:
        query, peer = sock.recvfrom(UDP_BUDGET * 4)
    except OSError as exc:
        log(f"  WARNING: recvfrom failed: {exc}")
        return
    try:
        reply = build_answer(query, policy, counters=counters)
    except Malformed as exc:
        if counters is not None:
            counters.record_malformed()
        if len(query) < 2:
            return
        log(f"  malformed query from {peer}: {exc}")
        reply = error_response(query, RCODE_FORMERR)
    except NotAQuery:
        # Not logged either: the log would be what a loop fills.
        if counters is not None:
            counters.record_malformed()
        return
    except Exception as exc:  # noqa: BLE001
        # Anything else is a bug here, and the width is the point: let it
        # unwind and the process exits, restarts, and exits again on the
        # same query, a crash loop in the workload's only nameserver.
        # SERVFAIL and not counted as malformed, which would point at the
        # workload: the query was fine and this program was not.
        if len(query) < 2:
            return
        log(f"  WARNING: could not answer a query from {peer}: "
            f"{type(exc).__name__}: {exc}")
        reply = error_response(query, RCODE_SERVFAIL)
    try:
        sock.sendto(reply, peer)
    except OSError as exc:
        log(f"  WARNING: sendto failed: {exc}")


class _TcpSlots:
    """How many TCP connections are being answered right now."""

    def __init__(self, limit=TCP_MAX_CONNECTIONS):
        self._limit = limit
        self._live = 0
        self._lock = threading.Lock()

    def take(self) -> bool:
        with self._lock:
            if self._live >= self._limit:
                return False
            self._live += 1
            return True

    def give_back(self) -> None:
        with self._lock:
            self._live -= 1


def serve_stream(listener, policy, counters=None, slots=None):
    """Accept one TCP connection and answer it off the loop.

    Off the loop because the loop is held by the read, not the answer: one
    loop serves UDP too, and a TCP peer that dribbles bytes would otherwise
    stop the workload resolving anything and the status file being written.
    """
    try:
        conn, _peer = listener.accept()
    except OSError as exc:
        log(f"  WARNING: accept failed: {exc}")
        return
    if slots is None:
        slots = _TCP_SLOTS
    if not slots.take():
        log("  WARNING: TCP connection refused: "
            f"more than {TCP_MAX_CONNECTIONS} already in flight")
        conn.close()
        return
    # Daemon, so a stop does not wait on connections already taken. A
    # thread that cannot start gives its slot back here, or the ceiling
    # drops for the life of the process.
    try:
        threading.Thread(target=_answer_stream,
                         args=(conn, policy, counters, slots),
                         daemon=True).start()
    except RuntimeError as exc:
        slots.give_back()
        log(f"  WARNING: TCP connection refused: cannot start thread: {exc}")
        conn.close()


def _answer_stream(conn, policy, counters=None, slots=None):
    try:
        handle_stream(conn, policy, counters)
    finally:
        if slots is not None:
            slots.give_back()


def handle_stream(conn, policy, counters=None, deadline=None):
    """Answer queries on an accepted TCP connection, then close it.

    `deadline` is a monotonic instant, TCP_LIFETIME from now by default.
    Each recv gets the nearer of it and the idle bound, so an ordinary
    client is ended by idleness and only a peer still talking by the
    deadline.
    """
    if deadline is None:
        deadline = time.monotonic() + TCP_LIFETIME
    with conn:
        try:
            while True:
                prefix = recv_exactly(conn, 2, deadline)
                if prefix is None:
                    return
                length = struct.unpack("!H", prefix)[0]
                if length > TCP_MAX:
                    return
                query = recv_exactly(conn, length, deadline)
                if query is None:
                    return
                if not _arm(conn, deadline):
                    return
                try:
                    reply = build_answer(query, policy, counters=counters)
                except Malformed as exc:
                    if counters is not None:
                        counters.record_malformed()
                    if len(query) < 2:
                        return
                    log(f"  malformed TCP query: {exc}")
                    reply = error_response(query, RCODE_FORMERR)
                except NotAQuery:
                    if counters is not None:
                        counters.record_malformed()
                    continue
                conn.sendall(struct.pack("!H", len(reply)) + reply)
        except (OSError, struct.error):
            return


def _arm(conn, deadline):
    """Set the timeout for the next read or send. False if time is up; the
    send is bounded too, so a peer that stops reading is ended as well."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        log(f"  TCP connection closed after {TCP_LIFETIME:.0f}s")
        return False
    conn.settimeout(min(TCP_IDLE_TIMEOUT, remaining))
    return True


def recv_exactly(conn, count, deadline=None):
    """Read exactly `count` bytes, or None if the peer stopped sending.

    The deadline is checked before every recv, not once per message: each
    recv rearms the idle bound, so a peer dribbling a byte at a time would
    otherwise spend TCP_IDLE_TIMEOUT per byte of a length it chose.
    """
    chunks = bytearray()
    while len(chunks) < count:
        if deadline is not None and not _arm(conn, deadline):
            return None
        chunk = conn.recv(count - len(chunks))
        if not chunk:
            return None
        chunks += chunk
    return bytes(chunks)


# One ceiling for the process. The tests pass their own.
_TCP_SLOTS = _TcpSlots()


def serve(sockets, policy, counters=None, status_path=None, stop=None):
    """The loop. Returns when `stop` says so, or never.

    `stop` is a callable so the tests can end the loop after a fixed number
    of turns; in the process it reads the SIGTERM flag.
    """
    selector = selectors.DefaultSelector()
    for sock in sockets:
        sock.setblocking(True)
        selector.register(sock, selectors.EVENT_READ)

    def emit():
        emit_status(status_path, counters)

    # Before the first query, so the file's absence means "never started",
    # not "never asked anything".
    emit()
    due = time.monotonic() + STATUS_INTERVAL
    while stop is None or not stop():
        # The timeout is what makes the tick happen on an idle responder,
        # whose file would otherwise read as a process that had died.
        for key, _events in selector.select(timeout=_SELECT_POLL):
            sock = key.fileobj
            if sock.type == socket.SOCK_DGRAM:
                serve_datagram(sock, policy, counters)
            else:
                serve_stream(sock, policy, counters)
        if time.monotonic() >= due:
            emit()
            due = time.monotonic() + STATUS_INTERVAL
    emit()


def emit_status(status_path, counters):
    """Replace the status file, or log why not. Never raises: a responder
    that died over a diagnostic would leave the workload resolving nothing.
    TypeError and ValueError are json.dump's, for a value it cannot
    serialise."""
    if status_path is None or counters is None:
        return
    try:
        write_status(status_path, counters.snapshot())
    except (OSError, TypeError, ValueError) as exc:
        log(f"  WARNING: could not write {status_path}: {exc}")
