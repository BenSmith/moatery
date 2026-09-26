"""egress_relay: the byte splice, and the two timeouts every plane spends.

`relay` moves bytes both ways until a side closes or goes idle: for a
spliced connection, and a terminated one after a 101.

CONNECTION_TIMEOUT bounds every wait up to a decision and
RELAY_IDLE_TIMEOUT every wait after one. One number cannot do both: a long
decision wait lets a guest pin every slot cheaply, and a short relay wait
cuts downloads at the first pause. On the cleartext plane the decision is
per request, and the wait between requests on a kept-alive connection takes
the idle number. Everything reads them here by attribute, so a test
patches one place.
"""

import selectors
import ssl
import time

from .http_framing import RELAY_CHUNK


# The timeout up to and including a decision, in seconds.
CONNECTION_TIMEOUT = 5.0

# The idle timeout after a decision, in seconds: rearmed by traffic in
# either direction, so a long download is fine.
RELAY_IDLE_TIMEOUT = 120.0

# What one direction may hold that its far side has not taken. Past it that
# direction's sender is not read, so a peer that stops reading slows the
# other rather than growing this process.
RELAY_BUFFER = 4 * RELAY_CHUNK


class _Direction:
    """Bytes read from `src` and not yet written to `dst`, and which event
    each side's last attempt was left waiting on.

    A TLS read can need the socket writable and a TLS write can need it
    readable, so the event is the one the engine asked for, not the one the
    direction suggests.
    """

    def __init__(self, src, dst):
        self.src, self.dst = src, dst
        self.buf = bytearray()
        # The chunk a TLS write was refused on: OpenSSL requires the retry
        # to carry the same bytes.
        self.inflight = None
        self.read_on = selectors.EVENT_READ
        self.write_on = selectors.EVENT_WRITE

    def holding(self):
        return bool(self.buf) or self.inflight is not None

    def room(self):
        return len(self.buf) < RELAY_BUFFER

    def read(self):
        """One read into the buffer: the bytes, b"" at the end of the
        stream, or None when there was nothing to take yet."""
        try:
            data = self.src.recv(RELAY_CHUNK)
        except ssl.SSLWantWriteError:
            self.read_on = selectors.EVENT_WRITE
            return None
        except (ssl.SSLWantReadError, BlockingIOError):
            self.read_on = selectors.EVENT_READ
            return None
        self.read_on = selectors.EVENT_READ
        if data:
            self.buf += data
        return data

    def write(self):
        """One write from the buffer. Whether any bytes moved."""
        chunk = self.inflight or bytes(self.buf[:RELAY_CHUNK])
        try:
            sent = self.dst.send(chunk)
        except ssl.SSLWantReadError:
            self.inflight, self.write_on = chunk, selectors.EVENT_READ
            return False
        except (ssl.SSLWantWriteError, BlockingIOError):
            self.inflight, self.write_on = chunk, selectors.EVENT_WRITE
            return False
        self.inflight, self.write_on = None, selectors.EVENT_WRITE
        del self.buf[:sent]
        return sent > 0


def relay(client, upstream):
    """Move bytes both ways until either side closes or goes idle.

    Neither direction waits on the other: each is read while its buffer has
    room and written while it holds anything, so a peer that writes before
    it reads is read while it writes. A close either way ends the relay
    once what was already read has been written, or the side it is for
    refuses it or goes idle; a half-close would hold a slot for a direction
    the guest abandoned. Idle means no byte moved either way for
    RELAY_IDLE_TIMEOUT, and before a close it raises TimeoutError if bytes
    were still waiting for a side that stopped reading.
    """
    directions = (_Direction(client, upstream),
                  _Direction(upstream, client))
    sel = selectors.DefaultSelector()
    watching = {}
    closing = False
    moved_at = time.monotonic()
    try:
        for s in (client, upstream):
            s.setblocking(False)
        while True:
            holding = any(d.holding() for d in directions)
            if closing and not holding:
                return
            idle = time.monotonic() - moved_at
            if idle >= RELAY_IDLE_TIMEOUT:
                if holding and not closing:
                    raise TimeoutError(
                        f"no byte moved for {RELAY_IDLE_TIMEOUT:.0f}s with "
                        f"bytes still to write")
                return
            reading = [d for d in directions if not closing and d.room()]
            events = {client: 0, upstream: 0}
            for d in reading:
                events[d.src] |= d.read_on
            for d in directions:
                if d.holding():
                    events[d.dst] |= d.write_on
            _watch(sel, watching, events)
            # Bytes already decrypted inside a TLS engine are invisible to
            # select(), so a side holding some is ready without it.
            ready = {d.src for d in reading
                     if getattr(d.src, "pending", None) and d.src.pending()}
            timeout = 0 if ready else RELAY_IDLE_TIMEOUT - idle
            ready |= {key.fileobj for key, _ in sel.select(timeout)}
            for d in directions:
                moved = False
                if d.src in ready and d in reading and not closing:
                    data = d.read()
                    if data == b"":
                        closing = True
                    elif data:
                        moved = True
                if d.holding() and (d.dst in ready or moved):
                    try:
                        moved = d.write() or moved
                    except OSError:
                        if not closing:
                            raise
                        # The side that closed will take nothing more.
                        return
                if moved:
                    moved_at = time.monotonic()
    finally:
        sel.close()
        for s in (client, upstream):
            try:
                s.settimeout(RELAY_IDLE_TIMEOUT)
            except OSError:
                pass


def _watch(sel, watching, events):
    """Bring the selector's registrations to `events`, a mask per socket;
    a socket with none is unregistered."""
    for sock, mask in events.items():
        now = watching.get(sock, 0)
        if mask == now:
            continue
        if not mask:
            sel.unregister(sock)
        elif not now:
            sel.register(sock, mask)
        else:
            sel.modify(sock, mask)
        watching[sock] = mask
