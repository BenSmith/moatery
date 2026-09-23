"""egress_relay: the byte splice, and the two timeouts every plane spends.

`relay` moves bytes both ways until a side closes or goes idle: for a
spliced connection, a terminated one after a 101, and an h2 session.

CONNECTION_TIMEOUT bounds every wait up to a decision and
RELAY_IDLE_TIMEOUT every wait after one. One number cannot do both: a long
decision wait lets a guest pin every slot cheaply, and a short relay wait
cuts downloads at the first pause. On the cleartext plane the decision is
per request, and the wait between requests on a kept-alive connection takes
the idle number. Everything reads them here by attribute, so a test
patches one place.
"""

import selectors

from http_framing import RELAY_CHUNK


# The timeout up to and including a decision, in seconds.
CONNECTION_TIMEOUT = 5.0

# The idle timeout after a decision, in seconds: rearmed by traffic in
# either direction, so a long download is fine.
RELAY_IDLE_TIMEOUT = 120.0


def relay(client, upstream, on_client_bytes=None):
    """Move bytes both ways until either side closes or goes idle.

    `on_client_bytes`, when given, sees every byte from `client` before it
    is forwarded, and may raise to end the relay. Only the guest's direction
    is checked: the origin is a name the workload allowlisted, reached over
    a verified session.
    """
    for s in (client, upstream):
        s.settimeout(RELAY_IDLE_TIMEOUT)
    peer = {client: upstream, upstream: client}
    sel = selectors.DefaultSelector()
    sel.register(client, selectors.EVENT_READ)
    sel.register(upstream, selectors.EVENT_READ)
    try:
        while True:
            # Bytes already decrypted inside a TLS engine are invisible to
            # select(), so they are read before selecting again.
            buffered = [s for s in (client, upstream)
                        if getattr(s, "pending", None) and s.pending()]
            if buffered:
                ready = buffered
            else:
                events = sel.select(timeout=RELAY_IDLE_TIMEOUT)
                if not events:
                    return                  # idle: nothing either way
                ready = [key.fileobj for key, _ in events]
            for sock in ready:
                data = sock.recv(RELAY_CHUNK)
                if data and on_client_bytes is not None and sock is client:
                    # Before the forward, so a refused stream never reaches
                    # the origin.
                    on_client_bytes(data)
                if not data:
                    # A close either way ends the relay; half-close would
                    # hold a slot for a direction the guest abandoned.
                    return
                peer[sock].sendall(data)
    finally:
        sel.close()
