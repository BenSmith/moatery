"""egress_upstream: the leg from the inspector to the name the policy named.

The plain dial the cleartext plane makes, the verified TLS session the
terminated plane opens, and the hop to this workload's broker, with the pool
that reuses a connection across one guest connection's requests. The name
is dialled, never the address the guest aimed at, which is this listener.
"""

import ipaddress
import select
import socket
import ssl

from .egress_plane import CLEARTEXT, TLS
from .egress_record import (
    DROP_CLIENT_CERT, DROP_INTERNAL, DROP_UNREACHABLE, DROP_UNVERIFIED,
)
from . import egress_relay
from .http_framing import RELAY_CHUNK, _Stream


# How many upstream connections one guest connection may hold. The pool is
# keyed by guest-chosen names under a wildcard, so it needs a bound; past it
# the least recently used is closed, which costs a redial. Across
# MAX_CONNECTIONS this is over a thousand descriptors, which is why
# customs-inspect raises its soft RLIMIT_NOFILE.
UPSTREAMS_MAX = 8

# The prefix giving a host's broker connection a pool slot apart from its
# origin connection. A NUL occurs in no host name, so no guest can name it.
BROKER_UPSTREAM_KEY = "broker\x00"

# What is offered upstream and to the guest, from configuration, never
# mirrored from the guest's own offer.
#
# An offer binds nobody: a server offering http/1.1 alone completes the
# handshake with a client offering h2 alone, and neither side selects
# anything. What holds a terminated connection to HTTP/1.1 is the non-HTTP
# refusal in inspect_tls._is_http and the request parser, not this tuple.
UPSTREAM_ALPN = ("http/1.1",)


class Upstream:
    """How this inspector reaches an authorised name, on either plane."""

    def __init__(self, broker_endpoint=None):
        # Full verification against the host's trust store, and no key to
        # turn it off.
        self._ctx = ssl.create_default_context()
        self._ctx.set_alpn_protocols(list(UPSTREAM_ALPN))
        # This workload's broker: (address, port), a socket path, or None.
        self._broker_endpoint = (
            None if broker_endpoint is None
            else broker_endpoint if isinstance(broker_endpoint, str)
            else tuple(broker_endpoint))

    def dial_cleartext(self, host):
        """A plain connection to an authorised name, as a _Stream."""
        sock = socket.create_connection(
            (host, CLEARTEXT.guest_port),
            timeout=egress_relay.CONNECTION_TIMEOUT)
        sock.settimeout(egress_relay.RELAY_IDLE_TIMEOUT)
        return _Stream(sock)


    def dial_tls(self, host):
        """A verified TLS session to an allowlisted name, as a _Stream."""
        sock = socket.create_connection(
            (host, TLS.guest_port), timeout=egress_relay.CONNECTION_TIMEOUT)
        try:
            ssock = self._ctx.wrap_socket(sock, server_hostname=host)
        except BaseException:
            sock.close()
            raise
        try:
            early = early_bytes(ssock)
        except BaseException:
            ssock.close()
            raise
        ssock.settimeout(egress_relay.RELAY_IDLE_TIMEOUT)
        return _Stream(ssock, prefill=early)


    def dial_broker(self, host):
        """A plain connection to this workload's broker.

        Cleartext, on loopback or a socket path the guest cannot reach; the
        leg that matters is the broker's own, verified TLS to the provider.
        `host` is unused here but kept, since every dial is called alike and
        it rides the head as `Host`. With no endpoint this raises OSError,
        which the caller reports as a dead broker.
        """
        if self._broker_endpoint is None:
            raise OSError("this inspector was started without a broker "
                          "endpoint, and the policy names a credential for "
                          f"{host}")
        if isinstance(self._broker_endpoint, str):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(egress_relay.CONNECTION_TIMEOUT)
            try:
                sock.connect(self._broker_endpoint)
            except BaseException:
                sock.close()
                raise
        else:
            sock = socket.create_connection(
                self._broker_endpoint,
                timeout=egress_relay.CONNECTION_TIMEOUT)
        sock.settimeout(egress_relay.RELAY_IDLE_TIMEOUT)
        return _Stream(sock)


    def connection_for(self, host, upstreams, reusable=True, dial=None,
                       key=None):
        """The connection to an authorised name, opened once and reused.

        `dial` opens one, and differs by plane. `upstreams` is the guest
        connection's pool, bounded at UPSTREAMS_MAX and evicted
        least-recently-used. `reusable=False` keeps the connection out of
        the pool; the caller closes it. `key` is the pool slot, which for a
        broker leg is not the host: a pool keyed by name alone would hand a
        brokered request the origin connection and never dial the broker.
        """
        slot = key or host
        up = upstreams.pop(slot, None)
        if up is not None and gone_while_idle(up):
            # The far end let go between requests; nothing has been sent,
            # so a fresh dial is the whole remedy.
            try:
                up.sock.close()
            except OSError:
                pass
            up = None
        if up is None:
            up = (dial or self.dial_cleartext)(host)
        if not reusable:
            return up
        upstreams[slot] = up
        while len(upstreams) > UPSTREAMS_MAX:
            # The oldest, never the one just inserted.
            oldest = next(iter(upstreams))
            try:
                upstreams.pop(oldest).sock.close()
            except OSError:
                pass
        return up


def gone_while_idle(stream):
    """Whether a pooled connection closed, or spoke unasked, while idle.

    An idle connection has nothing to say, so a readable socket means the
    far end closed it or sent bytes nobody asked for. A TLS record with no
    data, a late session ticket, reads as nothing and leaves it usable.
    Bytes the stream read past the last response spoke unasked too, though
    the socket no longer shows them.
    """
    if stream.holds_unread():
        return True
    sock = stream.sock
    # poll, not select: select refuses a descriptor past FD_SETSIZE, which
    # this process's raised limit reaches.
    poller = select.poll()
    try:
        poller.register(sock, select.POLLIN)
        readable = poller.poll(0)
    except (OSError, ValueError):
        return True
    if not readable and not (getattr(sock, "pending", None)
                             and sock.pending()):
        return False
    previous = sock.gettimeout()
    sock.settimeout(0)
    try:
        sock.recv(RELAY_CHUNK)
    except (ssl.SSLWantReadError, BlockingIOError):
        return False
    except OSError:
        return True
    finally:
        try:
            sock.settimeout(previous)
        except OSError:
            pass
    return True


def early_bytes(ssock):
    """One non-blocking read straight after the upstream handshake.

    A TLS 1.3 server that requires a client certificate completes the
    handshake and then sends `certificate_required`; read here, it fails
    the dial before a request byte is sent. Anything else is kept, to be
    read in order.
    """
    previous = ssock.gettimeout()
    ssock.settimeout(0)
    try:
        return ssock.recv(RELAY_CHUNK)
    except (ssl.SSLWantReadError, BlockingIOError):
        return b""
    finally:
        ssock.settimeout(previous)


def tls_failure(host, exc):
    """(drop reason, the operator's sentence) for a failed TLS leg.

    The sentence is for the journal; the guest gets a bare 502. A TLS 1.2
    server requiring a client certificate sends a handshake_failure it
    shares with other causes, so that arm names the possibility without
    asserting it.
    """
    code = getattr(exc, "reason", "") or ""
    if "CERTIFICATE_REQUIRED" in code:
        return (DROP_CLIENT_CERT,
                f"{host} requires a client certificate, which this "
                f"inspector cannot present on the guest's behalf. Add "
                f"{host} to the policy's `splice` list, and drop any "
                f"`policy` entry for it, so the guest's own handshake "
                f"reaches {host}.")
    if isinstance(exc, ssl.SSLCertVerificationError):
        detail = getattr(exc, "verify_message", None) or str(exc)
        return (DROP_UNVERIFIED,
                f"{host}'s certificate could not be verified: {detail}. If "
                f"{host} is behind a private root CA, that root must be "
                f"added to THIS HOST's trust anchors -- the guest's copy "
                f"is not consulted, because the guest is not the party "
                f"verifying {host}.")
    if code == "SSLV3_ALERT_HANDSHAKE_FAILURE":
        return (DROP_UNVERIFIED,
                f"{host} refused the handshake ({exc}). Under TLS 1.2 that "
                f"is also the alert a server sends when it requires a "
                f"client certificate, and the two are not distinguishable "
                f"here; if {host} uses client certificates it must be "
                f"spliced.")
    return (DROP_UNVERIFIED, f"the TLS session to {host} failed: {exc}")


def dial_failure_reason(host: str, internal_expected) -> str:
    """Why a dial to an allowlisted name failed, as far as can be told.

    A name that resolves into private space and has no `internal_expected`
    entry was probably refused by the host's private-address rule; anything
    else is a host that is down. The name is resolved again, since
    create_connection does not say which address it tried, and a rotating
    record can make that disagree: the cost is a misattributed counter, not
    a wrong decision. The lookup is not bounded by CONNECTION_TIMEOUT.
    """
    if host in internal_expected:
        return DROP_UNREACHABLE
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return DROP_UNREACHABLE
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return DROP_INTERNAL
    return DROP_UNREACHABLE
