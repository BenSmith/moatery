"""
inspect_tls: the TLS plane -- peek, match, then splice or terminate.

A connection on 443 has its ClientHello peeked and its server name matched
against the workload's policy. Under `tls = "splice"` the connection is then
relayed byte for byte, hello included, and nothing inside it is seen. Under
`tls = "inspect"` (the default) this process completes the guest's handshake
with a leaf from the workload's CA, opens its own verified session to the
origin, and authorises each request inside with the cleartext plane's loop.

Every refusal on a terminated connection is delivered through a completed
handshake, as a 403 or 502 with the status phrase alone. A failed handshake
would look to the guest like the host being down; the reason goes to the
journal.
"""

import socket
import ssl

from inspect_document import normalise_hostname
from egress_ca import LeafRefused
from egress_mint import MintFailed, MintThrottled
from egress_plane import TLS
from egress_record import (
    DROP_MINT_FAILED, DROP_NOT_ALLOWLISTED, DROP_NOT_H2, DROP_NOT_HTTP,
    DROP_NOT_HTTP_POLICY, DROP_NO_NAME, DROP_RELAY_FAILED, DROP_THROTTLED,
    Record,
)
from egress_relay import relay
import egress_relay
from egress_upstream import (
    ALPN_H2, UPSTREAM_ALPN, dial_failure_reason, tls_failure,
)
from h2_framing import H2_PREFACE, H2Framing, NotH2
from http_framing import (
    RequestUnreadable, _Stream, is_http_request_start, send_response,
)
from http_target import SCHEME_HTTPS
import inspect_http
from tls_hello import HelloUnreadable, read_client_hello


def serve_tls(insp, conn, where):
    """Peek, match, and then splice or terminate."""
    inspect = insp.policy.tls == "inspect"
    if inspect and insp.minter is None:
        # The entrypoint refuses to start like this; a Listener built by
        # hand would otherwise fail every handshake with no line saying why.
        insp.drop(where, DROP_MINT_FAILED, "this listener has no minter",
                  mode="terminate")
        return
    try:
        hello = read_client_hello(conn)
    except HelloUnreadable as exc:
        insp.drop(where, DROP_NO_NAME, exc, mode="terminate")
        return
    if not hello.server_name:
        # Before the drop: a hello that withholds SNI and carries ECH is the
        # tripwire's strongest signal.
        insp.counters.record_hello(hello, False)
        insp.drop(where, DROP_NO_NAME,
                  "the ClientHello carries no server_name extension",
                  mode="terminate")
        return
    host = normalise_hostname(hello.server_name)
    allowed = insp.policy.admits(host)
    insp.counters.record_hello(hello, allowed)
    # The allowlist first: a `splice` pattern can cover names no list
    # admits, and those are refused like any other denial, by a bump.
    if inspect and not (allowed and insp.policy.splices(host)):
        _serve_tls_inspect(insp, conn, where, host, allowed)
        return
    if not allowed:
        insp.drop(where, DROP_NOT_ALLOWLISTED, host=host, mode="splice")
        return
    # The name the policy authorised is dialled, never the address the
    # guest aimed at, which is this listener.
    try:
        upstream = socket.create_connection(
            (host, TLS.guest_port), timeout=egress_relay.CONNECTION_TIMEOUT)
    except OSError as exc:
        insp.drop(where, dial_failure_reason(host, insp.policy.internal), exc,
                  host=host, mode="splice")
        return
    try:
        # The hello is still on the socket, so the relay sends it first and
        # the origin completes its handshake with the guest's own bytes.
        insp.counters.record_splice()
        insp.log(f"splice {where} host={host}"
                            f"{' per-host' if inspect else ''}")
        rec = Record(insp.record, where, "splice", host=host)
        rec.dialled(upstream)
        rec.set(decision="forward")
        try:
            relay(conn, upstream)
        finally:
            rec.emit()
    finally:
        upstream.close()


def _serve_tls_inspect(insp, conn, where, host, allowed):
    """Terminate one connection: decide, dial, mint, handshake, serve.

    The origin is dialled before the guest's handshake, so the protocol
    offered to the guest comes from the policy and never from what the
    guest asked for, and a host that cannot be reached costs a leaf only to
    carry the refusal.
    """
    upstream = None
    refusal = None            # (drop reason, status, phrase, journal text)
    h2 = insp.policy.speaks_h2(host)
    # A brokered host's requests go to the broker, per request, so the
    # origin is not dialled here: that would make its reachability and
    # certificate a condition of requests that never reach it.
    brokered = allowed and insp.policy.credential_for(host) is not None
    if brokered:
        h2 = False
    if not allowed:
        refusal = (DROP_NOT_ALLOWLISTED, 403, "Forbidden",
                   (f"{host} matches no `hosts` pattern and no `policy` "
                    f"entry"))
    elif brokered:
        pass
    else:
        try:
            upstream = insp.upstream.dial_tls(
                host, ALPN_H2 if h2 else UPSTREAM_ALPN)
        except ssl.SSLError as exc:
            reason, text = tls_failure(host, exc)
            refusal = (reason, 502, "Bad Gateway", text)
        except OSError as exc:
            reason = dial_failure_reason(host, insp.policy.internal)
            refusal = (reason, 502, "Bad Gateway",
                       f"{host} could not be reached: {exc}")
        else:
            # An h2 offer binds nobody: an HTTP/1.1-only origin completes
            # the handshake selecting nothing, and the guest's preface
            # would be relayed into it as garbage.
            if h2 and upstream.sock.selected_alpn_protocol() != "h2":
                upstream.sock.close()
                upstream = None
                refusal = (
                    DROP_NOT_H2, 502, "Bad Gateway",
                    f"{host} is in the `http2` list but did not select "
                    f"h2 for this connection, so there is no HTTP/2 session "
                    f"to relay. Either it does not speak h2 -- drop the "
                    f"entry and let it be inspected as HTTP/1.1 -- or it "
                    f"cannot take this workload's CA, and belongs in the "
                    f"`splice` list")
    leaf = None
    try:
        # `denied` picks the cache: only names the policy refused go in the
        # denial set, which is the one a flood can fill.
        leaf = insp.minter.leaf(host, denied=not allowed)
    except MintThrottled:
        # With no leaf nothing legible can be sent, so this one closes.
        insp.drop(where, DROP_THROTTLED, "the leaf bucket is empty",
                  host=host, mode="terminate")
        return
    except (LeafRefused, MintFailed) as exc:
        insp.drop(where, DROP_MINT_FAILED, exc, host=host, mode="terminate")
        return
    finally:
        if leaf is None and upstream is not None:
            upstream.sock.close()
    if leaf is None:
        return
    try:
        # h2 only when there is a session to relay: a refusal is an
        # HTTP/1.1 response.
        tls_conn = wrap_guest(
            conn, leaf,
            ALPN_H2 if (h2 and refusal is None) else UPSTREAM_ALPN)
    except (ssl.SSLError, OSError) as exc:
        # A leaf evicted before it was loaded fails here too, and it is a
        # cache-sizing fault, not a guest that distrusts the CA. The caches
        # are sized so it cannot happen (DENIAL_CACHE_MAX).
        if not leaf.path.exists():
            insp.drop(where, DROP_MINT_FAILED,
                      f"the leaf minted for this connection was evicted "
                      f"before it could be presented: {exc}. This is a "
                      f"cache-sizing fault, not a trust one -- the leaf "
                      f"cache must hold more entries than there are "
                      f"connection slots", host=host, mode="terminate")
            if upstream is not None:
                upstream.sock.close()
            return
        # A guest that was never given the CA and one whose trust store is
        # built into its image (a JVM, rustls) look the same from here, and
        # need different remedies, so the line names both.
        insp.drop(where, DROP_RELAY_FAILED,
                 f"the client did not complete the handshake: {exc}. It "
                 f"did not trust the "
                 f"leaf this workload minted, which has two shapes and "
                 f"they need different remedies. (1) A client that COULD "
                 f"be given the CA and was not: a workload provisioned "
                 f"before it had one, or one whose CA bundle or CA "
                 f"environment variables are absent or wrong -- "
                 f"re-provision it. (2) A client that CANNOT be given it "
                 f"at all because its trust store is embedded in the image "
                 f"and it reads none of the CA environment variables -- a "
                 f"JVM, or anything on rustls. For (2) there is no CA "
                 f"route to fix: add {host} to the `splice` list "
                 f"so the connection is spliced rather than terminated, or "
                 f"change the image", host=host, mode="terminate")
        if upstream is not None:
            upstream.sock.close()
        return
    # wrap_socket detached `conn`, so this is the only close of the guest's
    # connection.
    try:
        if refusal is not None:
            reason, status, phrase, text = refusal
            insp.counters.record_bump()
            insp.drop(where, reason, text, host=host, mode="terminate",
                      answered=status, verb="bump", status=status)
            _bump_answer(tls_conn, status, phrase)
            return
        insp.counters.record_termination()
        insp.log(f"terminate {where} host={host}"
                            f"{' h2' if h2 else ''}")
        if h2:
            _serve_h2(insp, tls_conn, where, host, upstream)
        else:
            serve_terminated(insp, tls_conn, where, host, upstream)
    finally:
        try:
            tls_conn.close()
        except OSError:
            pass


def _bump_answer(tls_conn, status, phrase):
    """Deliver a refusal inside a handshake we just completed.

    The guest's request is read and discarded first: a client still sending
    when the connection closes reports a broken pipe instead of the status.
    """
    try:
        _Stream(tls_conn).read_head()
    except (RequestUnreadable, OSError):
        pass
    send_response(tls_conn, status, phrase, close=True)


def wrap_guest(conn, leaf, alpn=UPSTREAM_ALPN):
    """Complete the guest's handshake as the origin it dialled."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(leaf.path))
    ctx.set_alpn_protocols(list(alpn))
    return ctx.wrap_socket(conn, server_side=True)


def _serve_h2(insp, tls_conn, where, host, upstream):
    """Relay one h2 session frame by frame, refusing what is not h2.

    Nothing is decoded, so `:authority`, `methods` and `paths` go unread;
    the check holds an `http2` entry to meaning "speaks h2" rather than "is
    exempt". One record covers the session, and `h2_unrecorded` counts it.
    """
    rec = Record(insp.record, where, "h2", host=host)
    rec.dialled(upstream.sock)
    try:
        client = _Stream(tls_conn)
        tls_conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
        try:
            preface = client.read_exactly(len(H2_PREFACE))
        except (RequestUnreadable, OSError) as exc:
            _drop_not_h2(insp, where, host, rec,
                         f"the connection preface never arrived ({exc})")
            return
        if preface != H2_PREFACE:
            _drop_not_h2(insp, where, host, rec,
                         f"{preface[:8]!r} is not the connection preface")
            return
        framing = H2Framing()
        # What the preface read took past its 24 bytes is the guest's
        # opening SETTINGS, which the scanner exists to check.
        surplus = client.take_buffered()
        try:
            framing.feed(surplus)
        except NotH2 as exc:
            _drop_not_h2(insp, where, host, rec, exc)
            return
        try:
            upstream.sock.sendall(preface + surplus)
            # An h2 origin sends its SETTINGS at once, and the dial's
            # early read may already hold them.
            early = upstream.take_buffered()
            if early:
                tls_conn.sendall(early)
        except OSError as exc:
            insp.drop(where, DROP_RELAY_FAILED, exc, host=host, rec=rec)
            return
        try:
            relay(tls_conn, upstream.sock, on_client_bytes=framing.feed)
        except NotH2 as exc:
            _drop_not_h2(insp, where, host, rec, exc)
            return
        except OSError as exc:
            insp.drop(where, DROP_RELAY_FAILED, exc, host=host, rec=rec)
            return
        rec.set(decision="forward")
        insp.counters.record_h2_unrecorded()
        if not framing.aligned:
            _drop_not_h2(insp, where, host, rec,
                         "the connection ended part-way through a frame")
    finally:
        rec.emit()
        upstream.sock.close()


def _drop_not_h2(insp, where, host, rec, why):
    insp.drop(where, DROP_NOT_H2,
              f"{why}. {host} is in the `http2` list and this session did "
              f"not speak h2; drop the entry, or move the host to the "
              f"splice list", host=host, rec=rec)


def serve_terminated(insp, tls_conn, where, host, upstream):
    """Authorise every request inside one terminated session.

    The cleartext plane's loop, with the name pinned to the one the leaf
    was minted for: a request naming another host gets a 421.
    """
    client = _Stream(tls_conn)
    # No upstream for a brokered host; its requests dial the broker.
    upstreams = {host: upstream} if upstream is not None else {}
    try:
        if not _is_http(insp, client, tls_conn, where, host):
            return
        first = True
        seq = 1
        while inspect_http.serve_one_request(
                insp, client, tls_conn, where.request(seq),
                upstreams, first, scheme=SCHEME_HTTPS, pinned_host=host):
            first = False
            seq += 1
    finally:
        for up in upstreams.values():
            up.sock.close()


def _is_http(insp, client, conn, where, host):
    """Whether this terminated connection is speaking HTTP. Closed if not.

    Closed rather than answered, since an HTTP response means nothing to
    another protocol. A host named by a `policy` entry is counted apart,
    because its remedy also deletes the entry.
    """
    conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
    start = client.peek_start(
        until=lambda buf: is_http_request_start(buf) is not None)
    if is_http_request_start(start) is not False:
        # Undecided, b"" included, goes to the request loop, which already
        # handles a close, a timeout and a 400.
        return True
    if insp.policy.governs(host):
        insp.drop(
            where, DROP_NOT_HTTP_POLICY,
            f"this session was terminated and {start[:8]!r} does not begin "
            f"a request line, so the `policy` entry for {host} never ran "
            f"and never will. Either the host does not belong in `policy` "
            f"at all, or it needs a `splice` entry AND that `policy` entry "
            f"deleted -- a host cannot be in both",
            host=host, mode="terminate")
        return False
    insp.drop(where, DROP_NOT_HTTP,
              f"this session was terminated and {start[:8]!r} does not "
              f"begin a request line. Add {host} to the `splice` list if it "
              f"needs to keep end-to-end TLS", host=host, mode="terminate")
    return False
