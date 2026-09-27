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

from .inspect_document import normalise_hostname
from .egress_ca import LeafRefused
from .egress_mint import MintFailed, MintThrottled
from .egress_plane import TLS
from .egress_record import (
    DROP_ECH_SPLICED, DROP_MINT_FAILED, DROP_NOT_ALLOWLISTED, DROP_NOT_HTTP,
    DROP_NOT_HTTP_POLICY, DROP_NO_NAME, DROP_RELAY_FAILED, DROP_THROTTLED,
    NOTE_ECH, NOTE_H2_ONLY, Record,
)
from .egress_relay import relay
from . import egress_relay
from .egress_upstream import UPSTREAM_ALPN, dial_failure_reason, tls_failure
from .http_framing import (
    RequestUnreadable, _Stream, is_http_request_start, send_response,
)
from .http_target import SCHEME_HTTPS
from . import inspect_http
from .inspect_scope import quoted
from .tls_hello import TLS_EXT_ECH, HelloUnreadable, read_client_hello


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
    if TLS_EXT_ECH in hello.extensions:
        insp.note(where, NOTE_ECH,
                  "the ClientHello carries encrypted_client_hello, real or a "
                  "client's GREASE, which look alike. A terminated "
                  "connection hides nothing either way; a spliced one is "
                  "refused",
                  host=normalise_hostname(hello.server_name)
                  if hello.server_name else None)
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
        _serve_tls_inspect(insp, conn, where, host, allowed, hello)
        return
    if not allowed:
        insp.drop(where, DROP_NOT_ALLOWLISTED, host=host, mode="splice")
        return
    # The name checked is the hello's outer one. Under ECH the front serves
    # the inner one, which a splice never opens; GREASE and real ECH are
    # built to look alike, so both are refused.
    if TLS_EXT_ECH in hello.extensions:
        insp.drop(where, DROP_ECH_SPLICED,
                  f"the ClientHello carries encrypted_client_hello, and a "
                  f"spliced connection is never opened, so the front may "
                  f"serve the name encrypted inside it rather than {host}. "
                  f"A client's GREASE looks the same as real ECH, and "
                  f"Chromium-based clients send it by default: turn it off "
                  f"in the client (--disable-features=EncryptedClientHello), "
                  f"or have {host} terminated instead of spliced",
                  host=host, mode="splice")
        return
    # The name the policy authorised is dialled, never the address the
    # guest aimed at, which is this listener.
    try:
        upstream = socket.create_connection(
            (host, TLS.guest_port), timeout=egress_relay.CONNECTION_TIMEOUT)
    except OSError as exc:
        insp.drop(where, dial_failure_reason(
            host, insp.policy.internal_expected), exc,
                  host=host, mode="splice")
        return
    try:
        # The hello is still on the socket, so the relay sends it first and
        # the origin completes its handshake with the guest's own bytes.
        insp.counters.record_splice()
        insp.log(f"splice {where} host={host}"
                 f"{' per-host' if inspect else ''}{_offer(hello)}")
        rec = Record(insp.record, where, "splice", host=host)
        rec.dialled(upstream)
        rec.set(decision="forward")
        try:
            relay(conn, upstream)
        finally:
            rec.emit()
    finally:
        upstream.close()


def _offer(hello):
    """The hello's ALPN offer as a journal field, or nothing."""
    if not hello.alpn:
        return ""
    return f" alpn={quoted(','.join(hello.alpn))}"


def _serve_tls_inspect(insp, conn, where, host, allowed, hello):
    """Terminate one connection: decide, dial, mint, handshake, serve.

    The origin is dialled before the guest's handshake, so a host that
    cannot be reached costs a leaf only to carry the refusal.
    """
    if "h2" in hello.alpn and "http/1.1" not in hello.alpn:
        insp.note(where, NOTE_H2_ONLY,
                  f"the client offered {','.join(hello.alpn)} and not "
                  f"http/1.1, and {host} is served HTTP/1.1 alone, so the "
                  f"handshake selects no protocol and the client will "
                  f"likely fail. A gRPC client, most likely: splice {host}, "
                  f"where its h2 runs end to end and the host is checked by "
                  f"name alone, or use the client's REST transport",
                  host=host)
    upstream = None
    refusal = None            # (drop reason, status, phrase, journal text)
    # A brokered host's requests go to the broker, per request, so the
    # origin is not dialled here: that would make its reachability and
    # certificate a condition of requests that never reach it.
    brokered = allowed and insp.policy.credential_for(host) is not None
    if not allowed:
        refusal = (DROP_NOT_ALLOWLISTED, 403, "Forbidden",
                   (f"{host} matches no `hosts` pattern and no `policy` "
                    f"entry"))
    elif brokered:
        pass
    else:
        try:
            upstream = insp.upstream.dial_tls(host)
        except ssl.SSLError as exc:
            reason, text = tls_failure(host, exc)
            refusal = (reason, 502, "Bad Gateway", text)
        except OSError as exc:
            reason = dial_failure_reason(
                host, insp.policy.internal_expected)
            refusal = (reason, 502, "Bad Gateway",
                       f"{host} could not be reached: {exc}")
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
        tls_conn = wrap_guest(conn, leaf)
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
        insp.log(f"terminate {where} host={host}{_offer(hello)}")
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


def wrap_guest(conn, leaf):
    """Complete the guest's handshake as the origin it dialled."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(leaf.path))
    ctx.set_alpn_protocols(list(UPSTREAM_ALPN))
    return ctx.wrap_socket(conn, server_side=True)


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
