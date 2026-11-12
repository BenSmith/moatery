"""
inspect_http: authorise every request on a connection, and relay the ones
that pass.

Per request, not per connection: one connection carries many requests, each
free to name a different host, and the framing that says where one ends is
the guest's. The cleartext plane enters at serve_cleartext; a terminated TLS
connection enters at serve_one_request with the decrypted socket, so both
planes apply the policy through the same loop.
"""

import ssl

from .egress_record import (
    DROP_BROKER_UNREACHABLE, DROP_CLIENT_CERT, DROP_FILTER_FAILED,
    DROP_FILTER_REFUSED, DROP_FILTER_TIMED_OUT, DROP_FILTER_UNAVAILABLE,
    DROP_MISDIRECTED, DROP_MISDIRECTED_LISTED, DROP_NOT_ALLOWLISTED,
    DROP_NOT_FILTERABLE, DROP_NOT_PERMITTED, DROP_RELAY_FAILED,
    DROP_TIMED_OUT, DROP_UNREADABLE_REQUEST, NOTE_H2_PREFACE, NOTE_H2C,
    Record,
)
from .egress_relay import relay
from . import egress_relay
from .egress_upstream import (
    BROKER_UPSTREAM_KEY, dial_failure_reason, tls_failure,
)
from .http_framing import (
    BodyTooLarge, BudgetSpent, Framing, ReadTimedOut, RequestUnreadable,
    ResetWhileIdle, _Stream, _get_all, _is_count, _split_response_head,
    copy_body, drain, read_body, response_framing, send_response,
)
from .http_request import parse_request, rebuild_request
from .http_target import SCHEME_HTTP, redirect_target
from .inspect_scope import quoted
from .request_filter import (
    FAILED, FILTER_BODY_MAX, FILTER_TIMEOUT, PASSED, REFUSED, REWROTE,
    TIMED_OUT, UNAVAILABLE, filter_env, run_filter,
)


# How many 1xx interim responses one request may collect. A real exchange
# sends one; without a bound an origin could hold the connection with
# interim heads forever.
INTERIM_MAX = 32

# The start of HTTP/2's connection preface, which is a request line.
H2_PREFACE = b"PRI * HTTP/2.0\r\n"

# How each request-filter outcome that forwards nothing is counted and
# answered: (drop reason, status, phrase).
FILTER_ANSWERS = {
    REFUSED: (DROP_FILTER_REFUSED, 403, "Forbidden"),
    FAILED: (DROP_FILTER_FAILED, 502, "Bad Gateway"),
    TIMED_OUT: (DROP_FILTER_TIMED_OUT, 504, "Gateway Timeout"),
    UNAVAILABLE: (DROP_FILTER_UNAVAILABLE, 503, "Service Unavailable"),
}


class _ClientCertDemanded(Exception):
    """The origin's answer to a head already sent was a demand for a
    client certificate. The message is the operator's sentence."""


class _HeadRefused(RequestUnreadable):
    """An origin's response head this relay does not pass on. None of it
    has been sent, so the guest can still be answered."""


def serve_cleartext(insp, conn, where):
    """Authorise every request on this port-80 connection, and relay the
    ones that pass.

    Upstreams are pooled by the authorised name, so a request is only ever
    sent down a connection opened for the name it was authorised for.
    """
    client = _Stream(conn)
    upstreams = {}
    try:
        first = True
        seq = 1
        while serve_one_request(insp, client, conn,
                                      where.request(seq),
                                      upstreams, first):
            first = False
            seq += 1
    finally:
        for up in upstreams.values():
            up.sock.close()


def serve_one_request(insp, client, conn, where, upstreams, first, *,
                       scheme=SCHEME_HTTP, pinned_host=None):
    """One request, and the record it leaves. True to stay on the connection.

    A pass that ends with no decision -- an idle keep-alive reaching its
    bound, a guest closing between requests -- writes no record.
    """
    rec = Record(insp.record, where,
                  "terminate" if pinned_host is not None else "forward")
    try:
        return serve_request(insp, client, conn, where, upstreams, first,
                                   rec, scheme=scheme,
                                   pinned_host=pinned_host)
    finally:
        rec.emit()


def serve_request(insp, client, conn, where, upstreams, first, rec, *,
                   scheme=SCHEME_HTTP, pinned_host=None):
    """One request, start to finish. True to stay on the connection.

    `pinned_host`, on the terminated plane, is the name the session's leaf
    was minted for; a request naming another is answered 421. `first` picks
    the wait for the first byte: the decision timeout on a new connection,
    the idle timeout between requests on a kept-alive one.
    """
    conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
    try:
        head = client.read_head(
            idle_timeout=None if first else egress_relay.RELAY_IDLE_TIMEOUT)
    except ReadTimedOut as exc:
        if exc.idle:
            # An idle kept-alive connection reaching its bound is not a
            # drop, but the operator can still see which end let go.
            insp.log(f"close {where} reason={quoted(exc)}")
            return False
        insp.drop(where, DROP_TIMED_OUT, exc, rec=rec)
        return False
    except ResetWhileIdle as exc:
        # A close between requests, made with a reset.
        insp.log(f"close {where} reason={quoted(exc)}")
        return False
    except RequestUnreadable as exc:
        insp.drop(where, DROP_UNREADABLE_REQUEST, exc, rec=rec)
        return False
    if not head:
        return False                # the guest closed between requests
    # On a kept-alive connection the pass began when the last one ended.
    rec.started()
    try:
        req = parse_request(head, scheme)
    except RequestUnreadable as exc:
        if head.startswith(H2_PREFACE):
            _note_preface(insp, where, pinned_host)
        insp.drop(where, DROP_UNREADABLE_REQUEST, exc, rec=rec, answered=400)
        send_response(conn, 400, "Bad Request", close=True)
        return False
    if pinned_host is not None and req.host != pinned_host:
        rec.request(req)
        insp.drop(where, _binding_reason(insp, req.host),
                  f"the session is for {pinned_host}", host=req.host,
                  rec=rec, answered=421)
        return _refuse(client, conn, req, 421, "Misdirected Request")
    # Read once: a reload between two of its questions would answer them
    # from two documents.
    policy = insp.policy
    # The guest gets the same bare 403 for an unlisted host and a refused
    # method or path; only the journal and the record tell them apart.
    if not policy.admits(req.host):
        rec.request(req)
        insp.drop(where, DROP_NOT_ALLOWLISTED, host=req.host, rec=rec,
                  answered=403)
        return _refuse(client, conn, req, 403, "Forbidden")
    if not policy.permits(req.host, req.method, req.path):
        rec.request(req)
        insp.drop(where, DROP_NOT_PERMITTED, host=req.host, rec=rec,
                  answered=403, method=req.method)
        return _refuse(client, conn, req, 403, "Forbidden")
    rec.request(req)
    # A brokered request goes to the broker instead of the origin, with the
    # same head; the broker picks the credential by its Host.
    credential = policy.credential_for(req.host)
    if credential:
        rec.set(credential=credential)
    run = policy.request_filters.filter_for(req.host)
    if run is None:
        return _forward(insp, client, conn, where, upstreams, rec, req,
                        policy, credential, pinned_host)
    taken = _Taken(insp.filter_budget)
    try:
        return _serve_filtered(insp, client, conn, where, upstreams, rec,
                               req, policy, credential, pinned_host, run,
                               taken)
    finally:
        # After the dial, the send and every early return.
        taken.give_back()


class _Taken:
    """What one request holds of the shared filter budget."""

    def __init__(self, budget):
        self.budget, self.n = budget, 0

    def take(self, n):
        if not self.budget.take(n):
            return False
        self.n += n
        return True

    def give_back(self):
        self.budget.give(self.n)
        self.n = 0


def _unfilterable(req):
    """(status, phrase, why) for a request no filter can be given the
    whole body of, or None."""
    if req.upgrade:
        return (403, "Forbidden",
                "it offers Upgrade, and what follows a 101 is never read")
    codings = {t.strip().lower() for v in _get_all(req.headers,
                                                   "content-encoding")
               for t in v.split(",")} - {"", "identity"}
    if codings:
        return (415, "Unsupported Media Type",
                f"its body is encoded ({', '.join(sorted(codings))}), "
                f"which a filter would read as bytes it cannot judge")
    if req.framing.kind == "length" and req.framing.length > FILTER_BODY_MAX:
        return (413, "Content Too Large",
                f"its {req.framing.length}-byte body is over the "
                f"{FILTER_BODY_MAX}-byte filter cap")
    return None


def _serve_filtered(insp, client, conn, where, upstreams, rec, req, policy,
                    credential, pinned_host, run, taken):
    """A request to a filtered host: refused, answered for its filter, or
    forwarded with the body the filter wrote."""
    refusal = _unfilterable(req)
    if refusal is not None:
        status, phrase, why = refusal
        insp.drop(where, DROP_NOT_FILTERABLE, f"{req.host}: {why}",
                  host=req.host, rec=rec, answered=status)
        return _refuse(client, conn, req, status, phrase)
    if req.framing.kind == "none" or (req.framing.kind == "length"
                                      and req.framing.length == 0):
        return _forward(insp, client, conn, where, upstreams, rec, req,
                        policy, credential, pinned_host)
    if req.expects_continue:
        # As _forward grants it: after policy, here before the body is read.
        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
    conn.settimeout(egress_relay.RELAY_IDLE_TIMEOUT)
    try:
        body = read_body(client, req.framing, FILTER_BODY_MAX, taken.take)
    except ReadTimedOut as exc:
        insp.drop(where, DROP_TIMED_OUT, exc, host=req.host, rec=rec)
        return False
    except RequestUnreadable as exc:
        insp.drop(where, DROP_UNREADABLE_REQUEST, exc, host=req.host,
                  rec=rec, answered=400)
        send_response(conn, 400, "Bad Request", close=True)
        return False
    except BodyTooLarge as exc:
        # The rest of the body is unread, so the connection ends here.
        insp.drop(where, DROP_NOT_FILTERABLE, exc, host=req.host, rec=rec,
                  answered=413)
        send_response(conn, 413, "Content Too Large", close=True)
        return False
    except BudgetSpent as exc:
        insp.drop(where, DROP_FILTER_UNAVAILABLE, exc, host=req.host,
                  rec=rec, answered=503, budget="spent")
        send_response(conn, 503, "Service Unavailable", close=True)
        return False
    outcome = run_filter(
        run, body, filter_env(where.cid, where.seq, req, len(body)),
        budget=insp.filter_budget, slots=insp.filter_slots,
        timeout=FILTER_TIMEOUT, cap=FILTER_BODY_MAX)
    rec.set(filter_ms=outcome.ms)
    if outcome.kind in (PASSED, REWROTE):
        # run_filter left the output taken; it is given back with the body.
        taken.n += len(outcome.body)
        rec.set(filter=outcome.kind)
        held = req._replace(framing=Framing("length", len(outcome.body)),
                            expects_continue=False)
        return _forward(insp, client, conn, where, upstreams, rec, held,
                        policy, credential, pinned_host, outcome=outcome)
    reason, status, phrase = FILTER_ANSWERS[outcome.kind]
    fields = dict(f.split("=", 1) for f in outcome.fields if "=" in f)
    if outcome.kind == REFUSED:
        rec.set(filter=REFUSED)
        fields["filter_reason"] = outcome.reason
    if outcome.spawn_refused:
        insp.warn_unrunnable(policy.request_filters.digest, run,
                             fields.get("errno"))
    insp.drop(where, reason, f"{run}; nothing was sent to {req.host}",
              host=req.host, rec=rec, answered=status, **fields)
    return _answer_read(conn, req, status, phrase)


def _forward(insp, client, conn, where, upstreams, rec, req, policy,
             credential, pinned_host, outcome=None):
    """Dial, send the request and relay its answer. True to stay on the
    connection.

    With a filter's `outcome`, its body is sent in place of the guest's,
    which has been read already.
    """
    # An HTTP/1.0 request is sent with `Connection: close`, so its upstream
    # is not pooled.
    transient = req.version == "HTTP/1.0"
    try:
        up = insp.upstream.connection_for(
            req.host, upstreams, reusable=not transient,
            # Its own pool slot: the terminated plane seeds the pool with an
            # origin connection under the host's name.
            key=BROKER_UPSTREAM_KEY + req.host if credential else req.host,
            dial=insp.upstream.dial_broker if credential
            else (insp.upstream.dial_tls if pinned_host is not None
                  else insp.upstream.dial_cleartext))
    except ssl.SSLError as exc:
        # Before the OSError arm, which would catch it too.
        reason, text = tls_failure(req.host, exc)
        insp.drop(where, reason, text, host=req.host, rec=rec, answered=502)
        return _refuse(client, conn, req, 502, "Bad Gateway")
    except OSError as exc:
        # A dead broker is not the host's failure, so it is not attributed
        # by resolving the host.
        if credential:
            reason = DROP_BROKER_UNREACHABLE
            text = (f"{req.host} is brokered and this workload's "
                    f"credential broker did not answer ({exc}). The "
                    f"request was NOT sent to {req.host}: check that "
                    f"the broker's unit is running, and that its --listen "
                    f"is the endpoint this inspector's --broker names.")
        else:
            reason = dial_failure_reason(
                req.host, policy.internal_expected)
            text = f"{req.host} could not be reached: {exc}"
        insp.drop(where, reason, text, host=req.host, rec=rec, answered=502)
        return _refuse(client, conn, req, 502, "Bad Gateway")
    if credential:
        insp.counters.record_credentialed(req.host, credential)
    # From here the wait is transfer, bounded by idleness.
    conn.settimeout(egress_relay.RELAY_IDLE_TIMEOUT)
    rec.dialled(up.sock)
    try:
        try:
            up.sock.sendall(rebuild_request(req))
        except OSError as exc:
            # Nothing has been sent either way yet, so this is answered like
            # a failed dial rather than closed. Under TLS 1.3 an origin that
            # requires a client certificate can land here as a reset.
            insp.drop(
                where, DROP_RELAY_FAILED,
                f"the request to {req.host} was not delivered: the "
                f"upstream connection failed before its head could be "
                f"sent ({exc}). If {req.host} requires a client "
                f"certificate, this is one of the two ways that arrives -- "
                f"under TLS 1.3 the demand can land after the handshake "
                f"succeeded, leaving a reset rather than a named alert -- "
                f"and it must then be spliced: add {req.host} to the "
                f"policy's `splice` list, and drop any `policy` entry for "
                f"it, so the guest's own handshake reaches {req.host}.",
                host=req.host, rec=rec, answered=502)
            return _refuse(client, conn, req, 502, "Bad Gateway")
        if req.expects_continue:
            # Granted here, after policy. Expect is not forwarded: waiting
            # for the origin's 100 before sending the body deadlocks.
            conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        # The body goes up before the response is read. An origin that
        # answers without reading it stalls this send until the idle
        # timeout.
        if outcome is None:
            copy_body(client, up.sock, req.framing)
        else:
            up.sock.sendall(outcome.body)
        insp.counters.record_forward()
        rec.set(decision="forward")
        filtered = ""
        if outcome is not None:
            insp.counters.record_filtered(outcome.kind)
            filtered = f" filter={outcome.kind} filter_ms={outcome.ms}"
        insp.log(f"forward {where} host={req.host} method={req.method}"
                 f"{filtered}")
        if req.withheld:
            insp.note(where, NOTE_H2C,
                      f"the request offered Upgrade: {req.withheld} and "
                      f"went up without it, as HTTP/1.1: HTTP/2's frames "
                      f"would end the per-request check",
                      host=req.host)
        keep = _relay_response(insp, up, client, conn, req, where, rec)
        if credential and rec.fields.get("status") in (401, 403):
            insp.counters.record_credential_unauthorized()
        return keep
    except _ClientCertDemanded as exc:
        # The origin refused the session before reading anything, so the
        # guest is answered as the dial answers it; closed, since its body
        # has already gone up.
        insp.drop(where, DROP_CLIENT_CERT, exc, host=req.host, rec=rec,
                  answered=502)
        send_response(conn, 502, "Bad Gateway", close=True)
        return False
    except _HeadRefused as exc:
        # Nothing of the answer has reached the guest, so it can be told.
        insp.drop(where, DROP_RELAY_FAILED, exc, host=req.host, rec=rec,
                  answered=502)
        send_response(conn, 502, "Bad Gateway", close=True)
        return False
    except (RequestUnreadable, OSError) as exc:
        # Overwrites the `forward` set above. `status` survives if a head
        # had already come back, which tells a relay that failed before the
        # answer from one that failed after.
        insp.drop(where, DROP_RELAY_FAILED, exc, host=req.host, rec=rec)
        return False
    finally:
        if transient:
            try:
                up.sock.close()
            except OSError:
                pass


def _note_preface(insp, where, pinned_host):
    if pinned_host is None:
        detail = ("the client opened with HTTP/2's preface, prior "
                  "knowledge, and was answered 400: this relay speaks "
                  "HTTP/1.1 alone")
    else:
        detail = (f"the client opened with HTTP/2's preface though the "
                  f"handshake selected no h2, and was answered 400: "
                  f"{pinned_host} is served HTTP/1.1 alone. A client that "
                  f"speaks only h2 needs {pinned_host} spliced")
    insp.note(where, NOTE_H2_PREFACE, detail, host=pinned_host)


def _relay_response(insp, up, client, conn, req, where="", rec=None):
    """Relay one response. True if the connection may carry another.

    The head is parsed leniently, only to learn where its body ends, and
    relayed as the parse read it: it was written by an origin the policy
    authorised, and the smuggling defence is against the guest's framing.
    """
    interim = 0
    while True:
        try:
            head = up.read_head()
        except RequestUnreadable as exc:
            # A TLS 1.3 origin requiring a client certificate names it here
            # when its alert was slower than the dial's early read. Only
            # this read is asked: a guest can send any alert on its own leg.
            if isinstance(exc.__cause__, ssl.SSLError):
                reason, text = tls_failure(req.host, exc.__cause__)
                if reason == DROP_CLIENT_CERT:
                    raise _ClientCertDemanded(text) from exc
            raise
        if not head:
            raise RequestUnreadable("the upstream closed before answering")
        try:
            start, headers, head = _split_response_head(head)
            fields = start.split(" ")
            if len(fields) < 2 or not _is_count(fields[1]):
                raise RequestUnreadable(
                    f"status line {start!r} is not one we read")
            status = int(fields[1])
            if rec is not None:
                rec.set(status=status)
            framing = response_framing(status, req.method, headers)
        except RequestUnreadable as exc:
            raise _HeadRefused(str(exc)) from None
        conn.sendall(head)
        if status == 101:
            # The upgrade request was authorised; what flows after it is not
            # read.
            insp.log(f"upgrade {where} host={req.host} reason="
                     + quoted("switched protocols; per-request policy no "
                              "longer applies to this connection"))
            # Bytes either side read past the boundary belong to the tunnel.
            pending_up = up.take_buffered()
            if pending_up:
                conn.sendall(pending_up)
            pending_client = client.take_buffered()
            if pending_client:
                up.sock.sendall(pending_client)
            return _relay_upgraded(conn, up.sock)
        _note_redirect(insp, status, headers, req, where)
        if 100 <= status < 200:
            interim += 1
            if interim > INTERIM_MAX:
                raise RequestUnreadable(
                    f"the upstream sent more than {INTERIM_MAX} interim "
                    f"responses without a final one")
            continue
        break
    copy_body(up, conn, framing)
    # An origin that closes closes the guest's connection too, rather than
    # a replacement hiding a flapping upstream.
    closing = framing.kind == "close" or "close" in {
        t.strip() for v in _get_all(headers, "connection")
        for t in v.lower().split(",")}
    return not closing and not req.wants_close


def _relay_upgraded(conn, up_sock):
    """Move an upgraded connection's bytes both ways, then end it."""
    relay(conn, up_sock)
    return False


def _note_redirect(insp, status, headers, req, where):
    """Log a redirect off the allowlist. Decides nothing.

    The guest follows it on a new connection, whose refusal cannot say what
    sent it there; this is the one place both names are known.
    """
    if not 300 <= status < 400:
        return
    for value in _get_all(headers, "location"):
        target, path = redirect_target(value)
        if not target:
            continue
        if not insp.policy.admits(target):
            insp.log(f"note {where} host={req.host} reason="
                     + quoted(f"redirected to {target}, which is not "
                              f"allowlisted"))
        elif path is not None and insp.policy.governs(target):
            _note_policy_redirect(insp, status, target, path, req, where)


def _note_policy_redirect(insp, status, target, path, req, where):
    """Log a redirect to an allowlisted host whose policy will refuse it.

    Which method the guest will use is not ours to know, so the note is
    written only when every reading is refused: 307 and 308 keep the
    method, 303 is GET, and 301 and 302 are either.
    """
    if status in (307, 308):
        methods = (req.method,)
    elif status == 303:
        methods = ("GET",)
    elif status in (301, 302):
        methods = (req.method, "GET")
    else:
        return
    if any(insp.policy.permits(target, method, path)
           for method in set(methods)):
        return
    insp.log(f"note {where} host={req.host} reason="
             + quoted(f"redirected to {target}{path}, which its policy "
                      f"entry does not permit"))


def _binding_reason(insp, host):
    """Which figure a name that does not match the session lands in.

    Refused either way. An unlisted name is a guest reusing a session to
    reach a name it was not given; a listed one is usually a client
    coalescing two names it was.
    """
    if insp.policy.admits(host):
        return DROP_MISDIRECTED_LISTED
    return DROP_MISDIRECTED


def _answer_read(conn, req, status, reason):
    """Answer a request whose body has been read whole. True if the
    connection lives: there is nothing left of it to drain."""
    keep = not req.wants_close
    send_response(conn, status, reason, close=not keep)
    return keep


def _refuse(client, conn, req, status, reason):
    """Answer a request we will not relay. True if the connection lives.

    The body is drained before the answer, or the next request would be
    read out of it. It is drained on a connection that closes too: a close
    with the body unread resets it, and the reset can overtake the answer.
    A guest waiting on `Expect: 100-continue` has no body coming, so its
    connection is closed.
    """
    if req.expects_continue:
        keep = False
    else:
        keep = drain(client, req.framing) and not req.wants_close
    send_response(conn, status, reason, close=not keep)
    return keep
