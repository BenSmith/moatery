"""moat-inspect: the terminated TLS plane.

A spliced connection reads a name and replays the guest's own bytes. This
plane TERMINATES -- the listener completes the guest's handshake with a leaf
its own CA signed, opens a separately verified session to the origin, and
authorises every request inside.

WHY THESE TESTS ARE END TO END AND NOT ARGV ASSERTIONS

Every interesting failure on this path is invisible to a test that inspects
arguments. A leaf whose subjectAltName is not marked critical builds a perfect
argv and is then refused by every client. A wrap_socket that consumes the
ClientHello leaves the handshake to hang. A trust store that is loaded but not
consulted looks identical to one that is. So each of these drives a REAL client
against a REAL origin through the real listener: the assertion is on bytes that
came back, and the parts that cannot be true at once fail loudly.

THE ORIGIN IS A SECOND CA, ON PURPOSE

The workload CA signs what the guest sees; a separate throwaway root signs what
the ORIGIN presents. Sharing one would make the upstream verification test pass
for the wrong reason -- the inspector would be verifying a certificate its own
CA signed, which is exactly the check that must not accidentally hold.
"""

import io
import os
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

from tests import assert_bare_refusal, load_script
from tests.test_inspect_listener import _hello_bytes
from moatery.egress_plane import TLS
from moatery.inspect_document import VmPolicyEntry
from moatery.inspect_policy import Policy
from moatery.egress_ca import (
    ca_cert_path, ca_key_path, ca_openssl_argv, leaf_openssl_argv,
)
from moatery.tls_hello import HelloUnreadable, read_client_hello
from moatery.http_target import (
    SCHEME_HTTP, SCHEME_HTTPS, host_from_authority, redirect_target,
)
from moatery.http_framing import (
    Framing, HTTP_METHOD_MAX, ReadTimedOut, RequestUnreadable,
    ResetWhileIdle, _Stream, _is_count, _split_response_head,
    is_http_request_start, request_framing, response_framing,
)
from moatery import egress_mint, egress_upstream
from moatery.egress_upstream import tls_failure
from moatery import inspect_listener
from moatery.inspect_listener import MAX_CONNECTIONS, Listener, build_minter
from moatery.inspect_http import serve_one_request
from moatery import inspect_tls
from moatery.inspect_tls import serve_tls
from moatery.egress_record import (
    DROP_BROKER_UNREACHABLE,
    DROP_CLIENT_CERT,
    DROP_INTERNAL,
    DROP_NOT_HTTP,
    DROP_NOT_HTTP_POLICY,
    DROP_NOT_PERMITTED,
    DROP_RELAY_FAILED,
    DROP_TIMED_OUT,
    DROP_UNREACHABLE,
    DROP_UNREADABLE_REQUEST,
    DROP_UNVERIFIED,
    LOG_ID_FIELD,
    Where,
)

_MOD = None


def _mod():
    global _MOD
    if _MOD is None:
        _MOD = load_script("libexec/moat-inspect")
    return _MOD


def _where(plane="tls", cid="0" * 12):
    """A connection key of the shape _serve builds.

    A plain string will not do since T1c: `where` is a _Where, and the request
    loops ask it for each request's ordinal. Tests that enter at serve_tls or
    serve_cleartext skip _serve, so they build one here.
    """
    return Where(f"{LOG_ID_FIELD}={cid} plane={plane}",
                         cid=cid, plane=plane)


def _have_openssl():
    return bool(__import__("shutil").which("openssl"))


def _run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise AssertionError(f"{argv[:3]} failed: {result.stderr}")


def _make_ca(directory, name):
    """A CA keypair in `directory`, minted by the code under test."""
    directory.mkdir(parents=True, exist_ok=True)
    key, cert = directory / "ca.key", directory / "ca.crt"
    _run(ca_openssl_argv(name, key, cert, now=time.time()))
    return key, cert


def _make_leaf(directory, name, ca_key, ca_cert, stem):
    """A server certificate for `name`, as one PEM holding cert and key.

    Uses the product's own leaf argv, so the origin in these tests is presenting
    a certificate built the same way the inspector's is -- including the
    critical subjectAltName, which is the property an empty subject requires and
    which nothing about the argv reveals.
    """
    key = directory / f"{stem}.key"
    cert = directory / f"{stem}.crt"
    _run(leaf_openssl_argv(name, ca_key, ca_cert, key, cert,
                              now=time.time()))
    pem = directory / f"{stem}.pem"
    pem.write_text(cert.read_text() + key.read_text())
    return pem


class _Origin:
    """A one-connection TLS origin on 127.0.0.1, in its own thread.

    Records the request bytes it managed to read, so a test can assert that a
    refused exchange never reached it -- which is the whole claim of catching a
    client-certificate alert before forwarding anything.
    """

    def __init__(self, pem, *, client_ca=None, response=None, follow=False,
                 alpn=("http/1.1",)):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(pem))
        # Configurable so a test can have an origin that prefers `h2`, and
        # see what the listener's offer makes of it.
        self.ctx.set_alpn_protocols(list(alpn))
        self.alpn_seen = []
        if client_ca is not None:
            # TLS 1.3 only, so the CertificateRequest arrives AFTER a successful
            # handshake and the alert lands on the first read. Under 1.2 the
            # same requirement is a handshake_failure, which is the case the
            # design writes down as not distinguishable.
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            self.ctx.verify_mode = ssl.CERT_REQUIRED
            self.ctx.load_verify_locations(str(client_ca))
        self.response = response or (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        # `follow` keeps reading after the response has been sent, appending
        # each further chunk to `requests`. It is what an upgraded connection
        # needs: the bytes that matter there arrive AFTER the 101, and an origin
        # that closes on the first recv cannot see them at all.
        self.follow = follow
        self.requests = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn = self.ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                raw.close()
                continue
            try:
                conn.settimeout(5.0)
                self.alpn_seen.append(conn.selected_alpn_protocol())
                data = conn.recv(65536)
                if data:
                    self.requests.append(data)
                    conn.sendall(self.response)
                    while self.follow:
                        more = conn.recv(65536)
                        if not more:
                            break
                        self.requests.append(more)
            except (ssl.SSLError, OSError):
                pass
            finally:
                # Half-closed and drained before closing, and it is not
                # tidiness. In the client-certificate case the origin's alert
                # is raised on its FIRST read -- which can happen before the
                # listener's request has even arrived -- and a full close then
                # discards those bytes and answers them with an RST. The reset
                # raced the alert, and the listener classified a
                # `client certificate` refusal as `relay failed` about half the
                # time. A FIN plus a drain lets the alert be what the listener
                # reads, so the fixture stops deciding which branch is under
                # test.
                try:
                    raw.shutdown(socket.SHUT_WR)
                    raw.settimeout(1.0)
                    while raw.recv(65536):
                        pass
                except (OSError, ValueError):
                    pass
                conn.close()

    def close(self):
        self.sock.close()


def _tcp_pair():
    """A connected pair of real TCP sockets: (listener side, guest side)."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    guest = socket.socket()
    guest.connect(server.getsockname())
    ours, _ = server.accept()
    server.close()
    return ours, guest


def _certificate_required():
    """The TLS 1.3 alert an origin requiring a client certificate sends, as
    the ssl module raises it."""
    alert = ssl.SSLError(
        1, "[SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert "
           "certificate required")
    alert.reason = "TLSV13_ALERT_CERTIFICATE_REQUIRED"
    return alert


@unittest.skipUnless(_have_openssl(), "openssl is not installed")
class TerminationCase(unittest.TestCase):
    """A workload CA, a throwaway origin root, and a listener that terminates."""

    HOST = "localhost"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))
        self.state = self.tmp / "state"
        ca_dir = self.state / "ca"
        ca_dir.mkdir(parents=True)
        _run(ca_openssl_argv("demo", ca_key_path(self.state),
                                ca_cert_path(self.state), now=time.time()))
        self.origin_ca_key, self.origin_ca_cert = _make_ca(
            self.tmp / "origin-root", "origin-root")
        self.origin_pem = _make_leaf(self.tmp, self.HOST, self.origin_ca_key,
                                     self.origin_ca_cert, "origin")

    def _minter(self, mod, **kwargs):
        from moatery.egress_mint import Minter
        return Minter("demo", self.state, **kwargs)

    def _listener(self, mod, origin, *, hosts=("localhost",), trust=True,
                  minter=None, entries=()):
        out = io.StringIO()
        # `entries` is the `policy` list as (host, methods, paths) triples.
        policy = Policy(
            tls="inspect", hosts=tuple(hosts),
            policy=tuple(VmPolicyEntry(host=h, methods=m, paths=pa)
                         for h, m, pa in entries))
        listener = Listener([unittest.mock.Mock()], out, policy=policy,
                                minter=minter or self._minter(mod))
        if trust:
            # The product's own context, trusting the test origin as well, so
            # what it offers upstream is what these tests see.
            listener.inspection.upstream._ctx.load_verify_locations(
                str(self.origin_ca_cert))
        return listener, out

    def _guest_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(ca_cert_path(self.state)))
        return ctx

    def _exchange(self, listener, origin, *, request=None, host=None,
                  guest_ctx=None, alpn_out=None):
        """Drive one whole connection and return (response bytes, error).

        The listener half runs in a thread because both ends of a TLS handshake
        have to be live at once; the test is the guest. `alpn_out`, a list,
        receives the protocol the guest's handshake selected.
        """
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        # Short, and not the product's numbers: every assertion here is about
        # bytes that arrive promptly or not at all, and a break-on-purpose run
        # -- where a handshake is MEANT to hang -- has to end in seconds rather
        # than in the listener's own patience.
        ours.settimeout(3.0)
        guest.settimeout(3.0)
        served = threading.Thread(
            target=serve_tls, args=(listener.inspection, ours, _where("tls")), daemon=True)
        # The origin's port, on the plane object both the splice dial
        # (inspect_tls's) and the verifying dial (egress_upstream's) read.
        with unittest.mock.patch.object(
                inspect_tls, "TLS",
                TLS._replace(guest_port=origin.port)), \
                unittest.mock.patch.object(
                    egress_upstream, "TLS",
                    TLS._replace(guest_port=origin.port)):
            served.start()
            ctx = guest_ctx or self._guest_context()
            response, error = b"", None
            tls = None
            try:
                tls = ctx.wrap_socket(guest, server_hostname=host or self.HOST)
                if alpn_out is not None:
                    alpn_out.append(tls.selected_alpn_protocol())
                tls.sendall(request or (
                    f"GET / HTTP/1.1\r\nHost: {host or self.HOST}\r\n"
                    f"Connection: close\r\n\r\n").encode())
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    response += chunk
            except (ssl.SSLError, OSError) as exc:
                error = exc
            finally:
                if tls is not None:
                    tls.close()
            served.join(timeout=15)
        return response, error

    def _open_fds(self):
        return len(os.listdir("/proc/self/fd"))


class TestAnAllowlistedHostIsReachedThroughTheInspector(TerminationCase):

    def test_the_guest_gets_the_origins_bytes(self):
        """The gate: CA installed, allowlisted name, the origin's own body.

        Everything the rung claims has to hold at once for this to pass -- the
        leaf verifies against the workload CA, the peeked ClientHello was still
        there for the handshake, the upstream leg verified against a different
        root, and the request was relayed and answered.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        self.assertIn(b"200 OK", response)
        self.assertTrue(response.endswith(b"hello"), response)
        self.assertIn(b"Host: localhost", origin.requests[0])
        self.assertIn("terminate", out.getvalue())
        self.assertEqual(listener.status()["dispositions"]["terminated"], 1)
        self.assertEqual(listener.status()["dispositions"]["forwarded"], 1)

    def test_a_second_request_reuses_the_leaf_rather_than_minting(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        minter = self._minter(mod)
        listener, _ = self._listener(mod, origin, minter=minter)
        self._exchange(listener, origin)
        self._exchange(listener, origin)
        self.assertEqual(minter.stats["mints"], 1)
        self.assertEqual(minter.stats["hits"], 1)
        self.assertEqual(listener.status()["mint"]["mints"], 1)


class TestAClientThatRefusesTheLeafIsToldBothRemedies(TerminationCase):
    """The drop when the GUEST rejects the leaf, and the sentence it produces.

    There are exactly two reasons a client refuses a leaf this CA signed, and
    they need opposite remedies:

      1. It COULD have been given the CA and was not -- a VM instance seeded
         before the workload had one (cloud-init will not revisit it), or a
         container whose `ca_delivery` route is absent or wrong. Fixable.
      2. It CANNOT be given the CA at all, because its trust store is embedded
         in the image and it reads none of the five CA environment variables.
         A JVM is the common one; anything on rustls with webpki-roots is the
         same shape. There is no CA route to repair.

    THIS SENTENCE NAMED ONLY (1) AND WAS THEREFORE WRONG HALF THE TIME.
    Measured on hardware 2026-09-06 with container_egress_rig.py's R9 row: a
    JDK image under `ca_delivery = "env"` had all five variables delivered and
    readable, refused the leaf anyway, and the operator was told to re-seed a
    guest that does not exist. The listener cannot tell the two apart -- it
    sees a handshake that did not complete and nothing about how the client was
    built -- so it must name both rather than guess.

    Driven end to end rather than asserted against the source, because a
    grep would pass on the sentence sitting in a branch nothing reaches.
    """

    def _stranger_context(self):
        """A guest that trusts the ORIGIN's root and not the workload CA.

        Deliberately not `CERT_NONE`: a client that verifies nothing completes
        the handshake and takes this path nowhere near. The refusal has to be a
        real one.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(self.origin_ca_cert))
        return ctx

    def test_the_refusal_is_recorded_as_a_drop(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(listener, origin,
                                         guest_ctx=self._stranger_context())
        self.assertEqual(response, b"")
        self.assertIsNotNone(error)
        self.assertIn("drop", out.getvalue())

    def test_the_drop_names_the_embedded_store_case_and_its_remedy(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        self._exchange(listener, origin, guest_ctx=self._stranger_context())
        logged = out.getvalue()
        # The remedy, and the host it applies to. An operator who has to work
        # out which host to exempt from a message that does not say has the
        # same problem one step later.
        self.assertIn("splice", logged)
        self.assertIn(self.HOST, logged)

    def test_it_still_names_the_re_provisioning_case(self):
        """Naming only the embedded-store case would be the same defect
        mirrored: a workload provisioned before the CA existed really does
        need re-provisioning, and dropping that half to fix the other one
        would move the wrongness to the other kind of client.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        self._exchange(listener, origin, guest_ctx=self._stranger_context())
        logged = out.getvalue()
        self.assertIn("re-provision", logged)
        self.assertIn("environment variables are absent or wrong", logged)


class TestADeniedNameIsBumpedRatherThanClosed(TerminationCase):

    def test_the_guest_gets_a_readable_403_through_a_chain_it_trusts(self):
        """The property the CA exists for.

        Spliced, a refused name is a closed connection and the guest learns
        nothing it can distinguish from the host being down. Terminated, the
        same refusal is a readable 403, delivered inside a TLS session the
        guest's own verification accepted. The body is deliberately generic --
        the host and the reason are the operator's, in the journal and the
        record, not the guest's -- so what the guest gains is a legible STATUS,
        not a legible reason.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin, hosts=("nothing.example",))
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error, f"the handshake must succeed: {error}")
        self.assertIn(b"403 Forbidden", response)
        self.assertNotIn(b"egress allowlist", response)
        self.assertNotIn(b"moatery", response)
        self.assertEqual(origin.requests, [],
                         "a denied name must never reach an origin")
        status = listener.status()
        self.assertEqual(status["bumped"], 1)
        self.assertEqual(status["drop_reasons"]["not allowlisted"], 1)
        self.assertEqual(status["dispositions"]["terminated"], 0)

    def test_the_wrapped_socket_is_closed_before_the_handler_returns(self):
        """wrap_socket DETACHES the socket it wraps, so `_serve`'s own close is
        a no-op from that point and this is the only thing that closes the
        guest's connection.

        Asserted on the fd rather than on a count of open descriptors: CPython
        refcounting collects the SSLSocket soon after the handler returns and
        closes it anyway, so a count-based test passes with the close deleted.
        What is actually being defended is that the close is DETERMINISTIC in a
        process holding up to MAX_CONNECTIONS of these, not that a collector
        eventually gets to it.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin, hosts=("nothing.example",))
        wrapped = []
        real = inspect_tls.wrap_guest

        def capture(conn, leaf, *args):
            # *args, not the current signature spelled out: this test is about
            # the CLOSE, and a wrapper that had to be edited every time an
            # argument joined wrap_guest would fail as a missing socket rather
            # than as the mismatch it is.
            sock = real(conn, leaf, *args)
            wrapped.append(sock)
            return sock

        with unittest.mock.patch.object(inspect_tls, "wrap_guest", capture):
            self._exchange(listener, origin)
        self.assertEqual(len(wrapped), 1)
        self.assertEqual(wrapped[0].fileno(), -1,
                         "the handler returned with the guest's socket open")

    def test_the_denial_leaf_lands_in_the_denial_directory(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        minter = self._minter(mod)
        listener, _ = self._listener(mod, origin, hosts=("nothing.example",),
                                     minter=minter)
        self._exchange(listener, origin)
        self.assertEqual(len(minter.denials), 1)
        self.assertEqual(len(minter.working_set), 0)


class TestABumpedRefusalSaysNothingOfTheInspector(TerminationCase):
    """The refusals written inside a terminated session: a 421 for a name
    the session was not minted for, and the bumped 403 and 502.

    The 421 body named both names in a sentence of ours. The bumped
    answers are the status's phrase already; all three now carry the
    `Date` every origin sends.
    """

    def test_the_421_is_bare(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: other.example\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        assert_bare_refusal(self, response, 421, "Misdirected Request")
        self.assertIn("other.example", out.getvalue())

    def test_the_bumped_403_is_bare(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin,
                                       hosts=("nothing.example",))
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        assert_bare_refusal(self, response, 403, "Forbidden")
        self.assertIn("matches no `hosts` pattern", out.getvalue())

    def test_the_bumped_502_is_bare(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin, trust=False)
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        assert_bare_refusal(self, response, 502, "Bad Gateway")


class TestAnUnverifiableUpstreamIsBumpedWithA502(TerminationCase):

    def test_the_502_is_generic_and_the_journal_names_the_reason(self):
        """A failed handshake here would be an opaque error to the guest.

        The guest gets a readable 502 and nothing more: the reason names this
        host's trust anchors, which is a fact about the sandbox. It goes to
        the journal, and it has to point at the HOST's anchors, because that
        is where the operator's one-line fix lives.

        The body used to carry the sentence, which handed a guest the words
        "THIS HOST's trust anchors" on its first unverifiable request.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        # trust=False: the listener keeps its real default context, which does
        # not know the throwaway origin root.
        listener, out = self._listener(mod, origin, trust=False)
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        self.assertTrue(response.endswith(b"\r\n\r\nBad Gateway\n"),
                        response)
        log = out.getvalue()
        self.assertIn("localhost", log)
        self.assertIn("could not be verified", log)
        self.assertIn("THIS HOST", log)
        status = listener.status()
        self.assertEqual(
            status["drop_reasons"]["upstream certificate unverified"], 1)
        self.assertEqual(status["bumped"], 1)

    def test_the_leaf_stays_in_the_working_set_not_the_denial_set(self):
        """The name was allowlisted; only the host was unreachable.

        Filing it under denials would let a transient upstream failure push a
        legitimate name into the small cache a flood can churn, so the next
        successful connection to it pays for a mint it should not.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        minter = self._minter(mod)
        listener, _ = self._listener(mod, origin, trust=False, minter=minter)
        self._exchange(listener, origin)
        self.assertEqual(len(minter.working_set), 1)
        self.assertEqual(len(minter.denials), 0)


class TestTheClientCertificateCase(TerminationCase):

    def test_tls13_required_is_named_and_the_request_never_arrives(self):
        """One of three cases, and the only distinguishable one.

        TWO DISPOSITIONS, BOTH LEGITIMATE, AND THE TEST ASSERTS THE DISJUNCTION.
        Under TLS 1.3 the CertificateRequest is answered after the handshake
        succeeds, so the demand can surface as an SSLError on the dial --
        `CERTIFICATE_REQUIRED`, named exactly -- or, once the head is written,
        as the same alert on the first read or as a reset, with nothing left
        to read the reason from. Which one happens is decided inside the
        peer's stack; the two alerts are one reason and the reset the other.

        Asserting only the first is what this test used to do, and it failed
        about one run in thirty as a result. That read as flakiness; it was not.
        On the losing branch the guest received an EMPTY response, because the
        relay's handler closed the connection instead of refusing it -- so the
        race was hiding a real defect, and the fix was to make BOTH branches
        deliver a legible 502 rather than to make the race go away, which
        nothing here can do. The alert on the first read was a third branch
        with the same defect, and this test reported it as the same flake.

        What must hold either way: the guest is given a 502, the journal's
        sentence points at splice, and the request never reaches an origin
        that will refuse the session.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem, client_ca=self.origin_ca_cert)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        self.assertTrue(response.endswith(b"\r\n\r\nBad Gateway\n"),
                        response)
        self.assertIn("client certificate", out.getvalue())
        self.assertIn("`splice` list", out.getvalue())
        self.assertEqual(origin.requests, [],
                         "the request must not reach an origin that will "
                         "refuse the session")
        reasons = listener.status()["drop_reasons"]
        named = reasons["upstream wants a client certificate"]
        deferred = reasons["relay failed"]
        self.assertEqual(
            named + deferred, 1,
            f"exactly one refusal, under one of the two reasons this can "
            f"arrive as; got named={named} deferred={deferred}")

    def test_the_tls12_case_names_the_possibility_without_asserting_it(self):
        """Written down as unmet rather than guessed at.

        `handshake_failure` is shared with half a dozen causes, so the sentence
        says "this is also what that looks like" instead of claiming it.
        """
        mod = _mod()
        listener, _ = self._listener(mod, unittest.mock.Mock(), trust=False)
        exc = ssl.SSLError("handshake failure")
        exc.reason = "SSLV3_ALERT_HANDSHAKE_FAILURE"
        reason, text = tls_failure("api.example", exc)
        self.assertEqual(reason, DROP_UNVERIFIED)
        self.assertIn("not distinguishable", text)
        self.assertIn("api.example", text)


class TestTheHostHeaderIsPinnedToTheServerName(TerminationCase):

    def test_another_name_inside_the_session_is_misdirected(self):
        """421, not 403: the name may well be allowlisted.

        What it is not is the name this session's certificate was minted for,
        and relaying it down this connection would send it to an origin its own
        Host header never authorised.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(
            mod, origin, hosts=("localhost", "other.example"))
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: other.example\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertIn(b"421 Misdirected Request", response)
        self.assertEqual(origin.requests, [])
        # The ALLOWLISTED half: `other.example` is on this workload's list, so
        # the mismatch is a client reusing a session across two names it was
        # given, not a guest reaching for one it was not.
        status = listener.status()
        self.assertEqual(
            status["drop_reasons"][
                "host does not match the server name (allowlisted)"], 1)
        self.assertEqual(
            status["drop_reasons"]["host does not match the server name"], 0)
        self.assertEqual(
            status["per_host"][
                "host does not match the server name (allowlisted)"],
            {"other.example": 1})
        self.assertNotIn("suspect", out.getvalue())
        self.assertEqual(status["suspects"], 0)

    def test_a_name_on_no_list_inside_the_session_is_the_other_figure(self):
        """Same refusal, same 421, different figure.

        This is the attack the name binding exists to close -- a guest
        reusing a session it was granted to reach a name it never was -- and
        an operator
        reading a merged count could not tell it from the coalescing client
        above. `admits` decides which figure and nothing else: the request is
        refused either way, and it is refused BEFORE the allowlist check, so
        the guest learns no more than the 421 already tells it.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin, hosts=("localhost",))
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: evil.example\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertIn(b"421 Misdirected Request", response)
        self.assertEqual(origin.requests, [])
        status = listener.status()
        self.assertEqual(
            status["drop_reasons"]["host does not match the server name"], 1)
        self.assertEqual(
            status["drop_reasons"][
                "host does not match the server name (allowlisted)"], 0)
        # No per-host map for this half: the guest picks the name and there is
        # no bound on how many it invents. The log line carries it.
        self.assertNotIn("host does not match the server name",
                         status["per_host"])
        self.assertIn("host=evil.example suspect=yes", out.getvalue())
        self.assertNotIn("(allowlisted)", out.getvalue())
        self.assertEqual(status["suspects"], 1)

    def test_neither_binding_figure_is_a_policy_denial(self):
        """`not allowlisted` and `not permitted by policy` stay at zero
        through both, or the binding figure, meant to be read at a glance, is
        being read out of a bucket three different decisions land in."""
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(
            mod, origin, hosts=("localhost", "other.example"))
        self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: other.example\r\n"
                    b"Connection: close\r\n\r\n")
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons["not allowlisted"], 0)
        self.assertEqual(reasons["not permitted by policy"], 0)

    def test_a_trailing_root_dot_is_the_same_name(self):
        """`localhost.` and `localhost` are one name, and a naive comparison
        rejects a legitimate request. Name normalisation, as a fixture."""
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin)
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: localhost.\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertNotIn(b"421", response)
        self.assertEqual(len(origin.requests), 1)

    def test_an_uppercase_host_is_the_same_name(self):
        """DNS names are case-insensitive; the binding has to be too."""
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin)
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: LOCALHOST\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertNotIn(b"421", response)
        self.assertEqual(len(origin.requests), 1)

    def test_the_port_spelling_is_accepted_end_to_end(self):
        """`Host: name:443` reaches the origin rather than being bound out.

        The unit test below asserts the parser accepts it; this asserts the
        BINDING does, which is a different comparison -- the port is dropped
        before the pinned name is compared, and a copy that kept it would
        refuse the ordinary spelling on the plane it is ordinary on.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin)
        response, error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: localhost:443\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertNotIn(b"421", response)
        self.assertEqual(len(origin.requests), 1)

    def test_a_denied_host_mid_connection_leaves_its_neighbours_alone(self):
        """Three requests on ONE session: good, bound out,
        good. The 421 is the middle one's alone -- pinning to the first Host
        or tearing the connection down would either send a later request to an
        upstream it never authorised or lose one that was authorised.

        The THIRD request is asserted on the log rather than on the origin:
        `_Origin` answers one request per connection and closes, and whether
        its close has arrived before the third request is sent -- redialled,
        or written into the closing socket -- is the fixture's race, not the
        listener's. What is under test is that the request was authorised and
        forwarded after the refusal, which is a line the loop only reaches by
        having stayed on the connection. The redial has tests of its own.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(
            mod, origin, hosts=("localhost", "other.example"))
        response, error = self._exchange(
            listener, origin,
            request=b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n"
                    b"GET /two HTTP/1.1\r\nHost: other.example\r\n\r\n"
                    b"GET /three HTTP/1.1\r\nHost: localhost\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertEqual(response.count(b"421 Misdirected Request"), 1)
        self.assertIn(b"200 OK", response)
        self.assertEqual(origin.requests[0].split(b" ")[1], b"/one")
        self.assertNotIn(b"/two", b"".join(origin.requests))
        log = out.getvalue()
        # Counted with the request ordinal wildcarded: `where` carries a
        # `req=` between the plane and the host, and these are requests 1 and
        # 3 -- pinning the whole literal here would pin the ordinal too and
        # assert the numbering rather than the authorisation.
        forwards = re.findall(r"forward id=[0-9a-f]+ plane=tls req=\d+ host=localhost", log)
        self.assertEqual(len(forwards), 2,
                         "the request after the refusal must be authorised")
        self.assertEqual(log.count("host=other.example"), 1)
        self.assertEqual(
            listener.status()["drop_reasons"][
                "host does not match the server name (allowlisted)"], 1)

    def test_the_port_this_plane_reaches_is_accepted_in_a_host_header(self):
        """`Host: name:443` is the ordinary spelling on a terminated plane.

        The shared parser hard-coded port 80 while only the cleartext plane used
        it; a copy that still did would refuse this as naming a destination
        neither end is on.
        """
        self.assertEqual(
            host_from_authority("localhost:443", SCHEME_HTTPS).host,
            "localhost")
        with self.assertRaises(RequestUnreadable):
            host_from_authority("localhost:443", SCHEME_HTTP)
        with self.assertRaises(RequestUnreadable):
            host_from_authority("localhost:80", SCHEME_HTTPS)


class TestUpgradesAreRelayedAfterThePolicyCheck(TerminationCase):

    def test_a_101_hands_the_connection_to_the_relay_and_says_so(self):
        """The REQUEST was policed; the stream is not, and the log says which.

        An upgraded connection cannot carry further HTTP requests, so nothing is
        being re-authorised and lost -- but "policy stopped applying here" is
        not something an operator should have to infer.
        """
        mod = _mod()
        origin = _Origin(
            self.origin_pem,
            response=b"HTTP/1.1 101 Switching Protocols\r\n"
                     b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                     b"\x81\x03abc")
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(
            listener, origin,
            request=b"GET /ws HTTP/1.1\r\nHost: localhost\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        self.assertIn(b"101 Switching Protocols", response)
        self.assertIn(b"\x81\x03abc", response,
                      "the post-101 bytes must be relayed, buffer included")
        self.assertIn("upgrade", out.getvalue())
        self.assertIn("policy no longer applies", out.getvalue())
        # THE HALF THIS TEST USED TO MISS. _Origin answers 101 whatever it is
        # sent, so every assertion above held while the offer was being stripped
        # on the way upstream -- `Upgrade` and `Connection` are both in
        # _NOT_FORWARDED, so for one rung no real origin could ever have
        # answered 101 and this whole path was unreachable in production. The
        # request the origin actually received is the only thing that says
        # otherwise.
        self.assertTrue(origin.requests, "the origin saw no request at all")
        upstream = origin.requests[0]
        self.assertIn(b"Upgrade: websocket", upstream,
                      "the upgrade offer must reach the origin, or nothing can "
                      "ever answer 101")
        self.assertIn(b"Connection: upgrade", upstream)

    def test_a_policy_entry_decides_which_endpoint_may_be_upgraded(self):
        """`Upgrade:` is an ordinary HTTP request -- method, path and Host are
        all plain text -- so `paths` still decides WHICH endpoint may be
        upgraded, which is most of its value.

        The origin is the same one that answers 101 to anything, so a listener
        that let the request through would produce a 101 here. It never sees
        the request at all: the refusal happens before the upstream is dialled,
        which is what keeps the un-policed stream from existing.
        """
        mod = _mod()
        origin = _Origin(
            self.origin_pem,
            response=b"HTTP/1.1 101 Switching Protocols\r\n"
                     b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        self.addCleanup(origin.close)
        listener, out = self._listener(
            mod, origin, entries=(("localhost", None, ("/ws/allowed",)),))
        response, error = self._exchange(
            listener, origin,
            request=b"GET /ws/other HTTP/1.1\r\nHost: localhost\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                    b"Connection: close\r\n\r\n")
        self.assertIsNone(error)
        self.assertIn(b"403 Forbidden", response)
        self.assertNotIn(b"101", response)
        self.assertEqual(origin.requests, [])
        self.assertNotIn("policy no longer applies", out.getvalue())
        self.assertEqual(
            listener.status()["drop_reasons"]["not permitted by policy"], 1)

    def test_the_permitted_endpoint_still_upgrades(self):
        """The other half of the same rule, or the test above would pass on a
        listener that refused every upgrade."""
        mod = _mod()
        origin = _Origin(
            self.origin_pem,
            response=b"HTTP/1.1 101 Switching Protocols\r\n"
                     b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        self.addCleanup(origin.close)
        listener, out = self._listener(
            mod, origin, entries=(("localhost", None, ("/ws/allowed",)),))
        response, error = self._exchange(
            listener, origin,
            request=b"GET /ws/allowed HTTP/1.1\r\nHost: localhost\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        self.assertIn(b"101 Switching Protocols", response)
        self.assertIn("policy no longer applies", out.getvalue())

    def test_the_guests_pipelined_bytes_survive_the_upgrade(self):
        """Bytes sent behind the upgrade request belong to the tunnel.

        A client is entitled to write its first frame in the same segment as the
        request that upgrades. Those bytes are read off the socket by the head
        parser and sit in its buffer, and the 101 path has to hand them to the
        upstream -- it forwarded the origin's surplus to the guest for a rung
        while dropping the guest's on the floor, which presents as a tunnel that
        opens and then stalls rather than as lost bytes.
        """
        mod = _mod()
        origin = _Origin(
            self.origin_pem, follow=True,
            response=b"HTTP/1.1 101 Switching Protocols\r\n"
                     b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        self.addCleanup(origin.close)
        listener, _out = self._listener(mod, origin)
        self._exchange(
            listener, origin,
            request=b"GET /ws HTTP/1.1\r\nHost: localhost\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                    b"\x81\x03xyz")
        self.assertIn(b"\x81\x03xyz", b"".join(origin.requests),
                      "the guest's pipelined frame must reach the origin")

    def test_an_h2c_upgrade_is_not_carried(self):
        """HTTP/2 is the one upgrade that would cost the per-request check.

        An h2c connection carries HPACK-compressed frames this relay cannot
        read, so forwarding the offer would hand the guest a way out of
        per-request authorisation. The request still completes as the ordinary
        HTTP/1.1 exchange it also is -- a declined upgrade, which is behaviour
        HTTP already defines, not a refusal the guest has to interpret.
        """
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        response, _error = self._exchange(
            listener, origin,
            request=b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                    b"Upgrade: h2c\r\nConnection: Upgrade\r\n"
                    b"HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n")
        self.assertIn(b"200 OK", response)
        upstream = origin.requests[0]
        self.assertNotIn(b"Upgrade:", upstream)
        self.assertNotIn(b"Connection: upgrade", upstream)
        self.assertIn('reason="h2c withheld: ', out.getvalue())
        self.assertEqual(listener.status()["notes"]["h2c withheld"], 1)


class TestARedirectOffTheAllowlistIsNamedWhereBothNamesAreKnown(
        TerminationCase):
    """The only point in the system that knows both names.

    Driven through a REAL exchange rather than by calling the helper: what is
    being defended is that a response passing through the relay reaches this
    check at all. A test that called `_note_redirect` itself would stay green
    with the call site deleted, which is the shape of failure this rung has
    already been bitten by once.
    """

    def _redirecting_origin(self, location, status=302, reason="Found"):
        body = (f"HTTP/1.1 {status} {reason}\r\nLocation: {location}\r\n"
                f"Content-Length: 0\r\nConnection: close\r\n\r\n").encode()
        origin = _Origin(self.origin_pem, response=body)
        self.addCleanup(origin.close)
        return origin

    def test_the_note_names_the_origin_and_the_target(self):
        mod = _mod()
        origin = self._redirecting_origin("https://cdn.elsewhere/x")
        listener, out = self._listener(mod, origin)
        response, error = self._exchange(listener, origin)
        self.assertIn(b"302 Found", response)
        line = out.getvalue()
        self.assertIn("cdn.elsewhere", line)
        self.assertIn("not allowlisted", line)
        self.assertIn("host=localhost", line)

    def test_a_redirect_that_stays_on_the_list_is_silent(self):
        mod = _mod()
        origin = self._redirecting_origin("https://other.example/x")
        listener, out = self._listener(
            mod, origin, hosts=("localhost", "other.example"))
        self._exchange(listener, origin)
        self.assertNotIn("redirected to", out.getvalue())

    def test_a_relative_location_names_no_host(self):
        self.assertIsNone(redirect_target("/next")[0])
        self.assertIsNone(redirect_target("//host-relative/x")[0])

    def test_a_port_in_the_location_does_not_lose_the_name(self):
        """host_from_authority refuses a port the plane does not reach, which
        is right for authorising and wrong for reporting."""
        self.assertEqual(redirect_target("https://cdn.elsewhere:8443/x")[0],
                         "cdn.elsewhere")

    # --- the target its own policy entry will refuse ---

    def _policy_listener(self, mod, origin, methods=None, paths=("/ok/*",)):
        return self._listener(
            mod, origin, hosts=("localhost",),
            entries=(("other.example", methods, paths),))

    def test_a_target_its_policy_entry_refuses_names_both_hosts(self):
        """The other half. The target IS allowlisted, so the
        `not allowlisted` note stays silent, and the guest's next connection
        ends in a 403 naming a host and a path with nothing tying either back
        to the site that sent it there."""
        mod = _mod()
        origin = self._redirecting_origin("https://other.example/blocked")
        listener, out = self._policy_listener(mod, origin)
        self._exchange(listener, origin)
        line = out.getvalue()
        self.assertIn("host=localhost", line)
        self.assertIn("other.example/blocked", line)
        self.assertIn("policy entry does not permit", line)
        self.assertNotIn("not allowlisted", line)

    def test_a_target_its_policy_entry_permits_is_silent(self):
        mod = _mod()
        origin = self._redirecting_origin("https://other.example/ok/x")
        listener, out = self._policy_listener(mod, origin)
        self._exchange(listener, origin)
        self.assertNotIn("redirected to", out.getvalue())

    def test_an_allowlisted_target_no_entry_governs_is_silent(self):
        """`hosts` alone permits every path on it, so there is no verdict to
        predict and a note would send the operator to a file with nothing in
        it to change."""
        mod = _mod()
        origin = self._redirecting_origin("https://other.example/blocked")
        listener, out = self._listener(
            mod, origin, hosts=("localhost", "other.example"))
        self._exchange(listener, origin)
        self.assertNotIn("redirected to", out.getvalue())

    def test_a_307_is_read_with_the_method_the_guest_used(self):
        """307 preserves the method, so the POST is the request the guest is
        about to repeat and `methods = ["GET"]` is what will refuse it."""
        mod = _mod()
        origin = self._redirecting_origin("https://other.example/ok/x",
                                          307, "Temporary Redirect")
        listener, out = self._policy_listener(mod, origin, methods=("GET",))
        self._exchange(
            listener, origin,
            request=b"POST /p HTTP/1.1\r\nHost: localhost\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        self.assertIn("policy entry does not permit", out.getvalue())

    def test_a_302_says_nothing_when_either_reading_permits(self):
        """301 and 302 have two live readings -- the RFC preserves the method,
        every real client rewrites a non-GET to GET -- so a note is emitted
        only when the entry refuses BOTH. Silent here because the GET reading
        is permitted, and a note claiming otherwise would send an operator to
        edit a rule that was never going to fire."""
        mod = _mod()
        origin = self._redirecting_origin("https://other.example/ok/x")
        listener, out = self._policy_listener(mod, origin, methods=("GET",))
        self._exchange(
            listener, origin,
            request=b"POST /p HTTP/1.1\r\nHost: localhost\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        self.assertNotIn("redirected to", out.getvalue())

    def test_a_304_predicts_nothing(self):
        """A Location on a 300/304/305 does not describe a request the guest
        is about to repeat."""
        mod = _mod()
        origin = self._redirecting_origin("https://other.example/blocked",
                                          304, "Not Modified")
        listener, out = self._policy_listener(mod, origin)
        self._exchange(listener, origin)
        self.assertNotIn("`policy`", out.getvalue())

    def test_the_path_is_normalised_the_way_the_request_side_will(self):
        """The note predicts a verdict the guest's NEXT connection will get,
        so it has to be judged on the same string that connection is. A path
        normalised differently here produces a note that contradicts the 403
        it exists to explain."""
        self.assertEqual(redirect_target("https://h/a/../b"), ("h", "/b"))
        self.assertEqual(redirect_target("https://h/p?q=1/2"), ("h", "/p"))
        self.assertEqual(redirect_target("https://h/p#f/g"), ("h", "/p"))
        self.assertEqual(redirect_target("https://h"), ("h", "/"))
        self.assertEqual(redirect_target("https://h?q=1"), ("h", "/"))
        self.assertEqual(redirect_target("https://h:8443/x"), ("h", "/x"))
        self.assertEqual(redirect_target("/next"), (None, None))

    def test_a_path_that_cannot_be_normalised_predicts_nothing(self):
        """None is not "no refusal": an encoded slash has two readings and the
        request side declines to pick one, so there is no string to judge."""
        host, path = redirect_target("https://h/a%2fb")
        self.assertEqual(host, "h")
        self.assertIsNone(path)


class TestTheStartRefusesWhatItCannotDo(unittest.TestCase):

    def test_inspect_without_a_ca_fails_the_start(self):
        """Loud at start, not at the first connection.

        The CA is made by `workload-vm-inspect up` before this process is ever
        activated, so its absence is a provisioning failure -- and one that
        surfaced as a single refused connection an hour after boot is a
        provisioning failure nobody attributes.
        """
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError) as caught:
                build_minter("demo", Path(tmp),
                             Policy(tls="inspect", hosts=("a.example",)))
        self.assertIn("egress CA", str(caught.exception))

    def test_splice_needs_no_minter(self):
        self.assertIsNone(
            build_minter("demo", "/nonexistent", Policy(tls="splice", hosts=())))

    def test_a_terminating_listener_with_no_minter_drops_loudly(self):
        """Unreachable through main(), and it still must not be silent.

        The alternative is a listener that fails every guest handshake with an
        opaque certificate error while reporting itself up.
        """
        out = io.StringIO()
        listener = Listener([unittest.mock.Mock()], out,
                                policy=Policy(tls="inspect",
                                                  hosts=("a.example",)))
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        serve_tls(listener.inspection, ours, _where("tls"))
        self.assertIn("has no minter", out.getvalue())
        self.assertEqual(
            listener.status()["drop_reasons"]["could not mint a leaf"], 1)


class TestThePeekLeavesTheHelloWhereItWas(unittest.TestCase):
    """wrap_socket consumes from the SOCKET; a hello already read is gone.

    This is the difference between the two modes' readers, and it is not
    visible in either one's output -- a consuming read parses the same name and
    then hangs the handshake.
    """

    def _hello(self):
        """A real ClientHello, captured by starting one and never finishing."""
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        self.addCleanup(holder.close)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        client = socket.socket()
        client.settimeout(2.0)
        client.connect(holder.getsockname())
        self.addCleanup(client.close)
        def start_and_abandon():
            # It never completes -- nothing on the far end answers -- and the
            # exception it dies of is the point of the fixture, not a failure.
            try:
                ctx.wrap_socket(client, server_hostname="peek.example")
            except (ssl.SSLError, OSError):
                pass

        threading.Thread(target=start_and_abandon, daemon=True).start()
        conn, _ = holder.accept()
        conn.settimeout(5.0)
        return conn

    def test_peeking_reads_the_name_and_consumes_nothing(self):
        conn = self._hello()
        self.addCleanup(conn.close)
        hello = read_client_hello(conn)
        self.assertEqual(hello.server_name, "peek.example")
        self.assertEqual(read_client_hello(conn).server_name, "peek.example",
                         "a peek that consumed would not find it twice")

    def test_a_hello_that_never_arrives_whole_is_refused_not_spun_on(self):
        """MSG_WAITALL is advisory under a socket timeout, so a dribbling peer
        gets short reads forever. Without the no-progress guard that is a
        ceiling slot held until the peer feels like closing."""
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(0.3)
        guest.sendall(bytes([0x16, 0x03, 0x01, 0x40, 0x00]))   # 16 KiB claimed
        started = time.monotonic()
        with self.assertRaises(HelloUnreadable):
            read_client_hello(ours)
        self.assertLess(time.monotonic() - started, 10.0)

    def test_a_hello_split_across_segments_is_waited_for(self):
        """A socket with a timeout is non-blocking underneath, so while half a
        hello is buffered the peek returns that half at once. The default
        post-quantum hello is larger than a 1500-MTU segment, so a peek that
        took "no progress" for "too big" refused real clients whenever it woke
        between the two segments."""
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        hello = self._hello()
        self.addCleanup(hello.close)
        read_client_hello(hello)
        raw = hello.recv(65536)
        half = len(raw) // 2
        ours.settimeout(5.0)
        guest.sendall(raw[:half])

        def rest():
            time.sleep(0.2)
            guest.sendall(raw[half:])

        threading.Thread(target=rest, daemon=True).start()
        parsed = read_client_hello(ours)
        self.assertEqual(parsed.server_name, "peek.example")


class TestADribbledReadIsBoundedAsAWhole(unittest.TestCase):
    """A peer that sends one byte inside every timeout never trips a
    per-read bound, so the timeout has to bound the whole read: the hello,
    and a guest's request head."""

    def _dribble(self, guest, data, every=0.05):
        stop = threading.Event()

        def run():
            for i in range(len(data)):
                if stop.wait(every):
                    return
                try:
                    guest.sendall(data[i:i + 1])
                except OSError:
                    return

        threading.Thread(target=run, daemon=True).start()
        self.addCleanup(stop.set)

    def test_a_dribbled_hello_is_refused_in_time(self):
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(0.3)
        self._dribble(guest, bytes([0x16, 0x03, 0x01, 0x01, 0x2c])
                     + b"\x01" + b"\x00" * 299)
        started = time.monotonic()
        with self.assertRaises(HelloUnreadable):
            read_client_hello(ours)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_a_dribbled_request_head_times_out_in_time(self):
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(0.3)
        self._dribble(guest, b"GET / HTTP/1.1\r\nHost: " + b"a" * 200)
        started = time.monotonic()
        with self.assertRaises(ReadTimedOut) as caught:
            _Stream(ours).read_head()
        self.assertFalse(caught.exception.idle,
                         "a head that was started is not an idle connection")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_a_head_that_arrives_in_pieces_in_time_is_read(self):
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(2.0)
        self._dribble(guest, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
                      every=0.01)
        head = _Stream(ours).read_head()
        self.assertTrue(head.endswith(b"\r\n\r\n"))


class TestAResetBetweenRequests(unittest.TestCase):
    """A client may reset a kept-alive connection once it has its
    answer; only that wait, and nothing else, tells the reset apart."""

    def _reset(self):
        """A pair whose guest end was closed with our bytes unread in it,
        so our next read is a reset."""
        ours, guest = socket.socketpair()
        self.addCleanup(ours.close)
        ours.settimeout(2.0)
        ours.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        guest.close()
        return ours

    def test_a_reset_while_waiting_for_a_next_request_is_told_apart(self):
        with self.assertRaises(ResetWhileIdle):
            _Stream(self._reset()).read_head(idle_timeout=2.0)

    def test_a_reset_anywhere_else_is_an_unreadable_request(self):
        """A new connection's first wait, and a head begun, are not a
        client done with a connection."""
        with self.assertRaises(RequestUnreadable) as caught:
            _Stream(self._reset()).read_head()
        self.assertNotIsInstance(caught.exception, ResetWhileIdle)
        ours = self._reset()
        stream = _Stream(ours)
        stream._buf = b"GET / HT"
        with self.assertRaises(RequestUnreadable) as caught:
            stream.read_head(idle_timeout=2.0)
        self.assertNotIsInstance(caught.exception, ResetWhileIdle)


class TestWhatCountsAsTheStartOfARequest(unittest.TestCase):
    """The predicate on its own. Three-valued, and each value earns its place.

    True and False are the two verdicts; None is `not enough bytes yet`, which
    is what lets the caller stop waiting the moment the answer is settled
    instead of always waiting for a full method's worth of bytes.
    """

    def check(self, start, expected):
        self.assertIs(is_http_request_start(start), expected,
                      f"for {start!r}")

    def test_a_request_line_is_one(self):
        for start in (b"GET / HTTP/1.1", b"POST /x", b"OPTIONS *",
                      b"BASELINE-CONTROL /a"):
            self.check(start, True)

    def test_a_binary_first_byte_is_not(self):
        for start in (b"\x16\x03\x01\x02\x00",      # TLS inside the session
                      b"\x00\x00\x00\x00",
                      b"\x10\x1a\x00\x04MQTT"):
            self.check(start, False)

    def test_a_text_protocol_that_is_not_http_is_not(self):
        # SSH gets three uppercase letters in before the hyphen-digit that
        # gives it away, which is why the check cannot stop at byte one.
        self.check(b"SSH-2.0-OpenSSH_9.6", False)
        self.check(b"PING\r\n", False)

    def test_a_prefix_too_short_to_judge_is_undecided(self):
        for start in (b"", b"G", b"GE", b"OPTION"):
            self.check(start, None)

    def test_a_run_longer_than_any_method_is_not_a_method(self):
        self.check(b"A" * HTTP_METHOD_MAX, False)

    def test_the_h2_preface_is_left_to_the_parser(self):
        """`PRI * HTTP/2.0` IS a request line; what it is not is one this
        listener speaks. It gets the parser's 400, not a close: a client that
        opens with the preface has ignored the ALPN, and it is answered
        rather than closed."""
        self.check(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", True)

    def test_a_leading_space_is_not_a_method(self):
        self.check(b" GET / HTTP/1.1", False)

    def test_a_lowercase_method_is_refused_in_the_harmless_direction(self):
        """Named, not lamented. The alphabet is the one every registered method
        is spelled with; a lowercase extension method would be closed here
        rather than answered, and widening this is one character."""
        self.check(b"get / HTTP/1.1", False)


@unittest.skipUnless(_have_openssl(), "openssl is not installed")
class TestNonHttpInsideATerminatedSessionIsClosed(TerminationCase):
    """Spliced, these bytes pass and neither end notices; terminated, this
    listener is the one reading them."""

    NOT_HTTP = bytes(range(32)) + b"\x00" * 8

    def test_the_guest_gets_nothing_back_and_the_origin_sees_nothing(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, out = self._listener(mod, origin)
        response, _ = self._exchange(listener, origin, request=self.NOT_HTTP)
        self.assertEqual(response, b"",
                         "a close, not an HTTP response written into a "
                         "protocol that is not HTTP")
        self.assertEqual(origin.requests, [])
        self.assertIn('reason="not HTTP', out.getvalue())

    def test_it_is_counted_as_not_http_and_not_as_an_unreadable_request(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[DROP_NOT_HTTP], 1)
        self.assertEqual(reasons[DROP_UNREADABLE_REQUEST], 0)
        self.assertEqual(reasons[DROP_TIMED_OUT], 0)

    def test_the_remedy_it_names_is_the_PER_HOST_key(self):
        """`"tls": "splice"` gives up inspection for every OTHER name on the
        workload to fix one host. The `splice` list fixes the one, and the
        line has to name it -- an operator does what the log tells them, so a
        line naming the wrong hatch
        is how a workload ends up spliced whole."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, out = self._listener(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        line = out.getvalue()
        self.assertIn("`splice`", line)
        self.assertIn("localhost", line)

    def test_a_malformed_but_recognisable_request_still_gets_its_400(self):
        """The check must not swallow the case it looks most like. A request
        line that begins as one and then fails to parse is an HTTP peer making
        an HTTP mistake, and it gets an answer it can read."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin)
        response, _ = self._exchange(
            listener, origin,
            request=b"GET /\x01\x02 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertTrue(response.startswith(b"HTTP/1.1 400 "), response[:40])
        self.assertEqual(
            listener.status()["drop_reasons"][DROP_NOT_HTTP], 0)

    def test_a_decidable_prefix_does_not_wait_for_a_whole_method(self):
        """A peer that sends four bytes and then waits is answered on those
        four. Without the `until` this costs a decision timeout to decide
        something already decided."""
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(5.0)
        guest.sendall(b"\x00\x01\x02\x03")
        stream = _Stream(ours)
        started = time.monotonic()
        start = stream.peek_start(
            until=lambda buf: is_http_request_start(buf) is not None)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertIs(is_http_request_start(start), False)

    def test_the_peeked_bytes_are_still_there_for_the_parser(self):
        """The peek does not consume: an HTTP connection reaches the request
        loop with its head intact, which is why there is no MSG_PEEK here."""
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(5.0)
        head = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        guest.sendall(head)
        stream = _Stream(ours)
        stream.peek_start()
        self.assertEqual(stream.read_head(), head)


@unittest.skipUnless(_have_openssl(), "openssl is not installed")
class TestTheNonHttpRefusalIsSplitByPolicy(TerminationCase):
    """The same wire failure, two figures, because the two have
    different remedies -- and the second remedy includes a DELETION the first
    does not.

    A host with no policy entry needs one line: put it in the `splice` list.
    A host with a policy entry needs that line AND the entry removed,
    because load_policy refuses a host that is in both. Merged
    into one count an operator can see that something needs splicing but not
    that some of their method and path rules never ran, and nothing at startup
    could have told them -- whether a host speaks HTTP is not knowable from the
    file, which is why this is a runtime report rather than a refusal at
    start.
    """

    NOT_HTTP = bytes(range(32)) + b"\x00" * 8

    def _governed(self, mod, origin):
        return self._listener(
            mod, origin,
            entries=(("localhost", ("GET",), ("/v1/*",)),))

    def test_a_governed_host_lands_in_the_policy_bucket_not_the_plain_one(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._governed(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[DROP_NOT_HTTP_POLICY], 1)
        self.assertEqual(reasons[DROP_NOT_HTTP], 0)

    def test_an_ungoverned_host_stays_in_the_plain_bucket(self):
        """The other half of the same guard. A split that put everything in one
        bucket would pass the test above on its own."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[DROP_NOT_HTTP], 1)
        self.assertEqual(reasons[DROP_NOT_HTTP_POLICY], 0)

    def test_a_WILDCARD_policy_entry_governs_the_name_it_covers(self):
        """The split is asked of the policy's matcher, not of a literal host
        string. An entry written `*.example` governs `api.example`, and a check
        comparing names would put that host in the wrong bucket -- the same
        defect the composition rule's widening trap is about, one plane
        along."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(
            mod, origin, entries=(("*host", ("GET",), ("/",)),))
        self._exchange(listener, origin, request=self.NOT_HTTP)
        self.assertEqual(
            listener.status()["drop_reasons"][DROP_NOT_HTTP_POLICY], 1)

    def test_both_are_per_host_so_the_operator_gets_names_not_totals(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._governed(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        per_host = listener.status()["per_host"]
        self.assertEqual(per_host[DROP_NOT_HTTP_POLICY],
                         {"localhost": 1})
        self.assertEqual(per_host[DROP_NOT_HTTP], {})

    def test_the_governed_line_names_the_deletion_as_well_as_the_key(self):
        """Half the remedy is the trap. An operator told only to splice adds
        the entry, `validate` refuses the file, and the message that sent them
        there said nothing about why."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, out = self._governed(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        line = out.getvalue()
        self.assertIn("`splice`", line)
        self.assertIn("`policy` entry", line)
        self.assertIn("deleted", line)

    def test_the_ungoverned_line_does_NOT_mention_policy(self):
        """A remedy that names a key the operator has not written sends them
        looking for a file they do not have."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, out = self._listener(mod, origin)
        self._exchange(listener, origin, request=self.NOT_HTTP)
        self.assertNotIn("policy", out.getvalue())

    def test_the_guest_still_gets_a_close_and_the_origin_still_gets_nothing(
            self):
        """Tier 6 changed the accounting and the sentence. It must not have
        changed the disposition -- these bytes reach no origin either way."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._governed(mod, origin)
        response, _ = self._exchange(listener, origin, request=self.NOT_HTTP)
        self.assertEqual(response, b"")
        self.assertEqual(origin.requests, [])

    def test_a_governed_host_that_DOES_speak_http_is_not_counted_at_all(self):
        """The bucket is for connections that never became requests. A request
        the policy denies is `not permitted by policy`, which is a different
        reason with a different meaning -- one says the rules did not run, the
        other says they ran and said no."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._governed(mod, origin)
        self._exchange(
            listener, origin,
            request=b"DELETE /v1/x HTTP/1.1\r\nHost: localhost\r\n\r\n")
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[DROP_NOT_HTTP_POLICY], 0)
        self.assertEqual(reasons[DROP_NOT_HTTP], 0)
        self.assertEqual(reasons[DROP_NOT_PERMITTED], 1)


@unittest.skipUnless(_have_openssl(), "openssl is not installed")
class TestBothLegsAreHttp11(TerminationCase):
    """Whatever either end prefers. The requests are read as HTTP/1.1, so a
    leg that settled on h2 would carry frames nothing here can read."""

    def test_a_guest_preferring_h2_is_given_http11(self):
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        ctx = self._guest_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        alpn = []
        response, error = self._exchange(listener, origin, guest_ctx=ctx,
                                         alpn_out=alpn)
        self.assertIsNone(error)
        self.assertEqual(alpn, ["http/1.1"])
        self.assertIn(b"200 OK", response)
        # The offer is reported, and a client that can fall back is not
        # the one the h2-only note is for.
        line, = [line for line in out.getvalue().splitlines()
                 if line.startswith("terminate ")]
        self.assertTrue(line.endswith(' alpn="h2,http/1.1"'), line)
        self.assertNotIn("note ", out.getvalue())

    def test_a_guest_offering_only_h2_is_noted(self):
        """Its handshake selects nothing. This guest sends HTTP/1.1 anyway;
        a gRPC client would not, and the note is where that shows."""
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        ctx = self._guest_context()
        ctx.set_alpn_protocols(["h2"])
        alpn = []
        self._exchange(listener, origin, guest_ctx=ctx, alpn_out=alpn)
        self.assertEqual(alpn, [None])
        note, = [line for line in out.getvalue().splitlines()
                 if line.startswith("note ")]
        self.assertIn("host=localhost", note)
        self.assertIn('reason="h2 only: ', note)
        self.assertIn("splice localhost", note)
        self.assertEqual(listener.status()["notes"]["h2 only"], 1)

    def test_a_guest_opening_with_the_h2_preface_is_noted(self):
        """What a client that ignores the ALPN outcome sends. It is answered
        400, and the note names the host to splice."""
        mod = _mod()
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        listener, out = self._listener(mod, origin)
        ctx = self._guest_context()
        ctx.set_alpn_protocols(["h2"])
        response, _error = self._exchange(
            listener, origin, guest_ctx=ctx,
            request=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        self.assertIn(b"400", response)
        self.assertEqual(origin.requests, [])
        preface, = [line for line in out.getvalue().splitlines()
                    if line.startswith("note ") and "h2 preface" in line]
        self.assertIn("host=localhost", preface)
        self.assertIn("localhost spliced", preface)
        notes = listener.status()["notes"]
        self.assertEqual((notes["h2 only"], notes["h2 preface"]), (1, 1))

    def test_an_origin_preferring_h2_is_asked_for_http11(self):
        mod = _mod()
        origin = _Origin(self.origin_pem, alpn=("h2", "http/1.1"))
        self.addCleanup(origin.close)
        listener, _ = self._listener(mod, origin)
        response, error = self._exchange(listener, origin)
        self.assertIsNone(error)
        self.assertEqual(origin.alpn_seen, ["http/1.1"])
        self.assertIn(b"200 OK", response)


class TestWhatTheStatusFileCarriesFromARealExchange(TerminationCase):
    """Through the seam rather than over the counters. A figure that
    is only ever moved by a test calling record_drop is a figure nothing on the
    live path is known to move."""

    def test_an_unverifiable_upstream_names_the_host_it_could_not_verify(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin, trust=False)
        self._exchange(listener, origin)
        snap = listener.status()
        self.assertEqual(snap["per_host"][DROP_UNVERIFIED],
                         {self.HOST: 1})

    def test_the_ca_an_operator_must_install_is_in_the_status(self):
        """An operator compares this against the anchor in the guest.
        Nothing else produces the value -- this process is what mints with
        it."""
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin)
        self._exchange(listener, origin)
        ca = listener.status()["mint"]["ca"]
        self.assertRegex(ca["sha256"], r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")
        self.assertGreater(ca["not_after"], time.time())

    def test_a_denied_name_moves_the_denial_half_of_the_mint_figures(self):
        origin = _Origin(self.origin_pem)
        self.addCleanup(origin.close)
        mod = _mod()
        listener, _ = self._listener(mod, origin, hosts=("elsewhere.example",))
        self._exchange(listener, origin)
        mint = listener.status()["mint"]
        self.assertEqual((mint["mints"], mint["denied_mints"]), (1, 1))
        self.assertEqual(mint["denials"], 1)
        self.assertEqual(mint["working_set"], 0)


if __name__ == "__main__":
    unittest.main()


class TestACountIsASCIIOrItIsNotACount(unittest.TestCase):
    """`str.isdigit()` is the wrong guard in front of `int()` on this path.

    The RESPONSE head is decoded latin-1 on purpose -- so that a raw byte in a
    filename cannot kill an exchange the policy authorised -- and latin-1 spells
    the superscripts. `"²".isdigit()` is True and `int("²")` raises,
    so a Content-Length or a status code written with one passed the guard and
    then raised ValueError out of a call site that catches RequestUnreadable and
    OSError: the connection thread died with a traceback and no counter moved.

    Refusal is the right answer, not repair -- the same voice as every other
    framing refusal here.
    """

    def test_a_superscript_content_length_is_refused_not_crashed(self):
        with self.assertRaises(RequestUnreadable):
            response_framing(200, "GET", (("content-length", "²"),))

    def test_a_superscript_status_code_is_refused_not_crashed(self):
        self.assertFalse(_is_count("²"))
        self.assertFalse(_is_count("2²"))

    def test_ordinary_counts_still_pass(self):
        self.assertTrue(_is_count("0"))
        self.assertTrue(_is_count("4096"))
        self.assertEqual(
            response_framing(200, "GET", (("content-length", "5"),)),
            Framing("length", 5))

    def test_the_request_side_agrees(self):
        """Safe there already -- that head is ASCII -- and checked anyway.

        The guarantee that makes the request side safe lives two functions away
        in `_split_head`. A guard written to depend on it is one refactor from
        being wrong, so both sides use the same predicate and both are asserted.
        """
        with self.assertRaises(RequestUnreadable):
            request_framing((("content-length", "²"),))


class TestTheCachesCannotEvictALeafInFlight(unittest.TestCase):
    """A cache must hold more entries than there are connection slots.

    Eviction unlinks the victim's PEM, and a leaf is opened by the caller AFTER
    the minter has handed it over. So if the least-recently-used entry can be
    one a live connection still holds, a flood can delete a certificate out from
    under a handshake about to use it -- which fails as a missing file and reads
    as the guest not trusting the CA.

    The two numbers live in different files and nothing else makes them meet.
    """

    def test_every_cache_is_larger_than_the_connection_ceiling(self):
        from moatery.egress_mint import DENIAL_CACHE_MAX, LEAF_CACHE_MAX
        for name, size in (("working set", LEAF_CACHE_MAX),
                           ("denial set", DENIAL_CACHE_MAX)):
            with self.subTest(cache=name):
                self.assertGreater(
                    size, MAX_CONNECTIONS,
                    f"the {name} holds {size} entries against "
                    f"{MAX_CONNECTIONS} connection slots, so its "
                    f"least-recently-used entry can be one in flight")


class TestARedialThatCannotBeVerifiedSaysSo(TerminationCase):
    """`ssl.SSLError` IS an `OSError`, and one generic arm hid the difference.

    The front of a terminated connection has always split the two -- a
    certificate that will not verify gets the sentence naming THIS HOST's trust
    anchors, an unreachable host gets the one naming the host. The REDIAL did
    not: `_upstream_for` is reached again whenever an origin answers
    `Connection: close` or an HTTP/1.0 exchange ends, and its handler caught
    OSError only. So a verification failure on a redial was reported as
    "upstream unreachable", and then paid for a second getaddrinfo to decide
    which flavour of unreachable to call it.
    """

    def _drive(self, mod, exc):
        listener, out = self._listener(mod, _Origin(self.origin_pem))
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(3.0)
        guest.settimeout(3.0)
        guest.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        with unittest.mock.patch.object(
                listener.inspection.upstream, "connection_for", side_effect=exc):
            serve_one_request(
                listener.inspection,
                _Stream(ours), ours, _where("tls").request(1),
                {}, True)
        return listener, guest.recv(65536), out.getvalue()

    def test_a_verification_failure_is_not_called_unreachable(self):
        mod = _mod()
        listener, response, log = self._drive(
            mod, ssl.SSLCertVerificationError("self-signed certificate"))
        self.assertTrue(response.endswith(b"\r\n\r\nBad Gateway\n"),
                        response)
        self.assertIn("could not be verified", log)
        self.assertIn("THIS HOST", log,
                      "an operator has to be told whose trust store to fix")
        self.assertIn(DROP_UNVERIFIED, log)
        self.assertNotIn(DROP_UNREACHABLE, log)

    def test_an_ordinary_dial_failure_still_goes_the_other_way(self):
        """The other arm still works -- this is a split, not a replacement.

        The reason is `internal destination` rather than `upstream
        unreachable`, and that is _dial_failure_reason being right: the host
        here is `localhost`, which resolves into loopback, and a name resolving
        into private space with no `internal` entry is a config an
        operator is one line from fixing. Asserted as the specific string rather
        than "not the TLS one", or the test would still pass if the split
        collapsed back into a single arm.
        """
        mod = _mod()
        listener, response, log = self._drive(
            mod, ConnectionRefusedError("connection refused"))
        self.assertTrue(response.endswith(b"\r\n\r\nBad Gateway\n"),
                        response)
        self.assertIn("could not be reached", log)
        self.assertIn(DROP_INTERNAL, log)
        self.assertNotIn(DROP_UNVERIFIED, log)

    def test_a_dead_broker_is_named_in_the_journal_not_to_the_guest(self):
        """The broker sentence names the broker and its --listen -- facts
        about the sandbox. It reached the guest's body once."""
        mod = _mod()
        with unittest.mock.patch.object(
                Policy, "credential_for", return_value="api-key"):
            _, response, log = self._drive(
                mod, ConnectionRefusedError("connection refused"))
        self.assertTrue(response.endswith(b"\r\n\r\nBad Gateway\n"),
                        response)
        self.assertIn(DROP_BROKER_UNREACHABLE, log)
        self.assertIn("credential broker did not answer", log)
        self.assertIn("--listen", log)

    def test_a_head_that_never_left_is_named_in_the_journal(self):
        """The client-certificate sentence names the `splice` list."""
        mod = _mod()
        up = unittest.mock.Mock()
        up.sock.sendall.side_effect = ConnectionResetError("reset")
        listener, out = self._listener(mod, _Origin(self.origin_pem))
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(3.0)
        guest.settimeout(3.0)
        guest.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        with unittest.mock.patch.object(
                listener.inspection.upstream, "connection_for",
                return_value=up):
            serve_one_request(
                listener.inspection,
                _Stream(ours), ours, _where("tls").request(1),
                {}, True)
        response = guest.recv(65536)
        self.assertTrue(response.endswith(b"\r\n\r\nBad Gateway\n"),
                        response)
        self.assertIn("was not delivered", out.getvalue())
        self.assertIn("`splice` list", out.getvalue())

    def test_an_alert_on_the_first_read_is_answered_and_named(self):
        """The head went up and the alert is what the first read finds.

        This arm closed the guest's connection with nothing on it and filed
        the demand, named exactly, as `relay failed`: the empty response
        the client-certificate test reported once in ten to thirty runs,
        whenever the origin's alert was slower than the dial's early read.
        The alert reaches the handler only as the read failure's cause.
        """
        mod = _mod()
        sock = unittest.mock.Mock()
        sock.recv.side_effect = _certificate_required()
        listener, out = self._listener(mod, unittest.mock.Mock())
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(3.0)
        guest.settimeout(3.0)
        guest.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        with unittest.mock.patch.object(
                listener.inspection.upstream, "connection_for",
                return_value=_Stream(sock)):
            keep = serve_one_request(
                listener.inspection,
                _Stream(ours), ours, _where("tls").request(1),
                {}, True)
        # As its caller would, so a missing answer reads as b"".
        ours.close()
        response = guest.recv(65536)
        sock.sendall.assert_called_once()
        self.assertFalse(keep)
        self.assertTrue(response.endswith(b"\r\n\r\nBad Gateway\n"),
                        response)
        self.assertIn(b"Connection: close", response)
        self.assertIn("requires a client certificate", out.getvalue())
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[DROP_CLIENT_CERT], 1)
        self.assertEqual(reasons[DROP_RELAY_FAILED], 0)

    def test_the_same_alert_on_the_guests_leg_is_a_relay_failure(self):
        """The client-certificate sentence tells the operator to splice the
        host, which ends inspection of it, and a guest can send any alert
        it likes on its own leg. One read while its body is copied up is
        the guest's, and never files the origin's demand."""
        mod = _mod()
        guest = unittest.mock.Mock()
        guest.recv.side_effect = [
            (b"POST / HTTP/1.1\r\nHost: localhost\r\n"
             b"Content-Length: 10\r\n\r\n"),
            _certificate_required()]
        listener, out = self._listener(mod, unittest.mock.Mock())
        with unittest.mock.patch.object(
                listener.inspection.upstream, "connection_for",
                return_value=unittest.mock.Mock()):
            serve_one_request(
                listener.inspection, _Stream(guest), guest,
                _where("tls").request(1), {}, True)
        reasons = listener.status()["drop_reasons"]
        self.assertEqual(reasons[DROP_CLIENT_CERT], 0)
        self.assertEqual(reasons[DROP_RELAY_FAILED], 1)
        self.assertNotIn("`splice` list", out.getvalue())


class TestTheTlsContexts(TerminationCase):
    """What the two legs' contexts hold, asserted rather than left to
    Python's and OpenSSL's defaults."""

    def _handshake(self, leaf, guest_ctx, session=None):
        """One guest connection through wrap_guest: (the guest's session,
        whether it resumed)."""
        ours, guest = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        ours.settimeout(5.0)
        guest.settimeout(5.0)

        def serve():
            with inspect_tls.wrap_guest(ours, leaf) as tls:
                tls.sendall(b"x")
                tls.recv(1)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        with guest_ctx.wrap_socket(
                guest, server_hostname="localhost", session=session) as tls:
            # The ticket comes after the handshake; reading takes it in.
            self.assertEqual(tls.recv(1), b"x")
            tls.sendall(b"y")
            got = tls.session, tls.session_reused
        thread.join(5.0)
        return got

    def test_the_guest_leg_refuses_anything_below_tls_1_2(self):
        leaf = self._minter(None).leaf("localhost", denied=False)
        # The context, not a socket: wrapping would wait for a handshake.
        with unittest.mock.patch.object(
                ssl.SSLContext, "wrap_socket", autospec=True,
                side_effect=lambda ctx, *args, **kwargs: ctx):
            ctx = inspect_tls.wrap_guest(None, leaf)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_a_guest_cannot_resume_another_connections_session(self):
        """Each connection has a context, and so a ticket key, of its own,
        which nothing else states."""
        leaf = self._minter(None).leaf("localhost", denied=False)
        guest_ctx = self._guest_context()
        session, _ = self._handshake(leaf, guest_ctx)
        self.assertTrue(session.has_ticket,
                        "no ticket was issued, so nothing was tried")
        _, reused = self._handshake(leaf, guest_ctx, session)
        self.assertFalse(reused)

    def test_the_upstream_leg_verifies_name_and_chain_at_tls_1_2_or_above(self):
        ctx = egress_upstream.Upstream()._ctx
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)


class TestALeafNamesTheHostNotThePattern(TerminationCase):

    def test_a_wildcard_match_mints_the_one_name_the_guest_asked_for(self):
        minter = unittest.mock.Mock()
        minter.leaf.side_effect = egress_mint.MintFailed("stop here")
        listener = Listener([unittest.mock.Mock()], io.StringIO(),
                            policy=Policy(tls="inspect",
                                          hosts=("*.example.com",)),
                            minter=minter)
        ours, guest = _tcp_pair()
        self.addCleanup(ours.close)
        self.addCleanup(guest.close)
        guest.sendall(_hello_bytes(server_name="A.Example.com."))
        ours.settimeout(2.0)
        with unittest.mock.patch.object(
                listener.inspection.upstream, "dial_tls") as dial:
            serve_tls(listener.inspection, ours, _where("tls"))
        dial.assert_called_once_with("a.example.com")
        minter.leaf.assert_called_once_with("a.example.com", denied=False)

    def test_the_minted_san_is_that_name_alone(self):
        leaf = self._minter(None).leaf("a.example.com", denied=False)
        cert = ssl._ssl._test_decode_cert(str(leaf.path))
        self.assertEqual(cert["subjectAltName"], (("DNS", "a.example.com"),))


class TestTheResponseHeadHasOneFraming(unittest.TestCase):
    """The response head is relayed as it came and read leniently, so a
    line this reading drops or folds must not be a framing header to a
    guest that trims: the two would end the body in different places."""

    CORPUS = (
        b"Content-Length: 5",
        b"Transfer-Encoding: chunked",
        b"content-length:5",
        b"Content-Length : 5",
        b"Content-Length\t: 5",
        b"Transfer-Encoding : chunked",
        b"X-A: b\r\n Content-Length: 5",
        b"X-A: b\r\n\tTransfer-Encoding: chunked",
        b"X A: b",
        b"X-A: b\r\n folded value",
        b"Content Length: 5",
        b"Content-Length\xb2: 5",
    )

    @staticmethod
    def _trimmed(lines):
        """The framing names a parser that trims every line sees."""
        names = set()
        for line in lines:
            name, sep, _ = line.partition(b":")
            name = name.strip(b" \t").lower()
            if sep and name in (b"content-length", b"transfer-encoding"):
                names.add(name.decode())
        return names

    def test_both_readings_agree_or_the_head_is_refused(self):
        for fields in self.CORPUS:
            head = b"HTTP/1.1 200 OK\r\n" + fields + b"\r\n\r\n"
            with self.subTest(head=head):
                try:
                    _, headers = _split_response_head(head)
                except RequestUnreadable:
                    continue
                ours = {n for n, _ in headers
                        if n in ("content-length", "transfer-encoding")}
                self.assertEqual(
                    ours, self._trimmed(head[:-4].split(b"\r\n")[1:]))

    def test_the_ordinary_and_the_harmless_are_still_read(self):
        for fields in (b"Content-Length: 5", b"X A: b",
                       b"X-A: b\r\n folded value"):
            head = b"HTTP/1.1 200 OK\r\n" + fields + b"\r\n\r\n"
            with self.subTest(head=head):
                _split_response_head(head)
