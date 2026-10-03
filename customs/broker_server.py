"""The broker's server: one handler thread per admitted connection.

Handler identifies the caller once per connection, looks each request's
Host up in the profile table, and forwards it, buffered, to that profile's
fixed upstream with the credential attached; the decisions are
broker_request's. The pool refuses rather than queues past a global
ceiling, a small shared ceiling for every caller but the served one, and an
in-flight body budget. Server is bound to an address and reads the caller
from the socket table; UnixServer is bound to a path and asks the socket.

Used by `libexec/customs-broker`.
"""

import contextlib
import email.utils
import http.client
import http.server
import os
import socketserver
import ssl
import stat
import sys
import threading
import time

from .broker_profiles import normalize_host
from .broker_request import (
    forwarded_headers, request_framing, response_framing,
)
from .peer_identity import local_endpoints, peer_uid, peer_uid_unix

# At most this much request body buffered over every connection at once.
# MAX_REQUEST_BYTES bounds one request; without this, MAX_CONCURRENT legal
# bodies would reserve 8 GiB of the host's memory. Past it, a 503.
MAX_INFLIGHT_BYTES = 256 * 1024 * 1024

# The upstream leg's timeouts, which the flags override. Streamed
# completions idle between tokens far longer than a connect may take.
CONNECT_TIMEOUT = 15.0
READ_TIMEOUT = 900.0

CHUNK = 64 * 1024

# How long a caller's connection may make no progress. It bounds each
# blocking operation, not the request: a caller trickling bytes is held off
# by MAX_FOREIGN instead, unless it is the served one.
CONNECTION_TIMEOUT = 60.0


def log(event, **fields):
    """One structured line per event, to stderr -> journal. Never logs bodies,
    headers, or anything derived from the credential."""
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    # One write, newline included, so two threads cannot join their lines.
    sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {event} {parts}\n")
    sys.stderr.flush()


class Handler(http.server.BaseHTTPRequestHandler):
    # Set by main(). `workload_uid` is the one caller served, told and never
    # looked up; `profiles` is keyed by normalised Host.
    name = None
    workload_uid = None
    profiles = {}
    overflow = 65534
    upstream_context = None
    connect_timeout = CONNECT_TIMEOUT
    read_timeout = READ_TIMEOUT

    protocol_version = "HTTP/1.1"

    timeout = CONNECTION_TIMEOUT

    def setup(self):
        """Resolve the caller once per connection and take a slot against
        its ceiling, or refuse."""
        try:
            self.caller_uid = self.server.caller_uid(self.request,
                                                     self.client_address)
        except OSError:
            self.caller_uid = None  # peer vanished between accept and lookup
        served = (self.caller_uid is not None
                  and self.caller_uid != self.overflow
                  and self.caller_uid == self.workload_uid)
        if not self.server.admit_caller(self.request, served=served):
            raise CallerCeilingExceeded(
                self.caller_uid if served else FOREIGN)
        super().setup()

    def log_message(self, fmt, *args):
        pass  # replaced by explicit structured logging in _forward

    # Which methods a request may use is the inspector's policy. CONNECT and
    # TRACE are absent: one opens a tunnel, the other echoes the request
    # back, credential and all.
    def do_GET(self):
        self._forward("GET")

    def do_HEAD(self):
        self._forward("HEAD")

    def do_POST(self):
        self._forward("POST")

    def do_PUT(self):
        self._forward("PUT")

    def do_PATCH(self):
        self._forward("PATCH")

    def do_DELETE(self):
        self._forward("DELETE")

    def do_OPTIONS(self):
        self._forward("OPTIONS")

    def _identify(self):
        """(sandbox, label) for this caller; None if it gets nothing.

        No peer socket and an unmapped uid are refusals: both make every
        caller look alike. The Host is looked up per request, not here, since
        one connection may carry requests for two brokered hosts.
        """
        uid = self.caller_uid
        if uid is None:
            return None, "no-peer-socket"
        if uid == self.overflow:
            return None, "uid-unmapped"
        if uid == self.workload_uid:
            return self.name, self.name
        return None, f"uid:{uid}"

    def send_error(self, code, message=None, explain=None):
        """The base class's refusals, answered like ours: its HTML page
        would reach the guest as the provider's answer."""
        log("deny", reason=f"http-{code}", detail=message or "")
        self._fail(code)

    def _fail(self, status):
        """Answer without forwarding, and end the connection.

        The body is the status phrase and there is no Server header: the
        guest sees this as the provider's answer, and a sentence of ours
        would say a broker is there. The connection ends because the
        request's body may be unread, and reading on would take it for the
        next request.
        """
        body = f"{http.HTTPStatus(status).phrase}\n".encode()
        self.close_connection = True
        self.send_response_only(status)
        self.send_header("Date", email.utils.formatdate(usegmt=True))
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _forward(self, method):
        started = time.monotonic()
        self.response_started = False
        sandbox, label = self._identify()
        if sandbox is None:
            log("deny", reason="unidentified", caller=label)
            self._fail(403)
            return

        # The Host selects a row of this broker's own table and supplies
        # nothing; with no row, no credential is sent.
        host = normalize_host(self.headers.get("Host"))
        profile = self.profiles.get(host) if host else None
        if profile is None:
            log("deny", reason="host-not-configured", sandbox=label,
                host=host or "")
            self._fail(403)
            return
        sandbox = profile.name

        length, rejection = request_framing(self.path, self.headers)
        if rejection is not None:
            status, reason, message = rejection
            log("deny", reason=reason, sandbox=sandbox, bytes=length,
                detail=message.strip())
            self._fail(status)
            return
        if not self.server.reserve_body(length):
            log("deny", reason="inflight-body-limit", sandbox=sandbox,
                bytes=length)
            self._fail(503)
            return

        try:
            self._forward_body(method, length, profile, sandbox, started)
        finally:
            self.server.release_body(length)

    def _forward_body(self, method, length, profile, sandbox, started):
        """Read the body and relay one request, apart from _forward so the
        body budget is released on every path out."""
        body = self.rfile.read(length) if length else None

        # A denylist of the caller's headers, not an allowlist: provider SDKs
        # add version and beta headers faster than a list would keep up.
        headers = forwarded_headers(self.headers, profile)
        if body is not None:
            headers["Content-Length"] = str(len(body))

        path = self.path
        # The query stays out of the journal, which is not private: the
        # guest writes it, and it can carry what the guest was given.
        logged_path = path.partition("?")[0]
        conn = None
        try:
            conn = http.client.HTTPSConnection(
                profile.host,
                profile.port,
                context=self.upstream_context,
                timeout=self.connect_timeout,
            )
            conn.request(method, path, body=body, headers=headers)
            conn.sock.settimeout(self.read_timeout)
            resp = conn.getresponse()
            sent = self._relay(resp)
            log("ok", sandbox=sandbox, method=method, path=logged_path,
                status=resp.status, bytes=sent,
                ms=int((time.monotonic() - started) * 1000))
        # ValueError is http.client refusing a header before sending it, with
        # the value in its message, and one of the values is the credential:
        # logged by type, never as a traceback.
        except (OSError, http.client.HTTPException, ValueError) as exc:
            log("upstream-error", sandbox=sandbox, path=logged_path,
                error=type(exc).__name__, streamed=self.response_started)
            if self.response_started:
                # A response is already on the wire, and a second one would
                # read as its body. A dropped connection is a truncated
                # message, which every client reads as an error.
                self.close_connection = True
            else:
                try:
                    self._fail(502)
                except OSError:
                    pass  # client already gone
        finally:
            if conn is not None:
                conn.close()

    def _relay(self, resp):
        """Stream the upstream response back without buffering it.

        read1(), not read(n): read(n) waits for n bytes, which holds a
        token-by-token stream back until the end.
        """
        passthrough, declared, bodiless = response_framing(
            resp.status, resp.getheaders(), self.command)

        # The provider's Server and Date pass through; we add neither.
        self.send_response_only(resp.status)
        for k, v in passthrough:
            self.send_header(k, v)
        if bodiless:
            # A HEAD answer keeps the length a GET would have had.
            if self.command == "HEAD" and declared is not None:
                self.send_header("Content-Length", declared)
        elif declared is not None:
            self.send_header("Content-Length", declared)
        else:
            # No length up front: re-framed as chunked, so the stream can be
            # consumed as it comes and still end cleanly.
            self.send_header("Transfer-Encoding", "chunked")
        # Set before end_headers begins writing: from then on no other
        # response may follow. See _forward_body.
        self.response_started = True
        self.end_headers()

        sent = 0
        if bodiless:
            return sent
        while True:
            buf = resp.read1(CHUNK)
            if not buf:
                break
            if declared is None:
                self.wfile.write(f"{len(buf):X}\r\n".encode())
                self.wfile.write(buf)
                self.wfile.write(b"\r\n")
            else:
                self.wfile.write(buf)
            self.wfile.flush()
            sent += len(buf)
        if declared is None:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        return sent


# How many connections the broker holds at once. Its one served caller is
# the inspector, whose every brokered guest connection holds one of these,
# so this is sized against the inspector's MAX_CONNECTIONS.
MAX_CONCURRENT = 128

# How many of those every other caller may hold, together. A refusal still
# costs a thread until it is answered, and on an address other uids can
# dial they must not be able to take the pool. One bucket, not one per uid,
# so many users cannot sum past it.
MAX_FOREIGN = 8

# The bucket every caller that is not the served one shares.
FOREIGN = "foreign"


class CallerCeilingExceeded(Exception):
    """Raised out of Handler.setup() by a caller already at its ceiling.

    setup() cannot decline, so it raises: handle_error reports it and the
    connection is closed, freeing the thread at once.
    """

    def __init__(self, bucket):
        super().__init__(f"caller {bucket} is at its connection ceiling")
        self.bucket = bucket


class Pool(socketserver.ThreadingMixIn):
    """The pool, shared by the two servers below, which differ in how they
    bind and how they identify a caller."""

    daemon_threads = True
    allow_reuse_address = True
    block_on_close = False

    _slots = None  # set in __init__; a semaphore, not a count

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ThreadingMixIn has no ceiling of its own.
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT)
        self._lock = threading.Lock()
        self._held = {True: 0, False: 0}  # served, foreign: live connections
        self._served = {}     # accepted socket -> whether its caller is served
        self._inflight = 0    # request-body bytes reserved across all handlers

    def reserve_body(self, length):
        """Claim `length` bytes of the shared body budget, or refuse.

        On the declared length, before the body is read. request_framing has
        already held it to MAX_REQUEST_BYTES.
        """
        if length <= 0:
            return True
        with self._lock:
            if self._inflight + length > MAX_INFLIGHT_BYTES:
                return False
            self._inflight += length
        return True

    def release_body(self, length):
        if length <= 0:
            return
        with self._lock:
            self._inflight -= length

    def admit_caller(self, request, *, served=False):
        """Count this connection against its caller's ceiling, or refuse it.

        Called from the handler thread, not the accept loop: identifying a
        caller reads /proc/net/tcp, milliseconds on a busy host, and on the
        accept loop that is time no one else is accepted.
        """
        limit = MAX_CONCURRENT if served else MAX_FOREIGN
        with self._lock:
            if self._held[served] >= limit:
                return False
            self._held[served] += 1
            self._served[request] = served
        return True

    def process_request(self, request, client_address):
        """Take a global slot, or refuse before there is a thread to starve."""
        if not self._slots.acquire(blocking=False):
            log("deny", reason="too-many-connections",
                src=self.peer_label(client_address))
            # Our own shutdown_request would release a slot never taken.
            super().shutdown_request(request)
            return

        # No try around this: when start() raises, the base class already
        # calls shutdown_request, and a second release would overflow the
        # BoundedSemaphore.
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        """Called by ThreadingMixIn once the handler thread is done."""
        try:
            with self._lock:
                served = self._served.pop(request, None)
                if served is not None:
                    self._held[served] -= 1
            super().shutdown_request(request)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        """One line for the expected, a traceback for the rest.

        A stalled read, a vanished caller and a caller over its ceiling are
        routine, and a traceback each would let a caller flood the journal.
        Anything else is a bug and keeps its traceback.
        """
        exc = sys.exception()
        if isinstance(exc, CallerCeilingExceeded):
            log("deny", reason="too-many-connections-for-caller",
                caller=exc.bucket)
        elif isinstance(exc, (OSError, EOFError)):
            log("connection-error", error=type(exc).__name__)
        else:
            super().handle_error(request, client_address)


class Server(Pool, http.server.HTTPServer):
    """Bound to an address. The caller is the owner of the peer's row in
    the kernel's socket table; see peer_identity for why that and not the
    source address."""

    @staticmethod
    def caller_uid(request, client_address):
        return peer_uid(local_endpoints(request), client_address)

    @staticmethod
    def peer_label(client_address):
        return client_address[0]


# The socket file's mode: its owner and one group, whose other member is
# the inspector. The workload is kept off it by having no path to it.
SOCKET_MODE = 0o660


class UnixServer(Pool, socketserver.UnixStreamServer):
    """Bound to a path. The caller is whatever SO_PEERCRED says.

    A stale socket at the path is replaced at bind and the path unlinked on
    close; anything there that is not a socket fails the bind.
    """

    @staticmethod
    def caller_uid(request, client_address):
        return peer_uid_unix(request)

    @staticmethod
    def peer_label(client_address):
        return "unix"

    _bound = False

    def server_bind(self):
        path = self.server_address
        try:
            if stat.S_ISSOCK(os.stat(path).st_mode):
                os.unlink(path)
        except FileNotFoundError:
            pass
        super().server_bind()
        self._bound = True
        # Before listen(), so no connection is admitted under the umask's
        # mode.
        os.chmod(path, SOCKET_MODE)

    def server_close(self):
        super().server_close()
        # Only a file this instance bound: a failed bind closes too.
        if self._bound:
            with contextlib.suppress(OSError):
                os.unlink(self.server_address)


def make_server(endpoint, handler):
    """The server for a listen_endpoint value: a path is a UnixServer, an
    (address, port) pair a Server."""
    if isinstance(endpoint, str):
        return UnixServer(endpoint, handler)
    return Server(endpoint, handler)


def listening_url(endpoint):
    """What the `listening` log line names."""
    if isinstance(endpoint, str):
        return f"http+unix:{endpoint}"
    return f"http://{endpoint[0]}:{endpoint[1]}"


def upstream_tls_context(relax_x509_strict=False):
    """Verified TLS to the provider, using the host's trust store. There is
    no option to disable verification."""
    ctx = ssl.create_default_context()
    if relax_x509_strict:
        # Clears only VERIFY_X509_STRICT, which Python 3.13 turned on and
        # which refuses some private roots (one without keyUsage) that curl
        # accepts. Chain, signature, expiry and hostname are still checked.
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx
