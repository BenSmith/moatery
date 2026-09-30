#!/usr/bin/env python3
"""The egress inspector's record: what it refuses, what it writes, and the
file it writes to.

The drop reasons, the fields of one record line and the closed sets three of
them draw from, and the writer. Defined once for the listener that writes
them and whatever reads them back, because a reader spelling a reason
differently sees a refusal as one that never fired.
"""

import datetime
import json
import os
import threading
import time


# The fields that join a journal line to its record line: `id` per
# connection and `req` its request ordinal. `peer=` cannot do it, since a
# port repeats across a keep-alive connection and is reused after close.
LOG_ID_FIELD = "id"
LOG_REQ_FIELD = "req"


def format_endpoint(addr):
    """host:port, bracketing the host for the IPv6 listeners."""
    host, port = addr[0], addr[1]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


# Every reason a connection or a request is refused. Call sites name these
# constants, never literals, and a reason added here is one the counters
# pre-seed. DROP_REASONS is the whole set, for anything filtering the record
# to validate against: the guest is told only the status, so `reason` is the
# only place one refusal is told from another.
DROP_NOT_ALLOWLISTED = "not allowlisted"
DROP_NO_NAME = "no readable name"
DROP_UNREADABLE_REQUEST = "unreadable request"
DROP_UNREACHABLE = "upstream unreachable"
DROP_INTERNAL = "internal destination"
DROP_CEILING = "connection ceiling reached"
# The caller's uid is not this workload's.
DROP_FOREIGN_CALLER = "caller is not this workload"
# The caller wrote and closed before it could be identified, which any local
# uid can choose to do.
DROP_CALLER_CLOSED = "caller closed before it was identified"
DROP_RELAY_FAILED = "relay failed"
DROP_TIMED_OUT = "timed out"
DROP_UNVERIFIED = "upstream certificate unverified"
DROP_CLIENT_CERT = "upstream wants a client certificate"
DROP_MISDIRECTED = "host does not match the server name"
# The same, for a name that is allowlisted: usually a client coalescing two
# names it was given, where the unlisted one is a guest reaching for a name
# it was not. Both begin with the same words, so one grep finds both.
DROP_MISDIRECTED_LISTED = "host does not match the server name (allowlisted)"
DROP_THROTTLED = "mint rationed"
DROP_MINT_FAILED = "could not mint a leaf"
DROP_NOT_HTTP = "not HTTP"
# The same, on a host a `policy` entry names: its remedy also deletes the
# entry, since a host cannot be in both `splice` and `policy`.
DROP_NOT_HTTP_POLICY = "not HTTP (policy entry)"
DROP_NOT_PERMITTED = "not permitted by policy"
# The dial to this workload's broker failed: a unit on this host, not the
# provider, and so not DROP_UNREACHABLE.
DROP_BROKER_UNREACHABLE = "credential broker unreachable"
# A hello that would be spliced carries encrypted_client_hello, which can
# name a host other than the one the splice was decided on.
DROP_ECH_SPLICED = "ECH on a spliced connection"

DROP_REASONS = (
    DROP_NOT_ALLOWLISTED,
    DROP_NO_NAME,
    DROP_UNREADABLE_REQUEST,
    DROP_UNREACHABLE,
    DROP_INTERNAL,
    DROP_CEILING,
    DROP_FOREIGN_CALLER,
    DROP_CALLER_CLOSED,
    DROP_RELAY_FAILED,
    DROP_TIMED_OUT,
    DROP_UNVERIFIED,
    DROP_CLIENT_CERT,
    DROP_MISDIRECTED,
    DROP_MISDIRECTED_LISTED,
    DROP_THROTTLED,
    DROP_MINT_FAILED,
    DROP_NOT_HTTP,
    DROP_NOT_HTTP_POLICY,
    DROP_NOT_PERMITTED,
    DROP_BROKER_UNREACHABLE,
    DROP_ECH_SPLICED,
)

# The reasons that also get a per-host figure: those an operator fixes by
# naming a host, where the names come off the workload's own lists. The
# rest are keyed by names the guest invents (a wildcard entry bounds
# nothing), or, for `not permitted`, need the method and path that only the
# record has. Every per-host map is bounded, since its keys can be guest
# input.
PER_HOST_REASONS = (
    DROP_INTERNAL,
    DROP_MISDIRECTED_LISTED,
    DROP_UNVERIFIED,
    DROP_CLIENT_CERT,
    DROP_NOT_HTTP,
    DROP_NOT_HTTP_POLICY,
    DROP_ECH_SPLICED,
)

# Where a drop whose reason is not in DROP_REASONS is counted, and shown
# only when non-zero. Its presence is a bug in the listener.
DROP_UNCLASSIFIED = "(unclassified)"

# What a `note` line reports: something the operator asked to hear about,
# which refuses nothing by itself. The line's reason begins with the kind,
# and the status file counts each.
#
# A hello carrying encrypted_client_hello. GREASE dominates it, and a
# terminated connection takes it; a spliced one is refused
# (DROP_ECH_SPLICED).
NOTE_ECH = "ECH"
# A terminated connection whose client offered h2 and not http/1.1, so its
# handshake selects no protocol: a gRPC client, most likely, that fails.
NOTE_H2_ONLY = "h2 only"
# A connection opening with HTTP/2's preface, which is answered 400.
NOTE_H2_PREFACE = "h2 preface"
# A request offering `Upgrade: h2c`, which goes up without the offer.
NOTE_H2C = "h2c withheld"

NOTE_KINDS = (
    NOTE_ECH,
    NOTE_H2_ONLY,
    NOTE_H2_PREFACE,
    NOTE_H2C,
)


# The record's field names. `credential` is the name of the credential a
# request was brokered with, never the material; it is what explains why
# `upstream`, the address actually dialled, is the broker's.
RECORD_FIELDS = (
    LOG_ID_FIELD, LOG_REQ_FIELD, "ts", "plane", "mode", "host", "method",
    "path", "query", "http", "decision", "reason", "status", "upstream",
    "credential", "duration_ms",
)

# The journal's own verbs. Whether the guest was told is `status` being
# non-null, so there is no third value for it.
RECORD_DECISIONS = ("forward", "drop")

# What the listener did with the connection: `forward` a cleartext request,
# `terminate` a request inside a session this process completed, and
# `splice` the connection-level record of bytes never decrypted.
RECORD_MODES = ("forward", "terminate", "splice")


def record_timestamp():
    """Wall clock, ISO-8601 UTC to milliseconds: the record is joined
    against journals and people's memories, which monotonic joins to
    none of."""
    return (datetime.datetime.now(datetime.UTC)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


class Where(str):
    """The journal's connection key, carrying the record's fields as data.

    A str, so `f"drop {where} ..."` works unchanged while a Record reads
    the id, the plane and the request ordinal from it. `t0` is when the
    connection, or the request, began.
    """

    __slots__ = ("cid", "plane", "seq", "t0")

    def __new__(cls, text, *, cid, plane, seq=None):
        where = super().__new__(cls, text)
        where.cid = cid
        where.plane = plane
        where.seq = seq
        where.t0 = time.monotonic()
        return where

    def request(self, seq):
        """This connection's key with one request's ordinal appended."""
        return Where(f"{self} {LOG_REQ_FIELD}={seq}",
                      cid=self.cid, plane=self.plane, seq=seq)


class Record:
    """One line of the private record, filled in as the exchange runs.

    Written once at the end, and only if a decision was set: an idle
    keep-alive reaching its bound is not a request. No headers and no
    bodies, ever.
    """

    def __init__(self, log, where, mode, *, host=None):
        self._log = log
        self._t0 = where.t0
        # Every field on every line, null where not measured: a missing key
        # and a null one are different facts.
        self.fields = dict.fromkeys(RECORD_FIELDS)
        self.fields.update({
            LOG_ID_FIELD: where.cid,
            LOG_REQ_FIELD: where.seq,
            "ts": record_timestamp(),
            "plane": where.plane,
            "mode": mode,
            "host": host,
        })

    def set(self, **fields):
        self.fields.update(fields)

    def started(self):
        """Re-stamp now that a head has arrived: on a kept-alive connection
        the pass began when the previous response ended."""
        self.fields["ts"] = record_timestamp()
        self._t0 = time.monotonic()

    def request(self, req):
        """The fields a parsed head supplies. The query is recorded apart
        from the path: the sink is private, and a query can carry a
        credential the guest leaked."""
        path, _, query = req.target.partition("?")
        self.set(host=req.host, method=req.method, path=path,
                 query=query or None, http=req.version)

    def dialled(self, sock):
        """The address actually reached. Best effort: a diagnostic may not
        fail the request."""
        try:
            peer = sock.getpeername()
            if isinstance(peer, str) and peer:
                # The broker's socket path, spelled as the flag spells it.
                self.set(upstream=f"unix:{peer}")
                return
            if not isinstance(peer, (tuple, list)) or len(peer) < 2:
                return
            self.set(upstream=format_endpoint(peer))
        except Exception:
            return

    def emit(self):
        if self.fields["decision"] is None:
            return
        self.fields["duration_ms"] = round(
            (time.monotonic() - self._t0) * 1000, 3)
        self._log.write(self.fields)


# The most one record file holds before its lines are dropped, in bytes,
# until a rotation reopens it. Refusals cost a guest almost nothing, so
# without a cap it could fill the host's disk; past it the dropped lines
# are counted as write failures. Refusal lines stop at three quarters of
# it: a guest that floods refusals must not leave no room to record the
# requests that were let through.
RECORD_MAX_BYTES = 512 * 1024 * 1024


class RequestLog:
    """The per-request record's file: append, reopen on SIGHUP, never raise.

    Separate from the journal, readable by its owner only. It never raises,
    since it runs on connection threads. The first failure is logged and the
    rest only counted.
    """

    def __init__(self, path, out=None, on_failure=None,
                 max_bytes=RECORD_MAX_BYTES):
        self._path = None if path is None else str(path)
        self._max_bytes = max_bytes
        self._drop_max_bytes = max_bytes * 3 // 4
        self._size = 0
        self._out = out
        self._on_failure = on_failure
        self._fd = None
        self._lock = threading.Lock()
        # Set by the signal handler and acted on by the next write: the
        # handler runs on the main thread and may interrupt a write that
        # holds the lock.
        self._reopen = False
        # Which kinds of failure have warned: each once per file.
        self._warned = set()

    def reopen(self):
        """Ask for a reopen. Async-signal-safe: one assignment, no I/O."""
        self._reopen = True

    def write(self, record: dict) -> None:
        if self._path is None:
            return
        try:
            line = json.dumps(record, sort_keys=True) + "\n"
        except (TypeError, ValueError) as exc:
            self._fail(f"could not serialise a record: {exc}")
            return
        try:
            with self._lock:
                if self._reopen or self._fd is None:
                    self._open_locked()
                # One write of the whole line, under the lock: O_APPEND
                # alone does not make a partial write atomic.
                data = line.encode()
                refusal = record.get("decision") == "drop"
                cap = self._drop_max_bytes if refusal else self._max_bytes
                over = self._size + len(data) > cap
                if not over:
                    os.write(self._fd, data)
                    self._size += len(data)
            if over and refusal:
                self._fail(f"{self._path} reached its cap of {cap} bytes "
                           "for refusals; they are dropped until it is "
                           "rotated", kind="drop-cap")
            elif over:
                self._fail(f"{self._path} reached its cap of {cap} bytes; "
                           "lines are dropped until it is rotated",
                           kind="cap")
            return
        except OSError as exc:
            self._fail(f"could not write {self._path}: {exc}")

    def _open_locked(self):
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        self._reopen = False
        fd = os.open(self._path,
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        # 0600 whatever the umask.
        try:
            os.fchmod(fd, 0o600)
            self._size = os.fstat(fd).st_size
        except OSError:
            os.close(fd)
            raise
        self._fd = fd
        # A new file warns afresh.
        self._warned = set()

    def _fail(self, message, kind="write"):
        if self._on_failure is not None:
            self._on_failure()
        if kind in self._warned or self._out is None:
            return
        self._warned.add(kind)
        # One write, newline included: see Inspection.log.
        self._out.write(f"WARNING: the per-request record is not being "
                        f"written: {message}\n")
        self._out.flush()

    def close(self):
        with self._lock:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
