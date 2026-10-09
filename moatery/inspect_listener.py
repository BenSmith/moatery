"""
inspect_listener: the transparent egress inspector's accept loop.

Accept on the inherited listeners, identify the caller, admit up to a
ceiling, and hand each connection to its plane with the workload's
Inspection: 443 to inspect_tls, 80 to inspect_http.

The plane is read from the accepting socket's port, not LISTEN_FDNAMES:
under Accept=no every fd carries the unit's name.

One daemon thread per connection, up to a ceiling, and refused above it
rather than queued. Every accepted socket gets egress_relay's decision
timeout before it is touched.

A reload reads the policy file again between accepts and enforces it from
each connection's next decision; a connection already relaying keeps
going. Its `tls` is the one thing a reload cannot change: the minter was
built for it.
"""

import errno
import os
import secrets
import selectors
import threading
import time

from .egress_plane import TLS, plane_for_port
from .inspect_document import INSPECT_DIGEST_KEY
from .egress_ca import ca_cert_path, ca_key_path
from .http_framing import RequestUnreadable
from .egress_mint import Minter
from .egress_record import (
    DROP_CALLER_CLOSED, DROP_CEILING, DROP_FOREIGN_CALLER,
    DROP_NO_SOCKET_TABLE, LOG_ID_FIELD, Where, format_endpoint,
)
from . import egress_relay
from .egress_status import write_status
from . import inspect_http
from . import inspect_tls
from .inspect_policy import load_policy
from .inspect_scope import Inspection, quoted
from .peer_identity import (
    OWN_TABLES, NoSocketTable, in_ranges, local_endpoints, peer_caller,
    peer_closed,
)


# The ceiling on connections being served, well above a guest's honest
# concurrency.
MAX_CONNECTIONS = 128

# The ceiling on connections whose caller is still being looked up. Apart
# from MAX_CONNECTIONS so a foreign caller never holds a serving slot, and
# small because a lookup takes milliseconds. At it the loop stops
# accepting, so a flood of foreign callers queues the workload's
# connections in the kernel rather than having them refused.
MAX_IDENTIFYING = 32


# How often the accept loop wakes to look for a stop, in seconds: PEP 475
# retries select() across a signal.
_ACCEPT_POLL = 0.1


# How often the status file is replaced, in seconds.
STATUS_INTERVAL = 30.0


class Ceiling:
    """Admit up to `limit` live connections and refuse the rest."""

    def __init__(self, limit):
        self._limit = limit
        self._lock = threading.Condition()
        self._held = 0
        self.rejected = 0

    @property
    def held(self) -> int:
        """Connections live right now."""
        with self._lock:
            return self._held

    def admit(self):
        """Count a connection against the ceiling, or refuse it."""
        with self._lock:
            if self._held >= self._limit:
                self.rejected += 1
                return False
            self._held += 1
            return True

    def release(self, *, refused=False):
        """Give a slot back. `refused` counts a connection admitted and then
        turned away before it was served."""
        with self._lock:
            self._held -= 1
            if refused:
                self.rejected += 1
            self._lock.notify()

    def wait_for_room(self, timeout):
        """Whether a slot is free, waiting up to `timeout` seconds for
        one."""
        with self._lock:
            return self._lock.wait_for(lambda: self._held < self._limit,
                                       timeout)


class Listener:
    """Accept on the inherited listeners and act on each connection by
    plane."""

    def __init__(self, sockets, out=None, limit=MAX_CONNECTIONS, policy=None,
                 status_path=None, minter=None, record_path=None,
                 broker_endpoint=None, caller_uid=None, caller_ranges=None,
                 peer_tables=OWN_TABLES, policy_path=None):
        self._sockets = list(sockets)
        # Where a reload reads the policy from; None: it cannot be.
        self._policy_path = policy_path
        self._reload = threading.Event()
        self._ceiling = Ceiling(limit)
        self._identifying = Ceiling(MAX_IDENTIFYING)
        self._stop = threading.Event()
        # The one uid served, or None for this process's own. A sidecar's
        # workload is another uid by design.
        self._caller_uid = caller_uid
        # Or every uid of the workload's user namespace, as (start, count):
        # listeners bound in its network namespace are reachable from
        # nowhere else.
        self._caller_ranges = (None if caller_ranges is None
                               else tuple(caller_ranges))
        # The socket tables callers are looked up in: this process's own
        # namespace's, or the one the listeners were bound in.
        self._peer_tables = peer_tables
        # None: count, never write.
        self._status_path = status_path
        self.inspection = Inspection(
            policy, out=out, minter=minter, record_path=record_path,
            broker_endpoint=broker_endpoint)

    def stop(self):
        """Ask the accept loop to end; called from the SIGTERM handler."""
        self._stop.set()

    def request_reload(self):
        """Ask the accept loop to read the policy again; called from the
        reload signal's handler."""
        self._reload.set()

    def reload_policy(self):
        """Read the policy file and enforce it, or keep enforcing the one
        loaded and log why. The status file names the digest enforced
        either way."""
        current = self.inspection.policy
        try:
            if self._policy_path is None:
                raise ValueError("this listener was given no policy path")
            policy = load_policy(self._policy_path)
            if policy.tls != current.tls:
                raise ValueError(
                    f"its tls is {policy.tls!r} and the one enforced "
                    f"{current.tls!r}, which only a restart changes")
        except (OSError, ValueError) as exc:
            self.inspection.log(
                f"WARNING: policy not reloaded, still enforcing "
                f"{current.digest[:12] or 'none'}: reason={quoted(exc)}")
        else:
            self.inspection.policy = policy
            self.inspection.counters.set_lists(policy)
            self.inspection.log(f"policy reloaded from {self._policy_path}: "
                                f"{policy.summary}")
        self.write_status()

    def close(self):
        for s in self._sockets:
            s.close()

    def accept_loop(self):
        sel = selectors.DefaultSelector()
        for s in self._sockets:
            sel.register(s, selectors.EVENT_READ)
        # Written before the first connection, so a missing file means the
        # listener never started, not that it has served nothing.
        self.write_status()
        due = time.monotonic() + STATUS_INTERVAL
        try:
            while not self._stop.is_set():
                if self._reload.is_set():
                    self._reload.clear()
                    self.reload_policy()
                if time.monotonic() >= due:
                    self.write_status()
                    due = time.monotonic() + STATUS_INTERVAL
                try:
                    events = sel.select(timeout=_ACCEPT_POLL)
                except InterruptedError:
                    continue
                for key, _ in events:
                    if not self._identifying.wait_for_room(_ACCEPT_POLL):
                        break
                    try:
                        conn, peer = key.fileobj.accept()
                    except OSError as exc:
                        if exc.errno in (errno.EMFILE, errno.ENFILE):
                            self._out_of_fds(exc)
                        continue
                    self._fds_short = False
                    self._handle(conn, peer, key.fileobj)
        finally:
            sel.close()

    # Whether the last accept failed for want of a descriptor, so the
    # warning is written once per shortage.
    _fds_short = False

    def _out_of_fds(self, exc):
        """Wait out a shortage of file descriptors rather than spin on it.

        The connection stays queued, so the listener stays readable and
        select() would return at once.
        """
        if not self._fds_short:
            self._fds_short = True
            self.inspection.log(
                f"WARNING: cannot accept: {exc.strerror}; connections wait "
                f"in the queue until a descriptor is free")
        self._stop.wait(_ACCEPT_POLL)

    def _handle(self, conn, peer, listen_sock):
        conn.settimeout(egress_relay.CONNECTION_TIMEOUT)
        local = listen_sock.getsockname()
        plane = plane_for_port(local[1])
        # Random, not a counter: a socket-activated listener restarts, and
        # the record it keys outlives the restart.
        cid = secrets.token_hex(6)
        if plane is None:
            self.inspection.log(
                f"rejected {LOG_ID_FIELD}={cid} "
                f"local={format_endpoint(local)} "
                f"peer={format_endpoint(peer)} "
                f"reason=\"not an inspect port\"")
            conn.close()
            return
        # The id leads `where`, which every decision line and record
        # carries, so one field joins them all. `peer=` cannot: a port
        # repeats across a keep-alive connection's requests and is reused
        # by the kernel after close.
        where = Where(f"{LOG_ID_FIELD}={cid} plane={plane.label} "
                      f"local={format_endpoint(local)} "
                      f"peer={format_endpoint(peer)}",
                      cid=cid, plane=plane.label)
        # The caller is looked up in the connection's thread: the lookup
        # reads the kernel's socket table, and on this loop that time is
        # time no connection is accepted.
        if not self._identifying.admit():
            self._refuse_ceiling(conn, where, plane)
            return
        # Thread.start() raises when the process is out of threads, and the
        # slot taken above must come back or the ceiling shrinks for good.
        try:
            threading.Thread(
                target=self._admit, args=(conn, peer, where, plane),
                daemon=True).start()
        except RuntimeError as exc:
            self._identifying.release(refused=True)
            self._refuse_ceiling(conn, where, plane,
                                 f"cannot start thread: {exc}")

    def _refuse_ceiling(self, conn, where, plane, detail=None):
        mode = ("forward" if plane is not TLS
                else "terminate" if self.inspection.policy.tls == "inspect"
                else "splice")
        self.inspection.drop(where, DROP_CEILING, detail, mode=mode,
                             verb="rejected")
        conn.close()

    def _admit(self, conn, peer, where, plane):
        """Identify the caller, take a serving slot, and serve: the
        connection thread's first act."""
        try:
            admitted = self._identified(conn, peer, where)
        finally:
            self._identifying.release()
        if not admitted:
            return
        if not self._ceiling.admit():
            self._refuse_ceiling(conn, where, plane)
            return
        self._serve(conn, where, plane)

    def _identified(self, conn, peer, where):
        """Whether the caller is the one this listener serves. Closes the
        connection if not.

        Behind the host's rules, which are the primary control: a dial from
        another uid that got past them would be written into this
        workload's records as its own. Root is refused too, whatever the
        rules exempt.
        """
        try:
            caller, orphaned = peer_caller(local_endpoints(conn), peer[:2],
                                           self._peer_tables)
            if caller is None and not orphaned:
                orphaned = peer_closed(conn)
        except NoSocketTable:
            # Read through a process that has gone: no caller can be named
            # again, and admitting every one unnamed would serve anyone.
            self.inspection.drop(where, DROP_NO_SOCKET_TABLE, verb="rejected")
            conn.close()
            return False
        except Exception:
            # A second layer that throws must not take the connection path
            # down with it.
            caller, orphaned = None, False
        if orphaned:
            # The caller wrote and closed or reset before it could be looked
            # up, which any local uid can choose to do.
            self.inspection.drop(where, DROP_CALLER_CLOSED, verb="rejected")
            conn.close()
            return False
        if caller is not None and not self._serves(caller):
            self.inspection.drop(where, DROP_FOREIGN_CALLER, verb="rejected",
                                 caller_uid=caller)
            conn.close()
            return False
        # An owner the lookup could not name is admitted, since refusing
        # would drop the workload's own traffic when the table churns, and
        # counted rather than logged, since it is a routine race.
        if caller is None:
            self.inspection.counters.record_caller_unresolved()
        return True

    def _serves(self, uid):
        if self._caller_ranges is not None:
            return in_ranges(uid, self._caller_ranges)
        own = os.getuid() if self._caller_uid is None else self._caller_uid
        return uid == own

    def _serve(self, conn, where, plane):
        try:
            if plane is TLS:
                inspect_tls.serve_tls(self.inspection, conn, where)
            else:
                inspect_http.serve_cleartext(self.inspection, conn, where)
        except (OSError, RequestUnreadable):
            pass
        finally:
            conn.close()
            self._ceiling.release()

    @property
    def rejected(self) -> int:
        """How many connections this process turned away."""
        return self._ceiling.rejected + self._identifying.rejected

    def status(self) -> dict:
        """This listener's counters, as they would be written right now."""
        snap = self.inspection.counters.snapshot(open_now=self._ceiling.held,
                                      refused=self.rejected)
        # Which policy this process enforces, empty string included, so a
        # missing digest is not mistaken for an older listener.
        snap[INSPECT_DIGEST_KEY] = self.inspection.policy.digest
        if self.inspection.minter is not None:
            snap["mint"] = self.inspection.minter.snapshot()
        return snap

    def write_status(self):
        """Replace the status file, or log why it could not be replaced.

        Never raises: this runs on the accept loop. TypeError and ValueError
        are json.dump's for a value it cannot serialise.
        """
        if self._status_path is None:
            return
        try:
            write_status(self._status_path, self.status())
        except (OSError, TypeError, ValueError) as exc:
            self.inspection.log(
                f"WARNING: could not write {self._status_path}: {exc}")

    def log_summary(self):
        """One line at shutdown naming what was refused, zero included."""
        self.inspection.log(f"stopped: {self.rejected} connection(s) rejected")


def build_minter(name, state_dir, policy):
    """A Minter for a terminating workload, or None. Raises if it cannot.

    The CA is checked here, at start: it is made before the listener first
    runs, so its absence is a provisioning failure, and it should not
    surface as a refused connection an hour later.
    """
    if policy.tls != "inspect":
        return None
    cert = ca_cert_path(state_dir)
    key = ca_key_path(state_dir)
    for path in (cert, key):
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"\"tls\": \"inspect\" terminates, which needs this "
                f"workload's egress CA, and {path} is not there; "
                f"`moat-mint-ca "
                f"--name {name} --state-dir {state_dir}` makes one")
    return Minter(name, state_dir)
