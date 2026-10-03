"""
netns_listen: the inspector's listeners, or the responder's, bound in
another process's network namespace and handed to a program in this one.

A rootless container's network namespace belongs to a user namespace the
user owns. Joining the netns needs CAP_SYS_ADMIN over it and in the
joiner's own user namespace, which the user holds only inside the one it
owns, so a child joins both by the target's pidfd, binds, sends the
listeners back and exits. The parent never joins: it stays in the
host's namespaces, where the program it becomes dials its upstreams, and
hands the listeners down as a socket unit would.
"""

import fcntl
import os
import signal
import socket

from .egress_plane import PLANES, RESOLVE_PORT

# Where the listeners are bound in the target namespace. The redirect
# there lands 443, 80 and 53 on it.
LISTEN_ADDRESS = "127.0.0.1"

# (type, port) per listener, in the order they are handed over.
PLANE_LISTENERS = tuple((socket.SOCK_STREAM, plane.inspect_port)
                        for plane in PLANES)
RESOLVER_LISTENERS = ((socket.SOCK_DGRAM, RESOLVE_PORT),
                      (socket.SOCK_STREAM, RESOLVE_PORT))

# The first descriptor of the socket-activation protocol.
LISTEN_FDS_START = 3

# How long the child has to join, bind and send, in seconds.
BIND_TIMEOUT = 10.0


class BindFailed(Exception):
    """The listeners could not be bound in the target's namespace."""


def bind(specs):
    """One listener per (type, port) on this namespace's loopback."""
    socks = []
    try:
        for kind, port in specs:
            sock = socket.socket(socket.AF_INET, kind)
            socks.append(sock)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((LISTEN_ADDRESS, port))
            if kind == socket.SOCK_STREAM:
                sock.listen(socket.SOMAXCONN)
    except BaseException:
        for sock in socks:
            sock.close()
        raise
    return socks


def listeners_in(pid, specs=PLANE_LISTENERS):
    """The listeners `specs` names, bound in `pid`'s user and network
    namespace. Raises BindFailed, or OSError for a pid that cannot be
    opened.

    By pidfd, not /proc/PID/ns: a pid that exits and is reused between
    lookup and join is then an error, not another process's namespace.
    """
    pidfd = os.pidfd_open(pid)
    try:
        ours, theirs = socket.socketpair()
        with ours, theirs:
            child = os.fork()
            if child == 0:
                _join_and_bind(pidfd, ours, theirs, specs)
            theirs.close()
            return _received(ours, child, len(specs))
    finally:
        os.close(pidfd)


def _join_and_bind(pidfd, ours, theirs, specs):
    """The child: join, bind, send the listeners or the reason. Never
    returns."""
    status = 1
    try:
        ours.close()
        os.setns(pidfd, os.CLONE_NEWUSER | os.CLONE_NEWNET)
        socks = bind(specs)
        socket.send_fds(theirs, [b"ok"], [s.fileno() for s in socks])
        status = 0
    except BaseException as exc:
        try:
            theirs.sendall(str(exc).encode()[:1024] or b"failed")
        except OSError:
            pass
    finally:
        os._exit(status)


def _received(ours, child, count):
    """The `count` listeners the child sent, once it has exited."""
    ours.settimeout(BIND_TIMEOUT)
    fds = []
    try:
        msg, fds, _flags, _addr = socket.recv_fds(ours, 1024, count)
    except TimeoutError:
        os.kill(child, signal.SIGKILL)
        msg = f"nothing within {BIND_TIMEOUT}s".encode()
    _pid, status = os.waitpid(child, 0)
    socks = [socket.socket(fileno=fd) for fd in fds]
    if os.waitstatus_to_exitcode(status) == 0 and len(socks) == count:
        return socks
    for sock in socks:
        sock.close()
    raise BindFailed(msg.decode(errors="replace") or "the child exited")


def hand_over(socks, argv):
    """Become `argv` with `socks` as descriptors 3 onward and LISTEN_PID
    and LISTEN_FDS set, as a socket unit starts a service. Never
    returns."""
    count = len(socks)
    # Moved clear of 3..3+count first, so placing one never overwrites
    # another still to be placed.
    high = [fcntl.fcntl(s.fileno(), fcntl.F_DUPFD_CLOEXEC,
                        LISTEN_FDS_START + count) for s in socks]
    for sock in socks:
        sock.close()
    for i, fd in enumerate(high):
        os.dup2(fd, LISTEN_FDS_START + i, inheritable=True)
        os.close(fd)
    env = {k: v for k, v in os.environ.items() if k != "LISTEN_FDNAMES"}
    env.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS=str(count))
    os.execvpe(argv[0], argv, env)
