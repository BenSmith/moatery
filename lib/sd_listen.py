"""Recovering the listeners a .socket unit passed in.

For a program that is socket-activated and never binds. `refusal` is the
caller's own reason for refusing to bind, since that reason differs by
program.
"""
import os
import socket


class NotSocketActivated(Exception):
    """The process was not handed its listeners by the socket unit."""


def inherited_listening_sockets(*, refusal: str) -> list[socket.socket]:
    """The sockets systemd passed in, fds 3 .. 3+LISTEN_FDS, or raise.

    `refusal` completes the sentence "It refuses to open a socket of its
    own".
    """
    listen_pid = os.environ.get("LISTEN_PID")
    listen_fds = os.environ.get("LISTEN_FDS")
    missing = [name for name, value in (("LISTEN_PID", listen_pid),
                                        ("LISTEN_FDS", listen_fds))
               if value is None]
    if missing:
        raise NotSocketActivated(
            "this program is socket-activated and never binds: it takes its "
            f"sockets from the .socket unit, but {', '.join(missing)} is not "
            f"set. It refuses to open a socket of its own{refusal}")
    if listen_pid != str(os.getpid()):
        raise NotSocketActivated(
            f"LISTEN_PID={listen_pid} is not this process ({os.getpid()}); "
            "the activation environment belongs to another process, so the "
            "inherited fds would not be ours to use")
    try:
        count = int(listen_fds)
    except ValueError:
        raise NotSocketActivated(
            f"LISTEN_FDS={listen_fds!r} is not an integer") from None
    return [socket.socket(fileno=fd) for fd in range(3, 3 + count)]
