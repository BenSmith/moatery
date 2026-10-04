"""Telling the service manager a Type=notify unit is ready.

For a program whose readiness is a bind: once the socket is listening, a
connection waits in its backlog, so what is ordered after the unit may
start.
"""
import os
import socket


def notify_ready(environ=os.environ, main_pid=None):
    """Send READY=1 if the unit is Type=notify, and remove NOTIFY_SOCKET,
    so no process started after this one answers for the bind. With
    `main_pid`, the manager takes that process for the unit's main one
    from then; a unit whose main process does not send it needs
    NotifyAccess=all."""
    path = environ.pop("NOTIFY_SOCKET", None)
    if not path:
        return
    if path.startswith("@"):
        path = "\0" + path[1:]
    message = b"READY=1"
    if main_pid is not None:
        message = f"MAINPID={main_pid}\n".encode() + message
    with socket.socket(socket.AF_UNIX,
                       socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
        sock.connect(path)
        sock.sendall(message)
