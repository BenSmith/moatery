#!/usr/bin/env python3
"""sd_notify: READY=1 to the service manager of a Type=notify unit, and
nothing to one that is not."""

import os
import shutil
import socket
import tempfile
import time
import unittest

from customs.sd_notify import notify_ready


def notify_socket(case):
    """A bound datagram socket standing in for the manager's, and its
    path."""
    path = os.path.join(tempfile.mkdtemp(), "notify")
    case.addCleanup(shutil.rmtree, os.path.dirname(path))
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    case.addCleanup(sock.close)
    sock.bind(path)
    sock.settimeout(5)
    return path, sock


class TestNotifyReady(unittest.TestCase):
    def test_ready_is_sent_and_the_variable_removed(self):
        path, sock = notify_socket(self)
        environ = {"NOTIFY_SOCKET": path, "OTHER": "1"}
        notify_ready(environ)
        self.assertEqual(sock.recv(64), b"READY=1")
        self.assertEqual(environ, {"OTHER": "1"})

    def test_an_abstract_socket_is_reached(self):
        name = f"customs-test-{os.getpid()}-{time.monotonic_ns()}"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind("\0" + name)
        sock.settimeout(5)
        notify_ready({"NOTIFY_SOCKET": "@" + name})
        self.assertEqual(sock.recv(64), b"READY=1")

    def test_nothing_is_sent_unasked(self):
        environ = {"OTHER": "1"}
        notify_ready(environ)
        self.assertEqual(environ, {"OTHER": "1"})


if __name__ == "__main__":
    unittest.main()
