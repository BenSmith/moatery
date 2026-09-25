"""customs-netns-listen: the planes, or the responder's port, bound in
another process's network namespace and handed to a program in this one.

The cases that join a namespace need unprivileged user namespaces and a
`setns` the sandbox allows; where either is missing they skip, and the
proving host runs them. The target is `unshare --user --map-root-user
--net`, which is a rootless container's arrangement without the
container: a user namespace the user owns, and a network namespace it
owns.
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock

from tests import REPO_ROOT

import netns_listen
from egress_plane import CLEARTEXT, RESOLVE_PORT, TLS

LAUNCHER = REPO_ROOT / "libexec" / "customs-netns-listen"
INSPECTOR = REPO_ROOT / "libexec" / "customs-inspect"
RESOLVER = REPO_ROOT / "libexec" / "customs-resolve"
ENV = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "lib")}

# What the handed-over program sees: the activation variables and, for
# each descriptor, its address and whether its row is in the target's
# table and in this namespace's own.
PROBE = """
import json, os, socket, sys
from peer_identity import listed_in, netns_tables
pid = int(sys.argv[1])
socks = [socket.socket(fileno=fd)
         for fd in range(3, 3 + int(os.environ["LISTEN_FDS"]))]
print(json.dumps({
    "listen_pid": os.environ["LISTEN_PID"] == str(os.getpid()),
    "fdnames": "LISTEN_FDNAMES" in os.environ,
    "names": sorted(list(s.getsockname()) for s in socks),
    "in_target": [listed_in(s, netns_tables(pid)) for s in socks],
    "in_own": [listed_in(s) for s in socks],
    "netns": os.readlink("/proc/self/ns/net"),
}))
"""


def _target(test):
    """A process in a user and network namespace of its own, or skip."""
    if shutil.which("unshare") is None:
        test.skipTest("unshare is not installed")
    proc = subprocess.Popen(
        ["unshare", "--user", "--map-root-user", "--net", "sleep", "60"],
        stderr=subprocess.PIPE)
    test.addCleanup(proc.stderr.close)
    test.addCleanup(proc.wait)
    test.addCleanup(proc.kill)
    own = os.readlink("/proc/self/ns/net")
    for _ in range(100):
        try:
            if os.readlink(f"/proc/{proc.pid}/ns/net") != own:
                break
        except OSError:
            pass
        if proc.poll() is not None:
            test.skipTest("no unprivileged user namespaces: "
                          + proc.stderr.read().decode().strip())
        time.sleep(0.02)
    else:
        test.skipTest("unshare never entered its namespaces")
    return proc.pid


def _launch(pid, command, *flags, **kw):
    return subprocess.run(
        [sys.executable, str(LAUNCHER), "--pid", str(pid), *flags, "--",
         *command],
        capture_output=True, text=True, timeout=30, **{"env": ENV, **kw})


# A child that joins the target's namespaces and runs `body` there. A
# fresh namespace's loopback is down, where a container runtime brings it
# up; SIOCSIFFLAGS with IFF_UP does that here.
def _inside(pid, body):
    return subprocess.run([sys.executable, "-c", f"""
import fcntl, os, socket, struct
os.setns(os.pidfd_open({pid}), os.CLONE_NEWUSER | os.CLONE_NEWNET)
fcntl.ioctl(socket.socket(), 0x8914, struct.pack("16sh22x", b"lo", 1))
""" + body], capture_output=True, text=True, timeout=30)


def _joined(test, pid):
    """The launcher run once with a probe, or skip where this sandbox
    refuses the join."""
    done = _launch(pid, [sys.executable, "-c", PROBE, str(pid)])
    if "Operation not permitted" in done.stderr:
        test.skipTest("setns is refused here: " + done.stderr.strip())
    return done


class TestHandOver(unittest.TestCase):
    """The socket unit's half: descriptors 3 onward, LISTEN_PID the
    process that execs, and nothing stale from an outer activation."""

    def test_the_listeners_arrive_as_fds_3_and_4(self):
        script = f"""
import os, socket, sys
sys.path.insert(0, {str(REPO_ROOT / 'lib')!r})
from netns_listen import hand_over
# Something already on 3 and 4, and a listener that would be overwritten
# by a naive dup2 onto 3.
held = [os.open("/dev/null", os.O_RDONLY) for _ in range(2)]
os.environ["LISTEN_FDNAMES"] = "stale"
socks = []
for _ in range(2):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    socks.append(s)
want = sorted(s.getsockname()[1] for s in socks)
hand_over(socks, [sys.executable, "-c", '''
import json, os, socket
socks = [socket.socket(fileno=fd) for fd in (3, 4)]
print(json.dumps({{
    "fds": os.environ["LISTEN_FDS"],
    "pid": os.environ["LISTEN_PID"] == str(os.getpid()),
    "fdnames": "LISTEN_FDNAMES" in os.environ,
    "ports": sorted(s.getsockname()[1] for s in socks),
    "want": %r,
}}))
''' % want])
"""
        done = subprocess.run([sys.executable, "-c", script],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        got = json.loads(done.stdout)
        self.assertEqual(got["fds"], "2")
        self.assertTrue(got["pid"])
        self.assertFalse(got["fdnames"])
        self.assertEqual(got["ports"], got["want"])


class TestTheLauncherRefuses(unittest.TestCase):

    def test_a_pid_that_does_not_exist(self):
        done = _launch(2 ** 22 + 7, ["true"])
        self.assertEqual(done.returncode, 1)
        self.assertIn("cannot bind", done.stderr)

    def test_no_command(self):
        done = subprocess.run(
            [sys.executable, str(LAUNCHER), "--pid", "1", "--"],
            capture_output=True, text=True, env=ENV, timeout=30)
        self.assertEqual(done.returncode, 2)
        self.assertIn("no command", done.stderr)

    def test_a_child_that_fails_reports_why(self):
        """The child's exception is the message, not a bare exit status."""
        with unittest.mock.patch.object(
                netns_listen.os, "setns",
                side_effect=PermissionError(1, "Operation not permitted")), \
                self.assertRaises(netns_listen.BindFailed) as caught:
            netns_listen.listeners_in(os.getpid())
        self.assertIn("Operation not permitted", str(caught.exception))


class TestReadiness(unittest.TestCase):
    """Type=notify: READY=1 once the listeners are bound, and only then,
    so the workload ordered after the unit finds them there."""

    def _notify_socket(self):
        path = os.path.join(tempfile.mkdtemp(), "notify")
        self.addCleanup(shutil.rmtree, os.path.dirname(path))
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind(path)
        sock.settimeout(5)
        return path, sock

    def test_ready_is_sent_and_the_variable_removed(self):
        path, sock = self._notify_socket()
        environ = {"NOTIFY_SOCKET": path, "OTHER": "1"}
        netns_listen.notify_ready(environ)
        self.assertEqual(sock.recv(64), b"READY=1")
        self.assertEqual(environ, {"OTHER": "1"})

    def test_an_abstract_socket_is_reached(self):
        name = f"customs-test-{os.getpid()}-{time.monotonic_ns()}"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind("\0" + name)
        sock.settimeout(5)
        netns_listen.notify_ready({"NOTIFY_SOCKET": "@" + name})
        self.assertEqual(sock.recv(64), b"READY=1")

    def test_nothing_is_sent_unasked(self):
        environ = {"OTHER": "1"}
        netns_listen.notify_ready(environ)
        self.assertEqual(environ, {"OTHER": "1"})

    def test_the_launcher_tells_after_the_bind_and_the_program_is_not_asked(
            self):
        path, sock = self._notify_socket()
        pid = _target(self)
        _joined(self, pid)
        done = _launch(pid, [sys.executable, "-c", """
import os
print(os.environ.get("NOTIFY_SOCKET", "unset"), os.environ["LISTEN_FDS"])
"""], env={**ENV, "NOTIFY_SOCKET": path})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(sock.recv(64), b"READY=1")
        self.assertEqual(done.stdout.split(), ["unset", "2"])

    def test_a_failed_bind_is_never_reported_ready(self):
        path, sock = self._notify_socket()
        done = _launch(2 ** 22 + 7, ["true"],
                       env={**ENV, "NOTIFY_SOCKET": path})
        self.assertEqual(done.returncode, 1)
        sock.settimeout(0.2)
        with self.assertRaises(TimeoutError):
            sock.recv(64)

    def test_an_unreachable_manager_fails_the_start(self):
        pid = _target(self)
        _joined(self, pid)
        done = _launch(pid, ["true"], env={
            **ENV, "NOTIFY_SOCKET": os.path.join(tempfile.gettempdir(),
                                                 "no-such-notify-socket")})
        self.assertEqual(done.returncode, 1)
        self.assertIn("cannot tell the service manager", done.stderr)


class TestTheListenersAreInTheTarget(unittest.TestCase):

    def test_bound_in_the_target_and_handed_to_this_namespace(self):
        pid = _target(self)
        done = _joined(self, pid)
        self.assertEqual(done.returncode, 0, done.stderr)
        got = json.loads(done.stdout)
        self.assertTrue(got["listen_pid"])
        self.assertFalse(got["fdnames"])
        self.assertEqual(got["names"],
                         sorted([["127.0.0.1", TLS.inspect_port],
                                 ["127.0.0.1", CLEARTEXT.inspect_port]]))
        self.assertEqual(got["in_target"], [True, True])
        self.assertEqual(got["in_own"], [False, False])
        self.assertEqual(got["netns"], os.readlink("/proc/self/ns/net"),
                         "the program ran in the target's namespace")

    def test_with_resolver_the_responders_port_over_udp_and_tcp(self):
        pid = _target(self)
        _joined(self, pid)
        done = _launch(pid, [sys.executable, "-c", """
import json, os, socket
socks = [socket.socket(fileno=fd)
         for fd in range(3, 3 + int(os.environ["LISTEN_FDS"]))]
print(json.dumps([[s.type, *s.getsockname()] for s in socks]))
"""], "--resolver")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout), [
            [int(socket.SOCK_DGRAM), "127.0.0.1", RESOLVE_PORT],
            [int(socket.SOCK_STREAM), "127.0.0.1", RESOLVE_PORT]])


class TestTheInspectorBehindTheLauncher(unittest.TestCase):
    """The seam: the launcher's listeners, the real inspector, and a caller
    inside the target's namespace. Without --netns-pid the inspector's
    lookups read a table the listeners are not in, and it refuses to
    start rather than admit every caller unnamed."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.policy = os.path.join(self.dir, "policy.json")
        with open(self.policy, "w") as fh:
            json.dump({"tls": "splice", "hosts": [], "internal": [],
                       "splice": [], "policy": []}, fh)
        self.status = os.path.join(self.dir, "status.json")
        self.record = os.path.join(self.dir, "record.jsonl")

    def _inspector(self, pid, extra):
        return [sys.executable, str(INSPECTOR), "--name", "t",
                "--policy", self.policy, "--state-dir", self.dir,
                "--status", self.status, "--record", self.record, *extra]

    def test_without_netns_pid_the_start_is_refused(self):
        pid = _target(self)
        _joined(self, pid)
        done = _launch(pid, self._inspector(pid, []))
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("--netns-pid", done.stderr)

    def test_a_caller_in_the_namespace_is_named_and_served(self):
        pid = _target(self)
        _joined(self, pid)
        inspector = subprocess.Popen(
            [sys.executable, str(LAUNCHER), "--pid", str(pid), "--",
             *self._inspector(pid, ["--netns-pid", str(pid)])],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=ENV)
        self.addCleanup(inspector.kill)
        for _ in range(200):
            if os.path.exists(self.status) or inspector.poll() is not None:
                break
            time.sleep(0.05)
        if inspector.poll() is not None:
            self.fail(f"the inspector exited: {inspector.stderr.read()}")
        # The caller: a child that joins the namespace and dials the plane.
        answer = _inside(pid, f"""
s = socket.create_connection(("127.0.0.1", {CLEARTEXT.inspect_port}), 5)
s.sendall(b"GET / HTTP/1.1\\r\\nHost: unlisted.example\\r\\n\\r\\n")
print(s.recv(4096).split(b"\\r\\n")[0].decode())
""")
        inspector.send_signal(signal.SIGTERM)
        inspector.communicate(timeout=10)
        self.assertEqual(answer.stdout.strip(), "HTTP/1.1 403 Forbidden",
                         answer.stderr)
        with open(self.status) as fh:
            status = json.load(fh)
        self.assertEqual(status["caller_unresolved"], 0,
                         "the lookup read a table the caller is not in")
        with open(self.record) as fh:
            lines = [json.loads(ln) for ln in fh]
        self.assertEqual([r["decision"] for r in lines], ["drop"])



class TestTheResponderBehindTheLauncher(unittest.TestCase):
    """The same seam for customs-resolve: its sockets bound in the target,
    and a query from inside answered over both transports."""

    def test_a_query_in_the_namespace_is_answered(self):
        pid = _target(self)
        _joined(self, pid)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        policy = os.path.join(d, "policy.json")
        status = os.path.join(d, "status.json")
        with open(policy, "w") as fh:
            json.dump({"hosts": ["listed.example"]}, fh)
        responder = subprocess.Popen(
            [sys.executable, str(LAUNCHER), "--pid", str(pid), "--resolver",
             "--", sys.executable, str(RESOLVER), "--name", "t",
             "--address", "169.254.1.3", "--policy", policy,
             "--status", status],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=ENV)
        self.addCleanup(responder.kill)
        for _ in range(200):
            if os.path.exists(status) or responder.poll() is not None:
                break
            time.sleep(0.05)
        if responder.poll() is not None:
            self.fail(f"the responder exited: {responder.stderr.read()}")
        answer = _inside(pid, f"""
q = (struct.pack("!6H", 7, 0x0100, 1, 0, 0, 0)
     + b"\\x05exfil\\x07example\\x00" + struct.pack("!2H", 1, 1))
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(5)
u.sendto(q, ("127.0.0.1", {RESOLVE_PORT}))
print(socket.inet_ntoa(u.recv(512)[-4:]))
t = socket.create_connection(("127.0.0.1", {RESOLVE_PORT}), 5)
t.sendall(struct.pack("!H", len(q)) + q)
n = struct.unpack("!H", t.recv(2))[0]
print(socket.inet_ntoa(t.recv(n)[-4:]))
""")
        responder.send_signal(signal.SIGTERM)
        responder.communicate(timeout=10)
        self.assertEqual(answer.stdout.split(), ["169.254.1.3"] * 2,
                         answer.stderr)
        with open(status) as fh:
            self.assertEqual(json.load(fh)["unlisted_names"],
                             {"exfil.example": 2})


if __name__ == "__main__":
    unittest.main()
