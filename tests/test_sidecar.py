"""The sidecar entrypoint: what it hands each program, checked against the
program's own parser.

The entrypoint is a unit file as a process. Its one failure mode worth a
test here is the one a unit file has: a flag it writes that the program
does not take, or a value form the program reads differently, is a
container that never starts -- and nothing below main() in either program
sees the seam. So each argv the entrypoint builds is fed to the parser of
the program it is for. What the rows on the proving host add is the rest:
the bind, the drop, the socket at the path, the workload's request.
"""

import contextlib
import io
import os
import pwd
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from customs.egress_plane import CLEARTEXT, TLS
from tests import REPO_ROOT, load_script, script_env

FAKE_INSPECT = pwd.struct_passwd(("inspect", "x", 200, 200, "", "/", ""))


def _mod():
    return load_script("container/customs-sidecar")


class TestTheFlagsSplit(unittest.TestCase):

    def test_the_two_facts_are_taken_and_the_rest_is_the_brokers(self):
        mod = _mod()
        args, rest = mod.parse_args(
            ["x", "--name", "wl", "--caller-uid", "1000",
             "--host", "api.example=main", "--placeholder", "main=sk-x"])
        self.assertEqual((args.name, args.caller_uid), ("wl", 1000))
        self.assertEqual(rest, ["--host", "api.example=main",
                                "--placeholder", "main=sk-x"])

    def test_each_fact_is_required(self):
        mod = _mod()
        for argv in (["x", "--caller-uid", "1", "--host", "a=b"],
                     ["x", "--name", "wl", "--host", "a=b"]):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    mod.parse_args(argv)
            self.assertEqual(caught.exception.code, 2)

    def test_the_brokers_listen_is_not_the_callers_to_give(self):
        """A second --listen would win argparse's last-wins and put the
        broker on an address the pod can reach."""
        mod = _mod()
        for extra in (["--listen", "127.0.0.1:8081"],
                      ["--listen=127.0.0.1:8081"]):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit):
                    mod.parse_args(["x", "--name", "wl", "--caller-uid",
                                    "1000", "--host", "a=b", *extra])
            self.assertIn("--listen", err.getvalue())

    def test_no_broker_flags_at_all_is_a_usage_error(self):
        mod = _mod()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                mod.parse_args(["x", "--name", "wl", "--caller-uid", "1"])


class TestEachArgvIsAcceptedByItsProgram(unittest.TestCase):
    """The seam: the entrypoint's idea of the flags against the parsers."""

    def test_the_broker_argv_parses_and_binds_the_socket_path(self):
        mod = _mod()
        with mock.patch.object(mod.pwd, "getpwnam",
                               return_value=FAKE_INSPECT):
            argv = mod.broker_argv("wl", ["--host", "api.example=main"])
        broker = load_script("libexec/customs-broker")
        args = broker.parse_args(argv[1:])
        self.assertEqual(args.listen, f"unix:{mod.SOCKET}")
        self.assertEqual(args.caller_uid, 200)
        self.assertEqual(args.host, ["api.example=main"])
        from customs import broker_profiles
        self.assertEqual(broker_profiles.listen_endpoint(args.listen),
                         mod.SOCKET)

    def test_the_inspector_argv_parses_and_dials_the_same_path(self):
        mod = _mod()
        argv = mod.inspector_argv("wl", 1000)
        inspector = load_script("libexec/customs-inspect")
        args = inspector.parse_args(argv[1:])
        self.assertEqual(args.broker, mod.SOCKET)
        self.assertEqual(args.caller_uid, 1000)
        self.assertEqual(args.state_dir, mod.STATE)
        self.assertEqual(args.policy, mod.POLICY)

    def test_the_responder_argv_parses_and_answers_with_the_loopback(self):
        """Every name answered with the address the redirect lands 443 and
        80 from, counted against the policy the inspector reads."""
        mod = _mod()
        resolver = load_script("libexec/customs-resolve")
        args = resolver.parse_args(mod.resolver_argv("wl")[1:])
        self.assertEqual(args.address, mod.LOOPBACK)
        self.assertIsNone(args.address6)
        self.assertEqual(args.policy, mod.POLICY)
        self.assertTrue(args.status.startswith(mod.STATE + "/"))
        self.assertNotEqual(args.status, mod.STATUS)

    def test_the_responders_sockets_are_its_port_over_both_transports(self):
        import socket as socket_mod
        mod = _mod()
        from customs.egress_plane import RESOLVE_PORT
        self.assertEqual(sorted(mod.RESOLVER_SOCKETS), sorted([
            (socket_mod.SOCK_DGRAM, RESOLVE_PORT),
            (socket_mod.SOCK_STREAM, RESOLVE_PORT)]))

    def test_the_planes_are_the_inspectors(self):
        """The bind is here and the recognition is the inspector's: a port
        bound that plane_for_port does not know is a listener that rejects
        every connection as 'not an inspect port'."""
        mod = _mod()
        self.assertEqual(set(mod.PLANES),
                         {TLS.inspect_port, CLEARTEXT.inspect_port})


class TestTheSidecarMintsTheOneWay(unittest.TestCase):
    """The sidecar's first-start mint is egress_mint.mint_ca, the call
    customs-mint-ca makes on a host, made in a child that has already
    dropped to the inspector's uid. Root never writes into the volume the
    inspector owns, so nothing the inspector left there can steer it."""

    GROUP = mock.Mock(gr_gid=200)

    def _mint(self, mint_ca):
        """Run the sidecar's mint_ca with `become` recording into a pipe the
        parent reads -- mocks survive the fork, their calls do not."""
        mod = _mod()
        r, w = os.pipe()
        self.addCleanup(os.close, r)

        def become(user, group):
            os.write(w, b"dropped;")

        def mint(name, state):
            os.write(w, f"mint {name} {state};".encode())
            return mint_ca()

        with mock.patch.object(mod, "become", become), \
                mock.patch.object(mod.egress_mint, "mint_ca", mint), \
                mock.patch.object(mod.os, "chown",
                                  side_effect=AssertionError("chown")):
            try:
                result = mod.mint_ca("wl", FAKE_INSPECT, self.GROUP)
            finally:
                os.close(w)
        return mod, result, os.read(r, 4096).decode()

    def test_a_fresh_ca_is_minted_after_the_drop(self):
        mod, result, trail = self._mint(lambda: True)
        self.assertTrue(result)
        self.assertEqual(trail, f"dropped;mint wl {mod.STATE};")

    def test_a_kept_ca_is_reported_as_kept(self):
        _mod_, result, trail = self._mint(lambda: False)
        self.assertFalse(result)
        self.assertTrue(trail.startswith("dropped;"))

    def test_a_failed_mint_fails_the_start(self):
        mod = _mod()

        def refuse():
            raise mod.egress_mint.MintFailed("no openssl")

        with contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(mod.egress_mint.MintFailed):
            self._mint(refuse)

    def test_no_second_mint_lives_in_the_entrypoint(self):
        """Its own openssl argv would be a second mint for the three
        extensions to drift between."""
        source = (Path(REPO_ROOT) / "container" / "customs-sidecar").read_text()
        self.assertNotIn("ca_openssl_argv", source)
        self.assertNotIn("os.chown(path, inspect", source)


class TestTheProgramsGetAMinimalEnvironment(unittest.TestCase):
    """The container's environment stays with pid 1. A secret passed with
    `--secret ...,type=env` would otherwise be in the inspector's."""

    def test_only_the_named_variables_pass(self):
        mod = _mod()
        with mock.patch.dict(os.environ, {"PATH": "/p", "LANG": "C.UTF-8",
                                          "API_KEY": "sk-real"}, clear=True):
            env = mod.program_env(LISTEN_FDS="2")
        self.assertEqual(env, {"PATH": "/p", "LANG": "C.UTF-8",
                               "LISTEN_FDS": "2"})

    def test_a_path_is_given_whatever_the_container_had(self):
        """The inspector finds openssl on PATH."""
        mod = _mod()
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(mod.program_env()["PATH"], mod.DEFAULT_PATH)


class TestTheBrokerIsListeningBeforeTheInspectorStarts(unittest.TestCase):
    """The socket file exists from bind(), before listen(): a path check
    alone started the inspector in a window where its first brokered
    request was refused."""

    def _await(self, listening):
        import socket as socket_mod
        mod = _mod()
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp))
        path = os.path.join(tmp, "broker.sock")
        sock = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind(path)
        if listening:
            sock.listen(1)
        child = subprocess.Popen(["sleep", "5"])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        with mock.patch.object(mod, "SOCKET", path), \
                mock.patch.object(mod, "BROKER_START_TIMEOUT", 0.5):
            return mod.await_socket(child.pid)

    def test_a_bound_socket_that_does_not_listen_is_not_up(self):
        self.assertEqual(self._await(listening=False), (False, None))

    def test_a_listening_socket_is_up(self):
        self.assertEqual(self._await(listening=True), (True, None))


# Run in a child of its own so that supervise() waits on nothing but the
# processes the scenario forks. argv: repo root, scenario, STOP_GRACE,
# a directory for the marks each program leaves when SIGTERM reaches it.
SUPERVISED = r"""
import os, signal, sys, time
sys.path.insert(0, sys.argv[1])
from tests import load_script
mod = load_script("container/customs-sidecar")
scenario, mod.STOP_GRACE, marks = sys.argv[2], float(sys.argv[3]), sys.argv[4]

def program(name, exit_after=None, ignore_term=False):
    pid = os.fork()
    if pid:
        return pid
    def term(*_):
        open(os.path.join(marks, "term-" + name), "w").close()
        os._exit(0)
    signal.signal(signal.SIGTERM, signal.SIG_IGN if ignore_term else term)
    open(os.path.join(marks, "up-" + name), "w").close()
    if exit_after is not None:
        time.sleep(exit_after)
        os._exit(3)
    while True:
        time.sleep(0.05)

stopping = []
signal.signal(signal.SIGTERM, lambda signum, _: stopping.append(signum))
dies = scenario != "stop"
children = {program("broker", exit_after=0.3 if dies else None): "broker",
            program("inspector", ignore_term=scenario == "stubborn"):
                "inspector"}
if not os.fork():
    os._exit(0)                     # an orphan's stand-in: not a program
while len(os.listdir(marks)) < 2:
    time.sleep(0.01)
print("ready", flush=True)
sys.exit(mod.supervise(children, stopping))
"""


class TestTheContainerEndsWithEitherProgram(unittest.TestCase):
    """The pair serves together or not at all. A broker that died under a
    live inspector left the container up with every brokered request
    refused, so no restart policy ever fired: the entrypoint exec'd the
    inspector and nothing waited on the broker."""

    def _supervise(self, scenario, grace=5.0, stop=False):
        marks = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(marks))
        proc = subprocess.Popen(
            [sys.executable, "-c", SUPERVISED, str(REPO_ROOT), scenario,
             str(grace), marks],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=script_env())
        self.addCleanup(proc.kill)
        self.assertEqual(proc.stdout.readline(), "ready\n")
        if stop:
            # Once supervise() is waiting: a stop that lands before the
            # wait is seen whether or not the wait can be interrupted.
            time.sleep(0.5)
            proc.send_signal(signal.SIGTERM)
        _out, err = proc.communicate(timeout=10)
        termed = sorted(n[len("term-"):] for n in os.listdir(marks)
                        if n.startswith("term-"))
        return proc.returncode, err, termed

    def test_a_program_exiting_stops_the_other_and_the_container_fails(self):
        rc, err, termed = self._supervise("exit")
        self.assertIn("the broker exited (3)", err)
        self.assertEqual(termed, ["inspector"])
        self.assertEqual(rc, 1)

    def test_a_stop_reaches_both_and_the_container_succeeds(self):
        rc, err, termed = self._supervise("stop", stop=True)
        self.assertEqual(termed, ["broker", "inspector"])
        self.assertEqual(rc, 0, err)

    def test_a_program_deaf_to_sigterm_is_killed_after_the_grace(self):
        rc, err, _termed = self._supervise("stubborn", grace=0.5)
        self.assertIn("the inspector exited (-9)", err)
        self.assertEqual(rc, 1)


class TestTheSidecarStartsTwice(unittest.TestCase):
    """A restart finds its directories already handed over. The chmod
    that came first on a fresh volume was refused on the second start,
    since the directory was the inspector's and the container holds no
    CAP_FOWNER, so the sidecar could never start twice on one volume."""

    def test_each_directory_is_roots_before_its_chmod(self):
        mod = _mod()
        calls = []
        group = mock.Mock(gr_gid=200)
        broker = pwd.struct_passwd(("broker", "x", 201, 200, "", "/", ""))
        with mock.patch.object(mod.Path, "mkdir"), \
                mock.patch.object(mod.Path, "chmod",
                                  lambda path, mode: calls.append(
                                      ("chmod", str(path)))), \
                mock.patch.object(mod.os, "chown",
                                  lambda path, uid, gid: calls.append(
                                      ("chown", str(path), uid))):
            mod.prepare_dirs(FAKE_INSPECT, broker, group)
        self.assertEqual(calls, [
            ("chown", mod.RUN_DIR, 0), ("chmod", mod.RUN_DIR),
            ("chown", mod.RUN_DIR, 201),
            ("chown", mod.STATE, 0), ("chmod", mod.STATE),
            ("chown", mod.STATE, 200)])

    def test_an_exempt_caller_uid_is_refused(self):
        """The rules exempt 200 and 201 from the redirect and root can
        become either, so a workload running as one is never inspected."""
        mod = _mod()
        broker = pwd.struct_passwd(("broker", "x", 201, 200, "", "/", ""))
        users = {"inspect": FAKE_INSPECT, "broker": broker}
        for uid in ("0", "200", "201"):
            with mock.patch.object(mod.os, "getuid", return_value=0), \
                    mock.patch.object(mod.os, "getpid", return_value=1), \
                    mock.patch.object(mod.pwd, "getpwnam",
                                      users.__getitem__), \
                    mock.patch.object(mod.grp, "getgrnam"), \
                    mock.patch.object(mod, "prepare_dirs") as prepare, \
                    self.assertRaises(SystemExit) as caught:
                mod.main(["customs-sidecar", "--name", "wl", "--caller-uid",
                          uid, "--host", "h=c"])
            self.assertIn(f"--caller-uid {uid}", str(caught.exception.code))
            prepare.assert_not_called()

    def test_it_refuses_to_run_under_an_init(self):
        """An init running as root without CAP_KILL cannot deliver a stop
        to this process once it has dropped root."""
        mod = _mod()
        err = io.StringIO()
        with mock.patch.object(mod.os, "getuid", return_value=0), \
                mock.patch.object(mod.os, "getpid", return_value=7), \
                mock.patch.object(mod.pwd, "getpwnam"), \
                mock.patch.object(mod.grp, "getgrnam"), \
                contextlib.redirect_stderr(err), \
                self.assertRaises(SystemExit) as caught:
            mod.main(["customs-sidecar", "--name", "wl", "--caller-uid",
                      "1000", "--host", "h=c"])
        self.assertIn("without --init", str(caught.exception.code))


if __name__ == "__main__":
    unittest.main()
