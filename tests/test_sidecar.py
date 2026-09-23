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
import pwd
import unittest
from pathlib import Path
from unittest import mock

from egress_plane import CLEARTEXT, TLS
from tests import REPO_ROOT, load_script

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
        import broker_profiles
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

    def test_the_planes_are_the_inspectors(self):
        """The bind is here and the recognition is the inspector's: a port
        bound that plane_for_port does not know is a listener that rejects
        every connection as 'not an inspect port'."""
        mod = _mod()
        self.assertEqual(set(mod.PLANES),
                         {TLS.inspect_port, CLEARTEXT.inspect_port})


class TestTheSidecarMintsTheOneWay(unittest.TestCase):
    """The sidecar's first-start mint is egress_mint.mint_ca, the call
    customs-mint-ca makes on a host, and the chown to the inspector's uid
    is the only part that is the sidecar's own."""

    GROUP = mock.Mock(gr_gid=200)

    def _mint(self, minted):
        mod = _mod()
        with mock.patch.object(mod.egress_mint, "mint_ca",
                               return_value=minted) as mint, \
                mock.patch.object(mod.os, "chown") as chown:
            result = mod.mint_ca("wl", FAKE_INSPECT, self.GROUP)
        mint.assert_called_once_with("wl", mod.STATE)
        return mod, result, chown

    def test_a_fresh_ca_is_handed_to_the_inspector(self):
        mod, result, chown = self._mint(True)
        self.assertTrue(result)
        key, cert = mod.ca_key_path(mod.STATE), mod.ca_cert_path(mod.STATE)
        self.assertEqual([c.args for c in chown.call_args_list],
                         [(key.parent, 200, 200), (key, 200, 200),
                          (cert, 200, 200)])

    def test_a_kept_ca_is_not_touched(self):
        _mod_, result, chown = self._mint(False)
        self.assertFalse(result)
        chown.assert_not_called()

    def test_no_second_mint_lives_in_the_entrypoint(self):
        """Its own openssl argv would be a second mint for the three
        extensions to drift between."""
        source = (Path(REPO_ROOT) / "container" / "customs-sidecar").read_text()
        self.assertNotIn("ca_openssl_argv", source)


if __name__ == "__main__":
    unittest.main()
