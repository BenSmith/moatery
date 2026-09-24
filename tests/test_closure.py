#!/usr/bin/env python3
"""lib/ is exactly the programs' import closures, and nothing in it knows
what a workload is.

There is no other side here to hold a line against: every module in lib/
must be reachable from customs-broker, customs-inspect,
customs-resolve or customs-netns-listen, and no closure may reach anything
but lib/ and the standard library. The
workload-side property survives as absences -- no TOML reader, no passwd
lookup, no address or path derivation -- because a copy of one of those
functions would not show up as an import.

The flags each entrypoint takes are pinned too. They are the interface a
unit file or a container entrypoint writes against; a flag appearing or
disappearing here is a change to that contract. The one change so far is
the inspector's `--caller-uid`, mirroring the broker's: a sidecar's
workload is another uid by design, and an inspector that served only its
own uid refused every connection there as foreign. The second is its
`--netns-pid`: listeners bound in a container's namespace have their
callers in that namespace's socket table.
"""

import ast
import sys
import unittest
from pathlib import Path

from tests import REPO_ROOT

LIB = Path(REPO_ROOT) / "lib"
BROKER = Path(REPO_ROOT) / "libexec" / "customs-broker"
INSPECTOR = Path(REPO_ROOT) / "libexec" / "customs-inspect"
MINT_CA = Path(REPO_ROOT) / "libexec" / "customs-mint-ca"
NETNS_LISTEN = Path(REPO_ROOT) / "libexec" / "customs-netns-listen"
RESOLVER = Path(REPO_ROOT) / "libexec" / "customs-resolve"
SIDECAR = Path(REPO_ROOT) / "container" / "customs-sidecar"

BROKER_FLAGS = frozenset({
    "--name", "--listen", "--caller-uid", "--host",
    "--placeholder", "--auth-header", "--auth-format",
})
INSPECTOR_FLAGS = frozenset({
    "--name", "--policy", "--state-dir", "--status", "--record", "--broker",
    "--caller-uid", "--netns-pid",
})
RESOLVER_FLAGS = frozenset({
    "--name", "--address", "--address6", "--policy", "--status",
})

# Functions whose presence would mean a program derives a value it is meant
# to be handed. Asserted by absence of the call, not the import, so that a
# copied body is caught as well as an imported one.
DERIVATIONS = (
    "broker_listen_address", "broker_credential", "workload_name",
    "getpwuid", "getpwnam", "load_workload_config", "broker_config_path",
    "inspect_policy_path", "inspect_status_path", "inspect_record_path",
    "workload_state_dir",
)


def _lib_modules():
    return {p.stem: p for p in LIB.glob("*.py")}


def _imports(path):
    """(lib modules, other top-level modules) a file imports, at any depth
    of nesting. Nested imports count: a deferred import resolves at call
    time and is invisible to a fresh-interpreter import test."""
    tree = ast.parse(path.read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
    return found


def _closure(entrypoint, mods):
    seen = set()
    todo = list(_imports(entrypoint) & set(mods))
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo.extend(_imports(mods[name]) & set(mods))
    return seen


def _foreign(files, mods):
    """Imports that are neither lib/ nor the standard library."""
    stdlib = set(sys.stdlib_module_names)
    out = set()
    for f in files:
        out |= _imports(f) - set(mods) - stdlib
    return out


class TestTheScannerSeesTheTree(unittest.TestCase):
    """Guards the guard: every assertion below is about what the walk FOUND."""

    def test_the_entrypoints_exist(self):
        self.assertTrue(BROKER.exists())
        self.assertTrue(INSPECTOR.exists())
        self.assertTrue(MINT_CA.exists())
        self.assertTrue(NETNS_LISTEN.exists())
        self.assertTrue(RESOLVER.exists())

    def test_the_closures_are_not_trivial(self):
        mods = _lib_modules()
        self.assertGreaterEqual(len(_closure(BROKER, mods)), 4)
        self.assertGreaterEqual(len(_closure(INSPECTOR, mods)), 20)

    def test_the_walk_sees_a_nested_import(self):
        src = "def f():\n    import egress_ca\n"
        path = Path(self.enterContext(
            __import__("tempfile").TemporaryDirectory())) / "m.py"
        path.write_text(src)
        self.assertIn("egress_ca", _imports(path))


class TestLibIsTheClosure(unittest.TestCase):

    def test_every_module_is_reachable_from_an_entrypoint(self):
        """A module nothing imports is either dead or a program with no
        entrypoint; both are wrong here."""
        mods = _lib_modules()
        reachable = (_closure(BROKER, mods) | _closure(INSPECTOR, mods)
                     | _closure(RESOLVER, mods) | _closure(NETNS_LISTEN, mods))
        self.assertEqual(sorted(set(mods) - reachable), [])

    def test_the_closures_reach_only_lib_and_the_stdlib(self):
        mods = _lib_modules()
        files = ([BROKER, INSPECTOR, MINT_CA, NETNS_LISTEN, RESOLVER]
                 + [mods[m] for m in mods])
        self.assertEqual(sorted(_foreign(files, mods)), [])

    def test_the_ca_minter_is_inside_the_inspector_closure(self):
        """customs-mint-ca is the inspector's first-start step run on its
        own, and brings no module of its own into lib/."""
        mods = _lib_modules()
        minter = _closure(MINT_CA, mods)
        self.assertIn("egress_mint", minter)
        self.assertEqual(sorted(minter - _closure(INSPECTOR, mods)), [])

    def test_the_launcher_reaches_only_the_planes(self):
        """customs-netns-listen binds and execs. The port numbers are the
        one thing it shares with the inspector, and nothing that parses a
        byte a workload sent is in it."""
        mods = _lib_modules()
        self.assertEqual(sorted(_closure(NETNS_LISTEN, mods)),
                         ["egress_plane", "netns_listen"])

    def test_the_resolver_reaches_no_dialling_module(self):
        """customs-resolve answers from memory. Its closure is its own three
        modules, the policy reader it counts names against, and the status
        writer; nothing that opens a connection is in it."""
        mods = _lib_modules()
        self.assertEqual(
            sorted(_closure(RESOLVER, mods)),
            ["dns_wire", "egress_status", "inspect_document",
             "inspect_policy", "resolve_policy", "resolve_server",
             "sd_listen"])

    def test_the_broker_closure_is_the_four_broker_modules(self):
        mods = _lib_modules()
        self.assertEqual(
            sorted(_closure(BROKER, mods)),
            ["broker_profiles", "broker_request", "broker_server",
             "peer_identity"])

    def test_the_inspector_closure_does_not_reach_the_broker(self):
        """The inspector dials the broker; it never imports it. The one
        shared module is the caller-identity check."""
        mods = _lib_modules()
        shared = _closure(INSPECTOR, mods) & _closure(BROKER, mods)
        self.assertEqual(sorted(shared), ["peer_identity"])


class TestNothingKnowsWhatAWorkloadIs(unittest.TestCase):

    def _sources(self):
        mods = _lib_modules()
        return {**{m: mods[m].read_text() for m in mods},
                BROKER.name: BROKER.read_text(),
                INSPECTOR.name: INSPECTOR.read_text(),
                MINT_CA.name: MINT_CA.read_text(),
                NETNS_LISTEN.name: NETNS_LISTEN.read_text(),
                RESOLVER.name: RESOLVER.read_text()}

    def test_nothing_reads_toml(self):
        mods = _lib_modules()
        files = ([BROKER, INSPECTOR, MINT_CA, NETNS_LISTEN, RESOLVER]
                 + list(mods.values()))
        readers = sorted(f.name for f in files if "tomllib" in _imports(f))
        self.assertEqual(readers, [])

    def test_nothing_looks_a_user_up(self):
        """peer_identity compares a uid to a uid. A pwd import is a name
        lookup coming back, and the workload user prefix in the broker's
        closure is its twin (the inspector's closure mentions the prefix
        in prose about the host it came from)."""
        mods = _lib_modules()
        files = ([BROKER, INSPECTOR, MINT_CA, NETNS_LISTEN, RESOLVER]
                 + list(mods.values()))
        lookups = sorted(f.name for f in files if "pwd" in _imports(f))
        self.assertEqual(lookups, [])
        broker = _closure(BROKER, mods)
        sources = {m: mods[m].read_text() for m in broker}
        sources[BROKER.name] = BROKER.read_text()
        holders = sorted(n for n, t in sources.items() if "_wl-" in t)
        self.assertEqual(holders, [], holders)

    def test_nothing_derives_a_handed_value(self):
        for name in DERIVATIONS:
            holders = sorted(n for n, t in self._sources().items()
                             if f"{name}(" in t)
            self.assertEqual(holders, [], f"{name} called in {holders}")


class TestTheFlagsAreTheContract(unittest.TestCase):

    def _flags(self, path):
        tree = ast.parse(path.read_text())
        found = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_argument"
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and str(node.args[0].value).startswith("--")):
                found.add(node.args[0].value)
        return found

    def test_the_broker_takes_the_handed_flags(self):
        self.assertTrue(BROKER_FLAGS <= self._flags(BROKER),
                        sorted(BROKER_FLAGS - self._flags(BROKER)))

    def test_the_inspector_takes_exactly_the_handed_flags(self):
        self.assertEqual(self._flags(INSPECTOR), INSPECTOR_FLAGS)

    def test_the_resolver_takes_exactly_the_handed_flags(self):
        self.assertEqual(self._flags(RESOLVER), RESOLVER_FLAGS)

    def test_the_ca_minter_takes_two_of_the_inspectors(self):
        """The same --name and --state-dir the inspector's unit is given,
        so the CA lands where the inspector looks and carries its label."""
        self.assertEqual(self._flags(MINT_CA), {"--name", "--state-dir"})
        self.assertTrue(self._flags(MINT_CA) <= INSPECTOR_FLAGS)

    def test_the_launcher_takes_the_pid_and_which_listeners(self):
        """The pid is the one fact it needs and --resolver which program's
        ports; everything after `--` is the program's."""
        self.assertEqual(self._flags(NETNS_LISTEN), {"--pid", "--resolver"})


class TestNoProgramWritesBytecode(unittest.TestCase):
    """Every program turns bytecode off before its first lib import. The
    install directory is not the process's to write, and under a
    confining policy every start would log the attempt. The broker had
    no such line while the inspector did."""

    @staticmethod
    def _first_lib_import(tree):
        mods = set(_lib_modules())
        for i, node in enumerate(tree.body):
            if isinstance(node, ast.ImportFrom) and node.module in mods:
                return i
            if isinstance(node, ast.Import) and any(
                    a.name in mods for a in node.names):
                return i
        return None

    @staticmethod
    def _bytecode_off(tree):
        for i, node in enumerate(tree.body):
            if (isinstance(node, ast.Assign)
                    and ast.unparse(node) == "sys.dont_write_bytecode = True"):
                return i
        return None

    def test_every_program_turns_bytecode_off_first(self):
        for path in (BROKER, INSPECTOR, MINT_CA, NETNS_LISTEN, RESOLVER,
                     SIDECAR):
            with self.subTest(program=path.name):
                tree = ast.parse(path.read_text())
                first = self._first_lib_import(tree)
                self.assertIsNotNone(first)
                off = self._bytecode_off(tree)
                self.assertIsNotNone(off, "never turns bytecode off")
                self.assertLess(off, first)


if __name__ == "__main__":
    unittest.main()
