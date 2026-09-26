#!/usr/bin/env python3
"""What docs/INTERFACE.md publishes is what the code provides.

Two lists: the names workloadctl imports, each defined in its module, and
the status file's paths, each present in a file the inspector wrote. A
name or a key renamed without the list following would pass every other
test and break workloadctl at the switch: an import error for a name, a
figure that silently reads zero for a key.
"""

import importlib
import io
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from customs.egress_mint import mint_ca
from customs.inspect_document import VmPolicyEntry
from customs.inspect_listener import Listener, build_minter
from customs.inspect_policy import Policy
from tests import REPO_ROOT

INTERFACE = Path(REPO_ROOT) / "docs" / "INTERFACE.md"


def _block(heading):
    """The lines of the first fenced block under `heading`."""
    section = INTERFACE.read_text().split(f"## {heading}\n", 1)[1]
    return re.search(r"```\n(.*?)```", section, re.S).group(1).splitlines()


def published():
    """{module: [names]} from the block under "Imported names"."""
    names, module = {}, None
    for line in _block("Imported names"):
        words = line.split()
        if not words:
            continue
        if not line[0].isspace():
            module, words = words[0], words[1:]
        names.setdefault(module, []).extend(words)
    return names


def status_paths():
    """Each path, as a tuple of keys, from the status file's block."""
    return [tuple(line.split()[0].split("."))
            for line in _block("The inspector's status file")
            if line.strip()]


class TestPublishedInterface(unittest.TestCase):

    def test_the_list_is_read(self):
        """A parser that found nothing would pass the check below."""
        names = published()
        self.assertIn("customs.egress_ca", names)
        self.assertIn("patterns_overlap", names["customs.inspect_document"])
        self.assertGreater(sum(map(len, names.values())), 40)

    def test_every_published_name_is_defined(self):
        for module, names in published().items():
            mod = importlib.import_module(module)
            for name in names:
                with self.subTest(module=module, name=name):
                    self.assertTrue(hasattr(mod, name),
                                    f"{module}.{name} is published and "
                                    f"not defined")


class TestPublishedStatusPaths(unittest.TestCase):
    """The file a terminating inspector writes, read back as JSON, has
    every published path: the counters' own keys and the two the listener
    adds (the digest and the minter's)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def _written(self):
        state = self.tmp / "state"
        mint_ca("demo", state)
        policy = Policy(tls="inspect", hosts=("pypi.org",), policy=(
            VmPolicyEntry("api.example.com", ("POST",), ("/v1/messages",),
                          credential="example"),))
        status = self.tmp / "status.json"
        listener = Listener([], io.StringIO(), policy=policy,
                            status_path=str(status),
                            minter=build_minter("demo", state, policy))
        listener.write_status()
        return json.loads(status.read_text())

    def test_the_list_is_read(self):
        paths = status_paths()
        self.assertIn(("ech", "alarm"), paths)
        self.assertIn(("mint", "denials"), paths)
        self.assertGreater(len(paths), 25)

    def test_every_published_path_is_in_the_file(self):
        doc = self._written()
        for path in status_paths():
            with self.subTest(path=".".join(path)):
                cur = doc
                for key in path:
                    self.assertIsInstance(cur, dict)
                    self.assertIn(key, cur)
                    cur = cur[key]


if __name__ == "__main__":
    unittest.main()
