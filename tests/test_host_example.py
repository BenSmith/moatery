"""examples/README.md, the host placement's user units, held to DESIGN.md's
"Host" recipe and to the units it installs; and examples/request-filter/,
held to POLICY.md's wrapper and to the filter contract.

The README gives the recipe's container steps in full, to be run as
written; a copy that drifts from the recipe, or from the address the
responder answers with, is an example that does not work.
"""

import json
import os
import re
import subprocess
import unittest
from pathlib import Path

from moathut.units import HARDENING, LISTENER_HARDENING
from tests import REPO_ROOT

EXAMPLES = Path(REPO_ROOT) / "examples"
README = EXAMPLES / "README.md"
DESIGN = Path(REPO_ROOT) / "docs" / "DESIGN.md"
POLICY = Path(REPO_ROOT) / "docs" / "POLICY.md"


def _rules(text):
    """The nft document between `<<NFT` and `NFT`."""
    return re.search(r"<<NFT\n(.*?)\nNFT\n", text, re.S).group(1)


def _host_section():
    text = DESIGN.read_text()
    return text.split("\n## Host:", 1)[1].split("\n## ", 1)[0]


def _unit(name):
    return (EXAMPLES / "systemd" / name).read_text().splitlines()


class TestTheHostExample(unittest.TestCase):

    def test_its_rules_are_the_recipes(self):
        self.assertEqual(_rules(README.read_text()), _rules(_host_section()))

    def test_its_container_is_mapped_where_the_responder_answers(self):
        address = re.search(
            r"--address (\S+)",
            (EXAMPLES / "systemd" / "moat-resolve.service").read_text())[1]
        self.assertIn(f"--map-host-loopback={address} ", README.read_text())
        self.assertIn(f"dnat ip to {address}:8443", README.read_text())

    def test_its_container_has_a_name_and_a_command(self):
        create = re.search(r"podman create (?:[^\n\\]|\\\n)*",
                           README.read_text())[0]
        self.assertIn("--name example", create)
        self.assertTrue(create.rstrip().endswith("sleep infinity"), create)

    def test_its_inspector_is_hardened_as_a_huts_listeners(self):
        """A hut's listener lines, and no RestrictNamespaces=: a request
        filter's sandbox makes namespaces and mounts."""
        unit = _unit("moat-inspect.service")
        self.assertLessEqual(set(LISTENER_HARDENING.splitlines()), set(unit))
        self.assertEqual(
            [line for line in unit if line.startswith("RestrictNamespaces")],
            [])

    def test_its_responder_is_hardened_and_makes_no_namespace(self):
        """A hut's lines, and RestrictNamespaces=: socket activated, it
        joins no namespace, runs no podman and runs no filter."""
        lines = set(HARDENING.splitlines()) | {"RestrictNamespaces=yes"}
        self.assertLessEqual(lines, set(_unit("moat-resolve.service")))

    def test_every_unit_is_in_its_table_and_copied(self):
        text = README.read_text()
        listed = set(re.findall(r"^\| `(systemd/[^`]+)`", text, re.M))
        files = set()
        for entry in listed:
            stem = entry.removeprefix("systemd/")
            match = re.fullmatch(r"(.*)\.\{(.*)\}", stem)
            files |= ({f"{match[1]}.{s}" for s in match[2].split(",")}
                      if match else {stem})
        self.assertEqual(files,
                         {p.name for p in (EXAMPLES / "systemd").iterdir()})
        self.assertIn("cp systemd/* ~/.config/systemd/user/", text)


class TestTheRequestFilterExample(unittest.TestCase):
    """examples/request-filter/: the wrapper POLICY.md describes, and a
    filter that keeps the contract, run as the inspector runs one."""

    FILTERS = EXAMPLES / "request-filter"
    ENV = {"MOAT_ID": "5c0e81a2f4d3", "MOAT_REQ": "1",
           "MOAT_HOST": "api.example.com", "MOAT_METHOD": "POST",
           "MOAT_PATH": "/v1/messages",
           "MOAT_CONTENT_TYPE": "application/json", "MOAT_LENGTH": "0",
           "PATH": "/usr/bin:/bin"}

    def _run(self, body):
        return subprocess.run([str(self.FILTERS / "json-only")],
                              input=body, capture_output=True, cwd="/",
                              env={**self.ENV, "MOAT_LENGTH": str(len(body))},
                              start_new_session=True, timeout=30)

    def test_the_wrapper_carries_every_flag_the_policy_names(self):
        section = POLICY.read_text().split("\n### The wrapper\n", 1)[1]
        flags = set(re.findall(r"`(--[a-z-]+)", section.split("\n## ")[0]))
        self.assertGreaterEqual(len(flags), 6, flags)
        wrapper = (self.FILTERS / "sandboxed").read_text()
        for flag in flags:
            with self.subTest(flag=flag):
                self.assertIn(f" {flag} ", wrapper)

    def test_the_wrapper_runs_its_filter_alone_and_read_only(self):
        wrapper = (self.FILTERS / "sandboxed").read_text()
        self.assertIn('--ro-bind "$FILTER" "$FILTER"', wrapper)
        self.assertTrue(wrapper.rstrip().endswith('-- "$FILTER"'), wrapper)
        self.assertNotRegex(wrapper, r"--(?:dev-)?bind |\$HOME|/home|/run")

    def test_the_scripts_are_executable(self):
        for name in ("sandboxed", "json-only"):
            with self.subTest(name=name):
                self.assertTrue(os.access(self.FILTERS / name, os.X_OK))

    def test_the_filter_sends_json_unchanged(self):
        body = b'{"model": "x", "messages": []}\n'
        done = self._run(body)
        self.assertEqual((done.returncode, done.stdout), (0, body))

    def test_the_filter_refuses_what_is_not_json_and_names_why(self):
        for body in (b"not json", b"\xff\xfe{", b"[" * 100000):
            with self.subTest(body=body[:8]):
                done = self._run(body)
                self.assertEqual(done.returncode, 77)
                self.assertEqual(done.stdout, b"")
                self.assertEqual(done.stderr.splitlines()[0], b"not-json")

    def test_the_document_names_the_wrapper(self):
        doc = json.loads((self.FILTERS / "request-filters.json").read_text())
        self.assertEqual(list(doc), ["filters"])
        runs = {entry["run"] for entry in doc["filters"]}
        self.assertEqual({Path(run).name for run in runs}, {"sandboxed"})


if __name__ == "__main__":
    unittest.main()
