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
import shutil
import subprocess
import tempfile
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


class TestTheLoggedExample(unittest.TestCase):
    """examples/request-filter/logged and excerpt: sandboxed's sandbox
    with one writable directory, and a filter that logs a bounded line
    for each body and sends it unchanged."""

    FILTERS = EXAMPLES / "request-filter"
    ENV = TestTheRequestFilterExample.ENV

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _start(self, body, **env):
        proc = subprocess.Popen(
            [str(self.FILTERS / "excerpt")], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir,
            env={**self.ENV, "MOAT_LENGTH": str(len(body)), **env},
            start_new_session=True)
        return proc, body

    def _run(self, body, **env):
        proc, body = self._start(body, **env)
        out, _ = proc.communicate(body, timeout=30)
        return proc.returncode, out

    def _lines(self, name="excerpts"):
        return [json.loads(ln)
                for ln in (self.dir / name).read_text().splitlines()]

    def test_the_wrapper_is_sandboxed_with_one_writable_directory(self):
        def lines(name):
            return [ln for ln in (self.FILTERS / name).read_text()
                    .splitlines() if not ln.startswith(("#", "FILTER="))]
        logged = lines("logged")
        bind = '    --bind "$LOG" /log --chdir /log \\'
        self.assertIn("LOG=HOME/.local/state/request-filter", logged)
        self.assertIn(bind, logged)
        self.assertEqual(
            [ln for ln in logged if not ln.startswith("LOG=") and ln != bind],
            lines("sandboxed"))
        self.assertIn("FILTER=${0%/*}/excerpt",
                      (self.FILTERS / "logged").read_text())

    def test_its_document_names_its_wrapper(self):
        doc = json.loads(
            (self.FILTERS / "request-filters-logged.json").read_text())
        self.assertEqual(list(doc), ["filters"])
        self.assertEqual({entry["run"] for entry in doc["filters"]},
                         {"HOME/.local/libexec/request-filter/logged"})

    def test_the_readme_installs_every_file_and_the_log_directory(self):
        text = README.read_text()
        for path in self.FILTERS.iterdir():
            with self.subTest(name=path.name):
                self.assertIn(f"request-filter/{path.name}", text)
        log = re.search(r"(?m)^LOG=HOME(/\S+)$",
                        (self.FILTERS / "logged").read_text()).group(1)
        self.assertIn(f"mkdir -p ~/.local/libexec/request-filter ~{log}\n",
                      text)

    def test_the_scripts_are_executable(self):
        for name in ("logged", "excerpt"):
            with self.subTest(name=name):
                self.assertTrue(os.access(self.FILTERS / name, os.X_OK))

    def test_the_body_is_sent_unchanged_and_logged(self):
        body = b'{"model": "x", "messages": []}\n'
        self.assertEqual(self._run(body), (0, body))
        [line] = self._lines()
        self.assertEqual(
            {k: line[k] for k in ("id", "req", "host", "method", "path",
                                  "content_type", "length", "head")},
            {"id": "5c0e81a2f4d3", "req": "1", "host": "api.example.com",
             "method": "POST", "path": "/v1/messages",
             "content_type": "application/json", "length": len(body),
             "head": body.decode()})
        self.assertRegex(line["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual((self.dir / "excerpts").stat().st_mode & 0o777,
                         0o600)

    def test_the_workloads_bytes_are_bounded_and_stay_on_one_line(self):
        body = b"a\nb\r\x00\xff\xe2\x80\xa8" + b"x" * 4096
        path = "/p\n" + "y" * 4096
        self.assertEqual(self._run(body, MOAT_PATH=path), (0, body))
        text = (self.dir / "excerpts").read_bytes()
        self.assertEqual(text.count(b"\n"), 1)
        self.assertTrue(text.isascii())
        [line] = self._lines()
        self.assertEqual(line["head"], body[:256].decode(
            "utf-8", "backslashreplace"))
        self.assertEqual(line["path"], path[:512])
        self.assertEqual(line["length"], len(body))

    def test_eight_at_once_each_write_a_whole_line(self):
        procs = [self._start(f"body {i} ".encode() * 2000,
                             MOAT_REQ=str(i)) for i in range(8)]
        for proc, body in procs:
            out, _ = proc.communicate(body, timeout=30)
            self.assertEqual((proc.returncode, out), (0, body))
        self.assertEqual(sorted(int(ln["req"]) for ln in self._lines()),
                         list(range(8)))

    def test_a_full_log_is_moved_aside_once(self):
        with open(self.dir / "excerpts", "wb") as f:
            f.truncate(16 << 20)
        self.assertEqual(self._run(b"one"), (0, b"one"))
        self.assertEqual(self._run(b"two"), (0, b"two"))
        self.assertEqual((self.dir / "excerpts.1").stat().st_size, 16 << 20)
        self.assertEqual([ln["head"] for ln in self._lines()],
                         ["one", "two"])

    @unittest.skipIf(os.geteuid() == 0, "root writes a read-only directory")
    def test_a_line_it_cannot_write_fails_the_request(self):
        self.dir.chmod(0o555)
        self.addCleanup(self.dir.chmod, 0o755)
        code, out = self._run(b"secret")
        self.assertNotIn(code, (0, 77))
        self.assertEqual(out, b"")


if __name__ == "__main__":
    unittest.main()
