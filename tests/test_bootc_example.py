#!/usr/bin/env python3
"""The bootc example lints itself, and installs what the RPM recommends.

The lint runs inside the Containerfile, so an image that builds is an
image whose lint exited 0, but only with --fatal-warnings: without it a
warning exits 0 too. The image carries no --skip, so a new lint is never
exempted without this test changing.

The spec's Recommends are what the container shapes need on the host; an
image that dropped one, or a Recommends the image never gained, builds
green and fails at the first container.
"""

import re
import unittest
from pathlib import Path

from tests import REPO_ROOT

BOOTC = Path(REPO_ROOT) / "examples" / "bootc"
SPEC = Path(REPO_ROOT) / "rpm" / "customs.spec"

LINT_CALL = re.compile(r"bootc container lint\b(?:[^\n\\]|\\\n)*")


def _lint_calls(text):
    return [m.group(0).replace("\\\n", " ") for m in LINT_CALL.finditer(text)]


def _run_lines(text):
    """Each RUN instruction, continuations folded in."""
    return [m.group(0).replace("\\\n", " ")
            for m in re.finditer(r"^RUN\b(?:[^\n\\]|\\\n)*", text, re.M)]


class TestBootcExample(unittest.TestCase):
    def test_the_image_lints_itself_with_warnings_fatal(self):
        calls = _lint_calls((BOOTC / "Containerfile").read_text())
        self.assertEqual(len(calls), 1)
        self.assertIn("--fatal-warnings", calls[0])
        self.assertNotIn("--skip", calls[0])

    def test_the_lint_is_the_last_instruction(self):
        """A layer after the lint is a layer nothing checked."""
        lines = [line for line in
                 (BOOTC / "Containerfile").read_text().splitlines()
                 if line.strip() and not line.startswith("#")]
        self.assertIn("bootc container lint", lines[-1])

    def test_the_image_installs_every_recommends(self):
        recommends = set(re.findall(r"^Recommends:\s*(\S+)",
                                    SPEC.read_text(), re.M))
        self.assertTrue(recommends)
        install = next(r for r in _run_lines(
            (BOOTC / "Containerfile").read_text()) if "dnf" in r)
        installed = set(install.split("&&")[0].split()) - {
            "RUN", "dnf", "-y", "install"}
        installed = {w for w in installed
                     if not w.startswith(("-", "/"))}
        self.assertEqual(installed, recommends)


if __name__ == "__main__":
    unittest.main()
