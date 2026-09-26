#!/usr/bin/env python3
"""The quadlet example's units name each other, and load shape 1n's rules.

Five files and a script, joined only by names: a unit that names one no
file provides is a dependency systemd drops without a word, and a pod
name the script is not given is a namespace nothing binds into. The
rules are the ones DESIGN.md gives for shape 1n; a copy that drifted
from them would redirect what the design does not, or fail to.
"""

import re
import unittest
from pathlib import Path

from tests import REPO_ROOT

EXAMPLES = Path(REPO_ROOT) / "examples"
QUADLET = EXAMPLES / "quadlet"
DESIGN = Path(REPO_ROOT) / "docs" / "DESIGN.md"
LISTENERS = ("customs-inspect-example.service",
             "customs-resolve-example.service")
DEPENDENCIES = ("Wants", "Requires", "After", "BindsTo")


def _keys(path, key):
    """Every value of `key`, continuations folded in, split on spaces."""
    text = path.read_text().replace("\\\n", " ")
    return [word for value in re.findall(rf"^{key}=(.*)$", text, re.M)
            for word in value.split()]


def _provided():
    """Unit name → file, with quadlet's generated names."""
    units = {p.name: p for p in QUADLET.glob("*.service")}
    units["customs-broker.service"] = (
        EXAMPLES / "systemd" / "customs-broker.service")
    for p in QUADLET.glob("*.container"):
        units[f"{p.stem}.service"] = p
    for p in QUADLET.glob("*.pod"):
        units[f"{p.stem}-pod.service"] = p
    return units


def _ruleset(text):
    body = re.search(r"^table inet customs \{.*?^\}\n^table netdev "
                     r"customs \{.*?^\}", text, re.S | re.M).group(0)
    return re.sub(r'"\$\w+"', '"$DEV"', body)


class TestQuadletExample(unittest.TestCase):
    def test_every_unit_named_is_provided(self):
        units = _provided()
        for path in set(units.values()):
            for key in DEPENDENCIES:
                for name in _keys(path, key):
                    with self.subTest(file=path.name, key=key, unit=name):
                        self.assertIn(name, units)

    def test_the_pod_starts_the_listeners_and_the_workload_needs_them(self):
        pod = QUADLET / "example.pod"
        work = QUADLET / "example.container"
        for name in LISTENERS:
            with self.subTest(unit=name):
                self.assertIn(name, _keys(pod, "Wants"))
                self.assertIn(name, _keys(work, "Requires"))
                self.assertIn(name, _keys(work, "After"))

    def test_the_listeners_are_bound_to_the_pod_and_notify(self):
        """As Type=simple a unit is started when forked, and the
        workload's first dial can find nothing bound."""
        for name in LISTENERS:
            unit = QUADLET / name
            with self.subTest(unit=name):
                self.assertEqual(_keys(unit, "BindsTo"),
                                 ["example-pod.service"])
                self.assertIn("example-pod.service", _keys(unit, "After"))
                self.assertEqual(_keys(unit, "Type"), ["notify"])

    def test_the_script_is_given_the_pod_name(self):
        pod = QUADLET / "example.pod"
        (name,) = _keys(pod, "PodName")
        self.assertEqual(_keys(pod, "ExecStartPost")[-2:], ["rules", name])
        work = QUADLET / "example.container"
        self.assertEqual(_keys(work, "Pod"), ["example.pod"])
        for unit in LISTENERS:
            text = (QUADLET / unit).read_text()
            with self.subTest(unit=unit):
                self.assertIn(f"customs-pod-netns pid {name})", text)
        inspect = (QUADLET / LISTENERS[0]).read_text()
        self.assertIn('--netns-pid "$$pid"', inspect)

    def test_the_rules_are_shape_1n(self):
        design = DESIGN.read_text().split(
            "## Shape 1n", 1)[1].split("\n## ", 1)[0]
        script = (QUADLET / "customs-pod-netns").read_text()
        self.assertEqual(_ruleset(script), _ruleset(design))


if __name__ == "__main__":
    unittest.main()
