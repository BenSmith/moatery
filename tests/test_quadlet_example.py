#!/usr/bin/env python3
"""The quadlet example's units name each other, and load the netns rules.

Five files and a script, joined only by names: a unit that names one no
file provides is a dependency systemd drops without a word, and a pod
name the script is not given is a namespace nothing binds into. The
rules are the ones DESIGN.md gives for the netns placement; a copy that
drifted from them would redirect what the design does not, or fail to.
"""

import re
import unittest
from pathlib import Path

from moathut.units import ANSWER
from tests import REPO_ROOT

EXAMPLES = Path(REPO_ROOT) / "examples"
QUADLET = EXAMPLES / "quadlet"
DESIGN = Path(REPO_ROOT) / "docs" / "DESIGN.md"
LISTENERS = ("moat-inspect-example.service",
             "moat-resolve-example.service")
DEPENDENCIES = ("Wants", "Requires", "After", "BindsTo")


def _keys(path, key):
    """Every value of `key`, continuations folded in, split on spaces."""
    text = path.read_text().replace("\\\n", " ")
    return [word for value in re.findall(rf"^{key}=(.*)$", text, re.M)
            for word in value.split()]


def _provided():
    """Unit name → file, with quadlet's generated names."""
    units = {p.name: p for p in QUADLET.glob("*.service")}
    units["moat-broker.service"] = (
        EXAMPLES / "systemd" / "moat-broker.service")
    for p in QUADLET.glob("*.container"):
        units[f"{p.stem}.service"] = p
    for p in QUADLET.glob("*.pod"):
        units[f"{p.stem}-pod.service"] = p
    return units


def _ruleset(text):
    body = re.search(r"^table inet moatery \{.*?^\}\n^table netdev "
                     r"moatery \{.*?^\}", text, re.S | re.M).group(0)
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

    def test_the_pod_keeps_the_hosts_file_of_the_image(self):
        """podman seeds a pod's hosts file from the host's otherwise, and
        a name in it never reaches the responder."""
        self.assertIn("--hosts-file=image",
                      _keys(QUADLET / "example.pod", "PodmanArgs"))

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

    def test_the_broker_notifies(self):
        """The inspector is After= it, and a brokered request in its first
        moment finds the socket."""
        broker = EXAMPLES / "systemd" / "moat-broker.service"
        self.assertEqual(_keys(broker, "Type"), ["notify"])

    def test_the_script_is_given_the_pod_name(self):
        pod = QUADLET / "example.pod"
        (name,) = _keys(pod, "PodName")
        self.assertEqual(_keys(pod, "ExecStartPost")[-2:], ["rules", name])
        work = QUADLET / "example.container"
        self.assertEqual(_keys(work, "Pod"), ["example.pod"])
        for unit in LISTENERS:
            text = (QUADLET / unit).read_text()
            with self.subTest(unit=unit):
                self.assertIn(f"moat-pod-netns pid {name})", text)
        inspect = (QUADLET / LISTENERS[0]).read_text()
        self.assertIn('--netns-pid "$$pid"', inspect)

    def test_the_pod_has_no_cgroup_of_its_own(self):
        """With a pod cgroup, a container's start asks systemd for the
        pod's slice whenever podman misses its directory, and fails
        against a slice systemd already has."""
        pod = QUADLET / "example.pod"
        self.assertIn("--share-parent=false", _keys(pod, "PodmanArgs"))

    def test_the_responder_answers_as_moathut_does(self):
        """One address for the netns placement wherever it is written
        down: the example, the recipe and moathut. A copy left on the
        loopback works for a container and fails a VM's guest, which
        dials its own."""
        design = DESIGN.read_text().split(
            "## Netns:", 1)[1].split("\n## ", 1)[0]
        resolve = QUADLET / LISTENERS[1]
        for where, text in (("example", resolve.read_text()),
                            ("DESIGN.md", design)):
            with self.subTest(where=where):
                self.assertEqual(
                    re.findall(r"--address (\S+)", text), [ANSWER])

    def test_the_rules_are_the_netns_placements(self):
        design = DESIGN.read_text().split(
            "## Netns:", 1)[1].split("\n## ", 1)[0]
        script = (QUADLET / "moat-pod-netns").read_text()
        self.assertEqual(_ruleset(script), _ruleset(design))


if __name__ == "__main__":
    unittest.main()
