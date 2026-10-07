"""The rigs load rules of their own, and DESIGN.md is what they prove.

Each placement's rig holds its ruleset as text, so a rig could load one
that drifted from the documented one and pass on it. Here each rig's
`ruleset`, every control left in, is held to its placement's in
docs/DESIGN.md.
"""

import importlib
import re
import sys
import unittest

from tests import REPO_ROOT
from tests.test_quadlet_example import _ruleset

MANUAL = REPO_ROOT / "tests" / "manual"
DESIGN = REPO_ROOT / "docs" / "DESIGN.md"


def _rig(name):
    if str(MANUAL) not in sys.path:
        sys.path.insert(0, str(MANUAL))
    return importlib.import_module(name)


def _section(title):
    text = DESIGN.read_text()
    return text.split(f"\n## {title}:", 1)[1].split("\n## ", 1)[0]


def _addresses(text):
    return {a.strip(" {}") for block in re.findall(r"\{([^}]*)\}", text)
            for a in block.replace("\n", " ").split(",") if a.strip()}


class TestTheRigsLoadTheDocumentedRules(unittest.TestCase):

    def test_host(self):
        self.assertEqual(_ruleset(_rig("host_rig").ruleset("$DEV")),
                         _ruleset(_section("Host")))

    def test_vm_is_the_host_placements(self):
        self.assertEqual(_ruleset(_rig("vm_rig").ruleset("$DEV")),
                         _ruleset(_section("Host")))

    def test_netns(self):
        self.assertEqual(_ruleset(_rig("netns_rig").ruleset("$DEV")),
                         _ruleset(_section("Netns")))

    def test_sidecar(self):
        self.assertEqual(
            _ruleset(_rig("sidecar_rig").ruleset("$DEV", "169.254.1.1")),
            _ruleset(_section("Sidecar")))

    def test_the_sidecars_private_drop_is_the_documented_one(self):
        rig = _rig("sidecar_rig")
        documented = DESIGN.read_text().split(
            "\n## Private addresses", 1)[1].split("\n## ", 1)[0]
        drop = next(block for block in documented.split("```")[1::2]
                    if " drop" in block)
        self.assertEqual(
            _addresses(f"{{ {rig.PRIVATE_V4} }} {{ {rig.PRIVATE_V6} }}"),
            _addresses(drop))

    def test_a_control_left_out_changes_the_rules(self):
        """The comparison sees the lines the flags take out."""
        for name, off in (("host_rig", {"neighbour": False}),
                          ("host_rig", {"redirect_dns": False}),
                          ("netns_rig", {"redirect_dns": False})):
            with self.subTest(rig=name, **off):
                rig = _rig(name)
                self.assertNotEqual(_ruleset(rig.ruleset("$DEV", **off)),
                                    _ruleset(rig.ruleset("$DEV")))


if __name__ == "__main__":
    unittest.main()
