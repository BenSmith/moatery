"""examples/README.md, the host placement's user units, held to DESIGN.md's
"Host" recipe and to the units it installs.

The README gives the recipe's container steps in full, to be run as
written; a copy that drifts from the recipe, or from the address the
responder answers with, is an example that does not work.
"""

import re
import unittest
from pathlib import Path

from tests import REPO_ROOT

EXAMPLES = Path(REPO_ROOT) / "examples"
README = EXAMPLES / "README.md"
DESIGN = Path(REPO_ROOT) / "docs" / "DESIGN.md"


def _rules(text):
    """The nft document between `<<NFT` and `NFT`."""
    return re.search(r"<<NFT\n(.*?)\nNFT\n", text, re.S).group(1)


def _host_section():
    text = DESIGN.read_text()
    return text.split("\n## Host:", 1)[1].split("\n## ", 1)[0]


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


if __name__ == "__main__":
    unittest.main()
