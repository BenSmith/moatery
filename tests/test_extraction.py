#!/usr/bin/env python3
"""Every name docs/EXTRACTION.md publishes is defined where it says.

The list is the interface workloadctl imports once it requires customs.
A name removed or renamed here without the list following would pass
every other test and break workloadctl's imports at the switch.
"""

import importlib
import re
import unittest
from pathlib import Path

from tests import REPO_ROOT

EXTRACTION = Path(REPO_ROOT) / "docs" / "EXTRACTION.md"


def published():
    """{module: [names]} from the fenced block under "## The interface"."""
    text = EXTRACTION.read_text()
    section = text.split("## The interface", 1)[1]
    block = re.search(r"```\n(.*?)```", section, re.S).group(1)
    names, module = {}, None
    for line in block.splitlines():
        words = line.split()
        if not words:
            continue
        if not line[0].isspace():
            module, words = words[0], words[1:]
        names.setdefault(module, []).extend(words)
    return names


class TestPublishedInterface(unittest.TestCase):

    def test_the_list_is_read(self):
        """A parser that found nothing would pass the check below."""
        names = published()
        self.assertIn("egress_ca", names)
        self.assertIn("patterns_overlap", names["inspect_document"])
        self.assertGreater(sum(map(len, names.values())), 40)

    def test_every_published_name_is_defined(self):
        for module, names in published().items():
            mod = importlib.import_module(module)
            for name in names:
                with self.subTest(module=module, name=name):
                    self.assertTrue(hasattr(mod, name),
                                    f"{module}.{name} is published and "
                                    f"not defined")


if __name__ == "__main__":
    unittest.main()
