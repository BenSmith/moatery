"""The Forgejo publish job builds an RPM for every Fedora Copr builds for.

The RPM installs into the site-packages of the Python it is built
against and requires that python(abi), so a Fedora with a newer Python
cannot install another Fedora's build: a hypervisor image for Fedora 45
(Python 3.15) refused the Fedora 44 build when the registry held only
that one.
"""
import re
import unittest

from tests import REPO_ROOT


def packit_versions():
    text = (REPO_ROOT / ".packit.yaml").read_text()
    return sorted(set(re.findall(r"- fedora-(\d+)-x86_64", text)))


def publish_job():
    text = (REPO_ROOT / ".forgejo/workflows/unit.yml").read_text()
    return text[text.index("\n  publish:\n"):]


class PublishMatrix(unittest.TestCase):
    def test_the_matrix_is_the_copr_targets(self):
        m = re.search(r"fedora_version: \[([^\]]*)\]", publish_job())
        self.assertIsNotNone(m)
        versions = sorted(v.strip() for v in m.group(1).split(","))
        self.assertEqual(versions, packit_versions())
        self.assertTrue(packit_versions())

    def test_each_build_is_made_on_its_fedora(self):
        self.assertIn('--build-arg FEDORA_VERSION="$FEDORA_VERSION"',
                      publish_job())
        self.assertIn("FEDORA_VERSION: ${{ matrix.fedora_version }}",
                      publish_job())

    def test_each_build_goes_to_its_fedoras_group(self):
        self.assertRegex(
            publish_job(),
            r"UPLOAD: .*/rpm/fedora-\$\{\{ matrix\.fedora_version \}\}"
            r"/upload\n")

    def test_the_image_tag_is_unique_per_run_and_entry(self):
        self.assertIn("ci-${{ github.run_id }}-${{ matrix.fedora_version }}",
                      publish_job())


if __name__ == "__main__":
    unittest.main()
