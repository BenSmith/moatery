"""The Copilot recipe: the host token reaches only moathut's stdin,
the policy refuses what would act as the user, and the install is pinned."""

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from moatery.inspect_policy import load_policy
from moathut.credentials import Credential, brokering
from tests import REPO_ROOT, load_script, script_env


SCRIPT = REPO_ROOT / "examples/copilot/copilot_hut.py"
TOKEN = "gho_" + "hostonlytestcredential" * 2
FAKE = "gho_" + "a" * 32


class TestCopilotRecipe(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.recipe = load_script("examples/copilot/copilot_hut.py")

    def config(self, **over):
        data = {
            "lastLoggedInUser": {
                "host": "https://github.com", "login": "active"},
            "authTokens": {
                "https://github.com:active:github": {"token": TOKEN},
                "https://github.com:active": {"token": "gho_" + "old" * 12},
                "https://github.com:other:github": {
                    "token": "gho_" + "other" * 8}},
        }
        data.update(over)
        path = self.root / "config.json"
        path.write_text("// Copilot state\n" + json.dumps(data))
        return path

    def test_enrollment_executes_the_host_sealer_with_only_stdin_secret(self):
        self.config()
        receiver = self.root / "moathut"
        received = self.root / "received.json"
        receiver.write_text(
            "#!" + sys.executable + "\n"
            "import json, sys\n"
            f"with open({str(received)!r}, 'w') as stream:\n"
            "    json.dump([sys.argv[1:], sys.stdin.read()], stream)\n")
        receiver.chmod(0o700)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--copilot-home", str(self.root),
             "--moathut", str(receiver), "enroll"],
            env=script_env(), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        argv, secret = json.loads(received.read_text())
        self.assertEqual(secret, TOKEN)
        self.assertEqual(argv[:3], ["credential", "add", "copilot"])
        self.assertIn("--placeholder-prefix", argv)
        self.assertEqual(argv[argv.index("--placeholder-prefix") + 1], "gho_")
        self.assertNotIn(TOKEN, " ".join(argv) + result.stdout + result.stderr)
        self.assertEqual(self.recipe.host_token(self.root), TOKEN)

    def test_comments_preserve_urls_and_quoted_comment_markers(self):
        path = self.config()
        text = path.read_text().replace(
            '"authTokens":', '/* tokens */ "authTokens":')
        text = text[:-1] + ', "note": "https://x/\\\"//,}",}'
        path.write_text(text)
        self.assertEqual(self.recipe.host_token(self.root), TOKEN)

    def test_unsupported_stores_and_malformed_active_tokens_fail_closed(self):
        cases = [
            {"authTokens": {}},
            {"authTokens": {
                "https://github.com:active:github": {"token": ""},
                "https://github.com:active": {"token": TOKEN}}},
            {"lastLoggedInUser": {
                "host": "https://untrusted.example", "login": "active"}},
        ]
        for over in cases:
            with self.subTest(over=over):
                self.config(**over)
                with mock.patch.object(self.recipe.subprocess, "run") as run:
                    with self.assertRaises(self.recipe.Error):
                        self.recipe.enroll(self.root, "moathut")
                    run.assert_not_called()
        (self.root / "config.json").write_text('{"token": "' + TOKEN)
        with self.assertRaises(self.recipe.Error) as raised:
            self.recipe.host_token(self.root)
        self.assertNotIn(TOKEN, str(raised.exception))

    def archive(self, link=False):
        payload = b"pinned binary"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            member = tarfile.TarInfo("copilot")
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = "/outside"
                archive.addfile(member)
            else:
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        return stream.getvalue(), payload

    def installer(self, archive, digest=None):
        self.enterContext(mock.patch.object(
            self.recipe.platform, "system", return_value="Linux"))
        self.enterContext(mock.patch.object(
            self.recipe.platform, "machine", return_value="x86_64"))
        self.enterContext(mock.patch.object(
            self.recipe, "ASSETS", {"x86_64": (
                "x64", digest or hashlib.sha256(archive).hexdigest())}))
        return self.enterContext(mock.patch.object(
            self.recipe.urllib.request, "urlopen",
            return_value=io.BytesIO(archive)))

    def test_verified_install_is_repeatable_and_keeps_home_state(self):
        archive, payload = self.archive()
        download = self.installer(archive)
        state = self.root / "config.json"
        state.write_text("persistent state")
        with mock.patch.object(self.recipe, "version_matches",
                               return_value=True), mock.patch("sys.stdout"):
            self.recipe.install(self.root)
            self.recipe.install(self.root)
        self.assertEqual((self.root / ".local/bin/copilot").read_bytes(),
                         payload)
        self.assertEqual(state.read_text(), "persistent state")
        download.assert_called_once()

    def test_bad_checksum_or_link_never_replaces_an_existing_binary(self):
        for link in (False, True):
            with self.subTest(link=link):
                archive, _ = self.archive(link)
                self.installer(archive, None if link else "0" * 64)
                target = self.root / ".local/bin/copilot"
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"existing")
                with mock.patch.object(self.recipe, "version_matches",
                                       return_value=False):
                    with self.assertRaises(self.recipe.Error):
                        self.recipe.install(self.root)
                self.assertEqual(target.read_bytes(), b"existing")
                self.assertEqual(list(target.parent.iterdir()), [target])

    def test_policies_route_each_backend_but_never_mint_tokens(self):
        path = self.root / "policy.json"
        path.write_text(json.dumps(self.recipe.policy()))
        policy = load_policy(path)
        credential = Credential(
            "copilot", ("api.github.com", *self.recipe.PROVIDERS),
            "COPILOT_GITHUB_TOKEN", "Authorization", "Bearer {secret}", FAKE)
        broker = brokering(policy, lambda _: credential)
        self.assertEqual(dict(broker.hosts), {
            host: "copilot" for host in credential.hosts})
        for host in self.recipe.PROVIDERS:
            self.assertTrue(policy.permits(host, "POST", "/responses"))
            self.assertTrue(policy.permits(host, "POST", "/mcp/readonly"))
            self.assertFalse(policy.permits(host, "POST", "/mcp"))
            self.assertFalse(policy.permits(host, "POST", "/agents/sessions"))
            self.assertFalse(policy.permits(host, "POST", "/echo"))
            self.assertFalse(policy.permits(host, "DELETE", "/models"))
        self.assertFalse(policy.permits(
            "api.github.com", "GET", "/copilot_internal/v2/token"))


if __name__ == "__main__":
    unittest.main()
