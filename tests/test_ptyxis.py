"""moathut ptyxis: a hut's Ptyxis profile, written and removed in
GSettings, against a fake gsettings and, where Ptyxis's schema is
installed, the real one."""

import io
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from moathut import cli, commands, ptyxis
from moathut.cli import parse
from moathut.paths import Hut, user_dirs
from moathut.process import run
from tests.test_hut import _settings

PTYXIS_OWN = "0123456789abcdef0123456789abcdef"
OTHER = "fedcba9876543210fedcba9876543210"
DEFAULTS = {"profile-uuids": "@as []", "default-profile-uuid": "''"}


class FakeGSettings:
    """gsettings over a dict, with Ptyxis's schema installed or not."""

    def __init__(self, installed=True, listed=(PTYXIS_OWN,),
                 default=PTYXIS_OWN):
        self.installed = installed
        self.values = {
            (ptyxis.SCHEMA, "profile-uuids"): ptyxis.strings(listed),
            (ptyxis.SCHEMA, "default-profile-uuid"): ptyxis.text(default)}
        self.sets = []

    def __call__(self, argv, *, input=None, check=True, env=None):
        assert argv[0] == "gsettings", argv
        op, schema, *rest = argv[1:]
        code, out = 0, ""
        if not self.installed:
            code = 1
        elif op == "get":
            out = self.values.get((schema, rest[0]), DEFAULTS[rest[0]])
        elif op == "set":
            self.values[(schema, rest[0])] = rest[1]
            self.sets.append((schema, rest[0]))
        elif op == "reset":
            self.values.pop((schema, rest[0]), None)
        elif op == "reset-recursively":
            for key in [k for k in self.values if k[0] == schema]:
                del self.values[key]
        if check and code:
            raise commands.CommandFailed(" ".join(argv))
        return subprocess.CompletedProcess(argv, code, out + "\n", "")

    def listed(self):
        return ptyxis.parse_strings(
            self.values[(ptyxis.SCHEMA, "profile-uuids")])

    def profile(self, name):
        schema = f"{ptyxis.PROFILE_SCHEMA}:{ptyxis.profile_path(name)}"
        return {k: v for (s, k), v in self.values.items() if s == schema}


def _missing(argv, **kwargs):
    raise FileNotFoundError(argv[0])


class TestTheProfile(unittest.TestCase):

    def test_its_id_is_ptyxiss_shape_and_the_huts_own(self):
        own = ptyxis.profile_uuid("work")
        self.assertRegex(own, r"^[0-9a-f]{32}$")
        self.assertEqual(own, ptyxis.profile_uuid("work"))
        self.assertNotEqual(own, ptyxis.profile_uuid("play"))
        self.assertEqual(ptyxis.profile_path("work"),
                         f"/org/gnome/Ptyxis/Profiles/{own}/")

    def test_its_command_is_moathut_as_the_units_run_it(self):
        settings = _settings("/home/u", tool=("/usr/bin/python3", "-s",
                                              "/usr/bin/moathut"))
        self.assertEqual(shlex.split(ptyxis.command(settings, "work")),
                         ["/usr/bin/python3", "-s", "/usr/bin/moathut",
                          "enter", "work"])
        checkout = settings._replace(pythonpath="/src/my moatery")
        self.assertEqual(shlex.split(ptyxis.command(checkout, "work"))[:2],
                         ["env", "PYTHONPATH=/src/my moatery"])

    def test_it_opens_on_the_host_and_new_tabs_stay_with_it(self):
        values = dict(ptyxis.keys(_settings("/home/u"), "work"))
        self.assertEqual(values["default-container"], "'session'")
        self.assertEqual(values["use-custom-command"], "true")
        self.assertEqual(values["preserve-container"], "'never'")

    def test_strings_survive_gvariant_text(self):
        for value in ("plain", "it's", "back\\slash", "'\\'"):
            with self.subTest(value=value):
                self.assertEqual(ptyxis.parse_strings(ptyxis.text(value)),
                                 [value])
        self.assertEqual(ptyxis.parse_strings(
            ptyxis.strings(["a", "b'c"])), ["a", "b'c"])
        self.assertEqual(ptyxis.parse_strings("@as []"), [])
        self.assertEqual(ptyxis.parse_strings('"it\'s"'), ["it's"])


class TestTheCommands(unittest.TestCase):

    def setUp(self):
        home = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.dirs = user_dirs({"HOME": str(home)})
        hut = Hut("work", self.dirs)
        hut.settings.parent.mkdir(parents=True)
        hut.settings.write_text(_settings(str(home)).to_json())

    def test_add_writes_the_profile_and_lists_it_once(self):
        host = FakeGSettings(listed=(PTYXIS_OWN, OTHER))
        for _ in range(2):
            commands.ptyxis_add("work", dirs=self.dirs, runner=host)
        own = ptyxis.profile_uuid("work")
        self.assertEqual(host.listed(), [PTYXIS_OWN, OTHER, own])
        self.assertEqual(host.profile("work"),
                         dict(ptyxis.keys(_settings(str(self.dirs.home)),
                                          "work")))

    def test_add_refuses_where_the_huts_would_become_the_default(self):
        own = ptyxis.profile_uuid("work")
        for listed, default in (((), ""), ((OTHER,), ""),
                                ((OTHER,), PTYXIS_OWN),
                                ((own, OTHER), own)):
            with self.subTest(listed=listed, default=default):
                host = FakeGSettings(listed=listed, default=default)
                with self.assertRaisesRegex(commands.HutError,
                                            "no default profile"):
                    commands.ptyxis_add("work", dirs=self.dirs, runner=host)
                self.assertEqual(host.sets, [])

    def test_add_refuses_without_ptyxis_or_gsettings(self):
        for runner in (FakeGSettings(installed=False), _missing):
            with self.subTest(runner=runner):
                with self.assertRaisesRegex(commands.HutError,
                                            "settings are not installed"):
                    commands.ptyxis_add("work", dirs=self.dirs,
                                        runner=runner)

    def test_add_needs_the_hut(self):
        with self.assertRaisesRegex(commands.HutError, "no hut gone"):
            commands.ptyxis_add("gone", dirs=self.dirs,
                                runner=FakeGSettings())

    def test_remove_takes_it_out_and_its_keys_with_it(self):
        host = FakeGSettings(listed=(PTYXIS_OWN, OTHER))
        commands.ptyxis_add("work", dirs=self.dirs, runner=host)
        self.assertTrue(commands.ptyxis_remove("work", runner=host))
        self.assertEqual(host.listed(), [PTYXIS_OWN, OTHER])
        self.assertEqual(host.profile("work"), {})
        self.assertFalse(commands.ptyxis_remove("work", runner=host))

    def test_remove_resets_the_default_when_it_was_the_huts(self):
        host = FakeGSettings()
        commands.ptyxis_add("work", dirs=self.dirs, runner=host)
        own = ptyxis.profile_uuid("work")
        host.values[(ptyxis.SCHEMA, "default-profile-uuid")] = \
            ptyxis.text(own)
        commands.ptyxis_remove("work", runner=host)
        self.assertNotIn((ptyxis.SCHEMA, "default-profile-uuid"),
                         host.values)

    def test_remove_without_ptyxis_or_gsettings_removes_nothing(self):
        for runner in (FakeGSettings(installed=False), _missing):
            with self.subTest(runner=runner):
                self.assertFalse(commands.ptyxis_remove("work",
                                                        runner=runner))


class TestTheCommandLine(unittest.TestCase):

    def _run(self, words, **patches):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                mock.patch.multiple(cli, **patches):
            cli.run_command(parse(words), tool=(), environ={"HOME": "/h"},
                            cwd="/h", isatty=False)
        return out.getvalue()

    def test_rm_removes_the_huts_profile(self):
        remove = mock.Mock(return_value=True)
        said = self._run(["rm", "work"], rm=mock.Mock(return_value=[]),
                         ptyxis_remove=remove)
        remove.assert_called_once_with("work")
        self.assertIn("hut work's Ptyxis profile removed", said)

    def test_ptyxis_writes_it_and_remove_says_when_there_is_none(self):
        add = mock.Mock()
        self._run(["ptyxis", "work"], ptyxis_add=add)
        self.assertEqual(add.call_args.args, ("work",))
        with self.assertRaisesRegex(commands.HutError, "no Ptyxis profile"):
            self._run(["ptyxis", "work", "--remove"],
                      ptyxis_remove=mock.Mock(return_value=False))


def _real_ptyxis():
    if not shutil.which("gsettings"):
        return False
    return subprocess.run(["gsettings", "list-keys", ptyxis.SCHEMA],
                          capture_output=True).returncode == 0


@unittest.skipUnless(_real_ptyxis(), "needs gsettings and Ptyxis's schema")
class TestAgainstPtyxissSchema(unittest.TestCase):
    """Real gsettings, writing to a keyfile of its own: the keys and
    their values are ones Ptyxis's schema takes."""

    def setUp(self):
        home = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.env = dict(os.environ, XDG_CONFIG_HOME=str(home / "config"),
                        GSETTINGS_BACKEND="keyfile")
        self.dirs = user_dirs({"HOME": str(home)})
        hut = Hut("work", self.dirs)
        hut.settings.parent.mkdir(parents=True)
        self.settings = _settings(str(home), pythonpath="/src/it's")
        hut.settings.write_text(self.settings.to_json())
        self.gsettings("set", ptyxis.SCHEMA, "profile-uuids",
                       ptyxis.strings([PTYXIS_OWN]))
        self.gsettings("set", ptyxis.SCHEMA, "default-profile-uuid",
                       ptyxis.text(PTYXIS_OWN))

    def runner(self, argv, *, input=None, check=True, env=None):
        return run(argv, check=check, env=self.env)

    def gsettings(self, *args):
        return self.runner(["gsettings", *args]).stdout

    def test_it_is_written_and_removed(self):
        commands.ptyxis_add("work", dirs=self.dirs, runner=self.runner)
        own = ptyxis.profile_uuid("work")
        self.assertEqual(ptyxis.parse_strings(self.gsettings(
            "get", ptyxis.SCHEMA, "profile-uuids")), [PTYXIS_OWN, own])
        schema = f"{ptyxis.PROFILE_SCHEMA}:{ptyxis.profile_path('work')}"
        self.assertEqual(ptyxis.parse_strings(self.gsettings(
            "get", schema, "custom-command")),
            [ptyxis.command(self.settings, "work")])
        self.assertEqual(self.gsettings(
            "get", schema, "preserve-container").strip(), "'never'")
        self.assertTrue(commands.ptyxis_remove("work", runner=self.runner))
        self.assertEqual(ptyxis.parse_strings(self.gsettings(
            "get", ptyxis.SCHEMA, "profile-uuids")), [PTYXIS_OWN])
        self.assertEqual(self.gsettings(
            "get", schema, "custom-command").strip(), "''")


if __name__ == "__main__":
    unittest.main()
