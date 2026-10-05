"""completions/moathut.bash, held to moathut's parser and its directories.

Nothing runs the completion but a user's tab, so a command, an option or
a directory it falls behind on costs a completion and never an error.
Each check takes its expectation from cli.build_parser or from paths,
and runs the completion in bash with bash-completion's own helpers.
"""

import argparse
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from moathut import cli
from moathut.paths import Hut, described, user_dirs
from tests import REPO_ROOT

COMPLETION = Path(REPO_ROOT) / "completions" / "moathut.bash"
SPEC = Path(REPO_ROOT) / "rpm" / "moatery.spec"
BASH_COMPLETION = Path("/usr/share/bash-completion/bash_completion")

DRIVER = f"""
source {BASH_COMPLETION}
source {COMPLETION}
COMP_LINE=$1
shift
COMP_WORDS=("$@")
COMP_CWORD=$(($# - 1))
COMP_POINT=${{#COMP_LINE}}
_moathut
printf '%s\\n' "${{COMPREPLY[@]}}"
"""


def _subparsers(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    return {}


def _commands():
    """{the words naming it: its parser}, for every command a user
    types; the units' own are left out, as the parser's usage leaves
    them."""
    out = {}
    for name, parser in _subparsers(cli.build_parser()).items():
        if name == "unit":
            continue
        out[name] = parser
        for sub, subparser in _subparsers(parser).items():
            out[f"{name} {sub}"] = subparser
    return out


def _options(parser):
    return {o for a in parser._actions for o in a.option_strings
            if o.startswith("--") and o != "--help"}


@unittest.skipUnless(shutil.which("bash") and BASH_COMPLETION.exists(),
                     "needs bash and bash-completion")
class TestTheCompletion(unittest.TestCase):

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home)
        self.env = {"HOME": str(self.home), "PATH": os.environ["PATH"]}

    def complete(self, line, env=None):
        """What a tab at the end of LINE offers. bash splits `--like=`
        into `--like` and `=`, and so does this."""
        words = line.replace("=", " = ").split(" ")
        result = subprocess.run(
            ["bash", "-c", DRIVER, "bash", line, *words],
            env=env or self.env, capture_output=True, text=True,
            timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return set(result.stdout.split())

    def make_hut(self, name, env=None):
        hut = Hut(name, user_dirs(env or self.env))
        hut.settings.parent.mkdir(parents=True)
        hut.settings.write_text("{}")

    def make_credential(self, credential):
        path = described(user_dirs(self.env), credential)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
        path.with_suffix(".cred").write_text("")

    def test_the_commands_are_the_parsers(self):
        self.assertEqual(self.complete("moathut "),
                         {c for c in _commands() if " " not in c})
        self.assertEqual(self.complete("moathut credential "),
                         {c.split()[1] for c in _commands() if " " in c})

    def test_each_command_offers_its_options_and_no_other(self):
        for words, parser in _commands().items():
            with self.subTest(command=words):
                self.assertEqual(
                    self.complete(f"moathut {words} --") - {"--help"},
                    _options(parser))

    def test_the_options_skipped_with_their_value_are_those_taking_one(self):
        """Positions are counted past an option's value; an option missed
        here shifts every position after it."""
        listed = re.search(r"_moathut_takes_value\(\) \{\n    case \$1 in\n"
                           r"(.*?)\)\n", COMPLETION.read_text(), re.S)
        takes = {o.strip(" \\\n") for o in listed.group(1).split("|")}
        self.assertEqual(takes, {
            o for parser in _commands().values() for a in parser._actions
            if a.nargs != 0 for o in a.option_strings})

    def test_huts_are_offered_where_a_hut_is_named(self):
        self.make_hut("work")
        self.make_hut("play")
        (self.home / ".config" / "moatery" / "hut" / "half").mkdir()
        huts = {"work", "play"}
        for line in ("moathut enter ", "moathut log ", "moathut allow ",
                     "moathut policy ", "moathut stop ", "moathut rm ",
                     "moathut ptyxis ", "moathut ptyxis --remove ",
                     "moathut create x --like ",
                     "moathut create x --like=",
                     "moathut create x --like=w",
                     "moathut allow --method GET ",
                     "moathut enter --root w"):
            with self.subTest(line=line):
                self.assertEqual(self.complete(line),
                                 {b for b in huts
                                  if b.startswith(re.split("[ =]", line)[-1])})

    def test_nothing_is_offered_where_moathut_takes_a_new_name(self):
        self.make_hut("work")
        for line in ("moathut create ", "moathut allow work ",
                     "moathut allow --method GET work ",
                     "moathut enter work ", "moathut enter work -- ",
                     "moathut enter work -- -",
                     "moathut ls ", "moathut allow work --path "):
            with self.subTest(line=line):
                self.assertEqual(self.complete(line), set())

    def test_credentials_are_offered_to_rm_and_to_add(self):
        self.make_credential("anthropic")
        self.make_hut("work")
        for line in ("moathut credential rm ", "moathut credential add ",
                     "moathut credential add --env KEY "):
            with self.subTest(line=line):
                self.assertEqual(self.complete(line), {"anthropic"})
        self.assertEqual(self.complete("moathut credential ls "), set())

    def test_the_seccomp_profiles_are_offered_beside_files(self):
        self.assertLessEqual({"strict", "debug"},
                             self.complete("moathut create x --seccomp "))

    def test_huts_are_read_where_moathut_keeps_them(self):
        """XDG_CONFIG_HOME as paths.user_dirs reads it: honoured when
        absolute, ignored when not."""
        elsewhere = self.home / "elsewhere"
        absolute = dict(self.env, XDG_CONFIG_HOME=str(elsewhere))
        self.make_hut("there", absolute)
        self.assertEqual(self.complete("moathut enter ", absolute),
                         {"there"})
        relative = dict(self.env, XDG_CONFIG_HOME="elsewhere")
        self.make_hut("here", relative)
        self.assertEqual(self.complete("moathut enter ", relative),
                         {"here"})


class TestTheRpmInstallsIt(unittest.TestCase):

    def test_it_is_installed_and_listed(self):
        spec = SPEC.read_text()
        path = "%{_datadir}/bash-completion/completions/moathut"
        self.assertIn(f"%{{_sourcedir}}/completions/{COMPLETION.name} \\\n"
                      f"    %{{buildroot}}{path}", spec)
        self.assertIn(path, spec.split("\n%files\n", 1)[1].splitlines())


if __name__ == "__main__":
    unittest.main()
