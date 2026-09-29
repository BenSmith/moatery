#!/usr/bin/env python3
"""customs-box: the units it writes name each other and hand the programs
flags their parsers take; the rules are shape 1n's; what a mount may not
touch; and each command against a fake podman and systemctl.

The units are joined only by names, and a dependency on a name nothing
provides is one systemd drops without a word. The programs' flags are
parsed by the programs' own parsers, so a flag renamed there fails here.
"""

import json
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import REPO_ROOT, load_script
from tests.test_quadlet_example import _ruleset

from customs_box import commands, netns
from customs_box.cli import main
from customs_box.mounts import Mount, MountRefused, parse_mount, refuse
from customs_box.paths import Box, protected, user_dirs, valid_name
from customs_box.units import Settings, render

DESIGN = Path(REPO_ROOT) / "docs" / "DESIGN.md"
DEPENDENCIES = ("Wants", "Requires", "After", "BindsTo")
TRUST = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"


def _settings(home, **over):
    values = dict(image="registry.example/image:1", trust_path=TRUST,
                  home_path=str(home), uid=1000, gid=1000, mounts=(),
                  tool=("/usr/bin/python3", "/opt/cb/bin/customs-box"),
                  python="/usr/bin/python3", libexec="/opt/cb/libexec",
                  pythonpath=None)
    values.update(over)
    return Settings(**values)


def _keys(text, key):
    text = text.replace("\\\n", " ")
    return [word for value in re.findall(rf"^{key}=(.*)$", text, re.M)
            for word in value.split()]


def _exec_words(text, key):
    """An Exec line's words as systemd hands them over: continuations
    joined, quotes removed, `%%` and `$$` undone."""
    text = text.replace("\\\n", " ")
    value = re.search(rf"^{key}=(.*)$", text, re.M).group(1)
    return [w.replace("%%", "%").replace("$$", "$")
            for w in shlex.split(value.removeprefix("-"))]


class TestNamesAndPaths(unittest.TestCase):
    def test_a_name_is_a_hostname_and_a_unit_fragment(self):
        for good in ("a", "agent", "my-agent-2", "x" * 48):
            self.assertTrue(valid_name(good), good)
        for bad in ("", "-a", "a-", "A", "a.b", "a_b", "a b", "x" * 49,
                    "../a"):
            self.assertFalse(valid_name(bad), bad)

    def test_paths_follow_the_xdg_variables(self):
        dirs = user_dirs({"HOME": "/h", "XDG_CONFIG_HOME": "/c",
                          "XDG_STATE_HOME": "relative",
                          "XDG_RUNTIME_DIR": "/run/user/7"})
        box = Box("a", dirs)
        self.assertEqual(box.policy, Path("/c/customs/box/a/policy.json"))
        self.assertEqual(box.state, Path("/h/.local/state/customs/box/a"))
        self.assertEqual(box.home, Path("/h/.local/share/customs/box/a/home"))
        self.assertEqual(box.pod_file,
                         Path("/c/containers/systemd/customs-box-a.pod"))
        self.assertIn(Path("/run/user/7"), protected(dirs))


class TestMounts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.home = root / "home" / "u"
        self.run_dir = root / "run"
        for d in (self.home / "projects" / "p", self.home / ".config"
                  / "containers" / "systemd", self.home / ".config"
                  / "customs" / "box" / "a", self.home / ".local" / "share"
                  / "customs" / "box" / "b" / "home", self.run_dir):
            d.mkdir(parents=True)
        self.dirs = user_dirs({"HOME": str(self.home),
                               "XDG_RUNTIME_DIR": str(self.run_dir)})
        self.covered = (str(self.home), TRUST)

    def _refused(self, spec):
        mount = parse_mount(spec, self.home, self.home)
        with self.assertRaises(MountRefused) as caught:
            refuse(mount, self.dirs, self.covered)
        return str(caught.exception)

    def test_a_project_directory_is_allowed(self):
        mount = parse_mount("~/projects/p", self.home, self.home)
        refuse(mount, self.dirs, self.covered)
        self.assertEqual(mount.target, str(self.home / "projects" / "p"))
        self.assertFalse(mount.readonly)
        self.assertTrue(parse_mount("projects/p:/w:ro", self.home,
                                    self.home).readonly)

    def test_home_and_what_contains_it_are_refused(self):
        for spec in (str(self.home), str(self.home.parent), "/"):
            self.assertIn("home directory", self._refused(spec))

    def test_what_holds_units_keys_and_sockets_is_refused(self):
        for spec in (".config", ".config/containers/systemd",
                     ".config/customs/box/a",
                     ".local/share/customs/box/b/home", str(self.run_dir)):
            with self.subTest(spec=spec):
                self.assertIn("overlaps", self._refused(spec))

    def test_a_target_may_not_cover_the_home_or_the_trust_store(self):
        self.assertIn("would cover", self._refused("projects/p:/etc"))
        self.assertIn("would cover",
                      self._refused(f"projects/p:{self.home.parent}"))

    def test_malformed_specs(self):
        for spec in ("", ":x", "a:b:c:d", "a:relative"):
            with self.subTest(spec=spec), self.assertRaises(MountRefused):
                parse_mount(spec, self.home, self.home)


class TestUnits(unittest.TestCase):
    def setUp(self):
        self.dirs = user_dirs({"HOME": "/home/u",
                               "XDG_RUNTIME_DIR": "/run/user/1000"})
        self.box = Box("agent", self.dirs)
        self.settings = _settings(
            "/home/u", mounts=(Mount(Path("/home/u/p"), "/w", True),))
        self.units = {p.name: t for p, t in
                      render(self.box, self.settings).items()}
        self.pod = self.units["customs-box-agent.pod"]
        self.work = self.units["customs-box-agent.container"]
        self.inspect = self.units["customs-box-agent-inspect.service"]
        self.resolve = self.units["customs-box-agent-resolve.service"]

    def test_every_unit_named_is_one_the_box_provides(self):
        for name, text in self.units.items():
            for key in DEPENDENCIES:
                for unit in _keys(text, key):
                    with self.subTest(file=name, key=key, unit=unit):
                        self.assertIn(unit, self.box.services)

    def test_the_pod_starts_the_listeners_and_the_workload_needs_them(self):
        for unit in (self.box.inspect_service, self.box.resolve_service):
            with self.subTest(unit=unit):
                self.assertIn(unit, _keys(self.pod, "Wants"))
                self.assertIn(unit, _keys(self.work, "Requires"))
                self.assertIn(unit, _keys(self.work, "After"))
        self.assertEqual(_keys(self.work, "Pod"), ["customs-box-agent.pod"])

    def test_the_listeners_are_bound_to_the_pod_and_notify(self):
        """As Type=simple a listener unit is started when forked, and the
        workload's first dial can find nothing bound."""
        for text in (self.inspect, self.resolve):
            self.assertEqual(_keys(text, "BindsTo"), [self.box.pod_service])
            self.assertIn(self.box.pod_service, _keys(text, "After"))
            self.assertEqual(_keys(text, "Type"), ["notify"])

    def test_the_pod_loads_the_rules_and_has_no_cgroup_or_host_names(self):
        self.assertEqual(_exec_words(self.pod, "ExecStartPost"),
                         [*self.settings.tool, "unit", "rules", "agent"])
        args = _keys(self.pod, "PodmanArgs")
        self.assertIn("--share-parent=false", args)
        self.assertIn("--hosts-file=image", args)
        self.assertEqual(_keys(self.pod, "Network"), ["pasta"])
        self.assertEqual(_keys(self.pod, "UserNS"), ["keep-id"])

    def test_the_workload_cannot_touch_its_namespace(self):
        self.assertEqual(_keys(self.work, "DropCapability"), ["ALL"])
        added = set(_keys(self.work, "AddCapability"))
        self.assertTrue(added)
        self.assertFalse(added & {"NET_ADMIN", "NET_RAW", "SYS_ADMIN"})
        self.assertNotIn("PodmanArgs", self.work)
        self.assertNotIn("Network=", self.work)

    def test_the_workload_mounts_its_own_home_and_trusts_the_bundle(self):
        """The working directory is the home podman gives the user."""
        self.assertEqual(_keys(self.work, "WorkingDir"), ["/home/u"])
        volumes = _keys(self.work, "Volume")
        self.assertIn(f"{self.box.home}:/home/u:z", volumes)
        self.assertIn(f"{self.box.bundle}:{TRUST}:ro,z", volumes)
        self.assertIn("/home/u/p:/w:ro,z", volumes)
        self.assertFalse([v for v in volumes if v.startswith("/home/u:")])
        env = _keys(self.work, "Environment")
        self.assertIn(f"SSL_CERT_FILE={TRUST}", env)

    def _handed(self, unit_text):
        """What the launcher runs, with the pod's pid substituted, parsed by
        the launcher's own parser."""
        words = _exec_words(unit_text, "ExecStart")
        prefix = [*self.settings.tool, "unit", "exec", "agent", "--"]
        self.assertEqual(words[:len(prefix)], prefix)
        argv = [w.replace(netns.PID, "4242") for w in words[len(prefix):]]
        self.assertEqual(argv[0], self.settings.python)
        listen = load_script("libexec/customs-netns-listen")
        return listen.parse_args(argv[1:])

    def test_the_inspector_is_handed_flags_its_parser_takes(self):
        launched = self._handed(self.inspect)
        self.assertEqual(launched.pid, 4242)
        self.assertFalse(launched.resolver)
        self.assertEqual(launched.command[0], self.settings.python)
        args = load_script("libexec/customs-inspect").parse_args(
            launched.command[1:])
        self.assertEqual(args.netns_pid, 4242)
        self.assertEqual(args.name, "agent")
        self.assertEqual(args.policy, str(self.box.policy))
        self.assertEqual(args.state_dir, str(self.box.state))
        self.assertEqual(args.record, str(self.box.record))

    def test_the_responder_is_handed_flags_its_parser_takes(self):
        launched = self._handed(self.resolve)
        self.assertEqual(launched.pid, 4242)
        self.assertTrue(launched.resolver)
        args = load_script("libexec/customs-resolve").parse_args(
            launched.command[1:])
        self.assertEqual(args.policy, str(self.box.policy))
        self.assertEqual(args.address, "127.0.0.1")

    def test_awkward_paths_survive_the_unit_files(self):
        box = Box("agent", user_dirs({"HOME": "/home/a b%c$d"}))
        settings = _settings("/home/a b%c$d",
                             pythonpath="/src/a b", tool=("/py", "/t x"))
        units = {p.name: t for p, t in render(box, settings).items()}
        pod = units["customs-box-agent.pod"]
        self.assertEqual(_exec_words(pod, "ExecStartPost"),
                         ["/py", "/t x", "unit", "rules", "agent"])
        self.assertIn('Environment="PYTHONPATH=/src/a b"', pod)
        inspect = units["customs-box-agent-inspect.service"]
        self.assertIn("/home/a b%c$d/.config/customs/box/agent/policy.json",
                      _exec_words(inspect, "ExecStart"))
        work = units["customs-box-agent.container"]
        self.assertIn(
            "\nVolume=/home/a b%%c$d/.local/share/customs/box/agent/home:"
            "/home/a b%%c$d:z\n", work)


class TestRules(unittest.TestCase):
    def test_the_rules_are_shape_1n(self):
        design = DESIGN.read_text().split(
            "## Shape 1n", 1)[1].split("\n## ", 1)[0]
        self.assertEqual(_ruleset(netns.ruleset("$DEV")), _ruleset(design))

    def _runner(self, outputs):
        calls = []

        def runner(argv, *, input=None, check=True, env=None):
            calls.append((argv, input))
            for match, (code, out) in outputs.items():
                if match in " ".join(argv):
                    return subprocess.CompletedProcess(argv, code, out, "")
            return subprocess.CompletedProcess(argv, 0, "", "")
        return runner, calls

    def test_the_rules_go_in_with_the_device_read_inside(self):
        runner, calls = self._runner({
            "route show default": (0, json.dumps([{"dev": "enp9s0"}]))})
        netns.load_rules(77, runner)
        (argv, text), = [c for c in calls if "nft" in c[0]]
        self.assertEqual(argv[:6], ["podman", "unshare", "nsenter", "-t",
                                    "77", "-n"])
        self.assertIn('device "enp9s0"', text)

    def test_no_single_sane_device_is_an_error(self):
        for routes in ([], [{"dev": "a"}, {"dev": "b"}],
                       [{"dev": 'x" priority'}]):
            runner, _ = self._runner({
                "route show default": (0, json.dumps(routes))})
            with self.subTest(routes=routes), \
                    self.assertRaises(netns.NetnsError):
                netns.load_rules(77, runner)

    def test_loaded_means_both_tables(self):
        runner, _ = self._runner({"netdev customs": (1, "")})
        self.assertFalse(netns.rules_loaded(5, runner))
        runner, _ = self._runner({})
        self.assertTrue(netns.rules_loaded(5, runner))

    def test_the_pid_words_become_the_infra_pid(self):
        runner, _ = self._runner({"InfraContainerID": (0, "abc\n"),
                                  "State.Pid": (0, "31337\n")})
        seen = []
        netns.exec_with_pid("agent", ["/py", "x", "--pid", netns.PID],
                            runner, lambda path, argv: seen.append(argv))
        self.assertEqual(seen, [["/py", "x", "--pid", "31337"]])
        runner, _ = self._runner({"InfraContainerID": (0, "abc\n"),
                                  "State.Pid": (0, "0\n")})
        with self.assertRaises(netns.NetnsError):
            netns.exec_with_pid("agent", ["/py"], runner, None)


class FakeHost:
    """podman, systemctl and customs-mint-ca, as far as the commands ask."""

    def __init__(self, state_root, rules=True, load_state="loaded"):
        self.calls = []
        self.state_root = state_root
        self.rules = rules
        self.load_state = load_state

    def __call__(self, argv, *, input=None, check=True, env=None):
        self.calls.append(argv)
        line = " ".join(argv)
        code, out = 0, ""
        if argv[:3] in (["podman", "container", "exists"],
                        ["podman", "pod", "exists"]):
            code = 1
        elif "customs-mint-ca" in line:
            ca = Path(argv[argv.index("--state-dir") + 1]) / "ca.pem"
            ca.write_text("BOX CA\n")
            out = f"{ca}\n"
        elif argv[:3] == ["podman", "run", "--rm"]:
            out = TRUST + "\n"
        elif "LoadState" in line:
            out = self.load_state + "\n"
        elif "InfraContainerID" in line:
            out = "infra\n"
        elif "State.Pid" in line:
            out = "999\n"
        elif "nft list table" in line:
            code = 0 if self.rules else 1
        elif "exec echo" in line:
            out = "/bin/bash\n"
        if check and code:
            raise commands.CommandFailed(line)
        return subprocess.CompletedProcess(argv, code, out, "")


class TestCommands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.home = root / "home"
        (self.home / "projects" / "p").mkdir(parents=True)
        self.env = {"HOME": str(self.home),
                    "XDG_RUNTIME_DIR": str(root / "run"), "TERM": "xterm"}
        self.dirs = user_dirs(self.env)
        self.policy = root / "policy.json"
        self.policy.write_text('{"hosts": ["pypi.org"]}')
        host_bundle = root / "system.pem"
        host_bundle.write_text("SYSTEM CAS\n")
        patcher = mock.patch.object(commands, "HOST_BUNDLES",
                                    (str(host_bundle),))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _create(self, name="agent", host=None, policy=None, mounts=()):
        host = host or FakeHost(self.home)
        box = commands.create(
            name, policy or self.policy, "img", list(mounts),
            dirs=self.dirs, tool=("/py", "/cb"), python="/py",
            libexec="/lx", pythonpath=None, uid=1000, gid=1000,
            cwd=self.home, environ=self.env, runner=host)
        return box, host

    def test_create_lays_the_box_out(self):
        box, host = self._create(mounts=["projects/p"])
        for path in box.unit_files:
            self.assertTrue(path.is_file(), path)
        self.assertEqual(box.policy.read_text(), self.policy.read_text())
        self.assertEqual(box.policy.stat().st_mode & 0o777, 0o600)
        self.assertEqual(box.bundle.read_text(), "BOX CA\nSYSTEM CAS\n")
        self.assertTrue(box.home.is_dir())
        settings = Settings.from_json(box.settings.read_text())
        self.assertEqual(settings.trust_path, TRUST)
        self.assertEqual(settings.mounts[0].source,
                         self.home / "projects" / "p")
        self.assertIn(["systemctl", "--user", "daemon-reload"], host.calls)

    def test_create_refuses(self):
        self._create()
        bad_policy = self.policy.with_name("bad.json")
        bad_policy.write_text('{"hosts": "pypi.org"}')
        brokered = self.policy.with_name("brokered.json")
        brokered.write_text(json.dumps({"policy": [
            {"host": "api.x", "paths": ["/v1/*"], "credential": "k"}]}))
        cases = {"exists": dict(name="agent"),
                 "name": dict(name="Agent"),
                 "policy": dict(name="b", policy=bad_policy),
                 "credentials": dict(name="c", policy=brokered),
                 "home directory": dict(name="d", mounts=[str(self.home)])}
        for words, kwargs in cases.items():
            with self.subTest(words), \
                    self.assertRaisesRegex(commands.BoxError, words):
                self._create(**kwargs)
        self.assertFalse(Box("d", self.dirs).config.exists())

    def test_a_failed_create_leaves_nothing_but_a_home_it_found(self):
        kept = Box("agent", self.dirs).home
        kept.mkdir(parents=True)
        (kept / "notes").write_text("mine")
        with self.assertRaisesRegex(commands.BoxError, "did not generate"):
            self._create(host=FakeHost(self.home, load_state="not-found"))
        box = Box("agent", self.dirs)
        self.assertFalse(box.config.exists())
        self.assertFalse(any(p.exists() for p in box.unit_files))
        self.assertEqual((kept / "notes").read_text(), "mine")

    def test_enter_runs_podman_exec_in_the_box(self):
        self._create(mounts=["projects/p"])
        host, ran = FakeHost(self.home), []
        commands.enter("agent", [], root=False, dirs=self.dirs,
                       cwd=self.home / "projects" / "p", environ=self.env,
                       isatty=True, runner=host,
                       execvp=lambda f, argv: ran.append(argv))
        self.assertIn(["systemctl", "--user", "start",
                       "customs-box-agent.service"], host.calls)
        (argv,) = ran
        self.assertEqual(argv[:4], ["podman", "exec", "-i", "-t"])
        self.assertEqual(argv[argv.index("--user") + 1], "1000:1000")
        self.assertEqual(argv[argv.index("--workdir") + 1],
                         str(self.home / "projects" / "p"))
        self.assertIn("TERM", argv)
        self.assertEqual(argv[-3:], ["agent", "/bin/bash", "-l"])

    def test_enter_refuses_a_box_without_its_rules(self):
        self._create()
        with self.assertRaisesRegex(commands.BoxError, "no customs rules"):
            commands.enter("agent", ["id"], root=False, dirs=self.dirs,
                           cwd=self.home, environ=self.env, isatty=False,
                           runner=FakeHost(self.home, rules=False),
                           execvp=self.fail)

    def test_rm_keeps_the_home_unless_asked(self):
        box, _ = self._create()
        (box.home / "notes").write_text("mine")
        kept = commands.rm("agent", home=False, dirs=self.dirs,
                           runner=FakeHost(self.home))
        self.assertIn(str(box.home), kept)
        self.assertTrue((box.home / "notes").exists())
        self.assertFalse(box.config.exists())
        self.assertFalse(any(p.exists() for p in box.unit_files))
        self._create()
        commands.rm("agent", home=True, dirs=self.dirs,
                    runner=FakeHost(self.home))
        self.assertFalse(box.home.exists())

    def test_ls_lists_each_box_and_its_state(self):
        self._create("a")
        self._create("b")
        rows = commands.ls(dirs=self.dirs, runner=FakeHost(self.home))
        self.assertEqual([r[0] for r in rows], ["a", "b"])

    def test_the_command_line_reports_a_refusal_and_exits_1(self):
        with mock.patch("sys.stderr") as err:
            code = main(["customs-box", "stop", "nosuch"], environ=self.env)
        self.assertEqual(code, 1)
        self.assertIn("no box nosuch",
                      "".join(c.args[0] for c in err.write.call_args_list))


if __name__ == "__main__":
    unittest.main()
