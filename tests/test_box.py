#!/usr/bin/env python3
"""moathut: the units it writes name each other and hand the programs
flags their parsers take; the rules are the netns placement's; what a
mount may not touch; and each command against a fake podman and systemctl.

The units are joined only by names, and a dependency on a name nothing
provides is one systemd drops without a word. The programs' flags are
parsed by the programs' own parsers, so a flag renamed there fails here.
"""

import ipaddress
import os
import json
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import REPO_ROOT, load_script
from tests.test_quadlet_example import _ruleset

from moatery.egress_record import DROP_MISDIRECTED
from moatery.inspect_document import INSPECT_DIGEST_KEY, inspect_policy_digest
from moatery.inspect_policy import load_policy
from moathut import commands, document, netns, record
from moathut.cli import main, parse
from moathut.credentials import (Broker, Credential, CredentialError,
                                     brokering, describe)
from moathut.mounts import Mount, MountRefused, parse_mount, refuse
from moathut.paths import (Box, boxes_root, credentials_root, described,
                               protected, sealed, user_dirs, valid_name)
from moathut.units import (ALL_CAPABILITIES, ANSWER, CAPABILITIES,
                               PROMPT_PATH, Settings, container_unit,
                               interpreter, prompt, render)

DESIGN = Path(REPO_ROOT) / "docs" / "DESIGN.md"
DEPENDENCIES = ("Wants", "Requires", "After", "BindsTo", "PartOf")
TRUST = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"


def _settings(home, **over):
    values = dict(image="registry.example/image:1", trust_path=TRUST,
                  home_path=str(home), uid=1000, gid=1000, mounts=(),
                  tool=("/usr/bin/python3", "/opt/cb/bin/moathut"),
                  python="/usr/bin/python3", libexec="/opt/cb/libexec",
                  pythonpath=None)
    values.update(over)
    return Settings(**values)


def _credential(id="anthropic", hosts=("api.anthropic.com",),
                env="ANTHROPIC_API_KEY"):
    return Credential(id, tuple(hosts), env, "x-api-key", "{secret}",
                      f"moatery-placeholder-{id}")


def _policy(case, entries, hosts=()):
    path = Path(case.enterContext(tempfile.TemporaryDirectory())) / "p.json"
    path.write_text(json.dumps({"hosts": list(hosts), "policy": entries}))
    return load_policy(path)


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
        self.assertEqual(box.policy, Path("/c/moatery/box/a/policy.json"))
        self.assertEqual(box.state, Path("/h/.local/state/moatery/box/a"))
        self.assertEqual(box.home, Path("/h/.local/share/moatery/box/a/home"))
        self.assertEqual(box.pod_file,
                         Path("/c/containers/systemd/moathut-a.pod"))
        self.assertIn(Path("/run/user/7"), protected(dirs))

    def test_the_credentials_are_beside_the_boxes_and_protected(self):
        """Among them, a box named `credentials` would be their
        directory."""
        dirs = user_dirs({"HOME": "/h"})
        root = credentials_root(dirs)
        self.assertFalse(root.is_relative_to(boxes_root(dirs)))
        self.assertTrue(any(root.is_relative_to(p) for p in protected(dirs)))
        self.assertEqual(sealed(dirs, "k"), root / "k.cred")
        self.assertEqual(described(dirs, "k"), root / "k.json")


class TestMounts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.home = root / "home" / "u"
        self.run_dir = root / "run"
        for d in (self.home / "projects" / "p", self.home / ".config"
                  / "containers" / "systemd", self.home / ".config"
                  / "moatery" / "box" / "a", self.home / ".local" / "share"
                  / "moatery" / "box" / "b" / "home", self.run_dir):
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
                     ".config/moatery/box/a",
                     ".local/share/moatery/box/b/home", str(self.run_dir)):
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
                      render(self.box, self.settings, None).items()}
        self.pod = self.units["moathut-agent.pod"]
        self.work = self.units["moathut-agent.container"]
        self.inspect = self.units["moathut-agent-inspect.service"]
        self.resolve = self.units["moathut-agent-resolve.service"]

    def test_every_unit_named_is_one_the_box_provides(self):
        for name, text in self.units.items():
            for key in DEPENDENCIES:
                for unit in _keys(text, key):
                    with self.subTest(file=name, key=key, unit=unit):
                        self.assertIn(unit, self.box.services)

    def test_the_pod_starts_the_listeners_and_the_workload_waits(self):
        """Wants=, not Requires=: a new policy restarts the listeners, and
        a restart of a unit the workload required would restart it."""
        for unit in (self.box.inspect_service, self.box.resolve_service):
            with self.subTest(unit=unit):
                self.assertIn(unit, _keys(self.pod, "Wants"))
                self.assertIn(unit, _keys(self.work, "Wants"))
                self.assertIn(unit, _keys(self.work, "After"))
                for text in self.units.values():
                    self.assertNotIn(unit, _keys(text, "Requires"))
                    self.assertNotIn(unit, _keys(text, "BindsTo"))
        self.assertEqual(_keys(self.work, "Pod"), ["moathut-agent.pod"])

    def test_the_listeners_are_bound_to_the_pod_and_notify(self):
        """As Type=simple a listener unit is started when forked, and the
        workload's first dial can find nothing bound. One that dies is
        started again, since nothing it serves would notice."""
        for text in (self.inspect, self.resolve):
            self.assertEqual(_keys(text, "BindsTo"), [self.box.pod_service])
            self.assertIn(self.box.pod_service, _keys(text, "After"))
            self.assertEqual(_keys(text, "Type"), ["notify"])
            self.assertEqual(_keys(text, "Restart"), ["on-failure"])

    def test_a_listener_reload_is_the_signal_its_program_reads_again_on(self):
        """ExecReload= sends the main process, the program the launcher
        execs, the signal the inspector and the responder read the policy
        again on; the examples' units send the same."""
        units = [self.inspect, self.resolve] + [
            (REPO_ROOT / "examples" / d / f).read_text()
            for d, f in (("systemd", "moat-inspect.service"),
                         ("systemd", "moat-resolve.service"),
                         ("quadlet", "moat-inspect-example.service"),
                         ("quadlet", "moat-resolve-example.service"))]
        for text in units:
            self.assertEqual(_keys(text, "ExecReload"),
                             ["kill", "-USR1", "$MAINPID"])
        for program in ("moat-inspect", "moat-resolve"):
            self.assertIn("signal.signal(signal.SIGUSR1, lambda",
                          (REPO_ROOT / "libexec" / program).read_text())

    def test_the_pod_starts_the_rotation_which_stops_with_it(self):
        """The timer starts its service by their shared name, and that
        runs `unit rotate` on this box, as the command line takes it."""
        timer = self.units["moathut-agent-rotate.timer"]
        service = self.units["moathut-agent-rotate.service"]
        self.assertIn(self.box.rotate_timer, _keys(self.pod, "Wants"))
        self.assertEqual(_keys(timer, "PartOf"), [self.box.pod_service])
        self.assertEqual(_keys(timer, "Unit"), [])
        self.assertEqual(self.box.rotate_timer.removesuffix(".timer"),
                         self.box.rotate_service.removesuffix(".service"))
        self.assertEqual(_keys(service, "Type"), ["oneshot"])
        words = _exec_words(service, "ExecStart")
        self.assertEqual(words[:2], list(self.settings.tool))
        from moathut import cli
        with mock.patch.object(cli, "unit_rotate") as rotate:
            cli.run_command(parse(words[2:]), tool=(), environ={},
                            cwd="/", isatty=False)
        rotate.assert_called_once_with("agent", dirs=mock.ANY)

    def test_only_an_autostarted_box_is_installed(self):
        """The workload's unit, the one `enter` starts, so a login starts
        the pod and the listeners the way `enter` would."""
        for name, text in self.units.items():
            with self.subTest(file=name):
                self.assertNotIn("[Install]", text)
        units = {p.name: t for p, t in render(
            self.box, self.settings._replace(autostart=True),
            None).items()}
        for name, text in units.items():
            with self.subTest(file=name, autostart=True):
                self.assertEqual(
                    _keys(text, "WantedBy"),
                    ["default.target"]
                    if name == "moathut-agent.container" else [])
                self.assertEqual(text.count("[Install]"),
                                 name == "moathut-agent.container")

    def test_the_pod_loads_the_rules_and_has_no_cgroup_or_host_names(self):
        self.assertEqual(_exec_words(self.pod, "ExecStartPost"),
                         [*self.settings.tool, "unit", "rules", "agent"])
        args = _keys(self.pod, "PodmanArgs")
        self.assertIn("--share-parent=false", args)
        self.assertIn("--hosts-file=image", args)
        self.assertEqual(_keys(self.pod, "Network"), ["pasta"])
        self.assertEqual(_keys(self.pod, "UserNS"), ["keep-id"])

    def test_the_workload_cannot_touch_its_namespace(self):
        """Root holds podman's default set at most, and the user nothing:
        podman gives the user what a unit adds, and root's set when the
        unit does not name the user."""
        dropped = set(_keys(self.work, "DropCapability"))
        self.assertEqual(dropped, set(ALL_CAPABILITIES) - set(CAPABILITIES))
        self.assertNotIn("NET_ADMIN", CAPABILITIES)
        self.assertNotIn("AddCapability", self.work)
        settings = self.settings._replace(uid=1001, gid=1002)
        work = container_unit(self.box, settings, None)
        self.assertEqual((_keys(work, "User"), _keys(work, "Group")),
                         (["1001"], ["1002"]))
        self.assertNotIn("PodmanArgs", self.work)
        self.assertNotIn("Network=", self.work)

    def test_the_workload_keeps_the_hosts_time_zone(self):
        self.assertEqual(_keys(self.work, "Timezone"), ["local"])

    def test_the_prompt_is_mounted_read_only(self):
        self.assertIn(f"{self.box.prompt}:{PROMPT_PATH}:ro,z",
                      _keys(self.work, "Volume"))

    def _prompted(self, ps1, times=1):
        script = Path(self.enterContext(
            tempfile.TemporaryDirectory())) / "prompt.sh"
        script.write_text(prompt(self.box))
        reads = f'. "{script}"; ' * times
        # bash unsets an inherited PS1 when it is not interactive.
        return subprocess.run(
            ["bash", "--norc", "-c", f'PS1=$P; {reads}printf %s "$PS1"'],
            env={"P": ps1, "PATH": "/usr/bin:/bin"}, capture_output=True,
            text=True, check=True).stdout

    def test_the_prompt_names_the_box_once(self):
        """The profile and the home's .bashrc both read it. Root's is
        red: a test run as root sees that instead."""
        colour = "1;31" if os.geteuid() == 0 else "35"
        want = f"\\[\\e[{colour}m\\][agent]\\[\\e[0m\\] [\\u]\\$ "
        self.assertEqual(self._prompted("[\\u]\\$ ", times=2), want)

    def test_a_shell_with_no_prompt_is_given_none(self):
        self.assertEqual(self._prompted(""), "")

    def test_every_capability_this_kernel_has_is_named(self):
        last = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
        self.assertGreaterEqual(len(ALL_CAPABILITIES), last + 1)
        self.assertEqual(len(set(ALL_CAPABILITIES)), len(ALL_CAPABILITIES))

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
        tool = len(self.settings.tool)
        self.assertEqual(words[:tool], list(self.settings.tool))
        args = parse(words[tool:])
        self.assertEqual((args.command, args.unit_command, args.name),
                         ("unit", "exec", "agent"))
        argv = [w.replace(netns.PID, "4242") for w in args.argv]
        self.assertEqual(argv[:2], interpreter(self.settings))
        listen = load_script("libexec/moat-netns-listen")
        return listen.parse_args(argv[2:])

    def test_the_inspector_is_handed_flags_its_parser_takes(self):
        launched = self._handed(self.inspect)
        self.assertEqual(launched.pid, 4242)
        self.assertFalse(launched.resolver)
        self.assertEqual(launched.command[:2], interpreter(self.settings))
        args = load_script("libexec/moat-inspect").parse_args(
            launched.command[2:])
        self.assertEqual(args.netns_pid, 4242)
        self.assertEqual(args.name, "agent")
        self.assertEqual(args.policy, str(self.box.policy))
        self.assertEqual(args.state_dir, str(self.box.state))
        self.assertEqual(args.record, str(self.box.record))

    def test_the_responder_is_handed_flags_its_parser_takes(self):
        launched = self._handed(self.resolve)
        self.assertEqual(launched.pid, 4242)
        self.assertTrue(launched.resolver)
        self.assertEqual(launched.command[:2], interpreter(self.settings))
        args = load_script("libexec/moat-resolve").parse_args(
            launched.command[2:])
        self.assertEqual(args.policy, str(self.box.policy))
        self.assertEqual(args.address, ANSWER)
        self.assertFalse(ipaddress.ip_address(args.address).is_loopback)

    def test_awkward_paths_survive_the_unit_files(self):
        box = Box("agent", user_dirs({"HOME": "/home/a b%c$d"}))
        settings = _settings("/home/a b%c$d",
                             pythonpath="/src/a b", tool=("/py", "/t x"))
        units = {p.name: t for p, t in render(box, settings, None).items()}
        pod = units["moathut-agent.pod"]
        self.assertEqual(_exec_words(pod, "ExecStartPost"),
                         ["/py", "/t x", "unit", "rules", "agent"])
        self.assertIn('Environment="PYTHONPATH=/src/a b"', pod)
        inspect = units["moathut-agent-inspect.service"]
        self.assertIn("/home/a b%c$d/.config/moatery/box/agent/policy.json",
                      _exec_words(inspect, "ExecStart"))
        work = units["moathut-agent.container"]
        self.assertIn(
            "\nVolume=/home/a b%%c$d/.local/share/moatery/box/agent/home:"
            "/home/a b%%c$d:z\n", work)


class TestCredentials(unittest.TestCase):
    """A credential is checked as its broker will check it, and a policy
    sends it to no host its `credential add` did not name."""

    def _describe(self, **over):
        values = dict(credential="k", hosts=["API.x.com:443", "api.x.com"],
                      env="K", auth_header="Authorization",
                      auth_format="Bearer {secret}", fiction="fake",
                      secret="sk-real", reserved=commands.RESERVED)
        values.update(over)
        return describe(values.pop("credential"), values.pop("hosts"),
                        values.pop("env"), values.pop("auth_header"),
                        values.pop("auth_format"), values.pop("fiction"),
                        values.pop("secret"), **values)

    def test_a_credential_is_described_with_its_hosts_normalised(self):
        c = self._describe()
        self.assertEqual(c.hosts, ("api.x.com",))
        self.assertEqual(Credential.from_json("k", c.to_json()), c)
        self.assertNotIn("sk-real", c.to_json())

    def test_what_its_broker_would_refuse_is_refused_here(self):
        cases = {"host name": dict(hosts=["*.x.com"]),
                 "needs a --host": dict(hosts=[]),
                 "variable": dict(env="1K"),
                 "may set": dict(env="SSL_CERT_FILE"),
                 "no {secret}": dict(auth_format="Bearer"),
                 "empty": dict(secret=""),
                 "byte-identical": dict(fiction="sk-real"),
                 "not a header name": dict(auth_header="a b"),
                 "U\\+000A": dict(secret="sk\nreal"),
                 "credential's id": dict(credential="../k")}
        for words, over in cases.items():
            with self.subTest(words), \
                    self.assertRaisesRegex(CredentialError, words):
                self._describe(**over)

    def _brokering(self, entries, *held):
        held = {c.id: c for c in held}

        def load(credential):
            if credential not in held:
                raise CredentialError(f"no credential {credential}")
            return held[credential]
        return brokering(_policy(self, entries, ["pypi.org"]), load)

    def test_a_policy_with_no_credential_has_no_broker(self):
        self.assertIsNone(self._brokering([{"host": "api.x.com"}]))

    def test_the_broker_holds_what_the_policy_brokers_among_its_hosts(self):
        a = _credential("a", ["api.a.com", "up.a.com"], "A")
        b = _credential("b", ["api.b.com"], "B")
        broker = self._brokering([
            {"host": "*.a.com", "paths": ["/v1/*"], "credential": "a"},
            {"host": "api.b.com", "credential": "b"}], a, b)
        self.assertEqual(broker.hosts, (("api.a.com", "a"),
                                        ("up.a.com", "a"),
                                        ("api.b.com", "b")))
        self.assertEqual(broker.credentials, (a, b))

    def test_a_host_the_credential_does_not_name_is_refused(self):
        with self.assertRaisesRegex(CredentialError, "for api.a.com only"):
            self._brokering([{"host": "evil.example", "credential": "a"}],
                            _credential("a", ["api.a.com"]))

    def test_a_credential_an_earlier_entry_takes_every_host_of(self):
        a = _credential("a", ["api.x.com"], "A")
        b = _credential("b", ["api.x.com"], "B")
        with self.assertRaisesRegex(CredentialError, "earlier entry"):
            self._brokering([{"host": "api.x.com", "credential": "a"},
                             {"host": "api.x.com", "credential": "b"}], a, b)

    def test_two_credentials_may_not_set_one_variable(self):
        with self.assertRaisesRegex(CredentialError, "both set K"):
            self._brokering([{"host": "api.a.com", "credential": "a"},
                             {"host": "api.b.com", "credential": "b"}],
                            _credential("a", ["api.a.com"], "K"),
                            _credential("b", ["api.b.com"], "K"))

    def test_an_unknown_credential_is_refused(self):
        with self.assertRaisesRegex(CredentialError, "no credential a"):
            self._brokering([{"host": "api.a.com", "credential": "a"}])


class TestBrokerUnits(unittest.TestCase):
    """A box whose policy names credentials has a broker, which the
    inspector waits for and dials, and whose credentials are the ones
    systemd loads for it."""

    def setUp(self):
        self.dirs = user_dirs({"HOME": "/home/u",
                               "XDG_RUNTIME_DIR": "/run/user/1000"})
        self.box = Box("agent", self.dirs)
        self.settings = _settings("/home/u")
        a = _credential("a", ["api.a.com"], "A_KEY")
        b = _credential("b", ["api.b.com", "up.b.com"], "B_KEY")
        self.broker = Broker((("api.a.com", "a"), ("up.b.com", "b")), (a, b))
        self.units = {p.name: t for p, t in render(
            self.box, self.settings, self.broker).items()}
        self.inspect = self.units["moathut-agent-inspect.service"]
        self.work = self.units["moathut-agent.container"]
        self.unit = self.units["moathut-agent-broker.service"]

    def test_every_unit_named_is_one_the_box_provides(self):
        for name, text in self.units.items():
            for key in DEPENDENCIES:
                for unit in _keys(text, key):
                    with self.subTest(file=name, key=key, unit=unit):
                        self.assertIn(unit, self.box.services)

    def test_the_inspector_waits_for_the_broker_and_does_not_need_it(self):
        """Wants=, not Requires=: a broker restarted for a new key would
        restart the inspector, and the inspector the workload."""
        self.assertIn(self.box.broker_service, _keys(self.inspect, "Wants"))
        self.assertIn(self.box.broker_service, _keys(self.inspect, "After"))
        self.assertNotIn(self.box.broker_service,
                         _keys(self.inspect, "Requires"))
        self.assertEqual(_keys(self.unit, "Type"), ["notify"])
        self.assertNotIn("[Install]", self.unit)

    def test_the_broker_is_not_bound_to_the_pod(self):
        """A restart of the pod is a new namespace, which is nothing to the
        broker; and systemd leaves a credentialed unit it stops while it
        starts unable to start again."""
        for key in ("PartOf", "BindsTo", "Requires", "After"):
            self.assertEqual(_keys(self.unit, key), [], key)

    def test_the_inspector_dials_the_socket_the_broker_binds(self):
        broker = load_script("libexec/moat-broker").parse_args(
            _exec_words(self.unit, "ExecStart")[2:])
        words = [w.replace(netns.PID, "4242")
                 for w in _exec_words(self.inspect, "ExecStart")]
        command = words[words.index("--", words.index("--") + 1) + 1:]
        self.assertEqual(command[:2], interpreter(self.settings))
        inspect = load_script("libexec/moat-inspect").parse_args(
            command[2:])
        self.assertEqual(broker.listen, f"unix:{self.box.broker_socket}")
        self.assertEqual(inspect.broker, str(self.box.broker_socket))
        self.assertEqual(broker.caller_uid, self.settings.uid)
        (runtime,) = _keys(self.unit, "RuntimeDirectory")
        self.assertEqual(self.dirs.runtime / runtime,
                         self.box.broker_socket.parent)

    def test_the_broker_loads_each_credential_its_hosts_name(self):
        """It reads $CREDENTIALS_DIRECTORY/ID for each --host's ID."""
        broker = load_script("libexec/moat-broker").parse_args(
            _exec_words(self.unit, "ExecStart")[2:])
        self.assertEqual(broker.host, ["api.a.com=a", "up.b.com=b"])
        loaded = dict(v.split(":", 1)
                      for v in _keys(self.unit, "LoadCredentialEncrypted"))
        self.assertEqual(loaded, {c: str(sealed(self.dirs, c))
                                  for c in ("a", "b")})
        self.assertIn("a=moatery-placeholder-a", broker.placeholder)
        self.assertIn("b=x-api-key", broker.auth_header)

    def test_the_workload_holds_each_placeholder(self):
        env = _keys(self.work, "Environment")
        self.assertIn("A_KEY=moatery-placeholder-a", env)
        self.assertIn("B_KEY=moatery-placeholder-b", env)

    def test_a_box_without_credentials_has_no_broker(self):
        units = render(self.box, self.settings, None)
        self.assertNotIn(self.box.broker_file, units)
        inspect = units[self.box.inspect_file]
        self.assertNotIn("broker", inspect)


class TestRules(unittest.TestCase):
    def test_the_rules_are_the_netns_placements(self):
        design = DESIGN.read_text().split(
            "## Netns:", 1)[1].split("\n## ", 1)[0]
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
        runner, _ = self._runner({"netdev moatery": (1, "")})
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


class TestAllowDocument(unittest.TestCase):
    """allow widens and never narrows: whatever the policy permitted, the
    new one permits too, and it permits what was asked."""

    DOC = {"tls": "inspect", "hosts": ["pypi.org", "*.github.com"],
           "splice": [],
           "policy": [{"host": "api.x", "methods": ["POST"],
                       "paths": ["/v1/*"], "credential": "k"},
                      {"host": "api.y", "methods": ["GET"]}]}

    def _load(self, doc):
        path = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (path / "p.json").write_text(document.dumps(doc))
        return load_policy(path / "p.json")

    def _allow(self, host, methods=(), paths=()):
        before = self._load(self.DOC)
        doc = document.allow(self.DOC, before, document.host_name(host),
                             methods, paths)
        if doc is None:
            return None, before
        after = self._load(doc)
        for probe in (("pypi.org", "GET", "/x"), ("a.github.com", "PUT", "/"),
                      ("api.x", "POST", "/v1/m"), ("api.y", "GET", "/z")):
            with self.subTest(still=probe):
                self.assertTrue(after.permits(*probe))
        return doc, after

    def test_a_new_host_is_listed(self):
        doc, after = self._allow("Example.COM.")
        self.assertEqual(doc["hosts"][-1], "example.com")
        self.assertEqual(doc["policy"], self.DOC["policy"])
        self.assertTrue(after.permits("example.com", "DELETE", "/any"))

    def test_a_new_host_with_a_method_or_path_is_an_entry(self):
        doc, after = self._allow("example.com", ["get"], ["/a/*"])
        self.assertEqual(doc["policy"][-1], {"host": "example.com",
                                             "methods": ["GET"],
                                             "paths": ["/a/*"]})
        self.assertTrue(after.permits("example.com", "GET", "/a/b"))
        self.assertFalse(after.permits("example.com", "POST", "/a/b"))

    def test_a_listed_host_is_allowed_already(self):
        """An entry for it would restrict it to the entry."""
        for host, methods in (("pypi.org", ()), ("pypi.org", ["POST"]),
                              ("a.github.com", ())):
            with self.subTest(host=host, methods=methods):
                self.assertIsNone(self._allow(host, methods)[0])

    def test_a_governed_host_takes_another_entry_and_not_hosts(self):
        doc, after = self._allow("api.y", ["POST"], ["/up"])
        self.assertEqual(doc["hosts"], self.DOC["hosts"])
        self.assertTrue(after.permits("api.y", "POST", "/up"))
        self.assertFalse(after.permits("api.y", "POST", "/down"))
        with self.assertRaisesRegex(document.AllowRefused, "--method"):
            self._allow("api.y")
        self.assertIsNone(self._allow("api.y", ["get"])[0])

    def test_a_brokered_host_takes_paths_or_nothing(self):
        """Its key is sent with every request an entry for it permits."""
        with self.assertRaisesRegex(document.AllowRefused,
                                    "brokered with k"):
            self._allow("api.x", ["GET"])
        doc, after = self._allow("api.x", ["GET"], ["/v1/models"])
        self.assertTrue(after.permits("api.x", "GET", "/v1/models"))
        self.assertEqual(after.credential_for("api.x"), "k")

    def test_what_is_not_a_name_or_a_path(self):
        for host in ("*.example.com", "a b", "", "ex[am]ple.com"):
            with self.subTest(host=host), \
                    self.assertRaises(document.AllowRefused):
                document.host_name(host)
        with self.assertRaisesRegex(document.AllowRefused, "begins with /"):
            self._allow("example.com", paths=["v1/x"])


def _line(**fields):
    doc = dict.fromkeys(("ts", "host", "method", "path", "decision",
                         "reason", "status", "credential"))
    doc.update(ts="2026-09-30T01:02:03.456Z", mode="terminate", **fields)
    return doc


class TestRecordRotation(unittest.TestCase):
    def setUp(self):
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.dir / "requests.log"

    def _write(self, n):
        # As the inspector creates it.
        self.path.write_text(json.dumps(_line(host=f"h{n}")) + "\n")
        self.path.chmod(0o600)

    def test_a_record_under_its_size_stays(self):
        self._write(0)
        self.assertFalse(record.rotate(self.path, max_bytes=1 << 20))
        self.assertFalse(record.rotate(self.dir / "none", max_bytes=0))
        self.assertEqual(record.records(self.path), [self.path])

    def test_rotations_keep_the_newest_and_compress_the_rest(self):
        """Every rotated record read back, the oldest first; the newest is
        left as the inspector may still be writing its last line."""
        for n in range(record.KEEP + 3):
            self._write(n)
            self.assertTrue(record.rotate(self.path, max_bytes=1))
        self._write(record.KEEP + 3)
        files = record.records(self.path)
        self.assertEqual([p.name for p in files], [
            "requests.log.4.gz", "requests.log.3.gz", "requests.log.2.gz",
            "requests.log.1", "requests.log"])
        self.assertEqual(
            [doc["host"] for p in files for doc in record.lines(p)],
            ["h3", "h4", "h5", "h6", "h7"])
        for p in files:
            self.assertEqual(p.stat().st_mode & 0o777, 0o600, p)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()),
                         sorted(p.name for p in files))


class TestRecordReading(unittest.TestCase):
    def test_a_line_as_a_person_reads_it(self):
        self.assertEqual(
            record.format_line(_line(host="api.x", method="POST",
                                     path="/v1/m", decision="forward",
                                     status=200, credential="k")),
            "2026-09-30T01:02:03.456Z  forward 200  POST    api.x/v1/m  [k]")
        self.assertEqual(
            record.format_line(_line(host="evil.example", decision="drop",
                                     status=403,
                                     reason="not allowlisted")),
            "2026-09-30T01:02:03.456Z  drop    403  terminate "
            "evil.example  (not allowlisted)")
        self.assertEqual(
            record.format_line(_line(host="evil.example", decision="drop",
                                     status=421, method="GET", path="/",
                                     reason=DROP_MISDIRECTED)),
            "2026-09-30T01:02:03.456Z  drop    421  GET     evil.example/  "
            "(host does not match the server name)  suspect")

    def test_the_refusals_the_policy_still_makes(self):
        """A refusal the policy no longer makes is not one to act on."""
        policy = _policy(self, [{"host": "api.y", "methods": ["GET"]}],
                         hosts=["now.listed"])
        docs = [_line(host="evil.example", decision="drop",
                      reason="not allowlisted")] * 3 + [
            _line(host="now.listed", decision="drop",
                  reason="not allowlisted"),
            _line(host="api.y", method="POST", path="/p", decision="drop",
                  reason="not permitted by policy"),
            _line(host="api.y", method="GET", path="/p", decision="drop",
                  reason="not permitted by policy"),
            _line(host=None, decision="drop", reason="not TLS"),
            _line(host="pypi.org", decision="forward", status=200)]
        self.assertEqual(record.refusals(docs, policy), [
            (3, "evil.example", "not allowlisted", ""),
            (1, "-", "not TLS", ""),
            (1, "api.y", "not permitted by policy", "POST /p")])

    def test_the_names_no_list_admits(self):
        policy = _policy(self, [], hosts=["pypi.org"])
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        status = tmp / "resolve-status.json"
        self.assertEqual(record.unlisted(status, policy), [])
        status.write_text(json.dumps({"unlisted_names": {
            "a.example": 2, "pypi.org": 1, "b.example": 5}}))
        self.assertEqual(record.unlisted(status, policy),
                         [(5, "b.example"), (2, "a.example")])

    def test_follow_shows_the_last_lines_then_new_ones_and_rotations(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = tmp / "requests.log"
        old = [_line(host=f"h{i}.example", decision="forward", status=200)
               for i in range(5)]
        path.write_text("".join(json.dumps(d) + "\n" for d in old))
        seen, steps = [], []

        def pause(_interval):
            steps.append(len(seen))
            if len(steps) == 1:
                with path.open("a") as f:
                    f.write(json.dumps(_line(host="new.example")) + "\n")
                    f.write('{"half')
            elif len(steps) == 2:
                # Renamed away, and a new record already longer than the
                # old one was when read.
                path.rename(tmp / "requests.log.1")
                path.write_text("".join(
                    json.dumps(_line(host=f"r{i}.example")) + "\n"
                    for i in range(9)))
            elif len(steps) == 3:
                # Truncated where it is.
                path.write_text(json.dumps(_line(host="cut.example")) + "\n")
            else:
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            record.follow(path, seen.append, last=2, pause=pause)
        self.assertEqual([line.split()[4] for line in seen],
                         ["h3.example", "h4.example", "new.example"]
                         + [f"r{i}.example" for i in range(9)]
                         + ["cut.example"])


class FakeHost:
    """podman, systemctl and moat-mint-ca, as far as the commands ask."""

    def __init__(self, state_root, rules=True, load_state="loaded",
                 unshare=True, broker=True, broker_state="active",
                 listeners=True, listener_state="active", dirs=None,
                 reloads=True):
        self.calls = []
        self.inputs = []
        self.state_root = state_root
        self.rules = rules
        self.load_state = load_state
        self.unshare = unshare
        self.broker = broker
        self.broker_state = broker_state
        self.listeners = listeners
        self.listener_state = listener_state
        # With the dirs, a reload of an inspector writes the digest of its
        # box's policy to its status file, as the inspector does.
        self.dirs = dirs
        self.reloads = reloads

    def __call__(self, argv, *, input=None, check=True, env=None):
        self.calls.append(argv)
        self.inputs.append(input)
        line = " ".join(argv)
        code, out = 0, ""
        if argv[:3] in (["podman", "container", "exists"],
                        ["podman", "pod", "exists"]):
            code = 1
        elif argv[:3] == ["systemd-creds", "--user", "encrypt"]:
            Path(argv[-1]).write_text("SEALED\n")
        elif argv[:3] == ["systemctl", "--user", "start"] and \
                argv[-1].endswith("-broker.service"):
            code = 0 if self.broker else 1
        elif argv[:3] == ["systemctl", "--user", "is-active"] and \
                argv[-1].endswith("-broker.service"):
            out = self.broker_state + "\n"
        elif argv[:3] == ["systemctl", "--user", "is-active"] and \
                argv[-1].endswith(("-inspect.service", "-resolve.service")):
            out = self.listener_state + "\n"
        elif argv[:3] == ["systemctl", "--user", "try-restart"] or (
                argv[:3] == ["systemctl", "--user", "start"] and argv[-1]
                .endswith(("-inspect.service", "-resolve.service"))):
            code = 0 if self.listeners else 1
        elif argv[:3] == ["systemctl", "--user", "reload"] and \
                argv[-1].endswith("-inspect.service"):
            if self.dirs and self.reloads:
                box = Box(argv[-1].removeprefix("moathut-")
                          .removesuffix("-inspect.service"), self.dirs)
                box.status.write_text(json.dumps({
                    INSPECT_DIGEST_KEY:
                        inspect_policy_digest(box.policy.read_text())}))
        elif "moat-mint-ca" in line:
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
        elif argv[:4] == ["podman", "unshare", "rm", "-rf"] and self.unshare:
            shutil.rmtree(argv[-1], ignore_errors=True)
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

    def _create(self, name="agent", host=None, policy=None, mounts=(),
                autostart=False):
        host = host or FakeHost(self.home)
        box = commands.create(
            name, policy or self.policy, "img", list(mounts),
            dirs=self.dirs, tool=("/py", "/cb"), python="/py",
            libexec="/lx", pythonpath=None, uid=1000, gid=1000,
            cwd=self.home, environ=self.env, autostart=autostart,
            runner=host)
        return box, host

    def test_autostart_is_kept_and_rendered(self):
        """Kept in box.json, since `policy` and `credential add` write the
        units again; a box.json from before it was a setting reads as
        off."""
        box, _ = self._create(autostart=True)
        self.assertTrue(
            Settings.from_json(box.settings.read_text()).autostart)
        self.assertIn("WantedBy=default.target",
                      box.container_file.read_text())
        rows = commands.ls(dirs=self.dirs, runner=FakeHost(self.home))
        self.assertEqual(rows[0][3:], ("autostart",))
        doc = json.loads(box.settings.read_text())
        del doc["autostart"]
        self.assertFalse(Settings.from_json(json.dumps(doc)).autostart)

    def test_the_ca_is_minted_with_the_user_site_off(self):
        """The mint runs as the user, like every program a box starts;
        units.interpreter says why the flag."""
        _, host = self._create()
        (mint,) = [a for a in host.calls if "moat-mint-ca" in " ".join(a)]
        self.assertEqual(mint[:3], ["/py", "-s", "/lx/moat-mint-ca"])

    def test_the_units_call_moathut_with_the_user_site_off(self):
        from moathut import cli
        with mock.patch.object(cli, "run_command",
                               return_value=0) as run_command:
            cli.main(["/opt/cb/moathut", "ls"], environ=self.env)
        tool = run_command.call_args.kwargs["tool"]
        self.assertEqual(tool[1:], ("-s", "/opt/cb/moathut"))

    def test_the_command_line_hands_autostart_on(self):
        from moathut import cli
        for words, want in ((["--autostart"], True), ([], False)):
            args = parse(["create", "agent", "--policy", "p", *words])
            with mock.patch.object(cli, "create") as create, \
                    mock.patch("sys.stdout"):
                cli.run_command(args, tool=(), environ=self.env,
                                cwd=self.home, isatty=False)
            self.assertIs(create.call_args.kwargs["autostart"], want)

    def test_create_lays_the_box_out(self):
        box, host = self._create(mounts=["projects/p"])
        for path in box.unit_files:
            if path != box.broker_file:
                self.assertTrue(path.is_file(), path)
        self.assertFalse(box.broker_file.exists())
        self.assertEqual(box.policy.read_text(), self.policy.read_text())
        self.assertEqual(box.policy.stat().st_mode & 0o777, 0o600)
        self.assertEqual(box.bundle.read_text(), "BOX CA\nSYSTEM CAS\n")
        self.assertTrue(box.home.is_dir())
        self.assertTrue((box.home / "projects" / "p").is_dir())
        settings = Settings.from_json(box.settings.read_text())
        self.assertEqual(settings.trust_path, TRUST)
        self.assertEqual(settings.mounts[0].source,
                         self.home / "projects" / "p")
        self.assertIn(["systemctl", "--user", "daemon-reload"], host.calls)

    def test_create_gives_a_new_home_a_bashrc_that_reads_the_prompt(self):
        box, _ = self._create()
        self.assertEqual(box.prompt.read_text(), prompt(box))
        lines = (box.home / ".bashrc").read_text().splitlines()
        self.assertEqual(lines, [
            "[ -f /etc/bashrc ] && . /etc/bashrc",
            f"[ -f {PROMPT_PATH} ] && . {PROMPT_PATH}"])

    def test_a_bashrc_the_home_has_is_kept(self):
        kept = Box("agent", self.dirs).home
        kept.mkdir(parents=True)
        (kept / ".bashrc").write_text("mine\n")
        self._create()
        self.assertEqual((kept / ".bashrc").read_text(), "mine\n")

    def test_a_box_from_before_the_prompt_gains_it_when_written_again(self):
        """Its workload's unit is written again, so the file it mounts
        is."""
        box, _ = self._create()
        box.prompt.unlink()
        box.container_file.write_text("from before the prompt\n")
        commands.allow("agent", "example.com", methods=[], paths=[],
                       dirs=self.dirs, runner=self._host(), pause=self.fail)
        self.assertEqual(box.prompt.read_text(), prompt(box))

    def test_a_dry_run_writes_nothing_and_says_what_create_would(self):
        written = commands.create(
            "agent", self.policy, "img", ["projects/p"], dirs=self.dirs,
            tool=("/py", "/cb"), python="/py", libexec="/lx",
            pythonpath=None, uid=1000, gid=1000, cwd=self.home,
            environ=self.env, dry_run=True, runner=(host := FakeHost(
                self.home)))
        box = Box("agent", self.dirs)
        self.assertFalse(box.config.exists())
        self.assertFalse(box.share.exists())
        self.assertFalse(any(p.exists() for p in box.unit_files))
        self.assertFalse([c for c in host.calls if c[0] == "systemctl"
                          or "moat-mint-ca" in " ".join(c)])
        self._create(mounts=["projects/p"])
        self.assertEqual(written, {p: p.read_text() for p in written})
        self.assertIn(box.prompt, written)

    def test_the_command_line_prints_a_dry_run(self):
        from moathut import cli
        args = parse(["create", "agent", "--policy", "p", "--dry-run"])
        files = {Path("/u/a.pod"): "[Pod]\n", Path("/u/p.sh"): "x\n"}
        with mock.patch.object(cli, "create", return_value=files) as create, \
                mock.patch("builtins.print") as printed:
            cli.run_command(args, tool=(), environ=self.env, cwd=self.home,
                            isatty=False)
        self.assertIs(create.call_args.kwargs["dry_run"], True)
        self.assertEqual([c.args[0] for c in printed.call_args_list],
                         ["# /u/a.pod\n[Pod]\n", "# /u/p.sh\nx\n"])

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
                 "no credential k": dict(name="c", policy=brokered),
                 "home directory": dict(name="d", mounts=[str(self.home)]),
                 "would cover /etc/profile.d": dict(
                     name="e", mounts=["projects/p:/etc/profile.d"])}
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
                       "moathut-agent.service"], host.calls)
        (argv,) = ran
        self.assertEqual(argv[:4], ["podman", "exec", "-i", "-t"])
        self.assertEqual(argv[argv.index("--user") + 1], "1000:1000")
        self.assertEqual(argv[argv.index("--workdir") + 1],
                         str(self.home / "projects" / "p"))
        self.assertIn("TERM", argv)
        self.assertEqual(argv[-3:], ["agent", "/bin/bash", "-l"])

    def test_enter_refuses_a_box_without_its_rules(self):
        self._create()
        with self.assertRaisesRegex(commands.BoxError, "no moatery rules"):
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
        self._create()
        with self.assertRaisesRegex(commands.BoxError, "home is not"):
            commands.rm("agent", home=True, dirs=self.dirs,
                        runner=FakeHost(self.home, unshare=False))

    def test_ls_lists_each_box_and_its_state(self):
        self._create("a")
        self._create("b")
        rows = commands.ls(dirs=self.dirs, runner=FakeHost(self.home))
        self.assertEqual([r[0] for r in rows], ["a", "b"])

    def test_what_follows_the_first_separator_is_the_command(self):
        args = parse(["enter", "agent", "--root", "--", "id", "--root",
                      "--", "x"])
        self.assertEqual((args.name, args.root), ("agent", True))
        self.assertEqual(args.argv, ["id", "--root", "--", "x"])
        self.assertEqual(parse(["enter", "agent"]).argv, [])
        with mock.patch("sys.stderr"):
            for words in (["stop", "agent", "--", "x"], ["enter", "a", "x"]):
                with self.subTest(words), self.assertRaises(SystemExit):
                    parse(words)

    def _add(self, credential="k", secret="sk-real", host=None, **over):
        values = dict(hosts=["api.x"], env="K", auth_header="Authorization",
                      auth_format="Bearer {secret}")
        values.update(over)
        host = host or FakeHost(self.home)
        return commands.credential_add(credential, secret, dirs=self.dirs,
                                       runner=host, **values), host

    def _brokered(self, name="brokered.json", host="api.x"):
        path = self.policy.with_name(name)
        path.write_text(json.dumps({"policy": [
            {"host": host, "paths": ["/v1/*"], "credential": "k"}]}))
        return path

    def test_a_secret_is_sealed_by_its_standard_input(self):
        (boxes, _), host = self._add(secret="sk-real\n")
        (argv,) = [c for c in host.calls if c[0] == "systemd-creds"]
        self.assertEqual(argv, ["systemd-creds", "--user", "encrypt",
                                "--name=k", "-", argv[-1]])
        self.assertEqual(host.inputs[host.calls.index(argv)], "sk-real")
        self.assertFalse([c for c in host.calls if "sk-real" in " ".join(c)])
        self.assertEqual(sealed(self.dirs, "k").stat().st_mode & 0o777,
                         0o600)
        self.assertNotIn("sk-real", described(self.dirs, "k").read_text())
        self.assertEqual(boxes, [])
        self.assertEqual(commands.credential_ls(dirs=self.dirs),
                         [("k", "K", "api.x", "-")])

    def test_a_new_credential_needs_its_hosts_and_variable(self):
        with self.assertRaisesRegex(commands.BoxError, "needs --host"):
            self._add(hosts=[])
        with self.assertRaisesRegex(commands.BoxError, "no {secret}"):
            self._add(auth_format="Bearer")
        self.assertFalse(credentials_root(self.dirs).exists())

    def test_a_box_naming_a_credential_has_a_broker_holding_it(self):
        self._add()
        box, _ = self._create(policy=self._brokered())
        self.assertTrue(box.broker_file.is_file())
        unit = box.broker_file.read_text()
        self.assertIn(f"LoadCredentialEncrypted=k:{sealed(self.dirs, 'k')}",
                      unit)
        placeholder = json.loads(
            described(self.dirs, "k").read_text())["placeholder"]
        self.assertIn(f"Environment=K={placeholder}",
                      box.container_file.read_text())
        self.assertNotIn("sk-real", unit + box.container_file.read_text())
        self.assertEqual(commands.credential_ls(dirs=self.dirs),
                         [("k", "K", "api.x", "agent")])

    def test_create_refuses_a_credential_sent_where_it_was_not_added_for(
            self):
        self._add()
        with self.assertRaisesRegex(commands.BoxError, "for api.x only"):
            self._create(policy=self._brokered(host="evil.example"))
        env = {k: v for k, v in self.env.items() if k != "XDG_RUNTIME_DIR"}
        self.dirs = user_dirs(env)
        with self.assertRaisesRegex(commands.BoxError, "XDG_RUNTIME_DIR"):
            self._create(policy=self._brokered())
        self.assertFalse(Box("agent", self.dirs).config.exists())

    def test_a_credential_added_again_is_replaced_in_each_box(self):
        """Its secret, and what is given; the placeholder stays. The box's
        broker is restarted, and the workload's unit written again."""
        self._add()
        box, _ = self._create(policy=self._brokered())
        before = json.loads(described(self.dirs, "k").read_text())
        (boxes, moved), host = self._add(secret="sk-new", hosts=[],
                                         env="K2", auth_header=None,
                                         auth_format=None)
        after = json.loads(described(self.dirs, "k").read_text())
        self.assertEqual((boxes, moved), (["agent"], True))
        self.assertEqual(after, {**before, "env": "K2"})
        self.assertIn(f"K2={before['placeholder']}",
                      box.container_file.read_text())
        start = ["systemctl", "--user", "start", box.broker_service]
        self.assertLess(
            host.calls.index(["systemctl", "--user", "daemon-reload"]),
            host.calls.index(["systemctl", "--user", "stop",
                              box.broker_service]))
        self.assertLess(
            host.calls.index(["systemctl", "--user", "reset-failed",
                              box.broker_service]), host.calls.index(start))
        host = FakeHost(self.home, broker_state="inactive")
        self._add(secret="sk-newer", hosts=[], env=None, host=host)
        self.assertNotIn(start, host.calls)
        with self.assertRaisesRegex(commands.BoxError,
                                    "broker of agent did not start"):
            self._add(secret="sk-newest", hosts=[], env=None,
                      host=FakeHost(self.home, broker=False))

    def test_a_replacement_a_box_could_not_hold_changes_nothing(self):
        self._add()
        self._create(policy=self._brokered())
        before = described(self.dirs, "k").read_text()
        with self.assertRaisesRegex(commands.BoxError,
                                    "box agent: .*for api.y only"):
            self._add(hosts=["api.y"])
        self.assertEqual(described(self.dirs, "k").read_text(), before)

    def test_a_credential_a_box_names_is_not_removed(self):
        self._add()
        self._create(policy=self._brokered())
        with self.assertRaisesRegex(commands.BoxError, "named by"):
            commands.credential_rm("k", dirs=self.dirs)
        commands.rm("agent", home=True, dirs=self.dirs,
                    runner=FakeHost(self.home))
        commands.credential_rm("k", dirs=self.dirs)
        self.assertEqual(list(credentials_root(self.dirs).iterdir()), [])
        with self.assertRaisesRegex(commands.BoxError, "no credential"):
            commands.credential_rm("k", dirs=self.dirs)

    def test_enter_starts_a_stopped_broker_and_says_if_it_did_not(self):
        self._add()
        self._create(policy=self._brokered())
        for works in (True, False):
            host, ran, said = FakeHost(self.home, broker=works), [], []
            commands.enter("agent", ["id"], root=False, dirs=self.dirs,
                           cwd=self.home, environ=self.env, isatty=False,
                           runner=host, execvp=lambda f, a: ran.append(a),
                           warn=said.append)
            with self.subTest(works=works):
                self.assertIn(["systemctl", "--user", "start",
                               "moathut-agent-broker.service"],
                              host.calls)
                self.assertEqual(len(ran), 1)
                self.assertEqual(bool(said), not works)

    def test_stop_and_rm_stop_the_broker(self):
        self._add()
        box, _ = self._create(policy=self._brokered())
        host = FakeHost(self.home)
        commands.stop("agent", dirs=self.dirs, runner=host)
        commands.rm("agent", home=False, dirs=self.dirs, runner=host)
        stops = [c for c in host.calls if c[:3] == ["systemctl", "--user",
                                                    "stop"]]
        self.assertEqual(len(stops), 2)
        for argv in stops:
            self.assertEqual(argv[3:], [box.pod_service, box.broker_service])
        self.assertFalse(box.broker_file.exists())
        self._create()
        host = FakeHost(self.home)
        commands.stop("agent", dirs=self.dirs, runner=host)
        self.assertIn(["systemctl", "--user", "stop", box.pod_service],
                      host.calls)

    def test_enter_clears_what_a_stop_while_starting_left(self):
        """A broker that is not active, which after a failed start is
        `activating` while it waits to restart; before the start that
        would fail on it; and a workspace left read-only."""
        self._add()
        box, _ = self._create(policy=self._brokered())
        left = (self.dirs.runtime / "systemd" / "temporary-credentials"
                / box.broker_service)
        for state, cleared in (("failed", True), ("inactive", True),
                               ("activating", True), ("active", False)):
            left.mkdir(parents=True, exist_ok=True)
            (left / "k").write_text("SECRET")
            left.chmod(0o500)
            self.addCleanup(lambda: left.exists() and left.chmod(0o700))
            host = FakeHost(self.home, broker_state=state)
            commands.enter("agent", ["id"], root=False, dirs=self.dirs,
                           cwd=self.home, environ=self.env, isatty=False,
                           runner=host, execvp=lambda f, a: None,
                           warn=lambda m: None)
            with self.subTest(state=state):
                self.assertEqual(not left.exists(), cleared)
                stop = ["systemctl", "--user", "stop", box.broker_service]
                reset = ["systemctl", "--user", "reset-failed",
                         box.broker_service]
                start = ["systemctl", "--user", "start", box.service]
                self.assertEqual(reset in host.calls, cleared)
                self.assertEqual(stop in host.calls, cleared)
                if cleared:
                    self.assertLess(host.calls.index(stop),
                                    host.calls.index(reset))
                    self.assertLess(host.calls.index(reset),
                                    host.calls.index(start))

    def test_the_command_line_takes_a_credential(self):
        args = parse(["credential", "add", "k", "--host", "a", "--host",
                      "b", "--env", "K"])
        self.assertEqual((args.credential_command, args.id, args.host,
                          args.env, args.auth_header),
                         ("add", "k", ["a", "b"], "K", None))

    def test_the_secret_is_read_from_a_pipe_or_asked_for(self):
        """Asked without echo at a terminal; never an argument."""
        from moathut import cli
        pipe = mock.Mock(isatty=lambda: False, read=lambda: "sk-piped\n")
        self.assertEqual(cli._secret("k", pipe), "sk-piped\n")
        tty = mock.Mock(isatty=lambda: True)
        with mock.patch.object(cli.getpass, "getpass",
                               return_value="sk-typed") as asked:
            self.assertEqual(cli._secret("k", tty), "sk-typed")
        asked.assert_called_once_with("k: ")

    def test_credential_add_says_which_boxes_hold_it(self):
        from moathut import cli
        args = parse(["credential", "add", "k"])
        stdin = mock.Mock(isatty=lambda: False, read=lambda: "sk-new")
        with mock.patch.object(cli, "credential_add",
                               return_value=(["a", "b"], True)) as added, \
                mock.patch("sys.stdout") as out:
            cli.run_credential(args, dirs=self.dirs, stdin=stdin)
        self.assertEqual(added.call_args.args, ("k", "sk-new"))
        said = "".join(c.args[0] for c in out.write.call_args_list)
        self.assertIn("credential k sealed", said)
        self.assertIn("box b: its broker holds it; the new variable", said)

    def test_the_command_line_reports_a_refusal_and_exits_1(self):
        with mock.patch("sys.stderr") as err:
            code = main(["moathut", "stop", "nosuch"], environ=self.env)
        self.assertEqual(code, 1)
        self.assertIn("no box nosuch",
                      "".join(c.args[0] for c in err.write.call_args_list))

    def _restarts(self, host):
        return [c for c in host.calls if c[:3] == ["systemctl", "--user",
                                                   "try-restart"]]

    def _reloads(self, host):
        return [c[-1] for c in host.calls
                if c[:3] == ["systemctl", "--user", "reload"]]

    def _host(self, **kwargs):
        return FakeHost(self.home, dirs=self.dirs, **kwargs)

    def test_allow_reloads_the_listeners_and_restarts_nothing(self):
        box, _ = self._create()
        host = self._host()
        self.assertEqual(commands.allow("agent", "Example.com", methods=[],
                                        paths=[], dirs=self.dirs,
                                        runner=host, pause=self.fail),
                         commands.Applied(True))
        self.assertIn("example.com", json.loads(box.policy.read_text())[
            "hosts"])
        self.assertEqual(box.policy.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self._reloads(host), [box.resolve_service,
                                               box.inspect_service])
        self.assertEqual(self._restarts(host), [])
        for argv in host.calls:
            self.assertNotIn(box.service, argv)
            self.assertNotIn(box.pod_service, argv)
        self.assertEqual(sorted(p.name for p in box.config.iterdir()),
                         ["box.json", "bundle.pem", "policy.json",
                          "prompt.sh"])

    def test_allow_on_a_stopped_box_applies_from_its_next_start(self):
        box, _ = self._create()
        host = self._host(listener_state="inactive")
        self.assertEqual(commands.allow("agent", "example.com", methods=[],
                                        paths=[], dirs=self.dirs,
                                        runner=host),
                         commands.Applied(False))
        self.assertIn("example.com", box.policy.read_text())
        self.assertEqual(self._restarts(host), [])
        self.assertEqual(self._reloads(host), [])

    def test_an_inspector_that_does_not_take_the_reload_is_restarted(self):
        """Its status file names the document it enforces; one that still
        names the old after the wait is restarted, and read at start."""
        box, _ = self._create()
        host, waits = self._host(reloads=False), []
        self.assertEqual(commands.allow("agent", "example.com", methods=[],
                                        paths=[], dirs=self.dirs,
                                        runner=host, pause=waits.append),
                         commands.Applied(True,
                                          "it did not take the reload"))
        self.assertEqual(sum(waits), commands._RELOAD_WAIT)
        self.assertLess(
            host.calls.index(["systemctl", "--user", "reload",
                              box.inspect_service]),
            host.calls.index(["systemctl", "--user", "try-restart",
                              box.inspect_service]))

    def test_a_change_of_tls_restarts_the_inspector(self):
        """The minter was built for the `tls` it started with, so the
        inspector refuses to reload into another."""
        box, _ = self._create()
        host = self._host()
        self.assertEqual(
            self._edit(self._editor('{"tls": "splice", "hosts": []}')[0],
                       host=host),
            commands.Applied(True, '"tls" changed'))
        self.assertEqual(self._reloads(host), [box.resolve_service])
        self.assertEqual(self._restarts(host), [[
            "systemctl", "--user", "try-restart", box.inspect_service]])

    def test_an_allow_allowed_already_or_refused_changes_nothing(self):
        box, _ = self._create()
        before = box.policy.read_text()
        host = FakeHost(self.home)
        self.assertIsNone(commands.allow("agent", "pypi.org", methods=[],
                                         paths=[], dirs=self.dirs,
                                         runner=host))
        with self.assertRaisesRegex(commands.BoxError, "not a host name"):
            commands.allow("agent", "*.x", methods=[], paths=[],
                           dirs=self.dirs, runner=host)
        self.assertEqual(box.policy.read_text(), before)
        self.assertEqual(host.calls, [])

    def _editor(self, *texts):
        """An editor writing each text in turn, and what it was run as."""
        texts, runs = list(texts), []

        def edit(argv):
            runs.append(argv)
            text = texts.pop(0)
            if text is not None:
                Path(argv[-1]).write_text(text)
            return subprocess.CompletedProcess(argv, 0)
        return edit, runs

    def _edit(self, edit, *, isatty=False, ask=None, host=None, env=None):
        return commands.edit_policy(
            "agent", dirs=self.dirs, environ=env or self.env, isatty=isatty,
            runner=host or self._host(), edit=edit,
            ask=ask or self.fail, pause=self.fail)

    def test_policy_opens_a_copy_in_the_editor_and_applies_it(self):
        box, _ = self._create()
        edit, runs = self._editor('{"hosts": ["example.com"]}')
        host = self._host()
        self.assertEqual(self._edit(edit, host=host,
                                    env={**self.env,
                                         "EDITOR": "code --wait"}),
                         commands.Applied(True))
        (argv,) = runs
        self.assertEqual(argv[:2], ["code", "--wait"])
        self.assertNotEqual(Path(argv[-1]), box.policy)
        self.assertEqual(box.policy.read_text(),
                         '{"hosts": ["example.com"]}')
        self.assertEqual(len(self._reloads(host)), 2)
        self.assertIsNone(self._edit(self._editor(None)[0]))

    def test_a_policy_that_does_not_load_changes_nothing(self):
        """Refused at the command, and not by an inspector that will not
        start; the box keeps its listeners, and nothing is left beside
        the policy."""
        box, _ = self._create()
        before = box.policy.read_text()
        for bad, words in (('{"hosts": "x"}', "'hosts'"),
                           ("{", "policy: Expecting"),
                           ('{"policy": [{"host": "api.x", "paths": ["/*"],'
                            ' "credential": "nosuch"}]}', "no credential")):
            host = FakeHost(self.home)
            with self.subTest(bad), \
                    self.assertRaisesRegex(commands.BoxError, words):
                self._edit(self._editor(bad)[0], host=host)
            self.assertEqual(box.policy.read_text(), before)
            self.assertEqual(host.calls, [])
            self.assertNotIn(".policy.json.new", str(host.calls))
        self.assertEqual(sorted(p.name for p in box.config.iterdir()),
                         ["box.json", "bundle.pem", "policy.json",
                          "prompt.sh"])
        failing = lambda argv: subprocess.CompletedProcess(argv, 1)
        with self.assertRaisesRegex(commands.BoxError, "exited 1"):
            self._edit(failing)
        self.assertEqual(box.policy.read_text(), before)

    def test_at_a_terminal_a_policy_that_does_not_load_is_edited_again(self):
        box, _ = self._create()
        asked = []
        edit, runs = self._editor('{"hosts": "x"}', '{"hosts": ["y.z"]}')
        with mock.patch("sys.stderr"):
            self._edit(edit, isatty=True,
                       ask=lambda q: asked.append(q) or "")
        self.assertEqual((len(runs), len(asked)), (2, 1))
        self.assertIn("y.z", box.policy.read_text())
        before = box.policy.read_text()
        with mock.patch("sys.stderr"), \
                self.assertRaisesRegex(commands.BoxError, "unchanged"):
            self._edit(self._editor('{"hosts": "x"}')[0], isatty=True,
                       ask=lambda q: "n")
        self.assertEqual(box.policy.read_text(), before)

    def test_a_policy_naming_a_credential_gains_a_broker_and_loses_it(self):
        """Its units are written again, the broker started before the
        inspector restarts with its new --broker, and the workload told of
        its new variable."""
        self._add()
        box, _ = self._create()
        brokered = self._brokered().read_text()
        host = self._host()
        self.assertEqual(self._edit(self._editor(brokered)[0], host=host),
                         commands.Applied(True, "its broker is new"))
        self.assertTrue(box.broker_file.is_file())
        self.assertIn(f"unix:{box.broker_socket}",
                      box.inspect_file.read_text())
        self.assertIn("Environment=K=", box.container_file.read_text())
        reload = ["systemctl", "--user", "daemon-reload"]
        start = ["systemctl", "--user", "start", box.broker_service]
        (restart,) = self._restarts(host)
        self.assertLess(host.calls.index(reload), host.calls.index(start))
        self.assertLess(host.calls.index(start), host.calls.index(restart))
        host = self._host()
        self.assertEqual(
            self._edit(self._editor('{"hosts": ["pypi.org"]}')[0],
                       host=host),
            commands.Applied(True, "its broker is gone"))
        self.assertFalse(box.broker_file.exists())
        self.assertNotIn("--broker", box.inspect_file.read_text())
        self.assertIn(["systemctl", "--user", "stop", box.broker_service],
                      host.calls)

    def test_enter_starts_a_listener_that_is_not_running(self):
        """Nothing requires them, so the workload starts without them."""
        self._create()
        for works in (True, False):
            host, ran, said = FakeHost(self.home, listener_state="failed",
                                       listeners=works), [], []
            commands.enter("agent", ["id"], root=False, dirs=self.dirs,
                           cwd=self.home, environ=self.env, isatty=False,
                           runner=host, execvp=lambda f, a: ran.append(a),
                           warn=said.append)
            with self.subTest(works=works):
                for unit in ("moathut-agent-inspect.service",
                             "moathut-agent-resolve.service"):
                    self.assertLess(
                        host.calls.index(["systemctl", "--user",
                                          "reset-failed", unit]),
                        host.calls.index(["systemctl", "--user", "start",
                                          unit]))
                self.assertEqual(len(ran), 1)
                self.assertEqual(len(said), 0 if works else 2)
        host = FakeHost(self.home)
        commands.enter("agent", ["id"], root=False, dirs=self.dirs,
                       cwd=self.home, environ=self.env, isatty=False,
                       runner=host, execvp=lambda f, a: None,
                       warn=self.fail)
        self.assertNotIn("reset-failed", str(host.calls))

    def test_log_refused_reads_the_record_against_the_policy(self):
        box, _ = self._create()
        box.record.write_text("".join(json.dumps(d) + "\n" for d in (
            _line(host="pypi.org", decision="drop", reason="not allowlisted"),
            _line(host="evil.example", decision="drop",
                  reason="not allowlisted"))))
        box.resolve_status.write_text(json.dumps(
            {"unlisted_names": {"evil.example": 1}}))
        self.assertEqual(commands.refused("agent", dirs=self.dirs),
                         ([(1, "evil.example", "not allowlisted", "")],
                          [(1, "evil.example")]))

    def test_log_refused_reads_the_rotated_records_too(self):
        box, _ = self._create()
        refusal = json.dumps(_line(host="evil.example", decision="drop",
                                   reason="not allowlisted")) + "\n"
        box.record.write_text(refusal)
        record.rotate(box.record, max_bytes=1)
        box.record.write_text(refusal)
        record.rotate(box.record, max_bytes=1)
        box.record.write_text(refusal)
        self.assertEqual(commands.refused("agent", dirs=self.dirs)[0],
                         [(3, "evil.example", "not allowlisted", "")])

    def test_a_rotation_has_the_inspector_reopen_the_record(self):
        box, _ = self._create()
        host = FakeHost(self.home)
        hup = ["systemctl", "--user", "kill", "--kill-whom=main", "-s",
               "HUP", box.inspect_service]
        box.record.write_text("{}\n")
        commands.unit_rotate("agent", dirs=self.dirs, runner=host)
        self.assertEqual(host.calls, [])
        with box.record.open("r+") as handle:
            handle.truncate(record.ROTATE_BYTES)
        commands.unit_rotate("agent", dirs=self.dirs, runner=host)
        self.assertEqual(host.calls, [hup])
        self.assertFalse(box.record.exists())

    def test_the_command_line_takes_the_policy_loop(self):
        from moathut import cli
        args = parse(["allow", "agent", "api.x", "--method", "GET",
                      "--method", "post", "--path", "/v1/*"])
        self.assertEqual((args.name, args.host, args.method, args.path),
                         ("agent", "api.x", ["GET", "post"], ["/v1/*"]))
        self.assertTrue(parse(["log", "agent", "--refused"]).refused)
        for applied, words in (
                (commands.Applied(True),
                 "api.x allowed; its inspector and responder reloaded"),
                (commands.Applied(True, '"tls" changed'),
                 'its inspector restarted, since "tls" changed, and its '
                 'responder reloaded'),
                (commands.Applied(False),
                 "it applies from the box's next start")):
            with mock.patch.object(cli, "allow", return_value=applied), \
                    mock.patch("sys.stdout") as out:
                cli.run_command(args, tool=(), environ=self.env,
                                cwd=self.home, isatty=False)
            said = "".join(c.args[0] for c in out.write.call_args_list)
            self.assertIn(words, said)
        with mock.patch.object(cli, "refused", return_value=(
                [(3, "evil.example", "not allowlisted", "")], [])), \
                mock.patch("sys.stdout") as out:
            cli.run_command(parse(["log", "agent", "--refused"]), tool=(),
                            environ=self.env, cwd=self.home, isatty=False)
        said = "".join(c.args[0] for c in out.write.call_args_list)
        self.assertIn("evil.example  (not allowlisted)", said)
        self.assertIn("moathut allow agent HOST", said)


if __name__ == "__main__":
    unittest.main()
