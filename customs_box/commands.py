"""What each command does. The command line is cli's; everything here
takes its inputs as arguments, so the tests can hand them in."""

import os
import shutil
from pathlib import Path, PurePosixPath

from customs.inspect_policy import load_policy

from .mounts import MountRefused, parse_mount, refuse
from .netns import exec_with_pid, load_rules, pod_pid, rules_loaded
from .paths import Box, boxes_root, valid_name
from .process import CommandFailed, run
from .units import Settings, render

DEFAULT_IMAGE = "registry.fedoraproject.org/fedora-toolbox:44"
DEFAULT_LIBEXEC = "/usr/libexec/customs"

# The system bundles this knows, Fedora's first. The box's is mounted
# over the first of these its image has.
TRUST_PATHS = ("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
               "/etc/ssl/certs/ca-certificates.crt",
               "/etc/ssl/ca-bundle.pem")
HOST_BUNDLES = TRUST_PATHS + ("/etc/ssl/cert.pem",)

_FIRST_FILE = 'for p; do [ -f "$p" ] && { echo "$p"; exit 0; }; done; exit 1'

# The image's rule asks root's password of the wheel group; the user
# keep-id adds has no password and is in no group of the image's.
_SUDOERS = """\
set -e
u=$(id -nu "$1" 2>/dev/null) || u="#$1"
mkdir -p /etc/sudoers.d
printf '%s ALL=(ALL) NOPASSWD: ALL\\n' "$u" > /etc/sudoers.d/customs-box
chmod 0440 /etc/sudoers.d/customs-box
"""

PASSED_THROUGH = ("TERM", "COLORTERM", "LANG")


class BoxError(Exception):
    """A command refused, with the reason."""


def _box(name, dirs):
    if not valid_name(name):
        raise BoxError(f"{name!r}: a box's name is lowercase letters, "
                       "digits and inner dashes, 48 at most")
    return Box(name, dirs)


def _existing(name, dirs):
    box = _box(name, dirs)
    if not box.settings.exists():
        raise BoxError(f"no box {name}")
    return box, Settings.from_json(box.settings.read_text())


def _program_env(environ, pythonpath):
    env = dict(environ)
    if pythonpath:
        env["PYTHONPATH"] = pythonpath
    return env


def _refuse_credentials(policy_path):
    try:
        policy = load_policy(policy_path)
    except (OSError, ValueError) as exc:
        raise BoxError(f"policy: {exc}") from None
    named = sorted({e.credential for e in policy.policy if e.credential})
    if named:
        raise BoxError(f"policy: names credentials ({', '.join(named)}), "
                       "and a box has no broker yet")


def _trust_path(image, runner):
    if runner(["podman", "image", "exists", image],
              check=False).returncode != 0:
        runner(["podman", "pull", "-q", image])
    found = runner(["podman", "run", "--rm", "--network", "none",
                    "--entrypoint", "/bin/sh", image, "-c", _FIRST_FILE,
                    "sh", *TRUST_PATHS], check=False)
    if found.returncode != 0:
        raise BoxError(f"{image}: has none of the system trust stores "
                       f"this knows ({', '.join(TRUST_PATHS)})")
    return found.stdout.strip()


def _host_bundle():
    for path in HOST_BUNDLES:
        if os.path.isfile(path):
            return Path(path)
    raise BoxError("the host has none of the system trust stores this "
                   f"knows ({', '.join(HOST_BUNDLES)})")


def create(name, policy_path, image, mount_specs, *, dirs, tool, python,
           libexec, pythonpath, uid, gid, cwd, environ, runner=run):
    box = _box(name, dirs)
    if box.config.exists() or any(p.exists() for p in box.unit_files):
        raise BoxError(f"box {name} exists")
    for kind in ("container", "pod"):
        if runner(["podman", kind, "exists", name],
                  check=False).returncode == 0:
            raise BoxError(f"a {kind} named {name} exists")
    _refuse_credentials(policy_path)
    host_bundle = _host_bundle()
    try:
        mounts = tuple(parse_mount(spec, cwd, dirs.home)
                       for spec in mount_specs)
    except MountRefused as exc:
        raise BoxError(f"--mount {exc}") from None
    trust_path = _trust_path(image, runner)
    home_path = str(dirs.home)
    for mount in mounts:
        try:
            refuse(mount, dirs, (home_path, trust_path))
        except MountRefused as exc:
            raise BoxError(f"--mount {exc}") from None
    settings = Settings(image=image, trust_path=trust_path,
                        home_path=home_path, uid=uid, gid=gid,
                        mounts=mounts, tool=tuple(tool), python=python,
                        libexec=str(libexec), pythonpath=pythonpath)
    home_existed = box.home.exists()
    try:
        _lay_out(box, settings, policy_path, host_bundle, environ, runner)
    except BaseException:
        _discard(box, home=not home_existed, runner=runner)
        raise
    return box


def _lay_out(box, settings, policy_path, host_bundle, environ, runner):
    for path in (box.config, box.state, box.logs, box.home):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    box.policy.write_bytes(Path(policy_path).read_bytes())
    box.policy.chmod(0o600)
    minted = runner([settings.python,
                     str(Path(settings.libexec) / "customs-mint-ca"),
                     "--name", box.name, "--state-dir", str(box.state)],
                    env=_program_env(environ, settings.pythonpath))
    ca = Path(minted.stdout.strip())
    box.bundle.write_text(ca.read_text() + host_bundle.read_text())
    box.bundle.chmod(0o644)
    for path, text in render(box, settings).items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    box.settings.write_text(settings.to_json())
    runner(["systemctl", "--user", "daemon-reload"])
    for service in (box.pod_service, box.service):
        state = runner(["systemctl", "--user", "show", "-p", "LoadState",
                        "--value", service]).stdout.strip()
        if state != "loaded":
            raise BoxError(f"quadlet did not generate {service} "
                           "(/usr/libexec/podman/quadlet -dryrun -user "
                           "says why)")


def _discard(box, *, home, runner):
    runner(["systemctl", "--user", "stop", box.pod_service], check=False)
    for path in box.unit_files:
        path.unlink(missing_ok=True)
    runner(["systemctl", "--user", "daemon-reload"], check=False)
    runner(["systemctl", "--user", "reset-failed", *box.services],
           check=False)
    runner(["podman", "pod", "rm", "-f", "-i", box.name], check=False)
    shutil.rmtree(box.config, ignore_errors=True)
    shutil.rmtree(box.state, ignore_errors=True)
    if home:
        shutil.rmtree(box.share, ignore_errors=True)


def _workdir(settings, cwd, root):
    cwd = Path(cwd).resolve()
    for mount in settings.mounts:
        if cwd.is_relative_to(mount.source):
            inner = PurePosixPath(mount.target) / cwd.relative_to(
                mount.source)
            return str(inner)
    return "/root" if root else settings.home_path


# The user's own shell if the image has it, then bash; podman's entry for
# the user names /bin/sh.
_SHELL = ('for s; do [ -n "$s" ] && [ -x "$s" ] && exec echo "$s"; done; '
          'getent passwd "$(id -u)" | cut -d: -f7')


def _login_shell(box, user, environ, runner):
    shell = runner(["podman", "exec", "--user", user, box.name, "sh", "-c",
                    _SHELL, "sh", environ.get("SHELL", ""), "/bin/bash"],
                   check=False).stdout.strip()
    return [shell or "/bin/sh", "-l"]


def enter(name, command, *, root, dirs, cwd, environ, isatty,
          runner=run, execvp=os.execvp):
    box, settings = _existing(name, dirs)
    try:
        runner(["systemctl", "--user", "start", box.service])
    except CommandFailed as exc:
        raise BoxError(f"box {name} did not start ({exc}); see "
                       f"journalctl --user -u '{box.unit}*'") from None
    if not rules_loaded(pod_pid(name, runner), runner):
        raise BoxError(f"box {name}'s namespace has no customs rules: its "
                       "pod was started outside systemd. customs-box stop "
                       f"{name}, then enter it again")
    uid, gid = (0, 0) if root else (settings.uid, settings.gid)
    user = f"{uid}:{gid}"
    command = list(command)
    if not command:
        command = _login_shell(box, user, environ, runner)
    argv = ["podman", "exec", "-i", *(["-t"] if isatty else []),
            "--user", user, "--workdir", _workdir(settings, cwd, root)]
    for variable in PASSED_THROUGH:
        if variable in environ:
            argv += ["--env", variable]
    execvp("podman", [*argv, name, *command])


def stop(name, *, dirs, runner=run):
    box, _settings = _existing(name, dirs)
    runner(["systemctl", "--user", "stop", box.pod_service])


def rm(name, *, home, dirs, runner=run):
    box, _settings = _existing(name, dirs)
    _discard(box, home=home, runner=runner)
    kept = [str(box.logs)] + ([] if home else [str(box.home)])
    return kept


def ls(*, dirs, runner=run):
    rows = []
    for settings_file in sorted(boxes_root(dirs).glob("*/box.json")):
        box = Box(settings_file.parent.name, dirs)
        settings = Settings.from_json(settings_file.read_text())
        state = runner(["systemctl", "--user", "is-active", box.service],
                       check=False).stdout.strip() or "unknown"
        rows.append((box.name, state, settings.image))
    return rows


def unit_rules(name, *, runner=run):
    load_rules(pod_pid(name, runner), runner)


def unit_exec(name, argv, *, runner=run, execv=os.execv):
    exec_with_pid(name, argv, runner, execv)


def unit_sudoers(name, *, dirs, runner=run):
    _, settings = _existing(name, dirs)
    runner(["podman", "exec", "--user", "0", name, "sh", "-c", _SUDOERS,
            "sh", str(settings.uid)])
