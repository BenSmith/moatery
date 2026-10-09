"""What each command does. The command line is cli's; everything here
takes its inputs as arguments, so the tests can hand them in."""

import json
import os
import random
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from moatery.broker_profiles import (BROKER_DEFAULT_AUTH_FORMAT,
                                     BROKER_DEFAULT_AUTH_HEADER)
from moatery.inspect_document import (INSPECT_DIGEST_KEY,
                                      inspect_policy_digest)
from moatery.inspect_policy import load_policy
from moatery.sd_notify import notify_ready

from . import credentials, document, ptyxis, record, seccomp
from .credentials import CredentialError, brokering, describe
from .document import AllowRefused
from .mounts import MountRefused, parse_mount, refuse
from .netns import (NetnsError, connect, exec_with_pid, load_rules, make,
                    netns_id, pod_pid, release, rules_loaded)
from .paths import Hut, huts_root, credentials_root, described, sealed, \
    valid_name
from .process import CommandFailed, run
from .units import (CA_VARIABLES, MARK_PATH, PROMPT_PATH, Settings,
                    containers_conf, interpreter, prompt, render)

DEFAULT_IMAGE = "registry.fedoraproject.org/fedora-toolbox:44"
DEFAULT_LIBEXEC = "/usr/libexec/moatery"

# The system bundles this knows, Fedora's first. The hut's is mounted
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
printf '%s ALL=(ALL) NOPASSWD: ALL\\n' "$u" > /etc/sudoers.d/moathut
chmod 0440 /etc/sudoers.d/moathut
"""

PASSED_THROUGH = ("TERM", "COLORTERM", "LANG")

# What a credential's variable may not be: the hut sets these itself.
RESERVED = CA_VARIABLES + PASSED_THROUGH


class HutError(Exception):
    """A command refused, with the reason."""


def _hut(name, dirs):
    if not valid_name(name):
        raise HutError(f"{name!r}: a hut's name is lowercase letters, "
                       "digits and inner dashes, 48 at most")
    return Hut(name, dirs)


# How many categories podman picks a container's two from.
CATEGORIES = 1024

_sample = random.SystemRandom().sample


def _free_level(dirs):
    """Two categories no hut has, its SELinux level."""
    taken = {settings.level for _, settings in _huts(dirs)}
    while True:
        level = "s0:c{},c{}".format(*sorted(_sample(range(CATEGORIES), 2)))
        if level not in taken:
            return level


def _existing(name, dirs):
    """The hut and its settings: a hut with no level is given one, which
    it runs at from its next start."""
    hut = _hut(name, dirs)
    if not hut.settings.exists():
        raise HutError(f"no hut {name}")
    settings = Settings.from_json(hut.settings.read_text())
    if settings.level is None:
        settings = settings._replace(level=_free_level(dirs))
        hut.settings.write_text(settings.to_json())
    return hut, settings


def _huts(dirs):
    for settings_file in sorted(huts_root(dirs).glob("*/hut.json")):
        yield (Hut(settings_file.parent.name, dirs),
               Settings.from_json(settings_file.read_text()))


def _warn(message):
    print(f"moathut: {message}", file=sys.stderr)


def _program_env(environ, pythonpath):
    env = dict(environ)
    if pythonpath:
        env["PYTHONPATH"] = pythonpath
    return env


def _policy(path):
    try:
        return load_policy(path)
    except (OSError, ValueError) as exc:
        raise HutError(f"policy: {exc}") from None


def _broker(policy, dirs, load=None):
    """The hut's broker, from its policy and the credentials it names."""
    try:
        broker = brokering(
            policy, load or (lambda c: credentials.read(dirs, c)))
    except CredentialError as exc:
        raise HutError(f"policy: {exc}") from None
    if broker and dirs.runtime is None:
        raise HutError("XDG_RUNTIME_DIR is not set, and a hut's broker "
                       "listens in it")
    return broker


# Written into a home that lacks them, as Fedora's /etc/skel has them:
# the login shell enter starts reads .bash_profile, which reads .bashrc,
# which puts ~/.local/bin on PATH, where an installer run in the hut puts
# its tools, and reads the hut's prompt, which bash would otherwise not.
_BASH_PROFILE = """\
[ -f ~/.bashrc ] && . ~/.bashrc
"""
_BASHRC = f"""\
[ -f /etc/bashrc ] && . /etc/bashrc
case ":$PATH:" in
*":$HOME/.local/bin:"*) ;;
*) PATH="$HOME/.local/bin:$HOME/bin:$PATH" ;;
esac
export PATH
[ -f {PROMPT_PATH} ] && . {PROMPT_PATH}
"""


def _written(hut, settings, broker):
    """Path to text, for each file the units are and each they read
    that is written with them: a hut's own seccomp profile is not, and
    stays as it was copied in."""
    written = {**render(hut, settings, broker), hut.prompt: prompt(hut),
               hut.containers_conf: containers_conf(hut)}
    if settings.seccomp is not None:
        try:
            written[hut.seccomp] = seccomp.render(settings.seccomp)
        except ValueError as exc:
            raise HutError(f"hut {hut.name}: {exc}") from None
    return written


# The states in which a unit holds what it started with.
_UP = ("active", "activating", "deactivating", "reloading")


def _running(hut, runner):
    return _state(hut.pod_service, runner) in _UP


def _write_units(hut, settings, broker, runner):
    """The hut's files as `_written` gives them, and the units it no
    longer has removed. While its pod runs, the files its namespace and
    its shells started with are kept: a reload would give the running
    pod a unit bound to a namespace unit that is not running, and the
    manager would stop it. `enter` writes them at its next start."""
    units = _written(hut, settings, broker)
    kept = ((hut.netns_file, hut.pod_file, hut.containers_conf, hut.prompt)
            if _running(hut, runner) else ())
    for path, text in units.items():
        if path in kept:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for path in hut.unit_files:
        if path not in units and path not in kept:
            path.unlink(missing_ok=True)
    # The workload mounts it, and podman will not start a container with
    # a mount whose source is missing. Empty until the rules name the
    # namespace, which the hut reads as not knowing.
    hut.netns_mark.parent.mkdir(parents=True, exist_ok=True)
    hut.netns_mark.touch()


def _trust_path(image, runner):
    if runner(["podman", "image", "exists", image],
              check=False).returncode != 0:
        runner(["podman", "pull", "-q", image])
    found = runner(["podman", "run", "--rm", "--network", "none",
                    "--entrypoint", "/bin/sh", image, "-c", _FIRST_FILE,
                    "sh", *TRUST_PATHS], check=False)
    if found.returncode != 0:
        raise HutError(f"{image}: has none of the system trust stores "
                       f"this knows ({', '.join(TRUST_PATHS)})")
    return found.stdout.strip()


def _host_bundle():
    for path in HOST_BUNDLES:
        if os.path.isfile(path):
            return Path(path)
    raise HutError("the host has none of the system trust stores this "
                   f"knows ({', '.join(HOST_BUNDLES)})")


def _own_profile(given, cwd):
    """The text of a seccomp profile file, as podman will read it."""
    path = Path(cwd, given).expanduser()
    try:
        text = path.read_text()
        doc = json.loads(text)
    except OSError as exc:
        raise HutError(f"--seccomp {given}: {exc.strerror}; it is "
                       f"{' or '.join(seccomp.PROFILES)}, or a profile "
                       "file") from None
    except ValueError as exc:
        raise HutError(f"--seccomp {given}: {exc}") from None
    if not isinstance(doc, dict) or "defaultAction" not in doc:
        raise HutError(f"--seccomp {given}: a seccomp profile has a "
                       "defaultAction")
    return text


def create(name, policy_path, image, mount_specs, *, dirs, tool, python,
           libexec, pythonpath, uid, gid, cwd, environ, autostart=False,
           dry_run=False, like=None, profile=None, runner=run):
    """The hut; with dry_run, what would be written, path to text, and
    nothing is. A hut `like` another starts from its policy, image,
    mounts and seccomp profile: a policy, image or profile given
    replaces its, and a mount given joins its, replacing one at the same
    target. `profile` names one of seccomp's or a file, copied in."""
    hut = _hut(name, dirs)
    if hut.config.exists() or any(p.exists() for p in hut.unit_files):
        raise HutError(f"hut {name} exists")
    for kind in ("container", "pod"):
        if runner(["podman", kind, "exists", name],
                  check=False).returncode == 0:
            raise HutError(f"a {kind} named {name} exists")
    try:
        given = [(parse_mount(spec, cwd, dirs.home), "--mount")
                 for spec in mount_specs]
    except MountRefused as exc:
        raise HutError(f"--mount {exc}") from None
    inherited, own = [], None
    if profile is not None and profile not in seccomp.PROFILES:
        own = _own_profile(profile, cwd)
    if like is not None:
        other, other_settings = _existing(like, dirs)
        if profile is None:
            profile = other_settings.seccomp
            if profile is None:
                own = other.seccomp.read_text()
        policy_path = policy_path or other.policy
        image = image or other_settings.image
        targets = {mount.target for mount, _ in given}
        inherited = [(mount, f"hut {like}'s mount")
                     for mount in other_settings.mounts
                     if mount.target not in targets]
    if policy_path is None:
        raise HutError("create needs --policy FILE or --like HUT")
    if own is not None:
        profile = None
    elif profile is None:
        profile = seccomp.DEFAULT
    image = image or DEFAULT_IMAGE
    broker = _broker(_policy(policy_path), dirs)
    host_bundle = _host_bundle()
    trust_path = _trust_path(image, runner)
    home_path = str(dirs.home)
    for mount, origin in inherited + given:
        try:
            refuse(mount, dirs,
                   (home_path, trust_path, PROMPT_PATH, MARK_PATH))
        except MountRefused as exc:
            raise HutError(f"{origin} {exc}") from None
    mounts = tuple(mount for mount, _ in inherited + given)
    settings = Settings(image=image, trust_path=trust_path,
                        home_path=home_path, uid=uid, gid=gid,
                        mounts=mounts, tool=tuple(tool), python=python,
                        libexec=str(libexec), pythonpath=pythonpath,
                        autostart=autostart, seccomp=profile,
                        level=_free_level(dirs))
    if dry_run:
        return {**_written(hut, settings, broker),
                **({hut.seccomp: own} if own is not None else {})}
    home_existed = hut.home.exists()
    try:
        _lay_out(hut, settings, broker, policy_path, host_bundle, environ,
                 own, runner)
    except BaseException:
        _discard(hut, home=not home_existed, runner=runner)
        raise
    return hut


def _lay_out(hut, settings, broker, policy_path, host_bundle, environ,
             own_profile, runner):
    for path in (hut.config, hut.state, hut.logs, hut.home):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The runtime makes a missing mount point, and each directory above
    # it, as the hut's root, which the user could not write in its own
    # home.
    for mount in settings.mounts:
        target = PurePosixPath(mount.target)
        if target.is_relative_to(settings.home_path):
            _home_dirs(hut.home, target.relative_to(settings.home_path))
    for name, text in ((".bashrc", _BASHRC),
                       (".bash_profile", _BASH_PROFILE)):
        _home_file(hut.home / name, text)
    hut.policy.write_bytes(Path(policy_path).read_bytes())
    hut.policy.chmod(0o600)
    minted = runner([*interpreter(settings),
                     str(Path(settings.libexec) / "moat-mint-ca"),
                     "--name", hut.name, "--state-dir", str(hut.state)],
                    env=_program_env(environ, settings.pythonpath))
    ca = Path(minted.stdout.strip())
    hut.bundle.write_text(ca.read_text() + host_bundle.read_text())
    hut.bundle.chmod(0o644)
    if own_profile is not None:
        hut.seccomp.write_text(own_profile)
    _write_units(hut, settings, broker, runner)
    hut.settings.write_text(settings.to_json())
    runner(["systemctl", "--user", "daemon-reload"])
    for service in (hut.pod_service, hut.service):
        state = runner(["systemctl", "--user", "show", "-p", "LoadState",
                        "--value", service]).stdout.strip()
        if state != "loaded":
            raise HutError(f"quadlet did not generate {service} "
                           "(/usr/libexec/podman/quadlet -dryrun -user "
                           "says why)")


# A home kept from an earlier hut was that hut's workload to write, and
# what is written into it here is written as the user: a link the
# workload left is refused, never followed out of the home.

def _home_dirs(home, relative):
    path = home
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise HutError(f"{path} is a link, and a mount point in the "
                           "hut's home is not made through one")
        path.mkdir(exist_ok=True)


def _home_file(path, text):
    """`text` at `path` unless something is there, a link included."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    except FileExistsError:
        return
    with os.fdopen(fd, "w") as handle:
        handle.write(text)


def _units_to_stop(hut):
    """The namespace's unit stops the pod, and the pod what is bound to
    it; the pod is named too, for a hut whose units have no namespace's
    unit yet."""
    return [hut.pod_service] + [
        unit for unit, path in ((hut.netns_service, hut.netns_file),
                                (hut.broker_service, hut.broker_file))
        if path.exists()]


def _discard(hut, *, home, runner):
    runner(["systemctl", "--user", "stop", *_units_to_stop(hut)],
           check=False)
    if hut.broker_file.exists():
        _clear_broker(hut, runner)
    for path in hut.unit_files:
        path.unlink(missing_ok=True)
    runner(["systemctl", "--user", "daemon-reload"], check=False)
    runner(["systemctl", "--user", "reset-failed", *hut.services],
           check=False)
    runner(["podman", "pod", "rm", "-f", "-i", hut.name], check=False)
    shutil.rmtree(hut.config, ignore_errors=True)
    shutil.rmtree(hut.state, ignore_errors=True)
    if home:
        _remove_home(hut, runner)


def _remove_home(hut, runner):
    # The hut's other uids write in its home too: root by sudo, and the
    # runtime.
    runner(["podman", "unshare", "rm", "-rf", "--", str(hut.share)],
           check=False)


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


def _login_shell(hut, user, environ, runner):
    shell = runner(["podman", "exec", "--user", user, hut.name, "sh", "-c",
                    _SHELL, "sh", environ.get("SHELL", ""), "/bin/bash"],
                   check=False).stdout.strip()
    return [shell or "/bin/sh", "-l"]


def _state(unit, runner):
    return runner(["systemctl", "--user", "is-active", unit],
                  check=False).stdout.strip()


def _broker_state(hut, runner):
    return _state(hut.broker_service, runner)


def _listeners(hut):
    """Each listener's unit, and what the hut's workload finds while it
    is not running."""
    return ((hut.inspect_service, "inspector",
             "its connections are refused"),
            (hut.resolve_service, "responder",
             "its names do not resolve"))


def _remove_tree(path):
    """A directory tree the user owns, whatever its modes."""
    try:
        os.chmod(path, 0o700)
    except FileNotFoundError:
        return
    for directory, inner, _ in os.walk(path):
        for name in inner:
            os.chmod(os.path.join(directory, name), 0o700)
    shutil.rmtree(path)


def _reset_broker(hut, runner):
    runner(["systemctl", "--user", "stop", hut.broker_service], check=False)
    _clear_broker(hut, runner)


def _clear_broker(hut, runner):
    """What systemd leaves when it stops a credentialed unit while the
    unit's credentials are being decrypted: the workspace, which every
    start after fails on, a restart after a restart, and those
    failures."""
    if hut.dirs.runtime is not None:
        _remove_tree(hut.dirs.runtime / "systemd" / "temporary-credentials"
                     / hut.broker_service)
    runner(["systemctl", "--user", "reset-failed", hut.broker_service],
           check=False)


def _refresh(hut, settings, dirs, runner):
    """A stopped hut's files written again if this moathut would write
    them otherwise, so its start is one this moathut made."""
    broker = _broker(_policy(hut.policy), dirs)
    units = _written(hut, settings, broker)
    if any(not path.exists() or path.read_text() != text
           for path, text in units.items()) or any(
            path.exists() for path in hut.unit_files if path not in units):
        _write_units(hut, settings, broker, runner)
        runner(["systemctl", "--user", "daemon-reload"])


def enter(name, command, *, root, dirs, cwd, environ, isatty,
          runner=run, execvp=os.execvp, warn=_warn):
    hut, settings = _existing(name, dirs)
    if not _running(hut, runner):
        _refresh(hut, settings, dirs, runner)
    if hut.broker_file.exists() and _broker_state(hut, runner) != "active":
        _reset_broker(hut, runner)
    try:
        runner(["systemctl", "--user", "start", hut.service])
    except CommandFailed as exc:
        raise HutError(f"hut {name} did not start ({exc}); see "
                       f"journalctl --user -u '{hut.unit}*'") from None
    if not rules_loaded(pod_pid(name, runner), runner):
        raise HutError(f"hut {name}'s namespace has no moatery rules. "
                       f"moathut stop {name}, then enter it again")
    # Nothing requires them, so the workload starts without them.
    for unit, what, effect in _listeners(hut):
        if _state(unit, runner) == "active":
            continue
        runner(["systemctl", "--user", "reset-failed", unit], check=False)
        if runner(["systemctl", "--user", "start", unit],
                  check=False).returncode != 0:
            warn(f"hut {name}'s {what} did not start, and {effect} until "
                 f"it does; see journalctl --user -u {unit}")
    # Started again if it stopped; without it, a request with one of its
    # credentials is refused, not sent without.
    if hut.broker_file.exists() and runner(
            ["systemctl", "--user", "start", hut.broker_service],
            check=False).returncode != 0:
        warn(f"hut {name}'s broker did not start, and requests with its "
             f"credentials are refused; see journalctl --user -u "
             f"{hut.broker_service}")
    uid, gid = (0, 0) if root else (settings.uid, settings.gid)
    user = f"{uid}:{gid}"
    command = list(command)
    if not command:
        command = _login_shell(hut, user, environ, runner)
    argv = ["podman", "exec", "-i", *(["-t"] if isatty else []),
            "--user", user, "--workdir", _workdir(settings, cwd, root)]
    for variable in PASSED_THROUGH:
        if variable in environ:
            argv += ["--env", variable]
    execvp("podman", [*argv, name, *command])


def stop(name, *, dirs, runner=run):
    hut, _settings = _existing(name, dirs)
    runner(["systemctl", "--user", "stop", *_units_to_stop(hut)])


def rm(name, *, home, dirs, runner=run):
    """Remove the hut, or with `home`, the home a hut removed without it
    left behind."""
    hut = _hut(name, dirs)
    if hut.settings.exists():
        _discard(hut, home=home, runner=runner)
    elif home and hut.share.exists():
        _remove_home(hut, runner)
    else:
        raise HutError(f"no hut {name}")
    if home and hut.share.exists():
        raise HutError(f"hut {name} is removed but its home is not: "
                       f"podman unshare rm -rf {hut.share}")
    return [str(hut.logs)] + ([] if home else [str(hut.home)])


def _gsettings(runner, *args, check=True):
    return runner(["gsettings", *args], check=check)


def _has_ptyxis(runner):
    """Whether Ptyxis's schema is installed, where gsettings reads."""
    try:
        return _gsettings(runner, "list-keys", ptyxis.SCHEMA,
                          check=False).returncode == 0
    except FileNotFoundError:
        return False


def _ptyxis_get(runner, key):
    return ptyxis.parse_strings(
        _gsettings(runner, "get", ptyxis.SCHEMA, key).stdout)


def ptyxis_add(name, *, dirs, runner=run):
    """Write the hut's Ptyxis profile, or write it again."""
    _, settings = _existing(name, dirs)
    if not _has_ptyxis(runner):
        raise HutError("Ptyxis's settings are not installed here: no "
                       "gsettings, or no Ptyxis (a Ptyxis from Flatpak "
                       "keeps its own)")
    own = ptyxis.profile_uuid(name)
    listed = _ptyxis_get(runner, "profile-uuids")
    default = _ptyxis_get(runner, "default-profile-uuid")
    if not default or default[0] not in listed or default[0] == own:
        raise HutError("Ptyxis has no default profile of its own, so the "
                       "hut's would become it: open Ptyxis once, then "
                       "run this again")
    path = ptyxis.profile_path(name)
    for key, value in ptyxis.keys(settings, name):
        _gsettings(runner, "set", f"{ptyxis.PROFILE_SCHEMA}:{path}", key,
                   value)
    if own not in listed:
        _gsettings(runner, "set", ptyxis.SCHEMA, "profile-uuids",
                   ptyxis.strings([*listed, own]))


def ptyxis_remove(name, *, runner=run):
    """Remove the hut's Ptyxis profile; whether it had one."""
    _hut(name, None)
    if not _has_ptyxis(runner):
        return False
    own = ptyxis.profile_uuid(name)
    listed = _ptyxis_get(runner, "profile-uuids")
    if own not in listed:
        return False
    _gsettings(runner, "set", ptyxis.SCHEMA, "profile-uuids",
               ptyxis.strings([u for u in listed if u != own]))
    if _ptyxis_get(runner, "default-profile-uuid") == [own]:
        _gsettings(runner, "reset", ptyxis.SCHEMA, "default-profile-uuid")
    _gsettings(runner, "reset-recursively",
               f"{ptyxis.PROFILE_SCHEMA}:{ptyxis.profile_path(name)}")
    return True


def _unprotected(hut, runner):
    """Whether its pod runs in a namespace without the rules."""
    if runner(["podman", "pod", "exists", hut.name],
              check=False).returncode != 0:
        return False
    try:
        pid = pod_pid(hut.name, runner)
    except (CommandFailed, NetnsError):
        return False
    return not rules_loaded(pid, runner)


def ls(*, dirs, runner=run):
    rows = []
    for hut, settings in _huts(dirs):
        state = runner(["systemctl", "--user", "is-active", hut.service],
                       check=False).stdout.strip() or "unknown"
        rows.append((hut.name, state, settings.image)
                    + ((f"seccomp:{settings.seccomp or 'own'}",)
                       if settings.seccomp != seccomp.DEFAULT else ())
                    + (("autostart",) if settings.autostart else ())
                    + (("unprotected",) if _unprotected(hut, runner)
                       else ()))
    return rows


def log(name, *, dirs, write=print, pause=time.sleep):
    hut, _settings = _existing(name, dirs)
    record.follow(hut.record, write, pause=pause)


def refused(name, *, dirs):
    """The refusals in the hut's record its policy would still make, and
    the names its workload asked for that no list admits."""
    hut, _settings = _existing(name, dirs)
    policy = _policy(hut.policy)
    docs = (doc for path in record.records(hut.record)
            for doc in record.lines(path))
    return (record.refusals(docs, policy),
            record.unlisted(hut.resolve_status, policy))


def allow(name, host, *, methods, paths, dirs, runner=run,
          pause=time.sleep):
    """Widen the hut's policy for HOST and apply it. None if the policy
    allows it already."""
    hut, settings = _existing(name, dirs)
    policy = _policy(hut.policy)
    try:
        doc = document.allow(json.loads(hut.policy.read_text()), policy,
                             document.host_name(host), methods, paths)
    except AllowRefused as exc:
        raise HutError(f"allow: {exc}") from None
    if doc is None:
        return None
    staged, broker = _checked(hut, document.dumps(doc), dirs)
    return _apply_policy(hut, settings, staged, broker, runner, pause)


def edit_policy(name, *, dirs, environ, isatty, runner=run,
                edit=subprocess.run, ask=input, pause=time.sleep):
    """Open a copy of the hut's policy in the user's editor, and apply it
    once it loads. A copy that does not is opened again, if there is a
    terminal to ask on. None if it came back unchanged."""
    hut, settings = _existing(name, dirs)
    editor = shlex.split(environ.get("VISUAL") or environ.get("EDITOR")
                         or "vi")
    original = hut.policy.read_text()
    draft = hut.config / ".policy.json.edit"
    _private(draft, original)
    try:
        while True:
            done = edit([*editor, str(draft)])
            if done.returncode != 0:
                raise HutError(f"{editor[0]} exited {done.returncode}; the "
                               "policy is unchanged")
            text = draft.read_text()
            if text == original:
                return None
            try:
                staged, broker = _checked(hut, text, dirs)
                break
            except HutError as exc:
                if not isatty:
                    raise
                _warn(str(exc))
                if ask("edit it again? [Y/n] ").strip().lower() in ("n",
                                                                    "no"):
                    raise HutError("the policy is unchanged") from None
    finally:
        draft.unlink(missing_ok=True)
    return _apply_policy(hut, settings, staged, broker, runner, pause)


def _private(path, text):
    """Written as the user's alone from its creation."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def _checked(hut, text, dirs):
    """The text staged beside the policy, loaded as the inspector will
    load it, and the broker it gives the hut; or raise, staging nothing."""
    staged = hut.config / ".policy.json.new"
    try:
        _private(staged, text)
        try:
            policy = load_policy(staged)
        except (OSError, ValueError) as exc:
            raise HutError("policy: " + str(exc).replace(
                f"{staged}: ", "")) from None
        broker = _broker(policy, dirs)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return staged, broker


# How long a reload has to show in the inspector's status file, which it
# rewrites as soon as it has read the policy.
_RELOAD_WAIT = 5.0
_RELOAD_POLL = 0.1


class Applied(NamedTuple):
    """What a new policy did to a hut. `restarted` is why its inspector
    was restarted rather than reloaded, or None; `moved`, whether the
    workload's unit changed while it ran, which it has from its next
    start."""
    running: bool
    restarted: str | None = None
    moved: bool = False


def _apply_policy(hut, settings, staged, broker, runner, pause):
    """Put a checked policy in place, with the units its broker needs, and
    have the listeners read it if they are running: a reload, which cuts
    no connection, unless the inspector's unit or its `tls` changed."""
    units = render(hut, settings, broker)
    changed = {path for path, text in units.items()
               if not path.exists() or path.read_text() != text}
    gone = {path for path in hut.unit_files
            if path not in units and path.exists()}
    states = {unit: _state(unit, runner)
              for unit, _what, _effect in _listeners(hut)}
    running = any(state in ("active", "activating")
                  for state in states.values())
    text = staged.read_text()
    restart = None
    if hut.inspect_file in changed:
        restart = "its broker is " + ("new" if broker else "gone")
    elif _tls(hut.policy) != _tls(staged):
        restart = '"tls" changed'
    if hut.broker_file in gone:
        runner(["systemctl", "--user", "stop", hut.broker_service],
               check=False)
        _clear_broker(hut, runner)
    os.replace(staged, hut.policy)
    if changed or gone:
        _write_units(hut, settings, broker, runner)
        runner(["systemctl", "--user", "daemon-reload"])
    if not running:
        return Applied(False)
    broker_failed = False
    if broker and hut.broker_file in changed:
        _reset_broker(hut, runner)
        broker_failed = runner(
            ["systemctl", "--user", "start", hut.broker_service],
            check=False).returncode != 0
    # One activating reads the file when it has started.
    if states[hut.resolve_service] == "active":
        runner(["systemctl", "--user", "reload", hut.resolve_service],
               check=False)
    if restart is None and states[hut.inspect_service] == "active":
        runner(["systemctl", "--user", "reload", hut.inspect_service],
               check=False)
        if not _enforcing(hut, inspect_policy_digest(text), pause):
            restart = "it did not take the reload"
    if restart is not None:
        try:
            runner(["systemctl", "--user", "try-restart",
                    hut.inspect_service])
        except CommandFailed as exc:
            raise HutError(f"hut {hut.name}'s policy is replaced, but its "
                           f"inspector did not start again ({exc}); see "
                           f"journalctl --user -u {hut.inspect_service}"
                           ) from None
    if broker_failed:
        raise HutError(f"hut {hut.name}'s policy is replaced, but its broker "
                       "did not start, and requests with its credentials "
                       "are refused; see journalctl --user -u "
                       f"{hut.broker_service}")
    return Applied(True, restart,
                   hut.container_file in changed
                   and _state(hut.service, runner) == "active")


def _tls(path):
    """The document's `tls`, or None for one that does not load, which
    the inspector refuses to reload into and _enforcing catches."""
    try:
        return load_policy(path).tls
    except (OSError, ValueError):
        return None


def _enforcing(hut, digest, pause):
    """Whether the inspector's status file names the digest, within
    _RELOAD_WAIT."""
    for _ in range(round(_RELOAD_WAIT / _RELOAD_POLL)):
        try:
            doc = json.loads(hut.status.read_text())
        except (OSError, ValueError):
            doc = None
        if isinstance(doc, dict) and doc.get(INSPECT_DIGEST_KEY) == digest:
            return True
        pause(_RELOAD_POLL)
    return False


def _naming(credential, dirs):
    """The huts whose policies name the credential, with their settings
    and policies."""
    for hut, settings in _huts(dirs):
        policy = _policy(hut.policy)
        if any(e.credential == credential for e in policy.policy):
            yield hut, settings, policy


def _replace(path, data, mode=0o600):
    new = path.with_name(f".{path.name}.new")
    try:
        new.write_bytes(data)
        new.chmod(mode)
        os.replace(new, path)
    finally:
        new.unlink(missing_ok=True)


def credential_add(credential, secret, *, hosts, env, auth_header,
                   auth_format, dirs, runner=run):
    """Seal the secret, or replace one sealed before: what is not given is
    kept, and so is the placeholder. The huts naming it are written
    again and their brokers restarted. Returns their names and whether
    the variable changed, which a running hut's workload has from its
    next start."""
    if not valid_name(credential):
        raise HutError(f"{credential!r}: a credential's id is lowercase "
                       "letters, digits and inner dashes, 48 at most")
    try:
        old = credentials.read(dirs, credential)
    except CredentialError:
        if not (hosts and env):
            raise HutError(f"credential {credential} is new, and needs "
                           "--host and --env") from None
        old = credentials.Credential(
            credential, (), env, BROKER_DEFAULT_AUTH_HEADER,
            BROKER_DEFAULT_AUTH_FORMAT, credentials.placeholder())
    try:
        new = describe(credential, hosts or old.hosts, env or old.env,
                       auth_header or old.auth_header,
                       auth_format or old.auth_format, old.placeholder,
                       secret.strip(), reserved=RESERVED)
    except CredentialError as exc:
        raise HutError(f"credential: {exc}") from None

    def load(c):
        return new if c == credential else credentials.read(dirs, c)

    huts = []
    for hut, settings, policy in _naming(credential, dirs):
        try:
            huts.append((hut, settings, _broker(policy, dirs, load)))
        except HutError as exc:
            raise HutError(f"hut {hut.name}: {exc}") from None
    credentials_root(dirs).mkdir(mode=0o700, parents=True, exist_ok=True)
    path = sealed(dirs, credential)
    staged = path.with_name(f".{path.name}.new")
    try:
        runner(["systemd-creds", "--user", "encrypt",
                f"--name={credential}", "-", str(staged)],
               input=secret.strip())
        staged.chmod(0o600)
        os.replace(staged, path)
    finally:
        staged.unlink(missing_ok=True)
    _replace(described(dirs, credential), new.to_json().encode())
    for hut, settings, broker in huts:
        _write_units(hut, settings, broker, runner)
    if huts:
        runner(["systemctl", "--user", "daemon-reload"])
    failed = []
    for hut, _, _ in huts:
        if _broker_state(hut, runner) in ("active", "activating"):
            _reset_broker(hut, runner)
            if runner(["systemctl", "--user", "start", hut.broker_service],
                      check=False).returncode != 0:
                failed.append(hut.name)
    if failed:
        raise HutError(f"credential {credential} is sealed, but the broker "
                       f"of {', '.join(failed)} did not start again; see "
                       "journalctl --user -u 'moathut-*-broker'")
    return [hut.name for hut, _, _ in huts], new.env != old.env


def credential_ls(*, dirs):
    named = {}
    for hut, _settings in _huts(dirs):
        for entry in _policy(hut.policy).policy:
            if entry.credential:
                named.setdefault(entry.credential, set()).add(hut.name)
    rows = []
    for path in sorted(credentials_root(dirs).glob("*.json")):
        c = credentials.read(dirs, path.stem)
        rows.append((c.id, c.env, ",".join(c.hosts),
                     ",".join(sorted(named.get(c.id, ()))) or "-"))
    return rows


def credential_rm(credential, *, dirs):
    if not valid_name(credential) or not described(dirs,
                                                    credential).exists():
        raise HutError(f"no credential {credential}")
    huts = [hut.name for hut, _, _ in _naming(credential, dirs)]
    if huts:
        raise HutError(f"credential {credential} is named by the policy of "
                       f"{', '.join(huts)}")
    sealed(dirs, credential).unlink(missing_ok=True)
    described(dirs, credential).unlink()


def _until_stopped():
    while True:
        signal.pause()


def unit_netns(name, *, dirs, runner=run, ready=notify_ready,
               wait=_until_stopped, fork=os.fork):
    """The hut's network namespace, made in the user namespace `podman
    unshare` is root in, as the netns unit runs it: connected by pasta,
    the rules in, and its name where the hut reads it, written in place,
    since the hut mounts the file and not the directory. What a holder
    killed left is let go first.

    Then a fork holds it, until `wait` returns or raises, and lets go;
    this process tells the manager the holder is the unit's main process
    and returns. podman exits with it, and the holder, the manager's
    child then, is one whose end the manager sees."""
    hut = _hut(name, dirs)
    if dirs.runtime is None:
        raise HutError("XDG_RUNTIME_DIR is not set, and a hut's network "
                       "namespace is held in it")
    path = hut.namespace
    release(path, runner)
    try:
        make(path, runner)
        connect(path, runner)
        load_rules(path, runner)
        with open(hut.netns_mark, "w") as mark:
            mark.write(netns_id(path, runner) + "\n")
        holder = fork()
    except BaseException:
        release(path, runner)
        raise
    if holder:
        ready(main_pid=holder)
        return
    try:
        wait()
    finally:
        release(path, runner)


def unit_exec(name, argv, *, runner=run, execv=os.execv):
    exec_with_pid(name, argv, runner, execv)


def unit_rotate(name, *, dirs, runner=run):
    """The HUP to the main process alone: the unit's others are openssl
    mints under way, which it would end."""
    hut, _settings = _existing(name, dirs)
    if record.rotate(hut.record):
        runner(["systemctl", "--user", "kill", "--kill-whom=main", "-s",
                "HUP", hut.inspect_service], check=False)


def unit_sudoers(name, *, dirs, runner=run):
    _, settings = _existing(name, dirs)
    runner(["podman", "exec", "--user", "0", name, "sh", "-c", _SUDOERS,
            "sh", str(settings.uid)])
