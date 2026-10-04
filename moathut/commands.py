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

from . import credentials, document, record, seccomp
from .credentials import CredentialError, brokering, describe
from .document import AllowRefused
from .mounts import MountRefused, parse_mount, refuse
from .netns import (NetnsError, connect, exec_with_pid, load_rules, make,
                    netns_id, pod_pid, release, rules_loaded)
from .paths import Box, boxes_root, credentials_root, described, sealed, \
    valid_name
from .process import CommandFailed, run
from .units import (CA_VARIABLES, MARK_PATH, PROMPT_PATH, Settings,
                    containers_conf, interpreter, prompt, render)

DEFAULT_IMAGE = "registry.fedoraproject.org/fedora-toolbox:44"
DEFAULT_LIBEXEC = "/usr/libexec/moatery"

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
printf '%s ALL=(ALL) NOPASSWD: ALL\\n' "$u" > /etc/sudoers.d/moathut
chmod 0440 /etc/sudoers.d/moathut
"""

PASSED_THROUGH = ("TERM", "COLORTERM", "LANG")

# What a credential's variable may not be: the box sets these itself.
RESERVED = CA_VARIABLES + PASSED_THROUGH


class BoxError(Exception):
    """A command refused, with the reason."""


def _box(name, dirs):
    if not valid_name(name):
        raise BoxError(f"{name!r}: a box's name is lowercase letters, "
                       "digits and inner dashes, 48 at most")
    return Box(name, dirs)


# How many categories podman picks a container's two from.
CATEGORIES = 1024

_sample = random.SystemRandom().sample


def _free_level(dirs):
    """Two categories no box has, its SELinux level."""
    taken = {settings.level for _, settings in _boxes(dirs)}
    while True:
        level = "s0:c{},c{}".format(*sorted(_sample(range(CATEGORIES), 2)))
        if level not in taken:
            return level


def _existing(name, dirs):
    """The box and its settings: a box with no level is given one, which
    it runs at from its next start."""
    box = _box(name, dirs)
    if not box.settings.exists():
        raise BoxError(f"no box {name}")
    settings = Settings.from_json(box.settings.read_text())
    if settings.level is None:
        settings = settings._replace(level=_free_level(dirs))
        box.settings.write_text(settings.to_json())
    return box, settings


def _boxes(dirs):
    for settings_file in sorted(boxes_root(dirs).glob("*/box.json")):
        yield (Box(settings_file.parent.name, dirs),
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
        raise BoxError(f"policy: {exc}") from None


def _broker(policy, dirs, load=None):
    """The box's broker, from its policy and the credentials it names."""
    try:
        broker = brokering(
            policy, load or (lambda c: credentials.read(dirs, c)))
    except CredentialError as exc:
        raise BoxError(f"policy: {exc}") from None
    if broker and dirs.runtime is None:
        raise BoxError("XDG_RUNTIME_DIR is not set, and a box's broker "
                       "listens in it")
    return broker


# Read by a shell in a home with no .bashrc of its own: the image's,
# then the box's prompt, which bash would otherwise not read.
_BASHRC = f"""\
[ -f /etc/bashrc ] && . /etc/bashrc
[ -f {PROMPT_PATH} ] && . {PROMPT_PATH}
"""


def _written(box, settings, broker):
    """Path to text, for each file the units are and each they read
    that is written with them: a box's own seccomp profile is not, and
    stays as it was copied in."""
    written = {**render(box, settings, broker), box.prompt: prompt(box),
               box.containers_conf: containers_conf(box)}
    if settings.seccomp is not None:
        try:
            written[box.seccomp] = seccomp.render(settings.seccomp)
        except ValueError as exc:
            raise BoxError(f"box {box.name}: {exc}") from None
    return written


# The states in which a unit holds what it started with.
_UP = ("active", "activating", "deactivating", "reloading")


def _running(box, runner):
    return _state(box.pod_service, runner) in _UP


def _write_units(box, settings, broker, runner):
    """The box's files as `_written` gives them, and the units it no
    longer has removed. While its pod runs, the files its namespace and
    its shells started with are kept: a reload would give the running
    pod a unit bound to a namespace unit that is not running, and the
    manager would stop it. `enter` writes them at its next start."""
    units = _written(box, settings, broker)
    kept = ((box.netns_file, box.pod_file, box.containers_conf, box.prompt)
            if _running(box, runner) else ())
    for path, text in units.items():
        if path in kept:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for path in box.unit_files:
        if path not in units and path not in kept:
            path.unlink(missing_ok=True)
    # The workload mounts it, and podman will not start a container with
    # a mount whose source is missing. Empty until the rules name the
    # namespace, which the box reads as not knowing.
    box.netns_mark.parent.mkdir(parents=True, exist_ok=True)
    box.netns_mark.touch()


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


def _own_profile(given, cwd):
    """The text of a seccomp profile file, as podman will read it."""
    path = Path(cwd, given).expanduser()
    try:
        text = path.read_text()
        doc = json.loads(text)
    except OSError as exc:
        raise BoxError(f"--seccomp {given}: {exc.strerror}; it is "
                       f"{' or '.join(seccomp.PROFILES)}, or a profile "
                       "file") from None
    except ValueError as exc:
        raise BoxError(f"--seccomp {given}: {exc}") from None
    if not isinstance(doc, dict) or "defaultAction" not in doc:
        raise BoxError(f"--seccomp {given}: a seccomp profile has a "
                       "defaultAction")
    return text


def create(name, policy_path, image, mount_specs, *, dirs, tool, python,
           libexec, pythonpath, uid, gid, cwd, environ, autostart=False,
           dry_run=False, like=None, profile=None, runner=run):
    """The box; with dry_run, what would be written, path to text, and
    nothing is. A box `like` another starts from its policy, image,
    mounts and seccomp profile: a policy, image or profile given
    replaces its, and a mount given joins its, replacing one at the same
    target. `profile` names one of seccomp's or a file, copied in."""
    box = _box(name, dirs)
    if box.config.exists() or any(p.exists() for p in box.unit_files):
        raise BoxError(f"box {name} exists")
    for kind in ("container", "pod"):
        if runner(["podman", kind, "exists", name],
                  check=False).returncode == 0:
            raise BoxError(f"a {kind} named {name} exists")
    try:
        given = [(parse_mount(spec, cwd, dirs.home), "--mount")
                 for spec in mount_specs]
    except MountRefused as exc:
        raise BoxError(f"--mount {exc}") from None
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
        inherited = [(mount, f"box {like}'s mount")
                     for mount in other_settings.mounts
                     if mount.target not in targets]
    if policy_path is None:
        raise BoxError("create needs --policy FILE or --like BOX")
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
            raise BoxError(f"{origin} {exc}") from None
    mounts = tuple(mount for mount, _ in inherited + given)
    settings = Settings(image=image, trust_path=trust_path,
                        home_path=home_path, uid=uid, gid=gid,
                        mounts=mounts, tool=tuple(tool), python=python,
                        libexec=str(libexec), pythonpath=pythonpath,
                        autostart=autostart, seccomp=profile,
                        level=_free_level(dirs))
    if dry_run:
        return {**_written(box, settings, broker),
                **({box.seccomp: own} if own is not None else {})}
    home_existed = box.home.exists()
    try:
        _lay_out(box, settings, broker, policy_path, host_bundle, environ,
                 own, runner)
    except BaseException:
        _discard(box, home=not home_existed, runner=runner)
        raise
    return box


def _lay_out(box, settings, broker, policy_path, host_bundle, environ,
             own_profile, runner):
    for path in (box.config, box.state, box.logs, box.home):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The runtime makes a missing mount point, and each directory above
    # it, as the box's root, which the user could not write in its own
    # home.
    for mount in settings.mounts:
        target = PurePosixPath(mount.target)
        if target.is_relative_to(settings.home_path):
            (box.home / target.relative_to(settings.home_path)).mkdir(
                parents=True, exist_ok=True)
    bashrc = box.home / ".bashrc"
    if not bashrc.exists():
        bashrc.write_text(_BASHRC)
    box.policy.write_bytes(Path(policy_path).read_bytes())
    box.policy.chmod(0o600)
    minted = runner([*interpreter(settings),
                     str(Path(settings.libexec) / "moat-mint-ca"),
                     "--name", box.name, "--state-dir", str(box.state)],
                    env=_program_env(environ, settings.pythonpath))
    ca = Path(minted.stdout.strip())
    box.bundle.write_text(ca.read_text() + host_bundle.read_text())
    box.bundle.chmod(0o644)
    if own_profile is not None:
        box.seccomp.write_text(own_profile)
    _write_units(box, settings, broker, runner)
    box.settings.write_text(settings.to_json())
    runner(["systemctl", "--user", "daemon-reload"])
    for service in (box.pod_service, box.service):
        state = runner(["systemctl", "--user", "show", "-p", "LoadState",
                        "--value", service]).stdout.strip()
        if state != "loaded":
            raise BoxError(f"quadlet did not generate {service} "
                           "(/usr/libexec/podman/quadlet -dryrun -user "
                           "says why)")


def _units_to_stop(box):
    """The namespace's unit stops the pod, and the pod what is bound to
    it; the pod is named too, for a box whose units have no namespace's
    unit yet."""
    return [box.pod_service] + [
        unit for unit, path in ((box.netns_service, box.netns_file),
                                (box.broker_service, box.broker_file))
        if path.exists()]


def _discard(box, *, home, runner):
    runner(["systemctl", "--user", "stop", *_units_to_stop(box)],
           check=False)
    if box.broker_file.exists():
        _clear_broker(box, runner)
    for path in box.unit_files:
        path.unlink(missing_ok=True)
    runner(["systemctl", "--user", "daemon-reload"], check=False)
    runner(["systemctl", "--user", "reset-failed", *box.services],
           check=False)
    runner(["podman", "pod", "rm", "-f", "-i", box.name], check=False)
    shutil.rmtree(box.config, ignore_errors=True)
    shutil.rmtree(box.state, ignore_errors=True)
    if home:
        _remove_home(box, runner)


def _remove_home(box, runner):
    # The box's other uids write in its home too: root by sudo, and the
    # runtime.
    runner(["podman", "unshare", "rm", "-rf", "--", str(box.share)],
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


def _login_shell(box, user, environ, runner):
    shell = runner(["podman", "exec", "--user", user, box.name, "sh", "-c",
                    _SHELL, "sh", environ.get("SHELL", ""), "/bin/bash"],
                   check=False).stdout.strip()
    return [shell or "/bin/sh", "-l"]


def _state(unit, runner):
    return runner(["systemctl", "--user", "is-active", unit],
                  check=False).stdout.strip()


def _broker_state(box, runner):
    return _state(box.broker_service, runner)


def _listeners(box):
    """Each listener's unit, and what the box's workload finds while it
    is not running."""
    return ((box.inspect_service, "inspector",
             "its connections are refused"),
            (box.resolve_service, "responder",
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


def _reset_broker(box, runner):
    runner(["systemctl", "--user", "stop", box.broker_service], check=False)
    _clear_broker(box, runner)


def _clear_broker(box, runner):
    """What systemd leaves when it stops a credentialed unit while the
    unit's credentials are being decrypted: the workspace, which every
    start after fails on, a restart after a restart, and those
    failures."""
    if box.dirs.runtime is not None:
        _remove_tree(box.dirs.runtime / "systemd" / "temporary-credentials"
                     / box.broker_service)
    runner(["systemctl", "--user", "reset-failed", box.broker_service],
           check=False)


def _refresh(box, settings, dirs, runner):
    """A stopped box's files written again if this moathut would write
    them otherwise, so its start is one this moathut made."""
    broker = _broker(_policy(box.policy), dirs)
    units = _written(box, settings, broker)
    if any(not path.exists() or path.read_text() != text
           for path, text in units.items()) or any(
            path.exists() for path in box.unit_files if path not in units):
        _write_units(box, settings, broker, runner)
        runner(["systemctl", "--user", "daemon-reload"])


def enter(name, command, *, root, dirs, cwd, environ, isatty,
          runner=run, execvp=os.execvp, warn=_warn):
    box, settings = _existing(name, dirs)
    if not _running(box, runner):
        _refresh(box, settings, dirs, runner)
    if box.broker_file.exists() and _broker_state(box, runner) != "active":
        _reset_broker(box, runner)
    try:
        runner(["systemctl", "--user", "start", box.service])
    except CommandFailed as exc:
        raise BoxError(f"box {name} did not start ({exc}); see "
                       f"journalctl --user -u '{box.unit}*'") from None
    if not rules_loaded(pod_pid(name, runner), runner):
        raise BoxError(f"box {name}'s namespace has no moatery rules. "
                       f"moathut stop {name}, then enter it again")
    # Nothing requires them, so the workload starts without them.
    for unit, what, effect in _listeners(box):
        if _state(unit, runner) == "active":
            continue
        runner(["systemctl", "--user", "reset-failed", unit], check=False)
        if runner(["systemctl", "--user", "start", unit],
                  check=False).returncode != 0:
            warn(f"box {name}'s {what} did not start, and {effect} until "
                 f"it does; see journalctl --user -u {unit}")
    # Started again if it stopped; without it, a request with one of its
    # credentials is refused, not sent without.
    if box.broker_file.exists() and runner(
            ["systemctl", "--user", "start", box.broker_service],
            check=False).returncode != 0:
        warn(f"box {name}'s broker did not start, and requests with its "
             f"credentials are refused; see journalctl --user -u "
             f"{box.broker_service}")
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
    runner(["systemctl", "--user", "stop", *_units_to_stop(box)])


def rm(name, *, home, dirs, runner=run):
    """Remove the box, or with `home`, the home a box removed without it
    left behind."""
    box = _box(name, dirs)
    if box.settings.exists():
        _discard(box, home=home, runner=runner)
    elif home and box.share.exists():
        _remove_home(box, runner)
    else:
        raise BoxError(f"no box {name}")
    if home and box.share.exists():
        raise BoxError(f"box {name} is removed but its home is not: "
                       f"podman unshare rm -rf {box.share}")
    return [str(box.logs)] + ([] if home else [str(box.home)])


def _unprotected(box, runner):
    """Whether its pod runs in a namespace without the rules."""
    if runner(["podman", "pod", "exists", box.name],
              check=False).returncode != 0:
        return False
    try:
        pid = pod_pid(box.name, runner)
    except (CommandFailed, NetnsError):
        return False
    return not rules_loaded(pid, runner)


def ls(*, dirs, runner=run):
    rows = []
    for box, settings in _boxes(dirs):
        state = runner(["systemctl", "--user", "is-active", box.service],
                       check=False).stdout.strip() or "unknown"
        rows.append((box.name, state, settings.image)
                    + ((f"seccomp:{settings.seccomp or 'own'}",)
                       if settings.seccomp != seccomp.DEFAULT else ())
                    + (("autostart",) if settings.autostart else ())
                    + (("unprotected",) if _unprotected(box, runner)
                       else ()))
    return rows


def log(name, *, dirs, write=print, pause=time.sleep):
    box, _settings = _existing(name, dirs)
    record.follow(box.record, write, pause=pause)


def refused(name, *, dirs):
    """The refusals in the box's record its policy would still make, and
    the names its workload asked for that no list admits."""
    box, _settings = _existing(name, dirs)
    policy = _policy(box.policy)
    docs = (doc for path in record.records(box.record)
            for doc in record.lines(path))
    return (record.refusals(docs, policy),
            record.unlisted(box.resolve_status, policy))


def allow(name, host, *, methods, paths, dirs, runner=run,
          pause=time.sleep):
    """Widen the box's policy for HOST and apply it. None if the policy
    allows it already."""
    box, settings = _existing(name, dirs)
    policy = _policy(box.policy)
    try:
        doc = document.allow(json.loads(box.policy.read_text()), policy,
                             document.host_name(host), methods, paths)
    except AllowRefused as exc:
        raise BoxError(f"allow: {exc}") from None
    if doc is None:
        return None
    staged, broker = _checked(box, document.dumps(doc), dirs)
    return _apply_policy(box, settings, staged, broker, runner, pause)


def edit_policy(name, *, dirs, environ, isatty, runner=run,
                edit=subprocess.run, ask=input, pause=time.sleep):
    """Open a copy of the box's policy in the user's editor, and apply it
    once it loads. A copy that does not is opened again, if there is a
    terminal to ask on. None if it came back unchanged."""
    box, settings = _existing(name, dirs)
    editor = shlex.split(environ.get("VISUAL") or environ.get("EDITOR")
                         or "vi")
    original = box.policy.read_text()
    draft = box.config / ".policy.json.edit"
    _private(draft, original)
    try:
        while True:
            done = edit([*editor, str(draft)])
            if done.returncode != 0:
                raise BoxError(f"{editor[0]} exited {done.returncode}; the "
                               "policy is unchanged")
            text = draft.read_text()
            if text == original:
                return None
            try:
                staged, broker = _checked(box, text, dirs)
                break
            except BoxError as exc:
                if not isatty:
                    raise
                _warn(str(exc))
                if ask("edit it again? [Y/n] ").strip().lower() in ("n",
                                                                    "no"):
                    raise BoxError("the policy is unchanged") from None
    finally:
        draft.unlink(missing_ok=True)
    return _apply_policy(box, settings, staged, broker, runner, pause)


def _private(path, text):
    """Written as the user's alone from its creation."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def _checked(box, text, dirs):
    """The text staged beside the policy, loaded as the inspector will
    load it, and the broker it gives the box; or raise, staging nothing."""
    staged = box.config / ".policy.json.new"
    try:
        _private(staged, text)
        try:
            policy = load_policy(staged)
        except (OSError, ValueError) as exc:
            raise BoxError("policy: " + str(exc).replace(
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
    """What a new policy did to a box. `restarted` is why its inspector
    was restarted rather than reloaded, or None; `moved`, whether the
    workload's unit changed while it ran, which it has from its next
    start."""
    running: bool
    restarted: str | None = None
    moved: bool = False


def _apply_policy(box, settings, staged, broker, runner, pause):
    """Put a checked policy in place, with the units its broker needs, and
    have the listeners read it if they are running: a reload, which cuts
    no connection, unless the inspector's unit or its `tls` changed."""
    units = render(box, settings, broker)
    changed = {path for path, text in units.items()
               if not path.exists() or path.read_text() != text}
    gone = {path for path in box.unit_files
            if path not in units and path.exists()}
    states = {unit: _state(unit, runner)
              for unit, _what, _effect in _listeners(box)}
    running = any(state in ("active", "activating")
                  for state in states.values())
    text = staged.read_text()
    restart = None
    if box.inspect_file in changed:
        restart = "its broker is " + ("new" if broker else "gone")
    elif _tls(box.policy) != _tls(staged):
        restart = '"tls" changed'
    if box.broker_file in gone:
        runner(["systemctl", "--user", "stop", box.broker_service],
               check=False)
        _clear_broker(box, runner)
    os.replace(staged, box.policy)
    if changed or gone:
        _write_units(box, settings, broker, runner)
        runner(["systemctl", "--user", "daemon-reload"])
    if not running:
        return Applied(False)
    broker_failed = False
    if broker and box.broker_file in changed:
        _reset_broker(box, runner)
        broker_failed = runner(
            ["systemctl", "--user", "start", box.broker_service],
            check=False).returncode != 0
    # One activating reads the file when it has started.
    if states[box.resolve_service] == "active":
        runner(["systemctl", "--user", "reload", box.resolve_service],
               check=False)
    if restart is None and states[box.inspect_service] == "active":
        runner(["systemctl", "--user", "reload", box.inspect_service],
               check=False)
        if not _enforcing(box, inspect_policy_digest(text), pause):
            restart = "it did not take the reload"
    if restart is not None:
        try:
            runner(["systemctl", "--user", "try-restart",
                    box.inspect_service])
        except CommandFailed as exc:
            raise BoxError(f"box {box.name}'s policy is replaced, but its "
                           f"inspector did not start again ({exc}); see "
                           f"journalctl --user -u {box.inspect_service}"
                           ) from None
    if broker_failed:
        raise BoxError(f"box {box.name}'s policy is replaced, but its broker "
                       "did not start, and requests with its credentials "
                       "are refused; see journalctl --user -u "
                       f"{box.broker_service}")
    return Applied(True, restart,
                   box.container_file in changed
                   and _state(box.service, runner) == "active")


def _tls(path):
    """The document's `tls`, or None for one that does not load, which
    the inspector refuses to reload into and _enforcing catches."""
    try:
        return load_policy(path).tls
    except (OSError, ValueError):
        return None


def _enforcing(box, digest, pause):
    """Whether the inspector's status file names the digest, within
    _RELOAD_WAIT."""
    for _ in range(round(_RELOAD_WAIT / _RELOAD_POLL)):
        try:
            doc = json.loads(box.status.read_text())
        except (OSError, ValueError):
            doc = None
        if isinstance(doc, dict) and doc.get(INSPECT_DIGEST_KEY) == digest:
            return True
        pause(_RELOAD_POLL)
    return False


def _naming(credential, dirs):
    """The boxes whose policies name the credential, with their settings
    and policies."""
    for box, settings in _boxes(dirs):
        policy = _policy(box.policy)
        if any(e.credential == credential for e in policy.policy):
            yield box, settings, policy


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
    kept, and so is the placeholder. The boxes naming it are written
    again and their brokers restarted. Returns their names and whether
    the variable changed, which a running box's workload has from its
    next start."""
    if not valid_name(credential):
        raise BoxError(f"{credential!r}: a credential's id is lowercase "
                       "letters, digits and inner dashes, 48 at most")
    try:
        old = credentials.read(dirs, credential)
    except CredentialError:
        if not (hosts and env):
            raise BoxError(f"credential {credential} is new, and needs "
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
        raise BoxError(f"credential: {exc}") from None

    def load(c):
        return new if c == credential else credentials.read(dirs, c)

    boxes = []
    for box, settings, policy in _naming(credential, dirs):
        try:
            boxes.append((box, settings, _broker(policy, dirs, load)))
        except BoxError as exc:
            raise BoxError(f"box {box.name}: {exc}") from None
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
    for box, settings, broker in boxes:
        _write_units(box, settings, broker, runner)
    if boxes:
        runner(["systemctl", "--user", "daemon-reload"])
    failed = []
    for box, _, _ in boxes:
        if _broker_state(box, runner) in ("active", "activating"):
            _reset_broker(box, runner)
            if runner(["systemctl", "--user", "start", box.broker_service],
                      check=False).returncode != 0:
                failed.append(box.name)
    if failed:
        raise BoxError(f"credential {credential} is sealed, but the broker "
                       f"of {', '.join(failed)} did not start again; see "
                       "journalctl --user -u 'moathut-*-broker'")
    return [box.name for box, _, _ in boxes], new.env != old.env


def credential_ls(*, dirs):
    named = {}
    for box, _settings in _boxes(dirs):
        for entry in _policy(box.policy).policy:
            if entry.credential:
                named.setdefault(entry.credential, set()).add(box.name)
    rows = []
    for path in sorted(credentials_root(dirs).glob("*.json")):
        c = credentials.read(dirs, path.stem)
        rows.append((c.id, c.env, ",".join(c.hosts),
                     ",".join(sorted(named.get(c.id, ()))) or "-"))
    return rows


def credential_rm(credential, *, dirs):
    if not valid_name(credential) or not described(dirs,
                                                    credential).exists():
        raise BoxError(f"no credential {credential}")
    boxes = [box.name for box, _, _ in _naming(credential, dirs)]
    if boxes:
        raise BoxError(f"credential {credential} is named by the policy of "
                       f"{', '.join(boxes)}")
    sealed(dirs, credential).unlink(missing_ok=True)
    described(dirs, credential).unlink()


def _until_stopped():
    while True:
        signal.pause()


def unit_netns(name, *, dirs, runner=run, ready=notify_ready,
               wait=_until_stopped, fork=os.fork):
    """The box's network namespace, made in the user namespace `podman
    unshare` is root in, as the netns unit runs it: connected by pasta,
    the rules in, and its name where the box reads it, written in place,
    since the box mounts the file and not the directory. What a holder
    killed left is let go first.

    Then a fork holds it, until `wait` returns or raises, and lets go;
    this process tells the manager the holder is the unit's main process
    and returns. podman exits with it, and the holder, the manager's
    child then, is one whose end the manager sees."""
    box = _box(name, dirs)
    if dirs.runtime is None:
        raise BoxError("XDG_RUNTIME_DIR is not set, and a box's network "
                       "namespace is held in it")
    path = box.namespace
    release(path, runner)
    try:
        make(path, runner)
        connect(path, runner)
        load_rules(path, runner)
        with open(box.netns_mark, "w") as mark:
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
    box, _settings = _existing(name, dirs)
    if record.rotate(box.record):
        runner(["systemctl", "--user", "kill", "--kill-whom=main", "-s",
                "HUP", box.inspect_service], check=False)


def unit_sudoers(name, *, dirs, runner=run):
    _, settings = _existing(name, dirs)
    runner(["podman", "exec", "--user", "0", name, "sh", "-c", _SUDOERS,
            "sh", str(settings.uid)])
