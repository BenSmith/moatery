"""A hut's units as text: its network namespace's, the inspector's,
the responder's and, if its policy names a credential, the broker's
for the user's manager; the pod and the workload for quadlet.

What starts what: `enter` starts the workload's unit, which Wants= and
is After= the two listener units; they are BindsTo= and After= the
pod's, which is BindsTo= and After= the namespace's, active only once
the namespace is connected and has the rules. The pod joins that
namespace, so a restart of the pod keeps it, rules and all; the pod
Wants= the listeners, so a restart brings them back, and the timer that
rotates the record, which is PartOf= it. A stop of the namespace's unit
stops the pod, and what is bound to it. The inspector Wants= and is
After= the broker, which is ready once it is listening, and holds
nothing of the namespace: a restart of the pod does not restart it, and
`stop` stops it.

Nothing Requires= a listener, whose restart would restart what does:
a listener that fails is restarted, and not the workload. Without them
the rules send the workload's connections to ports nothing listens on,
which refuse them. A new policy reloads the listeners, which restarts
nothing.

A hut made with `--network-policy none` has the namespace's unit, the
pod and the workload alone: no rules, no listeners and no CA, and pasta
forwards what it sends.
"""

import json
import re
from pathlib import Path
from typing import NamedTuple

from .mounts import Mount
from .netns import DNS, PID
from .paths import NETNS_DIR, sealed

# podman's default set, the most root in a hut holds; none is
# CAP_NET_ADMIN. The unit drops every other capability, so a
# containers.conf cannot widen it, and adds none: podman gives what a
# unit adds to the hut's user as well, and the user holds none.
CAPABILITIES = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
                "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP",
                "SETUID", "SYS_CHROOT")

# Every capability the kernel names, in its order (linux/capability.h).
ALL_CAPABILITIES = (
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL",
    "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE",
    "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
    "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
    "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
    "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL",
    "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM",
    "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE")

DROPPED = tuple(c for c in ALL_CAPABILITIES if c not in CAPABILITIES)

# Each replaces a client's trust store, so the bundle carries the
# system's CAs as well as the hut's.
CA_VARIABLES = ("SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS",
                "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT")

# Where the hut's prompt is mounted: Fedora's /etc/bashrc reads it, and
# the home's .bashrc that create writes reads it after.
PROMPT_PATH = "/etc/profile.d/moathut.sh"

# Where the hut reads the namespace its rules were loaded into.
MARK_PATH = "/run/moathut/netns"

# The host's zone, which podman's Timezone=local reads. A host without
# it is on UTC (localtime(5)), and podman refuses to start a container
# with local there.
LOCALTIME = Path("/etc/localtime")


class Settings(NamedTuple):
    """What `create` decided, kept in hut.json for the other commands."""
    image: str
    # None for a hut with no network policy, which has no bundle.
    trust_path: str | None
    home_path: str
    uid: int
    gid: int
    mounts: tuple
    tool: tuple
    python: str
    libexec: str
    pythonpath: str | None
    autostart: bool = False
    # A profile seccomp renders, or None for the hut's own, copied in.
    seccomp: str | None = "strict"
    # The SELinux level its pod and workload run at, and its own files
    # are labelled with: two categories no other hut's has. None, podman
    # picks one at each start.
    level: str | None = None
    # False for `--network-policy none`.
    inspected: bool = True

    def to_json(self):
        doc = self._asdict()
        doc["mounts"] = [m.as_json() for m in self.mounts]
        doc["tool"] = list(self.tool)
        return json.dumps(doc, indent=2) + "\n"

    @classmethod
    def from_json(cls, text):
        doc = json.loads(text)
        doc["mounts"] = tuple(Mount.from_json(m) for m in doc["mounts"])
        doc["tool"] = tuple(doc["tool"])
        return cls(**doc)


def _value(text):
    """A value read whole (quadlet's Volume=, Image=): `%` is a specifier
    in the ExecStart= it becomes."""
    text = str(text)
    if "\n" in text:
        raise ValueError(f"a newline cannot be written in a unit: {text!r}")
    return text.replace("%", "%%")


def _quoted(text):
    """A value split on whitespace and unquoted (Environment=)."""
    text = _value(text)
    if not text or re.search(r"[\s\"'\\]", text):
        text = '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return text


def _word(text):
    """One word of an Exec line, where `$` is a variable as well."""
    text = str(text)
    return '";"' if text == ";" else _quoted(text.replace("$", "$$"))


def _exec_line(argv, width=72):
    lines, line = [], ""
    for word in map(_word, argv):
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = "    " + word
        else:
            line = f"{line} {word}" if line else word
    return " \\\n".join(lines + [line])


def _environment(settings):
    if not settings.pythonpath:
        return ""
    return f"Environment={_quoted('PYTHONPATH=' + settings.pythonpath)}\n"


def interpreter(settings):
    """The programs run as the user, whose own site-packages come ahead
    of the installed package on the path, and a directory in the user's
    home can be a hut's mount. `-s` leaves the user's site off."""
    return [settings.python, "-s"]


def _program(settings, name):
    return [*interpreter(settings), str(Path(settings.libexec) / name)]


def _tool(settings, *args):
    return [*settings.tool, "unit", *args]


def netns_unit(hut, settings):
    if settings.inspected:
        what, held = "network namespace and rules", """\
pasta connects it and the rules go in before
# the pod joins it. Type=notify: started once they are in, when the
# process that holds it is named the main one. Stopped, it lets the
# namespace go, and pasta with it."""
    else:
        what, held = "network namespace", """\
pasta connects it before the pod joins it;
# the hut has no network policy, and no rules go in. Type=notify:
# started once it is connected, when the process that holds it is named
# the main one. Stopped, it lets the namespace go, and pasta with it."""
    return f"""\
# moatery hut {hut.name}: its network namespace, made in the user
# namespace `podman unshare` is root in, of which the hut's is a child,
# and held while this runs. {held}

[Unit]
Description=moatery hut {hut.name}: {what}

[Service]
Type=notify
NotifyAccess=all
{_environment(settings)}ExecStart={_exec_line(
    ["podman", "unshare", *_tool(settings, "netns", hut.name)])}
"""


def pod_unit(hut, settings):
    after = ("listeners and the workload start" if settings.inspected
             else "workload starts")
    return f"""\
# moatery hut {hut.name}: the pod, in the network namespace the hut's
# netns unit holds, which the pod's user namespace does not own. The
# {after} after it.

[Unit]
Description=moatery hut {hut.name}: pod
BindsTo={hut.netns_service}
After={hut.netns_service}
{_wants(hut, settings, hut.rotate_timer)}
[Pod]
PodName={hut.name}
Network=ns:%t/{NETNS_DIR}/{hut.name}
DNS={DNS}
UserNS=keep-id
ExitPolicy=continue
PodmanArgs=--hosts-file=image --share-parent=false{_pod_level(settings)}

[Service]
Environment={_quoted(f"CONTAINERS_CONF_OVERRIDE={hut.containers_conf}")}
"""


def _wants(hut, settings, *more):
    """The listeners, and `more`, for a hut that has them."""
    if not settings.inspected:
        return ""
    units = (hut.inspect_service, hut.resolve_service, *more)
    return f"Wants={' '.join(units)}\n"


def _pod_level(settings):
    """The workload joins the pod's IPC namespace, and its /dev/shm is
    labelled at the infra container's level."""
    if settings.level is None:
        return ""
    return f" --security-opt=label=level:{settings.level}"


def containers_conf(hut):
    return f"""\
# moatery hut {hut.name}: read last by podman for the pod. Its infra
# container joins a network namespace its user namespace does not own,
# where podman's default net sysctls cannot be set.
[containers]
default_sysctls = []
"""


def container_unit(hut, settings, broker):
    # The hut's own files are labelled with its level, which no other
    # hut's runs at; a mount is the user's, which huts may share.
    volumes = [f"{hut.home}:{settings.home_path}:Z",
               f"{hut.prompt}:{PROMPT_PATH}:ro,Z",
               f"{hut.netns_mark}:{MARK_PATH}:ro,Z"]
    if settings.inspected:
        volumes.insert(1, f"{hut.bundle}:{settings.trust_path}:ro,Z")
    for mount in settings.mounts:
        volumes.append(f"{mount.source}:{mount.target}:"
                       + ("ro,z" if mount.readonly else "z"))
    lines = [f"DropCapability={' '.join(DROPPED[i:i + 5])}"
             for i in range(0, len(DROPPED), 5)]
    if settings.level is not None:
        lines.append(f"SecurityLabelLevel={settings.level}")
    lines += [f"Volume={_value(v)}" for v in volumes]
    lines += [f"Environment={_quoted(f'{v}={settings.trust_path}')}"
              for v in (CA_VARIABLES if settings.inspected else ())]
    lines += [f"Environment={_quoted(f'{c.env}={c.placeholder}')}"
              for c in (broker.credentials if broker else ())]
    body = "\n".join(lines)
    # The user is named: podman gives a container whose user it is not told
    # root's capabilities, and exec as the user keeps them. WorkingDir is
    # also the home: podman writes the user's passwd entry with the working
    # directory as its home.
    return f"""\
# moatery hut {hut.name}: the workload. A new container from the image at
# every start; its home and its mounts are what persist.

[Unit]
Description=moatery hut {hut.name}
{_wants(hut, settings)}{_after(hut, settings)}
[Container]
ContainerName={hut.name}
Pod={hut.unit}.pod
Image={_value(settings.image)}
User={settings.uid}
Group={settings.gid}
WorkingDir={_value(settings.home_path)}
Exec=sleep infinity
RunInit=true
Timezone={_timezone()}
SeccompProfile={_value(hut.seccomp)}
{body}

[Service]
{_environment(settings)}ExecStartPost=-{_exec_line(
    _tool(settings, "sudoers", hut.name))}
SuccessExitStatus=143
""" + (_AUTOSTART if settings.autostart else "")


def _after(hut, settings):
    if not settings.inspected:
        return ""
    return f"After={hut.inspect_service} {hut.resolve_service}\n"


def _timezone():
    return "local" if LOCALTIME.exists() else "UTC"


# Started with the user's manager, at login or, lingering, at boot, the
# way `enter` starts it: the pod and the listeners come first.
_AUTOSTART = """
[Install]
WantedBy=default.target
"""


def _listener_unit(hut, settings, what, argv, broker=None):
    after = [hut.pod_service] + ([hut.broker_service] if broker else [])
    wants = f"Wants={hut.broker_service}\n" if broker else ""
    return f"""\
# moatery hut {hut.name}: the {what}, its listeners bound in the pod's
# namespace. Type=notify: started once they are bound. A reload reads
# the policy again and cuts no connection.

[Unit]
Description=moatery hut {hut.name}: {what}
BindsTo={hut.pod_service}
{wants}After={' '.join(after)}

[Service]
Type=notify
{_environment(settings)}ExecStart={_exec_line(
    _tool(settings, "exec", hut.name, "--", *argv))}
ExecReload=kill -USR1 $MAINPID
Restart=on-failure
"""


def inspect_argv(hut, settings, broker):
    argv = [*_program(settings, "moat-netns-listen"), "--pid", PID,
            "--", *_program(settings, "moat-inspect"),
            "--name", hut.name, "--policy", str(hut.policy),
            "--state-dir", str(hut.state), "--status", str(hut.status),
            "--record", str(hut.record), "--netns-pid", PID]
    if broker:
        argv += ["--broker", f"unix:{hut.broker_socket}"]
    return argv


# What the responder answers every name with. The redirect is by port, so
# any address the workload's traffic leaves its namespace for lands on the
# listeners; loopback would not, from a VM's guest, whose 127.0.0.1 is its
# own. In 198.18.0.0/15, which is never routed (RFC 2544).
ANSWER = "198.18.0.1"


def resolve_argv(hut, settings):
    return [*_program(settings, "moat-netns-listen"), "--pid", PID,
            "--resolver", "--", *_program(settings, "moat-resolve"),
            "--name", hut.name, "--address", ANSWER,
            "--policy", str(hut.policy),
            "--status", str(hut.resolve_status)]


def inspect_unit(hut, settings, broker):
    return _listener_unit(hut, settings, "inspector",
                          inspect_argv(hut, settings, broker), broker)


def resolve_unit(hut, settings):
    return _listener_unit(hut, settings, "responder",
                          resolve_argv(hut, settings))


def broker_argv(hut, settings, broker):
    """Its one caller is the inspector, which runs as the user."""
    argv = [*_program(settings, "moat-broker"), "--name", hut.name,
            "--listen", f"unix:{hut.broker_socket}",
            "--caller-uid", str(settings.uid)]
    for host, credential in broker.hosts:
        argv += ["--host", f"{host}={credential}"]
    for c in broker.credentials:
        argv += ["--placeholder", f"{c.id}={c.placeholder}",
                 "--auth-header", f"{c.id}={c.auth_header}",
                 "--auth-format", f"{c.id}={c.auth_format}"]
    return argv


def broker_unit(hut, settings, broker):
    loads = "".join(
        f"LoadCredentialEncrypted={c.id}:{_value(sealed(hut.dirs, c.id))}\n"
        for c in broker.credentials)
    runtime = hut.runtime.relative_to(hut.dirs.runtime)
    return f"""\
# moatery hut {hut.name}: the broker, holding the credentials the hut's
# policy names. Its socket is in the user's runtime directory, which the
# hut has no path to. Type=notify: started once it is listening.

[Unit]
Description=moatery hut {hut.name}: broker

[Service]
Type=notify
{_environment(settings)}ExecStart={_exec_line(
    broker_argv(hut, settings, broker))}
{loads}RuntimeDirectory={_value(runtime)}
RuntimeDirectoryMode=0700
Restart=on-failure
"""


def rotate_unit(hut, settings):
    return f"""\
# moatery hut {hut.name}: its record moved aside once it is past its
# size, and the inspector told to reopen it. Started by its timer.

[Unit]
Description=moatery hut {hut.name}: rotate the record

[Service]
Type=oneshot
{_environment(settings)}ExecStart={_exec_line(
    _tool(settings, "rotate", hut.name))}
"""


def rotate_timer(hut):
    return f"""\
# moatery hut {hut.name}: the record's rotation, while the pod runs.

[Unit]
Description=moatery hut {hut.name}: rotate the record
PartOf={hut.pod_service}

[Timer]
OnActiveSec=1min
OnUnitActiveSec=10min
"""


def prompt(hut, inspected=True):
    """Read by every shell in the hut. In a hut with a network policy, an
    interactive one in another namespace than the rules were loaded
    into, as a container started from the hut's files by hand is, says
    the moat does not cover it. Then bash's prompt, the hut's name
    first: magenta, red as root, white on red when not covered, and
    marked uninspected in a hut with no network policy. Fedora's
    /etc/bashrc and the home's .bashrc both read it, and the second
    changes nothing."""
    name = hut.name
    warn = r"printf '\033[1;31m%s\033[0m\n  %s\n  %s\n  %s\n  %s\n'"
    if not inspected:
        head, tag = f"""\
# moatery hut {name}: the hut's name before bash's prompt; the hut has
# no network policy, and no rules to warn of.
_moathut_unprotected=
""", "' uninspected'"
    else:
        head, tag = f"""\
# moatery hut {name}: a warning in a shell the moat does not cover, and
# the hut's name before bash's prompt.
_moathut_unprotected=
case $- in
*i*)
    if [ -z "${{_moathut_checked:-}}" ]; then
        _moathut_checked=1
        if [ -s {MARK_PATH} ] &&
                [ "$(cat {MARK_PATH})" != "$(readlink /proc/self/ns/net)" ]
        then
            _moathut_unprotected=1
            {warn} \\
                'moathut: hut {name} is not protected by the moat.' \\
                'It was started outside moathut, so its network has none' \\
                "of the moat's rules: what runs in it reaches the network" \\
                'uninspected. On the host, run moathut stop {name}' \\
                'and then moathut enter {name}.' >&2
        fi
    fi ;;
esac
""", ""
    return head + f"""\
if [ -n "${{BASH_VERSION:-}}" ] && [ -n "${{PS1:-}}" ]; then
    case $PS1 in
    *'⬢ {name}'*) ;;
    *) if [ -n "$_moathut_unprotected" ]; then
           _moathut='1;37;41'; _moathut_tag=' UNPROTECTED'
       elif [ "$EUID" = 0 ]; then _moathut='1;31'; _moathut_tag={tag}
       else _moathut='35'; _moathut_tag={tag}
       fi
       _moathut="\\[\\e[${{_moathut}}m\\]⬢ {name}${{_moathut_tag}}"
       PS1="$_moathut\\[\\e[0m\\] $PS1"
       unset _moathut _moathut_tag ;;
    esac
fi
unset _moathut_unprotected
"""


def render(hut, settings, broker):
    """Unit file path to text, for every unit the hut has: the listeners'
    and the record's only if it has a network policy, and the broker's
    only if it has a broker."""
    units = {hut.netns_file: netns_unit(hut, settings),
             hut.pod_file: pod_unit(hut, settings),
             hut.container_file: container_unit(hut, settings, broker)}
    if settings.inspected:
        units.update({
            hut.inspect_file: inspect_unit(hut, settings, broker),
            hut.resolve_file: resolve_unit(hut, settings),
            hut.rotate_file: rotate_unit(hut, settings),
            hut.rotate_timer_file: rotate_timer(hut)})
    if broker:
        units[hut.broker_file] = broker_unit(hut, settings, broker)
    return units
