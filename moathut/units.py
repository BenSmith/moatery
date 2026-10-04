"""A box's units as text: the pod and the workload for quadlet, the
inspector, the responder and, if its policy names a credential, the
broker for the user's manager.

What starts what: `enter` starts the workload's unit, which Wants= and
is After= the two listener units; they are BindsTo= and After= the
pod's, which is active only once its ExecStartPost= has loaded the
rules. The pod Wants= the listeners, so a restart of the pod brings
them back into its new namespace, and the timer that rotates the
record, which is PartOf= it. The inspector Wants= and is After=
the broker, which is ready once it is listening, and holds nothing of
the namespace: a restart of the pod does not restart it, and `stop`
stops it.

Nothing Requires= a listener, whose restart would restart what does:
a listener that fails is restarted, and not the workload. Without them
the rules send the workload's connections to ports nothing listens on,
which refuse them. A new policy reloads the listeners, which restarts
nothing.
"""

import json
import re
from pathlib import Path
from typing import NamedTuple

from .mounts import Mount
from .netns import PID
from .paths import sealed

# podman's default set, the most root in a box holds; none is
# CAP_NET_ADMIN. The unit drops every other capability, so a
# containers.conf cannot widen it, and adds none: podman gives what a
# unit adds to the box's user as well, and the user holds none.
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
# system's CAs as well as the box's.
CA_VARIABLES = ("SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS",
                "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT")

# Where the box's prompt is mounted: Fedora's /etc/bashrc reads it, and
# the home's .bashrc that create writes reads it after.
PROMPT_PATH = "/etc/profile.d/moathut.sh"

# Where the box reads the namespace its rules were loaded into.
MARK_PATH = "/run/moathut/netns"


class Settings(NamedTuple):
    """What `create` decided, kept in box.json for the other commands."""
    image: str
    trust_path: str
    home_path: str
    uid: int
    gid: int
    mounts: tuple
    tool: tuple
    python: str
    libexec: str
    pythonpath: str | None
    autostart: bool = False

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
    home can be a box's mount. `-s` leaves the user's site off."""
    return [settings.python, "-s"]


def _program(settings, name):
    return [*interpreter(settings), str(Path(settings.libexec) / name)]


def _tool(settings, *args):
    return [*settings.tool, "unit", *args]


def pod_unit(box, settings):
    return f"""\
# moatery box {box.name}: the pod, holding the network namespace. Its
# start loads the rules; the listeners and the workload start after.

[Unit]
Description=moatery box {box.name}: pod and rules
Wants={box.inspect_service} {box.resolve_service} {box.rotate_timer}

[Pod]
PodName={box.name}
Network=pasta
UserNS=keep-id
ExitPolicy=continue
PodmanArgs=--hosts-file=image --share-parent=false

[Service]
{_environment(settings)}ExecStartPost={_exec_line(
    _tool(settings, "rules", box.name))}
"""


def container_unit(box, settings, broker):
    volumes = [f"{box.home}:{settings.home_path}:z",
               f"{box.bundle}:{settings.trust_path}:ro,z",
               f"{box.prompt}:{PROMPT_PATH}:ro,z",
               f"{box.netns_mark}:{MARK_PATH}:ro,z"]
    for mount in settings.mounts:
        volumes.append(f"{mount.source}:{mount.target}:"
                       + ("ro,z" if mount.readonly else "z"))
    lines = [f"DropCapability={' '.join(DROPPED[i:i + 5])}"
             for i in range(0, len(DROPPED), 5)]
    lines += [f"Volume={_value(v)}" for v in volumes]
    lines += [f"Environment={_quoted(f'{v}={settings.trust_path}')}"
              for v in CA_VARIABLES]
    lines += [f"Environment={_quoted(f'{c.env}={c.placeholder}')}"
              for c in (broker.credentials if broker else ())]
    body = "\n".join(lines)
    # The user is named: podman gives a container whose user it is not told
    # root's capabilities, and exec as the user keeps them. WorkingDir is
    # also the home: podman writes the user's passwd entry with the working
    # directory as its home.
    return f"""\
# moatery box {box.name}: the workload. A new container from the image at
# every start; its home and its mounts are what persist.

[Unit]
Description=moatery box {box.name}
Wants={box.inspect_service} {box.resolve_service}
After={box.inspect_service} {box.resolve_service}

[Container]
ContainerName={box.name}
Pod={box.unit}.pod
Image={_value(settings.image)}
User={settings.uid}
Group={settings.gid}
WorkingDir={_value(settings.home_path)}
Exec=sleep infinity
RunInit=true
Timezone=local
{body}

[Service]
{_environment(settings)}ExecStartPost=-{_exec_line(
    _tool(settings, "sudoers", box.name))}
SuccessExitStatus=143
""" + (_AUTOSTART if settings.autostart else "")


# Started with the user's manager, at login or, lingering, at boot, the
# way `enter` starts it: the pod and the listeners come first.
_AUTOSTART = """
[Install]
WantedBy=default.target
"""


def _listener_unit(box, settings, what, argv, broker=None):
    after = [box.pod_service] + ([box.broker_service] if broker else [])
    wants = f"Wants={box.broker_service}\n" if broker else ""
    return f"""\
# moatery box {box.name}: the {what}, its listeners bound in the pod's
# namespace. Type=notify: started once they are bound. A reload reads
# the policy again and cuts no connection.

[Unit]
Description=moatery box {box.name}: {what}
BindsTo={box.pod_service}
{wants}After={' '.join(after)}

[Service]
Type=notify
{_environment(settings)}ExecStart={_exec_line(
    _tool(settings, "exec", box.name, "--", *argv))}
ExecReload=kill -USR1 $MAINPID
Restart=on-failure
"""


def inspect_argv(box, settings, broker):
    argv = [*_program(settings, "moat-netns-listen"), "--pid", PID,
            "--", *_program(settings, "moat-inspect"),
            "--name", box.name, "--policy", str(box.policy),
            "--state-dir", str(box.state), "--status", str(box.status),
            "--record", str(box.record), "--netns-pid", PID]
    if broker:
        argv += ["--broker", f"unix:{box.broker_socket}"]
    return argv


# What the responder answers every name with. The redirect is by port, so
# any address the workload's traffic leaves its namespace for lands on the
# listeners; loopback would not, from a VM's guest, whose 127.0.0.1 is its
# own. In 198.18.0.0/15, which is never routed (RFC 2544).
ANSWER = "198.18.0.1"


def resolve_argv(box, settings):
    return [*_program(settings, "moat-netns-listen"), "--pid", PID,
            "--resolver", "--", *_program(settings, "moat-resolve"),
            "--name", box.name, "--address", ANSWER,
            "--policy", str(box.policy),
            "--status", str(box.resolve_status)]


def inspect_unit(box, settings, broker):
    return _listener_unit(box, settings, "inspector",
                          inspect_argv(box, settings, broker), broker)


def resolve_unit(box, settings):
    return _listener_unit(box, settings, "responder",
                          resolve_argv(box, settings))


def broker_argv(box, settings, broker):
    """Its one caller is the inspector, which runs as the user."""
    argv = [*_program(settings, "moat-broker"), "--name", box.name,
            "--listen", f"unix:{box.broker_socket}",
            "--caller-uid", str(settings.uid)]
    for host, credential in broker.hosts:
        argv += ["--host", f"{host}={credential}"]
    for c in broker.credentials:
        argv += ["--placeholder", f"{c.id}={c.placeholder}",
                 "--auth-header", f"{c.id}={c.auth_header}",
                 "--auth-format", f"{c.id}={c.auth_format}"]
    return argv


def broker_unit(box, settings, broker):
    loads = "".join(
        f"LoadCredentialEncrypted={c.id}:{_value(sealed(box.dirs, c.id))}\n"
        for c in broker.credentials)
    runtime = box.runtime.relative_to(box.dirs.runtime)
    return f"""\
# moatery box {box.name}: the broker, holding the credentials the box's
# policy names. Its socket is in the user's runtime directory, which the
# box has no path to. Type=notify: started once it is listening.

[Unit]
Description=moatery box {box.name}: broker

[Service]
Type=notify
{_environment(settings)}ExecStart={_exec_line(
    broker_argv(box, settings, broker))}
{loads}RuntimeDirectory={_value(runtime)}
RuntimeDirectoryMode=0700
Restart=on-failure
"""


def rotate_unit(box, settings):
    return f"""\
# moatery box {box.name}: its record moved aside once it is past its
# size, and the inspector told to reopen it. Started by its timer.

[Unit]
Description=moatery box {box.name}: rotate the record

[Service]
Type=oneshot
{_environment(settings)}ExecStart={_exec_line(
    _tool(settings, "rotate", box.name))}
"""


def rotate_timer(box):
    return f"""\
# moatery box {box.name}: the record's rotation, while the pod runs.

[Unit]
Description=moatery box {box.name}: rotate the record
PartOf={box.pod_service}

[Timer]
OnActiveSec=1min
OnUnitActiveSec=10min
"""


def prompt(box):
    """Read by every shell in the box. An interactive one the moat does
    not cover says so: one holding CAP_NET_ADMIN, which only `podman
    exec --privileged` gives, can change the rules, and one in another
    namespace than the rules were loaded into has none. Then bash's
    prompt, the box's name first: magenta, red as root, white on red
    when not covered. Fedora's /etc/bashrc and the home's .bashrc both
    read it, and the second changes nothing."""
    name = box.name
    warn = r"printf '\033[1;31m%s\033[0m\n  %s\n  %s\n  %s\n  %s\n'"
    return f"""\
# moatery box {name}: a warning in a shell the moat does not cover, and
# the box's name before bash's prompt.
_moathut_why=
case $- in
*i*)
    if [ -z "${{_moathut_checked:-}}" ]; then
        _moathut_checked=1
        # CAP_NET_ADMIN is bit 12 of the bounding set.
        while read -r _moathut_key _moathut_value; do
            [ "$_moathut_key" = CapBnd: ] || continue
            case $_moathut_value in *[!0-9a-fA-F]*|'') continue ;; esac
            if [ $(( 0x$_moathut_value >> 12 & 1 )) = 1 ]; then
                _moathut_why=privileged
            fi
        done < /proc/self/status
        if [ -s {MARK_PATH} ] &&
                [ "$(cat {MARK_PATH})" != "$(readlink /proc/self/ns/net)" ]
        then
            _moathut_why="$_moathut_why namespace"
        fi
        case $_moathut_why in *privileged*)
            {warn} \\
                'moathut: this shell is not protected by the moat.' \\
                'It was opened with podman exec --privileged, as Ptyxis' \\
                "opens a container's tabs. It can change the box's rules," \\
                'so what runs in it can reach the network uninspected.' \\
                'Open shells in the box with: moathut enter {name}' >&2 ;;
        esac
        case $_moathut_why in *namespace*)
            {warn} \\
                'moathut: box {name} is not protected by the moat.' \\
                'It was started outside moathut, so its network has none' \\
                "of the moat's rules: what runs in it reaches the network" \\
                'uninspected. On the host, run moathut stop {name}' \\
                'and then moathut enter {name}.' >&2 ;;
        esac
    fi ;;
esac
if [ -n "${{BASH_VERSION:-}}" ] && [ -n "${{PS1:-}}" ]; then
    case $PS1 in
    *'⬢ {name}'*) ;;
    *) if [ -n "$_moathut_why" ]; then
           _moathut='1;37;41'; _moathut_tag=' UNPROTECTED'
       elif [ "$EUID" = 0 ]; then _moathut='1;31'; _moathut_tag=
       else _moathut='35'; _moathut_tag=
       fi
       _moathut="\\[\\e[${{_moathut}}m\\]⬢ {name}${{_moathut_tag}}"
       PS1="$_moathut\\[\\e[0m\\] $PS1"
       unset _moathut _moathut_tag ;;
    esac
fi
unset _moathut_why _moathut_key _moathut_value
"""


def render(box, settings, broker):
    """Unit file path to text, for every unit the box has: the broker's
    only if it has a broker."""
    units = {box.pod_file: pod_unit(box, settings),
             box.container_file: container_unit(box, settings, broker),
             box.inspect_file: inspect_unit(box, settings, broker),
             box.resolve_file: resolve_unit(box, settings),
             box.rotate_file: rotate_unit(box, settings),
             box.rotate_timer_file: rotate_timer(box)}
    if broker:
        units[box.broker_file] = broker_unit(box, settings, broker)
    return units
