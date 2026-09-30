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


def _program(settings, name):
    return [settings.python, str(Path(settings.libexec) / name)]


def _tool(settings, *args):
    return [*settings.tool, "unit", *args]


def pod_unit(box, settings):
    return f"""\
# customs box {box.name}: the pod, holding the network namespace. Its
# start loads the rules; the listeners and the workload start after.

[Unit]
Description=customs box {box.name}: pod and rules
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
               f"{box.bundle}:{settings.trust_path}:ro,z"]
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
# customs box {box.name}: the workload. A new container from the image at
# every start; its home and its mounts are what persist.

[Unit]
Description=customs box {box.name}
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
# customs box {box.name}: the {what}, its listeners bound in the pod's
# namespace. Type=notify: started once they are bound. A reload reads
# the policy again and cuts no connection.

[Unit]
Description=customs box {box.name}: {what}
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
    argv = [*_program(settings, "customs-netns-listen"), "--pid", PID,
            "--", *_program(settings, "customs-inspect"),
            "--name", box.name, "--policy", str(box.policy),
            "--state-dir", str(box.state), "--status", str(box.status),
            "--record", str(box.record), "--netns-pid", PID]
    if broker:
        argv += ["--broker", f"unix:{box.broker_socket}"]
    return argv


def resolve_argv(box, settings):
    return [*_program(settings, "customs-netns-listen"), "--pid", PID,
            "--resolver", "--", *_program(settings, "customs-resolve"),
            "--name", box.name, "--address", "127.0.0.1",
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
    argv = [*_program(settings, "customs-broker"), "--name", box.name,
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
# customs box {box.name}: the broker, holding the credentials the box's
# policy names. Its socket is in the user's runtime directory, which the
# box has no path to. Type=notify: started once it is listening.

[Unit]
Description=customs box {box.name}: broker

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
# customs box {box.name}: its record moved aside once it is past its
# size, and the inspector told to reopen it. Started by its timer.

[Unit]
Description=customs box {box.name}: rotate the record

[Service]
Type=oneshot
{_environment(settings)}ExecStart={_exec_line(
    _tool(settings, "rotate", box.name))}
"""


def rotate_timer(box):
    return f"""\
# customs box {box.name}: the record's rotation, while the pod runs.

[Unit]
Description=customs box {box.name}: rotate the record
PartOf={box.pod_service}

[Timer]
OnActiveSec=1min
OnUnitActiveSec=10min
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
