"""A box's four units as text: the pod and the workload for quadlet, the
inspector and the responder for the user's manager.

What starts what: `enter` starts the workload's unit, which Requires=
and is After= the two listener units; they are BindsTo= and After= the
pod's, which is active only once its ExecStartPost= has loaded the
rules. The pod Wants= the listeners, so a restart of the pod brings
them back into its new namespace.
"""

import json
import re
from pathlib import Path
from typing import NamedTuple

from .mounts import Mount
from .netns import PID

# podman's default set, written out so a containers.conf cannot widen
# it. None is CAP_NET_ADMIN.
CAPABILITIES = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
                "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP",
                "SETUID", "SYS_CHROOT")

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
Wants={box.inspect_service} {box.resolve_service}

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


def container_unit(box, settings):
    volumes = [f"{box.home}:{settings.home_path}:z",
               f"{box.bundle}:{settings.trust_path}:ro,z"]
    for mount in settings.mounts:
        volumes.append(f"{mount.source}:{mount.target}:"
                       + ("ro,z" if mount.readonly else "z"))
    lines = [f"Volume={_value(v)}" for v in volumes]
    lines += [f"Environment={_quoted(f'{v}={settings.trust_path}')}"
              for v in CA_VARIABLES]
    body = "\n".join(lines)
    # WorkingDir is also the home: podman writes the passwd entry of a user
    # the pod's keep-id brings in with the working directory as its home.
    return f"""\
# customs box {box.name}: the workload. A new container from the image at
# every start; its home and its mounts are what persist.

[Unit]
Description=customs box {box.name}
Requires={box.inspect_service} {box.resolve_service}
After={box.inspect_service} {box.resolve_service}

[Container]
ContainerName={box.name}
Pod={box.unit}.pod
Image={_value(settings.image)}
WorkingDir={_value(settings.home_path)}
Exec=sleep infinity
RunInit=true
DropCapability=ALL
AddCapability={" ".join(CAPABILITIES)}
{body}

[Service]
{_environment(settings)}ExecStartPost=-{_exec_line(
    _tool(settings, "sudoers", box.name))}
SuccessExitStatus=143
"""


def _listener_unit(box, settings, what, argv):
    return f"""\
# customs box {box.name}: the {what}, its listeners bound in the pod's
# namespace. Type=notify: started once they are bound.

[Unit]
Description=customs box {box.name}: {what}
BindsTo={box.pod_service}
After={box.pod_service}

[Service]
Type=notify
{_environment(settings)}ExecStart={_exec_line(
    _tool(settings, "exec", box.name, "--", *argv))}
"""


def inspect_argv(box, settings):
    return [*_program(settings, "customs-netns-listen"), "--pid", PID,
            "--", *_program(settings, "customs-inspect"),
            "--name", box.name, "--policy", str(box.policy),
            "--state-dir", str(box.state), "--status", str(box.status),
            "--record", str(box.record), "--netns-pid", PID]


def resolve_argv(box, settings):
    return [*_program(settings, "customs-netns-listen"), "--pid", PID,
            "--resolver", "--", *_program(settings, "customs-resolve"),
            "--name", box.name, "--address", "127.0.0.1",
            "--policy", str(box.policy),
            "--status", str(box.resolve_status)]


def inspect_unit(box, settings):
    return _listener_unit(box, settings, "inspector",
                          inspect_argv(box, settings))


def resolve_unit(box, settings):
    return _listener_unit(box, settings, "responder",
                          resolve_argv(box, settings))


def render(box, settings):
    """Unit file path to text, for every unit the box has."""
    return {box.pod_file: pod_unit(box, settings),
            box.container_file: container_unit(box, settings),
            box.inspect_file: inspect_unit(box, settings),
            box.resolve_file: resolve_unit(box, settings)}
