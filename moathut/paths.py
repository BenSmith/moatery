"""Where a box's files are, from its name and the user's directories."""

import os
import re
from pathlib import Path
from typing import NamedTuple

# A pod name, a container name, a hostname and part of a unit name at
# once: no dots, no leading or trailing dash.
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?")


class Dirs(NamedTuple):
    home: Path
    config: Path
    state: Path
    data: Path
    runtime: Path | None


def user_dirs(environ=os.environ):
    """The XDG directories the user's manager resolves %E, %S and the rest
    against, from the same variables."""
    home = Path(environ.get("HOME") or Path.home())

    def xdg(key, default):
        value = environ.get(key, "")
        return Path(value) if os.path.isabs(value) else home / default

    runtime = environ.get("XDG_RUNTIME_DIR", "")
    return Dirs(home=home,
                config=xdg("XDG_CONFIG_HOME", ".config"),
                state=xdg("XDG_STATE_HOME", ".local/state"),
                data=xdg("XDG_DATA_HOME", ".local/share"),
                runtime=Path(runtime) if os.path.isabs(runtime) else None)


def valid_name(name):
    return bool(NAME.fullmatch(name))


def boxes_root(dirs):
    return dirs.config / "moatery" / "box"


def credentials_root(dirs):
    """Beside the boxes, not among them, where a box's name could be
    its."""
    return dirs.config / "moatery" / "credentials"


def sealed(dirs, credential):
    return credentials_root(dirs) / f"{credential}.cred"


def described(dirs, credential):
    return credentials_root(dirs) / f"{credential}.json"


def protected(dirs):
    """What no box may mount, or mount a parent of, or mount from inside:
    every box's key, policy, record and home, the units that load its
    rules, podman's storage, and the runtime directory the broker's
    socket is in."""
    paths = [dirs.config / "moatery", dirs.state / "moatery",
             dirs.state / "log" / "moatery", dirs.data / "moatery",
             dirs.config / "containers", dirs.config / "systemd",
             dirs.data / "containers"]
    if dirs.runtime is not None:
        paths.append(dirs.runtime)
    return paths


class Box(NamedTuple):
    name: str
    dirs: Dirs

    @property
    def unit(self):
        return f"moathut-{self.name}"

    @property
    def config(self):
        return boxes_root(self.dirs) / self.name

    @property
    def settings(self):
        return self.config / "box.json"

    @property
    def policy(self):
        return self.config / "policy.json"

    @property
    def bundle(self):
        return self.config / "bundle.pem"

    @property
    def prompt(self):
        return self.config / "prompt.sh"

    @property
    def state(self):
        return self.dirs.state / "moatery" / "box" / self.name

    @property
    def status(self):
        return self.state / "status.json"

    @property
    def resolve_status(self):
        return self.state / "resolve-status.json"

    @property
    def logs(self):
        return self.dirs.state / "log" / "moatery" / "box" / self.name

    @property
    def record(self):
        return self.logs / "requests.log"

    @property
    def share(self):
        return self.dirs.data / "moatery" / "box" / self.name

    @property
    def home(self):
        return self.share / "home"

    @property
    def runtime(self):
        """The broker's, in the user's runtime directory."""
        return self.dirs.runtime / "moathut" / self.name

    @property
    def broker_socket(self):
        return self.runtime / "broker.sock"

    @property
    def pod_file(self):
        return self.dirs.config / "containers" / "systemd" / f"{self.unit}.pod"

    @property
    def container_file(self):
        return (self.dirs.config / "containers" / "systemd"
                / f"{self.unit}.container")

    @property
    def inspect_file(self):
        return self.dirs.config / "systemd" / "user" / self.inspect_service

    @property
    def resolve_file(self):
        return self.dirs.config / "systemd" / "user" / self.resolve_service

    @property
    def broker_file(self):
        return self.dirs.config / "systemd" / "user" / self.broker_service

    @property
    def rotate_file(self):
        return self.dirs.config / "systemd" / "user" / self.rotate_service

    @property
    def rotate_timer_file(self):
        return self.dirs.config / "systemd" / "user" / self.rotate_timer

    @property
    def unit_files(self):
        return (self.pod_file, self.container_file, self.inspect_file,
                self.resolve_file, self.broker_file, self.rotate_file,
                self.rotate_timer_file)

    # quadlet names the services it generates: NAME.pod gives
    # NAME-pod.service, NAME.container gives NAME.service.
    @property
    def pod_service(self):
        return f"{self.unit}-pod.service"

    @property
    def service(self):
        return f"{self.unit}.service"

    @property
    def inspect_service(self):
        return f"{self.unit}-inspect.service"

    @property
    def resolve_service(self):
        return f"{self.unit}-resolve.service"

    @property
    def broker_service(self):
        return f"{self.unit}-broker.service"

    @property
    def rotate_service(self):
        return f"{self.unit}-rotate.service"

    @property
    def rotate_timer(self):
        return f"{self.unit}-rotate.timer"

    @property
    def services(self):
        return (self.pod_service, self.service, self.inspect_service,
                self.resolve_service, self.broker_service,
                self.rotate_service, self.rotate_timer)
