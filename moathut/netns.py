"""The hut's network namespace: made and held in the user namespace
`podman unshare` is root in, connected by pasta, the rules loaded into
it, the pod's infra process in it, and the check that they are there.

The pod's own user namespace (keep-id) is a child of that one, and does
not own the network namespace: root in the hut, even with every
capability `podman exec --privileged` gives, cannot change it, so what
is loaded stays loaded. The rules are the netns placement's (DESIGN.md).
"""

import json
import os
import re
from string import Template

from .process import run

RULES = Template("""\
table inet moatery {
  chain out {
    type nat hook output priority -100
    tcp dport 443 dnat ip to 127.0.0.1:8443
    tcp dport 80  dnat ip to 127.0.0.1:8080
    udp dport 53  dnat ip to 127.0.0.1:8053
    tcp dport 53  dnat ip to 127.0.0.1:8053
  }
}
table netdev moatery {
  chain egress {
    type filter hook egress device "$DEV" priority 0; policy drop
    udp dport 443 counter comment "quic"
    counter comment "dropped"
  }
}
""")

TABLES = (("inet", "moatery"), ("netdev", "moatery"))

# Where a unit's command line takes the pod's infra pid.
PID = "{pid}"

# The address the hut's resolv.conf names, which pasta forwards; the
# rules send port 53 to the responder whatever the address.
DNS = "169.254.1.1"

# What podman runs pasta with for a rootless pod (its libnetwork's
# pasta_linux.go), so the namespace is connected as Network=pasta
# connects one; `--netns PATH` follows.
PASTA = ("pasta", "--config-net", "--dns-forward", DNS, "-t", "none",
         "-u", "none", "-T", "none", "-U", "none", "--no-map-gw", "--quiet",
         "--map-guest-addr", "169.254.1.2")

_DEVICE = re.compile(r"[A-Za-z0-9_.:@-]{1,15}")
_NETNS = re.compile(r"net:\[[0-9]+\]")


class NetnsError(Exception):
    """The namespace, or what is in it, is not as a hut needs it."""


def pod_pid(pod, runner=run):
    """The pid of the pod's infra process, whose namespace the pod's
    containers share."""
    infra = runner(["podman", "pod", "inspect", pod, "--format",
                    "{{.InfraContainerID}}"]).stdout.strip()
    if not infra:
        raise NetnsError(f"pod {pod} has no infra container")
    pid = runner(["podman", "inspect", "--format", "{{.State.Pid}}",
                  infra]).stdout.strip()
    if not pid.isdigit() or int(pid) <= 0:
        raise NetnsError(f"pod {pod}'s infra container is not running")
    return int(pid)


def in_netns(pid, argv):
    """From the host, in the namespace of a process in it."""
    return ["podman", "unshare", "nsenter", "-t", str(pid), "-n", *argv]


def at(path, argv):
    """In the namespace held at `path`, from the user namespace it is
    held in: the netns unit's, under `podman unshare`."""
    return ["nsenter", f"--net={path}", *argv]


def make(path, runner=run):
    """A new namespace, held at `path`: a bind mount over an empty
    file."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.touch()
    runner(["unshare", f"--net={path}", "true"])


def connect(path, runner=run):
    """pasta: it forks once the namespace is connected, and serves it
    until `path` is removed."""
    runner([*PASTA, "--netns", str(path)])


def release(path, runner=run):
    """The namespace's hold, lazily, since pasta has it open, and the
    file, whose removal pasta exits on. Neither need be there."""
    runner(["umount", "-l", str(path)], check=False)
    path.unlink(missing_ok=True)


def egress_device(path, runner=run):
    """The device the namespace's default route leaves by, read inside
    it: pasta names it, and the host's may differ."""
    out = runner(at(path, ["ip", "-j", "route", "show", "default"])).stdout
    devices = {route.get("dev") for route in json.loads(out or "[]")}
    if len(devices) != 1:
        raise NetnsError(f"no single default route in the namespace at "
                         f"{path}: {sorted(map(str, devices))}")
    (device,) = devices
    if not isinstance(device, str) or not _DEVICE.fullmatch(device):
        raise NetnsError(f"unexpected egress device {device!r}")
    return device


def ruleset(device):
    return RULES.substitute(DEV=device)


def load_rules(path, runner=run):
    runner(at(path, ["nft", "-f", "-"]),
           input=ruleset(egress_device(path, runner)))


def netns_id(path, runner=run):
    """The namespace's name as /proc gives it, `net:[INODE]`: what a
    process in it reads at /proc/self/ns/net."""
    name = runner(at(path, ["readlink", "/proc/self/ns/net"])).stdout.strip()
    if not _NETNS.fullmatch(name):
        raise NetnsError(f"unexpected namespace name {name!r}")
    return name


def rules_loaded(pid, runner=run):
    return all(runner(in_netns(pid, ["nft", "list", "table", *table]),
                      check=False).returncode == 0 for table in TABLES)


def exec_with_pid(pod, argv, runner=run, execv=os.execv):
    """Become `argv` with every PID word replaced by the pod's infra pid.
    An exec, not a child, so a Type=notify unit's main process is the
    launcher that sends READY=1."""
    if not argv:
        raise NetnsError("nothing to run")
    pid = str(pod_pid(pod, runner))
    argv = [pid if word == PID else word for word in argv]
    execv(argv[0], argv)
