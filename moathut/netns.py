"""The box's network namespace: the pod's infra process, the rules
loaded into it, and the check that they are there.

A rootless pod's namespace belongs to the user's user namespace, where
`podman unshare` is root; the workload holds no CAP_NET_ADMIN, so what
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

_DEVICE = re.compile(r"[A-Za-z0-9_.:@-]{1,15}")


class NetnsError(Exception):
    """The namespace, or what is in it, is not as a box needs it."""


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
    return ["podman", "unshare", "nsenter", "-t", str(pid), "-n", *argv]


def egress_device(pid, runner=run):
    """The device the namespace's default route leaves by, read inside
    it: pasta names it, and the host's may differ."""
    out = runner(in_netns(pid, ["ip", "-j", "route", "show",
                                "default"])).stdout
    devices = {route.get("dev") for route in json.loads(out or "[]")}
    if len(devices) != 1:
        raise NetnsError(f"no single default route in pid {pid}'s "
                         f"namespace: {sorted(map(str, devices))}")
    (device,) = devices
    if not isinstance(device, str) or not _DEVICE.fullmatch(device):
        raise NetnsError(f"unexpected egress device {device!r}")
    return device


def ruleset(device):
    return RULES.substitute(DEV=device)


def load_rules(pid, runner=run):
    runner(in_netns(pid, ["nft", "-f", "-"]),
           input=ruleset(egress_device(pid, runner)))


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
