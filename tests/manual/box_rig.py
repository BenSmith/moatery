#!/usr/bin/env python3
"""box_rig.py — a moathut box, made and run through its command line.

docs/BOX.md: `moathut credential add`, `create`, `enter`, `log`,
`allow`, `policy`, `stop` and `rm`, the box's units run by the user's
manager and quadlet, the namespace its netns unit holds, the netns
placement's rules and listeners in it, and the box's broker. Run on the
proving host as an ordinary user, from a checkout:

    python3 tests/manual/box_rig.py [--keep] [--without-rules]
                                    [--without-held-netns]
                                    [--podman-seccomp]
                                    [--broker-not-ready]
                                    [--listeners-required]
                                    [--without-reload] [--without-reopen]
                                    [--without-autostart]
                                    [--restarts N]

The tool is the checkout's bin/moathut running the checkout's
programs, or, with MOATERY_LIBEXEC=/usr/libexec/moatery, the installed
moathut. riglib's two host facts need sudo and are undone at teardown.

Beside the units `create` writes, the rig writes seven drop-ins, and
removes them before `rm`:

  inspector SSL_CERT_FILE names the stub's certificate, which no system
            store holds; with --without-reload, an empty ExecReload=.
  broker    the same, and a PYTHONPATH whose sitecustomize sleeps 3 s, so
            the broker's start has a window a request can fall in; with
            --broker-not-ready, Type=simple.
  workload  Exec= is a script in the box's home in place of `sleep
            infinity`; with --podman-seccomp, SeccompProfile= names
            podman's default. At every start its first act is a request to the
            provider, whose nonce and status it appends to a file in the
            home; then it sleeps. That request is the window: nothing the
            workload sends may come before the rules, the listeners and
            the broker.
  netns     for the fail rows, PATH puts an nft that fails ahead of the
            system's for the holder; with --without-rules, one that loads
            nothing.
  pod       for outside's last row, an empty ExecStopPost=, so a stop
            leaves the pod, as a crash of the manager can.
  quadlet pod  with --without-held-netns, Network=pasta, and an
            ExecStartPost= that loads the rules into the pod's own
            namespace and writes its name where the box reads it.
  rotate    with --without-reopen, for the record's row only, its
            ExecStart= moves the record aside and signals nothing.

The stub is on the host's 127.0.0.1, which the pod cannot reach, so
anything the stub answers came by the inspector's dial. The provider is
brokered: the box holds a placeholder, and the stub answers 200 only to
the key the rig sealed, which only the broker holds, and 401 to anything
else. Every request's path carries a nonce, found in the stub's log and
in the record.

THE ROWS

  credential  add seals the key: neither file holds it, and ls lists it.
  create    --dry-run first wrote nothing and printed each file create
            then wrote, as it wrote it; the files docs/BOX.md lists are
            there, with a .bashrc in the home, and nothing started; the
            box is made with --autostart, and ls says so.
  chain     the manager loaded the order: the workload Wants= both
            listeners, Requires= neither, and is After= them, and is
            BindsTo= the pod; each
            listener is BindsTo= and After= the pod; the inspector pulls
            in the broker and is After= it, which is Type=notify and not
            bound to the pod. The pod is BindsTo= and After= the
            namespace's unit, which is Type=notify and bound to nothing,
            and pulls in the record's rotation timer, which is PartOf= it.
  fail      with the namespace's rules load failing, enter refuses and
            the workload never ran: its first act left no line; stop
            leaves no unit active.
  first     at the box's first start, the workload's first request was
            inspected and brokered: the stub answered 200 and logged its
            path, and the record says forward under the credential.
  premise   root in the box, by sudo, holds no CAP_NET_ADMIN and is refused
            `ip link add`; the user holds no capability at all; the rules
            are in the pod's namespace, which is the one the netns unit
            holds; the pod has no cgroup of its own.
  enter     as the user, with the box's home as working directory, HOME
            and passwd home; from inside a mount, in the same directory
            inside; with --root, as uid 0. An interactive bash's prompt
            starts with the box's name, magenta, and red as root; the
            box's clock reads in the host's zone.
  warn      no shell enter opens warns, as the user or as root, and the
            namespace's name the box reads is its own; nor does one
            podman exec --privileged opens.
  held      a shell podman exec --privileged opens, root with every
            capability in the box's user namespace, as Ptyxis opens a
            container's tab, is refused `ip link add` and `ip link set lo
            down`; the host's nft with those credentials is refused
            `nft flush ruleset`, and the rules stay; the pasta serving
            the box has the arguments podman gives a stock pod's.
  seccomp   a probe whose calls each take an argument the kernel
            rejects: in a stock container every one reaches the kernel,
            a vsock with an upper bit in its family among them; in the
            box, the profile refuses the user, and root in a privileged
            exec, a namespace, a mount, ptrace, the keyring and a vsock
            however written, and lets a thread, an unshare of nothing
            new and an inet and a netlink socket through.
  home      the box's home is its own: a file in the user's home is absent
            inside, and one written inside is in the box's home on the
            host and not in the user's. The directories between the home
            and a mount inside it are the user's to write in.
  mount     a :ro mount is at the DST it was given, and read-only.
  hosts     the host's hosts file, which has the rig's line for the
            provider, is not the box's.
  dns       riglib's rows, asked by the user in the box.
  silent    a filtered UDP send returns rc=0 while the drop counter moves.
  quic      a UDP send to 443 moves the quic counter, and is dropped.
  ssh       a TCP connect to port 22 times out, and is dropped.
  listed    the provider's 200 reaches the user, the stub logged the path,
            and the record says forward under the credential.
  unlisted  the inspector's 403, and one more record for the host, saying
            why, with no upstream.
  root      root, by sudo, which drops the CA variables, is inspected the
            same: the listed host verifies through the bundle mounted over
            the system store, and the unlisted one gets the 403.
  broker    the box holds the placeholder, by exec and by enter, and never
            the key; the broker's socket is on the host and not in the box,
            and it holds no TCP socket. Stopped, a request is refused 502,
            never reaches the provider, and the record says why; enter
            starts it again, and a request is served. Premise: systemd
            will not start the broker again after a stop while it starts;
            enter does, and a request is served.
  rotate    with the stub now wanting a new key (the old one gets 401),
            credential add with the new key: the next request is served,
            and the broker restarted while the inspector and the workload
            did not.
  counters  every caller was named and none dropped as foreign.
  loop      log --refused counts the unlisted host's 403s and names it
            among the responder's unlisted names; allow lists it, and
            reloads the listeners, restarting nothing, and the
            inspector's status file names the new document; the host is
            then dialled (a 502, since the host has no address for it)
            and not refused, and log --refused no longer lists it. A
            download through the inspector, begun before an allow and
            still running when it returns, finishes whole. policy with
            an $EDITOR writing a document the loader refuses exits 1
            with its reason, changes nothing and restarts nothing; at a
            terminal it asks, opens the editor again, and applies the
            second document; without the credential, the broker stops,
            its unit goes, and the provider is reached unbrokered (the
            stub's 401); with it again, the broker is back and the
            provider served. The inspector killed is started again, and
            nothing else is. Stopped, the workload runs on in the same
            container and its request is not served; enter starts it
            again. log follows a request just made, and Ctrl-C ends it
            with status 0. The provider is served after each.
  record    the timer started with the pod, and it has run the rotation,
            which exited 0. The record padded past its size, the
            rotation the manager runs moves it aside, and the next
            request's line is in a new record and not in the moved one.
  persist   after a workload restart, a file written outside the home is
            gone and one in it is there.
  restart   N workload restarts, then N pod restarts, each pod restart
            in the held namespace, with the rules in it: at every start
            the first request was inspected.
  stop      every unit inactive, the timer too, no pod, no container, the
            namespace let go, and ls says so; then enter starts it, and
            its first request was inspected.
  autostart the manager loaded the workload as wanted by default.target;
            stopped, the manager's start of default.target, as at login,
            starts it with the rules, and its first request was
            inspected.
  outside   after `podman pod restart`, outside systemd, the pod is in the
            held namespace, with the rules, enter serves it, and neither
            a shell nor ls warns. With a table deleted from the host,
            where the user is root over the namespace, ls marks it
            unprotected and says so, and enter refuses it; stop, then
            enter, serves it again. A container run by hand from the
            box's image, prompt and mark warns that the box is not
            protected. A pod the box left, started by podman while the
            namespace's unit is stopped, does not start.
  like      create --like the box, as the loop left its policy, with
            --seccomp debug: the new box has its policy, image and
            mounts, and neither its autostart nor its home; entered, it
            reads the :ro mount at its DST, and under debug ptrace
            reaches the kernel and a namespace is refused still; rm
            --home leaves nothing of it.
  rm        credential rm is refused while the box names it; no unit, pod
            or container is left, nor the broker's socket; the home and the
            record stay, and create, with a policy naming no credential,
            finds the home again and writes no broker; made without
            --autostart, default.target does not start it; rm --home removes
            it; then credential rm removes the credential.

`--without-rules` puts an nft that loads nothing ahead of the system's
for the holder, so the box starts with no rules in its namespace: first,
the premise that the rules are there, enter (which refuses) and every
row through it on the rig's box (warn's first and the broker's
placeholder among them), held's nft row (no rules to keep), dns,
silent, quic, ssh, listed, unlisted, root, the broker's requests,
rotate, the loop's rows that make a request or read one back, the
record's rotation, the killed inspector's, and enter's, restart,
stop's enter and its first request, autostart's, and outside's rows
that enter serves the box, with its ls, must go red. (The killed
inspector's row is red because an enter refused left the broker
stopped, and the inspector's restart starts it: Wants=.) The like and
rm rows enter other boxes, which the drop-in is not on.

`--without-held-netns` lets the pod make its own namespace, as
Network=pasta does, which its keep-id user namespace owns, and loads
the rules into it at its start: held's rows that root with every
capability in the box is refused, premise's that the pod's namespace is
the held one, restart's that each pod restart keeps it, and outside's
that `podman pod restart` keeps it and that a left pod does not start,
must go red.

`--podman-seccomp` runs the workload under podman's default seccomp
profile: seccomp's rows that the box's user, and root in a privileged
exec, are refused by the profile must go red. Its stock container's row
and the row of what a box does stay green, and so does the like box's,
which the drop-in is not on.

`--listeners-required` adds `Requires=` on both listeners to the
workload's drop-in, as its unit had before the policy loop: the loop's
rows that the manager's start of the inspector after it is killed
restarts only the inspector, that the workload runs on while the
inspector is stopped, and that it runs on through the policy edits that
restart the inspector, must go red. A required unit's automatic restart
restarts the workload as well.

`--without-reload` empties the inspector's ExecReload=, so a reload
of it fails and allow restarts it once the status file has not named
the new document in time: the loop's rows that allow says the listeners
reloaded and restarts nothing, that the download runs on through an
allow and finishes whole, and that the policy edited at a terminal
reloads the listeners, must go red. The restarted inspector reads the
new document at its start, so the row that its status file names it
after allow stays green.

`--without-reopen` makes the rotation a rename and no more, as a
logrotate configuration without its `postrotate` would: the record's
row that the next request's line is in the new record must go red,
since the inspector writes on into the file it has open.

`--without-autostart` makes the box without --autostart: the create
row's ls, and the autostart rows, must go red, and outside's first,
which restarts the pod the autostart row started.

`--broker-not-ready` makes the broker's unit Type=simple, so nothing
waits for its socket: the first request after each start of the broker,
at the first start, each enter that starts it again, rotate, the loop's
once policy names the credential again, and each enter after a stop,
must go red; and the premise of a stop while it
starts, since a Type=simple unit is started when forked.
"""

import argparse
import hashlib
import json
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import riglib  # noqa
from riglib import (  # noqa
    CHECKOUT, HOME, LIBEXEC, PROGRAM_ENV, PROVIDER, RIG, UNLISTED, row, run,
    say,
)
from moatery.egress_ca import ca_cert_path  # noqa
from moatery.inspect_document import (  # noqa
    INSPECT_DIGEST_KEY, inspect_policy_digest,
)
from moatery.egress_record import (  # noqa
    DROP_BROKER_UNREACHABLE, DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED,
    DROP_UNREACHABLE,
)
from moathut.record import ROTATE_BYTES, rotated  # noqa

BOX = "moatery-rig-box"
UNIT = f"moathut-{BOX}"
NETNS_SERVICE = f"{UNIT}-netns.service"
POD_SERVICE = f"{UNIT}-pod.service"
SERVICE = f"{UNIT}.service"
INSPECT_SERVICE = f"{UNIT}-inspect.service"
RESOLVE_SERVICE = f"{UNIT}-resolve.service"
BROKER_SERVICE = f"{UNIT}-broker.service"
ROTATE_SERVICE = f"{UNIT}-rotate.service"
ROTATE_TIMER = f"{UNIT}-rotate.timer"
SERVICES = (NETNS_SERVICE, POD_SERVICE, INSPECT_SERVICE, RESOLVE_SERVICE,
            BROKER_SERVICE, SERVICE, ROTATE_SERVICE, ROTATE_TIMER)
LISTENERS = {INSPECT_SERVICE, RESOLVE_SERVICE}
# docs/BOX.md's default.
IMAGE = "registry.fedoraproject.org/fedora-toolbox:44"

# docs/BOX.md's table of a box's files.
CONFIG = HOME / ".config" / "moatery" / "box" / BOX
STATE = HOME / ".local" / "state" / "moatery" / "box" / BOX
LOGS = HOME / ".local" / "state" / "log" / "moatery" / "box" / BOX
SHARE = HOME / ".local" / "share" / "moatery" / "box" / BOX
BOX_HOME = SHARE / "home"
# A box made --like the rig's.
TWIN = "moatery-rig-twin"
TWIN_CONFIG = CONFIG.parent / TWIN
TWIN_SHARE = SHARE.parent / TWIN
TWIN_LOGS = LOGS.parent / TWIN
QUADLET = HOME / ".config" / "containers" / "systemd"
UNITS = HOME / ".config" / "systemd" / "user"
UNIT_FILES = (UNITS / NETNS_SERVICE, QUADLET / f"{UNIT}.pod",
              QUADLET / f"{UNIT}.container", UNITS / INSPECT_SERVICE,
              UNITS / RESOLVE_SERVICE, UNITS / BROKER_SERVICE,
              UNITS / ROTATE_SERVICE, UNITS / ROTATE_TIMER)
WRITTEN_WITH = (CONFIG / "prompt.sh", CONFIG / "containers.conf",
                CONFIG / "seccomp.json")
LAID_OUT = (CONFIG / "policy.json", CONFIG / "bundle.pem", *WRITTEN_WITH,
            ca_cert_path(STATE), LOGS, BOX_HOME, BOX_HOME / ".bashrc",
            *UNIT_FILES)
MARK = STATE / "netns"
STATUS = STATE / "status.json"
RESOLVE_STATUS = STATE / "resolve-status.json"
RECORD = LOGS / "requests.log"
CREDENTIAL = "moatery-rig-key"
CREDENTIAL_ENV = "MOATERY_RIG_KEY"
CREDENTIALS = HOME / ".config" / "moatery" / "credentials"
SEALED = CREDENTIALS / f"{CREDENTIAL}.cred"
DESCRIBED = CREDENTIALS / f"{CREDENTIAL}.json"
RUNTIME = Path(os.environ.get("XDG_RUNTIME_DIR")
               or f"/run/user/{os.getuid()}")
BROKER_SOCKET = RUNTIME / "moathut" / BOX / "broker.sock"
# Where the netns unit holds the box's namespace: a file on the host,
# bound in podman's mount namespace.
NAMESPACE = RUNTIME / "moathut-netns" / BOX

DROP_INS = {"inspect": UNITS / f"{INSPECT_SERVICE}.d" / "rig.conf",
            "broker": UNITS / f"{BROKER_SERVICE}.d" / "rig.conf",
            "workload": QUADLET / f"{UNIT}.container.d" / "rig.conf",
            "netns": UNITS / f"{NETNS_SERVICE}.d" / "rig.conf",
            "pod": UNITS / f"{POD_SERVICE}.d" / "rig.conf",
            "quadlet pod": QUADLET / f"{UNIT}.pod.d" / "rig.conf",
            "rotate": UNITS / f"{ROTATE_SERVICE}.d" / "rig.conf"}
# An nft ahead of the system's on the holder's PATH: one that fails, and
# one that loads nothing and says it did.
NFT_FAILS = RIG / "box-nft-fails"
NFT_LOADS_NOTHING = RIG / "box-nft-noop"
HOLDER_PATH = "/usr/local/bin:/usr/bin:/usr/sbin"
FAILING_RULES = f"[Service]\nEnvironment=PATH={NFT_FAILS}:{HOLDER_PATH}\n"
NO_RULES = f"[Service]\nEnvironment=PATH={NFT_LOADS_NOTHING}:{HOLDER_PATH}\n"
# With --without-held-netns, the pod makes its own namespace, which its
# user namespace owns, and this loads the rules into it and names it
# where the box reads it, as a pod's own start once did.
OLD_RULES = RIG / "box-old-rules"
# The pod's unit removes the pod when it stops; emptied, a stop leaves
# the pod, as a crash of the manager can.
POD_LEFT = "[Service]\nExecStopPost=\n"

# Inside, the box's home is at the user's home's path.
INSIDE = str(HOME)
START = ".moatery-rig-start"
STARTS = ".moatery-rig-starts"
KEPT = ".moatery-rig-kept"
WRITTEN = ".moatery-rig-written"
MARKER = HOME / ".moatery-rig-marker"

POLICY = RIG / "box-policy.json"
PLAIN_POLICY = RIG / "box-plain-policy.json"
# $EDITOR for `moathut policy`: writes a document the loader refuses.
BAD_EDITOR = RIG / "box-bad-editor"
# And two that write the rig's plain and brokered documents.
PLAIN_EDITOR = RIG / "box-plain-editor"
BROKERED_EDITOR = RIG / "box-brokered-editor"
# And one that writes a refused document the first time and TTY_POLICY
# the second, counting its runs in TTY_RUNS.
TTY_EDITOR = RIG / "box-tty-editor"
TTY_POLICY = RIG / "box-tty-policy.json"
TTY_RUNS = RIG / "box-tty-runs"
# A host allowed while a download runs, and one the terminal's edit adds.
RELOAD_HOST = "moatery-rig-reload.example"
TTY_HOST = "moatery-rig-tty.example"
# The stub's /slow/N: N chunks of 64 KiB, 0.1 s apart (stub_provider.py).
SLOW_CHUNKS = 80
SLOW_BYTES = b"".join(bytes([i % 256]) * 65536 for i in range(SLOW_CHUNKS))
FOLLOWED = RIG / "box-log-followed"
SLOW = RIG / "box-slow"
PROJECT = RIG / "box-project"
SUBDIR = PROJECT / "sub"
READONLY = RIG / "box-ro"
READONLY_AT = "/srv/moatery-rig-ro"
STUB_LOG = RIG / "stub.log"
HOSTS_MARK = "moathut-rig"

if riglib.INSTALLED:
    TOOL = ["moathut"]
    TOOL_ENV = dict(os.environ)
else:
    TOOL = [sys.executable, str(CHECKOUT / "bin" / "moathut")]
    TOOL_ENV = {**os.environ, **PROGRAM_ENV,
                "MOATERY_LIBEXEC": str(LIBEXEC)}

USER = f"{os.getuid()}:{os.getgid()}"

START_SCRIPT = f"""\
# written by tests/manual/box_rig.py: the workload's first act at every
# start, then what `create` runs.
n=$(cat /proc/sys/kernel/random/uuid)
c=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 \\
    -H "Authorization: Bearer ${CREDENTIAL_ENV}" \\
    "https://{PROVIDER}/start/$n")
echo "$n $c" >> "{INSIDE}/{STARTS}"
exec sleep infinity
"""

CURL = ["curl", "-s", "-S", "--max-time", "15", "-o", "/dev/null",
        "-w", "%{http_code}"]

CONNECT = """
import socket, sys
host, port = sys.argv[1].rsplit(":", 1)
s = socket.socket()
s.settimeout(5)
try:
    s.connect((host, int(port)))
except OSError as exc:
    print(type(exc).__name__)
else:
    print("connected")
"""

UDP_SEND = """
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x", (sys.argv[1], int(sys.argv[2])))
except OSError as exc:
    print(type(exc).__name__)
else:
    print("sent")
"""

# Not port 53, which the redirect takes.
FILTERED_UDP = ("192.0.2.1", "9")
# HTTP/3's port: dropped like port 9, and counted as `quic` first.
QUIC_UDP = ("192.0.2.1", "443")
SSH = "192.0.2.1:22"

RULES = {"table inet moatery", "table netdev moatery"}

OLD_RULES_SCRIPT = f"""\
# written by tests/manual/box_rig.py: under podman unshare, the rules
# into the pod's own namespace, and its name where the box reads it.
from pathlib import Path
from moathut.netns import load_rules, netns_id, pod_pid
held = Path(f"/proc/{{pod_pid('{BOX}')}}/ns/net")
load_rules(held)
with open("{MARK}", "w") as mark:
    mark.write(netns_id(held) + "\\n")
"""

# Each call with an argument the kernel itself rejects, so the errno says
# which refused it: the filter's EPERM or ENOSYS, or the kernel's own.
SECCOMP_PROBE = ".moatery-rig-seccomp"
SECCOMP_SCRIPT = """\
import ctypes, errno, json
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
NOWHERE = ctypes.create_string_buffer(b"/nonexistent")
NO_PID = 4194305
def call(nr, *args):
    if libc.syscall(nr, *map(ctypes.c_long, args)) >= 0:
        return "0"
    return errno.errorcode.get(ctypes.get_errno(), "?")
print(json.dumps({
    "clone NEWUSER": call(56, 0x10000 | 0x10000000, 0, 0, 0, 0),
    "clone NEWNET": call(56, 0x10000 | 0x40000000, 0, 0, 0, 0),
    "unshare NEWUSER": call(272, 1 | 0x10000000),
    "clone3": call(435, 0, 0),
    "setns": call(308, -1, 0),
    "mount": call(165, 0, ctypes.addressof(NOWHERE), 0, 0, 0),
    "ptrace": call(101, 2, NO_PID, 0, 0),
    "process_vm_readv": call(310, NO_PID, 0, 0, 0, 0, 0),
    "pidfd_getfd": call(438, -1, 0, 0),
    "keyctl": call(250, 9999, 0, 0, 0, 0),
    "vsock": call(41, 40, 1, 0),
    "vsock, upper bit": call(41, (1 << 32) | 40, 1, 0),
    "clone THREAD": call(56, 0x10000, 0, 0, 0, 0),
    "unshare nothing new": call(272, 1),
    "socket inet": call(41, 2, 99, 0),
    "socket netlink route": call(41, 16, 3, 0),
    "socket netlink audit": call(41, 16, 3, 9),
}))
"""
# What the probe's calls get from the box's profile, strict.
SECCOMP_REFUSED = {
    "clone NEWUSER": "EPERM", "clone NEWNET": "EPERM",
    "unshare NEWUSER": "EPERM", "clone3": "ENOSYS", "setns": "EPERM",
    "mount": "EPERM", "ptrace": "EPERM", "process_vm_readv": "EPERM",
    "pidfd_getfd": "EPERM", "keyctl": "ENOSYS", "vsock": "ENOSYS",
    "vsock, upper bit": "ENOSYS"}
# What the kernel answers them with, under podman's default profile; a
# vsock is refused by it, but not one with an upper bit set.
SECCOMP_KERNEL = {
    "clone NEWUSER": "EINVAL", "clone NEWNET": "EINVAL",
    "unshare NEWUSER": "EINVAL", "clone3": "EINVAL", "setns": "EBADF",
    "mount": "ENOENT", "ptrace": "ESRCH", "process_vm_readv": "0",
    "pidfd_getfd": "EBADF", "keyctl": "ENOTSUP"}
# And what the box does, which reaches the kernel under either.
SECCOMP_ALLOWED = {
    "clone THREAD": "EINVAL", "unshare nothing new": "EINVAL",
    "socket inet": "EINVAL", "socket netlink route": "0",
    "socket netlink audit": "EINVAL"}
# The ptrace calls under debug.
SECCOMP_DEBUG = {"ptrace": "ESRCH", "process_vm_readv": "0",
                 "pidfd_getfd": "EBADF", "unshare NEWUSER": "EPERM",
                 "clone3": "ENOSYS"}
PODMAN_SECCOMP = "/usr/share/containers/seccomp.json"

SITECUSTOMIZE = """\
# written by tests/manual/box_rig.py: the broker's interpreter waits
# before it runs, so its start has a window a request can fall in.
import time
time.sleep(3)
"""


# --- the tool and the box ----------------------------------------------------

def box(*args, cwd=RIG, timeout=180, input=None, env=None):
    """moathut as the user types it, with `input`, or nothing, on its
    stdin."""
    stdin = {"input": input} if input is not None else {
        "stdin": subprocess.DEVNULL}
    return run([*TOOL, *args], check=False, cwd=cwd,
               env={**TOOL_ENV, **(env or {})}, timeout=timeout, **stdin)


def exec_in(argv, *, user=USER, timeout=30):
    return run(["podman", "exec", "--user", user, BOX, *argv], check=False,
               timeout=timeout)


# What an interactive bash in the box prints first: the prompt's warnings.
SHELL_PS1 = ["bash", "-ic", 'printf "%s\\n" "$PS1"']
NOT_PROTECTED = "not protected by the moat"


def interactive(*podman_exec):
    """An interactive bash opened by `podman exec`, as a terminal would:
    (its stderr, its prompt)."""
    got = run(["podman", "exec", *podman_exec, BOX, *SHELL_PS1],
              check=False, timeout=30)
    return got.stderr, got.stdout.strip()


def sudo_in(argv, **kw):
    return exec_in(["sudo", "-n", *argv], **kw)


def short(unit):
    name = unit.removesuffix(".service").replace(".timer", " timer")
    return "workload" if name == UNIT else name.removeprefix(UNIT + "-")


def states():
    out = run(["systemctl", "--user", "is-active", *SERVICES],
              check=False).stdout.split()
    return {short(s): state for s, state in zip(SERVICES, out)}


def exists(kind):
    return run(["podman", kind, "exists", BOX], check=False).returncode == 0


def listed(name=BOX):
    """The box's line in `moathut ls`, as words, or None."""
    for line in box("ls").stdout.splitlines():
        words = line.split()
        if words and words[0] == name:
            return words
    return None


def show(unit, key):
    return run(["systemctl", "--user", "show", "-p", key, "--value", unit],
               check=False).stdout.strip()


def placeholder():
    try:
        return json.loads(DESCRIBED.read_text())["placeholder"]
    except (OSError, ValueError, KeyError):
        return None


def credential_listed():
    """The rig's credential's line in `credential ls`, as words, or
    None."""
    for line in box("credential", "ls").stdout.splitlines():
        words = line.split()
        if words and words[0] == CREDENTIAL:
            return words
    return None


def reload():
    run(["systemctl", "--user", "daemon-reload"], check=False)


def reset_failed():
    """Back-to-back restarts reach the manager's start limit, which is for
    crash loops."""
    run(["systemctl", "--user", "reset-failed", *SERVICES], check=False)


def write_drop_in(which, text):
    path = DROP_INS[which]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# written by tests/manual/box_rig.py\n" + text)
    reload()


def remove_drop_in(which):
    path = DROP_INS[which]
    path.unlink(missing_ok=True)
    try:
        path.parent.rmdir()
    except OSError:
        pass


def remove_drop_ins():
    for which in DROP_INS:
        remove_drop_in(which)
    reload()


def infra_pid():
    infra = run(["podman", "pod", "inspect", BOX, "--format",
                 "{{.InfraContainerID}}"], check=False).stdout.strip()
    if not infra:
        return None
    pid = run(["podman", "inspect", "--format", "{{.State.Pid}}", infra],
              check=False).stdout.strip()
    return int(pid) if pid.isdigit() and int(pid) > 0 else None


def in_netns(pid, argv):
    return run(["podman", "unshare", "nsenter", "-t", str(pid), "-n",
                *argv], check=False)


def tables(pid):
    if pid is None:
        return set()
    out = in_netns(pid, ["nft", "list", "tables"]).stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


def netns_of(pid):
    """The namespace a process is in, as /proc names it, or None."""
    if pid is None:
        return None
    return run(["podman", "unshare", "readlink", f"/proc/{pid}/ns/net"],
               check=False).stdout.strip() or None


def held():
    """The namespace held at NAMESPACE, as /proc names it, or None."""
    return run(["podman", "unshare", "nsenter", f"--net={NAMESPACE}",
                "readlink", "/proc/self/ns/net"],
               check=False).stdout.strip() or None


def pasta_words(path):
    """The arguments of the pasta serving the namespace at `path`, as
    (option, value) pairs without `--netns PATH`, or None."""
    for proc in Path("/proc").iterdir():
        try:
            argv = (proc / "cmdline").read_bytes().split(b"\0")[:-1]
        except OSError:
            continue
        words = [w.decode() for w in argv]
        # pasta.avx2, which pasta becomes where the CPU has it, keeps
        # pasta's argv.
        if not words or not Path(words[0]).name.startswith("pasta") \
                or str(path) not in words:
            continue
        at = words.index("--netns")
        words = words[1:at] + words[at + 2:]
        pairs = []
        for word in words:
            if pairs and not word.startswith("-") and pairs[-1][1] is None:
                pairs[-1] = (pairs[-1][0], word)
            else:
                pairs.append((word, None))
        return sorted(pairs, key=str)
    return None


def counter(comment):
    pid = infra_pid()
    if pid is None:
        return -1
    out = in_netns(pid, ["nft", "list", "chain", "netdev", "moatery",
                         "egress"]).stdout
    for line in out.splitlines():
        if "packets" in line and f'comment "{comment}"' in line:
            fields = line.split()
            return int(fields[fields.index("packets") + 1])
    return -1


# --- what the far side and the record saw ------------------------------------

def await_(probe, seconds):
    """probe()'s first truthy value within `seconds`, or its last."""
    deadline = time.monotonic() + seconds
    while True:
        got = probe()
        if got or time.monotonic() > deadline:
            return got
        time.sleep(0.2)


def starts():
    """The workload's first acts: [nonce, status] per start."""
    try:
        text = (BOX_HOME / STARTS).read_text()
    except FileNotFoundError:
        return []
    return [line.split() for line in text.splitlines() if line.strip()]


def await_start(count, seconds=30):
    got = await_(lambda: starts()[count:count + 1], seconds)
    return got[0] if got else None


def records():
    try:
        return riglib.parse_records(RECORD.read_text())
    except FileNotFoundError:
        return []


def record_for(path):
    return next((r for r in records() if r.get("path") == path), None)


def refusals():
    return [r for r in records() if r.get("host") == UNLISTED]


def stub_logged(path):
    return f'"GET {path} ' in STUB_LOG.read_text()


def served(path, code):
    """Whether a request to the provider at `path` went by the inspector
    and the broker: the stub's 200, which it answers only the sealed key,
    the path in the stub's log, the record's forward under the
    credential."""
    logged = await_(lambda: stub_logged(path), 5)
    rec = await_(lambda: record_for(path), 5)
    ok = (code == "200" and logged and rec is not None
          and rec.get("decision") == "forward" and rec.get("status") == 200
          and rec.get("credential") == CREDENTIAL)
    seen = "logged" if logged else "never saw"
    return ok, (f"http={code!r}; the stub {seen} {path}; record: "
                + (f"{rec.get('decision')} {rec.get('status')} "
                   f"{rec.get('reason') or rec.get('credential')}" if rec
                   else "none"))


def start_row(label, seen):
    if seen is None:
        row(label, False, "the workload's first act wrote no line in 30 s")
        return
    nonce, code = (seen + ["", ""])[:2]
    row(label, *served(f"/start/{nonce}", code))


# --- the rows ----------------------------------------------------------------

def credential_rows(secret):
    say("credential")
    added = box("credential", "add", CREDENTIAL, "--host", PROVIDER,
                "--env", CREDENTIAL_ENV, "--auth-header", "Authorization",
                "--auth-format", "Bearer {secret}", input=secret + "\n")
    files = [p for p in (SEALED, DESCRIBED) if p.exists()]
    holding = [p.name for p in files if secret.encode() in p.read_bytes()]
    mode = f"{SEALED.stat().st_mode & 0o777:o}" if SEALED.exists() else None
    row("credential: add seals the key, and neither file holds it",
        added.returncode == 0 and len(files) == 2 and not holding
        and mode == "600",
        f"rc={added.returncode} {added.stderr.strip()[-200:]}; files "
        f"{[p.name for p in files]}; holding the key: {holding}; "
        f"mode {mode}")
    mine = credential_listed()
    row("credential: ls lists it for the provider, named by no box",
        mine == [CREDENTIAL, CREDENTIAL_ENV, PROVIDER, "-"], f"{mine}")
    return added.returncode == 0


def dry_files(text, paths):
    """--dry-run's output as path to text: each file follows a line
    naming one of `paths`, and a blank line ends it."""
    files, at = {}, None
    for line in text.splitlines(keepends=True):
        if line.startswith("# ") and Path(line[2:].strip()) in paths:
            at = Path(line[2:].strip())
            files[at] = ""
        elif at is not None:
            files[at] += line
    return {k: v.removesuffix("\n") for k, v in files.items()}


def create_rows(autostart):
    say("create")
    words = ("create", BOX, "--policy", str(POLICY),
             "--mount", str(PROJECT),
             "--mount", f"{READONLY}:{READONLY_AT}:ro",
             *(["--autostart"] if autostart else []))
    dry = box(*words, "--dry-run", timeout=300)
    wrote = [str(p) for p in (CONFIG, *UNIT_FILES) if p.exists()]
    made = box(*words, timeout=300)
    expected = set(UNIT_FILES) | set(WRITTEN_WITH)
    printed = dry_files(dry.stdout, expected)
    differ = sorted(str(p) for p, text in printed.items()
                    if not p.exists() or p.read_text() != text)
    row("create: --dry-run wrote nothing, and printed each file create "
        "wrote, as it wrote it",
        dry.returncode == 0 and not wrote and printed and not differ
        and {p for p in expected if p.exists()} == set(printed),
        f"rc={dry.returncode} {dry.stderr.strip()[-200:]}; written: "
        f"{wrote}; printed: {sorted(map(str, printed))}; differ: {differ}")
    missing = [str(p) for p in LAID_OUT if not p.exists()]
    row("create: it laid out every file docs/BOX.md lists",
        made.returncode == 0 and not missing,
        f"rc={made.returncode} {made.stderr.strip()[-300:]}; "
        f"missing: {missing}")
    running = {k: v for k, v in states().items() if v != "inactive"}
    mine = listed()
    row("create: nothing started, and ls lists the box inactive on the "
        "default image, started at login",
        not running and not exists("pod")
        and mine == [BOX, "inactive", IMAGE, "autostart"],
        f"not inactive: {running}; pod: {exists('pod')}; ls: {mine}")
    return made.returncode == 0


def chain_rows():
    say("chain")

    keys = ("Requires", "Wants", "After", "BindsTo", "PartOf", "Type",
            "Triggers")

    def loaded(unit):
        out = run(["systemctl", "--user", "show",
                   *(w for k in keys for w in ("-p", k)), unit],
                  check=False).stdout
        got = {}
        for line in out.splitlines():
            key, _, value = line.partition("=")
            got[key] = set(value.split())
        return {k: got.get(k, set()) for k in keys}

    work = loaded(SERVICE)
    row("chain: the workload wants both listeners without requiring them, "
        "is After= them, and is BindsTo= the pod",
        LISTENERS <= work["Wants"] and not LISTENERS & work["Requires"]
        and LISTENERS | {POD_SERVICE} <= work["After"]
        and POD_SERVICE in work["BindsTo"],
        "; ".join(f"{k}: {sorted(map(short, v & (LISTENERS | {POD_SERVICE})))}"
                  for k, v in work.items() if k != "Type"))
    for unit in sorted(LISTENERS):
        deps = loaded(unit)
        row(f"chain: the {short(unit)} listener is BindsTo= and "
            "After= the pod",
            POD_SERVICE in deps["BindsTo"] and POD_SERVICE in deps["After"],
            f"BindsTo: {sorted(deps['BindsTo'])}; pod in After: "
            f"{POD_SERVICE in deps['After']}")
    pod = loaded(POD_SERVICE)
    row("chain: the pod pulls in both listeners",
        LISTENERS <= pod["Wants"] | pod["Requires"],
        f"Wants: {sorted(map(short, pod['Wants'] & LISTENERS))}")
    held_by = loaded(NETNS_SERVICE)
    bound = (held_by["BindsTo"] | held_by["PartOf"]
             | held_by["Requires"]) & set(SERVICES)
    row("chain: the pod is BindsTo= and After= the namespace's unit, which "
        "is Type=notify and bound to nothing of the box's",
        NETNS_SERVICE in pod["BindsTo"] & pod["After"]
        and held_by["Type"] == {"notify"} and not bound,
        f"in the pod's BindsTo {NETNS_SERVICE in pod['BindsTo']}, After "
        f"{NETNS_SERVICE in pod['After']}; the namespace's Type "
        f"{held_by['Type']}, bound to {sorted(map(short, bound))}")
    timer = loaded(ROTATE_TIMER)
    row("chain: the pod pulls in the record's rotation timer, which is "
        "PartOf= it and triggers the rotation",
        ROTATE_TIMER in pod["Wants"] and POD_SERVICE in timer["PartOf"]
        and timer["Triggers"] == {ROTATE_SERVICE},
        f"in the pod's Wants: {ROTATE_TIMER in pod['Wants']}; PartOf: "
        f"{sorted(timer['PartOf'])}; Triggers: {sorted(timer['Triggers'])}")
    inspect = loaded(INSPECT_SERVICE)
    row("chain: the inspector pulls in the broker and is After= it, "
        "without Requires=",
        BROKER_SERVICE in inspect["Wants"] & inspect["After"]
        and BROKER_SERVICE not in inspect["Requires"],
        f"broker in Wants {BROKER_SERVICE in inspect['Wants']}, After "
        f"{BROKER_SERVICE in inspect['After']}, Requires "
        f"{BROKER_SERVICE in inspect['Requires']}")
    broker = loaded(BROKER_SERVICE)
    bound = [k for k, v in broker.items() if POD_SERVICE in v]
    row("chain: the broker is Type=notify, and nothing binds it to the pod",
        broker["Type"] == {"notify"} and not bound,
        f"Type: {broker['Type']}; the pod in {bound or 'none'}")


def fail_rows():
    say("fail (the namespace's rules load fails)")
    write_drop_in("netns", FAILING_RULES)
    before = len(starts())
    entered = box("enter", BOX, "--", "true")
    # A workload that started writes its line within its curl's 10 s.
    wrote = await_(lambda: len(starts()) > before, 15)
    row("fail: enter refuses a box whose rules load fails",
        entered.returncode != 0 and "did not start" in entered.stderr,
        f"rc={entered.returncode} {entered.stderr.strip()[-200:]}")
    row("fail: the workload never ran: its first act wrote nothing, and "
        "no container is left",
        not wrote and not exists("container"),
        f"lines {before} -> {len(starts())}; units {states()}")
    stopped = box("stop", BOX)
    now = states()
    row("fail: stop leaves no unit active, the broker's either",
        stopped.returncode == 0
        and set(now.values()) <= {"inactive", "failed"},
        f"rc={stopped.returncode} {stopped.stderr.strip()[-160:]}; {now}")


def first_rows():
    say("first start")
    before = len(starts())
    entered = box("enter", BOX, "--", "true")
    row("enter: starts the box and runs a command in it",
        entered.returncode == 0,
        f"rc={entered.returncode} {entered.stderr.strip()[-300:]}")
    start_row("first: at the box's first start, the workload's first "
              "request was inspected", await_start(before))


def premise_rows():
    say(f"premise (tool: {' '.join(TOOL)}; programs: {LIBEXEC})")
    uid = sudo_in(["id", "-u"]).stdout.strip()
    status = sudo_in(["cat", "/proc/self/status"]).stdout
    caps = {}
    for line in status.splitlines():
        key, _, value = line.partition(":")
        if key in ("CapBnd", "CapEff"):
            caps[key] = int(value.strip(), 16)
    row("premise: root in the box, by sudo, holds no CAP_NET_ADMIN",
        uid == "0" and len(caps) == 2
        and not any(v & (1 << 12) for v in caps.values()),
        f"sudo id -u: {uid!r}; "
        + ", ".join(f"{k}={v:016x}" for k, v in caps.items()))
    user = {}
    for line in exec_in(["cat", "/proc/self/status"]).stdout.splitlines():
        key, _, value = line.partition(":")
        if key in ("CapPrm", "CapEff", "CapAmb"):
            user[key] = int(value.strip(), 16)
    row("premise: the user in the box holds no capability",
        len(user) == 3 and not any(user.values()),
        ", ".join(f"{k}={v:016x}" for k, v in user.items()))
    add = sudo_in(["ip", "link", "add", "moatery-rig0", "type", "dummy"])
    row("premise: and is refused `ip link add`",
        add.returncode != 0 and "Operation not permitted" in add.stderr,
        f"rc={add.returncode} {add.stderr.strip()}")
    if add.returncode == 0:
        sudo_in(["ip", "link", "del", "moatery-rig0"])
    pid = infra_pid()
    found = tables(pid)
    row("premise: the rules are in the pod's namespace", RULES <= found,
        f"infra pid {pid}: {sorted(found) or 'no tables'}")
    infra, holding = netns_of(pid), held()
    row("premise: which is the one the netns unit holds",
        infra is not None and infra == holding,
        f"infra {infra!r}; held at {NAMESPACE}: {holding!r}")
    cgroup = run(["podman", "pod", "inspect", BOX, "--format",
                  "{{.CgroupPath}}"], check=False)
    row("premise: the pod has no cgroup of its own",
        cgroup.returncode == 0 and not cgroup.stdout.strip(),
        f"CgroupPath={cgroup.stdout.strip()!r} {cgroup.stderr.strip()}")


def enter_rows(tag):
    say("enter")
    got = box("enter", BOX, "--", "sh", "-c",
              'id -u; pwd; echo "$HOME"; '
              'getent passwd "$(id -u)" | cut -d: -f6')
    seen = got.stdout.splitlines()
    row("enter: as the user, with the box's home as working directory, "
        "HOME and passwd home",
        seen == [str(os.getuid()), INSIDE, INSIDE, INSIDE],
        f"uid, pwd, HOME, passwd home: {seen} {got.stderr.strip()[-200:]}")
    got = box("enter", BOX, "--", "sh", "-c", "pwd; cat file", cwd=SUBDIR)
    seen = got.stdout.split()
    row("enter: from inside a mount, in the same directory inside",
        seen == [str(SUBDIR), tag],
        f"pwd, file: {seen} {got.stderr.strip()[-200:]}")
    got = box("enter", BOX, "--root", "--", "sh", "-c", "id -u; pwd")
    seen = got.stdout.split()
    row("enter: with --root, as uid 0 in /root", seen == ["0", "/root"],
        f"uid, pwd: {seen} {got.stderr.strip()[-200:]}")
    prompts = [box("enter", BOX, *root, "--", "bash", "-ic",
                   'printf "%s\\n" "$PS1"').stdout.strip()
               for root in ([], ["--root"])]
    named = [f"\\[\\e[{c}m\\]\u2b22 {BOX}\\[\\e[0m\\] "
             for c in ("35", "1;31")]
    row("enter: bash's prompt starts with the box's name, magenta, and "
        "red as root",
        all(p.startswith(n) for p, n in zip(prompts, named)), f"{prompts}")
    inside = exec_in(["date", "+%z %Z"]).stdout.strip()
    outside = run(["date", "+%z %Z"]).stdout.strip()
    row("enter: the box's clock reads in the host's zone",
        inside == outside, f"inside {inside!r}, host {outside!r}"
        + ("; the host is on UTC, so this shows nothing"
           if outside.startswith("+0000") else ""))
    warn_rows()


def warn_rows():
    say("warn")
    # A shell enter refused to open warns of nothing.
    entered = [box("enter", BOX, *root, "--", *SHELL_PS1)
               for root in ([], ["--root"])]
    said = [got.stderr for got in entered]
    mark = (STATE / "netns").read_text().strip() \
        if (STATE / "netns").exists() else None
    own = exec_in(["readlink", "/proc/self/ns/net"]).stdout.strip()
    pid = infra_pid()
    infra = run(["podman", "unshare", "readlink", f"/proc/{pid}/ns/net"],
                check=False).stdout.strip() if pid else None
    row("warn: no shell enter opens warns, as the user or as root, and the "
        "namespace the box reads is its own",
        all(got.returncode == 0 for got in entered)
        and not any(NOT_PROTECTED in s for s in said)
        and mark is not None and mark == own == infra,
        f"enter rc={[got.returncode for got in entered]}; warned: "
        f"{[NOT_PROTECTED in s for s in said]}; mark {mark!r}, "
        f"inside {own!r}, infra {infra!r}")
    said, ps1 = interactive("--privileged")
    row("warn: nor does one podman exec --privileged opens, whose prompt "
        "is the box's own: it cannot change the rules (held's rows)",
        NOT_PROTECTED not in said and f"\u2b22 {BOX}" in ps1
        and "UNPROTECTED" not in ps1,
        f"stderr {said.strip()[-200:]!r}; PS1 {ps1!r}")


def held_rows():
    """What Ptyxis opens a container's tab with, `podman exec
    --privileged`: root with every capability, in the box's user
    namespace, which does not own the network namespace."""
    say("held")
    refused = {}
    for words in (["link", "add", "moatery-rig1", "type", "dummy"],
                  ["link", "set", "lo", "down"]):
        got = run(["podman", "exec", "--privileged", "--user", "0", BOX,
                   "ip", *words], check=False, timeout=30)
        refused[" ".join(words[:2])] = (
            got.returncode != 0 and "Operation not permitted" in got.stderr)
        if got.returncode == 0:
            run(["podman", "exec", "--privileged", "--user", "0", BOX, "ip",
                 *(["link", "del", "moatery-rig1"] if "add" in words
                   else ["link", "set", "lo", "up"])], check=False)
    row("held: a shell podman exec --privileged opens, as root, is refused "
        "`ip link add` and `ip link set lo down`",
        all(refused.values()), f"refused: {refused}")
    # The image has no nft: the host's, with the credentials that exec
    # gives, root with every capability in the box's user namespace.
    pid = infra_pid()
    flush = run(["podman", "unshare", "nsenter", "-t", str(pid), "-U", "-n",
                 "nft", "flush", "ruleset"], check=False, timeout=30)
    found = tables(pid)
    row("held: root with every capability in the box's user namespace is "
        "refused `nft flush ruleset`, and the rules are still there",
        flush.returncode != 0 and "Operation not permitted" in flush.stderr
        and RULES <= found,
        f"rc={flush.returncode} {flush.stderr.strip()[-160:]}; "
        f"{sorted(found) or 'no tables'}")
    if not RULES <= found:
        say("  the rules are gone: the pod restarted to load them again")
        before = len(starts())
        run(["systemctl", "--user", "restart", POD_SERVICE], check=False,
            timeout=120)
        await_start(before)
    stock = "moatery-rig-stock"
    run(["podman", "pod", "rm", "-f", "-i", stock], check=False)
    made = run(["podman", "pod", "create", "--name", stock,
                "--userns=keep-id", "--network", "pasta",
                "--share-parent=false"], check=False, timeout=120)
    run(["podman", "pod", "start", stock], check=False, timeout=120)
    infra = run(["podman", "pod", "inspect", stock, "--format",
                 "{{.InfraContainerID}}"], check=False).stdout.strip()
    sandbox = run(["podman", "inspect", "--format",
                   "{{.NetworkSettings.SandboxKey}}", infra],
                  check=False).stdout.strip()
    theirs = pasta_words(sandbox) if sandbox else None
    ours = pasta_words(NAMESPACE)
    run(["podman", "pod", "rm", "-f", "-i", stock], check=False, timeout=120)
    row("held: the box's pasta has the arguments podman gives a pod's",
        made.returncode == 0 and theirs is not None and ours == theirs,
        f"podman's: {theirs}; the box's: {ours}"
        + (f"; {made.stderr.strip()[-160:]}" if made.returncode else ""))


def seccomp_probe(*podman_exec, name=BOX):
    """The probe's errnos, run by `podman exec` in the box `name`."""
    got = run(["podman", "exec", *podman_exec, name, "python3",
               f"{INSIDE}/{SECCOMP_PROBE}"], check=False, timeout=60)
    try:
        return json.loads(got.stdout)
    except ValueError:
        return {"rc": got.returncode, "stderr": got.stderr.strip()[-200:]}


def differing(got, want):
    return {k: got.get(k) for k in want if got.get(k) != want[k]}


def seccomp_rows():
    """docs/BOX.md's profile, by errno: in a stock container the probe's
    arguments reach the kernel, in the box the filter answers first."""
    say("seccomp")
    (BOX_HOME / SECCOMP_PROBE).write_text(SECCOMP_SCRIPT)
    got = run(["podman", "run", "--rm", "--network", "none", "--userns",
               "keep-id", "--user", USER, "-v",
               f"{BOX_HOME / SECCOMP_PROBE}:/probe:ro,z", IMAGE, "python3",
               "/probe"], check=False, timeout=120)
    try:
        stock = json.loads(got.stdout)
    except ValueError:
        stock = {"rc": got.returncode, "stderr": got.stderr.strip()[-200:]}
    upper = stock.get("vsock, upper bit")
    row("seccomp: under podman's default, every call the probe makes "
        "reaches the kernel, a vsock with an upper bit set among them",
        not differing(stock, {**SECCOMP_KERNEL, **SECCOMP_ALLOWED})
        and stock.get("vsock") == "EPERM"
        and upper not in (None, "EPERM", "ENOSYS"),
        f"differing: {differing(stock, SECCOMP_KERNEL)}; vsock "
        f"{stock.get('vsock')}, with an upper bit {upper}")
    mine = seccomp_probe("--user", USER)
    row("seccomp: the box's user is refused, by the profile, a namespace, "
        "a mount, ptrace, the keyring and a vsock however its family is "
        "written",
        not differing(mine, SECCOMP_REFUSED),
        f"differing: {differing(mine, SECCOMP_REFUSED)}")
    row("seccomp: and what a box does reaches the kernel: a thread, an "
        "unshare of nothing new, an inet and a netlink socket",
        not differing(mine, SECCOMP_ALLOWED),
        f"differing: {differing(mine, SECCOMP_ALLOWED)}")
    root = seccomp_probe("--privileged", "--user", "0")
    row("seccomp: a shell podman exec --privileged opens, as root, is "
        "refused every one of them as well",
        not differing(root, SECCOMP_REFUSED),
        f"differing: {differing(root, SECCOMP_REFUSED)}")


def home_rows(tag):
    say("home")
    seen = exec_in(["sh", "-c",
                    f'test -e "{MARKER}" && echo present || echo absent; '
                    f'echo {tag} > "{INSIDE}/{WRITTEN}"']).stdout.strip()
    row("home: a file in the user's own home is not in the box",
        seen == "absent" and MARKER.exists(),
        f"{MARKER.name} inside: {seen}; on the host: {MARKER.exists()}")
    on_host = BOX_HOME / WRITTEN
    wrote = on_host.exists() and on_host.read_text().strip() == tag
    row("home: a file written in it is in the box's home on the host, "
        "not the user's",
        wrote and not (HOME / WRITTEN).exists(),
        f"in the box's home: {wrote}; in the user's: "
        f"{(HOME / WRITTEN).exists()}")

    between = [f"{INSIDE}/{d}" for d in PROJECT.relative_to(HOME).parents
               if d != Path(".")]
    wrote = exec_in(["sh", "-c", "; ".join(
        f'touch "{d}/{WRITTEN}"; echo $?' for d in between)])
    row("home: the directories between it and a mount in it are the "
        "user's", wrote.stdout.split() == ["0"] * len(between),
        f"touch in {between}: {wrote.stdout.split()} "
        f"{wrote.stderr.strip()}")

    say("mount")
    got = exec_in(["sh", "-c", f'cat "{READONLY_AT}/file"; '
                   f'touch "{READONLY_AT}/x" 2>&1; echo "rc=$?"'])
    lines = got.stdout.splitlines()
    row("mount: a :ro mount is at the DST it was given, and read-only",
        lines[:1] == [tag] and "Read-only file system" in got.stdout
        and lines[-1:] != ["rc=0"], f"{lines}")

    say("hosts")
    inside = exec_in(["cat", "/etc/hosts"]).stdout
    host = Path("/etc/hosts").read_text()
    row("hosts: the host's hosts file, with the rig's line, is not the box's",
        HOSTS_MARK in host and HOSTS_MARK not in inside,
        f"the line on the host: {HOSTS_MARK in host}; in the box: "
        f"{HOSTS_MARK in inside}")


def dns_rows():
    resolv = exec_in(["cat", "/etc/resolv.conf"]).stdout
    resolver = next((ln.split()[1] for ln in resolv.splitlines()
                     if ln.startswith("nameserver")), "169.254.1.1")
    riglib.dns_rows(
        lambda argv: exec_in(["python3", "-c", riglib.DNS_LOOKUP,
                              *argv]).stdout.strip(),
        resolver, riglib.ANSWER, RESOLVE_STATUS.read_text)


def drop_rows():
    say("silent drop")
    before = counter("dropped")
    sent = exec_in(["python3", "-c", UDP_SEND, *FILTERED_UDP]).stdout.strip()
    moved = counter("dropped")
    row("silent: a filtered UDP send returns rc=0, and is dropped",
        sent == "sent" and moved > before >= 0,
        f"send={sent!r}, dropped counter {before} -> {moved}")

    say("quic")
    before = counter("quic")
    sent = exec_in(["python3", "-c", UDP_SEND, *QUIC_UDP]).stdout.strip()
    counted, dropped = counter("quic"), counter("dropped")
    row("quic: a UDP send to 443 is counted as quic, and dropped",
        sent == "sent" and before >= 0 and counted == before + 1
        and dropped > moved,
        f"send={sent!r}, quic counter {before} -> {counted}, "
        f"dropped counter {moved} -> {dropped}")

    say("ssh")
    got = exec_in(["python3", "-c", CONNECT, SSH]).stdout.strip()
    after = counter("dropped")
    row("ssh: a TCP connect to port 22 times out, and is dropped",
        got == "TimeoutError" and dropped >= 0 and after > dropped,
        f"connect {SSH}: {got!r}, dropped counter {dropped} -> {after}")


def request_rows():
    for who, prefix, label in (("the user", [], "listed"),
                               ("root, by sudo,", ["sudo", "-n"], "root")):
        say(f"{label}: as {who.rstrip(',')}")
        nonce = os.urandom(8).hex()
        path = f"/{label}/{nonce}"
        got = exec_in([*prefix, *CURL, f"https://{PROVIDER}{path}"])
        ok, detail = served(path, got.stdout.strip())
        row(f"{label}: {who} reaches the brokered host through the "
            "inspector and the broker", ok, f"{detail} {got.stderr.strip()}")
        # Refused after the handshake, before the request is read: the
        # record has no path, and is the one more for the host.
        before = len(refusals())
        got = exec_in([*prefix, *CURL, f"https://{UNLISTED}/"])
        new = await_(lambda: refusals()[before:], 5)
        row(f"{'unlisted' if label == 'listed' else label}: {who} gets the "
            f"inspector's 403 for {UNLISTED}, and the record says why",
            got.stdout.strip() == "403" and len(new) == 1
            and new[0].get("decision") == "drop"
            and new[0].get("reason") == DROP_NOT_ALLOWLISTED
            and new[0].get("upstream") is None,
            f"http={got.stdout.strip()!r} {got.stderr.strip()}; new "
            f"records: {new}")


def counter_rows():
    say("counters (waiting for the inspector's next status write)")
    status = riglib.await_status(STATUS.read_text, after=time.time())
    if status is None:
        row("counters: the inspector wrote its status", False,
            f"{STATUS} not updated within 40 s")
        return
    unresolved = status.get("caller_unresolved")
    row("counters: every connection's caller was named",
        unresolved == 0, f"caller_unresolved={unresolved}")
    foreign = status.get("drop_reasons", {}).get(DROP_FOREIGN_CALLER)
    row("counters: nothing was dropped as a foreign caller",
        foreign == 0, f"{DROP_FOREIGN_CALLER!r}: {foreign}")


def invocation(unit):
    return show(unit, "InvocationID")


def broker_rows(secret):
    say("broker")
    fiction = placeholder()
    env = exec_in(["env"]).stdout
    got = box("enter", BOX, "--", "printenv", CREDENTIAL_ENV)
    row("broker: the box holds the placeholder, by exec and by enter, and "
        "never the key",
        fiction is not None
        and f"{CREDENTIAL_ENV}={fiction}" in env.splitlines()
        and got.stdout.strip() == fiction
        and secret not in env and secret not in got.stdout,
        f"placeholder {fiction!r}; exec's {CREDENTIAL_ENV} "
        f"{f'{CREDENTIAL_ENV}={fiction}' in env.splitlines()}; enter's "
        f"{got.stdout.strip()!r}; the key in either: "
        f"{secret in env or secret in got.stdout}")
    inside = exec_in(["test", "-e", str(BROKER_SOCKET)]).returncode
    row("broker: its socket is on the host, and the box has no path to it",
        BROKER_SOCKET.is_socket() and inside != 0,
        f"{BROKER_SOCKET} a socket on the host: {BROKER_SOCKET.is_socket()};"
        f" test -e inside: rc={inside}")
    pid = show(BROKER_SERVICE, "MainPID")
    tcp = [ln.split()[3] for ln in run(["ss", "-lntpH"]).stdout.splitlines()
           if f"pid={pid}," in ln]
    row("broker: it holds no TCP socket", pid not in ("", "0") and not tcp,
        f"pid {pid}: {tcp or 'none'}")

    run(["systemctl", "--user", "stop", BROKER_SERVICE], check=False)
    path = f"/stopped/{os.urandom(8).hex()}"
    got = exec_in([*CURL, f"https://{PROVIDER}{path}"])
    rec = await_(lambda: record_for(path), 5)
    row("broker: stopped, a request is refused 502, never reaches the "
        "provider, and the record says why",
        got.stdout.strip() == "502" and not stub_logged(path)
        and rec is not None and rec.get("decision") == "drop"
        and rec.get("reason") == DROP_BROKER_UNREACHABLE,
        f"http={got.stdout.strip()!r}; the stub saw it: "
        f"{stub_logged(path)}; record: "
        + (f"{rec.get('decision')} {rec.get('reason')!r}" if rec
           else "none"))
    path = f"/again/{os.urandom(8).hex()}"
    got = box("enter", BOX, "--", *CURL, f"https://{PROVIDER}{path}")
    ok, detail = served(path, got.stdout.strip())
    row("broker: enter starts it again, and a request is served",
        got.returncode == 0 and ok,
        f"rc={got.returncode} {got.stderr.strip()[-160:]}; {detail}")

    say("broker stopped while it starts")
    run(["systemctl", "--user", "stop", BROKER_SERVICE], check=False)
    run(["systemctl", "--user", "start", "--no-block", BROKER_SERVICE],
        check=False)
    # Inside the 3 s its interpreter sleeps.
    time.sleep(1)
    was = show(BROKER_SERVICE, "ActiveState")
    run(["systemctl", "--user", "stop", BROKER_SERVICE], check=False)
    again = run(["systemctl", "--user", "start", BROKER_SERVICE],
                check=False)
    row("broker: premise: stopped while it starts, systemd will not start "
        "it again",
        was == "activating" and again.returncode != 0,
        f"stopped while {was}; start rc={again.returncode}")
    path = f"/cleared/{os.urandom(8).hex()}"
    got = box("enter", BOX, "--", *CURL, f"https://{PROVIDER}{path}")
    ok, detail = served(path, got.stdout.strip())
    row("broker: enter starts it anyway, and a request is served",
        got.returncode == 0 and ok,
        f"rc={got.returncode} {got.stderr.strip()[-160:]}; {detail}")


def rotate_rows():
    say("rotate")
    new = "sk-new-" + os.urandom(12).hex()
    riglib.stop_children()
    riglib.children.clear()
    riglib.start_stub(new)
    path = f"/old/{os.urandom(8).hex()}"
    got = exec_in([*CURL, f"https://{PROVIDER}{path}"])
    row("rotate: premise: the provider now wants a new key, and the old one "
        "gets its 401", got.stdout.strip() == "401",
        f"http={got.stdout.strip()!r} {got.stderr.strip()}")
    before = {u: invocation(u) for u in (SERVICE, INSPECT_SERVICE,
                                         BROKER_SERVICE)}
    added = box("credential", "add", CREDENTIAL, input=new + "\n")
    path = f"/rotated/{os.urandom(8).hex()}"
    got = exec_in([*CURL, f"https://{PROVIDER}{path}"])
    ok, detail = served(path, got.stdout.strip())
    row("rotate: credential add with the new key, and the box's next "
        "request carries it",
        added.returncode == 0 and f"box {BOX}:" in added.stdout and ok,
        f"rc={added.returncode} {added.stdout.strip()!r} "
        f"{added.stderr.strip()[-160:]}; {detail}")
    after = {u: invocation(u) for u in before}
    moved = sorted(short(u) for u in before if before[u] != after[u])
    row("rotate: the broker restarted, and the inspector and the workload "
        "did not", moved == ["broker"], f"restarted: {moved}")
    return new


def container_started():
    return run(["podman", "inspect", BOX, "--format",
                "{{.Id}} {{.State.StartedAt}}"], check=False).stdout.strip()


def loop_invocations():
    return {u: invocation(u) for u in (NETNS_SERVICE, POD_SERVICE, SERVICE,
                                       INSPECT_SERVICE, RESOLVE_SERVICE,
                                       BROKER_SERVICE)}


def refused_lines():
    """`log --refused` as its lines, and its exit status."""
    got = box("log", BOX, "--refused")
    return got.returncode, got.stdout.splitlines(), got.stderr.strip()


def refused_for(lines, host, reason):
    pattern = re.compile(rf"^\s+\d+\s+{re.escape(host)}\s+"
                         rf"\({re.escape(reason)}\)$")
    return any(pattern.match(line) for line in lines)


def provider_served(label):
    path = f"/{label}/{os.urandom(8).hex()}"
    got = exec_in([*CURL, f"https://{PROVIDER}{path}"])
    return served(path, got.stdout.strip())


def policy_digest():
    return inspect_policy_digest((CONFIG / "policy.json").read_text())


def status_digest():
    try:
        return json.loads(STATUS.read_text()).get(INSPECT_DIGEST_KEY)
    except (OSError, ValueError):
        return None


def download_rows():
    say("loop: allow while a download runs")
    path = f"/slow/{SLOW_CHUNKS}/{os.urandom(8).hex()}"
    before = loop_invocations()
    download = subprocess.Popen(
        ["podman", "exec", "--user", USER, BOX, "bash", "-o", "pipefail",
         "-c", f"curl -sSf --max-time 60 'https://{PROVIDER}{path}' "
               "| sha256sum"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        # The stub logs a request as it answers it, before the body.
        began = await_(lambda: stub_logged(path), 10)
        allowed = box("allow", BOX, RELOAD_HOST)
        running = download.poll() is None
        out, err = download.communicate(timeout=60)
    finally:
        if download.poll() is None:
            download.kill()
            download.wait()
    moved = sorted(short(u) for u in before
                   if before[u] != loop_invocations()[u])
    row("loop: allow while a download through the inspector runs: it had "
        "begun, was still running when allow returned, and nothing "
        "restarted", began and running and allowed.returncode == 0
        and moved == [],
        f"begun {bool(began)}, running {running}; allow "
        f"rc={allowed.returncode} {allowed.stdout.strip()!r}; restarted: "
        f"{moved}")
    rec = await_(lambda: record_for(path), 5)
    whole = out.split()[:1] == [hashlib.sha256(SLOW_BYTES).hexdigest()]
    row("loop: and the download finished whole, every byte in order, and "
        "the record says forward 200",
        download.returncode == 0 and whole and rec is not None
        and rec.get("decision") == "forward" and rec.get("status") == 200,
        f"rc={download.returncode} {err.strip()[-160:]!r}; whole {whole}; "
        "record: " + (f"{rec.get('decision')} {rec.get('status')}"
                      if rec else "none"))


def at_terminal(argv, env, answer, prompt, seconds=60):
    """argv run with a terminal for its standard streams, `answer` typed
    once `prompt` is shown. Returns (exit status, what it wrote)."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvpe(argv[0], argv, env)
        finally:
            os._exit(127)
    said, typed = b"", False
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            said += chunk
            if not typed and prompt.encode() in said:
                os.write(fd, answer.encode())
                typed = True
    finally:
        os.close(fd)
    done, status = os.waitpid(pid, os.WNOHANG)
    if not done:
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        return None, said.decode(errors="replace")
    return os.waitstatus_to_exitcode(status), said.decode(errors="replace")


def terminal_rows():
    say("loop: policy at a terminal")
    doc = json.loads((CONFIG / "policy.json").read_text())
    doc["hosts"] = [*doc.get("hosts", []), TTY_HOST]
    TTY_POLICY.write_text(json.dumps(doc, indent=2) + "\n")
    TTY_RUNS.unlink(missing_ok=True)
    code, said = at_terminal(
        [*TOOL, "policy", BOX],
        {**TOOL_ENV, "EDITOR": str(TTY_EDITOR), "VISUAL": ""},
        "y\n", "edit it again? [Y/n]")
    runs = len(TTY_RUNS.read_text().split()) if TTY_RUNS.exists() else 0
    lines = [x for x in said.splitlines() if x.strip()]
    row("loop: policy at a terminal: the refused document is named and "
        "the editor opened again on asking, and the second is applied",
        code == 0 and "'hosts'" in said and runs == 2
        and (CONFIG / "policy.json").read_text() == TTY_POLICY.read_text(),
        f"status {code}; editor ran {runs} time(s); {lines[-3:]}")
    enforced = status_digest()
    row("loop: and the listeners reloaded: the command says so, and the "
        "inspector's status file names it",
        "its inspector and responder reloaded" in said
        and enforced == policy_digest(),
        f"{lines[-1:]}; {enforced} for {policy_digest()}")


def loop_rows():
    say("loop: log, allow and policy on the running box")
    # The responder counts a name at the query and writes its status on a
    # 30 s tick.
    listed_name = await_(lambda: UNLISTED in RESOLVE_STATUS.read_text()
                         if RESOLVE_STATUS.exists() else False, 40)
    rc, lines, err = refused_lines()
    names = lines[lines.index("names asked for that no list admits:") + 1:] \
        if "names asked for that no list admits:" in lines else []
    row("loop: log --refused counts the unlisted host's refusals, and names "
        "it among the names the responder was asked for",
        rc == 0 and refused_for(lines, UNLISTED, DROP_NOT_ALLOWLISTED)
        and listed_name and any(line.split()[-1:] == [UNLISTED]
                                for line in names),
        f"rc={rc} {err} {lines}")

    before, started = loop_invocations(), container_started()
    allowed = box("allow", BOX, UNLISTED)
    doc = json.loads((CONFIG / "policy.json").read_text())
    row("loop: allow lists the host and says the listeners reloaded",
        allowed.returncode == 0 and UNLISTED in doc.get("hosts", [])
        and "its inspector and responder reloaded" in allowed.stdout,
        f"rc={allowed.returncode} {allowed.stdout.strip()!r} "
        f"{allowed.stderr.strip()[-200:]}; hosts: {doc.get('hosts')}")
    after = loop_invocations()
    moved = sorted(short(u) for u in before if before[u] != after[u])
    same = container_started() == started
    row("loop: nothing restarted: not the listeners, the namespace, the "
        "pod, the workload or the broker",
        moved == [] and same and started != "",
        f"restarted: {moved}; the workload's container "
        f"{'the same' if same else 'replaced'}")
    enforced = status_digest()
    row("loop: the inspector's status file names the new document's digest",
        enforced == policy_digest(), f"{enforced} for {policy_digest()}")
    n = len(refusals())
    got = exec_in([*CURL, f"https://{UNLISTED}/"])
    new = await_(lambda: refusals()[n:], 5)
    row(f"loop: {UNLISTED} is dialled now, not refused: the host has no "
        "address for it, so a 502, and the record says unreachable",
        got.stdout.strip() == "502" and len(new) == 1
        and new[0].get("reason") == DROP_UNREACHABLE,
        f"http={got.stdout.strip()!r}; new records: "
        f"{[(r.get('status'), r.get('reason')) for r in new]}")
    rc, lines, err = refused_lines()
    row("loop: log --refused no longer lists it as not allowlisted",
        rc == 0 and not refused_for(lines, UNLISTED, DROP_NOT_ALLOWLISTED),
        f"rc={rc} {err} {lines}")
    row("loop: the provider is served after the reload",
        *provider_served("loop-allowed"))
    download_rows()

    say("loop: a policy that does not load")
    text = (CONFIG / "policy.json").read_text()
    before = loop_invocations()
    edited = box("policy", BOX, env={"EDITOR": str(BAD_EDITOR),
                                     "VISUAL": ""})
    row("loop: policy refuses a document the loader refuses, at the "
        "command, and the box's policy is unchanged",
        edited.returncode == 1 and "'hosts'" in edited.stderr
        and (CONFIG / "policy.json").read_text() == text,
        f"rc={edited.returncode} {edited.stderr.strip()[-200:]!r}")
    moved = sorted(short(u) for u in before
                   if before[u] != loop_invocations()[u])
    ok, detail = provider_served("loop-refused")
    row("loop: and the running box keeps its listeners: none restarted, "
        "and the provider is served", moved == [] and ok,
        f"restarted: {moved}; {detail}")
    terminal_rows()

    say("loop: a listener that dies")
    before, started = loop_invocations(), container_started()
    pid = show(INSPECT_SERVICE, "MainPID")
    run(["kill", "-KILL", pid], check=False)
    back = await_(lambda: show(INSPECT_SERVICE, "ActiveState") == "active"
                  and show(INSPECT_SERVICE, "MainPID") not in ("0", pid),
                  15)
    after = loop_invocations()
    moved = sorted(short(u) for u in before if before[u] != after[u])
    row("loop: the inspector killed is started again, and nothing else "
        "restarts", back and moved == ["inspect"]
        and container_started() == started and pid not in ("", "0"),
        f"killed {pid}, now {show(INSPECT_SERVICE, 'MainPID')} "
        f"{show(INSPECT_SERVICE, 'ActiveState')}; new invocations: {moved}")
    row("loop: and the provider is served", *provider_served("loop-killed"))

    say("loop: a listener stopped")
    started = container_started()
    run(["systemctl", "--user", "stop", INSPECT_SERVICE], check=False)
    path = f"/loop-stopped/{os.urandom(8).hex()}"
    got = exec_in([*CURL, f"https://{PROVIDER}{path}"])
    workload = show(SERVICE, "ActiveState")
    same = container_started() == started
    row("loop: the inspector stopped, the workload runs on in the same "
        "container, and its request is not served",
        workload == "active" and same and got.stdout.strip() != "200"
        and not stub_logged(path),
        f"workload {workload}, container "
        f"{'the same' if same else 'replaced'}; http="
        f"{got.stdout.strip()!r}; the stub "
        f"{'logged' if stub_logged(path) else 'never saw'} it")
    entered = box("enter", BOX, "--", "true")
    ok, detail = provider_served("loop-entered")
    row("loop: enter starts the inspector again, and the provider is served",
        entered.returncode == 0 and ok
        and show(INSPECT_SERVICE, "ActiveState") == "active",
        f"rc={entered.returncode} {entered.stderr.strip()[-160:]!r}; "
        f"{detail}")

    say("loop: log follows")
    with FOLLOWED.open("w") as out:
        follower = subprocess.Popen([*TOOL, "log", BOX], stdout=out,
                                    stderr=subprocess.STDOUT, env=TOOL_ENV,
                                    stdin=subprocess.DEVNULL)
        try:
            time.sleep(1)
            path = f"/loop-followed/{os.urandom(8).hex()}"
            exec_in([*CURL, f"https://{PROVIDER}{path}"])
            line = await_(lambda: next(
                (x for x in FOLLOWED.read_text().splitlines() if path in x),
                None), 10)
            follower.send_signal(signal.SIGINT)
            try:
                code = follower.wait(timeout=10)
            except subprocess.TimeoutExpired:
                code = None
        finally:
            if follower.poll() is None:
                follower.kill()
                follower.wait(timeout=10)
    row("loop: log follows the record: the request just made is a line, "
        "forwarded under the credential",
        line is not None and " forward 200 " in line
        and f"[{CREDENTIAL}]" in line, f"{line!r}")
    tail = FOLLOWED.read_text()
    row("loop: Ctrl-C ends log with status 0, and no traceback",
        code == 0 and "Traceback" not in tail,
        f"status {code}; {tail.strip().splitlines()[-1:]}")

    say("loop: policy drops the credential, then names it again")
    started = container_started()
    edited = box("policy", BOX, env={"EDITOR": str(PLAIN_EDITOR),
                                     "VISUAL": ""})
    broker = show(BROKER_SERVICE, "ActiveState")
    inspect = show(INSPECT_SERVICE, "ExecStart")
    row("loop: policy without the credential: the broker is stopped and its "
        "unit gone, and the inspector restarted without it",
        edited.returncode == 0 and broker == "inactive"
        and not (UNITS / BROKER_SERVICE).exists() and "--broker" not in inspect
        and show(INSPECT_SERVICE, "ActiveState") == "active",
        f"rc={edited.returncode} {edited.stdout.strip()!r} "
        f"{edited.stderr.strip()[-160:]!r}; broker {broker}, its unit "
        f"{'there' if (UNITS / BROKER_SERVICE).exists() else 'gone'}; "
        f"--broker in the inspector's command: {'--broker' in inspect}")
    path = f"/loop-plain/{os.urandom(8).hex()}"
    got = exec_in([*CURL, f"https://{PROVIDER}{path}"])
    rec = await_(lambda: record_for(path), 5)
    row("loop: the provider is reached unbrokered now: the stub's 401 to "
        "the placeholder, and the record names no credential",
        got.stdout.strip() == "401" and rec is not None
        and rec.get("decision") == "forward" and rec.get("status") == 401
        and rec.get("credential") is None,
        f"http={got.stdout.strip()!r}; record: "
        + (f"{rec.get('decision')} {rec.get('status')} "
           f"{rec.get('credential')}" if rec else "none"))
    edited = box("policy", BOX, env={"EDITOR": str(BROKERED_EDITOR),
                                     "VISUAL": ""})
    ok, detail = provider_served("loop-brokered")
    same = container_started() == started
    row("loop: policy naming it again: the broker is back, and the provider "
        "is served; the workload ran on in the same container throughout",
        edited.returncode == 0 and ok and same
        and show(BROKER_SERVICE, "ActiveState") == "active",
        f"rc={edited.returncode} {edited.stdout.strip()!r} "
        f"{edited.stderr.strip()[-160:]!r}; {detail}; container "
        f"{'the same' if same else 'replaced'}")


def record_rows(without_reopen):
    say("record: its rotation")
    # Ended, not begun: a start while the timer's run is under way joins
    # it, and that run measured the record before the line below.
    ran = await_(lambda: show(ROTATE_SERVICE,
                              "ExecMainExitTimestampMonotonic")
                 not in ("", "0")
                 and show(ROTATE_SERVICE, "ActiveState") == "inactive", 75)
    timer, result, status = (show(ROTATE_TIMER, "ActiveState"),
                             show(ROTATE_SERVICE, "Result"),
                             show(ROTATE_SERVICE, "ExecMainStatus"))
    row("record: the rotation's timer is active with the pod, and has run "
        "the rotation, which exited 0",
        timer == "active" and ran and result == "success" and status == "0",
        f"timer {timer}; ran {bool(ran)}; result {result}, status {status}")
    if without_reopen:
        write_drop_in("rotate", "[Service]\nExecStart=\n"
                      f"ExecStart=/usr/bin/mv {RECORD} {rotated(RECORD, 1)}\n")
        say("  the rotation signals nothing, as asked")
    # A line the record's readers skip, as they do one being written.
    with RECORD.open("ab") as handle:
        handle.write(b"x" * ROTATE_BYTES + b"\n")
    started = run(["systemctl", "--user", "start", ROTATE_SERVICE],
                  check=False, timeout=60)
    path = f"/record/{os.urandom(8).hex()}"
    got = exec_in([*CURL, f"https://{PROVIDER}{path}"])
    rec = await_(lambda: record_for(path), 5)
    try:
        moved = rotated(RECORD, 1).read_bytes()
    except FileNotFoundError:
        moved = b""
    padded, stale = b"x" * 1024 in moved, path.encode() in moved
    size = RECORD.stat().st_size if RECORD.exists() else None
    row("record: past its size it is moved aside, and the next request's "
        "line is in a new record, not the moved one",
        started.returncode == 0 and padded and not stale
        and rec is not None and size is not None and size < ROTATE_BYTES,
        f"rc={started.returncode} {started.stderr.strip()[-160:]}; "
        f"http={got.stdout.strip()!r}; moved: {len(moved)} bytes, padded "
        f"{padded}, the line in it {stale}; new record: {size} bytes, the "
        f"line in it {rec is not None}")
    if without_reopen:
        remove_drop_in("rotate")
        reload()
        # What the rotation leaves out, so the rows after read the record.
        run(["systemctl", "--user", "kill", "--kill-whom=main", "-s", "HUP",
             INSPECT_SERVICE], check=False)


def restart_rows(count, tag):
    say("persist, and workload restarts")
    exec_in(["sh", "-c", f"echo {tag} > /var/tmp/moatery-rig-reset; "
             f'echo {tag} > "{INSIDE}/{KEPT}"'])
    for i in range(1, count + 1):
        reset_failed()
        before = len(starts())
        run(["systemctl", "--user", "restart", SERVICE], check=False)
        start_row(f"restart: after workload restart {i}, the first request "
                  "was inspected", await_start(before))
        if i == 1:
            seen = exec_in(["sh", "-c",
                            "cat /var/tmp/moatery-rig-reset 2>/dev/null "
                            f'|| echo gone; cat "{INSIDE}/{KEPT}"']
                           ).stdout.split()
            row("persist: after a restart, a file outside the home is gone "
                "and one in it is there", seen == ["gone", tag],
                f"outside, in the home: {seen}")

    say("pod restarts")
    for i in range(1, count + 1):
        reset_failed()
        pid, before = infra_pid(), len(starts())
        was = netns_of(pid)
        run(["systemctl", "--user", "restart", POD_SERVICE], check=False)
        seen = await_start(before)
        now = infra_pid()
        found = tables(now)
        row(f"restart: pod restart {i} keeps the held namespace, with the "
            "rules in it",
            now not in (None, pid) and netns_of(now) == was == held()
            and RULES <= found,
            f"infra pid {pid} -> {now}, namespace {was} -> "
            f"{netns_of(now)}, held {held()}: "
            f"{sorted(found) or 'no tables'}")
        start_row(f"restart: after pod restart {i}, the first request was "
                  "inspected", seen)


def stop_rows():
    say("stop")
    stopped = box("stop", BOX)
    now, mine = states(), listed()
    row("stop: every unit inactive, the timer too, no pod, no container, "
        "the namespace let go, and ls says so",
        stopped.returncode == 0 and set(now.values()) == {"inactive"}
        and not exists("pod") and not exists("container")
        and not NAMESPACE.exists()
        and mine is not None and mine[1:2] == ["inactive"],
        f"rc={stopped.returncode}; units {now}; pod {exists('pod')}, "
        f"container {exists('container')}; namespace's file "
        f"{NAMESPACE.exists()}; ls: {mine}")
    before = len(starts())
    entered = box("enter", BOX, "--", "true")
    seen, mine = await_start(before), listed()
    row("stop: enter starts it again, and ls says so",
        entered.returncode == 0 and mine is not None
        and mine[1:2] == ["active"],
        f"rc={entered.returncode} {entered.stderr.strip()[-200:]}; "
        f"ls: {mine}")
    start_row("stop: after enter, the first request was inspected", seen)


def autostart_rows():
    """What the manager does at login, or at boot for a lingering user, is
    start default.target; it is started here the same way, the box
    stopped, and it is the manager that starts the box."""
    say("autostart")
    wanted = show(SERVICE, "WantedBy").split()
    box("stop", BOX)
    before = len(starts())
    run(["systemctl", "--user", "start", "default.target"], check=False,
        timeout=180)
    seen = await_start(before)
    now, found = states(), tables(infra_pid())
    row("autostart: the manager's start of default.target starts the "
        "stopped box, with the rules",
        "default.target" in wanted and now["workload"] == "active"
        and RULES <= found,
        f"WantedBy={wanted}; units {now}; {sorted(found) or 'no tables'}")
    start_row("autostart: and its first request was inspected", seen)


def outside_rows():
    say("outside systemd")
    pid, before, was = infra_pid(), len(starts()), held()
    run(["podman", "pod", "restart", BOX], check=False, timeout=120)
    seen = await_start(before)
    if seen:
        say(f"  the workload's first request after it: http={seen[1:2]}")
    now = infra_pid()
    found = tables(now)
    entered = box("enter", BOX, "--", "true")
    row("outside: after podman pod restart the pod is in the held "
        "namespace, with the rules, and enter serves it",
        now not in (None, pid) and netns_of(now) == was is not None
        and RULES <= found and entered.returncode == 0,
        f"infra pid {pid} -> {now}, namespace {was} -> {netns_of(now)}: "
        f"{sorted(found) or 'no tables'}; enter rc={entered.returncode} "
        f"{entered.stderr.strip()[-160:]}")
    said, ps1 = interactive()
    mine = listed()
    row("outside: and a shell in it does not warn, nor ls",
        NOT_PROTECTED not in said and "UNPROTECTED" not in ps1
        and mine is not None and "unprotected" not in mine,
        f"stderr {said.strip()[-200:]!r}; PS1 {ps1!r}; ls: {mine}")

    # The user is root over the namespace, from the host: the moat does
    # not stand against the user, and ls and enter say what is missing.
    run(["podman", "unshare", "nsenter", f"--net={NAMESPACE}", "nft",
         "delete", "table", "inet", "moatery"], check=False)
    listing = box("ls")
    mine = listed()
    entered = box("enter", BOX, "--", "true")
    row("outside: with a table deleted from the host, ls marks the box "
        "unprotected and says so, and enter refuses it",
        mine is not None and mine[-1] == "unprotected"
        and f"box {BOX} is not protected" in listing.stderr
        and entered.returncode != 0 and "no moatery rules" in entered.stderr,
        f"ls: {mine}; stderr {listing.stderr.strip()[-160:]!r}; enter "
        f"rc={entered.returncode} {entered.stderr.strip()[-160:]}")
    box("stop", BOX)
    # After the stop no workload is left to write a line.
    before = len(starts())
    entered = box("enter", BOX, "--", "true")
    seen = await_start(before)
    found, mine = tables(infra_pid()), listed()
    row("outside: stop, then enter, serves it again with the rules, and ls "
        "no longer marks it",
        entered.returncode == 0 and RULES <= found
        and mine is not None and "unprotected" not in mine,
        f"rc={entered.returncode} {entered.stderr.strip()[-200:]}; "
        f"{sorted(found) or 'no tables'}; ls: {mine}")
    start_row("outside: and its first request was inspected", seen)

    got = run(["podman", "run", "--rm", "--network", "none",
               "-v", f"{CONFIG / 'prompt.sh'}:/etc/profile.d/moathut.sh:ro,z",
               "-v", f"{MARK}:/run/moathut/netns:ro,z", IMAGE,
               "bash", "--rcfile", "/etc/profile.d/moathut.sh", "-ic",
               'printf "%s\\n" "$PS1"'], check=False, timeout=120)
    row("outside: a container run by hand from the box's image and files "
        "warns that the box is not protected, and its prompt says "
        "UNPROTECTED",
        f"box {BOX} is not protected by the moat" in got.stderr
        and f"\u2b22 {BOX} UNPROTECTED" in got.stdout,
        f"rc={got.returncode} stderr {got.stderr.strip()[-200:]!r}; PS1 "
        f"{got.stdout.strip()!r}")

    write_drop_in("pod", POD_LEFT)
    box("stop", BOX)
    left = exists("pod")
    started = run(["podman", "pod", "start", BOX], check=False, timeout=60)
    running = infra_pid()
    row("outside: a pod the box left, started by podman with the "
        "namespace's unit stopped, does not start: nothing of it runs",
        left and started.returncode != 0 and running is None
        and not exists("container"),
        f"pod left {left}; start rc={started.returncode} "
        f"{(started.stderr or started.stdout).strip()[-200:]}; infra pid "
        f"{running}")
    run(["podman", "pod", "rm", "-f", "-i", BOX], check=False, timeout=60)
    remove_drop_in("pod")
    reload()


def load_state(unit):
    return run(["systemctl", "--user", "show", "-p", "LoadState", "--value",
                unit], check=False).stdout.strip()


def like_rows(tag):
    say("like")
    made = box("create", TWIN, "--like", BOX, "--seccomp", "debug",
               timeout=300)
    mine, twin = (json.loads((c / "box.json").read_text())
                  if (c / "box.json").exists() else {}
                  for c in (CONFIG, TWIN_CONFIG))
    same = {k: mine.get(k) == twin.get(k) for k in ("image", "mounts")}
    policy = (TWIN_CONFIG / "policy.json").exists() and (
        (TWIN_CONFIG / "policy.json").read_bytes()
        == (CONFIG / "policy.json").read_bytes())
    row("like: create --like gives the box's policy, as edited, its image "
        "and its mounts",
        made.returncode == 0 and policy and all(same.values()),
        f"rc={made.returncode} {made.stderr.strip()[-200:]}; policy "
        f"{policy}; {same}")
    entry = listed(TWIN)
    row("like: and neither its autostart nor its home; its profile is "
        "debug, as given",
        entry == [TWIN, "inactive", IMAGE, "seccomp:debug"]
        and not (TWIN_SHARE / "home" / KEPT).exists(),
        f"ls: {entry}; {KEPT} in its home: "
        f"{(TWIN_SHARE / 'home' / KEPT).exists()}")
    got = box("enter", TWIN, "--", "cat", f"{READONLY_AT}/file",
              timeout=300)
    row("like: entered, it reads the :ro mount at its DST",
        got.returncode == 0 and got.stdout.strip() == tag,
        f"rc={got.returncode} {got.stdout.strip()!r} "
        f"{got.stderr.strip()[-200:]}")
    (TWIN_SHARE / "home" / SECCOMP_PROBE).write_text(SECCOMP_SCRIPT)
    debug = seccomp_probe("--user", USER, name=TWIN)
    row("like: under debug, ptrace reaches the kernel, and a namespace is "
        "refused still",
        not differing(debug, SECCOMP_DEBUG),
        f"differing: {differing(debug, SECCOMP_DEBUG)}")
    removed = box("rm", TWIN, "--home")
    row("like: rm --home leaves nothing of it",
        removed.returncode == 0 and not TWIN_CONFIG.exists()
        and not TWIN_SHARE.exists() and listed(TWIN) is None,
        f"rc={removed.returncode}; config {TWIN_CONFIG.exists()}, share "
        f"{TWIN_SHARE.exists()}")


def rm_rows(tag):
    say("rm")
    refused = box("credential", "rm", CREDENTIAL)
    row("rm: credential rm is refused while the box names it",
        refused.returncode != 0 and "named by" in refused.stderr
        and SEALED.exists() and DESCRIBED.exists(),
        f"rc={refused.returncode} {refused.stderr.strip()[-160:]}")
    remove_drop_ins()
    # A box nothing reached has no record.
    recorded = RECORD.exists()
    removed = box("rm", BOX)
    left = [p.name for p in UNIT_FILES if p.exists()]
    loads = {short(s): load_state(s) for s in SERVICES}
    row("rm: no unit, pod or container is left, nor the broker's socket, "
        "and ls does not list it",
        removed.returncode == 0 and not left
        and set(loads.values()) == {"not-found"}
        and not exists("pod") and not exists("container")
        and not BROKER_SOCKET.parent.exists() and listed() is None,
        f"rc={removed.returncode}; files left {left}; {loads}; pod "
        f"{exists('pod')}, container {exists('container')}; socket "
        f"directory {BROKER_SOCKET.parent.exists()}")
    row("rm: the box's home and its record stay",
        (BOX_HOME / KEPT).exists() and LOGS.is_dir()
        and RECORD.exists() == recorded,
        f"{KEPT} in the home: {(BOX_HOME / KEPT).exists()}; record: "
        f"{recorded} -> {RECORD.exists()}; said {removed.stdout.split()}")
    made = box("create", BOX, "--policy", str(PLAIN_POLICY))
    run(["systemctl", "--user", "start", "default.target"], check=False,
        timeout=180)
    now = states()
    row("rm: a box made without --autostart, default.target does not "
        "start",
        made.returncode == 0 and set(now.values()) == {"inactive"},
        f"units {now}")
    got = box("enter", BOX, "--", "cat", f"{INSIDE}/{KEPT}")
    broker = (UNITS / BROKER_SERVICE).exists()
    row("rm: create again, with a policy naming no credential, finds the "
        "home and writes no broker",
        made.returncode == 0 and got.stdout.strip() == tag and not broker,
        f"create rc={made.returncode}; enter: {got.stdout.strip()!r} "
        f"{got.stderr.strip()[-200:]}; broker unit {broker}")
    removed = box("rm", BOX, "--home")
    row("rm --home: the home goes too",
        removed.returncode == 0 and not SHARE.exists()
        and not CONFIG.exists(),
        f"rc={removed.returncode}; home {SHARE.exists()}, config "
        f"{CONFIG.exists()}")
    gone = box("credential", "rm", CREDENTIAL)
    row("rm: then credential rm removes the credential",
        gone.returncode == 0 and not SEALED.exists()
        and not DESCRIBED.exists() and credential_listed() is None,
        f"rc={gone.returncode} {gone.stderr.strip()[-160:]}; files "
        f"{SEALED.exists()}, {DESCRIBED.exists()}")


def probe(args, tag, secret):
    chain_rows()
    write_drop_in("inspect",
                  f"[Service]\nEnvironment=SSL_CERT_FILE={riglib.STUB_CERT}\n"
                  + ("ExecReload=\n" if args.without_reload else ""))
    if args.without_reload:
        say("  the inspector's unit has no ExecReload=, as asked")
    pythonpath = ":".join([str(SLOW), *PROGRAM_ENV.values()])
    write_drop_in("broker",
                  f"[Service]\nEnvironment=SSL_CERT_FILE={riglib.STUB_CERT}\n"
                  f"Environment=PYTHONPATH={pythonpath}\n"
                  + ("Type=simple\n" if args.broker_not_ready else ""))
    if args.broker_not_ready:
        say("  the broker's unit is Type=simple, as asked")
    (BOX_HOME / START).write_text(START_SCRIPT)
    write_drop_in("workload", (
        f"[Unit]\nRequires={INSPECT_SERVICE} {RESOLVE_SERVICE}\n"
        if args.listeners_required else "")
        + f"[Container]\nExec=/bin/sh {INSIDE}/{START}\n"
        + (f"SeccompProfile={PODMAN_SECCOMP}\n" if args.podman_seccomp
           else ""))
    if args.listeners_required:
        say("  the workload Requires= the listeners, as asked")
    if args.podman_seccomp:
        say("  the workload runs under podman's default profile, as asked")
    fail_rows()
    if args.without_rules:
        write_drop_in("netns", NO_RULES)
        say("  the namespace's rules NOT loaded, as asked")
    else:
        remove_drop_in("netns")
        reload()
    if args.without_held_netns:
        pythonpath = "".join(f"Environment=PYTHONPATH={v}\n"
                             for v in PROGRAM_ENV.values())
        write_drop_in("quadlet pod", (
            "[Pod]\nNetwork=\nNetwork=pasta\n[Service]\n" + pythonpath
            + f"ExecStartPost=podman unshare {sys.executable} -s "
              f"{OLD_RULES}\n"))
        say("  the pod makes its own namespace, as asked")
    reset_failed()
    first_rows()
    premise_rows()
    enter_rows(tag)
    held_rows()
    seccomp_rows()
    home_rows(tag)
    dns_rows()
    drop_rows()
    request_rows()
    broker_rows(secret)
    rotate_rows()
    counter_rows()
    loop_rows()
    record_rows(args.without_reopen)
    restart_rows(args.restarts, tag)
    stop_rows()
    autostart_rows()
    outside_rows()
    like_rows(tag)
    rm_rows(tag)


# --- material, leftovers, teardown -------------------------------------------

def clear_leftovers():
    """The rig's own box, by name, as a run with --keep or one cut short
    left it."""
    remove_drop_ins()
    for name, config in ((BOX, CONFIG), (TWIN, TWIN_CONFIG)):
        if (config / "box.json").exists():
            box("rm", name, "--home")
    run(["systemctl", "--user", "stop", BROKER_SERVICE], check=False)
    run(["podman", "pod", "rm", "-f", "-i", BOX], check=False)
    run(["podman", "rm", "-f", "-i", BOX], check=False)
    # The box's root writes in its home, as a uid the user is not.
    run(["podman", "unshare", "rm", "-rf", "--", str(CONFIG), str(STATE),
         str(LOGS), str(SHARE), str(PROJECT), str(READONLY),
         str(TWIN_CONFIG), str(TWIN_LOGS), str(TWIN_SHARE)], check=False)
    for path in (MARKER, HOME / WRITTEN, SEALED, DESCRIBED):
        path.unlink(missing_ok=True)
    shutil.rmtree(SLOW, ignore_errors=True)
    for path in (NFT_FAILS, NFT_LOADS_NOTHING):
        shutil.rmtree(path, ignore_errors=True)
    OLD_RULES.unlink(missing_ok=True)
    run(["podman", "pod", "rm", "-f", "-i", "moatery-rig-stock"],
        check=False)


def material():
    say("material")
    riglib.make_stub_cert()
    POLICY.write_text(json.dumps({
        "tls": "inspect", "hosts": [], "internal_expected": [],
        "splice": [], "policy": [
            {"host": PROVIDER, "credential": CREDENTIAL}]}, indent=2) + "\n")
    PLAIN_POLICY.write_text(json.dumps({"hosts": [PROVIDER]}) + "\n")
    BAD_EDITOR.write_text("#!/bin/sh\nprintf '{\"hosts\": \"x\"}' > \"$1\"\n")
    BAD_EDITOR.chmod(0o755)
    TTY_EDITOR.write_text(
        "#!/bin/sh\n"
        f"echo run >> '{TTY_RUNS}'\n"
        f"if [ \"$(wc -l < '{TTY_RUNS}')\" -eq 1 ]; then\n"
        "  printf '{\"hosts\": \"x\"}' > \"$1\"\n"
        f"else\n  cp '{TTY_POLICY}' \"$1\"\nfi\n")
    TTY_EDITOR.chmod(0o755)
    for editor, document in ((PLAIN_EDITOR, PLAIN_POLICY),
                             (BROKERED_EDITOR, POLICY)):
        editor.write_text(f"#!/bin/sh\ncp '{document}' \"$1\"\n")
        editor.chmod(0o755)
    SLOW.mkdir(parents=True, exist_ok=True)
    (SLOW / "sitecustomize.py").write_text(SITECUSTOMIZE)
    for directory, body in ((NFT_FAILS, "echo 'box_rig: nft fails, as "
                                        "asked' >&2\nexit 1\n"),
                            (NFT_LOADS_NOTHING, "cat > /dev/null\n")):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "nft").write_text(
            "#!/bin/sh\n# written by tests/manual/box_rig.py\n" + body)
        (directory / "nft").chmod(0o755)
    OLD_RULES.write_text(OLD_RULES_SCRIPT)
    tag = os.urandom(4).hex()
    SUBDIR.mkdir(parents=True)
    READONLY.mkdir(parents=True)
    for path in (SUBDIR / "file", READONLY / "file", MARKER):
        path.write_text(tag + "\n")
    if run(["podman", "image", "exists", IMAGE], check=False).returncode:
        say(f"  pulling {IMAGE}")
        run(["podman", "pull", "-q", IMAGE], timeout=900)
    return tag


def teardown(keep):
    say("teardown")
    if not keep:
        remove_drop_ins()
        for name, config in ((BOX, CONFIG), (TWIN, TWIN_CONFIG)):
            if (config / "box.json").exists():
                box("rm", name, "--home")
        for path in (PROJECT, READONLY, SLOW, TWIN_LOGS, NFT_FAILS,
                     NFT_LOADS_NOTHING):
            shutil.rmtree(path, ignore_errors=True)
        OLD_RULES.unlink(missing_ok=True)
        for path in (MARKER, SEALED, DESCRIBED):
            path.unlink(missing_ok=True)
    riglib.stop_children()
    riglib.restore_privileged_ports()
    riglib.remove_hosts_entry()


# --- main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="leave the box and its drop-ins for inspection")
    ap.add_argument("--without-rules", action="store_true",
                    help="give the namespace's unit an nft that loads "
                         "nothing; the rows that need the rules must go "
                         "red")
    ap.add_argument("--without-held-netns", action="store_true",
                    help="let the pod make its own namespace, with the "
                         "rules loaded into it; held's, the held "
                         "namespace's and outside's rows must go red")
    ap.add_argument("--podman-seccomp", action="store_true",
                    help="run the workload under podman's default seccomp "
                         "profile; seccomp's refusals must go red")
    ap.add_argument("--broker-not-ready", action="store_true",
                    help="make the broker's unit Type=simple; the first "
                         "request after each start of it must go red")
    ap.add_argument("--listeners-required", action="store_true",
                    help="make the workload Requires= the listeners again; "
                         "the loop's rows that no restart or stop of a "
                         "listener reaches the workload must go red")
    ap.add_argument("--without-reload", action="store_true",
                    help="empty the inspector's ExecReload=; the loop's "
                         "rows that a new policy restarts nothing must go "
                         "red")
    ap.add_argument("--without-reopen", action="store_true",
                    help="make the rotation a rename that signals nothing; "
                         "the record's row that the next line is in a new "
                         "record must go red")
    ap.add_argument("--without-autostart", action="store_true",
                    help="make the box without --autostart; the create "
                         "row's ls and the autostart rows must go red")
    ap.add_argument("--restarts", type=int, default=3, metavar="N",
                    help="workload restarts, then pod restarts (default 3)")
    args = ap.parse_args()

    riglib.preflight(
        ("podman", "nsenter", "openssl", "curl", "ss", "systemctl",
         "systemd-creds", *(("moathut",) if riglib.INSTALLED else ())),
        (riglib.PROVIDER_PORT,))
    state = run(["systemctl", "--user", "is-system-running", "--wait"],
                check=False, timeout=180).stdout.strip()
    if state not in ("running", "degraded"):
        sys.exit(f"user manager is {state or 'absent'}; log in with a "
                 "session (ssh is one)")
    RIG.mkdir(parents=True, exist_ok=True)
    clear_leftovers()
    tag = material()
    # Only the broker holds it; the stub answers 200 to it alone.
    secret = "sk-real-" + os.urandom(12).hex()
    try:
        say("host side")
        riglib.lower_privileged_ports()
        riglib.write_hosts_entry(HOSTS_MARK)
        riglib.start_stub(secret)
        if credential_rows(secret) and \
                create_rows(not args.without_autostart):
            probe(args, tag, secret)
    finally:
        teardown(args.keep)

    expected = []
    if args.without_rules:
        expected.append(
            "--without-rules: first, premise's rules, enter and every row "
            "through it on the rig's box, held's nft row, dns, silent, "
            "quic, ssh, listed, unlisted, root, the broker's requests, "
            "rotate, the loop's that make a request or read one back, the "
            "record's rotation, the killed inspector's and enter's, "
            "restart, stop's enter, autostart's, and outside's that enter "
            "serves the box, with its ls, are expected red")
    if args.without_held_netns:
        expected.append(
            "--without-held-netns: held's refusals, premise's held "
            "namespace, restart's pod restarts, and outside's restart and "
            "left pod are expected red")
    if args.podman_seccomp:
        expected.append(
            "--podman-seccomp: seccomp's two rows of refusals are expected "
            "red")
    if args.broker_not_ready:
        expected.append(
            "--broker-not-ready: first, the premise of a stop while the "
            "broker starts, each enter that starts it again, rotate's "
            "request, the loop's request once policy names the credential "
            "again, and each enter after a stop are expected red")
    if args.listeners_required:
        expected.append(
            "--listeners-required: the loop's rows that the inspector's "
            "start after it is killed restarts nothing else, and that the "
            "workload runs on while the inspector is stopped and through "
            "the policy edits that restart it, are expected red")
    if args.without_reload:
        expected.append(
            "--without-reload: the loop's rows that allow says the "
            "listeners reloaded and restarts nothing, the download running "
            "on and finishing whole, and the terminal's edit reloading the "
            "listeners are expected red")
    if args.without_reopen:
        expected.append(
            "--without-reopen: the record's row that the next request's "
            "line is in a new record is expected red")
    if args.without_autostart:
        expected.append(
            "--without-autostart: create's ls, the autostart rows and "
            "outside's first are expected red")
    rc = riglib.report("; ".join(expected) or None)
    if rc:
        say(f"journal: journalctl --user -u '{UNIT}*' -b")
    return rc


if __name__ == "__main__":
    sys.exit(main())
