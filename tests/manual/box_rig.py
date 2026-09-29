#!/usr/bin/env python3
"""box_rig.py — a customs box, made and run through its command line.

docs/BOX.md: `customs-box create`, `enter`, `stop` and `rm`, the box's
units run by the user's manager and quadlet, and shape 1n's rules and
listeners in the pod's namespace. Run on the proving host as an ordinary
user, from a checkout:

    python3 tests/manual/box_rig.py [--keep] [--without-rules]
                                    [--restarts N]

The tool is the checkout's bin/customs-box running the checkout's
programs, or, with CUSTOMS_LIBEXEC=/usr/libexec/customs, the installed
customs-box. riglib's two host facts need sudo and are undone at teardown.

Beside the units `create` writes, the rig writes three drop-ins, and
removes them before `rm`:

  inspector SSL_CERT_FILE names the stub's certificate, which no system
            store holds.
  workload  Exec= is a script in the box's home in place of `sleep
            infinity`. At every start its first act is a request to the
            provider, whose nonce and status it appends to a file in the
            home; then it sleeps. That request is the window: nothing the
            workload sends may come before the rules and the listeners.
  pod       for the fail rows, its ExecStartPost= is `false`; with
            --without-rules, it is empty.

The stub is on the host's 127.0.0.1, which the pod cannot reach, so
anything the stub answers came by the inspector's dial. The box holds no
key, so the stub's answer is its 401. Every request's path carries a
nonce, found in the stub's log and in the record.

THE ROWS

  create    the files docs/BOX.md lists are there, and nothing started.
  chain     the manager loaded the order: the workload pulls in both
            listeners and is After= them, and is BindsTo= the pod; each
            listener is BindsTo= and After= the pod.
  fail      with the pod's rules load failing, enter refuses and the
            workload never ran: its first act left no line.
  first     at the box's first start, the workload's first request was
            inspected: the stub logged its path and the record says
            forward.
  premise   root in the box, by sudo, holds no CAP_NET_ADMIN and is refused
            `ip link add`; the user holds no capability at all; the rules
            are in the pod's namespace; the pod has no cgroup of its own.
  enter     as the user, with the box's home as working directory, HOME
            and passwd home; from inside a mount, in the same directory
            inside; with --root, as uid 0.
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
  listed    the provider's 401 reaches the user, the stub logged the path,
            and the record says forward.
  unlisted  the inspector's 403, and one more record for the host, saying
            why, with no upstream.
  root      root, by sudo, which drops the CA variables, is inspected the
            same: the listed host verifies through the bundle mounted over
            the system store, and the unlisted one gets the 403.
  counters  every caller was named and none dropped as foreign.
  persist   after a workload restart, a file written outside the home is
            gone and one in it is there.
  restart   N workload restarts, then N pod restarts, each pod restart a
            new namespace with the rules in it: at every start the first
            request was inspected.
  stop      every unit inactive, no pod, no container, and ls says so; then
            enter starts it, and its first request was inspected.
  outside   after `podman pod restart`, outside systemd, the namespace is
            new and has no rules, and enter refuses it; stop, then enter,
            serves it again.
  rm        no unit, pod or container is left; the home and the record
            stay, and create finds the home again; rm --home removes it.

`--without-rules` empties the pod's ExecStartPost=, so the pod starts
with no rules in its namespace: first, the premise that the rules are
there, enter (which refuses), dns, silent, quic, ssh, listed, unlisted,
root, restart, and each enter after a stop with its first request must
go red.
"""

import argparse
import json
import os
import shutil
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
from customs.egress_ca import ca_cert_path  # noqa
from customs.egress_record import DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED  # noqa

BOX = "customs-rig-box"
UNIT = f"customs-box-{BOX}"
POD_SERVICE = f"{UNIT}-pod.service"
SERVICE = f"{UNIT}.service"
INSPECT_SERVICE = f"{UNIT}-inspect.service"
RESOLVE_SERVICE = f"{UNIT}-resolve.service"
SERVICES = (POD_SERVICE, INSPECT_SERVICE, RESOLVE_SERVICE, SERVICE)
LISTENERS = {INSPECT_SERVICE, RESOLVE_SERVICE}
# docs/BOX.md's default.
IMAGE = "registry.fedoraproject.org/fedora-toolbox:44"

# docs/BOX.md's table of a box's files.
CONFIG = HOME / ".config" / "customs" / "box" / BOX
STATE = HOME / ".local" / "state" / "customs" / "box" / BOX
LOGS = HOME / ".local" / "state" / "log" / "customs" / "box" / BOX
SHARE = HOME / ".local" / "share" / "customs" / "box" / BOX
BOX_HOME = SHARE / "home"
QUADLET = HOME / ".config" / "containers" / "systemd"
UNITS = HOME / ".config" / "systemd" / "user"
UNIT_FILES = (QUADLET / f"{UNIT}.pod", QUADLET / f"{UNIT}.container",
              UNITS / INSPECT_SERVICE, UNITS / RESOLVE_SERVICE)
LAID_OUT = (CONFIG / "policy.json", CONFIG / "bundle.pem",
            ca_cert_path(STATE), LOGS, BOX_HOME, *UNIT_FILES)
STATUS = STATE / "status.json"
RESOLVE_STATUS = STATE / "resolve-status.json"
RECORD = LOGS / "requests.log"

DROP_INS = {"inspect": UNITS / f"{INSPECT_SERVICE}.d" / "rig.conf",
            "workload": QUADLET / f"{UNIT}.container.d" / "rig.conf",
            "pod": UNITS / f"{POD_SERVICE}.d" / "rig.conf"}
FAILING_RULES = "[Service]\nExecStartPost=\nExecStartPost=/usr/bin/false\n"
NO_RULES = "[Service]\nExecStartPost=\n"

# Inside, the box's home is at the user's home's path.
INSIDE = str(HOME)
START = ".customs-rig-start"
STARTS = ".customs-rig-starts"
KEPT = ".customs-rig-kept"
WRITTEN = ".customs-rig-written"
MARKER = HOME / ".customs-rig-marker"

POLICY = RIG / "box-policy.json"
PROJECT = RIG / "box-project"
SUBDIR = PROJECT / "sub"
READONLY = RIG / "box-ro"
READONLY_AT = "/srv/customs-rig-ro"
STUB_LOG = RIG / "stub.log"
HOSTS_MARK = "customs-box-rig"

if riglib.INSTALLED:
    TOOL = ["customs-box"]
    TOOL_ENV = dict(os.environ)
else:
    TOOL = [sys.executable, str(CHECKOUT / "bin" / "customs-box")]
    TOOL_ENV = {**os.environ, **PROGRAM_ENV,
                "CUSTOMS_LIBEXEC": str(LIBEXEC)}

USER = f"{os.getuid()}:{os.getgid()}"

START_SCRIPT = f"""\
# written by tests/manual/box_rig.py: the workload's first act at every
# start, then what `create` runs.
n=$(cat /proc/sys/kernel/random/uuid)
c=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 \\
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

RULES = {"table inet customs", "table netdev customs"}


# --- the tool and the box ----------------------------------------------------

def box(*args, cwd=RIG, timeout=180):
    """customs-box as the user types it, with nothing on its stdin."""
    return run([*TOOL, *args], check=False, cwd=cwd, env=TOOL_ENV,
               stdin=subprocess.DEVNULL, timeout=timeout)


def exec_in(argv, *, user=USER, timeout=30):
    return run(["podman", "exec", "--user", user, BOX, *argv], check=False,
               timeout=timeout)


def sudo_in(argv, **kw):
    return exec_in(["sudo", "-n", *argv], **kw)


def short(unit):
    name = unit.removesuffix(".service")
    return "workload" if name == UNIT else name.removeprefix(UNIT + "-")


def states():
    out = run(["systemctl", "--user", "is-active", *SERVICES],
              check=False).stdout.split()
    return {short(s): state for s, state in zip(SERVICES, out)}


def exists(kind):
    return run(["podman", kind, "exists", BOX], check=False).returncode == 0


def listed():
    """The box's line in `customs-box ls`, as words, or None."""
    for line in box("ls").stdout.splitlines():
        words = line.split()
        if words and words[0] == BOX:
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


def counter(comment):
    pid = infra_pid()
    if pid is None:
        return -1
    out = in_netns(pid, ["nft", "list", "chain", "netdev", "customs",
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
    """Whether a request to the provider at `path` went by the inspector:
    the stub's 401, the path in the stub's log, the record's forward."""
    logged = await_(lambda: stub_logged(path), 5)
    rec = await_(lambda: record_for(path), 5)
    ok = (code == "401" and logged and rec is not None
          and rec.get("decision") == "forward" and rec.get("status") == 401)
    seen = "logged" if logged else "never saw"
    return ok, (f"http={code!r}; the stub {seen} {path}; record: "
                + (f"{rec.get('decision')} {rec.get('status')}" if rec
                   else "none"))


def start_row(label, seen):
    if seen is None:
        row(label, False, "the workload's first act wrote no line in 30 s")
        return
    nonce, code = (seen + ["", ""])[:2]
    row(label, *served(f"/start/{nonce}", code))


# --- the rows ----------------------------------------------------------------

def create_rows():
    say("create")
    made = box("create", BOX, "--policy", str(POLICY),
               "--mount", str(PROJECT),
               "--mount", f"{READONLY}:{READONLY_AT}:ro", timeout=300)
    missing = [str(p) for p in LAID_OUT if not p.exists()]
    row("create: it laid out every file docs/BOX.md lists",
        made.returncode == 0 and not missing,
        f"rc={made.returncode} {made.stderr.strip()[-300:]}; "
        f"missing: {missing}")
    running = {k: v for k, v in states().items() if v != "inactive"}
    mine = listed()
    row("create: nothing started, and ls lists the box inactive on the "
        "default image",
        not running and not exists("pod")
        and mine == [BOX, "inactive", IMAGE],
        f"not inactive: {running}; pod: {exists('pod')}; ls: {mine}")
    return made.returncode == 0


def chain_rows():
    say("chain")

    def loaded(unit):
        out = run(["systemctl", "--user", "show", "-p", "Requires",
                   "-p", "Wants", "-p", "After", "-p", "BindsTo", unit],
                  check=False).stdout
        got = {}
        for line in out.splitlines():
            key, _, value = line.partition("=")
            got[key] = set(value.split())
        return {k: got.get(k, set())
                for k in ("Requires", "Wants", "After", "BindsTo")}

    work = loaded(SERVICE)
    row("chain: the workload pulls in both listeners, is After= them, and "
        "is BindsTo= the pod",
        LISTENERS <= work["Requires"] | work["Wants"]
        and LISTENERS | {POD_SERVICE} <= work["After"]
        and POD_SERVICE in work["BindsTo"],
        "; ".join(f"{k}: {sorted(map(short, v & (LISTENERS | {POD_SERVICE})))}"
                  for k, v in work.items()))
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


def fail_rows():
    say("fail (the pod's rules load fails)")
    write_drop_in("pod", FAILING_RULES)
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
    add = sudo_in(["ip", "link", "add", "customs-rig0", "type", "dummy"])
    row("premise: and is refused `ip link add`",
        add.returncode != 0 and "Operation not permitted" in add.stderr,
        f"rc={add.returncode} {add.stderr.strip()}")
    if add.returncode == 0:
        sudo_in(["ip", "link", "del", "customs-rig0"])
    pid = infra_pid()
    found = tables(pid)
    row("premise: the rules are in the pod's namespace", RULES <= found,
        f"infra pid {pid}: {sorted(found) or 'no tables'}")
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
        resolver, "127.0.0.1", RESOLVE_STATUS.read_text)


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
        row(f"{label}: {who} reaches the listed host through the inspector",
            ok, f"{detail} {got.stderr.strip()}")
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


def restart_rows(count, tag):
    say("persist, and workload restarts")
    exec_in(["sh", "-c", f"echo {tag} > /var/tmp/customs-rig-reset; "
             f'echo {tag} > "{INSIDE}/{KEPT}"'])
    for i in range(1, count + 1):
        reset_failed()
        before = len(starts())
        run(["systemctl", "--user", "restart", SERVICE], check=False)
        start_row(f"restart: after workload restart {i}, the first request "
                  "was inspected", await_start(before))
        if i == 1:
            seen = exec_in(["sh", "-c",
                            "cat /var/tmp/customs-rig-reset 2>/dev/null "
                            f'|| echo gone; cat "{INSIDE}/{KEPT}"']
                           ).stdout.split()
            row("persist: after a restart, a file outside the home is gone "
                "and one in it is there", seen == ["gone", tag],
                f"outside, in the home: {seen}")

    say("pod restarts")
    for i in range(1, count + 1):
        reset_failed()
        pid, before = infra_pid(), len(starts())
        run(["systemctl", "--user", "restart", POD_SERVICE], check=False)
        seen = await_start(before)
        now = infra_pid()
        found = tables(now)
        row(f"restart: pod restart {i} is a new namespace with the rules "
            "in it", now not in (None, pid) and RULES <= found,
            f"infra pid {pid} -> {now}: {sorted(found) or 'no tables'}")
        start_row(f"restart: after pod restart {i}, the first request was "
                  "inspected", seen)


def stop_rows():
    say("stop")
    stopped = box("stop", BOX)
    now, mine = states(), listed()
    row("stop: every unit inactive, no pod, no container, and ls says so",
        stopped.returncode == 0 and set(now.values()) == {"inactive"}
        and not exists("pod") and not exists("container")
        and mine is not None and mine[1:2] == ["inactive"],
        f"rc={stopped.returncode}; units {now}; pod {exists('pod')}, "
        f"container {exists('container')}; ls: {mine}")
    before = len(starts())
    entered = box("enter", BOX, "--", "true")
    seen, mine = await_start(before), listed()
    row("stop: enter starts it again, and ls says so",
        entered.returncode == 0 and mine is not None
        and mine[1:2] == ["active"],
        f"rc={entered.returncode} {entered.stderr.strip()[-200:]}; "
        f"ls: {mine}")
    start_row("stop: after enter, the first request was inspected", seen)


def outside_rows():
    say("outside systemd (podman pod restart)")
    pid, before = infra_pid(), len(starts())
    run(["podman", "pod", "restart", BOX], check=False, timeout=120)
    seen = await_start(before)
    if seen:
        say(f"  the workload's first request in the new namespace: "
            f"http={seen[1:2]} (docs/BOX.md, What is not closed)")
    now = infra_pid()
    found = tables(now)
    entered = box("enter", BOX, "--", "true")
    row("outside: after podman pod restart the namespace is new and has "
        "no rules, and enter refuses it",
        now not in (None, pid) and not RULES & found
        and entered.returncode != 0
        and "no customs rules" in entered.stderr,
        f"infra pid {pid} -> {now}: {sorted(found) or 'no tables'}; "
        f"enter rc={entered.returncode} {entered.stderr.strip()[-160:]}")
    box("stop", BOX)
    # After the stop no workload is left to write a line.
    before = len(starts())
    entered = box("enter", BOX, "--", "true")
    seen = await_start(before)
    found = tables(infra_pid())
    row("outside: stop, then enter, serves it again with the rules",
        entered.returncode == 0 and RULES <= found,
        f"rc={entered.returncode} {entered.stderr.strip()[-200:]}; "
        f"{sorted(found) or 'no tables'}")
    start_row("outside: and its first request was inspected", seen)


def load_state(unit):
    return run(["systemctl", "--user", "show", "-p", "LoadState", "--value",
                unit], check=False).stdout.strip()


def rm_rows(tag):
    say("rm")
    remove_drop_ins()
    # A box nothing reached has no record.
    recorded = RECORD.exists()
    removed = box("rm", BOX)
    left = [p.name for p in UNIT_FILES if p.exists()]
    loads = {short(s): load_state(s) for s in SERVICES}
    row("rm: no unit, pod or container is left, and ls does not list it",
        removed.returncode == 0 and not left
        and set(loads.values()) == {"not-found"}
        and not exists("pod") and not exists("container")
        and listed() is None,
        f"rc={removed.returncode}; files left {left}; {loads}; pod "
        f"{exists('pod')}, container {exists('container')}")
    row("rm: the box's home and its record stay",
        (BOX_HOME / KEPT).exists() and LOGS.is_dir()
        and RECORD.exists() == recorded,
        f"{KEPT} in the home: {(BOX_HOME / KEPT).exists()}; record: "
        f"{recorded} -> {RECORD.exists()}; said {removed.stdout.split()}")
    made = box("create", BOX, "--policy", str(POLICY))
    got = box("enter", BOX, "--", "cat", f"{INSIDE}/{KEPT}")
    row("rm: create again finds the home",
        made.returncode == 0 and got.stdout.strip() == tag,
        f"create rc={made.returncode}; enter: {got.stdout.strip()!r} "
        f"{got.stderr.strip()[-200:]}")
    removed = box("rm", BOX, "--home")
    row("rm --home: the home goes too",
        removed.returncode == 0 and not SHARE.exists()
        and not CONFIG.exists(),
        f"rc={removed.returncode}; home {SHARE.exists()}, config "
        f"{CONFIG.exists()}")


def probe(args, tag):
    chain_rows()
    write_drop_in("inspect",
                  f"[Service]\nEnvironment=SSL_CERT_FILE={riglib.STUB_CERT}\n")
    (BOX_HOME / START).write_text(START_SCRIPT)
    write_drop_in("workload", f"[Container]\nExec=/bin/sh {INSIDE}/{START}\n")
    fail_rows()
    if args.without_rules:
        write_drop_in("pod", NO_RULES)
        say("  the pod's rules NOT loaded, as asked")
    else:
        remove_drop_in("pod")
        reload()
    reset_failed()
    first_rows()
    premise_rows()
    enter_rows(tag)
    home_rows(tag)
    dns_rows()
    drop_rows()
    request_rows()
    counter_rows()
    restart_rows(args.restarts, tag)
    stop_rows()
    outside_rows()
    rm_rows(tag)


# --- material, leftovers, teardown -------------------------------------------

def clear_leftovers():
    """The rig's own box, by name, as a run with --keep or one cut short
    left it."""
    remove_drop_ins()
    if (CONFIG / "box.json").exists():
        box("rm", BOX, "--home")
    run(["podman", "pod", "rm", "-f", "-i", BOX], check=False)
    run(["podman", "rm", "-f", "-i", BOX], check=False)
    # The box's root writes in its home, as a uid the user is not.
    run(["podman", "unshare", "rm", "-rf", "--", str(CONFIG), str(STATE),
         str(LOGS), str(SHARE), str(PROJECT), str(READONLY)], check=False)
    for path in (MARKER, HOME / WRITTEN):
        path.unlink(missing_ok=True)


def material():
    say("material")
    riglib.make_stub_cert()
    POLICY.write_text(json.dumps({
        "tls": "inspect", "hosts": [PROVIDER], "internal_expected": [],
        "splice": [], "policy": []}, indent=2) + "\n")
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
        if (CONFIG / "box.json").exists():
            box("rm", BOX, "--home")
        for path in (PROJECT, READONLY):
            shutil.rmtree(path, ignore_errors=True)
        MARKER.unlink(missing_ok=True)
    riglib.stop_children()
    riglib.restore_privileged_ports()
    riglib.remove_hosts_entry()


# --- main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="leave the box and its drop-ins for inspection")
    ap.add_argument("--without-rules", action="store_true",
                    help="empty the pod's ExecStartPost=; the rows that "
                         "need the rules must go red")
    ap.add_argument("--restarts", type=int, default=3, metavar="N",
                    help="workload restarts, then pod restarts (default 3)")
    args = ap.parse_args()

    riglib.preflight(
        ("podman", "nsenter", "openssl", "curl", "ss", "systemctl",
         *(("customs-box",) if riglib.INSTALLED else ())),
        (riglib.PROVIDER_PORT,))
    state = run(["systemctl", "--user", "is-system-running", "--wait"],
                check=False, timeout=180).stdout.strip()
    if state not in ("running", "degraded"):
        sys.exit(f"user manager is {state or 'absent'}; log in with a "
                 "session (ssh is one)")
    RIG.mkdir(parents=True, exist_ok=True)
    clear_leftovers()
    tag = material()
    # The box holds no key; the stub answers it 401.
    secret = "sk-real-" + os.urandom(12).hex()
    try:
        say("host side")
        riglib.lower_privileged_ports()
        riglib.write_hosts_entry(HOSTS_MARK)
        riglib.start_stub(secret)
        if create_rows():
            probe(args, tag)
    finally:
        teardown(args.keep)

    rc = riglib.report(
        "--without-rules: first, premise's rules, enter, dns, silent, "
        "quic, ssh, listed, unlisted, root, restart, and each enter after "
        "a stop are expected red" if args.without_rules else None)
    if rc:
        say(f"journal: journalctl --user -u '{UNIT}*' -b")
    return rc


if __name__ == "__main__":
    sys.exit(main())
