#!/usr/bin/env python3
"""box_rig.py — a customs box, made and run through its command line.

docs/BOX.md: `customs-box credential add`, `create`, `enter`, `log`,
`allow`, `policy`, `stop` and `rm`, the box's units run by the user's
manager and quadlet, shape 1n's rules and listeners in the pod's
namespace, and the box's broker. Run on
the proving host as an ordinary user, from a checkout:

    python3 tests/manual/box_rig.py [--keep] [--without-rules]
                                    [--broker-not-ready]
                                    [--listeners-required]
                                    [--without-reload] [--restarts N]

The tool is the checkout's bin/customs-box running the checkout's
programs, or, with CUSTOMS_LIBEXEC=/usr/libexec/customs, the installed
customs-box. riglib's two host facts need sudo and are undone at teardown.

Beside the units `create` writes, the rig writes four drop-ins, and
removes them before `rm`:

  inspector SSL_CERT_FILE names the stub's certificate, which no system
            store holds; with --without-reload, an empty ExecReload=.
  broker    the same, and a PYTHONPATH whose sitecustomize sleeps 3 s, so
            the broker's start has a window a request can fall in; with
            --broker-not-ready, Type=simple.
  workload  Exec= is a script in the box's home in place of `sleep
            infinity`. At every start its first act is a request to the
            provider, whose nonce and status it appends to a file in the
            home; then it sleeps. That request is the window: nothing the
            workload sends may come before the rules, the listeners and
            the broker.
  pod       for the fail rows, its ExecStartPost= is `false`; with
            --without-rules, it is empty.

The stub is on the host's 127.0.0.1, which the pod cannot reach, so
anything the stub answers came by the inspector's dial. The provider is
brokered: the box holds a placeholder, and the stub answers 200 only to
the key the rig sealed, which only the broker holds, and 401 to anything
else. Every request's path carries a nonce, found in the stub's log and
in the record.

THE ROWS

  credential  add seals the key: neither file holds it, and ls lists it.
  create    the files docs/BOX.md lists are there, and nothing started.
  chain     the manager loaded the order: the workload Wants= both
            listeners, Requires= neither, and is After= them, and is
            BindsTo= the pod; each
            listener is BindsTo= and After= the pod; the inspector pulls
            in the broker and is After= it, which is Type=notify and not
            bound to the pod.
  fail      with the pod's rules load failing, enter refuses and the
            workload never ran: its first act left no line; stop leaves
            no unit active.
  first     at the box's first start, the workload's first request was
            inspected and brokered: the stub answered 200 and logged its
            path, and the record says forward under the credential.
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
  rm        credential rm is refused while the box names it; no unit, pod
            or container is left, nor the broker's socket; the home and the
            record stay, and create, with a policy naming no credential,
            finds the home again and writes no broker; rm --home removes
            it; then credential rm removes the credential.

`--without-rules` empties the pod's ExecStartPost=, so the pod starts
with no rules in its namespace: first, the premise that the rules are
there, enter (which refuses) and every row through it, dns, silent,
quic, ssh, listed, unlisted, root, the broker's requests, rotate, the
loop's rows that make a request or read one back, the killed
inspector's, and enter's, restart, and each enter after a stop with its
first request must go red. (The killed inspector's row is red because an
enter refused left the broker stopped, and the inspector's restart
starts it: Wants=.)

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
from customs.egress_ca import ca_cert_path  # noqa
from customs.inspect_document import (  # noqa
    INSPECT_DIGEST_KEY, inspect_policy_digest,
)
from customs.egress_record import (  # noqa
    DROP_BROKER_UNREACHABLE, DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED,
    DROP_UNREACHABLE,
)

BOX = "customs-rig-box"
UNIT = f"customs-box-{BOX}"
POD_SERVICE = f"{UNIT}-pod.service"
SERVICE = f"{UNIT}.service"
INSPECT_SERVICE = f"{UNIT}-inspect.service"
RESOLVE_SERVICE = f"{UNIT}-resolve.service"
BROKER_SERVICE = f"{UNIT}-broker.service"
SERVICES = (POD_SERVICE, INSPECT_SERVICE, RESOLVE_SERVICE, BROKER_SERVICE,
            SERVICE)
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
              UNITS / INSPECT_SERVICE, UNITS / RESOLVE_SERVICE,
              UNITS / BROKER_SERVICE)
LAID_OUT = (CONFIG / "policy.json", CONFIG / "bundle.pem",
            ca_cert_path(STATE), LOGS, BOX_HOME, *UNIT_FILES)
STATUS = STATE / "status.json"
RESOLVE_STATUS = STATE / "resolve-status.json"
RECORD = LOGS / "requests.log"
CREDENTIAL = "customs-rig-key"
CREDENTIAL_ENV = "CUSTOMS_RIG_KEY"
CREDENTIALS = HOME / ".config" / "customs" / "credentials"
SEALED = CREDENTIALS / f"{CREDENTIAL}.cred"
DESCRIBED = CREDENTIALS / f"{CREDENTIAL}.json"
RUNTIME = Path(os.environ.get("XDG_RUNTIME_DIR")
               or f"/run/user/{os.getuid()}")
BROKER_SOCKET = RUNTIME / "customs-box" / BOX / "broker.sock"

DROP_INS = {"inspect": UNITS / f"{INSPECT_SERVICE}.d" / "rig.conf",
            "broker": UNITS / f"{BROKER_SERVICE}.d" / "rig.conf",
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
PLAIN_POLICY = RIG / "box-plain-policy.json"
# $EDITOR for `customs-box policy`: writes a document the loader refuses.
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
RELOAD_HOST = "customs-rig-reload.example"
TTY_HOST = "customs-rig-tty.example"
# The stub's /slow/N: N chunks of 64 KiB, 0.1 s apart (stub_provider.py).
SLOW_CHUNKS = 80
SLOW_BYTES = b"".join(bytes([i % 256]) * 65536 for i in range(SLOW_CHUNKS))
FOLLOWED = RIG / "box-log-followed"
SLOW = RIG / "box-slow"
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

RULES = {"table inet customs", "table netdev customs"}

SITECUSTOMIZE = """\
# written by tests/manual/box_rig.py: the broker's interpreter waits
# before it runs, so its start has a window a request can fall in.
import time
time.sleep(3)
"""


# --- the tool and the box ----------------------------------------------------

def box(*args, cwd=RIG, timeout=180, input=None, env=None):
    """customs-box as the user types it, with `input`, or nothing, on its
    stdin."""
    stdin = {"input": input} if input is not None else {
        "stdin": subprocess.DEVNULL}
    return run([*TOOL, *args], check=False, cwd=cwd,
               env={**TOOL_ENV, **(env or {})}, timeout=timeout, **stdin)


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

    keys = ("Requires", "Wants", "After", "BindsTo", "PartOf", "Type")

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
    return {u: invocation(u) for u in (POD_SERVICE, SERVICE, INSPECT_SERVICE,
                                       RESOLVE_SERVICE, BROKER_SERVICE)}


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
    row("loop: nothing restarted: not the listeners, the pod, the workload "
        "or the broker", moved == [] and same and started != "",
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
        + f"[Container]\nExec=/bin/sh {INSIDE}/{START}\n")
    if args.listeners_required:
        say("  the workload Requires= the listeners, as asked")
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
    broker_rows(secret)
    rotate_rows()
    counter_rows()
    loop_rows()
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
    run(["systemctl", "--user", "stop", BROKER_SERVICE], check=False)
    run(["podman", "pod", "rm", "-f", "-i", BOX], check=False)
    run(["podman", "rm", "-f", "-i", BOX], check=False)
    # The box's root writes in its home, as a uid the user is not.
    run(["podman", "unshare", "rm", "-rf", "--", str(CONFIG), str(STATE),
         str(LOGS), str(SHARE), str(PROJECT), str(READONLY)], check=False)
    for path in (MARKER, HOME / WRITTEN, SEALED, DESCRIBED):
        path.unlink(missing_ok=True)
    shutil.rmtree(SLOW, ignore_errors=True)


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
        for path in (PROJECT, READONLY, SLOW):
            shutil.rmtree(path, ignore_errors=True)
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
                    help="empty the pod's ExecStartPost=; the rows that "
                         "need the rules must go red")
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
    ap.add_argument("--restarts", type=int, default=3, metavar="N",
                    help="workload restarts, then pod restarts (default 3)")
    args = ap.parse_args()

    riglib.preflight(
        ("podman", "nsenter", "openssl", "curl", "ss", "systemctl",
         "systemd-creds", *(("customs-box",) if riglib.INSTALLED else ())),
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
        if credential_rows(secret) and create_rows():
            probe(args, tag, secret)
    finally:
        teardown(args.keep)

    expected = []
    if args.without_rules:
        expected.append(
            "--without-rules: first, premise's rules, enter and every row "
            "through it, dns, silent, quic, ssh, listed, unlisted, root, the "
            "broker's requests, rotate, the loop's that make a request "
            "or read one back, the killed inspector's and enter's, "
            "restart, and each enter after a stop are expected red")
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
    rc = riglib.report("; ".join(expected) or None)
    if rc:
        say(f"journal: journalctl --user -u '{UNIT}*' -b")
    return rc


if __name__ == "__main__":
    sys.exit(main())
