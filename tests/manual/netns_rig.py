#!/usr/bin/env python3
"""netns_rig.py — the inspector's listeners in the container's netns.

"Netns" in docs/DESIGN.md: one rootless podman container under plain
pasta, the broker as a hand-written user unit, the inspector and the
responder as transient user units started between `podman init` and
`podman start` through moat-netns-listen, which binds their sockets in
the container's network namespace. Run on the proving host as an
ordinary user, from a checkout:

    python3 tests/manual/netns_rig.py [--keep] [--without-rules]
                                        [--without-dns-redirect]
                                        [--without-netns-pid]
                                        [--without-notify]

The two host facts riglib needs sudo for are host_rig's, undone at teardown.

THE ROWS

  premise   the container's bounding set holds no CAP_NET_ADMIN; the rules
            are in its netns.
  ready     the units are Type=notify: when systemd reported each started,
            its ports were already listening in the container's namespace,
            so a workload ordered after them cannot dial before the bind.
  inspector the inspector is up on the listeners the launcher handed it,
            and both are rows in the container's socket table, none in the
            host's.
  dns       the workload's queries, to its resolver over UDP and TCP and to
            any other nameserver, are answered by moat-resolve with the
            namespace's loopback, for names nothing resolves; an AAAA gets
            no records; the responder's status names the unlisted names and
            not the provider's. The container has no --add-host, so every
            request row below also resolved its name here.
  host      nothing listens on the host's 127.0.0.1 at either plane: the
            user's dial and another uid's are refused. The control is the
            request row, which reaches the same planes from inside.
  silent    a filtered UDP send returns rc=0 while the egress chain's drop
            counter moves. Nothing the workload may send crosses the
            egress device now, so the chain accepts nothing at all.
  quic      a UDP send to 443, HTTP/3's port, moves the egress chain's
            `quic` counter, which the silent row's port-9 send left at
            zero, and the drop counter with it.
  request   from inside, with the placeholder, the provider answers 200 and
            reports the REAL key; the environment holds the placeholder
            only; the broker logged it; the record says forwarded under the
            credential. The provider is on the host's 127.0.0.1, which the
            container cannot reach, so the 200 is also the observation that
            the inspector's upstream dial left from the host's namespace.
  another   a request from another uid inside the container, a subuid
  uid       outside, is served too: the inspector serves every uid of the
            container's user namespace, which is how sudo inside works.
  broker    the broker holds no TCP socket; the container has no path to
            its socket.
  unlisted  from inside, a host the policy does not name is refused by the
            inspector and the record says why.
  no key    the origin gives the placeholder 401 and the real key 200.
  counters  every caller was named -- in the container's table, which is
            where they are -- and none was dropped as foreign.

`--without-rules` skips the netns rules: premise, dns, silent, quic,
request and unlisted must go red. `--without-dns-redirect` leaves the
port-53 lines out of the redirect, so the queries go to pasta's
forwarder and the egress chain drops them: dns, request and unlisted
must go red.
`--without-netns-pid` starts the inspector without it, so its lookups
would read the host's table: it must refuse to start, and inspector,
request, unlisted and counters go red.
`--without-notify` starts the two units as Type=simple, reported started
when forked, before the launcher has bound anything: ready must go red.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import riglib  # noqa
from riglib import (  # noqa
    CA_BUNDLE_IN_CONTAINER, CREDENTIAL, IMAGE, INSPECT_CLEARTEXT,
    INSPECT_TLS, LIBEXEC, NAME, PLACEHOLDER, PROGRAM_ENV, PROVIDER,
    RESOLVE_PORT, RIG, STUB_CERT, UNLISTED, row, run, say,
)
from moatery.egress_ca import ca_cert_path  # noqa
from moatery.egress_record import DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED  # noqa
from moatery.peer_identity import PROC_NET_TCP, netns_tables  # noqa

CONTAINER = "moatery-rig-netns"
UNIT = "moatery-rig-netns"
BROKER_SOCKET = Path(os.environ.get("XDG_RUNTIME_DIR",
                                    f"/run/user/{os.getuid()}"),
                     UNIT, "broker.sock")
HOSTS_MARK = "moatery-netns-rig"

UNITS = riglib.HOME / ".config" / "systemd" / "user"
STATE = RIG / "state"
POLICY = RIG / "inspect-netns.json"
STATUS = RIG / "inspect-netns-status.json"
RESOLVE_STATUS = RIG / "resolve-netns-status.json"
RECORD = RIG / "egress-netns.jsonl"
BUNDLE = RIG / "bundle-netns.pem"
CRED = RIG / f"{CREDENTIAL}-netns.cred"

# PYTHONPATH when the programs are the checkout's. SSL_CERT_FILE hands both
# programs the stub's certificate and replaces their trust store, which is
# fine only because neither dials anything but the stub here.
ENV = {**PROGRAM_ENV, "SSL_CERT_FILE": str(STUB_CERT)}


# --- the host side -----------------------------------------------------------

def seal_credential(secret):
    run(["systemd-creds", "--user", "encrypt", f"--name={CREDENTIAL}",
         "-", str(CRED)], input=secret + "\n")
    CRED.chmod(0o600)


def start_broker():
    """host_rig's broker unit, unchanged: the placement of the listeners
    does not touch it."""
    UNITS.mkdir(parents=True, exist_ok=True)
    (UNITS / f"{UNIT}-broker.service").write_text(
        "# written by tests/manual/netns_rig.py — removed at teardown\n"
        "[Service]\n"
        f"ExecStart={sys.executable} {LIBEXEC / 'moat-broker'}"
        f" --name {NAME} --listen unix:%t/{UNIT}/broker.sock"
        f" --caller-uid {os.getuid()}"
        f" --host {PROVIDER}={CREDENTIAL}"
        f" --placeholder {CREDENTIAL}={PLACEHOLDER}"
        f" --auth-header {CREDENTIAL}=Authorization"
        f" \"--auth-format={CREDENTIAL}=Bearer {{secret}}\"\n"
        f"LoadCredentialEncrypted={CREDENTIAL}:{CRED}\n"
        f"RuntimeDirectory={UNIT}\n"
        "RuntimeDirectoryMode=0700\n"
        + "".join(f"Environment={k}={v}\n" for k, v in ENV.items()))
    run(["systemctl", "--user", "daemon-reload"])
    run(["systemctl", "--user", "start", f"{UNIT}-broker.service"])
    for _ in range(50):
        if BROKER_SOCKET.exists():
            say(f"  broker listening on {BROKER_SOCKET}")
            return
        time.sleep(0.2)
    sys.exit("broker never listened:\n" + journal("broker"))


# Whether each unit's ports were listening in the container's namespace
# the moment systemd-run returned, which is when systemd reported it
# started.
READY = {}


def listening(pid, proto, port):
    """Whether 127.0.0.1:port is bound in pid's namespace: a TCP row in
    LISTEN, or a UDP row, which is unconnected."""
    want = f"0100007F:{port:04X}"
    state = "0A" if proto == "tcp" else "07"
    try:
        lines = Path(f"/proc/{pid}/net/{proto}").read_text().splitlines()
    except OSError:
        return False
    return any(f[1] == want and f[3] == state
               for f in (line.split() for line in lines[1:]))


def unit_type(notify):
    return ["-p", f"Type={'notify' if notify else 'simple'}"]


def start_inspector(pid, netns_pid, notify):
    """The recipe's line: a transient unit, started once the netns exists
    and before the workload does. The launcher binds in the container's
    namespace and execs the inspector with the listeners."""
    extra = ["--netns-pid", str(pid)] if netns_pid else []
    run(["systemd-run", "--user", "--quiet", "--unit", f"{UNIT}-inspect",
         *unit_type(notify),
         *(f"--setenv={k}={v}" for k, v in ENV.items()),
         sys.executable, str(LIBEXEC / "moat-netns-listen"),
         "--pid", str(pid), "--",
         sys.executable, str(LIBEXEC / "moat-inspect"),
         "--name", NAME, "--policy", str(POLICY), "--state-dir", str(STATE),
         "--status", str(STATUS), "--record", str(RECORD),
         "--broker", f"unix:{BROKER_SOCKET}", *extra])
    READY["inspector"] = [listening(pid, "tcp", port)
                          for port in (INSPECT_TLS, INSPECT_CLEARTEXT)]
    for _ in range(50):
        if STATUS.exists() or not unit_active():
            break
        time.sleep(0.2)
    say(f"  inspector {'up' if unit_active() else 'NOT up'}"
        f" (pid {unit_pid()})")


def start_responder(pid, notify, address=riglib.ANSWER):
    """The same launcher with --resolver: the responder's port bound in the
    container's namespace, and every name answered with `address`."""
    run(["systemd-run", "--user", "--quiet", "--unit", f"{UNIT}-resolve",
         *unit_type(notify),
         *(f"--setenv={k}={v}" for k, v in PROGRAM_ENV.items()),
         sys.executable, str(LIBEXEC / "moat-netns-listen"),
         "--pid", str(pid), "--resolver", "--",
         sys.executable, str(LIBEXEC / "moat-resolve"),
         "--name", NAME, "--address", address, "--policy", str(POLICY),
         "--status", str(RESOLVE_STATUS)])
    READY["responder"] = [listening(pid, proto, RESOLVE_PORT)
                          for proto in ("udp", "tcp")]
    for _ in range(50):
        if RESOLVE_STATUS.exists() or not unit_active("resolve"):
            break
        time.sleep(0.2)
    say(f"  responder {'up' if unit_active('resolve') else 'NOT up'}"
        f" (pid {unit_pid('resolve')})")


def unit_active(kind="inspect"):
    return run(["systemctl", "--user", "is-active",
                f"{UNIT}-{kind}.service"], check=False).stdout.strip() \
        == "active"


def unit_pid(kind="inspect"):
    return run(["systemctl", "--user", "show", "-p", "MainPID", "--value",
                f"{UNIT}-{kind}.service"], check=False).stdout.strip()


def journal(kind):
    return run(["journalctl", "--user", "-u", f"{UNIT}-{kind}.service",
                "-o", "cat", "--no-pager", "-b"], check=False).stdout


def stop_units():
    for unit in (f"{UNIT}-inspect.service", f"{UNIT}-resolve.service",
                 f"{UNIT}-broker.service"):
        run(["systemctl", "--user", "stop", unit], check=False)
    (UNITS / f"{UNIT}-broker.service").unlink(missing_ok=True)
    run(["systemctl", "--user", "daemon-reload"], check=False)
    run(["systemctl", "--user", "reset-failed"], check=False)


# --- the container -----------------------------------------------------------

def create_container():
    run(["podman", "rm", "-f", CONTAINER], check=False)
    run(["podman", "create", "--name", CONTAINER, "--network", "pasta",
         "--hosts-file", "image",
         "-v", f"{BUNDLE}:{CA_BUNDLE_IN_CONTAINER}:ro,Z",
         "-e", f"SSL_CERT_FILE={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"NODE_EXTRA_CA_CERTS={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"REQUESTS_CA_BUNDLE={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"GIT_SSL_CAINFO={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"PIP_CERT={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"EXAMPLE_API_KEY={PLACEHOLDER}",
         IMAGE, "sleep", "infinity"], timeout=300)
    run(["podman", "init", CONTAINER])
    pid = int(run(["podman", "inspect", "-f", "{{.State.Pid}}",
                   CONTAINER]).stdout.strip())
    resolv = run(["podman", "inspect", "-f", "{{.ResolvConfPath}}",
                  CONTAINER]).stdout.strip()
    dns = next((ln.split()[1] for ln in Path(resolv).read_text().splitlines()
                if ln.startswith("nameserver")), "169.254.1.1")
    say(f"  container created and initialised (pid {pid}, resolver {dns})")
    return pid, dns


def in_netns(pid, argv, **kw):
    return run(["podman", "unshare", "nsenter", "-t", str(pid), "-n",
                *argv], **kw)


def default_route_device():
    return run(["ip", "route", "show", "default"]).stdout.split()[4]


def load_rules(pid, redirect_dns):
    """host_rig's rules with the listeners in the netns: the redirect lands
    443, 80 and 53 on this namespace's loopback, which never crosses the
    egress device, so the egress chain accepts nothing. `redirect_dns`
    false leaves the port-53 lines out, for the `dns` rows to go red."""
    dev = default_route_device()
    dns = (f"    udp dport 53  dnat ip to 127.0.0.1:{RESOLVE_PORT}\n"
           f"    tcp dport 53  dnat ip to 127.0.0.1:{RESOLVE_PORT}\n"
           if redirect_dns else "")
    rules = f"""
table inet moatery {{
  chain out {{
    type nat hook output priority -100
    tcp dport 443 dnat ip to 127.0.0.1:{INSPECT_TLS}
    tcp dport 80  dnat ip to 127.0.0.1:{INSPECT_CLEARTEXT}
{dns}  }}
}}
table netdev moatery {{
  chain egress {{
    type filter hook egress device "{dev}" priority 0; policy drop
    udp dport 443 counter comment "quic"
    counter comment "dropped"
  }}
}}
"""
    in_netns(pid, ["nft", "-f", "-"], input=rules)
    say(f"  rules loaded into the container's netns (egress on {dev})")


def exec_in(argv, timeout=30):
    return run(["podman", "exec", CONTAINER, *argv], check=False,
               timeout=timeout)


def curl_in(url, *extra, timeout=15):
    r = exec_in(["curl", "-s", "-S", "--max-time", str(timeout),
                 "--cacert", CA_BUNDLE_IN_CONTAINER,
                 "-o", "/tmp/body", "-w", "%{http_code}", *extra, url],
                timeout=timeout + 10)
    body = exec_in(["cat", "/tmp/body"]).stdout if r.returncode == 0 else ""
    return r.returncode, r.stdout.strip(), body, r.stderr.strip()


# --- the rows ----------------------------------------------------------------

def records():
    if not RECORD.exists():
        return []
    return riglib.parse_records(RECORD.read_text())


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
FILTERED_UDP = ("192.0.2.1", 9)
# A uid inside the container that is not root, the user outside.
OTHER_UID = 65534

# HTTP/3's port: dropped like port 9, and counted as `quic` first.
QUIC_UDP = ("192.0.2.1", 443)


def chain_counter(pid, comment):
    out = in_netns(pid, ["nft", "list", "chain", "netdev", "moatery",
                         "egress"], check=False).stdout
    for line in out.splitlines():
        if "packets" in line and f'comment "{comment}"' in line:
            fields = line.split()
            return int(fields[fields.index("packets") + 1])
    return -1


def listener_inodes(ipid):
    """The inodes of the inspector's fds 3 and 4, from outside it."""
    out = []
    for fd in (3, 4):
        try:
            link = os.readlink(f"/proc/{ipid}/fd/{fd}")
        except OSError:
            continue
        if link.startswith("socket:["):
            out.append(link[len("socket:["):-1])
    return out


def rows_for(inodes, tables):
    found = set()
    for path in tables:
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) >= 10 and f[9] in inodes:
                found.add(f[9])
    return found


def probe(pid, dns, secret):
    say(f"premise (programs: {LIBEXEC})")
    caps = int(next(ln.split()[1] for ln in
                    Path(f"/proc/{pid}/status").read_text().splitlines()
                    if ln.startswith("CapBnd:")), 16)
    row("premise: no CAP_NET_ADMIN in the container's bounding set",
        not caps & (1 << 12), f"CapBnd={caps:016x}")
    listed = in_netns(pid, ["nft", "list", "tables"], check=False).stdout
    row("premise: the rules are in the container's netns",
        "table inet moatery" in listed, listed.strip() or "no tables")

    say("inspector")
    ipid = unit_pid()
    up = unit_active()
    row("inspector: up on the listeners it was handed", up,
        f"pid {ipid}" if up else
        "not running: " + journal("inspect").strip()[-400:])
    inodes = listener_inodes(ipid) if up else []
    inside = rows_for(inodes, netns_tables(pid))
    outside = rows_for(inodes, PROC_NET_TCP)
    row("inspector: both listeners are in the container's table, "
        "neither in the host's",
        len(inodes) == 2 and inside == set(inodes) and not outside,
        f"inodes {inodes}; in the container's {sorted(inside)}; "
        f"in the host's {sorted(outside)}")

    say("ready")
    for unit, seen in READY.items():
        row(f"ready: the {unit}'s ports were listening in the container "
            "when its unit was reported started", seen and all(seen),
            f"listening: {seen}")

    say("host")
    for port in (INSPECT_TLS, INSPECT_CLEARTEXT):
        where = f"127.0.0.1:{port}"
        own = run(["python3", "-c", CONNECT, where], check=False)
        other = run(["podman", "unshare", "setpriv", "--reuid", "1",
                     "--regid", "1", "--clear-groups",
                     "python3", "-c", CONNECT, where], check=False)
        row(f"host: nothing on the host's {where}, for the user or another "
            "uid",
            own.stdout.strip() == other.stdout.strip()
            == "ConnectionRefusedError",
            f"user: {own.stdout.strip() or own.stderr.strip()}; other uid: "
            f"{other.stdout.strip() or other.stderr.strip()}")

    riglib.dns_rows(
        lambda argv: in_netns(pid, ["python3", "-c", riglib.DNS_LOOKUP,
                                    *argv], check=False).stdout.strip(),
        dns, riglib.ANSWER, RESOLVE_STATUS.read_text)

    say("silent drop")
    sent = in_netns(pid, ["python3", "-c", UDP_SEND, FILTERED_UDP[0],
                          str(FILTERED_UDP[1])], check=False).stdout.strip()
    moved = chain_counter(pid, "dropped")
    row("silent drop: a filtered UDP send returns rc=0, not EPERM",
        sent == "sent" and moved >= 1,
        f"send={sent!r}, dropped counter={moved}")

    say("quic")
    before = chain_counter(pid, "quic")
    sent = in_netns(pid, ["python3", "-c", UDP_SEND, QUIC_UDP[0],
                          str(QUIC_UDP[1])], check=False).stdout.strip()
    counted = chain_counter(pid, "quic")
    dropped = chain_counter(pid, "dropped")
    row("quic: a UDP send to 443 is counted as quic, and dropped",
        sent == "sent" and before == 0 and counted == 1
        and dropped > moved,
        f"send={sent!r}, quic counter {before} -> {counted}, "
        f"dropped counter {moved} -> {dropped}")

    say("request")
    before = journal("broker").count(" ok ")
    rc, code, body, err = curl_in(
        f"https://{PROVIDER}/v1/probe", "-H",
        f"Authorization: Bearer {PLACEHOLDER}", "-D", "/tmp/head")
    arrived = ""
    try:
        arrived = json.loads(body).get("authorization", "")
    except ValueError:
        pass
    row("request: the provider answers 200 through inspector and broker",
        rc == 0 and code == "200", f"curl rc={rc} http={code} {err}")
    row("request: the REAL key arrived at the provider",
        arrived == f"Bearer {secret}",
        "the stub reports the real key" if arrived == f"Bearer {secret}"
        else f"the stub saw {arrived!r}")
    env = exec_in(["env"]).stdout
    row("request: the container's environment holds the placeholder only",
        PLACEHOLDER in env and secret not in env,
        "placeholder present, key absent" if secret not in env
        else "THE KEY IS IN THE CONTAINER")
    after = journal("broker").count(" ok ")
    row("request: the broker's journal logged the request",
        after == before + 1, f"ok lines {before} -> {after}")
    forwarded = [r for r in records() if r.get("host") == PROVIDER]
    hit = next((r for r in forwarded if r.get("decision") == "forward"
                and r.get("credential") == CREDENTIAL
                and r.get("status") == 200), None)
    row("request: the record says forwarded under the credential",
        hit is not None,
        f"{hit}" if hit else f"records for {PROVIDER}: {forwarded}")

    say("another uid")
    sub = run(["podman", "exec", "--user", str(OTHER_UID), CONTAINER,
               "curl", "-s", "-S", "--max-time", "15",
               "--cacert", CA_BUNDLE_IN_CONTAINER, "-o", "/dev/null",
               "-w", "%{http_code}",
               "-H", f"Authorization: Bearer {PLACEHOLDER}",
               f"https://{PROVIDER}/v1/probe"], check=False, timeout=30)
    row(f"another uid: uid {OTHER_UID} inside is served too",
        sub.returncode == 0 and sub.stdout.strip() == "200",
        f"curl rc={sub.returncode} http={sub.stdout.strip()} "
        f"{sub.stderr.strip()}")

    say("broker")
    bpid = run(["systemctl", "--user", "show", "-p", "MainPID", "--value",
                f"{UNIT}-broker.service"]).stdout.strip()
    tcp = [ln for ln in run(["ss", "-lntpH"]).stdout.splitlines()
           if f"pid={bpid}," in ln]
    row("broker: it holds no TCP socket", not tcp,
        "; ".join(ln.split()[3] for ln in tcp) or "none")
    seen = exec_in(["test", "-e", str(BROKER_SOCKET)]).returncode
    row("broker: the container has no path to its socket", seen != 0,
        f"test -e rc={seen}")

    say("unlisted")
    rc, code, body, err = curl_in(f"https://{UNLISTED}/", timeout=10)
    row(f"unlisted: {UNLISTED} gets the inspector's 403 from inside",
        rc == 0 and code == "403",
        f"curl rc={rc} http={code!r} body={body.strip()!r} {err}")
    dropped = [r for r in records() if r.get("host") == UNLISTED]
    hit = next((r for r in dropped if r.get("decision") == "drop"
                and r.get("reason") == DROP_NOT_ALLOWLISTED
                and r.get("upstream") is None), None)
    row("unlisted: the record says dropped, 'not allowlisted', no upstream",
        hit is not None, f"{hit}" if hit else f"records: {dropped}")

    riglib.origin_rows(secret)

    say("counters (waiting for the inspector's next status write)")
    status = riglib.await_status(STATUS.read_text, after=time.time())
    if status is None:
        row("counters: the inspector wrote its status", False,
            f"{STATUS} not updated within 40 s")
    else:
        unresolved = status.get("caller_unresolved")
        row("counters: every connection's caller was named",
            unresolved == 0, f"caller_unresolved={unresolved}")
        foreign = status.get("drop_reasons", {}).get(DROP_FOREIGN_CALLER)
        row("counters: nothing was dropped as a foreign caller",
            foreign == 0, f"{DROP_FOREIGN_CALLER!r}: {foreign}")


# --- teardown ----------------------------------------------------------------

def teardown(keep):
    say("teardown")
    if not keep:
        run(["podman", "rm", "-f", CONTAINER], check=False)
    stop_units()
    riglib.stop_children()
    riglib.restore_privileged_ports()
    riglib.remove_hosts_entry()


# --- main --------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="leave the container for inspection")
    ap.add_argument("--without-rules", action="store_true",
                    help="skip the netns rules; premise, dns, silent, "
                         "request and unlisted must go red")
    ap.add_argument("--without-dns-redirect", action="store_true",
                    help="leave port 53 out of the redirect; dns, request "
                         "and unlisted must go red")
    ap.add_argument("--without-netns-pid", action="store_true",
                    help="start the inspector without --netns-pid; it must "
                         "refuse, and inspector, request, unlisted and "
                         "counters go red")
    ap.add_argument("--without-notify", action="store_true",
                    help="start the listener units as Type=simple; ready "
                         "must go red")
    args = ap.parse_args()

    riglib.preflight(
        ("podman", "pasta", "nft", "openssl", "curl", "ss", "systemctl",
         "systemd-run", "systemd-creds", "nsenter", "setpriv"),
        (INSPECT_TLS, INSPECT_CLEARTEXT, RESOLVE_PORT, riglib.PROVIDER_PORT))
    state = run(["systemctl", "--user", "is-system-running"],
                check=False).stdout.strip()
    if state not in ("running", "degraded"):
        sys.exit(f"user manager is {state or 'absent'}; log in with a "
                 "session (ssh is one)")
    RIG.mkdir(parents=True, exist_ok=True)
    for stale in (STATUS, RECORD, Path(f"{STATUS}.tmp"), RESOLVE_STATUS):
        stale.unlink(missing_ok=True)
    secret = "sk-real-" + os.urandom(12).hex()

    say("material")
    riglib.mint_ca(STATE)
    riglib.write_bundle(ca_cert_path(STATE).read_text(), BUNDLE)
    riglib.make_stub_cert()
    riglib.write_policy(POLICY)
    seal_credential(secret)
    try:
        say("host side")
        riglib.lower_privileged_ports()
        riglib.write_hosts_entry(HOSTS_MARK)
        riglib.start_stub(secret)
        start_broker()
        say("container")
        pid, dns = create_container()
        if args.without_rules:
            say("  rules NOT loaded, as asked")
        else:
            load_rules(pid, not args.without_dns_redirect)
        start_inspector(pid, not args.without_netns_pid,
                        not args.without_notify)
        start_responder(pid, not args.without_notify)
        run(["podman", "start", CONTAINER])
        probe(pid, dns, secret)
    finally:
        teardown(args.keep)

    expected = [note for flag, note in (
        (args.without_rules, "--without-rules: premise, dns, silent, request "
                             "and unlisted are expected red"),
        (args.without_dns_redirect,
         "--without-dns-redirect: dns, request and unlisted are expected "
         "red"),
        (args.without_netns_pid, "--without-netns-pid: inspector, "
                                 "request, unlisted and counters are "
                                 "expected red"),
        (args.without_notify, "--without-notify: ready is expected red"),
    ) if flag]
    rc = riglib.report("; ".join(expected) or None)
    if rc:
        say(f"journal: journalctl --user -u {UNIT}-inspect.service"
            f" -u {UNIT}-broker.service -u {UNIT}-resolve.service -b")
    return rc


if __name__ == "__main__":
    sys.exit(main())
