#!/usr/bin/env python3
"""host_rig.py — does moatery work with nothing but a normal user?

"Host" in docs/DESIGN.md, as it stands: one rootless podman container
under pasta, the programs as hand-written user units, the nft rules
loaded into the container's netns, a placeholder in the container's
environment, and one real request that reaches the provider carrying the
sealed key. Run on the proving host as an ordinary user, from a checkout:

    python3 tests/manual/host_rig.py [--keep] [--without-rules]
                                       [--without-neighbour-discovery]
                                       [--without-dns-redirect]
                                       [--broker-over-tcp]

Nothing here needs root except two host facts the rig cannot fake and
undoes at teardown: a line in /etc/hosts pointing the provider's name at
the stub, and `net.ipv4.ip_unprivileged_port_start` lowered so the stub can
bind :443. Both programs dial their upstream at 443 with no override --
deliberately, so a policy-matched host cannot be steered to another port
on the way out -- so the provider has to answer there.

THE ROWS

  premise   the container's bounding set holds no CAP_NET_ADMIN; the rules
            are in its netns. Without the first, the second is a suggestion.
  dns       the workload's queries, to its resolver over UDP and TCP and to
            any other nameserver, are answered by moat-resolve with the
            loopback map, for names nothing resolves; an AAAA gets no
            records; the responder's status names the unlisted names and
            not the provider's. The container has no --add-host, so every
            request row below also resolved its name here.
  silent    a filtered UDP send returns rc=0 while the egress chain's drop
            counter moves. The drop is a netdev egress hook, not an output
            filter: an output `policy drop` fails the send with EPERM, a
            tell no real network gives. The counter proves the packet was
            dropped, not delivered.
  quic      a UDP send to 443, HTTP/3's port, moves the egress chain's
            `quic` counter, which the silent row's port-9 send left at
            zero, and the drop counter with it.
  h2        from inside, curl offering h2 is served over HTTP/1.1 and
            answered 200; one opening with HTTP/2's preface on the
            cleartext plane is answered 400 and leaves an `h2 preface`
            note; an HTTPS query gets no records, a responder line and a
            count under `https`.
  request   from inside, with the placeholder, the provider answers 200 and
            reports that the REAL key arrived; the container's environment
            holds only the placeholder; the inspector's record names the
            request as forwarded under the credential, and its counters
            show it named the caller (SO_ORIGINAL_DST on a host socket whose
            DNAT happened a namespace away must fall back cleanly).
  neighbour with the container's neighbour table flushed, the request is
            served again: its dial to the loopback map has to resolve the
            gateway afresh, and the egress chain sees that ARP. The flush
            stands in for the entry ageing out, which otherwise fails a
            dial only when an idle gap happens to outlast it.
  broker    the broker holds no TCP socket, only a path under the user's
            runtime directory, which the container has no path to. From
            the host, another uid's connect to it is refused by the kernel
            (EACCES), where the user's own connects. The other uid is one
            of the user's subuids, through `podman unshare setpriv`.
  unlisted  from inside, a host the policy does not name is refused by the
            inspector and the record says why.
  no key    from the host, the placeholder alone gets 401 from the origin;
            the real key gets 200. The second half is the control that the
            stub distinguishes at all.

`--without-rules` skips loading the netns rules and changes nothing else.
The `premise`, `dns`, `silent`, `quic`, `h2`, `request`, `neighbour`,
`unlisted` and `counters` rows must go red -- the inspector is never even
activated, and with no egress chain the counters are absent -- and a run
where they stay green is measuring nothing. `--without-dns-redirect` leaves the
port-53 lines out of the redirect: the queries go to pasta's forwarder,
which the egress chain drops, and `dns`, `h2`, `request`, `neighbour`,
`unlisted` and `counters` must go red.
`--broker-over-tcp` puts the broker on 127.129.0.1:8081 instead of the
socket path, and the broker's no-TCP and other-uid rows must go red.
`--without-neighbour-discovery` loads the egress chain without its ARP
and neighbour-discovery lines; `neighbour` and `unlisted` must go red.

WHAT THIS RIG TELLS THE DESIGN

Three of DESIGN.md's host-placement facts were not facts on this host and the
recipe here is what worked:

  - podman starts pasta with `--no-map-gw`. The gateway does NOT map to the
    host's loopback; the mapping has to be asked for, and asking for a
    dedicated address (`--network pasta:--map-host-loopback=169.254.1.3`)
    reads better than borrowing the gateway.
  - the container's resolver is pasta's forwarder at 169.254.1.1 (its
    `--dns-forward`), not the gateway, followed by the host's own
    nameservers. The redirect catches port 53 whatever the address.
  - the inspector recognises exactly the ports 8080 and 8443 as its planes
    (moatery/egress_plane.py). "Each container gets its own inspector port" is
    not something the program supports; one container per host loopback.
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
    INSPECT_TLS, LIBEXEC, LOOPBACK_MAP, NAME, PLACEHOLDER, PROGRAM_ENV,
    PROVIDER, RESOLVE_PORT, RIG, STUB_CERT, UNLISTED, row, run, say,
)
from moatery.egress_ca import ca_cert_path  # noqa
from moatery.egress_record import (  # noqa
    DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED, DROP_UNREADABLE_REQUEST,
    NOTE_H2_PREFACE,
)

BROKER_ADDR = "127.129.0.1"
BROKER_PORT = 8081
CONTAINER = "moatery-rig"
UNIT = "moatery-rig"
BROKER_SOCKET = Path(os.environ.get("XDG_RUNTIME_DIR",
                                    f"/run/user/{os.getuid()}"),
                     UNIT, "broker.sock")
HOSTS_MARK = "moatery-host-rig"

UNITS = riglib.HOME / ".config" / "systemd" / "user"
STATE = RIG / "state"
POLICY = RIG / "inspect.json"
STATUS = RIG / "inspect-status.json"
RESOLVE_STATUS = RIG / "resolve-status.json"
RECORD = RIG / "egress.jsonl"
BUNDLE = RIG / "bundle.pem"
CRED = RIG / f"{CREDENTIAL}.cred"


# --- the host side: units ----------------------------------------------------

def seal_credential(secret):
    """`systemd-creds --user encrypt`: sealed to this user on this host,
    which is what LoadCredentialEncrypted= in a user unit can open."""
    run(["systemd-creds", "--user", "encrypt", f"--name={CREDENTIAL}",
         "-", str(CRED)], input=secret + "\n")
    CRED.chmod(0o600)


def write_units(over_tcp):
    """Hand-written, which is the point: no generator between the operator
    and the two ExecStart= lines. PYTHONPATH when the programs are the
    checkout's; installed, the package is in site-packages.
    SSL_CERT_FILE hands both units the stub's certificate and REPLACES
    their trust store, which is fine only because neither dials anything
    but the stub here -- it is a rig fact, not a recipe."""
    UNITS.mkdir(parents=True, exist_ok=True)
    py = sys.executable
    path = "".join(f"Environment={k}={v}\n" for k, v in PROGRAM_ENV.items())
    env = path + f"Environment=SSL_CERT_FILE={STUB_CERT}\n"
    endpoint = (f"{BROKER_ADDR}:{BROKER_PORT}" if over_tcp
                else f"unix:%t/{UNIT}/broker.sock")
    (UNITS / f"{UNIT}-broker.service").write_text(
        "# written by tests/manual/host_rig.py — removed at teardown\n"
        "[Service]\n"
        f"ExecStart={py} {LIBEXEC / 'moat-broker'}"
        f" --name {NAME} --listen {endpoint}"
        f" --caller-uid {os.getuid()}"
        f" --host {PROVIDER}={CREDENTIAL}"
        f" --placeholder {CREDENTIAL}={PLACEHOLDER}"
        f" --auth-header {CREDENTIAL}=Authorization"
        f" \"--auth-format={CREDENTIAL}=Bearer {{secret}}\"\n"
        f"LoadCredentialEncrypted={CREDENTIAL}:{CRED}\n"
        f"RuntimeDirectory={UNIT}\n"
        "RuntimeDirectoryMode=0700\n"
        + env)
    (UNITS / f"{UNIT}-inspect.socket").write_text(
        "# written by tests/manual/host_rig.py — removed at teardown\n"
        "[Socket]\n"
        f"ListenStream=127.0.0.1:{INSPECT_TLS}\n"
        f"ListenStream=127.0.0.1:{INSPECT_CLEARTEXT}\n")
    (UNITS / f"{UNIT}-inspect.service").write_text(
        "# written by tests/manual/host_rig.py — removed at teardown\n"
        "[Service]\n"
        f"ExecStart={py} {LIBEXEC / 'moat-inspect'}"
        f" --name {NAME} --policy {POLICY} --state-dir {STATE}"
        f" --status {STATUS} --record {RECORD}"
        f" --broker {endpoint}\n"
        + env)
    (UNITS / f"{UNIT}-resolve.socket").write_text(
        "# written by tests/manual/host_rig.py — removed at teardown\n"
        "[Socket]\n"
        f"ListenDatagram=127.0.0.1:{RESOLVE_PORT}\n"
        f"ListenStream=127.0.0.1:{RESOLVE_PORT}\n")
    (UNITS / f"{UNIT}-resolve.service").write_text(
        "# written by tests/manual/host_rig.py — removed at teardown\n"
        "[Service]\n"
        f"ExecStart={py} {LIBEXEC / 'moat-resolve'}"
        f" --name {NAME} --address {LOOPBACK_MAP} --policy {POLICY}"
        f" --status {RESOLVE_STATUS}\n"
        + path)
    run(["systemctl", "--user", "daemon-reload"])


def broker_pid():
    return run(["systemctl", "--user", "show", "-p", "MainPID", "--value",
                f"{UNIT}-broker.service"]).stdout.strip()


def start_units(over_tcp):
    run(["systemctl", "--user", "start", f"{UNIT}-broker.service"])
    pid = broker_pid()
    where = (f"{BROKER_ADDR}:{BROKER_PORT}" if over_tcp
             else str(BROKER_SOCKET))
    for _ in range(50):
        held = run(["ss", "-lntpH" if over_tcp else "-lxpH"]).stdout
        if any(where in ln and f"pid={pid}," in ln
               for ln in held.splitlines()):
            break
        if run(["systemctl", "--user", "is-active", f"{UNIT}-broker.service"],
               check=False).stdout.strip() != "active":
            sys.exit("broker did not stay up:\n" + journal("broker"))
        time.sleep(0.2)
    else:
        sys.exit(f"broker (pid {pid}) never listened on {where}")
    say(f"  broker listening on {where} (pid {pid})")
    run(["systemctl", "--user", "start", f"{UNIT}-inspect.socket"])
    held = run(["ss", "-lntH", f"sport = :{INSPECT_TLS}"]).stdout
    if not held.strip():
        sys.exit(f"the socket unit is up but nothing holds :{INSPECT_TLS}")
    say(f"  inspector socket bound on 127.0.0.1:{INSPECT_TLS},"
        f" :{INSPECT_CLEARTEXT}")
    run(["systemctl", "--user", "start", f"{UNIT}-resolve.socket"])
    held = run(["ss", "-lnuH", f"sport = :{RESOLVE_PORT}"]).stdout
    if not held.strip():
        sys.exit(f"the responder's socket unit is up but nothing holds "
                 f"udp :{RESOLVE_PORT}")
    say(f"  responder socket bound on 127.0.0.1:{RESOLVE_PORT}, UDP and TCP")


def journal(kind):
    return run(["journalctl", "--user", "-u", f"{UNIT}-{kind}.service",
                "-o", "cat", "--no-pager", "-b"], check=False).stdout


UNIT_FILES = ("inspect.socket", "inspect.service", "resolve.socket",
              "resolve.service", "broker.service")


def stop_units():
    for unit in UNIT_FILES:
        run(["systemctl", "--user", "stop", f"{UNIT}-{unit}"], check=False)
    for unit in UNIT_FILES:
        (UNITS / f"{UNIT}-{unit}").unlink(missing_ok=True)
    run(["systemctl", "--user", "daemon-reload"], check=False)
    run(["systemctl", "--user", "reset-failed"], check=False)


# --- the container -----------------------------------------------------------

def create_container():
    run(["podman", "rm", "-f", CONTAINER], check=False)
    run(["podman", "create", "--name", CONTAINER,
         "--network", f"pasta:--map-host-loopback={LOOPBACK_MAP}",
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
    """The host's default-route interface, whose name pasta mirrors into the
    netns as the device egress leaves by."""
    return run(["ip", "route", "show", "default"]).stdout.split()[4]


def load_rules(pid, neighbour, redirect_dns):
    """What replaces `meta skuid`: the rules see only this netns's traffic.
    nat output runs before the egress hook, so the accept lines name the
    translated ports, not 80, 443 and 53.

    The drop is a netdev egress hook, not an output filter. An output
    `policy drop` fails a UDP send with EPERM, which no real network does;
    the egress hook drops the packet after send() has returned and counts
    it. It hangs on the pasta device, so loopback never crosses it and no
    `oif lo accept` is needed.

    `neighbour` false leaves out the ARP and neighbour-discovery lines,
    for the `neighbour` row to go red; `redirect_dns` false the port-53
    lines, for the `dns` rows to."""
    dev = default_route_device()
    in_netns(pid, ["nft", "-f", "-"],
             input=ruleset(dev, neighbour=neighbour,
                           redirect_dns=redirect_dns))
    say(f"  rules loaded into the container's netns (egress on {dev})")


def ruleset(dev, *, neighbour=True, redirect_dns=True):
    """The rules load_rules loads: docs/DESIGN.md's "Host" ruleset
    with every keyword at its default (tests/test_rig_rules.py)."""
    ports = f"{{ {INSPECT_TLS}, {INSPECT_CLEARTEXT}, {RESOLVE_PORT} }}"
    nd = riglib.NEIGHBOUR_DISCOVERY if neighbour else ""
    dns = (f"    udp dport 53  dnat ip to {LOOPBACK_MAP}:{RESOLVE_PORT}\n"
           f"    tcp dport 53  dnat ip to {LOOPBACK_MAP}:{RESOLVE_PORT}\n"
           if redirect_dns else "")
    return f"""
table inet moatery {{
  chain out {{
    type nat hook output priority -100
    tcp dport 443 dnat ip to {LOOPBACK_MAP}:{INSPECT_TLS}
    tcp dport 80  dnat ip to {LOOPBACK_MAP}:{INSPECT_CLEARTEXT}
{dns}  }}
}}
table netdev moatery {{
  chain egress {{
    type filter hook egress device "{dev}" priority 0; policy drop
{nd}    ip daddr {LOOPBACK_MAP} tcp dport {ports} accept
    ip daddr {LOOPBACK_MAP} udp dport {RESOLVE_PORT} accept
    udp dport 443 counter comment "quic"
    counter comment "dropped"
  }}
}}
"""


def exec_in(argv, timeout=30):
    return run(["podman", "exec", CONTAINER, *argv], check=False,
               timeout=timeout)


def curl_in(url, *extra, timeout=15):
    """curl from inside: (exit status, http status or '', body)."""
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


# Prints "connected" or the exception's class, so a missing interpreter
# or a typo is not read as a refusal.
CONNECT = """
import socket, sys
where = sys.argv[1]
if where.startswith("/"):
    s = socket.socket(socket.AF_UNIX)
else:
    host, port = where.rsplit(":", 1)
    s, where = socket.socket(), (host, int(port))
try:
    s.connect(where)
except OSError as exc:
    print(type(exc).__name__)
else:
    print("connected")
"""


# One UDP datagram, reporting send() outcome only: "sent" or the OSError
# class. A netdev egress drop returns "sent"; an output-hook drop, EPERM.
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

# TEST-NET-1: never routed, and named by no accept line, so a packet to it
# falls to the egress chain's drop. Not port 53, which the redirect takes.
FILTERED_UDP = ("192.0.2.1", 9)
# HTTP/3's port: dropped like port 9, and counted as `quic` first.
QUIC_UDP = ("192.0.2.1", 443)


def chain_counter(pid, comment):
    """The egress chain's counter with this comment, in packets, or -1 if
    the chain is absent (as under --without-rules)."""
    out = in_netns(pid, ["nft", "list", "chain", "netdev", "moatery",
                         "egress"], check=False).stdout
    for line in out.splitlines():
        if "packets" in line and f'comment "{comment}"' in line:
            fields = line.split()
            return int(fields[fields.index("packets") + 1])
    return -1


def h2_rows(pid, dns):
    """HTTP/2 is refused without refusing its client: one that offers h2
    is served HTTP/1.1, and what cannot be served is reported."""
    say("h2")
    rc, got, _, err = curl_in(
        f"https://{PROVIDER}/v1/probe", "--http2", "-H",
        f"Authorization: Bearer {PLACEHOLDER}",
        "-w", "%{http_code} %{http_version}")
    row("h2: a client offering h2 is served, over HTTP/1.1",
        rc == 0 and got == "200 1.1", f"curl rc={rc} got={got!r} {err}")
    # curl cannot read the HTTP/1.1 answer as the SETTINGS frame it
    # expects, so the 400 is the record's to report.
    before = journal("inspect").count(f"reason=\"{NOTE_H2_PREFACE}:")
    seen = len(records())
    rc, _, _, err = curl_in(f"http://{PROVIDER}/", "--http2-prior-knowledge")
    after = journal("inspect").count(f"reason=\"{NOTE_H2_PREFACE}:")
    refused = [r for r in records()[seen:] if r.get("plane") == "cleartext"]
    row("h2: HTTP/2's preface is answered 400, and noted",
        [(r.get("reason"), r.get("status")) for r in refused]
        == [(DROP_UNREADABLE_REQUEST, 400)] and after == before + 1,
        f"curl rc={rc} {err}; records {refused}; "
        f"{NOTE_H2_PREFACE} notes {before} -> {after}")
    # A fresh name nothing resolves: the provider's is in the host's hosts
    # file, which pasta's forwarder answers with nodata too, and last
    # run's line for it is still in the journal.
    name = f"h2-{os.urandom(4).hex()}.exfil.test"
    asked = time.time()
    got = in_netns(pid, ["python3", "-c", riglib.DNS_LOOKUP, dns,
                         name, "HTTPS", "udp"], check=False)
    row("h2: an HTTPS query gets no records",
        got.stdout.strip() == "nodata",
        got.stdout.strip() or got.stderr.strip())
    line = f"  {name} HTTPS -> nodata"
    row("h2: the responder logged it",
        line in journal("resolve").splitlines(), repr(line))
    status = riglib.await_status(RESOLVE_STATUS.read_text, asked)
    https = None if status is None else status.get("https")
    row("h2: the responder counted it under https",
        https is not None and https >= 1, f"https={https}")


def probe(pid, dns, secret, over_tcp):
    say(f"premise (programs: {LIBEXEC})")
    caps = int(next(ln.split()[1] for ln in
                    Path(f"/proc/{pid}/status").read_text().splitlines()
                    if ln.startswith("CapBnd:")), 16)
    net_admin = bool(caps & (1 << 12))
    row("premise: no CAP_NET_ADMIN in the container's bounding set",
        not net_admin, f"CapBnd={caps:016x}")
    listed = in_netns(pid, ["nft", "list", "tables"], check=False).stdout
    row("premise: the rules are in the container's netns",
        "table inet moatery" in listed,
        listed.strip() or "no tables")

    riglib.dns_rows(
        lambda argv: in_netns(pid, ["python3", "-c", riglib.DNS_LOOKUP,
                                    *argv], check=False).stdout.strip(),
        dns, LOOPBACK_MAP, RESOLVE_STATUS.read_text)

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

    h2_rows(pid, dns)

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
    head = exec_in(["cat", "/tmp/head"]).stdout
    server = next((ln.strip() for ln in head.splitlines()
                   if ln.lower().startswith("server:")), "no Server")
    row("request: the response names the provider's server, not a broker",
        server == f"Server: {riglib.STUB_SERVER}"
        and "moatery" not in head.lower(), server)
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

    say("neighbour")
    dev = default_route_device()
    in_netns(pid, ["ip", "neigh", "flush", "dev", dev])
    rc, code, _, err = curl_in(
        f"https://{PROVIDER}/v1/probe", "-H",
        f"Authorization: Bearer {PLACEHOLDER}")
    learned = in_netns(pid, ["ip", "neigh", "show", "dev", dev],
                       check=False).stdout.strip()
    row("neighbour: with the neighbour table flushed, the provider answers",
        rc == 0 and code == "200",
        f"curl rc={rc} http={code} {err}; neighbours: "
        f"{learned or 'none'}")

    say("broker")
    pid = broker_pid()
    tcp = [ln for ln in run(["ss", "-lntpH"]).stdout.splitlines()
           if f"pid={pid}," in ln]
    row("broker: it holds no TCP socket", not tcp,
        "; ".join(ln.split()[3] for ln in tcp) or "none")
    where = (f"{BROKER_ADDR}:{BROKER_PORT}" if over_tcp
             else str(BROKER_SOCKET))
    own = run(["python3", "-c", CONNECT, where], check=False)
    row("broker: the user connects to it (the control)",
        own.stdout.strip() == "connected",
        own.stdout.strip() or own.stderr.strip())
    other = run(["podman", "unshare", "setpriv", "--reuid", "1",
                 "--regid", "1", "--clear-groups",
                 "python3", "-c", CONNECT, where], check=False)
    row("broker: another uid on the host is refused by the kernel",
        other.stdout.strip() == "PermissionError",
        other.stdout.strip() or other.stderr.strip())
    seen = exec_in(["test", "-e", str(BROKER_SOCKET)]).returncode
    row("broker: the container has no path to its socket", seen != 0,
        f"test -e rc={seen}")

    say("unlisted")
    # Under `tls = "inspect"` the refusal is a real 403 from the inspector,
    # under a leaf its own CA minted for the refused name -- not a closed
    # connection. The body says only "Forbidden"; the reason is the record's
    # and the journal's. The record's `upstream` being null is what says the
    # origin was never dialled: the status code alone would also fit an
    # origin that answered 403 itself.
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
        prefaces = status.get("notes", {}).get(NOTE_H2_PREFACE)
        row("counters: the h2 preface was counted as a note",
            prefaces == 1, f"notes={status.get('notes')}")


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
                         "request, neighbour, unlisted and counters must go "
                         "red")
    ap.add_argument("--without-neighbour-discovery", action="store_true",
                    help="leave ARP and neighbour discovery out of the "
                         "egress chain; neighbour and unlisted must go red")
    ap.add_argument("--without-dns-redirect", action="store_true",
                    help="leave port 53 out of the redirect; dns, request, "
                         "neighbour, unlisted and counters must go red")
    ap.add_argument("--broker-over-tcp", action="store_true",
                    help="the broker on 127.129.0.1:8081; its no-TCP and "
                         "other-uid rows must go red")
    args = ap.parse_args()

    riglib.preflight(
        ("podman", "pasta", "nft", "openssl", "curl", "ss", "systemctl",
         "systemd-creds", "nsenter", "setpriv"),
        (INSPECT_TLS, INSPECT_CLEARTEXT, RESOLVE_PORT, BROKER_PORT,
         riglib.PROVIDER_PORT))
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
        write_units(args.broker_over_tcp)
        start_units(args.broker_over_tcp)
        say("container")
        pid, dns = create_container()
        if args.without_rules:
            say("  rules NOT loaded, as asked")
        else:
            load_rules(pid, not args.without_neighbour_discovery,
                       not args.without_dns_redirect)
        run(["podman", "start", CONTAINER])
        probe(pid, dns, secret, args.broker_over_tcp)
    finally:
        teardown(args.keep)

    expected = [note for flag, note in (
        (args.without_rules, "--without-rules: premise, dns, silent, "
                             "request, neighbour, unlisted and counters are "
                             "expected red"),
        (args.without_dns_redirect,
         "--without-dns-redirect: dns, request, neighbour, unlisted and "
         "counters are expected red"),
        (args.without_neighbour_discovery,
         "--without-neighbour-discovery: neighbour and unlisted are "
         "expected red"),
        (args.broker_over_tcp, "--broker-over-tcp: the broker's no-TCP and "
                               "other-uid rows are expected red"),
    ) if flag]
    rc = riglib.report("; ".join(expected) or None)
    if rc:
        say(f"journal: journalctl --user -u {UNIT}-inspect.service"
            f" -u {UNIT}-broker.service -u {UNIT}-resolve.service -b")
    return rc


if __name__ == "__main__":
    sys.exit(main())
