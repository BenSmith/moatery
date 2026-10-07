#!/usr/bin/env python3
"""sidecar_rig.py — does moatery work as a sidecar, with no host install?

"Sidecar" in docs/DESIGN.md: a podman pod under pasta, the sidecar image
(the programs, one container, two uids) beside a workload container, the
nft rules loaded into the pod's netns keyed on `meta skuid`, the broker on
a socket path the workload has no mount for, the key mounted as a podman
secret, and one real request that reaches the provider carrying it. Run
on the proving host as an ordinary user, from a checkout:

    python3 tests/manual/sidecar_rig.py [--keep] [--without-rules]
                                        [--without-neighbour-discovery]
                                        [--without-dns-redirect]
                                        [--without-private-drop]
                                        [--shared-label]
                                        [--no-build]

The same two host facts as host_rig need sudo and are undone at teardown.
The image is built from the checkout on every run unless --no-build.

THE ROWS

  premise   the workload's bounding set holds neither CAP_NET_ADMIN nor
            CAP_SETUID -- the second because the uid is the selector, and
            a workload that could become the sidecar's uid would be
            exempt from its own redirect; the rules are in the pod's
            netns; the sidecar's programs run as the two image uids, the
            responder as the inspector's, and its pid 1, which supervises
            them, holds no capability.
  label     the sidecar runs at an SELinux level of its own, not the
            workload's, the pod's; its policy, its secret and the CA key
            in its volume are labelled at it. A container at the
            workload's level, as the inspector's uid and mounting the
            volume without relabelling it, is refused the key, which
            one at the sidecar's level reads.
  dns       the workload's queries, to its resolver over UDP and TCP and to
            any other nameserver, are answered by the sidecar's
            moat-resolve with the pod's loopback, for names nothing
            resolves; an AAAA gets no records; the responder's status names
            the unlisted names and not the provider's. The unlisted row
            below also resolved its name here; the provider's name is in
            the pod's hosts file, which the sidecar's dials need.
  silent    a filtered UDP send returns rc=0 while the egress chain's drop
            counter moves. The drop is a netdev egress hook, not an output
            filter: an output `policy drop` fails the send with EPERM, a
            tell no real network gives.
  quic      a UDP send to 443, HTTP/3's port, moves the egress chain's
            `quic` counter, which the silent row's port-9 send left at
            zero, and the drop counter with it.
  request   from the workload, with the placeholder, the provider answers
            200 and reports that the REAL key arrived; the workload's
            environment holds the placeholder only; the broker logged one
            request; the record says forwarded under the credential.
  neighbour with the pod's neighbour table flushed, the request is served
            again: the programs' dial has to resolve the gateway afresh,
            and the egress chain sees that ARP. The flush stands in for
            the entry ageing out, which otherwise fails a dial only when
            an idle gap happens to outlast it.
  broker    from the workload, connect() to the broker's socket path is
            ENOENT -- not ECONNREFUSED, which would mean the path exists
            and the mount is shared. Nothing but the inspector's two
            planes and the responder's port listens on TCP in the pod, so
            there is no address to spell. The broker's log did not grow.
  unlisted  from the workload, a host the policy does not name gets the
            inspector's 403 and the record says why, with no upstream.
  private   the programs' dials into private space are dropped unless an
            accept line names the address. The provider is on the
            loopback map, link-local, so it has one; that line is
            deleted, the workload's request must not reach the stub (its
            log does not grow) while the private-drop counter moves, and
            with the line back the same request arrives. The programs'
            own DNS query to the resolver, also link-local, is answered.
  no key    from the host, the placeholder alone gets 401 from the origin;
            the real key gets 200.
  counters  every caller was named (the DNAT is in the same netns now, so
            SO_ORIGINAL_DST answers rather than falling back), and none
            was dropped as foreign: the inspector was told the workload's
            uid, and the workload IS another uid here.
  lifecycle the broker killed from outside takes the container down,
            non-zero, and the restart policy brings it back on the same
            volume: the restart count rose and the workload's request is
            served again under the CA its bundle holds. Then a stop
            reaches every program well inside podman's timeout, and the
            container exits 0.

`--without-rules` loads no rules into the pod's netns. `premise`, `dns`,
`silent`, `quic`, `request`, `neighbour`, `unlisted`, `private` and
the lifecycle's request must go red: the workload's dial reaches the stub
directly and refuses its certificate, which no bundle of the workload's
carries, pasta's forwarder answers the names and does not know the
unlisted one, and with no egress chain the counters are absent.
`--without-dns-redirect` leaves the port-53 lines out of the redirect;
the workload's queries go to pasta's forwarder, whose accept lines are
the programs' alone, and `dns` and `unlisted` must go red.
`--without-neighbour-discovery` loads the egress chain without its ARP
and neighbour-discovery lines; `neighbour` and the lifecycle's request
must go red. `--without-private-drop` leaves out the private-space drop
and its accept line: the request with the line deleted arrives, so
`private` goes red. `--shared-label` runs the sidecar at the pod's
level, its volume unlabelled: both `label` rows must go red.
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
    CA_BUNDLE_IN_CONTAINER, CHECKOUT, CREDENTIAL, IMAGE, INSPECT_CLEARTEXT,
    INSPECT_TLS, LOOPBACK_MAP, NAME, PLACEHOLDER, PROVIDER, RESOLVE_PORT,
    RIG, STUB_CERT, UNLISTED, row, run, say,
)
from moatery.egress_ca import ca_key_path  # noqa
from moatery.egress_record import DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED  # noqa

POD = "moatery-rig-pod"
SIDECAR = "moatery-rig-sidecar"
WORKLOAD = "moatery-rig-workload"
SIDECAR_IMAGE = "localhost/moat-sidecar:rig"
SECRET = "moatery-rig-example"
VOLUME = "moatery-rig-state"
HOSTS_MARK = "moat-sidecar-rig"
# The image's two uids and their group (container/Containerfile), and the
# workload's: any uid that is neither, chosen here.
INSPECT_UID, BROKER_UID, GROUP_GID = 200, 201, 200
WORKLOAD_UID = 1000
# The mark the output hook puts on the programs' connections, and so on
# their packets, for the egress hook to exempt. One bit in an otherwise
# unused netns; no other consumer.
OURS_MARK = "0x1"
# Inside the sidecar (container/moat-sidecar).
SOCKET_PATH = "/run/moatery/broker.sock"
STATE_IN_SIDECAR = "/var/lib/moatery"
POLICY_IN_SIDECAR = "/etc/moatery/policy.json"
UPSTREAM_CA_IN_SIDECAR = "/etc/moatery/upstream-ca.pem"
# The sidecar's SELinux level, the rig's choice: the workload's is the
# pod's, which podman draws from the same pairs of categories, and one
# drawn equal to this is a 1 in 523776.
SIDECAR_LEVEL = "s0:c1022,c1023"

# The drop set docs/DESIGN.md gives for the programs' dials.
PRIVATE_V4 = ("0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, "
              "169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16")
PRIVATE_V6 = "::1, fc00::/7, fe80::/10"
# The provider's accept line: the stub is reached at the loopback map.
INTERNAL_ACCEPT = (f"meta mark {OURS_MARK} ip daddr {LOOPBACK_MAP} "
                   f"tcp dport {riglib.PROVIDER_PORT} accept")

POLICY = RIG / "sidecar-policy.json"
BUNDLE = RIG / "sidecar-bundle.pem"
BUILD_LOG = RIG / "build.log"


# --- the image and the secret ------------------------------------------------

def build_image():
    say(f"  building {SIDECAR_IMAGE} (log: {BUILD_LOG})")
    with open(BUILD_LOG, "w") as log:
        r = run(["podman", "build", "-t", SIDECAR_IMAGE,
                 "-f", str(CHECKOUT / "container" / "Containerfile"),
                 str(CHECKOUT)], check=False, timeout=600,
                stdout=log, stderr=log, capture_output=False)
    if r.returncode != 0:
        sys.exit(f"image build failed; see {BUILD_LOG}")
    say("  built")


def create_secret(secret):
    run(["podman", "secret", "rm", SECRET], check=False)
    run(["podman", "secret", "create", SECRET, "-"], input=secret)


# --- the pod -----------------------------------------------------------------

def remove_pod():
    run(["podman", "pod", "rm", "-f", POD], check=False)
    run(["podman", "volume", "rm", "-f", VOLUME], check=False)


def create_pod():
    """The provider's name resolves to the loopback-mapped address so the
    sidecar's dials reach the stub on the host. The hosts file is the
    pod's, so the workload reads it too, and its dial to that address is
    what the redirect catches."""
    run(["podman", "pod", "create", "--name", POD,
         "--network", f"pasta:--map-host-loopback={LOOPBACK_MAP}",
         "--hosts-file", "image", "--share-parent=false",
         "--add-host", f"{PROVIDER}:{LOOPBACK_MAP}"])


def start_sidecar(shared_label=False):
    """At a level of its own, which its files are labelled at, unless
    `shared_label`: the pod's, the volume unlabelled."""
    label = [] if shared_label else [
        "--security-opt", f"label=level:{SIDECAR_LEVEL}"]
    run(["podman", "create", "--pod", POD, "--name", SIDECAR,
         "--restart", "on-failure",
         "--cap-drop", "all",
         "--cap-add", "chown,dac_override,setgid,setuid", *label,
         "-v", f"{POLICY}:{POLICY_IN_SIDECAR}:ro,Z",
         "-v", f"{STUB_CERT}:{UPSTREAM_CA_IN_SIDECAR}:ro,Z",
         "-v", f"{VOLUME}:{STATE_IN_SIDECAR}"
               + ("" if shared_label else ":Z"),
         "-e", f"SSL_CERT_FILE={UPSTREAM_CA_IN_SIDECAR}",
         "--secret", f"{SECRET},target={CREDENTIAL},uid={BROKER_UID},"
                     f"gid={GROUP_GID},mode=0400",
         SIDECAR_IMAGE, "--name", NAME, "--caller-uid", str(WORKLOAD_UID),
         "--host", f"{PROVIDER}={CREDENTIAL}",
         "--placeholder", f"{CREDENTIAL}={PLACEHOLDER}",
         "--auth-header", f"{CREDENTIAL}=Authorization",
         f"--auth-format={CREDENTIAL}=Bearer {{secret}}"])
    run(["podman", "start", SIDECAR])
    return await_sidecar()


def await_sidecar():
    """The sidecar's pid once its planes are bound and the broker's
    socket is at its path."""
    pid = int(run(["podman", "inspect", "-f", "{{.State.Pid}}",
                   SIDECAR]).stdout.strip())
    for _ in range(100):
        if run(["podman", "inspect", "-f", "{{.State.Running}}",
                SIDECAR]).stdout.strip() != "true":
            sys.exit("the sidecar did not stay up:\n" + logs())
        held = in_netns(pid, ["ss", "-lntH"], check=False).stdout
        if f":{INSPECT_TLS} " in held and exec_in(
                SIDECAR, ["test", "-S", SOCKET_PATH]).returncode == 0:
            say(f"  sidecar up (pid {pid}): planes bound, socket at "
                f"{SOCKET_PATH}")
            return pid
        time.sleep(0.2)
    sys.exit("the sidecar never bound its planes and socket:\n" + logs())


def logs():
    r = run(["podman", "logs", SIDECAR], check=False)
    return r.stdout + r.stderr


def sidecar_file(path):
    r = exec_in(SIDECAR, ["cat", path])
    if r.returncode != 0:
        raise OSError(r.stderr)
    return r.stdout


def level_of(container):
    label = run(["podman", "inspect", "-f", "{{.ProcessLabel}}",
                 container], check=False).stdout.strip()
    return label.split(":", 3)[3] if label.count(":") >= 3 else label


def label_rows(workload=WORKLOAD):
    """What a workload out of its mount namespace would meet: its own
    label, the sidecar's files. The probe containers stand in for it."""
    say("label")
    mine, theirs = level_of(SIDECAR), level_of(workload)
    key = str(ca_key_path(STATE_IN_SIDECAR))
    listed = exec_in(SIDECAR, ["ls", "-Z", POLICY_IN_SIDECAR,
                               f"/run/secrets/{CREDENTIAL}", key]).stdout
    files = {path: label.split(":", 3)[-1] for label, path in
             (ln.split() for ln in listed.splitlines())}
    row("label: the sidecar runs at a level of its own, not the "
        "workload's, and its policy, secret and CA key are labelled at it",
        mine == SIDECAR_LEVEL and theirs != mine and len(files) == 3
        and set(files.values()) == {mine},
        f"sidecar {mine}, workload {theirs}; {files}")
    reads = {}
    for whose, level in (("workload's", theirs), ("sidecar's", mine)):
        got = run(["podman", "run", "--rm", "--network", "none", "--user",
                   f"{INSPECT_UID}:{GROUP_GID}", "--cap-drop", "all",
                   "--security-opt", f"label=level:{level}",
                   "-v", f"{VOLUME}:{STATE_IN_SIDECAR}", IMAGE, "sh", "-c",
                   f'cat "{key}" > /dev/null && echo read'],
                  check=False, timeout=120)
        reads[whose] = (got.stdout.strip(), got.stderr.strip()[-120:])
    row("label: a container at the workload's level, as the inspector's "
        "uid, is refused the CA key, which one at the sidecar's reads",
        reads["workload's"][0] != "read"
        and "Permission denied" in reads["workload's"][1]
        and reads["sidecar's"][0] == "read", f"{reads}")


def in_netns(pid, argv, **kw):
    return run(["podman", "unshare", "nsenter", "-t", str(pid), "-n",
                *argv], **kw)


def default_route_device(pid):
    """The pod's default-route interface, whose name pasta takes from the
    host's and which egress leaves by."""
    return in_netns(pid, ["ip", "route", "show", "default"]).stdout.split()[4]


def load_rules(pid, neighbour, redirect_dns, private):
    """The discriminator is the uid: the two image uids are exempt from
    the redirect and the drop, since their dials are the upstream legs
    and leave through this same netns. The resolver is pasta's forwarder,
    read from the pod's resolv.conf; its accept lines are the programs',
    since everyone else's port 53 is redirected to the responder.

    The drop is a netdev egress hook, not an output filter. An output
    `policy drop` fails a UDP send with EPERM, which no real network does;
    the egress hook drops the packet after send() has returned and counts
    it. It hangs on the pod's egress device, so loopback -- the redirected
    plane's dial to 127.0.0.1 among it -- never crosses the hook.

    The egress chain exempts the programs by a connection mark, not by
    uid: `meta skuid` needs the packet to carry the program's socket, and
    the segments a connection sends after that socket is gone -- the FIN
    and RST of a program that exited, TIME_WAIT's ACKs -- carry none. The
    `tag` chain reads the uid at the output hook, stores it on the
    connection, and copies it onto every packet for the egress hook.

    The private-space drop is docs/DESIGN.md's, with the one accept line
    the provider needs. It follows the resolver's lines: pasta's
    resolver is link-local, and the programs resolve through it too.

    `neighbour` false leaves out the ARP and neighbour-discovery lines,
    for the `neighbour` row to go red; `redirect_dns` false the port-53
    lines, for the `dns` rows; `private` false, the private-space drop,
    for the `private` row."""
    resolv = exec_in(SIDECAR, ["cat", "/etc/resolv.conf"]).stdout
    dns = next((ln.split()[1] for ln in resolv.splitlines()
                if ln.startswith("nameserver")), "169.254.1.1")
    dev = default_route_device(pid)
    in_netns(pid, ["nft", "-f", "-"],
             input=ruleset(dev, dns, neighbour=neighbour,
                           redirect_dns=redirect_dns, private=private))
    say(f"  rules loaded into the pod's netns (resolver {dns}, "
        f"egress on {dev})")
    return dns


def ruleset(dev, dns, *, neighbour=True, redirect_dns=True, private=False):
    """The rules load_rules loads: docs/DESIGN.md's "Sidecar" ruleset
    with every keyword at its default (tests/test_rig_rules.py), and
    `private` its "Private addresses" drop."""
    ours = f"{{ {INSPECT_UID}, {BROKER_UID} }}"
    nd = riglib.NEIGHBOUR_DISCOVERY if neighbour else ""
    redirect = (f"    udp dport 53  dnat ip to 127.0.0.1:{RESOLVE_PORT}\n"
                f"    tcp dport 53  dnat ip to 127.0.0.1:{RESOLVE_PORT}\n"
                if redirect_dns else "")
    inward = f"""\
    {INTERNAL_ACCEPT} comment "internal"
    meta mark {OURS_MARK} ip daddr {{ {PRIVATE_V4} }} counter drop \
comment "private"
    meta mark {OURS_MARK} ip6 daddr {{ {PRIVATE_V6} }} counter drop \
comment "private"
""" if private else ""
    return f"""
table inet moatery {{
  chain out {{
    type nat hook output priority -100
    meta skuid {ours} accept
    tcp dport 443 dnat ip to 127.0.0.1:{INSPECT_TLS}
    tcp dport 80  dnat ip to 127.0.0.1:{INSPECT_CLEARTEXT}
{redirect}  }}
  chain tag {{
    type filter hook output priority mangle
    meta skuid {ours} ct mark set {OURS_MARK}
    meta mark set ct mark
  }}
}}
table netdev moatery {{
  chain egress {{
    type filter hook egress device "{dev}" priority 0; policy drop
{nd}    meta mark {OURS_MARK} ip daddr {dns} udp dport 53 accept
    meta mark {OURS_MARK} ip daddr {dns} tcp dport 53 accept
{inward}    meta mark {OURS_MARK} accept
    udp dport 443 counter comment "quic"
    counter comment "dropped"
  }}
}}
"""


def start_workload():
    run(["podman", "create", "--pod", POD, "--name", WORKLOAD,
         "--user", f"{WORKLOAD_UID}:{WORKLOAD_UID}", "--cap-drop", "all",
         "-v", f"{BUNDLE}:{CA_BUNDLE_IN_CONTAINER}:ro,Z",
         "-e", f"SSL_CERT_FILE={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"NODE_EXTRA_CA_CERTS={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"REQUESTS_CA_BUNDLE={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"GIT_SSL_CAINFO={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"PIP_CERT={CA_BUNDLE_IN_CONTAINER}",
         "-e", f"EXAMPLE_API_KEY={PLACEHOLDER}",
         IMAGE, "sleep", "infinity"], timeout=300)
    run(["podman", "start", WORKLOAD])
    pid = int(run(["podman", "inspect", "-f", "{{.State.Pid}}",
                   WORKLOAD]).stdout.strip())
    say(f"  workload started (pid {pid}, uid {WORKLOAD_UID})")
    return pid


def exec_in(container, argv, timeout=30):
    return run(["podman", "exec", container, *argv], check=False,
               timeout=timeout)


def curl_in(url, *extra, timeout=15):
    """curl from the workload: (exit status, http status or '', body)."""
    r = exec_in(WORKLOAD, ["curl", "-s", "-S", "--max-time", str(timeout),
                           "--cacert", CA_BUNDLE_IN_CONTAINER,
                           "-o", "/tmp/body", "-w", "%{http_code}",
                           *extra, url], timeout=timeout + 10)
    body = (exec_in(WORKLOAD, ["cat", "/tmp/body"]).stdout
            if r.returncode == 0 else "")
    return r.returncode, r.stdout.strip(), body, r.stderr.strip()


# --- the rows ----------------------------------------------------------------

def records():
    try:
        return riglib.parse_records(
            sidecar_file(f"{STATE_IN_SIDECAR}/egress.jsonl"))
    except OSError:
        return []


def caps_of(pid):
    return int(next(ln.split()[1] for ln in
                    Path(f"/proc/{pid}/status").read_text().splitlines()
                    if ln.startswith("CapBnd:")), 16)


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


def egress_rules(pid):
    return in_netns(pid, ["nft", "-a", "list", "chain", "netdev", "moatery",
                          "egress"], check=False).stdout


def handle_of(pid, comment):
    """The handle of the first egress rule with this comment, or None."""
    for line in egress_rules(pid).splitlines():
        if f'comment "{comment}"' in line and "# handle " in line:
            return line.rsplit("# handle ", 1)[1].strip()
    return None


def private_counter(pid):
    """Packets the private-space drop lines have counted, both families."""
    total = 0
    for line in egress_rules(pid).splitlines():
        if 'comment "private"' in line and "packets" in line:
            fields = line.split()
            total += int(fields[fields.index("packets") + 1])
    return total


def stub_arrivals():
    """Requests the stub has served: a dropped SYN never becomes one."""
    return sum(ln.startswith("stub: ")
               for ln in (RIG / "stub.log").read_text().splitlines())


def private_rows(sidecar_pid, dns):
    """The accept line is deleted and put back by handle, around one
    request each way; the broker dials afresh per request, so the next
    one meets the chain as it stands."""
    say("private")
    answer = run(["podman", "exec", "--user", str(INSPECT_UID), SIDECAR,
                  "python3", "-c", riglib.DNS_QUERY, dns],
                 check=False).stdout.strip()
    row("private: the programs' own DNS query to the resolver is answered",
        answer == "answered", f"query to {dns} as uid {INSPECT_UID}: "
        f"{answer!r}")

    handle = handle_of(sidecar_pid, "internal")
    if handle is not None:
        in_netns(sidecar_pid, ["nft", "delete", "rule", "netdev", "moatery",
                               "egress", "handle", handle])
    counted, arrived = private_counter(sidecar_pid), stub_arrivals()
    rc, code, _, err = curl_in(
        f"https://{PROVIDER}/v1/probe", "-H",
        f"Authorization: Bearer {PLACEHOLDER}", timeout=25)
    counted_after = private_counter(sidecar_pid)
    arrived_after = stub_arrivals()
    row("private: with no accept line, the provider's dial is dropped",
        code != "200" and arrived_after == arrived
        and counted_after > counted,
        f"curl rc={rc} http={code!r} {err}; stub requests {arrived} -> "
        f"{arrived_after}; private drops {counted} -> {counted_after}")
    last = next((r for r in reversed(records())
                 if r.get("host") == PROVIDER), None)
    row("private: the record does not say it was served",
        last is not None and last.get("status") != 200, f"{last}")

    first_drop = handle_of(sidecar_pid, "private")
    if first_drop is not None:
        in_netns(sidecar_pid, ["nft", "insert", "rule", "netdev", "moatery",
                               "egress", "position", first_drop,
                               *INTERNAL_ACCEPT.split(),
                               "comment", '"internal"'])
    arrived = stub_arrivals()
    rc, code, _, err = curl_in(
        f"https://{PROVIDER}/v1/probe", "-H",
        f"Authorization: Bearer {PLACEHOLDER}")
    row("private (control): with the line back, the same request arrives",
        rc == 0 and code == "200" and stub_arrivals() == arrived + 1,
        f"curl rc={rc} http={code} {err}; stub requests {arrived} -> "
        f"{stub_arrivals()}")


def probe(sidecar_pid, workload_pid, secret, dns):
    say("premise")
    caps = caps_of(workload_pid)
    row("premise: no CAP_NET_ADMIN in the workload's bounding set",
        not caps & (1 << 12), f"CapBnd={caps:016x}")
    row("premise: no CAP_SETUID either -- the uid is the selector",
        not caps & (1 << 7), f"CapBnd={caps:016x}")
    listed = in_netns(sidecar_pid, ["nft", "list", "tables"],
                      check=False).stdout
    row("premise: the rules are in the pod's netns",
        "table inet moatery" in listed, listed.strip() or "no tables")
    top = run(["podman", "top", SIDECAR, "user,args"], check=False).stdout
    who = {}
    for ln in top.splitlines()[1:]:
        user, _, argv = ln.partition(" ")
        for prog in ("moat-broker", "moat-inspect", "moat-resolve"):
            if prog in argv:
                who[prog] = user.strip()
    inspect = ("inspect", str(INSPECT_UID))
    row("premise: the sidecar's programs run as the two image uids",
        who.get("moat-broker") in ("broker", str(BROKER_UID))
        and who.get("moat-inspect") in inspect
        and who.get("moat-resolve") in inspect,
        f"{who}")
    effective = int(next(ln.split()[1] for ln in
                         Path(f"/proc/{sidecar_pid}/status").read_text()
                         .splitlines() if ln.startswith("CapEff:")), 16)
    row("premise: the supervisor holds no capability",
        effective == 0, f"CapEff={effective:016x}")

    label_rows()

    riglib.dns_rows(
        lambda argv: in_netns(sidecar_pid, ["python3", "-c",
                                            riglib.DNS_LOOKUP, *argv],
                              check=False).stdout.strip(),
        dns, riglib.ANSWER,
        lambda: sidecar_file(f"{STATE_IN_SIDECAR}/resolve-status.json"))

    say("silent drop")
    sent = in_netns(sidecar_pid, ["python3", "-c", UDP_SEND,
                                  FILTERED_UDP[0], str(FILTERED_UDP[1])],
                    check=False).stdout.strip()
    moved = chain_counter(sidecar_pid, "dropped")
    row("silent drop: a filtered UDP send returns rc=0, not EPERM",
        sent == "sent" and moved >= 1,
        f"send={sent!r}, dropped counter={moved}")

    say("quic")
    before = chain_counter(sidecar_pid, "quic")
    sent = in_netns(sidecar_pid, ["python3", "-c", UDP_SEND,
                                  QUIC_UDP[0], str(QUIC_UDP[1])],
                    check=False).stdout.strip()
    counted = chain_counter(sidecar_pid, "quic")
    dropped = chain_counter(sidecar_pid, "dropped")
    row("quic: a UDP send to 443 is counted as quic, and dropped",
        sent == "sent" and before == 0 and counted == 1
        and dropped > moved,
        f"send={sent!r}, quic counter {before} -> {counted}, "
        f"dropped counter {moved} -> {dropped}")

    say("request")
    before = logs().count(" ok ")
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
    head = exec_in(WORKLOAD, ["cat", "/tmp/head"]).stdout
    server = next((ln.strip() for ln in head.splitlines()
                   if ln.lower().startswith("server:")), "no Server")
    row("request: the response names the provider's server, not a broker",
        server == f"Server: {riglib.STUB_SERVER}"
        and "moatery" not in head.lower(), server)
    env = exec_in(WORKLOAD, ["env"]).stdout
    row("request: the workload's environment holds the placeholder only",
        PLACEHOLDER in env and secret not in env,
        "placeholder present, key absent" if secret not in env
        else "THE KEY IS IN THE WORKLOAD")
    after = logs().count(" ok ")
    row("request: the broker logged the request",
        after == before + 1, f"ok lines {before} -> {after}")
    forwarded = [r for r in records() if r.get("host") == PROVIDER]
    hit = next((r for r in forwarded if r.get("decision") == "forward"
                and r.get("credential") == CREDENTIAL
                and r.get("status") == 200), None)
    row("request: the record says forwarded under the credential",
        hit is not None,
        f"{hit}" if hit else f"records for {PROVIDER}: {forwarded}")

    say("neighbour")
    dev = default_route_device(sidecar_pid)
    in_netns(sidecar_pid, ["ip", "neigh", "flush", "dev", dev])
    rc, code, _, err = curl_in(
        f"https://{PROVIDER}/v1/probe", "-H",
        f"Authorization: Bearer {PLACEHOLDER}")
    learned = in_netns(sidecar_pid, ["ip", "neigh", "show", "dev", dev],
                       check=False).stdout.strip()
    row("neighbour: with the neighbour table flushed, it serves the workload",
        rc == 0 and code == "200",
        f"curl rc={rc} http={code} {err}; neighbours: "
        f"{learned or 'none'}")

    say("broker")
    before = logs().count(" ok ")
    # curl reports a missing path and a path nobody listens on with the
    # same words, so the errno is read off the filesystem: strerror(ENOENT)
    # from stat, then the dial, which must fail too.
    seen = exec_in(WORKLOAD, ["ls", "-ld", SOCKET_PATH])
    dial = exec_in(WORKLOAD, ["curl", "-s", "-S", "--max-time", "5",
                              "--unix-socket", SOCKET_PATH, "http://x/"])
    row(f"broker: {SOCKET_PATH} is ENOENT from the workload",
        seen.returncode != 0 and "No such file or directory" in seen.stderr
        and dial.returncode == 7,
        f"stat: {seen.stderr.strip()!r}; curl rc={dial.returncode}")
    held = in_netns(sidecar_pid, ["ss", "-lntH"], check=False).stdout
    ports = sorted({ln.split()[3].rsplit(":", 1)[1]
                    for ln in held.splitlines() if ln.strip()})
    row("broker: nothing but the planes and the responder listen on TCP",
        ports == sorted({str(INSPECT_TLS), str(INSPECT_CLEARTEXT),
                         str(RESOLVE_PORT)}),
        f"listening: {ports}")
    after = logs().count(" ok ")
    row("broker: its log saw nothing", after == before,
        f"ok lines {before} -> {after}")

    say("unlisted")
    rc, code, body, err = curl_in(f"https://{UNLISTED}/", timeout=10)
    row(f"unlisted: {UNLISTED} gets the inspector's 403 from the workload",
        rc == 0 and code == "403",
        f"curl rc={rc} http={code!r} body={body.strip()!r} {err}")
    dropped = [r for r in records() if r.get("host") == UNLISTED]
    hit = next((r for r in dropped if r.get("decision") == "drop"
                and r.get("reason") == DROP_NOT_ALLOWLISTED
                and r.get("upstream") is None), None)
    row("unlisted: the record says dropped, 'not allowlisted', no upstream",
        hit is not None, f"{hit}" if hit else f"records: {dropped}")

    private_rows(sidecar_pid, dns)

    riglib.origin_rows(secret)

    say("counters (waiting for the inspector's next status write)")
    status = riglib.await_status(
        lambda: sidecar_file(f"{STATE_IN_SIDECAR}/status.json"),
        after=time.time())
    if status is None:
        row("counters: the inspector wrote its status", False,
            "status.json not updated within 40 s")
    else:
        unresolved = status.get("caller_unresolved")
        row("counters: every connection's caller was named",
            unresolved == 0, f"caller_unresolved={unresolved}")
        foreign = status.get("drop_reasons", {}).get(DROP_FOREIGN_CALLER)
        row("counters: nothing was dropped as a foreign caller",
            foreign == 0, f"{DROP_FOREIGN_CALLER!r}: {foreign}")


def sidecar_state(field):
    return run(["podman", "inspect", "-f", "{{" + field + "}}", SIDECAR],
               check=False).stdout.strip()


def lifecycle(secret):
    """Last: every row here ends the sidecar at least once."""
    say("lifecycle")
    restarts = int(sidecar_state(".RestartCount") or 0)
    top = run(["podman", "top", SIDECAR, "hpid,args"], check=False).stdout
    broker = next((ln.split()[0] for ln in top.splitlines()
                   if "moat-broker" in ln), None)
    if broker is None:
        row("lifecycle: the broker is running to be killed", False, top)
        return
    run(["podman", "unshare", "kill", "-TERM", broker])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        now = int(sidecar_state(".RestartCount") or 0)
        if now > restarts:
            break
        time.sleep(0.2)
    log = logs()
    row("lifecycle: the broker's death ends the container, non-zero",
        now == restarts + 1 and "the broker exited (-15)" in log
        and "the inspector exited (0)" in log
        and "the responder exited (0)" in log,
        f"restarts {restarts} -> {now}; "
        + "; ".join(ln for ln in log.splitlines() if " exited (" in ln))

    if now > restarts:
        await_sidecar()
    rc, code, body, err = curl_in(
        f"https://{PROVIDER}/v1/probe", "-H",
        f"Authorization: Bearer {PLACEHOLDER}")
    arrived = ""
    try:
        arrived = json.loads(body).get("authorization", "")
    except ValueError:
        pass
    row("lifecycle: restarted on the same volume, it serves the workload",
        rc == 0 and code == "200" and arrived == f"Bearer {secret}",
        f"curl rc={rc} http={code} {err}".strip())

    started = time.monotonic()
    run(["podman", "stop", "-t", "10", SIDECAR], check=False)
    took = time.monotonic() - started
    status = sidecar_state(".State.ExitCode")
    log = logs()
    tail = [ln for ln in log.splitlines() if " exited (" in ln][-3:]
    row("lifecycle: a stop reaches every program and exits 0",
        took < 5 and status == "0"
        and sorted(tail) == ["the broker exited (-15)",
                             "the inspector exited (0)",
                             "the responder exited (0)"],
        f"{took:.1f}s, exit {status}; {tail}")


# --- teardown ----------------------------------------------------------------

def teardown(keep):
    say("teardown")
    if not keep:
        remove_pod()
        run(["podman", "secret", "rm", SECRET], check=False)
    riglib.stop_children()
    riglib.restore_privileged_ports()
    riglib.remove_hosts_entry()


# --- main --------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="leave the pod, its volume and the secret")
    ap.add_argument("--without-rules", action="store_true",
                    help="load no rules into the pod's netns; premise, "
                         "dns, silent, request, neighbour, unlisted and "
                         "private must go red")
    ap.add_argument("--without-neighbour-discovery", action="store_true",
                    help="leave ARP and neighbour discovery out of the "
                         "egress chain; neighbour and the lifecycle's "
                         "request must go red")
    ap.add_argument("--without-dns-redirect", action="store_true",
                    help="leave port 53 out of the redirect; dns and "
                         "unlisted must go red")
    ap.add_argument("--without-private-drop", action="store_true",
                    help="leave out the private-space drop and its accept "
                         "line; private must go red")
    ap.add_argument("--shared-label", action="store_true",
                    help="the sidecar at the pod's level, its volume "
                         "unlabelled; both label rows must go red")
    ap.add_argument("--no-build", action="store_true",
                    help=f"use the {SIDECAR_IMAGE} already built")
    args = ap.parse_args()

    riglib.preflight(("podman", "pasta", "nft", "openssl", "curl", "ss",
                      "nsenter"), (riglib.PROVIDER_PORT,))
    RIG.mkdir(parents=True, exist_ok=True)
    secret = "sk-real-" + os.urandom(12).hex()

    say("material")
    riglib.make_stub_cert()
    riglib.write_policy(POLICY)
    create_secret(secret)
    if not args.no_build:
        build_image()
    try:
        say("host side")
        riglib.lower_privileged_ports()
        riglib.write_hosts_entry(HOSTS_MARK)
        riglib.start_stub(secret)
        say("pod")
        remove_pod()
        create_pod()
        sidecar_pid = start_sidecar(args.shared_label)
        # The CA is the sidecar's, minted into its volume on this first
        # start; the workload's bundle is built from it.
        riglib.write_bundle(
            sidecar_file(f"{STATE_IN_SIDECAR}/ca/egress-ca.crt"), BUNDLE)
        dns = "169.254.1.1"
        if args.without_rules:
            say("  rules NOT loaded, as asked")
        else:
            dns = load_rules(sidecar_pid,
                             not args.without_neighbour_discovery,
                             not args.without_dns_redirect,
                             not args.without_private_drop)
        workload_pid = start_workload()
        probe(sidecar_pid, workload_pid, secret, dns)
        lifecycle(secret)
    finally:
        teardown(args.keep)

    expected = [note for flag, note in (
        (args.without_rules, "--without-rules: premise, dns, silent, "
                             "request, neighbour, unlisted, private and the "
                             "lifecycle's request are expected red"),
        (args.without_dns_redirect,
         "--without-dns-redirect: dns and unlisted are expected red"),
        (args.without_neighbour_discovery,
         "--without-neighbour-discovery: neighbour and the lifecycle's "
         "request are expected red"),
        (args.without_private_drop,
         "--without-private-drop: private is expected red"),
        (args.shared_label,
         "--shared-label: both label rows are expected red"),
    ) if flag]
    rc = riglib.report("; ".join(expected) or None)
    if rc:
        say(f"logs: podman logs {SIDECAR}  (with --keep)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
