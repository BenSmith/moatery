#!/usr/bin/env python3
"""vm_placement_rig.py -- a VM in the netns and sidecar placements.

vm_rig.py proves a VM in the host placement: qemu in a rootless
container, its passt backend re-originating the guest's egress as
sockets in the container's namespace, the listeners on the host. This
rig moves the same qemu container and guest into the two placements
whose listeners are inside the namespace:

    python3 tests/manual/vm_placement_rig.py --placement netns|sidecar
                                             [--loopback-answer]
                                             [--keep] [--no-build]

  netns     netns_rig.py's host side: the broker a user unit, the
            inspector and the responder bound in the qemu container's
            namespace by moat-netns-listen, that rig's rules.
  sidecar   sidecar_rig.py's pod: the sidecar image, its rules, and the
            qemu container as the workload, uid 1000, every capability
            dropped.

Both answer every name with riglib.ANSWER, moathut's, which passt
carries out of the guest and the redirect lands on the listeners by
port. `--loopback-answer` (netns only) answers with the namespace's
127.0.0.1 instead, which the guest takes for its own: request, unlisted
and drop must go red.

The guest, the seed and the qemu image are vm_rig.py's; it needs what
that rig needs (a KVM host, the guest qcow2), and the sidecar image
sidecar_rig.py builds (`localhost/moat-sidecar:rig`).

THE ROWS

  premise   qemu's container holds no CAP_NET_ADMIN; the rules are in
            the namespace; qemu holds /dev/kvm; the guest is a namespace
            of its own.
  dns       the guest's queries, to its resolver over UDP and TCP and to
            another nameserver, are answered with the placement's
            address; an AAAA gets no records.
  egress    the guest's UDP sends return while the namespace's drop
            counter moves; the one to 443 moves `quic`.
  request   from inside the guest, with the placeholder, the provider
            answers 200 and reports the REAL key; the record says
            forwarded under the credential.
  unlisted  a host the policy does not name gets the inspector's 403,
            and the record says why.
  drop      a guest connect to another port at the answered address
            times out.
  counters  every caller was named; none was foreign.
  label     sidecar only: sidecar_rig.py's, with qemu's container as the
            workload.
"""

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import netns_rig  # noqa
import riglib  # noqa
import sidecar_rig  # noqa
import vm_rig  # noqa
from riglib import (  # noqa
    CREDENTIAL, LOOPBACK_MAP, PLACEHOLDER, PROVIDER, RIG, UNLISTED, row,
    run, say,
)
from moatery.egress_ca import ca_cert_path  # noqa
from moatery.egress_record import DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED  # noqa

CONTAINER = vm_rig.CONTAINER
VM_DIR = vm_rig.VM_DIR


# --- the qemu container ------------------------------------------------------

def create_qemu(network, extra=()):
    """vm_rig's qemu container, on `network`. The serial and probe files
    are made first and left writable by anyone, so a qemu running as a
    subordinate uid (the sidecar's workload) can open them."""
    run(["podman", "rm", "-f", CONTAINER], check=False)
    for path in (vm_rig.SERIAL, vm_rig.PROBE_LOG):
        path.write_text("")
        path.chmod(0o666)
    run(["podman", "create", "--name", CONTAINER, *network,
         "--device", "/dev/kvm", *extra,
         "-v", f"{VM_DIR}:{vm_rig.VM}:Z",
         vm_rig.QEMU_IMAGE, *vm_rig.qemu_argv()], timeout=300)


def container_pid(name):
    return int(run(["podman", "inspect", "-f", "{{.State.Pid}}",
                    name]).stdout.strip())


# --- netns -------------------------------------------------------------------

def netns_up(secret, answer, build):
    riglib.mint_ca(netns_rig.STATE)
    riglib.write_bundle(ca_cert_path(netns_rig.STATE).read_text(),
                        netns_rig.BUNDLE)
    riglib.make_stub_cert()
    riglib.write_policy(netns_rig.POLICY)
    netns_rig.seal_credential(secret)
    if build:
        vm_rig.build_image()
    vm_rig.write_seed(netns_rig.BUNDLE, answer)
    riglib.lower_privileged_ports()
    riglib.write_hosts_entry(netns_rig.HOSTS_MARK)
    riglib.start_stub(secret)
    netns_rig.start_broker()
    create_qemu(["--network", "pasta", "--hosts-file", "image"])
    run(["podman", "init", CONTAINER])
    pid = container_pid(CONTAINER)
    say(f"  qemu container initialised (pid {pid})")
    netns_rig.load_rules(pid, True)
    netns_rig.start_inspector(pid, True, True)
    netns_rig.start_responder(pid, True, answer)
    run(["podman", "start", CONTAINER])
    netns_rig.await_up()
    return pid, pid


def netns_reads():
    return {
        "records": lambda: riglib.parse_records(
            netns_rig.RECORD.read_text()),
        "status": netns_rig.STATUS.read_text,
    }


def netns_down():
    run(["podman", "rm", "-f", CONTAINER], check=False)
    netns_rig.stop_units()


# --- sidecar -----------------------------------------------------------------

def sidecar_up(secret, answer, build):
    riglib.make_stub_cert()
    riglib.write_policy(sidecar_rig.POLICY)
    sidecar_rig.create_secret(secret)
    if build:
        vm_rig.build_image()
        sidecar_rig.build_image()
    riglib.lower_privileged_ports()
    riglib.write_hosts_entry(sidecar_rig.HOSTS_MARK)
    riglib.start_stub(secret)
    sidecar_rig.remove_pod()
    sidecar_rig.create_pod()
    spid = sidecar_rig.start_sidecar()
    riglib.write_bundle(sidecar_rig.sidecar_file(
        f"{sidecar_rig.STATE_IN_SIDECAR}/ca/egress-ca.crt"),
        sidecar_rig.BUNDLE)
    sidecar_rig.load_rules(spid, True, True, True)
    vm_rig.write_seed(sidecar_rig.BUNDLE, answer)
    uid = sidecar_rig.WORKLOAD_UID
    create_qemu(["--pod", sidecar_rig.POD],
                ["--user", f"{uid}:{uid}", "--cap-drop", "all"])
    run(["podman", "start", CONTAINER])
    return spid, container_pid(CONTAINER)


def sidecar_reads():
    state = sidecar_rig.STATE_IN_SIDECAR
    return {
        "records": lambda: riglib.parse_records(
            sidecar_rig.sidecar_file(f"{state}/egress.jsonl")),
        "status": lambda: sidecar_rig.sidecar_file(f"{state}/status.json"),
    }


def sidecar_down():
    run(["podman", "rm", "-f", CONTAINER], check=False)
    sidecar_rig.remove_pod()
    run(["podman", "secret", "rm", sidecar_rig.SECRET], check=False)


PLACEMENTS = {
    "netns": (netns_up, netns_reads, netns_down),
    "sidecar": (sidecar_up, sidecar_reads, sidecar_down),
}


# --- the rows ----------------------------------------------------------------

def chain_counter(ns_pid, comment):
    out = vm_rig.in_netns(ns_pid, ["nft", "list", "chain", "netdev",
                                   "moatery", "egress"], check=False).stdout
    for line in out.splitlines():
        if "packets" in line and f'comment "{comment}"' in line:
            fields = line.split()
            return int(fields[fields.index("packets") + 1])
    return -1


def records(reads):
    try:
        return reads["records"]()
    except (OSError, ValueError):
        return []


def probe(ns_pid, qemu_pid, reports, secret, answer, reads):
    say("premise")
    caps = int(next(ln.split()[1] for ln in
                    Path(f"/proc/{qemu_pid}/status").read_text()
                    .splitlines() if ln.startswith("CapBnd:")), 16)
    row("premise: no CAP_NET_ADMIN in qemu's bounding set",
        not caps & (1 << 12), f"CapBnd={caps:016x}")
    listed = vm_rig.in_netns(ns_pid, ["nft", "list", "tables"],
                             check=False).stdout
    row("premise: the rules are in the namespace",
        "table inet moatery" in listed, listed.strip() or "no tables")
    # Through `podman unshare`: the sidecar's qemu runs as a subordinate
    # uid, whose /proc entries the user cannot read.
    links = run(["podman", "unshare", "sh", "-c",
                 f"readlink /proc/{qemu_pid}/ns/net "
                 f"/proc/{qemu_pid}/fd/*"], check=False).stdout.split()
    ns, fds = (links[0], links[1:]) if links else ("", [])
    row("premise: qemu holds /dev/kvm open",
        "/dev/kvm" in fds, "yes" if "/dev/kvm" in fds else "no")
    boot = vm_rig.pick(reports, "boot")
    row("premise: the guest is a namespace of its own",
        bool(boot.get("netns")) and boot.get("netns") != ns,
        f"guest {boot.get('netns')} container {ns}")

    say("dns")
    dns = {r.get("label"): r for r in reports if r.get("probe") == "dns"}
    for label, expect in (("udp", answer), ("tcp", answer),
                          ("elsewhere", answer), ("aaaa", "nodata"),
                          ("provider", answer)):
        got = dns.get(label, {}).get("result")
        row(f"dns: {label} answers {expect}", got == expect, repr(got))

    say("egress")
    udp = {r.get("port"): r.get("result")
           for r in reports if r.get("probe") == "udp"}
    dropped = chain_counter(ns_pid, "dropped")
    row("egress: the guest's UDP sends returned and the chain dropped "
        "them", udp.get(9) == "sent" and udp.get(443) == "sent"
        and dropped >= 2, f"sends={udp}, dropped={dropped}")
    quic = chain_counter(ns_pid, "quic")
    row("egress: the guest's UDP to 443 is counted as quic",
        quic >= 1, f"quic={quic}")

    say("request")
    prov = vm_rig.pick(reports, "http", label="provider")
    row("request: the provider answers 200 through inspector and broker",
        prov.get("status") == 200,
        f"dialled {prov.get('address')}: http={prov.get('status')} "
        f"{prov.get('error', '')}")
    try:
        arrived = json.loads(prov.get("body") or "{}").get(
            "authorization", "")
    except ValueError:
        arrived = ""
    row("request: the REAL key arrived at the provider",
        arrived == f"Bearer {secret}", f"the stub saw {arrived[:20]!r}")
    hit = next((r for r in records(reads) if r.get("host") == PROVIDER
                and r.get("decision") == "forward"
                and r.get("credential") == CREDENTIAL
                and r.get("status") == 200), None)
    row("request: the record says forwarded under the credential",
        hit is not None, f"{hit}")
    env = vm_rig.pick(reports, "env").get("vars", {})
    row("request: the guest's environment holds the placeholder only",
        env.get("EXAMPLE_API_KEY") == PLACEHOLDER,
        f"EXAMPLE_API_KEY={env.get('EXAMPLE_API_KEY')!r}")

    say("unlisted")
    unl = vm_rig.pick(reports, "http", label="unlisted")
    row(f"unlisted: {UNLISTED} gets the inspector's 403",
        unl.get("status") == 403,
        f"dialled {unl.get('address')}: http={unl.get('status')} "
        f"{unl.get('error', '')}")
    hit = next((r for r in records(reads) if r.get("host") == UNLISTED
                and r.get("decision") == "drop"
                and r.get("reason") == DROP_NOT_ALLOWLISTED), None)
    row("unlisted: the record says dropped, 'not allowlisted'",
        hit is not None, f"{hit}")

    say("drop")
    tcp = vm_rig.pick(reports, "tcp", port=vm_rig.DROP_PORT)
    row(f"drop: a guest connect to {answer}:{vm_rig.DROP_PORT} times out",
        tcp.get("result") == "timeout", repr(tcp.get("result")))

    say("counters (waiting for the inspector's next status write)")
    status = riglib.await_status(reads["status"], after=time.time())
    if status is None:
        row("counters: the inspector wrote its status", False,
            "not updated within 40 s")
    else:
        row("counters: every connection's caller was named",
            status.get("caller_unresolved") == 0,
            f"caller_unresolved={status.get('caller_unresolved')}")
        foreign = status.get("drop_reasons", {}).get(DROP_FOREIGN_CALLER)
        row("counters: nothing was dropped as a foreign caller",
            foreign == 0, f"{DROP_FOREIGN_CALLER!r}: {foreign}")


# --- main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--placement", required=True, choices=PLACEMENTS)
    ap.add_argument("--loopback-answer", action="store_true",
                    help="netns only: answer with 127.0.0.1; request, "
                         "unlisted and drop must go red")
    ap.add_argument("--keep", action="store_true",
                    help="leave the containers for inspection")
    ap.add_argument("--no-build", action="store_true",
                    help="reuse the last qemu image")
    ap.add_argument("--guest-timeout", type=int, default=300)
    args = ap.parse_args()

    if platform.machine() != "x86_64":
        sys.exit("x86_64 only (qemu-system-x86_64)")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        sys.exit("/dev/kvm is not readable and writable by the user")
    if not vm_rig.GUEST_IMAGE.exists():
        sys.exit(f"no guest image at {vm_rig.GUEST_IMAGE}")
    riglib.preflight(
        ("podman", "pasta", "nft", "openssl", "curl", "ss", "systemctl",
         "systemd-run", "systemd-creds", "nsenter"),
        (riglib.INSPECT_TLS, riglib.INSPECT_CLEARTEXT, riglib.RESOLVE_PORT,
         riglib.PROVIDER_PORT))
    vm_rig.seed_tool()
    RIG.mkdir(parents=True, exist_ok=True)
    VM_DIR.mkdir(parents=True, exist_ok=True)
    for stale in (netns_rig.STATUS, netns_rig.RECORD,
                  netns_rig.RESOLVE_STATUS):
        stale.unlink(missing_ok=True)
    if args.loopback_answer and args.placement != "netns":
        sys.exit("--loopback-answer is for the netns placement")
    answer = "127.0.0.1" if args.loopback_answer else riglib.ANSWER
    secret = "sk-real-" + os.urandom(12).hex()
    up, reads, down = PLACEMENTS[args.placement]

    say(f"placement: {args.placement}, answer {answer}")
    try:
        ns_pid, qemu_pid = up(secret, answer, not args.no_build)
        say("guest (booting)")
        reports = vm_rig.await_reports(args.guest_timeout)
        if reports is None:
            say(f"  the guest did not finish in {args.guest_timeout}s")
            say(vm_rig.SERIAL.read_text(errors="replace")[-2000:])
            sys.exit(1)
        probe(ns_pid, qemu_pid, reports, secret, answer, reads())
        if args.placement == "sidecar":
            sidecar_rig.label_rows(CONTAINER)
    finally:
        say("teardown")
        if not args.keep:
            down()
        riglib.stop_children()
        riglib.restore_privileged_ports()
        riglib.remove_hosts_entry()
    return riglib.report(
        "--loopback-answer: request, unlisted and drop are expected red"
        if args.loopback_answer else None)


if __name__ == "__main__":
    sys.exit(main())
