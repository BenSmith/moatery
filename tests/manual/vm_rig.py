#!/usr/bin/env python3
"""vm_rig.py -- does customs filter a VM's egress?

"VM" in docs/DESIGN.md, as it stands: one rootless podman container
under pasta holding nothing but qemu and its passt backend, the guest's
egress re-originated by passt as sockets in the container's netns, the
customs programs as hand-written user units on the host, the nft rules
loaded into the container's netns, and a workload inside the guest that
reaches the provider carrying the sealed key. Run on the proving host as
an ordinary user, from a checkout:

    python3 tests/manual/vm_rig.py [--keep] [--no-build]
                                       [--image PATH] [--without-rules]
                                       [--without-dns-redirect]
                                       [--without-neighbour-discovery]

Nothing here needs root except the two host facts every placement needs,
undone at teardown (see riglib). It needs a KVM host, /dev/kvm readable
and writable by the user, and a cloud image with cloud-init: the operator
puts a Fedora Cloud Base Generic qcow2 at
~/.local/state/customs-rig/vm/guest.qcow2 once, and the rig builds
its own qemu container image from tests/manual/vm.Containerfile.

THE ROWS

  premise   qemu runs with no CAP_NET_ADMIN; the rules are in its netns;
            qemu holds /dev/kvm; the guest is a namespace inside the
            container's, and the guest's own nft tables hold none of ours.
  egress    the guest's UDP sends return while the container chain's
            `dropped` counter moves: the guest's egress IS the container's.
  dns       the guest's raw queries, over UDP and TCP and to another
            nameserver, are answered by customs-resolve with the map;
            an AAAA gets no records; the responder's status names the
            guest's names and not the provider's.
  silent    a filtered UDP send returns rc=0 while the drop counter
            moves -- the netdev egress hook, not an output filter.
  quic      the guest's UDP to 443 moves the `quic` counter, which the
            port-9 send left at zero.
  request   from inside the guest, with the placeholder, the provider
            answers 200 and reports the REAL key arrived; the guest's
            environment holds only the placeholder; the broker's journal
            grew by one; the record says forwarded under the credential.
  neighbour the container's neighbour table is flushed before the guest's
            first packet, so the dial to the map re-learns the gateway;
            the dns and request rows are the observation.
  broker    it holds no TCP socket, another uid is refused by the kernel,
            and the map accepts only the inspector's and responder's
            ports: a guest connect to another port times out and the drop
            counter moves.
  unlisted  from inside the guest, a host the policy does not name is
            refused by the inspector and the record says why.
  no key    from the host, the placeholder alone gets 401; the real key
            gets 200.
  counters  every connection's caller was named; none was foreign.

`--without-rules` skips loading the netns rules: premise, egress, dns,
silent, quic, request, neighbour, broker, unlisted and counters must go
red. `--without-dns-redirect` leaves port 53 out of the redirect: dns,
request, unlisted and counters must go red. `--without-neighbour-discovery`
loads the egress chain without its ARP lines: dns, request, unlisted and
counters must go red.
"""

import argparse
import base64
import json
import os
import platform
import shutil
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import riglib  # noqa
from riglib import (  # noqa
    CREDENTIAL, INSPECT_CLEARTEXT, INSPECT_TLS,
    LIBEXEC, LOOPBACK_MAP, NAME, PLACEHOLDER, PROGRAM_ENV, PROVIDER,
    RESOLVE_PORT, RIG, STUB_CERT, UNLISTED, row, run, say,
)
from customs.egress_ca import ca_cert_path  # noqa
from customs.egress_record import DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED  # noqa

HERE = Path(__file__).resolve().parent
CONTAINER = "customs-rig-2"
UNIT = "customs-rig-2"
BROKER_SOCKET = Path(os.environ.get("XDG_RUNTIME_DIR",
                                    f"/run/user/{os.getuid()}"),
                     UNIT, "broker.sock")
HOSTS_MARK = "customs-vm-rig"
UNITS = riglib.HOME / ".config" / "systemd" / "user"
STATE = RIG / "state"
POLICY = RIG / "inspect-2.json"
STATUS = RIG / "inspect-2-status.json"
RESOLVE_STATUS = RIG / "resolve-2-status.json"
RECORD = RIG / "egress-2.jsonl"
BUNDLE = RIG / "bundle-2.pem"
CRED = RIG / f"{CREDENTIAL}-2.cred"
VM_DIR = RIG / "vm"
GUEST_IMAGE = VM_DIR / "guest.qcow2"
SEED = VM_DIR / "seed.iso"
SERIAL = VM_DIR / "serial.log"
PROBE_LOG = VM_DIR / "probe.log"
GUEST_SCRIPT = HERE / "vm_guest.py"
CONTAINERFILE = HERE / "vm.Containerfile"
QEMU_IMAGE = "localhost/customs-rig-qemu"
VM = "/vm"
CA_IN_GUEST = "/etc/customs-rig/bundle.pem"
DROP_PORT = 8081


# --- the host side: units ----------------------------------------------------

def seal_credential(secret):
    """`systemd-creds --user encrypt`: sealed to this user on this host,
    which is what LoadCredentialEncrypted= in a user unit can open."""
    run(["systemd-creds", "--user", "encrypt", f"--name={CREDENTIAL}",
         "-", str(CRED)], input=secret + "\n")
    CRED.chmod(0o600)


def write_units():
    """host_rig's units, verbatim. The programs run on the host; only the
    qemu container and its guest are new."""
    UNITS.mkdir(parents=True, exist_ok=True)
    py = sys.executable
    path = "".join(f"Environment={k}={v}\n" for k, v in PROGRAM_ENV.items())
    env = path + f"Environment=SSL_CERT_FILE={STUB_CERT}\n"
    endpoint = f"unix:%t/{UNIT}/broker.sock"
    (UNITS / f"{UNIT}-broker.service").write_text(
        "# written by tests/manual/vm_rig.py -- removed at teardown\n"
        "[Service]\n"
        f"ExecStart={py} {LIBEXEC / 'customs-broker'}"
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
        "# written by tests/manual/vm_rig.py -- removed at teardown\n"
        "[Socket]\n"
        f"ListenStream=127.0.0.1:{INSPECT_TLS}\n"
        f"ListenStream=127.0.0.1:{INSPECT_CLEARTEXT}\n")
    (UNITS / f"{UNIT}-inspect.service").write_text(
        "# written by tests/manual/vm_rig.py -- removed at teardown\n"
        "[Service]\n"
        f"ExecStart={py} {LIBEXEC / 'customs-inspect'}"
        f" --name {NAME} --policy {POLICY} --state-dir {STATE}"
        f" --status {STATUS} --record {RECORD}"
        f" --broker {endpoint}\n"
        + env)
    (UNITS / f"{UNIT}-resolve.socket").write_text(
        "# written by tests/manual/vm_rig.py -- removed at teardown\n"
        "[Socket]\n"
        f"ListenDatagram=127.0.0.1:{RESOLVE_PORT}\n"
        f"ListenStream=127.0.0.1:{RESOLVE_PORT}\n")
    (UNITS / f"{UNIT}-resolve.service").write_text(
        "# written by tests/manual/vm_rig.py -- removed at teardown\n"
        "[Service]\n"
        f"ExecStart={py} {LIBEXEC / 'customs-resolve'}"
        f" --name {NAME} --address {LOOPBACK_MAP} --policy {POLICY}"
        f" --status {RESOLVE_STATUS}\n"
        + path)
    run(["systemctl", "--user", "daemon-reload"])


def broker_pid():
    return run(["systemctl", "--user", "show", "-p", "MainPID", "--value",
                f"{UNIT}-broker.service"]).stdout.strip()


def start_units():
    run(["systemctl", "--user", "start", f"{UNIT}-broker.service"])
    pid = broker_pid()
    for _ in range(50):
        held = run(["ss", "-lxpH"]).stdout
        if any(str(BROKER_SOCKET) in ln and f"pid={pid}," in ln
               for ln in held.splitlines()):
            break
        if run(["systemctl", "--user", "is-active", f"{UNIT}-broker.service"],
               check=False).stdout.strip() != "active":
            sys.exit("broker did not stay up:\n" + journal("broker"))
        time.sleep(0.2)
    else:
        sys.exit(f"broker (pid {pid}) never listened on {BROKER_SOCKET}")
    say(f"  broker listening on {BROKER_SOCKET} (pid {pid})")
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


# --- the container and its netns ---------------------------------------------

def build_image():
    run(["podman", "build", "-t", QEMU_IMAGE, "-f", str(CONTAINERFILE),
         str(HERE)], timeout=900)
    say(f"  qemu image built: {QEMU_IMAGE}")


def in_netns(pid, argv, **kw):
    return run(["podman", "unshare", "nsenter", "-t", str(pid), "-n",
                *argv], **kw)


def default_route_device():
    """The host's default-route interface, whose name pasta mirrors into
    the netns as the device egress leaves by."""
    return run(["ip", "route", "show", "default"]).stdout.split()[4]


def load_rules(pid, neighbour, redirect_dns):
    """host_rig's rules, verbatim: the container netns sees only qemu's and
    passt's traffic, and the guest's egress is passt's."""
    dev = default_route_device()
    ports = f"{{ {INSPECT_TLS}, {INSPECT_CLEARTEXT}, {RESOLVE_PORT} }}"
    nd = riglib.NEIGHBOUR_DISCOVERY if neighbour else ""
    dns = (f"    udp dport 53  dnat ip to {LOOPBACK_MAP}:{RESOLVE_PORT}\n"
           f"    tcp dport 53  dnat ip to {LOOPBACK_MAP}:{RESOLVE_PORT}\n"
           if redirect_dns else "")
    rules = f"""
table inet customs {{
  chain out {{
    type nat hook output priority -100
    tcp dport 443 dnat ip to {LOOPBACK_MAP}:{INSPECT_TLS}
    tcp dport 80  dnat ip to {LOOPBACK_MAP}:{INSPECT_CLEARTEXT}
{dns}  }}
}}
table netdev customs {{
  chain egress {{
    type filter hook egress device "{dev}" priority 0; policy drop
{nd}    ip daddr {LOOPBACK_MAP} tcp dport {ports} accept
    ip daddr {LOOPBACK_MAP} udp dport {RESOLVE_PORT} accept
    udp dport 443 counter comment "quic"
    counter comment "dropped"
  }}
}}
"""
    in_netns(pid, ["nft", "-f", "-"], input=rules)
    say(f"  rules loaded into the container's netns (egress on {dev})")


def flush_neighbours(pid):
    """Before the guest's first packet, so its dial to the map has to
    resolve the gateway afresh and the egress chain sees that ARP. The
    flush stands in for the entry ageing out."""
    dev = default_route_device()
    in_netns(pid, ["ip", "neigh", "flush", "dev", dev])
    left = in_netns(pid, ["ip", "neigh", "show"], check=False).stdout.strip()
    say(f"  neighbour table flushed (egress on {dev})")
    return not left


def seed_tool():
    for tool in ("cloud-localds", "genisoimage", "xorriso"):
        if shutil.which(tool):
            return tool
    sys.exit("need cloud-localds, genisoimage or xorriso for the seed")


def b64(data):
    return base64.b64encode(data).decode()


def write_seed():
    """The NoCloud seed: the CA bundle, the agent's environment, and the
    guest probe. Both touches the design puts in the seed are here."""
    VM_DIR.mkdir(parents=True, exist_ok=True)
    (VM_DIR / "meta-data").write_text(
        f"instance-id: customs-vm-{os.urandom(4).hex()}\n"
        "local-hostname: guest\n")
    profile = "\n".join((
        f"export SSL_CERT_FILE={CA_IN_GUEST}",
        f"export NODE_EXTRA_CA_CERTS={CA_IN_GUEST}",
        f"export REQUESTS_CA_BUNDLE={CA_IN_GUEST}",
        f"export GIT_SSL_CAINFO={CA_IN_GUEST}",
        f"export PIP_CERT={CA_IN_GUEST}",
        f"export EXAMPLE_API_KEY={PLACEHOLDER}",
    )) + "\n"
    user_data = (
        "#cloud-config\n"
        "write_files:\n"
        f"  - path: {CA_IN_GUEST}\n"
        "    permissions: '0644'\n"
        "    encoding: b64\n"
        "    content: |\n"
        f"      {b64(BUNDLE.read_bytes())}\n"
        "  - path: /etc/profile.d/customs-rig.sh\n"
        "    permissions: '0644'\n"
        "    content: |\n"
        + "".join(f"      {line}\n" for line in profile.splitlines())
        + "  - path: /usr/local/bin/customs-vm-guest.py\n"
        "    permissions: '0755'\n"
        "    encoding: b64\n"
        "    content: |\n"
        f"      {b64(GUEST_SCRIPT.read_bytes())}\n"
        "  - path: /usr/local/bin/customs-vm-run\n"
        "    permissions: '0755'\n"
        "    content: |\n"
        "      #!/bin/bash\n"
        "      . /etc/profile.d/customs-rig.sh\n"
        "      exec > /dev/ttyS0 2>&1\n"
        "      echo CUSTOMS-RIG-BOOTED\n"
        "      python3 /usr/local/bin/customs-vm-guest.py\n"
        "      echo CUSTOMS-RIG-EXIT=$?\n"
        "  - path: /etc/systemd/system/customs-vm-probe.service\n"
        "    permissions: '0644'\n"
        "    content: |\n"
        "      [Unit]\n"
        "      Description=vm rig guest probe\n"
        "      [Service]\n"
        "      Type=simple\n"
        "      ExecStart=/usr/local/bin/customs-vm-run\n"
        "runcmd:\n"
        "  - [ bash, -lc, 'systemctl daemon-reload; systemctl start "
        "customs-vm-probe.service' ]\n"
    )
    (VM_DIR / "user-data").write_text(user_data)
    tool = seed_tool()
    if tool == "cloud-localds":
        run(["cloud-localds", str(SEED), "user-data", "meta-data"],
            cwd=VM_DIR)
    elif tool == "genisoimage":
        run(["genisoimage", "-quiet", "-output", str(SEED), "-volid",
             "cidata", "-joliet", "-rock", "user-data", "meta-data"],
            cwd=VM_DIR)
    else:
        run(["xorriso", "-as", "mkisofs", "-quiet", "-output", str(SEED),
             "-volid", "cidata", "-joliet", "-rock", "user-data",
             "meta-data"], cwd=VM_DIR)
    say(f"  seed built with {tool}: {SEED}")


def qemu_argv():
    return [
        "qemu-system-x86_64", "-enable-kvm", "-cpu", "host",
        "-machine", "q35", "-m", "1024", "-smp", "2",
        "-display", "none", "-serial", f"file:{VM}/serial.log",
        "-monitor", "none", "-no-reboot",
        "-netdev", "passt,id=net0",
        "-device", "virtio-net-pci,netdev=net0",
        "-device", "virtio-rng-pci",
        "-device", "virtio-serial-pci",
        "-chardev", f"file,id=probe,path={VM}/probe.log",
        "-device", "virtserialport,chardev=probe,name=customs-rig",
        "-drive", f"file={VM}/guest.qcow2,if=virtio,format=qcow2,"
                  "snapshot=on",
        "-drive", f"file={VM}/seed.iso,media=cdrom,readonly=on,"
                  "format=raw",
    ]


def create_container(image):
    run(["podman", "rm", "-f", CONTAINER], check=False)
    mounts = ["-v", f"{VM_DIR}:{VM}:Z"]
    if Path(image).resolve() != GUEST_IMAGE.resolve():
        mounts += ["-v", f"{image}:{VM}/guest.qcow2:ro,Z"]
    run(["podman", "create", "--name", CONTAINER,
         "--network", f"pasta:--map-host-loopback={LOOPBACK_MAP}",
         "--hosts-file", "image",
         "--device", "/dev/kvm",
         *mounts,
         QEMU_IMAGE, *qemu_argv()], timeout=300)
    run(["podman", "init", CONTAINER])
    pid = int(run(["podman", "inspect", "-f", "{{.State.Pid}}",
                   CONTAINER]).stdout.strip())
    say(f"  container created and initialised (pid {pid})")
    return pid


# --- reading what the guest and the inspector wrote --------------------------

def await_reports(timeout):
    """The guest's CUSTOMS-RIG lines, once its probe says done, or the
    reports so far if the container stops. None on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = PROBE_LOG.read_text(errors="replace") \
            if PROBE_LOG.exists() else ""
        reports = []
        for line in text.splitlines():
            if line.startswith("CUSTOMS-RIG "):
                try:
                    reports.append(json.loads(line[len("CUSTOMS-RIG "):]))
                except ValueError:
                    pass
        if any(r.get("probe") == "done" for r in reports):
            return reports
        if "CUSTOMS-RIG-EXIT=" in text:
            return reports
        running = run(["podman", "inspect", "-f", "{{.State.Running}}",
                       CONTAINER], check=False).stdout.strip()
        if running != "true":
            say("  the container stopped before the guest finished")
            return reports
        time.sleep(0.5)
    return None


def pick(reports, probe, **match):
    for report in reports:
        if report.get("probe") == probe and all(
                report.get(k) == v for k, v in match.items()):
            return report
    return {}


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


def chain_counter(pid, comment):
    """The egress chain's counter with this comment, in packets, or -1 if
    the chain is absent (as under --without-rules)."""
    out = in_netns(pid, ["nft", "list", "chain", "netdev", "customs",
                         "egress"], check=False).stdout
    for line in out.splitlines():
        if "packets" in line and f'comment "{comment}"' in line:
            fields = line.split()
            return int(fields[fields.index("packets") + 1])
    return -1


# --- the rows ----------------------------------------------------------------

def probe(pid, reports, secret, broker_before, neigh_empty):
    say(f"premise (programs: {LIBEXEC})")
    caps = int(next(ln.split()[1] for ln in
                    Path(f"/proc/{pid}/status").read_text().splitlines()
                    if ln.startswith("CapBnd:")), 16)
    net_admin = bool(caps & (1 << 12))
    row("premise: no CAP_NET_ADMIN in the container's bounding set",
        not net_admin, f"CapBnd={caps:016x}")
    listed = in_netns(pid, ["nft", "list", "tables"], check=False).stdout
    row("premise: the rules are in the container's netns",
        "table inet customs" in listed, listed.strip() or "no tables")
    kvm = []
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            kvm.append(os.readlink(f"/proc/{pid}/fd/{fd}"))
        except OSError:
            pass
    row("premise: qemu holds /dev/kvm open",
        any("kvm" in target for target in kvm),
        " ".join(t for t in kvm if "kvm" in t) or "no kvm fd")
    boot = pick(reports, "boot")
    container_ns = os.readlink(f"/proc/{pid}/ns/net")
    row("premise: the guest is a namespace inside the container's",
        bool(boot.get("netns")) and boot.get("netns") != container_ns,
        f"guest {boot.get('netns')} container {container_ns}")
    nft = pick(reports, "nft")
    tables = nft.get("tables") or []
    row("premise: the guest's own nft tables hold none of ours",
        bool(nft) and not any("customs" in line for line in tables),
        f"guest tables: {tables}")
    row("neighbour: the container's table was empty before the guest's "
        "first packet", neigh_empty,
        "flushed" if neigh_empty else "entries present")

    say("dns")
    want = {"udp": LOOPBACK_MAP, "tcp": LOOPBACK_MAP,
            "elsewhere": LOOPBACK_MAP, "aaaa": "nodata",
            "provider": LOOPBACK_MAP}
    dns = {r.get("label"): r for r in reports if r.get("probe") == "dns"}
    for label, expect in want.items():
        got = dns.get(label, {}).get("result")
        report = dns.get(label, {})
        row(f"dns: {label} answers {expect}", got == expect,
            f"{report.get('qtype')} {report.get('name')} over "
            f"{report.get('transport')} to {report.get('server')}: "
            f"{got!r}")
    names = [r.get("name") for label, r in dns.items()
             if label != "provider" and r.get("name")]
    asked = time.time()
    say("dns counters (waiting for the responder's next status write)")
    status = riglib.await_status(RESOLVE_STATUS.read_text, asked)
    if status is None:
        row("dns: the responder wrote its status", False,
            "not updated within 40 s")
    else:
        counted = status.get("unlisted_names", {})
        row("dns: the responder counted the guest's names, not the "
            "provider's",
            set(names) <= set(counted) and PROVIDER not in counted,
            f"unlisted_names={counted}")

    say("guest egress")
    udp = {r.get("port"): r.get("result")
           for r in reports if r.get("probe") == "udp"}
    dropped = chain_counter(pid, "dropped")
    quic = chain_counter(pid, "quic")
    row("egress: the guest's UDP sends returned and the container's chain "
        "dropped them",
        udp.get(9) == "sent" and udp.get(443) == "sent" and dropped >= 2,
        f"sends={udp}, dropped counter={dropped}")
    row("quic: the guest's UDP to 443 is counted as quic",
        quic == 1, f"quic counter={quic}")

    say("request")
    prov = pick(reports, "http", label="provider")
    body = prov.get("body") or ""
    try:
        arrived = json.loads(body).get("authorization", "")
    except ValueError:
        arrived = ""
    row("request: the provider answers 200 through inspector and broker",
        prov.get("status") == 200,
        f"http={prov.get('status')} {prov.get('error', '')}")
    row("request: the REAL key arrived at the provider",
        arrived == f"Bearer {secret}",
        "the stub reports the real key" if arrived == f"Bearer {secret}"
        else f"the stub saw {arrived!r}")
    row("request: the response names the provider's server, not a broker",
        (prov.get("server") or "").strip() == riglib.STUB_SERVER,
        f"Server: {prov.get('server')!r}")
    env = pick(reports, "env").get("vars", {})
    row("request: the guest's environment holds the placeholder only",
        env.get("EXAMPLE_API_KEY") == PLACEHOLDER
        and secret not in json.dumps(env),
        f"EXAMPLE_API_KEY={env.get('EXAMPLE_API_KEY')!r}")
    after = journal("broker").count(" ok ")
    row("request: the broker's journal logged the request",
        after == broker_before + 1,
        f"ok lines {broker_before} -> {after}")
    forwarded = [r for r in records() if r.get("host") == PROVIDER]
    hit = next((r for r in forwarded if r.get("decision") == "forward"
                and r.get("credential") == CREDENTIAL
                and r.get("status") == 200), None)
    row("request: the record says forwarded under the credential",
        hit is not None,
        f"{hit}" if hit else f"records for {PROVIDER}: {forwarded}")

    say("broker")
    bpid = broker_pid()
    tcp = [ln for ln in run(["ss", "-lntpH"]).stdout.splitlines()
           if f"pid={bpid}," in ln]
    row("broker: it holds no TCP socket", not tcp,
        "; ".join(ln.split()[3] for ln in tcp) or "none")
    own = run(["python3", "-c", CONNECT, str(BROKER_SOCKET)], check=False)
    row("broker: the user connects to it (the control)",
        own.stdout.strip() == "connected",
        own.stdout.strip() or own.stderr.strip())
    other = run(["podman", "unshare", "setpriv", "--reuid", "1",
                 "--regid", "1", "--clear-groups",
                 "python3", "-c", CONNECT, str(BROKER_SOCKET)], check=False)
    row("broker: another uid on the host is refused by the kernel",
        other.stdout.strip() == "PermissionError",
        other.stdout.strip() or other.stderr.strip())
    tcp_guest = pick(reports, "tcp", port=DROP_PORT)
    row("broker: the map accepts only the inspector's and responder's "
        "ports",
        tcp_guest.get("result") in ("TimeoutError", "timeout")
        and dropped >= 3,
        f"guest tcp to map:{DROP_PORT}={tcp_guest.get('result')!r}, "
        f"dropped counter={dropped}")

    say("unlisted")
    unl = pick(reports, "http", label="unlisted")
    row(f"unlisted: {UNLISTED} gets the inspector's 403 from the guest",
        unl.get("status") == 403,
        f"http={unl.get('status')} {unl.get('error', '')}")
    dropped_rec = [r for r in records() if r.get("host") == UNLISTED]
    hit = next((r for r in dropped_rec if r.get("decision") == "drop"
                and r.get("reason") == DROP_NOT_ALLOWLISTED
                and r.get("upstream") is None), None)
    row("unlisted: the record says dropped, 'not allowlisted', no upstream",
        hit is not None, f"{hit}" if hit else f"records: {dropped_rec}")

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
    ap.add_argument("--no-build", action="store_true",
                    help="reuse the last qemu image")
    ap.add_argument("--image", type=Path, default=GUEST_IMAGE,
                    help="the guest qcow2 (default: the rig's vm dir)")
    ap.add_argument("--guest-timeout", type=int, default=300,
                    help="seconds to wait for the guest's probes")
    ap.add_argument("--without-rules", action="store_true",
                    help="skip the netns rules; premise, egress, dns, "
                         "silent, quic, request, broker, unlisted and "
                         "counters must go red")
    ap.add_argument("--without-dns-redirect", action="store_true",
                    help="leave port 53 out of the redirect; dns, request, "
                         "unlisted and counters must go red")
    ap.add_argument("--without-neighbour-discovery", action="store_true",
                    help="leave ARP and neighbour discovery out of the "
                         "egress chain; dns, request, unlisted and counters "
                         "must go red")
    args = ap.parse_args()

    if platform.machine() != "x86_64":
        sys.exit("the VM rig is x86_64-only (qemu-system-x86_64)")
    if not Path("/dev/kvm").exists() or not os.access(
            "/dev/kvm", os.R_OK | os.W_OK):
        sys.exit("/dev/kvm is not readable and writable by the user")
    if not Path(args.image).exists():
        sys.exit(f"no guest image at {args.image}; fetch a Fedora Cloud "
                 "Base Generic qcow2 once (see tests/manual/README.md)")
    if Path(args.image).read_bytes()[:4] != b"QFI\xfb":
        sys.exit(f"{args.image} is not a qcow2 image")
    riglib.preflight(
        ("podman", "pasta", "nft", "openssl", "curl", "ss", "systemctl",
         "systemd-creds", "nsenter", "setpriv"),
        (INSPECT_TLS, INSPECT_CLEARTEXT, RESOLVE_PORT,
         riglib.PROVIDER_PORT))
    seed_tool()
    state = run(["systemctl", "--user", "is-system-running"],
                check=False).stdout.strip()
    if state not in ("running", "degraded"):
        sys.exit(f"user manager is {state or 'absent'}; log in with a "
                 "session (ssh is one)")
    RIG.mkdir(parents=True, exist_ok=True)
    VM_DIR.mkdir(parents=True, exist_ok=True)
    for stale in (STATUS, RECORD, Path(f"{STATUS}.tmp"), RESOLVE_STATUS,
                  SERIAL, PROBE_LOG):
        stale.unlink(missing_ok=True)
    secret = "sk-real-" + os.urandom(12).hex()

    say("material")
    riglib.mint_ca(STATE)
    riglib.write_bundle(ca_cert_path(STATE).read_text(), BUNDLE)
    riglib.make_stub_cert()
    riglib.write_policy(POLICY)
    seal_credential(secret)
    if not args.no_build:
        say("image")
        build_image()
    say("seed")
    write_seed()
    try:
        say("host side")
        riglib.lower_privileged_ports()
        riglib.write_hosts_entry(HOSTS_MARK)
        riglib.start_stub(secret)
        write_units()
        start_units()
        say("container")
        pid = create_container(args.image)
        if args.without_rules:
            say("  rules NOT loaded, as asked")
        else:
            load_rules(pid, not args.without_neighbour_discovery,
                       not args.without_dns_redirect)
        neigh_empty = flush_neighbours(pid)
        broker_before = journal("broker").count(" ok ")
        run(["podman", "start", CONTAINER])
        say("guest (booting)")
        reports = await_reports(args.guest_timeout)
        if reports is None:
            say(f"  the guest did not finish in {args.guest_timeout}s; "
                "serial tail:")
            say(SERIAL.read_text(errors="replace")[-2000:]
                if SERIAL.exists() else "  (no serial output)")
            say(PROBE_LOG.read_text(errors="replace")[-2000:]
                if PROBE_LOG.exists() else "  (no probe output)")
            sys.exit(1)
        probe(pid, reports, secret, broker_before, neigh_empty)
    finally:
        teardown(args.keep)

    expected = [note for flag, note in (
        (args.without_rules, "--without-rules: premise, egress, dns, "
                             "silent, quic, request, broker, unlisted and "
                             "counters are expected red"),
        (args.without_dns_redirect,
         "--without-dns-redirect: dns, request, unlisted and counters are "
         "expected red"),
        (args.without_neighbour_discovery,
         "--without-neighbour-discovery: dns, request, unlisted and "
         "counters are expected red"),
    ) if flag]
    rc = riglib.report("; ".join(expected) or None)
    if rc:
        say(f"journal: journalctl --user -u {UNIT}-inspect.service"
            f" -u {UNIT}-broker.service -u {UNIT}-resolve.service -b")
        say(f"container: podman logs {CONTAINER} (removed unless --keep)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
