"""What the rigs share: the fixture customs is measured against.

One provider name and one unlisted name, which nothing on the internet
resolves, so a workload resolves them only through customs-resolve; a
stub provider on the host's :443 that answers 200 to the real key alone;
the CA, the trust bundle, the policy; two host facts that need sudo and
are undone at teardown. Each rig owns its placement -- what runs where, and
the rules -- and its rows.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKOUT = HERE.parent.parent
sys.path.insert(0, str(CHECKOUT))

# The programs under test: the checkout's, or the installed copy
# CUSTOMS_LIBEXEC names (the RPM's /usr/libexec/customs), whose package
# is installed and so is found without PYTHONPATH.
INSTALLED = os.environ.get("CUSTOMS_LIBEXEC")
LIBEXEC = Path(INSTALLED) if INSTALLED else CHECKOUT / "libexec"
PROGRAM_ENV = {} if INSTALLED else {"PYTHONPATH": str(CHECKOUT)}


NAME = "rig"
# stub_provider.py's server_version, which a brokered response must carry.
STUB_SERVER = "stub-provider/1"
PROVIDER = "provider.test"
UNLISTED = "unlisted.test"
CREDENTIAL = "example"
PLACEHOLDER = "sk-placeholder"
# What a container dials to reach the host's 127.0.0.1. pasta maps it;
# nothing else on the host's loopback is reachable from inside by any name.
LOOPBACK_MAP = "169.254.1.3"
INSPECT_TLS, INSPECT_CLEARTEXT = 8443, 8080
# What the responder answers every name with where the listeners are in the
# workload's namespace: customs-box's, which the netns recipe and the
# sidecar answer too (tests/test_quadlet_example.py, tests/test_sidecar.py).
from customs_box.units import ANSWER  # noqa: E402, F401
RESOLVE_PORT = 8053
PROVIDER_PORT = 443
IMAGE = "registry.fedoraproject.org/fedora:44"
SYSCTL = "net.ipv4.ip_unprivileged_port_start"
CA_BUNDLE_IN_CONTAINER = "/usr/local/share/ca-certificates/egress-ca.crt"
# Where the host keeps its own trust store, first one found.
SYSTEM_BUNDLES = ("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                  "/etc/pki/tls/certs/ca-bundle.crt",
                  "/etc/ssl/certs/ca-certificates.crt")

# The egress chain's first lines. A netdev egress hook sees the link layer
# as well as IP: without these the netns loses its gateway's address once
# the neighbour entry ages out, and every dial through the device fails.
# The frames reach only pasta.
NEIGHBOUR_DISCOVERY = """\
    meta protocol arp accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert,
                  nd-router-solicit } accept
"""

# One A query for example.com: "answered", "timeout", or the error class.
DNS_QUERY = """
import socket, struct, sys
q = (struct.pack("!6H", 0x5a17, 0x0100, 1, 0, 0, 0)
     + b"\\x07example\\x03com\\x00" + struct.pack("!2H", 1, 1))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    s.sendto(q, (sys.argv[1], 53))
    print("answered" if s.recv(512)[:2] == q[:2] else "garbled")
except TimeoutError:
    print("timeout")
except OSError as exc:
    print(type(exc).__name__)
"""

# One query, as the workload makes it: the first address answered,
# "nodata", "rcode N", "timeout", or the error class. argv: server, name,
# A, AAAA or HTTPS, udp or tcp.
DNS_LOOKUP = r"""
import socket, struct, sys
server, name, qtype, transport = sys.argv[1:5]
t = {"A": 1, "AAAA": 28, "HTTPS": 65}[qtype]
q = (struct.pack("!6H", 0x5a18, 0x0100, 1, 0, 0, 0)
     + b"".join(bytes([len(x)]) + x.encode() for x in name.split("."))
     + b"\0" + struct.pack("!2H", t, 1))
try:
    if transport == "tcp":
        s = socket.create_connection((server, 53), timeout=5)
        s.sendall(struct.pack("!H", len(q)) + q)
        head = s.recv(2)
        n = struct.unpack("!H", head)[0] if len(head) == 2 else 0
        r = b""
        while len(r) < n:
            chunk = s.recv(n - len(r))
            if not chunk:
                break
            r += chunk
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(q, (server, 53))
        r = s.recv(512)
except TimeoutError:
    sys.exit(print("timeout"))
except OSError as exc:
    sys.exit(print(type(exc).__name__))
if r[:2] != q[:2]:
    print("garbled")
elif r[3] & 0xF:
    print(f"rcode {r[3] & 0xF}")
elif struct.unpack("!H", r[6:8])[0] == 0:
    print("nodata")
else:
    size, family = (16, socket.AF_INET6) if t == 28 else (4, socket.AF_INET)
    print(socket.inet_ntop(family, r[-size:]))
"""

# A nameserver that is not the container's: TEST-NET, where nothing answers,
# so an answer from it is the redirect's.
ELSEWHERE_DNS = "192.0.2.53"

HOME = Path.home()
RIG = HOME / ".local" / "state" / "customs-rig"
STUB_CERT, STUB_KEY = RIG / "stub-cert.pem", RIG / "stub-key.pem"

results = []
children = []
hosts_line_written = None
sysctl_before = None


def say(msg):
    print(msg, flush=True)


def run(argv, *, check=True, timeout=60, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    return subprocess.run(argv, check=check, timeout=timeout, **kw)


def sudo(argv, **kw):
    return run(["sudo", "-n", *argv], **kw)


def row(label, ok, detail):
    results.append((label, ok, detail))
    say(f"  [{'ok' if ok else 'FAIL'}] {label}: {detail}")


def preflight(tools, ports):
    import shutil
    for tool in tools:
        if shutil.which(tool) is None:
            sys.exit(f"{tool} not found")
    if os.getuid() == 0:
        sys.exit("run this as the user, not root: the placement under test is "
                 "the one with no root in it")
    if sudo(["true"], check=False).returncode != 0:
        sys.exit("needs passwordless sudo for /etc/hosts and one sysctl")
    for port in ports:
        held = run(["ss", "-lntH", f"sport = :{port}"], check=False).stdout
        if held.strip():
            sys.exit(f"something already listens on :{port}:\n{held}")


# --- material ----------------------------------------------------------------

def mint_ca(state):
    """The per-workload CA, once, kept across runs like an SSH host key.
    The operator's job on the host, done the operator's way: by running
    customs-mint-ca. In the sidecar it is the entrypoint's."""
    done = run([sys.executable, str(LIBEXEC / "customs-mint-ca"),
                "--name", NAME, "--state-dir", str(state)],
               env={**os.environ, **PROGRAM_ENV})
    say(f"  {done.stderr.strip()}")


def write_bundle(ca_pem, bundle):
    """The CA over the system store. The five variables REPLACE a client's
    trust store, so a bundle without the system CAs breaks every host the
    policy splices."""
    system = next((Path(p) for p in SYSTEM_BUNDLES if Path(p).exists()),
                  None)
    if system is None:
        sys.exit("no system CA bundle found at any of "
                 + ", ".join(SYSTEM_BUNDLES))
    bundle.write_text(ca_pem + system.read_text())
    bundle.chmod(0o644)


def make_stub_cert():
    """A self-signed CA-and-leaf for the stub, valid two days. Both programs
    verify their upstream with no way to skip it, so the stub needs a
    certificate that passes VERIFY_X509_STRICT: basicConstraints and
    keyUsage are what Python 3.13+ demands of a trust anchor."""
    if STUB_CERT.exists() and STUB_KEY.exists():
        fresh = run(["openssl", "x509", "-checkend", "3600", "-noout",
                     "-in", str(STUB_CERT)], check=False)
        if fresh.returncode == 0:
            return
        say("  stub certificate expired — regenerating")
    run(["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
         "-keyout", str(STUB_KEY), "-out", str(STUB_CERT), "-days", "2",
         "-subj", f"/CN={PROVIDER}",
         "-addext", f"subjectAltName=DNS:{PROVIDER}",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,digitalSignature"])
    STUB_CERT.chmod(0o644)
    say(f"  stub certificate for {PROVIDER}: {STUB_CERT}")


def write_policy(path):
    path.write_text(json.dumps({
        "tls": "inspect",
        "hosts": [PROVIDER],
        "internal_expected": [],
        "splice": [],
        "policy": [{"host": PROVIDER, "methods": None, "paths": None,
                    "credential": CREDENTIAL}],
    }, indent=2) + "\n")
    path.chmod(0o644)


# --- the host side: ports, name, stub ---------------------------------------

def lower_privileged_ports():
    global sysctl_before
    sysctl_before = run(["sysctl", "-n", SYSCTL]).stdout.strip()
    if int(sysctl_before) > PROVIDER_PORT:
        sudo(["sysctl", "-q", "-w", f"{SYSCTL}={PROVIDER_PORT}"])
        say(f"  {SYSCTL}: {sysctl_before} -> {PROVIDER_PORT}")


def restore_privileged_ports():
    if sysctl_before is not None and int(sysctl_before) > PROVIDER_PORT:
        sudo(["sysctl", "-q", "-w", f"{SYSCTL}={sysctl_before}"],
             check=False)
        say(f"  {SYSCTL}: restored to {sysctl_before}")


def write_hosts_entry(mark):
    """For host-side dials of the provider's name only. podman seeds a
    container's hosts file from this one, so every rig's container or pod
    is created with `--hosts-file image`."""
    global hosts_line_written
    sudo(["sh", "-c", f"printf '%s\\n' '127.0.0.1 {PROVIDER} # {mark}, "
                      "removed at teardown' >> /etc/hosts"])
    hosts_line_written = mark


def remove_hosts_entry():
    if hosts_line_written:
        sudo(["sed", "-i", f"/{hosts_line_written}/d", "/etc/hosts"],
             check=False)


def start_stub(secret):
    log = open(RIG / "stub.log", "w")
    stub = subprocess.Popen(
        [sys.executable, str(HERE / "stub_provider.py"), str(PROVIDER_PORT),
         str(STUB_CERT), str(STUB_KEY)],
        stdout=log, stderr=log, env={**os.environ, "STUB_SECRET": secret})
    children.append(stub)
    for _ in range(50):
        if stub.poll() is not None:
            sys.exit("stub provider died:\n"
                     + (RIG / "stub.log").read_text()[-2000:])
        held = run(["ss", "-lntpH", f"sport = :{PROVIDER_PORT}"]).stdout
        if f"pid={stub.pid}," in held:
            say(f"  stub provider on :{PROVIDER_PORT} (pid {stub.pid})")
            return
        time.sleep(0.2)
    sys.exit("stub provider never listened")


def stop_children():
    for child in children:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()


# --- reading what the inspector wrote ---------------------------------------

def parse_records(text):
    return [json.loads(ln) for ln in text.splitlines() if ln]


def await_status(read, after):
    """The inspector writes its counters every 30 s; wait for a write that
    postdates the probes rather than reading the one from start-up.
    `read` returns the file's text or raises."""
    for _ in range(40 * 5):
        try:
            body = json.loads(read())
            if body.get("written_at", 0) > after:
                return body
        except (OSError, ValueError):
            pass
        time.sleep(0.2)
    return None


# --- rows every placement shares ---------------------------------------------

def origin_rows(secret):
    """From the host, straight at the stub: the placeholder alone gets
    401 and the real key 200. The second half is the control that the
    stub distinguishes at all."""
    say("no key")
    for label, token, want in (
            ("no key: the origin gives the placeholder 401", PLACEHOLDER,
             "401"),
            ("no key (control): the origin gives the real key 200", secret,
             "200")):
        r = run(["curl", "-s", "--max-time", "10", "--cacert",
                 str(STUB_CERT), "-o", "/dev/null", "-w", "%{http_code}",
                 "-H", f"Authorization: Bearer {token}",
                 f"https://{PROVIDER}/v1/probe"], check=False)
        row(label, r.stdout.strip() == want, f"http={r.stdout.strip()!r}")


def dns_rows(ask, resolver, synthesised, read_status):
    """The workload's DNS goes to customs-resolve and nowhere else.

    `ask(argv)` runs DNS_LOOKUP as the workload, in its netns, and returns what
    it printed; `resolver` is the container's first nameserver; `synthesised`
    the address every name should get; `read_status` returns the responder's
    status file's text. The names are fresh each run, and nothing on the
    internet resolves them, so an answer at all is the responder's; the status
    file naming them is the observation that they arrived there, and the
    provider's name absent from it is the control that it counts against the
    policy. The provider's name is asked of a nameserver that does not exist,
    since pasta's forwarder answers it from the host's hosts file, with the
    rig's own 127.0.0.1: only the redirect answers a query sent there, whatever
    address the placement's responder gives. The file is awaited from after
    the queries: a socket-activated responder first writes it at start,
    which is after the first query arrived and before it was counted.
    """
    say("dns")
    tag = os.urandom(4).hex()
    name = {k: f"{k}-{tag}.exfil.test"
            for k in ("udp", "tcp", "elsewhere", "aaaa")}
    for label, server, qname, qtype, transport, want in (
            ("an unlisted name is answered with the inspector's address, "
             "over UDP", resolver, name["udp"], "A", "udp", synthesised),
            ("the same over TCP", resolver, name["tcp"], "A", "tcp",
             synthesised),
            ("a query to another nameserver is answered the same",
             ELSEWHERE_DNS, name["elsewhere"], "A", "udp", synthesised),
            ("an AAAA query gets no records", resolver, name["aaaa"],
             "AAAA", "udp", "nodata"),
            ("the provider's name is answered the same", ELSEWHERE_DNS,
             PROVIDER, "A", "tcp", synthesised)):
        got = ask([server, qname, qtype, transport])
        row(f"dns: {label}", got == want,
            f"{qtype} {qname} over {transport} to {server}: {got!r}")
    asked = time.time()
    say("dns counters (waiting for the responder's next status write)")
    status = await_status(read_status, asked)
    if status is None:
        row("dns: the responder wrote its status", False,
            "not updated within 40 s")
        return
    counted = status.get("unlisted_names", {})
    row("dns: the responder counted the unlisted names, not the provider's",
        set(name.values()) <= set(counted) and PROVIDER not in counted,
        f"unlisted_names={counted}")


def report(expect_red=None):
    failed = [r for r in results if not r[1]]
    say(f"\n{len(results) - len(failed)}/{len(results)} rows green")
    if expect_red:
        say(f"({expect_red})")
    for label, _, detail in failed:
        say(f"  FAIL {label}: {detail}")
    return 1 if failed else 0
