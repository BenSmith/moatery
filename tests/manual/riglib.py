"""What the rigs share: the fixture the pair is measured against.

One provider name and one unlisted name, both resolving to TEST-NET
addresses so nothing admits them by accident; a stub provider on the
host's :443 that answers 200 to the real key alone; the CA, the trust
bundle, the policy; two host facts that need sudo and are undone at
teardown. Each rig owns its shape -- what runs where, and the rules --
and its rows.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKOUT = HERE.parent.parent
sys.path.insert(0, str(CHECKOUT / "lib"))

from egress_ca import ca_cert_path, ca_key_path, ca_openssl_argv  # noqa

NAME = "rig"
# stub_provider.py's server_version, which a brokered response must carry.
STUB_SERVER = "stub-provider/1"
PROVIDER = "provider.test"
UNLISTED = "unlisted.test"
CREDENTIAL = "example"
PLACEHOLDER = "sk-placeholder"
# TEST-NET addresses: the container has to resolve both names to something
# that is not its own loopback, or `oif lo accept` admits the dial and the
# redirect never sees it. Neither address is ever reached: the DNAT rewrites
# the destination before routing, and the inspector keys on the SNI.
PROVIDER_ADDR = "203.0.113.1"
UNLISTED_ADDR = "203.0.113.2"
# What a container dials to reach the host's 127.0.0.1. pasta maps it;
# nothing else on the host's loopback is reachable from inside by any name.
LOOPBACK_MAP = "169.254.1.3"
INSPECT_TLS, INSPECT_CLEARTEXT = 8443, 8080
PROVIDER_PORT = 443
IMAGE = "registry.fedoraproject.org/fedora:44"
SYSCTL = "net.ipv4.ip_unprivileged_port_start"
CA_BUNDLE_IN_CONTAINER = "/usr/local/share/ca-certificates/customs.crt"
# Where the host keeps its own trust store, first one found.
SYSTEM_BUNDLES = ("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                  "/etc/pki/tls/certs/ca-bundle.crt",
                  "/etc/ssl/certs/ca-certificates.crt")

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
        sys.exit("run this as the user, not root: the shape under test is "
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
    The operator's job in shape 1, with the program's own openssl argv;
    the sidecar entrypoint's in shape 1b."""
    key, cert = ca_key_path(state), ca_cert_path(state)
    if key.exists() and cert.exists():
        say(f"  CA present: {cert}")
        return
    key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    run(ca_openssl_argv(NAME, key, cert, now=time.time()))
    say(f"  CA minted: {cert}")


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
        "internal": [],
        "splice": [],
        "http2": [],
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
    """For host-side dials of the provider's name only. A container never
    consults this file; it has --add-host."""
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


# --- rows every shape shares -------------------------------------------------

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


def report(expect_red=None):
    failed = [r for r in results if not r[1]]
    say(f"\n{len(results) - len(failed)}/{len(results)} rows green")
    if expect_red:
        say(f"({expect_red})")
    for label, _, detail in failed:
        say(f"  FAIL {label}: {detail}")
    return 1 if failed else 0
