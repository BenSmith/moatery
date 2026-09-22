#!/usr/bin/env python3
"""shape1_rig.py — does the pair work with nothing but a normal user?

Shape 1 of docs/DESIGN.md, as it stands: one rootless podman container
under pasta, both programs as hand-written user units, the nft rules
loaded into the container's netns, a placeholder in the container's
environment, and one real request that reaches the provider carrying the
sealed key. Run on the proving host as an ordinary user, from a checkout:

    python3 tests/manual/shape1_rig.py [--keep] [--without-rules]

Nothing here needs root except two host facts the rig cannot fake and
undoes at teardown: a line in /etc/hosts pointing the provider's name at
the stub, and `net.ipv4.ip_unprivileged_port_start` lowered so the stub can
bind :443. Both programs dial their upstream at 443 with no override --
deliberately, so a policy-matched host cannot be steered to another port
on the way out -- so the provider has to answer there.

THE ROWS

  premise   the container's bounding set holds no CAP_NET_ADMIN; the rules
            are in its netns. Without the first, the second is a suggestion.
  request   from inside, with the placeholder, the provider answers 200 and
            reports that the REAL key arrived; the container's environment
            holds only the placeholder; the inspector's record names the
            request as forwarded under the credential, and its counters
            show it named the caller (SO_ORIGINAL_DST on a host socket whose
            DNAT happened a namespace away must fall back cleanly).
  broker    from inside, the broker's address is unreachable both ways it
            could be spelled -- as the host's 127.129.0.1, which is the
            container's own loopback, and via the loopback-mapped address --
            and the broker's journal saw nothing. The control is `request`:
            pasta re-originates as the user, so a connection that arrived
            WOULD be served.
  unlisted  from inside, a host the policy does not name is refused by the
            inspector and the record says why.
  no key    from the host, the placeholder alone gets 401 from the origin;
            the real key gets 200. The second half is the control that the
            stub distinguishes at all.

`--without-rules` skips loading the netns rules and changes nothing else.
The `premise`, `request` and `unlisted` rows must go red -- the inspector
is never even activated -- and a run where they stay green is measuring
nothing.

WHAT THIS RIG TELLS THE DESIGN

Three of DESIGN.md's shape-1 facts were not facts on this host and the
recipe here is what worked:

  - podman starts pasta with `--no-map-gw`. The gateway does NOT map to the
    host's loopback; the mapping has to be asked for, and asking for a
    dedicated address (`--network pasta:--map-host-loopback=169.254.1.3`)
    reads better than borrowing the gateway.
  - the container's resolver is pasta's forwarder at 169.254.1.1 (its
    `--dns-forward`), not the gateway. The 53 rule names that.
  - the inspector recognises exactly the ports 8080 and 8443 as its planes
    (lib/egress_plane.py). "Each container gets its own inspector port" is
    not something the program supports; one container per host loopback.
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

HERE = Path(__file__).resolve().parent
CHECKOUT = HERE.parent.parent
sys.path.insert(0, str(CHECKOUT / "lib"))

from egress_ca import ca_cert_path, ca_key_path, ca_openssl_argv  # noqa
from egress_record import DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED  # noqa

NAME = "rig"
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
# What the container dials to reach the host's 127.0.0.1. pasta maps it;
# nothing else on the host's loopback is reachable from inside by any name.
LOOPBACK_MAP = "169.254.1.3"
BROKER_ADDR = "127.129.0.1"
BROKER_PORT = 8081
INSPECT_TLS, INSPECT_CLEARTEXT = 8443, 8080
PROVIDER_PORT = 443
IMAGE = "registry.fedoraproject.org/fedora:44"
CONTAINER = "customs-rig"
UNIT = "customs-rig"
HOSTS_MARK = "# customs-shape1-rig, removed at teardown"
SYSCTL = "net.ipv4.ip_unprivileged_port_start"
CA_BUNDLE_IN_CONTAINER = "/usr/local/share/ca-certificates/customs.crt"
# Where the host keeps its own trust store, first one found.
SYSTEM_BUNDLES = ("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                  "/etc/pki/tls/certs/ca-bundle.crt",
                  "/etc/ssl/certs/ca-certificates.crt")

HOME = Path.home()
RIG = HOME / ".local" / "state" / "customs-rig"
UNITS = HOME / ".config" / "systemd" / "user"
STATE = RIG / "state"
POLICY = RIG / "inspect.json"
STATUS = RIG / "inspect-status.json"
RECORD = RIG / "egress.jsonl"
BUNDLE = RIG / "bundle.pem"
STUB_CERT, STUB_KEY = RIG / "stub-cert.pem", RIG / "stub-key.pem"
CRED = RIG / f"{CREDENTIAL}.cred"

results = []
children = []
hosts_line_written = False
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


# --- preflight ---------------------------------------------------------------

def preflight():
    for tool in ("podman", "pasta", "nft", "openssl", "curl", "ss",
                 "systemctl", "systemd-creds", "nsenter"):
        if shutil.which(tool) is None:
            sys.exit(f"{tool} not found")
    if os.getuid() == 0:
        sys.exit("run this as the user, not root: the shape under test is "
                 "the one with no root in it")
    if sudo(["true"], check=False).returncode != 0:
        sys.exit("needs passwordless sudo for /etc/hosts and one sysctl")
    state = run(["systemctl", "--user", "is-system-running"],
                check=False).stdout.strip()
    if state not in ("running", "degraded"):
        sys.exit(f"user manager is {state or 'absent'}; log in with a "
                 "session (ssh is one)")
    for port in (INSPECT_TLS, INSPECT_CLEARTEXT, BROKER_PORT,
                 PROVIDER_PORT):
        held = run(["ss", "-lntH", f"sport = :{port}"], check=False).stdout
        if held.strip():
            sys.exit(f"something already listens on :{port}:\n{held}")


# --- material ----------------------------------------------------------------

def mint_ca():
    """The per-workload CA, once. Under workloadctl `workload-vm-inspect up`
    does this before the socket is ever activated; here the operator does,
    with the same openssl argv, and there is no second copy of the argv."""
    key, cert = ca_key_path(STATE), ca_cert_path(STATE)
    if key.exists() and cert.exists():
        say(f"  CA present: {cert}")
        return
    key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    run(ca_openssl_argv(NAME, key, cert, now=time.time()))
    say(f"  CA minted: {cert}")


def write_bundle():
    """The CA over the system store. The five variables REPLACE a client's
    trust store, so a bundle without the system CAs breaks every host the
    policy splices."""
    system = next((Path(p) for p in SYSTEM_BUNDLES if Path(p).exists()),
                  None)
    if system is None:
        sys.exit("no system CA bundle found at any of "
                 + ", ".join(SYSTEM_BUNDLES))
    BUNDLE.write_text(ca_cert_path(STATE).read_text() + system.read_text())
    BUNDLE.chmod(0o644)


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


def write_policy():
    POLICY.write_text(json.dumps({
        "tls": "inspect",
        "hosts": [PROVIDER],
        "internal": [],
        "splice": [],
        "http2": [],
        "policy": [{"host": PROVIDER, "methods": None, "paths": None,
                    "credential": CREDENTIAL}],
    }, indent=2) + "\n")


def seal_credential(secret):
    """`systemd-creds --user encrypt`: sealed to this user on this host,
    which is what LoadCredentialEncrypted= in a user unit can open."""
    run(["systemd-creds", "--user", "encrypt", f"--name={CREDENTIAL}",
         "-", str(CRED)], input=secret + "\n")
    CRED.chmod(0o600)


# --- the host side: stub, name, units ----------------------------------------

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


def write_hosts_entry():
    """For the two host-side dials only: the broker resolves its upstream
    itself, and the inspector dials the origin over verified TLS before it
    reads the request even on a host it will send to the broker. The
    container never consults this file; it has --add-host."""
    global hosts_line_written
    sudo(["sh", "-c", f"printf '%s\\n' '127.0.0.1 {PROVIDER} {HOSTS_MARK}'"
                      " >> /etc/hosts"])
    hosts_line_written = True


def remove_hosts_entry():
    if hosts_line_written:
        sudo(["sed", "-i", "/customs-shape1-rig/d", "/etc/hosts"],
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


def write_units():
    """Hand-written, which is the point: no generator between the operator
    and the two ExecStart= lines. PYTHONPATH because the checkout is not
    installed; a package would put lib/ beside the entrypoints instead.
    SSL_CERT_FILE hands both units the stub's certificate and REPLACES
    their trust store, which is fine only because neither dials anything
    but the stub here -- it is a rig fact, not a recipe."""
    UNITS.mkdir(parents=True, exist_ok=True)
    py = sys.executable
    env = (f"Environment=PYTHONPATH={CHECKOUT / 'lib'}\n"
           f"Environment=SSL_CERT_FILE={STUB_CERT}\n")
    (UNITS / f"{UNIT}-broker.service").write_text(
        "# written by tests/manual/shape1_rig.py — removed at teardown\n"
        "[Service]\n"
        f"ExecStart={py} {CHECKOUT / 'libexec' / 'customs-broker'}"
        f" --name {NAME} --listen {BROKER_ADDR}:{BROKER_PORT}"
        f" --caller-uid {os.getuid()}"
        f" --host {PROVIDER}={CREDENTIAL}"
        f" --placeholder {CREDENTIAL}={PLACEHOLDER}"
        f" --auth-header {CREDENTIAL}=Authorization"
        f" \"--auth-format={CREDENTIAL}=Bearer {{secret}}\"\n"
        f"LoadCredentialEncrypted={CREDENTIAL}:{CRED}\n"
        + env)
    (UNITS / f"{UNIT}-inspect.socket").write_text(
        "# written by tests/manual/shape1_rig.py — removed at teardown\n"
        "[Socket]\n"
        f"ListenStream=127.0.0.1:{INSPECT_TLS}\n"
        f"ListenStream=127.0.0.1:{INSPECT_CLEARTEXT}\n")
    (UNITS / f"{UNIT}-inspect.service").write_text(
        "# written by tests/manual/shape1_rig.py — removed at teardown\n"
        "[Service]\n"
        f"ExecStart={py} {CHECKOUT / 'libexec' / 'customs-inspect'}"
        f" --name {NAME} --policy {POLICY} --state-dir {STATE}"
        f" --status {STATUS} --record {RECORD}"
        f" --broker {BROKER_ADDR}:{BROKER_PORT}\n"
        + env)
    run(["systemctl", "--user", "daemon-reload"])


def start_units():
    run(["systemctl", "--user", "start", f"{UNIT}-broker.service"])
    pid = run(["systemctl", "--user", "show", "-p", "MainPID", "--value",
               f"{UNIT}-broker.service"]).stdout.strip()
    for _ in range(50):
        held = run(["ss", "-lntpH", f"sport = :{BROKER_PORT}"]).stdout
        if f"pid={pid}," in held:
            break
        if run(["systemctl", "--user", "is-active", f"{UNIT}-broker.service"],
               check=False).stdout.strip() != "active":
            sys.exit("broker did not stay up:\n" + journal("broker"))
        time.sleep(0.2)
    else:
        sys.exit(f"broker (pid {pid}) never listened on :{BROKER_PORT}")
    say(f"  broker listening on {BROKER_ADDR}:{BROKER_PORT} (pid {pid})")
    run(["systemctl", "--user", "start", f"{UNIT}-inspect.socket"])
    held = run(["ss", "-lntH", f"sport = :{INSPECT_TLS}"]).stdout
    if not held.strip():
        sys.exit(f"the socket unit is up but nothing holds :{INSPECT_TLS}")
    say(f"  inspector socket bound on 127.0.0.1:{INSPECT_TLS},"
        f" :{INSPECT_CLEARTEXT}")


def journal(kind):
    return run(["journalctl", "--user", "-u", f"{UNIT}-{kind}.service",
                "-o", "cat", "--no-pager", "-b"], check=False).stdout


def stop_units():
    for unit in (f"{UNIT}-inspect.socket", f"{UNIT}-inspect.service",
                 f"{UNIT}-broker.service"):
        run(["systemctl", "--user", "stop", unit], check=False)
    for unit in (f"{UNIT}-broker.service", f"{UNIT}-inspect.socket",
                 f"{UNIT}-inspect.service"):
        (UNITS / unit).unlink(missing_ok=True)
    run(["systemctl", "--user", "daemon-reload"], check=False)
    run(["systemctl", "--user", "reset-failed"], check=False)


# --- the container -----------------------------------------------------------

def create_container():
    run(["podman", "rm", "-f", CONTAINER], check=False)
    run(["podman", "create", "--name", CONTAINER,
         "--network", f"pasta:--map-host-loopback={LOOPBACK_MAP}",
         "--add-host", f"{PROVIDER}:{PROVIDER_ADDR}",
         "--add-host", f"{UNLISTED}:{UNLISTED_ADDR}",
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


def load_rules(pid, dns):
    """What replaces `meta skuid`: the rules see only this netns's traffic.
    nat output runs before filter output, so the filter matches on the
    translated destination and the accept line names the inspector's
    ports, not 80 and 443."""
    planes = f"{{ {INSPECT_TLS}, {INSPECT_CLEARTEXT} }}"
    rules = f"""
table inet customs {{
  chain out {{
    type nat hook output priority -100
    tcp dport 443 dnat ip to {LOOPBACK_MAP}:{INSPECT_TLS}
    tcp dport 80  dnat ip to {LOOPBACK_MAP}:{INSPECT_CLEARTEXT}
  }}
  chain filter {{
    type filter hook output priority 0; policy drop
    oif lo accept
    ip daddr {LOOPBACK_MAP} tcp dport {planes} accept
    ip daddr {dns} udp dport 53 accept
    ip daddr {dns} tcp dport 53 accept
  }}
}}
"""
    in_netns(pid, ["nft", "-f", "-"], input=rules)
    say("  rules loaded into the container's netns")


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
    return [json.loads(ln) for ln in RECORD.read_text().splitlines() if ln]


def await_status(after):
    """The inspector writes its counters every 30 s; wait for a write that
    postdates the probes rather than reading the one from start-up."""
    for _ in range(40 * 5):
        try:
            body = json.loads(STATUS.read_text())
            if body.get("written_at", 0) > after:
                return body
        except (OSError, ValueError):
            pass
        time.sleep(0.2)
    return None


def probe(pid, secret):
    say("premise")
    caps = int(next(ln.split()[1] for ln in
                    Path(f"/proc/{pid}/status").read_text().splitlines()
                    if ln.startswith("CapBnd:")), 16)
    net_admin = bool(caps & (1 << 12))
    row("premise: no CAP_NET_ADMIN in the container's bounding set",
        not net_admin, f"CapBnd={caps:016x}")
    listed = in_netns(pid, ["nft", "list", "tables"], check=False).stdout
    row("premise: the rules are in the container's netns",
        "table inet customs" in listed,
        listed.strip() or "no tables")

    say("request")
    before = journal("broker").count(" ok ")
    rc, code, body, err = curl_in(
        f"https://{PROVIDER}/v1/probe", "-H",
        f"Authorization: Bearer {PLACEHOLDER}")
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

    say("broker")
    before = journal("broker").count(" ok ")
    rc1, _, _, err1 = curl_in(f"http://{BROKER_ADDR}:{BROKER_PORT}/",
                              timeout=5)
    rc2, _, _, err2 = curl_in(f"http://{LOOPBACK_MAP}:{BROKER_PORT}/",
                              timeout=5)
    after = journal("broker").count(" ok ")
    row(f"broker: {BROKER_ADDR} from inside is the container's loopback",
        rc1 == 7, f"curl rc={rc1} {err1}")
    row(f"broker: {LOOPBACK_MAP}:{BROKER_PORT} from inside is unreachable",
        rc2 in (7, 28), f"curl rc={rc2} {err2}")
    row("broker: its journal saw neither dial",
        after == before, f"ok lines {before} -> {after}")

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

    say("no key")
    r = run(["curl", "-s", "--max-time", "10", "--cacert", str(STUB_CERT),
             "-o", "/dev/null", "-w", "%{http_code}",
             "-H", f"Authorization: Bearer {PLACEHOLDER}",
             f"https://{PROVIDER}/v1/probe"], check=False)
    row("no key: the origin gives the placeholder 401",
        r.stdout.strip() == "401", f"http={r.stdout.strip()!r}")
    r = run(["curl", "-s", "--max-time", "10", "--cacert", str(STUB_CERT),
             "-o", "/dev/null", "-w", "%{http_code}",
             "-H", f"Authorization: Bearer {secret}",
             f"https://{PROVIDER}/v1/probe"], check=False)
    row("no key (control): the origin gives the real key 200",
        r.stdout.strip() == "200", f"http={r.stdout.strip()!r}")

    say("counters (waiting for the inspector's next status write)")
    status = await_status(after=probe_started)
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
    for child in children:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
    restore_privileged_ports()
    remove_hosts_entry()


# --- main --------------------------------------------------------------------

probe_started = 0.0


def main():
    global probe_started
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="leave the container for inspection")
    ap.add_argument("--without-rules", action="store_true",
                    help="skip the netns rules; premise and request must "
                         "go red")
    args = ap.parse_args()

    preflight()
    RIG.mkdir(parents=True, exist_ok=True)
    for stale in (STATUS, RECORD, Path(f"{STATUS}.tmp")):
        stale.unlink(missing_ok=True)
    secret = "sk-real-" + os.urandom(12).hex()

    say("material")
    mint_ca()
    write_bundle()
    make_stub_cert()
    write_policy()
    seal_credential(secret)
    try:
        say("host side")
        lower_privileged_ports()
        write_hosts_entry()
        start_stub(secret)
        write_units()
        start_units()
        say("container")
        pid, dns = create_container()
        if args.without_rules:
            say("  rules NOT loaded, as asked")
        else:
            load_rules(pid, dns)
        run(["podman", "start", CONTAINER])
        probe_started = time.time()
        probe(pid, secret)
    finally:
        teardown(args.keep)

    failed = [r for r in results if not r[1]]
    say(f"\n{len(results) - len(failed)}/{len(results)} rows green")
    if args.without_rules:
        say("(--without-rules: premise and request are expected red)")
    for label, _, detail in failed:
        say(f"  FAIL {label}: {detail}")
    if failed:
        say(f"journal: journalctl --user -u {UNIT}-inspect.service"
            f" -u {UNIT}-broker.service -b")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
