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
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import riglib  # noqa
from riglib import (  # noqa
    CA_BUNDLE_IN_CONTAINER, CHECKOUT, CREDENTIAL, IMAGE, INSPECT_CLEARTEXT,
    INSPECT_TLS, LOOPBACK_MAP, NAME, PLACEHOLDER, PROVIDER, PROVIDER_ADDR,
    RIG, STUB_CERT, UNLISTED, UNLISTED_ADDR, row, run, say,
)
from egress_ca import ca_cert_path  # noqa
from egress_record import DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED  # noqa

BROKER_ADDR = "127.129.0.1"
BROKER_PORT = 8081
CONTAINER = "customs-rig"
UNIT = "customs-rig"
HOSTS_MARK = "customs-shape1-rig"

UNITS = riglib.HOME / ".config" / "systemd" / "user"
STATE = RIG / "state"
POLICY = RIG / "inspect.json"
STATUS = RIG / "inspect-status.json"
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
    return riglib.parse_records(RECORD.read_text())


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
        and "customs" not in head.lower(), server)
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

    riglib.origin_rows(secret)

    say("counters (waiting for the inspector's next status write)")
    status = riglib.await_status(STATUS.read_text, after=probe_started)
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

    riglib.preflight(
        ("podman", "pasta", "nft", "openssl", "curl", "ss", "systemctl",
         "systemd-creds", "nsenter"),
        (INSPECT_TLS, INSPECT_CLEARTEXT, BROKER_PORT, riglib.PROVIDER_PORT))
    state = run(["systemctl", "--user", "is-system-running"],
                check=False).stdout.strip()
    if state not in ("running", "degraded"):
        sys.exit(f"user manager is {state or 'absent'}; log in with a "
                 "session (ssh is one)")
    RIG.mkdir(parents=True, exist_ok=True)
    for stale in (STATUS, RECORD, Path(f"{STATUS}.tmp")):
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

    rc = riglib.report(
        "--without-rules: premise and request are expected red"
        if args.without_rules else None)
    if rc:
        say(f"journal: journalctl --user -u {UNIT}-inspect.service"
            f" -u {UNIT}-broker.service -b")
    return rc


if __name__ == "__main__":
    sys.exit(main())
