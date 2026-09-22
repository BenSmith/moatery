#!/usr/bin/env python3
"""shape1b_rig.py — does the pair work as a sidecar, with no host install?

Shape 1b of docs/DESIGN.md: a podman pod under pasta, the sidecar image
(both programs, one container, two uids) beside a workload container, the
nft rules loaded into the pod's netns keyed on `meta skuid`, the broker on
a socket path the workload has no mount for, the key mounted as a podman
secret, and one real request that reaches the provider carrying it. Run
on the proving host as an ordinary user, from a checkout:

    python3 tests/manual/shape1b_rig.py [--keep] [--without-rules]
                                        [--no-build]

The same two host facts as shape 1 need sudo and are undone at teardown.
The image is built from the checkout on every run unless --no-build.

THE ROWS

  premise   the workload's bounding set holds neither CAP_NET_ADMIN nor
            CAP_SETUID -- the second because the uid is the selector, and
            a workload that could become the sidecar's uid would be
            exempt from its own redirect; the rules are in the pod's
            netns; the sidecar's two processes run as the two image uids.
  request   from the workload, with the placeholder, the provider answers
            200 and reports that the REAL key arrived; the workload's
            environment holds the placeholder only; the broker logged one
            request; the record says forwarded under the credential.
  broker    from the workload, connect() to the broker's socket path is
            ENOENT -- not ECONNREFUSED, which would mean the path exists
            and the mount is shared. Nothing but the inspector's two
            planes listens on TCP in the pod, so there is no address to
            spell. The broker's log did not grow.
  unlisted  from the workload, a host the policy does not name gets the
            inspector's 403 and the record says why, with no upstream.
  no key    from the host, the placeholder alone gets 401 from the origin;
            the real key gets 200.
  counters  every caller was named (the DNAT is in the same netns now, so
            SO_ORIGINAL_DST answers rather than falling back), and none
            was dropped as foreign: the inspector was told the workload's
            uid, and the workload IS another uid here.

`--without-rules` loads no rules into the pod's netns. `premise`,
`request` and `unlisted` must go red: the workload's dial reaches the
stub directly and refuses its certificate, which no bundle of the
workload's carries, and the unlisted name times out on TEST-NET.
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
    INSPECT_TLS, LOOPBACK_MAP, NAME, PLACEHOLDER, PROVIDER, RIG, STUB_CERT,
    UNLISTED, UNLISTED_ADDR, row, run, say,
)
from egress_record import DROP_FOREIGN_CALLER, DROP_NOT_ALLOWLISTED  # noqa

POD = "customs-rig-pod"
SIDECAR = "customs-rig-sidecar"
WORKLOAD = "customs-rig-workload"
SIDECAR_IMAGE = "localhost/customs-sidecar:rig"
SECRET = "customs-rig-example"
VOLUME = "customs-rig-state"
HOSTS_MARK = "customs-shape1b-rig"
# The image's two uids and their group (container/Containerfile), and the
# workload's: any uid that is neither, chosen here.
INSPECT_UID, BROKER_UID, GROUP_GID = 200, 201, 200
WORKLOAD_UID = 1000
# Inside the sidecar (container/customs-sidecar).
SOCKET_PATH = "/run/customs/broker.sock"
STATE_IN_SIDECAR = "/var/lib/customs"
POLICY_IN_SIDECAR = "/etc/customs/policy.json"
UPSTREAM_CA_IN_SIDECAR = "/etc/customs/upstream-ca.pem"

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
    SIDECAR's dials reach the stub on the host; the workload's dial to the
    same address is what the redirect catches, and it is not the pod's
    own loopback, so `oif lo` does not admit it first."""
    run(["podman", "pod", "create", "--name", POD,
         "--network", f"pasta:--map-host-loopback={LOOPBACK_MAP}",
         "--add-host", f"{PROVIDER}:{LOOPBACK_MAP}",
         "--add-host", f"{UNLISTED}:{UNLISTED_ADDR}"])


def start_sidecar():
    run(["podman", "create", "--pod", POD, "--name", SIDECAR, "--init",
         "--cap-drop", "all",
         "--cap-add", "chown,dac_override,setgid,setuid",
         "-v", f"{POLICY}:{POLICY_IN_SIDECAR}:ro,Z",
         "-v", f"{STUB_CERT}:{UPSTREAM_CA_IN_SIDECAR}:ro,Z",
         "-v", f"{VOLUME}:{STATE_IN_SIDECAR}",
         "-e", f"SSL_CERT_FILE={UPSTREAM_CA_IN_SIDECAR}",
         "--secret", f"{SECRET},target={CREDENTIAL},uid={BROKER_UID},"
                     f"gid={GROUP_GID},mode=0400",
         SIDECAR_IMAGE, "--name", NAME, "--caller-uid", str(WORKLOAD_UID),
         "--host", f"{PROVIDER}={CREDENTIAL}",
         "--placeholder", f"{CREDENTIAL}={PLACEHOLDER}",
         "--auth-header", f"{CREDENTIAL}=Authorization",
         f"--auth-format={CREDENTIAL}=Bearer {{secret}}"])
    run(["podman", "start", SIDECAR])
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


def in_netns(pid, argv, **kw):
    return run(["podman", "unshare", "nsenter", "-t", str(pid), "-n",
                *argv], **kw)


def load_rules(pid):
    """The discriminator is the uid: the two image uids are exempt from
    the redirect and the drop, since their dials are the upstream legs
    and leave through this same netns. The resolver is pasta's forwarder,
    read from the pod's resolv.conf."""
    resolv = exec_in(SIDECAR, ["cat", "/etc/resolv.conf"]).stdout
    dns = next((ln.split()[1] for ln in resolv.splitlines()
                if ln.startswith("nameserver")), "169.254.1.1")
    ours = f"{{ {INSPECT_UID}, {BROKER_UID} }}"
    planes = f"{{ {INSPECT_TLS}, {INSPECT_CLEARTEXT} }}"
    rules = f"""
table inet customs {{
  chain out {{
    type nat hook output priority -100
    meta skuid {ours} accept
    tcp dport 443 dnat ip to 127.0.0.1:{INSPECT_TLS}
    tcp dport 80  dnat ip to 127.0.0.1:{INSPECT_CLEARTEXT}
  }}
  chain filter {{
    type filter hook output priority 0; policy drop
    meta skuid {ours} accept
    oif lo accept
    ip daddr 127.0.0.1 tcp dport {planes} accept
    ip daddr {dns} udp dport 53 accept
    ip daddr {dns} tcp dport 53 accept
  }}
}}
"""
    in_netns(pid, ["nft", "-f", "-"], input=rules)
    say(f"  rules loaded into the pod's netns (resolver {dns})")


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


def probe(sidecar_pid, workload_pid, secret):
    say("premise")
    caps = caps_of(workload_pid)
    row("premise: no CAP_NET_ADMIN in the workload's bounding set",
        not caps & (1 << 12), f"CapBnd={caps:016x}")
    row("premise: no CAP_SETUID either -- the uid is the selector",
        not caps & (1 << 7), f"CapBnd={caps:016x}")
    listed = in_netns(sidecar_pid, ["nft", "list", "tables"],
                      check=False).stdout
    row("premise: the rules are in the pod's netns",
        "table inet customs" in listed, listed.strip() or "no tables")
    top = run(["podman", "top", SIDECAR, "user,args"], check=False).stdout
    who = {}
    for ln in top.splitlines()[1:]:
        user, _, argv = ln.partition(" ")
        for prog in ("customs-broker", "customs-inspect"):
            if prog in argv:
                who[prog] = user.strip()
    row("premise: the sidecar's programs run as the two image uids",
        who.get("customs-broker") in ("broker", str(BROKER_UID))
        and who.get("customs-inspect") in ("inspect", str(INSPECT_UID)),
        f"{who}")

    say("request")
    before = logs().count(" ok ")
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
    row("broker: nothing but the two planes listens on TCP in the pod",
        ports == sorted({str(INSPECT_TLS), str(INSPECT_CLEARTEXT)}),
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

    riglib.origin_rows(secret)

    say("counters (waiting for the inspector's next status write)")
    status = riglib.await_status(
        lambda: sidecar_file(f"{STATE_IN_SIDECAR}/status.json"),
        after=probe_started)
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

probe_started = 0.0


def main():
    global probe_started
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="leave the pod, its volume and the secret")
    ap.add_argument("--without-rules", action="store_true",
                    help="load no rules into the pod's netns; premise, "
                         "request and unlisted must go red")
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
        sidecar_pid = start_sidecar()
        # The CA is the sidecar's, minted into its volume on this first
        # start; the workload's bundle is built from it.
        riglib.write_bundle(
            sidecar_file(f"{STATE_IN_SIDECAR}/ca/egress-ca.crt"), BUNDLE)
        if args.without_rules:
            say("  rules NOT loaded, as asked")
        else:
            load_rules(sidecar_pid)
        workload_pid = start_workload()
        probe_started = time.time()
        probe(sidecar_pid, workload_pid, secret)
    finally:
        teardown(args.keep)

    rc = riglib.report(
        "--without-rules: premise, request and unlisted are expected red"
        if args.without_rules else None)
    if rc:
        say(f"logs: podman logs {SIDECAR}  (with --keep)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
