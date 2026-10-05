# Manual rigs

Checks that need a real host and cannot run under `just test`. Each is
invoked by hand, as an ordinary user, from a checkout on the proving host.
Nothing here is a unit gate; these are the gate the unit suites cannot be.

The host and netns rigs run the checkout's programs, or with
`MOATERY_LIBEXEC=/usr/libexec/moatery` the installed RPM's, with no
`PYTHONPATH`; the premise line names which.

## Writing a row here

Every real defect the pair has had was correct code nothing connected to,
or a packet that never arrived, and the unit suite was green at every one.
A rig is what sees the seam, and a rig has blind spots of its own. The
rules below were each paid for by a defect that shipped past a green row.

**Probe the window, not the settled state.** A control that arms too
late — a filter, a policy load, a cgroup move — is indistinguishable from
a correct one by the time anything probes it. If a row sleeps before it
measures, ask what it would miss. Here the rules go into the netns
between `podman init` and `podman start`, and the row's request is the
container's first packet.

**Assert an observation, not the presence of a string.** Read what the
manager loaded, what the far side received, what the record wrote — not
the file that was meant to produce it. Where the property is "this must
not arrive", the observation is the receiver's log not growing, and the
control is a request that does arrive and does grow it.

**Pin the premise as its own row.** "The rules are in the netns" matters
only because the container cannot touch them; without a row for the
missing `CAP_NET_ADMIN`, the rules are a suggestion.

**A row can assert the defect and pass on it.** A row that pins a message
is green over a bug once the message becomes the wrong one. When the
product changes what it says, the row is re-derived from what it should
now say, never edited until it passes again.

**Check the fixture cannot satisfy the property by accident.** The rig's
own `/etc/hosts` line for the provider reached the containers, since
podman seeds a container's hosts file from the host's, and sent the
workload to its own loopback; and pasta's forwarder answered the same
name from the same line, with the address the responder gives in two
placements, so a DNS row passed with no responder at all. Where a row asserts
something is blocked, a control row proves an unblocked caller reaches
the same fixture, or a responder that never started satisfies every
assertion.

**Refused is not blocked.** Connection refused means the packet arrived
and nothing was listening, which is a broken fixture reporting itself as
a working filter. A drop presents as `EPERM` or a timeout.

**A run must be able to go red.** Every rig takes a flag that leaves out
the control it is about, and the rows that depend on it must fail under
that flag. A rig that has only ever passed has not been shown to measure.

`riglib.py` is the fixture the rigs share: the provider and unlisted
names, which nothing on the internet resolves, the stub, the CA and
bundle, the policy, the two sudo facts and their teardown, and the rows
every placement has (the workload's DNS, the origin's 401 and 200). A
rig owns its placement and its rows.

## host_rig.py — moatery with nothing but a normal user

`docs/DESIGN.md`, "Host": one rootless podman container under pasta,
the programs as hand-written user units, the nft rules loaded into the
container's netns through `podman unshare nsenter`, a placeholder in the
container's environment, and one real request that reaches the provider
carrying the sealed key.

```bash
python3 tests/manual/host_rig.py                  # every row green
python3 tests/manual/host_rig.py --without-rules  # must go red
python3 tests/manual/host_rig.py --without-dns-redirect  # dns red
python3 tests/manual/host_rig.py --broker-over-tcp  # the broker rows red
```

Runs as the user. Two host facts need `sudo`, and both are undone at
teardown: a line in `/etc/hosts` pointing `provider.test` at the stub,
and `net.ipv4.ip_unprivileged_port_start` lowered so the stub can bind
`:443` — both programs dial their upstream at 443 with no override, on
purpose, so the provider has to answer there. The stub
(`stub_provider.py`) returns 200 only to the real key and reports in the
body which `Authorization` arrived, so "200" means the substitution
happened and the placeholder alone measurably gets 401.

The per-workload CA is minted once into `~/.local/state/moatery-rig/` and
kept, like an SSH host key; everything else is rebuilt per run. `--keep`
leaves the container for inspection.

**Rows.** Premise (no `CAP_NET_ADMIN`; the table is in the netns). DNS:
the workload's queries for names nothing resolves, to its resolver over
UDP and TCP and to a nameserver that does not exist, are answered with
the loopback map; an AAAA gets no records; the provider's name is
answered the same; the responder's status names the unlisted names and
not the provider's. The container has no `--add-host`, so the request
and unlisted rows resolve through the responder too. A filtered UDP
send returns without error while the drop counter moves, and one to
443 moves the `quic` counter too. HTTP/2: curl offering h2 gets 200
over HTTP/1.1; HTTP/2's preface on the cleartext plane is recorded as
refused with 400 and noted once; an HTTPS query gets no records, a
responder line and a count under `https`. The request (200;
the real key arrived; the container's environment holds
the placeholder only; the broker's journal grew by one; the record says
`forward` under the credential). The broker's address is unreachable
from inside both ways it can be spelled, and its journal did not grow.
An unlisted host gets the inspector's own 403 and a record saying
`not allowlisted` with no upstream. The origin gives the placeholder 401
and the real key 200. The counters name every caller and dropped none as
foreign.

**What it found, first run, 2026-09-22.** No defect in the pair. Four in
the host recipe as `DESIGN.md` had it, which is now corrected:

- podman starts pasta with `--no-map-gw`, so the gateway does not map to
  the host's loopback. The mapping is asked for with
  `--network pasta:--map-host-loopback=169.254.1.3`, a dedicated address.
- the container's resolver is pasta's forwarder (`169.254.1.1`), not the
  gateway; the DNS rule names that address.
- the policy's TLS mode is `"inspect"`, not `"terminate"`. The loader did
  not then validate the value, so the misspelling would have started a
  listener that refuses every terminated handshake for want of a minter.
  It refuses an unknown mode at start now.
- the inspector recognises exactly ports 8080 and 8443 as its planes, so
  "each container gets its own inspector port" is not something the
  program supports today: one inspected container per host loopback.

And two facts for the packaging step: the entrypoints find their modules
by `sys.path` only, so a checkout needs `PYTHONPATH` in the unit (an
install puts the package where Python looks); and nothing minted the CA, so the operator had
to, before the socket was first activated. `moat-mint-ca` is that
step now.

`SO_ORIGINAL_DST` on a host socket whose DNAT happened a namespace away
falls back to `getsockname()` cleanly: `caller_unresolved` is 0 and the
caller check admitted every connection as the user's.

**What it found, the responder, 2026-09-24.** 26/26;
`--without-dns-redirect` 10/25, with dns, request, neighbour, unlisted
and the inspector's counters red (the queries time out at the egress
drop, and nothing ever activates the inspector); `--without-rules` 8/25.
No defect in the responder. Three facts, two of them the rig's:

- podman seeds a container's `/etc/hosts` from the host's, and a name in
  it is never asked. The rig's own line for the provider sent curl to
  the container's loopback, where the DNAT to the map cannot route. The
  containers here and in the recipes are created with
  `--hosts-file image`.
- a socket-activated responder writes its first status when the first
  query starts it, after that query arrived and before it was counted.
  The DNS rows await a write from after their queries.
- pasta carries UDP over the loopback map in both directions, so the
  responder can sit on the host's `127.0.0.1` beside the inspector.

**What it found, HTTP/2, 2026-09-30.** 33/33; `--without-rules` 8/31
and `--without-dns-redirect` 11/31, the five `h2` rows red in both. No
defect in the pair. Two in the rows as first written:

- curl with `--http2-prior-knowledge` cannot read an HTTP/1.1 answer
  and exits 16 with no status, so the 400 is read from the record.
- the HTTPS query first asked for the provider's name, and without
  rules two rows stayed green: pasta's forwarder answers it nodata from
  the host's hosts file, and the previous run's responder line was
  still in the journal. It asks for a fresh name now.

## netns_rig.py — the listeners in the container's netns

`docs/DESIGN.md`, "Netns": host_rig's container under plain pasta, with
no loopback map, and host_rig's broker unit. The inspector and the responder
are transient user units started between `podman init` and `podman
start`, through `moat-netns-listen`, which binds their sockets in the
container's network namespace and execs each program with its own.

```bash
python3 tests/manual/netns_rig.py                        # every row green
python3 tests/manual/netns_rig.py --without-rules        # must go red
python3 tests/manual/netns_rig.py --without-netns-pid    # inspector red
python3 tests/manual/netns_rig.py --without-dns-redirect # dns red
python3 tests/manual/netns_rig.py --without-notify       # ready red
```

**Rows.** host_rig's premise, DNS, silent-drop, quic, request, broker,
unlisted, origin and counter rows, and four of its own. The inspector is
up on the listeners it was handed, and their inodes are rows in the
container's socket table and in none of the host's. Nothing listens on
the host's `127.0.0.1` at either plane, for the user or another uid;
the request row, which reaches the same planes from inside, is the
control. The request's 200 is also the observation that the inspector's
upstream dial left from the host's namespace: the stub is on the host's
`127.0.0.1`, which the container cannot reach. A request from another
uid inside the container (65534, a subuid outside) is served too: the
inspector serves every uid of the container's user namespace, which is
what sudo inside needs.

The listener units are `Type=notify`: when `systemd-run` returned, each
unit's ports were already listening in the container's namespace.
`--without-notify` starts them as `Type=simple`, and on the proving host
neither had bound anything by then.

`--without-netns-pid` starts the inspector without the flag. It must
refuse to start, since its lookups would read the host's table, which
the listeners are not in, so inspector, request, unlisted and counters
go red.

**What it found, first run, 2026-09-24.** 21/21, and each flag red where
it should be: `--without-rules` 13/21, `--without-neighbour-discovery`
20/21 (the gateway `FAILED`, the query timed out),
`--without-netns-pid` 11/20 with the inspector's refusal in the journal.
No defect in the pair. Two facts for the design:

- joining the container's namespaces needs no podman. The user owns the
  container's user namespace, so a child holding a pidfd of the
  container's process can `setns` into its user and network namespaces
  together, and bind there.
- the caller check reads a different socket in this placement. On the
  host the inspector's peer is pasta's host socket, which is always the
  user's; here it is the workload's own, in the container's table, with
  the uid the host sees: the user for container root, a subuid for
  anything else.

**What it found, the responder, 2026-09-24.** 26/26;
`--without-dns-redirect` 14/26 (dns, request, unlisted); `--without-rules`
12/26. With the responder in the namespace nothing the workload may send
crosses the egress device, so the chain accepts nothing: the neighbour
row, which queried pasta's forwarder, went with the resolver's lines,
and `--without-neighbour-discovery` with it.

## sidecar_rig.py — moatery as a sidecar, with no host install

`docs/DESIGN.md`, "Sidecar": a podman pod under pasta, the sidecar image
(`container/`: the programs, one container, two uids) beside a workload
container running as a third uid with no capabilities, the nft rules in
the pod's netns keyed on `meta skuid`, the broker on a socket path under
the sidecar's own `/run`, the key as a podman secret, and one real request
that reaches the provider carrying it.

```bash
python3 tests/manual/sidecar_rig.py                  # builds the image first
python3 tests/manual/sidecar_rig.py --without-rules  # must go red
python3 tests/manual/sidecar_rig.py --without-private-drop  # private red
python3 tests/manual/sidecar_rig.py --without-dns-redirect  # dns red
python3 tests/manual/sidecar_rig.py --no-build       # reuse the last image
```

The image is built from the checkout on each run; the state volume and
the secret are removed at teardown, so the CA is the sidecar's and is
minted afresh each run. `--keep` leaves the pod, the volume and the
secret.

**Rows.** Premise (the workload holds neither `CAP_NET_ADMIN` nor
`CAP_SETUID`; the table is in the pod's netns; `podman top` shows the
broker and the inspector as the two image users and the responder as the
inspector's, and the supervising pid 1 holds no capability). host_rig's
DNS rows, answered by the sidecar's responder with the pod's loopback;
the unlisted row resolves through it too, while the provider's name is
in the pod's hosts file, which the sidecar's dials need. host_rig's
silent-drop and quic rows. The request (200; the real key arrived; the
workload's environment holds the placeholder only; the broker's log grew
by one; the record says `forward` under the credential with `upstream`
naming the socket path). The broker's path is ENOENT from the workload
-- `stat` says "No such file or directory", which curl alone cannot
distinguish from a refusal -- and nothing but the two planes and the
responder's port listens on TCP in the pod, so there is no address to
spell; its log did not grow. An unlisted host gets the 403 and the
record. The private rows: the egress chain carries `DESIGN.md`'s
private-space drop and an accept line for the provider, which is on the
host's mapped loopback and so link-local; with that line deleted the
workload's request gets no 200, the stub's log does not grow and the
drop's counter moves, and with it put back the same request arrives. The
programs' own DNS query to the resolver is answered. The origin's two
rows. The counters name every caller and dropped none as foreign, with
the workload being another uid. Last, the lifecycle: the broker killed
from outside ends the container non-zero and the restart policy brings
it back (the restart count rose; every exit is in the log), the
restarted programs serve the workload's request under the CA its bundle
already holds, and a stop reaches every program well inside podman's
timeout and exits 0.

**What it found, first run, 2026-09-22.** One defect in the pair, the
seam kind: `peer_identity.userns_ranges` read the *outside* column of
`/proc/self/uid_map`. The uid the broker is told and the uids the kernel
reports to it are both inside values, and every layout the pair had run
under -- the initial namespace, `PrivateUsers=` -- had the two columns
equal, so the check passed everywhere it was tried and refused every uid
the first rootless broker had ("this user namespace cannot represent uid
200"). Fixed to the inside column; a unit test with a rootless map now
holds it, and the same check runs in the inspector under `--caller-uid`.

Two facts for the design, both now in `DESIGN.md`: nothing in the sidecar
needs `systemd-socket-activate` -- the entrypoint binds the planes as
root and hands them down as fds 3 and 4 with `LISTEN_PID`/`LISTEN_FDS`
set, then starts the inspector as its uid, which is the socket unit's
property (the bind is not the inspector's) by a different route;
and the entrypoint needs exactly `chown,dac_override,setgid,setuid` on
top of `--cap-drop all`, all of which `setuid()` clears before either
program runs. `SO_ORIGINAL_DST` answers in the pod rather than falling
back, since the DNAT is in the same netns: `caller_unresolved` is 0.

**What it found, the lifecycle rows, 2026-09-23.** Three defects in the
entrypoint, none of which the earlier rows could see because each run
started one fresh container and tore it down:

- a stop never arrived. `--init`'s catatonit runs as root without
  `CAP_KILL` and cannot signal uid 200, so every stop waited out the
  timeout and ended in SIGKILL (exit 137), and the inspector never wrote
  its last status. The entrypoint is pid 1 now and refuses `--init`.
- a second start on the same volume failed: the directory was already
  the inspector's, and the chmod that came first needs `CAP_FOWNER`.
- a dead broker left the inspector up and the container running, so no
  restart policy fired. The entrypoint supervises both now.

Seen red against the entrypoint before the fix: the three lifecycle rows
failed. The capability row was seen red against an image whose
supervisor skipped its drop (`CapEff=c3`), which also failed two
lifecycle rows: a root supervisor without `CAP_KILL` cannot stop the
inspector, so the uid arrangement is what makes the stop work.

**What it found, the private rows, 2026-09-24.** One defect in the
recipe as `DESIGN.md` had it: the private-space drop went before the
blanket accept, which came before the resolver's lines, so it dropped
the programs' own DNS to pasta's link-local resolver. The rig hid this
because `--add-host` pins every name the programs dial. Seen red with
the lines in that order (the DNS row, `timeout`); the resolver's lines
now come first, in the recipe and here. 29/29; `--without-private-drop`
27/29, the two drop rows red. The request the drop refuses is brokered,
so its record is the inspector's `forward` with the broker's 502, not
`internal destination`: that report is for the inspector's own dial.

**What it found, the responder, 2026-09-24.** 35/35;
`--without-dns-redirect` 27/35 (dns and unlisted; the resolver's accept
lines are the programs' now); `--without-rules` 15/35. In the first
version the provider's DNS row stayed green under `--without-rules`:
pasta's forwarder answered the name from the host's hosts file, with
the rig's own `127.0.0.1`, the address the responder gives in the pod.
The name is asked of a nameserver that does not exist now, which only
the redirect answers. `--without-rules` also turns neighbour and
private red, which its note had left out.

## vm_rig.py — moatery under a VM

`docs/DESIGN.md`, "VM": one rootless podman container under pasta whose
only payload is qemu and the passt backend qemu starts itself, the
guest's egress re-originated by passt as sockets in the container's
netns, moatery as host_rig's hand-written user units on the host, the
nft rules loaded into the container's netns, and a workload inside the
guest that reaches the provider carrying the sealed key.

```bash
python3 tests/manual/vm_rig.py                  # builds the qemu image first
python3 tests/manual/vm_rig.py --without-rules  # must go red
python3 tests/manual/vm_rig.py --without-dns-redirect  # dns red
python3 tests/manual/vm_rig.py --without-neighbour-discovery  # dns red
python3 tests/manual/vm_rig.py --no-build       # reuse the last image
python3 tests/manual/vm_rig.py --keep           # leave the container
```

Runs as the user, on a KVM host with `/dev/kvm` readable and writable.
The operator puts a Fedora Cloud Base Generic qcow2 at
`~/.local/state/moatery-rig/vm/guest.qcow2` once (44-1.7 was used);
the rig builds its own qemu image from `vm.Containerfile`. The guest
probe (`vm_guest.py`) goes in through the NoCloud seed with the CA
bundle and the agent's environment, and reports on a virtio-serial port
the host reads as a file.

**Rows.** Premise (no `CAP_NET_ADMIN` in the container; the table is in
its netns; qemu holds `/dev/kvm`; the guest is a namespace inside the
container's; the guest's own nft tables hold none of ours; the neighbour
table is flushed before the guest's first packet). The guest's UDP sends
return while the container chain's `dropped` counter moves -- the guest's
egress IS the container's. host_rig's DNS rows, asked from inside the
guest. The silent-drop and quic rows. The request (200; the real key
arrived; the response names the provider's server; the guest's
environment holds the placeholder only; the broker's journal grew by one;
the record says `forward` under the credential). The broker's rows, plus
a guest connect to a map port nothing accepts (timeout, drop counter).
The unlisted row. The origin's two rows. The counters.

**What it found, first run, 2026-09-28.** 30/30; `--without-rules` 11/29,
`--without-dns-redirect` 15/29, `--without-neighbour-discovery` 13/29. No
defect in the pair. Four facts, all in the guest half:

- cloud-init's `scripts_user` caps a `runcmd` at about ten seconds and
  fails the module when it overruns, killing the command. A probe that
  can outlast that -- every red run -- has to be a systemd unit, not a
  `runcmd`.
- a systemd unit whose output goes to `/dev/ttyS0` stops at a write: the
  process ran (a busy loop advanced its clock) but the next write to the
  tty never returned, and the probe froze mid-row. The results go on a
  virtio-serial port (`-chardev file:...`) instead; the serial console
  stays for boot diagnostics.
- the guest's resolver is systemd-resolved's stub. The probe reads the
  uplink from `/run/systemd/resolve/resolv.conf` and queries it directly,
  and pins each HTTPS connection to the address the responder gave with
  the name in SNI, so neither depends on resolved's `.test` handling.
- qemu 10.2's `-netdev passt,id=net0` starts passt itself, in the
  container's netns, with no separate process and no shell entrypoint;
  the guest's DNS reaches pasta's forwarder through passt, where the
  port-53 DNAT claims it. SELinux in Enforcing needed no extra flag for
  `--device /dev/kvm` or the bind mount.

## vm_placement_rig.py — a VM in the netns and sidecar placements

vm_rig.py's qemu container and guest, moved into the two placements whose
listeners are in the workload's namespace: netns_rig's host side (the
broker a user unit, the listeners bound in the qemu container's namespace
by moat-netns-listen), or sidecar_rig's pod with the qemu container as
its workload, uid 1000 with every capability dropped.

```bash
python3 tests/manual/vm_placement_rig.py --placement netns
python3 tests/manual/vm_placement_rig.py --placement sidecar  # builds
python3 tests/manual/vm_placement_rig.py --placement netns \
    --loopback-answer                                       # must go red
python3 tests/manual/vm_placement_rig.py --placement netns --no-build
```

It needs what vm_rig needs. The guest reads the address the responder
answers with from the seed (`/etc/moatery-rig/answer`) and dials whatever
it is given, so a wrong answer is a failed request and not a skipped one.
The sidecar's qemu runs as a subordinate uid, so the serial and probe
files are made first, writable by anyone, and its `/proc` is read through
`podman unshare`.

**Rows.** Premise (no `CAP_NET_ADMIN` in qemu's bounding set; the table is
in the namespace; qemu holds `/dev/kvm`; the guest is a namespace of its
own). DNS from the guest, answered with riglib.ANSWER. The guest's UDP
sends dropped and the one to 443 counted as quic. The request (200; the
real key arrived; the record says `forward` under the credential; the
guest holds the placeholder only). The unlisted row. A guest connect to
another port at the answered address times out. The counters.

**What it found, first runs, 2026-10-03.** One defect: the netns
placement, moathut and the sidecar answered every name with the
namespace's `127.0.0.1`, which a container dials into its own namespace
and a guest into its own stack, where passt never carries it. 14/20 in
both placements: DNS green, request, unlisted and drop red, the guest's
dials refused by its own loopback. Nothing left the namespace, and every
caller was named. With `198.18.0.1`, never routed, 20/20 in both; the
redirect is by port, and passt's dial to that address meets it. The
three now answer `198.18.0.1`, and `--loopback-answer` 14/20 is the old
answer as a control. Re-run on that change, the same day: vm_rig 30/30,
netns_rig 30/30, sidecar_rig 36/36, hut_rig 103/103.

Outside the rig, the same day, two more ways to hold a VM:

- qemu under pasta alone, with no podman (`pasta --config-net --
  qemu ...`), host_rig's listeners: 30/30 with vm_rig's rows, given two
  things podman supplies. pasta runs the command as root in its user
  namespace with every capability, so qemu was started under `setpriv
  --bounding-set=-all`; kept, the premise row goes red, and root there
  lists our tables. The namespace shares the host's mount namespace, so
  its `resolv.conf` names the host's `127.0.0.53`, which passt forwards
  to and no DNAT moves off loopback: DNS timed out until qemu had a
  mount namespace of its own and a `resolv.conf` naming pasta's
  forwarder.
- a krun microVM (`podman run --runtime krun`, crun-krun 1.28, libkrun
  1.19), in the host placement and in the netns: 11/11 and 6/6 of a
  smaller set (DNS, request with the real key, unlisted 403, drop,
  callers named), with either answer. krun hands the guest's sockets to
  its process in the container's namespace, loopback ones too. A dial to
  a dropped port fails in the guest at once (curl 7) instead of timing
  out; a listener on the host's end of it saw nothing.

**Every placement after the rename, 2026-10-04.** At 1d34a22, on the
proving host: host_rig 33/33, netns_rig 30/30, vm_rig 30/30, this rig
`--placement netns` 20/20 and `--placement sidecar` 22/22, sidecar_rig
38/38, hut_rig 130/130. No defect.

## hut_rig.py — a moathut hut, through its command line

`docs/MOATHUT.md`: `moathut credential add`, `create`, `enter`, `log`,
`allow`, `policy`, `stop` and `rm`, the hut's units run by the user's
manager and quadlet, the namespace its netns unit holds, the netns
placement's rules and listeners in it, and the hut's broker.
The tool is the checkout's `bin/moathut`, or with
`MOATERY_LIBEXEC=/usr/libexec/moatery` the installed one.

```bash
python3 tests/manual/hut_rig.py                     # every row green
python3 tests/manual/hut_rig.py --without-rules     # must go red
python3 tests/manual/hut_rig.py --without-held-netns  # must go red
python3 tests/manual/hut_rig.py --podman-seccomp    # must go red
python3 tests/manual/hut_rig.py --broker-not-ready  # must go red
python3 tests/manual/hut_rig.py --listeners-required  # must go red
python3 tests/manual/hut_rig.py --without-reload    # must go red
python3 tests/manual/hut_rig.py --without-reopen    # must go red
python3 tests/manual/hut_rig.py --without-autostart  # must go red
python3 tests/manual/hut_rig.py --restarts 10       # more restarts of each
```

The fixture is riglib's, and seven drop-ins beside the units `create`
writes, removed before `rm`: the inspector and the broker trust the
stub's certificate, and under `--without-reload` the inspector's unit
has no `ExecReload=`; the broker's interpreter sleeps 3 s before it runs,
so its start has a window, and under `--broker-not-ready` its unit is
Type=simple; the namespace's unit finds an nft that fails ahead of the
system's, for two rows, or one that loads nothing, under
`--without-rules`; the pod's unit keeps the pod at its stop, for one
row; under `--without-held-netns` the pod makes its own namespace, and
loads the rules into it at its start; and the workload's `Exec=` is a
script whose
first act at every start is a request to the provider, with a nonce in
its path, recorded in the hut's home, and under `--listeners-required`
its unit `Requires=` both listeners, as it did before the policy loop;
and under `--without-reopen`, for the record's row alone, the
rotation's `ExecStart=` is an `mv` of the record and signals nothing.
That request is the window: the row for each start is the stub's log and
the record naming its nonce.
The provider is brokered: the rig seals a key with `credential add`, the
hut holds a placeholder, and the stub answers 200 only to the sealed
key, which only the broker has, and 401 to anything else. Its
`/slow/N/` path, with the key, is a download of N 64 KiB chunks 0.1 s
apart, long enough for an `allow` to land in it.

**Rows.** `credential add` seals the key, and neither file holds it. The
files `create` lays out, and nothing started; the hut is made with
`--autostart`, and `ls` says so. The chain as the manager
loaded it: the workload wants the listeners and requires neither, the
broker is Type=notify and bound to nothing, the pod is bound to the
namespace's unit, which is Type=notify and bound to nothing of the
hut's, and the pod pulls in the record's rotation timer, which is
`PartOf=` it. A failing rules
load starts nothing: `enter` refuses, the workload's first act never
happened, and `stop` leaves nothing active. The first request, brokered,
at the first start, at every workload restart and pod restart, and
after `stop` and `enter`. Root in the hut holds no `CAP_NET_ADMIN` and
the user no capability; the rules are in the pod's namespace, which is
the one the netns unit holds; the pod has no cgroup. Root in a shell
`podman exec --privileged` opens is refused `ip link add` and `ip link
set lo down`, and the host's nft with those credentials is refused
`nft flush ruleset`, the rules staying; that shell does not warn; the
hut's pasta has the arguments podman gives a stock pod's. Each pod
restart keeps the held namespace. `enter`'s user, home, working directory and `--root`.
The hut's home is not the user's, and the directories between it and a
mount in it are the user's. A `:ro` mount. The host's hosts file is not
the hut's. riglib's DNS rows, the silent drop, quic, and TCP 22 dropped.
The brokered host and the unlisted one, as the user and as root by sudo.
The hut's placeholder, by exec and by `enter`, and never the key; the
broker's socket on the host and not in the hut, and no TCP socket. A
stopped broker: a request is refused 502, never reaches the provider,
and the record says `credential broker unreachable`; `enter` starts it
again. The premise that systemd will not start a broker stopped while
it starts, and `enter` starting it anyway. `credential add` with a new
key, which the stub now wants: the next request carries it, and the
broker restarted while the inspector and the workload did not. The
inspector's counters. The policy loop: `log --refused` counts the
unlisted host's 403s and names it among the responder's unlisted names;
`allow` lists it and reloads the listeners, restarting nothing, and the
inspector's status file names the new document; the host is then
dialled and not refused, and `log --refused` stops listing it; a
download through the inspector, begun before an `allow` and still
running when it returns, finishes whole, every byte in order; a
`policy` edit the loader refuses exits 1 and restarts nothing, and at a
terminal (a pty) asks, opens the editor again, and applies the second
document, reloading the listeners; one dropping the credential stops
the broker and removes its unit, and the provider is reached unbrokered
(the stub's 401), and one naming it again brings the broker back and
the provider is served; the inspector killed is started again, and
nothing else is; stopped, the workload runs on in its container, and
`enter` starts it again; `log` follows a request just made, and SIGINT,
which is Ctrl-C, ends it with status 0 and no traceback. The record's
rotation: its timer active with the pod and its run exited 0; the
record padded past 32 MiB, the manager's run of the rotation moves it
aside, and the next request's line is in a new record and not in the
moved one. A file outside
the home is gone after a restart. Autostart: the manager loaded the
workload as wanted by `default.target`, and with the hut stopped, its
start of `default.target`, which is what a login or a lingering boot
does, starts the hut with the rules, and the first request is
inspected; a hut made without `--autostart` it does not start. After
`podman pod restart` the pod is in the held namespace, with the rules,
and `enter` serves it; with a table deleted from the host, `ls` marks
the hut unprotected and `enter` refuses it, and `stop` then `enter`
serves it again; a container run by hand from the hut's image, prompt
and mark warns; a pod the hut left does not start while the namespace's
unit is stopped. `credential
rm` is refused while the hut names the credential. `rm` leaves no unit,
pod or container, nor the broker's socket, and keeps the home and the
record; `create`, with a policy naming no credential, finds the home
again and writes no broker; `rm --home` removes it; then `credential rm`
removes the credential.

**What it found, first runs, 2026-09-29.** Three defects in moathut,
none of which the unit suite could see:

- `enter NAME --root -- COMMAND`, the documented form, handed `--root`
  to the command: the parser took everything after the name. Found
  writing the rig. The words after the first `--` are the command's now.
- a mount inside the home had its mount point, and every directory above
  it, made by the runtime as the hut's root: the user could not write in
  its own `~/.local`, and `rm --home`, which ignored errors, left the
  home and said nothing. `create` makes those directories as the user,
  and `rm --home` removes the home through `podman unshare`.
- the hut's user held all eleven of podman's default capabilities,
  effective and ambient, and could `chown` a root file without sudo. The
  home row above passed over a stale home the hut's root owned, which is
  how it showed. Podman gives a non-root user what `--cap-add` names,
  and a container whose user is not named gets root's set, which exec as
  the keep-id user keeps. The unit drops every capability outside the
  default set, adds none, and names the user.

53/56 at first (the home, and two rig rows matching the unlisted record
by path: the inspector refuses an unlisted host after the handshake,
before a request is read, so the record has none); then 57/57 with the
capabilities hidden; 57/58 with the added set gone and the user still
unnamed; 58/58. `--without-rules` 25/58. With `create`'s directories
left out the home row goes red, `Permission denied`.

Facts for the design. `podman pod restart` leaves every unit active
while the workload runs in a new namespace with no rules; its first
request there got no answer (no responder, and the provider's address
is the pod's own loopback), and `enter` refuses the hut, as
`docs/MOATHUT.md` says. `systemctl restart` of the pod returns in under a
second, before the listeners and the workload are back; quadlet adds
`Wants=` from the pod to its container, which is what brings the
workload back. A run takes under two minutes, `--without-rules` under
four.

**The broker, 2026-09-29.** 56/73 at first: the broker never started,
and every brokered request was refused 502 and recorded `credential
broker unreachable`, none sent without the key. systemd leaves a
credentialed unit's workspace,
`$XDG_RUNTIME_DIR/systemd/temporary-credentials/UNIT`, when it stops the
unit while its credentials are being decrypted, and every start after
fails `243/CREDENTIALS`, `File exists`, a restart after a restart, until
the user's manager ends. The fail rows' pod restarted, and the broker,
then `PartOf=` it and inside its 3 s, was stopped with it. Reproduced
with a bare unit: Type=notify, Type=simple with an `ExecStartPre=` or
`ExecStartPost=`, and Type=simple stopped in its first second, since
decrypting with `systemd-creds --user` takes over a second on the
proving host; a restart of an active unit is safe, and removing the
workspace from outside lets the next start through. The broker is bound
to nothing now; `stop` and `rm` stop it; `enter` and `credential add`
stop a broker that is not active, remove its workspace, forget its
failures, and start it. 63/75 while the repair skipped a broker waiting
to restart, which is `activating`; then 75/75. `--broker-not-ready`
68/75, the seven rows it names (an earlier 59/75, before the repair
covered every state but `active`, left the broker unable to start for
the rest of the run); `--without-rules` 36/75.

A broker's start is about 1.5 s on the proving host, the decryption and
the interpreter: as Type=simple, the first brokered request of every
start that starts it is refused. A run takes two minutes,
`--without-rules` four and a half.

**The policy loop, 2026-09-30.** 87/88 at first: the row for a killed
inspector wanted no new invocation at all, and the manager's start of
the inspector is one; re-derived to the inspector's alone. Then 88/88,
in 2m10s, and with the rows for a policy that drops the credential and
names it again, 91/91 in 2m17s. `--listeners-required` 85/88, the three
rows it names: with the workload requiring the listeners, `allow`
replaced the workload's container, so did the manager's automatic start
of the killed inspector, and stopping the inspector stopped the
workload. `--broker-not-ready` 83/91, the eight it names, the loop's
request after the broker is named again among them. `--without-rules`
41/88; its loop row for what `allow` restarts is red because an earlier
`enter`, refused, had left the broker stopped, and the inspector's
restart starts it (`Wants=`). A request while the inspector is stopped
gets curl's `000`, which is the listener's port refusing it: the rows
claim only that the workload runs on and is not served, not that
anything is blocked.

**The policy reload, 2026-09-30.** 97/97 in about 2m30s. The download,
5 MiB over 8 s through the inspector and the broker, had begun when
`allow` ran, was still running when it returned, and finished whole;
nothing restarted. `--without-reload` 92/97, the five it names: `allow`
waited out the reload, restarted the inspector, and said so ("since it
did not take the reload"), and the download ended at curl's `(56)
unexpected eof`, the cut the reload exists to avoid; the status file
row stays green, since the restarted inspector reads the new document
at its start. `--listeners-required` 94/97, the three it names; `allow`
no longer reaches the workload under it, since it restarts nothing.
`--without-rules` 46/97: every row that makes a request or reads one
back, and the killed inspector's, whose restart starts the broker an
earlier refused `enter` left stopped (`Wants=`); the reload's own rows,
the terminal's edit and Ctrl-C stay green, since none needs the rules.
`--broker-not-ready` 89/97, the eight it names; a first run gave 80/97:
the stop while the broker starts left its credential workspace behind,
its restarts hit the start limit on it, and it stayed down from
`enter` through the loop, where before `allow`'s restart of the
inspector had started it again (`Wants=`). The rerun is the one
recorded.

The rig had not reached the re-edit prompt or Ctrl-C before: every
command ran with its standard input on `/dev/null`, so `policy` never
saw a terminal and took the refusal's non-interactive path, and `log`
was ended with SIGTERM, not SIGINT.

`log --refused` on the run's own record, before `allow`:

```
refused, and refused by the policy now:
       2  unlisted.test  (not allowlisted)
       1  provider.test  (credential broker unreachable)
names asked for that no list admits:
       4  unlisted.test
       1  aaaa-b0d94ce6.exfil.test
```

**The record's rotation, 2026-09-30.** 100/100. The timer's own run of
the rotation had exited 0; the padded record, 33.5 MiB, moved to `.1`,
and the next request's line was in the new record, 402 bytes, and not
in the moved one. `--without-reopen` 99/100, the one row it
names: the line was in the moved record, and no new one was made,
since the inspector wrote on into the file it held open.
`--without-rules` 48/100: the rotation's row is red with the rows that
make a request, and the timer's two stay green, since neither needs the
rules.

**Autostart, 2026-09-30.** 103/103. quadlet adds the pod's unit to
the workload's `WantedBy=` itself, so the row reads `default.target`
among them. `--without-autostart` 99/103: create's `ls`, the two
autostart rows, and `outside`'s first, which restarts a pod that is
now not running. A real login is not driven: a lingering user's
manager outlives the ssh session, and `start default.target` is the
job the manager queues at its own start.

**No user site, 2026-10-03.** 103/103 against the RPM, with every
program's shebang and every interpreter line a hut's units carry
running `python3 -s`. The run before it was 102/103: `log` did not
end within 10 s of its SIGINT, once, and the rerun was green. `log`
starts with the rig's own interpreter, which the change does not
touch.

The same day, autostart was proven at a real boot, outside the rig: a
hut created with `--autostart`, linger on, the host rebooted. The
linger session (logind class `manager`) started the user's manager, and
the chain was active with its rules loaded before the first login
(class `user`).

**The held namespace, 2026-10-04.** The hut's namespace moved from its
pod to the netns unit (podman 5.8.7, systemd 259.9, crun 1.28,
kernel 7.2). 120/121 at first: the chain row read systemd's default
`Requires=app.slice basic.target` on the netns unit as a binding; it
asks now for none of the hut's units. Then 121/121. A shell `podman
exec --privileged` opens was refused `ip link add` and `ip link set lo
down`, and the host's nft as root with every capability in the hut's
user namespace was refused `nft flush ruleset` ("Operation not
permitted"), the tables staying; a left pod's `podman pod start` failed
with `crun: open .../moathut-netns/NAME: No such file or directory`.
`--without-held-netns` 112/121, the nine rows it names. `--without-rules`
63/121; warn's first stayed green there, since a refused enter opens no
shell to warn, and now asks that enter succeeded.

Facts for the design, from probes beside the rig the same day:
- with podman as the netns unit's main process, every stop left the
  unit failed: `podman unshare` exits 1 on SIGTERM (its shutdown
  handler);
- with MAINPID naming podman's child, a `kill -9` of that child left
  the unit active ("Supervising process ... which is not our child"):
  pasta kept the cgroup populated. The holder is a fork whose parent
  exits, so podman exits 0 and the holder's parent is the user manager;
  its `kill -9` then failed the unit, and the pod and pasta went with
  it, and the next `enter` served the hut again;
- moat-netns-listen's pidfd join of the infra's user and network
  namespaces at once works on a namespace the parent user namespace
  owns; joining the user namespace first, then the network one, is
  refused;
- a daemon-reload that gives a running unit `BindsTo=` on an inactive
  one stops it (two bare user units), which is why a running pod's
  network files wait for its next `enter`;
- a privileged exec keeps the hut's seccomp filter and `container_t`
  label: podman's exec changes capabilities alone, and crun applies the
  container's filter to every exec. The hut's user, without any
  capability, can already `unshare -Urn` and, inside, add links, open
  the netfilter socket and mount a tmpfs.

**The hut's seccomp profile, 2026-10-04.** On the proving host
(podman 5.8.7, crun 1.28, libseccomp 2.6.1, kernel 7.2.5): 126/126.
`--podman-seccomp` 124/126, the two rows of refusals, every call of
the probe reaching the kernel there (`clone3` EINVAL, `setns` EBADF,
`mount` ENOENT, `ptrace` ESRCH, `keyctl` ENOTSUP), a vsock refused EPERM
by podman's profile and one with an upper bit in its family made. The
unit tests' breaks (moathut's unit line, the file written with the
units, each of the profile's shapes) each turned a test red.

Beside the rig, in a container shaped like a hut (keep-id, the toolbox image)
under each profile: sudo, `dnf install`, git over HTTPS, curl and
threaded subprocesses worked under `strict` as under podman's default;
gdb ("During startup program exited with code 127"), strace and
`unshare -Ur` were refused, and under `debug` gdb and strace worked.
libseccomp's readings, measured the same day, are in
`tests/test_seccomp.py`'s docstring.

**A hut's SELinux level, 2026-10-04.** On the proving host (podman
5.8.7, SELinux enforcing): 130/130. Beside the rig, by hand: a
container at a level of its own in a pod at podman's random one ran at
its own level and wrote its `:Z` mount, and was refused `/dev/shm`,
which is the infra container's, labelled at the infra's level; with
the pod at the same level, `/dev/shm` was writable. A second start at
a fixed level left a file deep in a `:Z` mount with its ctime
unchanged: podman relabelled nothing. A container at another fixed
level, and one at podman's random one, were refused the directory.
The unit tests' breaks (the pod's level, the workload's, a level
different from the pod's, each of the four `:Z` mounts, a mount made
`:Z`, create's level, the level given a hut without one, a level drawn
twice, categories unsorted) each turned a test red.

**The sidecar's SELinux level, 2026-10-04.** On the proving host
(podman 5.8.7, SELinux enforcing), by hand, the recipe as it was: the
infra container, the sidecar and the workload ran at one level, the
pod's (`container_t:s0:c280,c478`); the policy and the secret were
labelled at it, and the named volume, mounted without `:Z`, at `s0`,
so a container mounting it without relabelling, as the inspector's
uid, read the CA key at the workload's level and at an unrelated one.
With the sidecar at a level of its own and the volume `:Z`, the three
were labelled at the sidecar's level, a container at the workload's
level or at podman's random one was refused the key, the workload's
loopback TCP to the sidecar was served, and the sidecar was refused
`/dev/shm`, the infra container's. Then `sidecar_rig.py` 38/38 and
`vm_placement_rig.py --placement sidecar` 22/22, the label rows among
them. `--shared-label`, the recipe as it was, turned both label rows
red and no other (36/38).

**The workspace, 2026-09-30: the user manager's alone.** A bare unit
loading a sealed credential, `ExecStart=sleep infinity`, started with
`--no-block` and stopped 0.05, 0.2, 0.4, 0.7 and 1.0 s into its 1.3 s
start, then started again, on systemd 259.9. As a system unit with
`DynamicUser=` (a credential sealed by `systemd-creds encrypt`), 5/5
left no workspace and started again; as a user unit, 5/5 left
`temporary-credentials/UNIT` and failed the next start. The system
manager decrypts into a tmpfs it mounts only once it is filled, and
falls back to the directory a killed start leaves only when it may not
mount one (`setup_credentials_plain_dir`, `src/core/exec-credential.c`,
the same on systemd's main branch). workloadctl's credentialed units,
all system units, are not exposed; `examples/systemd`'s broker is.
