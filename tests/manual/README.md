# Manual rigs

Checks that need a real host and cannot run under `just test`. Each is
invoked by hand, as an ordinary user, from a checkout on the proving host.
Nothing here is a unit gate; these are the gate the unit suites cannot be.

The shape-1 and 1n rigs run the checkout's programs, or with
`CUSTOMS_LIBEXEC=/usr/libexec/customs` the installed RPM's, with no
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
shapes, so a DNS row passed with no responder at all. Where a row asserts
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
every shape has (the workload's DNS, the origin's 401 and 200). A rig
owns its shape and its rows.

## shape1_rig.py — the pair with nothing but a normal user

`docs/DESIGN.md` shape 1: one rootless podman container under pasta,
the programs as hand-written user units, the nft rules loaded into the
container's netns through `podman unshare nsenter`, a placeholder in the
container's environment, and one real request that reaches the provider
carrying the sealed key.

```bash
python3 tests/manual/shape1_rig.py                  # every row green
python3 tests/manual/shape1_rig.py --without-rules  # must go red
python3 tests/manual/shape1_rig.py --without-dns-redirect  # dns red
python3 tests/manual/shape1_rig.py --broker-over-tcp  # the broker rows red
```

Runs as the user. Two host facts need `sudo`, and both are undone at
teardown: a line in `/etc/hosts` pointing `provider.test` at the stub,
and `net.ipv4.ip_unprivileged_port_start` lowered so the stub can bind
`:443` — both programs dial their upstream at 443 with no override, on
purpose, so the provider has to answer there. The stub
(`stub_provider.py`) returns 200 only to the real key and reports in the
body which `Authorization` arrived, so "200" means the substitution
happened and the placeholder alone measurably gets 401.

The per-workload CA is minted once into `~/.local/state/customs-rig/` and
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
443 moves the `quic` counter too. The request (200;
the real key arrived; the container's environment holds
the placeholder only; the broker's journal grew by one; the record says
`forward` under the credential). The broker's address is unreachable
from inside both ways it can be spelled, and its journal did not grow.
An unlisted host gets the inspector's own 403 and a record saying
`not allowlisted` with no upstream. The origin gives the placeholder 401
and the real key 200. The counters name every caller and dropped none as
foreign.

**What it found, first run, 2026-09-22.** No defect in the pair. Four in
the shape-1 recipe as `DESIGN.md` had it, which is now corrected:

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
to, before the socket was first activated. `customs-mint-ca` is that
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

## shape1n_rig.py — shape 1 with the listeners in the container

`docs/DESIGN.md` shape 1n: shape 1's container under plain pasta, with no
loopback map, and shape 1's broker unit. The inspector and the responder
are transient user units started between `podman init` and `podman
start`, through `customs-netns-listen`, which binds their sockets in the
container's network namespace and execs each program with its own.

```bash
python3 tests/manual/shape1n_rig.py                        # every row green
python3 tests/manual/shape1n_rig.py --without-rules        # must go red
python3 tests/manual/shape1n_rig.py --without-netns-pid    # inspector red
python3 tests/manual/shape1n_rig.py --without-dns-redirect # dns red
python3 tests/manual/shape1n_rig.py --without-notify       # ready red
```

**Rows.** Shape 1's premise, DNS, silent-drop, quic, request, broker,
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
- the caller check reads a different socket in this shape. In shape 1
  the inspector's peer is pasta's host socket, which is always the
  user's; here it is the workload's own, in the container's table, with
  the uid the host sees: the user for container root, a subuid for
  anything else.

**What it found, the responder, 2026-09-24.** 26/26;
`--without-dns-redirect` 14/26 (dns, request, unlisted); `--without-rules`
12/26. With the responder in the namespace nothing the workload may send
crosses the egress device, so the chain accepts nothing: the neighbour
row, which queried pasta's forwarder, went with the resolver's lines,
and `--without-neighbour-discovery` with it.

## shape1b_rig.py — the pair as a sidecar, with no host install

`docs/DESIGN.md` shape 1b: a podman pod under pasta, the sidecar image
(`container/`: the programs, one container, two uids) beside a workload
container running as a third uid with no capabilities, the nft rules in
the pod's netns keyed on `meta skuid`, the broker on a socket path under
the sidecar's own `/run`, the key as a podman secret, and one real request
that reaches the provider carrying it.

```bash
python3 tests/manual/shape1b_rig.py                  # builds the image first
python3 tests/manual/shape1b_rig.py --without-rules  # must go red
python3 tests/manual/shape1b_rig.py --without-private-drop  # private red
python3 tests/manual/shape1b_rig.py --without-dns-redirect  # dns red
python3 tests/manual/shape1b_rig.py --no-build       # reuse the last image
```

The image is built from the checkout on each run; the state volume and
the secret are removed at teardown, so the CA is the sidecar's and is
minted afresh each run. `--keep` leaves the pod, the volume and the
secret.

**Rows.** Premise (the workload holds neither `CAP_NET_ADMIN` nor
`CAP_SETUID`; the table is in the pod's netns; `podman top` shows the
broker and the inspector as the two image users and the responder as
the inspector's, and the supervising pid 1 holds no capability). Shape
1's DNS rows, answered by the sidecar's responder with the pod's
loopback; the unlisted row resolves through it too, while the provider's
name is in the pod's hosts file, which the sidecar's dials need. Shape
1's silent-drop and quic rows. The request (200; the real key arrived;
the workload's environment holds the placeholder only; the broker's log
grew by one; the record says `forward` under the credential with
`upstream` naming the socket path). The broker's path is ENOENT from the
workload -- `stat` says "No such file or directory", which curl alone
cannot distinguish from a refusal -- and nothing but the two planes and
the responder's port listens on TCP in the pod, so there is no address
to spell; its log did not grow. An unlisted host gets the 403 and the record. The private
rows: the egress chain carries `DESIGN.md`'s private-space drop and an
accept line for the provider, which is on the host's mapped loopback and
so link-local; with that line deleted the workload's request gets no 200,
the stub's log does not grow and the drop's counter moves, and with it
put back the same request arrives. The programs' own DNS query to the
resolver is answered. The origin's two rows. The counters name every
caller and dropped none as foreign, with the workload being another
uid. Last, the lifecycle: the broker killed from outside ends the
container non-zero and the restart policy brings it back (the restart
count rose; every exit is in the log), the restarted programs serve the
workload's request under the CA its bundle already holds, and a stop
reaches every program well inside podman's timeout and exits 0.

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
