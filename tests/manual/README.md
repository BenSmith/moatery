# Manual rigs

Checks that need a real host and cannot run under `just test`. Each is
invoked by hand, as an ordinary user, from a checkout on the proving host.
Nothing here is a unit gate; these are the gate the unit suites cannot be.

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

**Check the fixture cannot satisfy the property by accident.** A name
that resolves to the container's own loopback is admitted by `oif lo` and
never meets the redirect; the rig gives every name it dials a TEST-NET
address for exactly that reason. Where a row asserts something is
blocked, a control row proves an unblocked caller reaches the same
fixture, or a responder that never started satisfies every assertion.

**Refused is not blocked.** Connection refused means the packet arrived
and nothing was listening, which is a broken fixture reporting itself as
a working filter. A drop presents as `EPERM` or a timeout.

**A run must be able to go red.** Every rig takes a flag that leaves out
the control it is about, and the rows that depend on it must fail under
that flag. A rig that has only ever passed has not been shown to measure.

`riglib.py` is the fixture both rigs share: the provider and unlisted
names on TEST-NET, the stub, the CA and bundle, the policy, the two sudo
facts and their teardown, and the rows every shape has (the origin's 401
and 200). A rig owns its shape and its rows.

## shape1_rig.py — the pair with nothing but a normal user

`docs/DESIGN.md` shape 1: one rootless podman container under pasta,
both programs as hand-written user units, the nft rules loaded into the
container's netns through `podman unshare nsenter`, a placeholder in the
container's environment, and one real request that reaches the provider
carrying the sealed key.

```bash
python3 tests/manual/shape1_rig.py                  # every row green
python3 tests/manual/shape1_rig.py --without-rules  # must go red
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

**Rows.** Premise (no `CAP_NET_ADMIN`; the table is in the netns). The
request (200; the real key arrived; the container's environment holds
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

And two facts for the packaging step: the entrypoints find `lib/` by
`sys.path` only, so a checkout needs `PYTHONPATH` in the unit (an install
puts them side by side); and nothing minted the CA, so the operator had
to, before the socket was first activated. `customs-mint-ca` is that
step now.

`SO_ORIGINAL_DST` on a host socket whose DNAT happened a namespace away
falls back to `getsockname()` cleanly: `caller_unresolved` is 0 and the
caller check admitted every connection as the user's.

## shape1n_rig.py — shape 1 with the listeners in the container

`docs/DESIGN.md` shape 1n: shape 1's container under plain pasta, with no
loopback map, and shape 1's broker unit. The inspector is a transient
user unit started between `podman init` and `podman start`, through
`customs-netns-listen`, which binds the two planes in the container's
network namespace and execs the inspector with them.

```bash
python3 tests/manual/shape1n_rig.py                        # every row green
python3 tests/manual/shape1n_rig.py --without-rules        # must go red
python3 tests/manual/shape1n_rig.py --without-netns-pid    # inspector red
python3 tests/manual/shape1n_rig.py --without-neighbour-discovery
```

**Rows.** Shape 1's premise, silent-drop, request, broker, unlisted,
origin and counter rows, and three of its own. The inspector is up on
the listeners it was handed, and their inodes are rows in the
container's socket table and in none of the host's. Nothing listens on
the host's `127.0.0.1` at either plane, for the user or another uid;
the request row, which reaches the same planes from inside, is the
control. With the neighbour table flushed, a DNS query to pasta's
forwarder is answered: the planes are on loopback and never cross the
egress device, so the resolver is the dial the neighbour lines are for.
The request's 200 is also the observation that the inspector's upstream
dial left from the host's namespace: the stub is on the host's
`127.0.0.1`, which the container cannot reach.

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

## shape1b_rig.py — the pair as a sidecar, with no host install

`docs/DESIGN.md` shape 1b: a podman pod under pasta, the sidecar image
(`container/`: both programs, one container, two uids) beside a workload
container running as a third uid with no capabilities, the nft rules in
the pod's netns keyed on `meta skuid`, the broker on a socket path under
the sidecar's own `/run`, the key as a podman secret, and one real request
that reaches the provider carrying it.

```bash
python3 tests/manual/shape1b_rig.py                  # builds the image first
python3 tests/manual/shape1b_rig.py --without-rules  # must go red
python3 tests/manual/shape1b_rig.py --no-build       # reuse the last image
```

The image is built from the checkout on each run; the state volume and
the secret are removed at teardown, so the CA is the sidecar's and is
minted afresh each run. `--keep` leaves the pod, the volume and the
secret.

**Rows.** Premise (the workload holds neither `CAP_NET_ADMIN` nor
`CAP_SETUID`; the table is in the pod's netns; `podman top` shows the two
programs as the two image users, and the supervising pid 1 holds no
capability). The request (200; the real key arrived;
the workload's environment holds the placeholder only; the broker's log
grew by one; the record says `forward` under the credential with
`upstream` naming the socket path). The broker's path is ENOENT from the
workload -- `stat` says "No such file or directory", which curl alone
cannot distinguish from a refusal -- and nothing but the two planes
listens on TCP in the pod, so there is no address to spell; its log did
not grow. An unlisted host gets the 403 and the record. The origin's two
rows. The counters name every caller and dropped none as foreign, with
the workload being another uid. Last, the lifecycle: the broker killed
from outside ends the container non-zero and the restart policy brings
it back (the restart count rose; both exits are in the log), the
restarted pair serves the workload's request under the CA its bundle
already holds, and a stop reaches both programs well inside podman's
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
