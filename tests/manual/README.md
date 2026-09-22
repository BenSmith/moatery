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

## shape1_rig.py — the pair with nothing but a normal user

`docs/DESIGN.md` shape 1: one rootless podman container under pasta,
both programs as hand-written user units, the nft rules loaded into the
container's netns through `podman unshare nsenter`, a placeholder in the
container's environment, and one real request that reaches the provider
carrying the sealed key.

```bash
python3 tests/manual/shape1_rig.py                  # 16 rows
python3 tests/manual/shape1_rig.py --without-rules  # must go red
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
- the policy's TLS mode is `"inspect"`, not `"terminate"`. The loader does
  not validate the value, so the misspelling would have started a listener
  that refuses every terminated handshake for want of a minter.
- the inspector recognises exactly ports 8080 and 8443 as its planes, so
  "each container gets its own inspector port" is not something the
  program supports today: one inspected container per host loopback.

And two facts for the packaging step: the entrypoints find `lib/` by
`sys.path` only, so a checkout needs `PYTHONPATH` in the unit (an install
puts them side by side); and nothing here mints the CA — under workloadctl
`workload-vm-inspect up` does — so the operator does, with
`egress_ca.ca_openssl_argv`, before the socket is first activated.

`SO_ORIGINAL_DST` on a host socket whose DNAT happened a namespace away
falls back to `getsockname()` cleanly: `caller_unresolved` is 0 and the
caller check admitted every connection as the user's.
