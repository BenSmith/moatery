# customs

Egress inspection and credential brokering for a sandboxed workload — a
container, a VM, or a VM inside a container — that is never told it is
being inspected and never holds the key it appears to be using.

At a border, *customs* inspects what leaves, and a *customs broker* is the
agent who clears your goods across on your behalf, carrying papers you
never handle yourself. Same two jobs here. 🛃

---

## What it is

Two programs, stdlib Python, no config file, everything on the
command line:

- **customs-inspect** — a transparent egress inspector. Outbound 443
  (and 80) from the workload is redirected into it; it reads the SNI or
  Host, matches an allow-list, terminates TLS under a per-workload CA the
  workload trusts, re-originates the request itself, and applies
  method/path policy. The workload sees no proxy variable and no proxy
  address; an agent that ignores its whole environment is inspected anyway.
- **customs-broker** — holds the real provider key. When a policy entry
  names a credential, the inspector sends that request to the broker
  instead of the origin. The broker discards whatever header the workload
  sent (a placeholder, so the SDK is happy), attaches the real one, and
  dials the provider itself, from outside the workload. The placeholder
  never leaves loopback; the key never enters the workload.

The workload cannot name the broker, cannot choose to use it, and cannot
be pointed at another workload's. The only thing that dials the broker is
that workload's own inspector.

## Where the code is today

Both programs exist and are proven end to end, as part of
[workloadctl](https://github.com/BenSmith/bootc-hypervisor) — `libexec/agent-broker`
and `libexec/workload-inspect-listener` plus a 24-module closure under
`lib/`. Their import closures are held by tests to contain nothing that
knows what a workload is: no config grammar, no uid-to-address derivation,
no guest access. That is what makes them liftable. This repository is
where they go once lifted; see [docs/EXTRACTION.md](docs/EXTRACTION.md)
for the inventory and [docs/DESIGN.md](docs/DESIGN.md) for how the pair
applies outside workloadctl.

## The one property

Something *outside* the workload has to own the workload's outbound
sockets, so rules can select them without the workload's cooperation.

- Under workloadctl, on a hypervisor host, that owner is a **dedicated
  uid per workload** — passt/pasta re-originate the workload's traffic as
  host sockets owned by that uid, and `meta skuid` selects them. Needs
  root.
- Without root there is no uid to spend, so the owner is a **network
  namespace you are root in and the workload is not**. A rootless podman
  container is the cheapest way to get one; rules go inside its netns via
  `podman unshare nsenter`, and the container's own processes hold no
  `CAP_NET_ADMIN` to undo them. A VM is one more process inside such a
  container.

Everything else — the policy document, the CA bundle and the env vars that
point at it, the socket-activated inspector, the broker's flags and
`$CREDENTIALS_DIRECTORY` — is the same in both placements.

## Status

The code is here as a copy of the workloadctl modules (2026-09-22):
`libexec/customs-broker`, `libexec/customs-inspect`, the 24-module closure
under `lib/`, and the unit tests that import only that closure (554,
green). Shape 1 is proved on a host by `tests/manual/shape1_rig.py`;
shape 1b by `tests/manual/shape1b_rig.py`, with the sidecar image under
`container/`. The prose is renamed; module names and imported
identifiers are not. Three flags and one fix have been added since the
copy: the broker's `--listen unix:PATH`, the inspector's `--broker
unix:PATH` and `--caller-uid`, and `peer_identity.userns_ranges` reading
the inside column of `uid_map`; the fix is mirrored to workloadctl on a
branch, the flags are not yet.
