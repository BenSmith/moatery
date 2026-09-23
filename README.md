# customs

Egress inspection and credential brokering for a sandboxed workload — a
container, a VM, or a VM inside a container — that is never told it is
being inspected and never holds the key it appears to be using.

At a border, *customs* inspects what leaves, and a *customs broker* is the
agent who clears your goods across on your behalf, carrying papers you
never handle yourself. Same two jobs here. 🛃

---

## What it is

Two programs, stdlib Python. Everything is on the command line except
the inspector's policy, one JSON document:

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

A third, **customs-mint-ca**, makes the per-workload CA once, before the
inspector first starts.

The workload cannot name the broker, cannot choose to use it, and cannot
be pointed at another workload's. The only thing that dials the broker is
that workload's own inspector.

## The one property

Something *outside* the workload has to own the workload's outbound
sockets, so rules can select them without the workload's cooperation.

- With root, that owner can be a **dedicated uid per workload**:
  passt/pasta re-originate the workload's traffic as host sockets owned
  by that uid, and `meta skuid` selects them.
- Without root there is no uid to spend, so the owner is a **network
  namespace you are root in and the workload is not**. A rootless podman
  container is the cheapest way to get one; rules go inside its netns via
  `podman unshare nsenter`, and the container's own processes hold no
  `CAP_NET_ADMIN` to undo them. A VM is one more process inside such a
  container.

Everything else — the policy document, the CA bundle and the env vars that
point at it, the socket-activated inspector, the broker's flags and
`$CREDENTIALS_DIRECTORY` — is the same in every placement.

## Documents

- [docs/POLICY.md](docs/POLICY.md): the policy document the inspector
  reads.
- [docs/DESIGN.md](docs/DESIGN.md): placing the pair: a rootless
  container, a sidecar in a pod, a VM, a cosy container; and what the
  host has to do that customs does not (private addresses among it).
- [examples/](examples/): user units, a logrotate configuration, and the
  one-time setup for a rootless container.
- `customs-inspect --help`, `customs-broker --help`: the flags.
- [container/](container/): the sidecar image, both programs in one
  container of a pod.

## Requirements

Python 3.14, standard library only; OpenSSL 3.5 (`openssl` on `PATH`, for
the CA and the per-host certificates); systemd 256 or later for
`LoadCredentialEncrypted=` in a user unit; podman with pasta for the
container shapes.

## Status

Version 0.1.0, not yet released. Both programs have run end to end on a
real host in two shapes: a rootless container
(`tests/manual/shape1_rig.py`) and a sidecar in a pod
(`tests/manual/shape1b_rig.py`). The VM and cosy shapes
are designed, not proved. DNS is not yet controlled: a workload can
still exfiltrate through its resolver ([DESIGN.md](docs/DESIGN.md), "DNS").
`just test` runs the unit tests; `just lint` runs ruff.

## Licence

MIT; see [LICENSE](LICENSE).
