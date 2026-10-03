# customs

Egress inspection and credential brokering for a sandboxed workload — a
container, a VM, or a VM inside a container — that is never told it is
being inspected and never holds the key it appears to be using.

At a border, *customs* inspects what crosses, and a *customs broker* is
the agent who deals with customs for you and files your declarations.
Here the border is the workload's, and what crosses is outbound:
the inspector examines it, and the broker presents a credential the
workload never sees.

---

## What it is

Six programs, stdlib Python. Three run beside each workload and take
everything on the command line but the inspector's policy, one JSON
document; the responder's `--static` map, a file; and the broker's keys,
which systemd hands it in `$CREDENTIALS_DIRECTORY`:

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
  never leaves the host; the key never enters the workload.
- **customs-resolve** — the workload's nameserver. It answers every name
  with the address the redirect catches, or from the `--static` map, and
  asks no one, so the workload's DNS is not a way out.

Two put them in place:

- **customs-mint-ca** makes the per-workload CA once, before the
  inspector first starts.
- **customs-netns-listen** binds the inspector's or the responder's
  listeners inside a rootless container's network namespace and hands
  them over.

And **customs-box** puts them all together for command-line work:
`customs-box create NAME --policy FILE` makes a long-lived rootless 
container with its own home, inspector and responder, and a broker 
once its policy names a credential; `customs-box enter NAME` runs a 
shell or a command in it. A lot like toolbx or distrobox, with some 
handles to manage and monitor ingress and egress.

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
  container is an inexpensive way to get one; rules go inside its netns via
  `podman unshare nsenter`, and the container's own processes hold no
  `CAP_NET_ADMIN` to undo them. A VM is one more process inside such a
  container.

Everything else — the policy document, the CA bundle and the env vars that
point at it, the socket-activated inspector and responder, the broker's
flags and `$CREDENTIALS_DIRECTORY` — is the same in every placement.

## Documents

- [docs/POLICY.md](docs/POLICY.md): the policy document the inspector
  reads.
- [docs/DESIGN.md](docs/DESIGN.md): placing customs beside a rootless
  container, with its listeners on the host or in the container's
  network namespace; as a sidecar in a pod; and for a VM. Also how the
  workload's DNS is answered, and what the host has to do that customs
  does not, such as stopping the programs from dialling a loopback or
  private address that an allowed name resolves to.
- [docs/BOX-GUIDE.md](docs/BOX-GUIDE.md): customs-box, long-lived
  inspected containers for command-line work, as a user's guide;
  [docs/BOX.md](docs/BOX.md) is its reference.
- [docs/LOGGING.md](docs/LOGGING.md): what the journal, the record and
  the status files report, and what to look for in them.
- [docs/INTERFACE.md](docs/INTERFACE.md): what stays stable for a
  program that imports the modules or reads the inspector's status file.
- [examples/](examples/): user units, a logrotate configuration, and the
  one-time setup for a rootless container.
- `--help` on any of the programs: the flags.
- [container/](container/): the sidecar image, the programs in one
  container of a pod.
- [examples/quadlet/](examples/quadlet/): the listeners in the
  container's network namespace, as a quadlet pod.
- [examples/bootc/](examples/bootc/): a bootc image with customs and
  what it recommends installed.

## Requirements

Python 3.14, standard library only; OpenSSL 3.5 (`openssl` on `PATH`, for
the CA and the per-host certificates); systemd 256 or later for
`LoadCredentialEncrypted=` in a user unit; podman with pasta for the
container placements.

Building the RPM takes `just`, `rpm-build` and
`python3-rpm-macros`: `just rpm` builds from the checkout into
`rpmbuild/RPMS/`, with the programs in `/usr/libexec/customs/`,
`customs-box` in `/usr/bin/`, and the `customs` and `customs_box`
packages in site-packages.
`just rpm-image` builds and tests it in a container, into
`localhost/customs-rpm:VERSION`, an image holding `/customs.rpm` alone,
for another image's build to copy; a tag `vVERSION` on the forge pushes
it, signed, to the local registry (`.forgejo/workflows/rpm-image.yml`).
`.forgejo/workflows/unit.yml` runs `just lint` and `just coverage` on
every push and pull request.

## Status

Version 0.5.1. The programs have run end to end on a real host in
four placements: a rootless container (`tests/manual/host_rig.py`), the
same with the listeners in the container (`tests/manual/netns_rig.py`),
a sidecar in a pod (`tests/manual/sidecar_rig.py`), and a VM inside the
container (`tests/manual/vm_rig.py`); and a box, through
`customs-box` (`tests/manual/box_rig.py`). The workload's DNS is answered by
customs-resolve and forwarded nowhere ([DESIGN.md](docs/DESIGN.md),
"DNS").
`just test` runs the unit tests; `just lint` runs ruff. `just coverage`
runs the suite under coverage of the shipped code alone — the `customs`
package and every entrypoint, including the scripts the suite executes as
subprocesses — and fails below the floor in `.coveragerc`.

## Licence

MIT; see [LICENSE](LICENSE).
