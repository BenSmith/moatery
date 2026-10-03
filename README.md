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
shell or a command in it. A lot like toolbx or distrobox, but a box
publishes no ports, so nothing can connect to it as a server, and what
it sends out is inspected, with commands to watch it and change what
is allowed.

The workload cannot name the broker, cannot choose to use it, and cannot
be pointed at another workload's. The only thing that dials the broker is
that workload's own inspector.

## What it needs

No root. Something outside the workload has to own the workload's
outbound sockets, so rules can select them without the workload's
cooperation, and that owner is a **network namespace you are root in
and the workload is not**. A rootless podman container is the cheapest
way to get one: rules go into its namespace with `podman unshare
nsenter`, and the container's own processes hold no `CAP_NET_ADMIN` to
undo them. A VM is one more process inside such a container. With
root, a uid of the workload's own can be the selector instead, which is
how workloadctl runs customs.

customs is placed in one of four ways, each run end to end on a real
host ([DESIGN.md](docs/DESIGN.md)):

- **host**: the programs as user units, the listeners on the host's
  loopback;
- **netns**: the same programs, the listeners inside the container's
  network namespace (what customs-box uses);
- **sidecar**: the programs as a second container in the workload's
  pod, with no host install;
- **VM**: qemu as the workload of a host-placed container.

The policy, the trust bundle and the sealed credential are the same in
every placement.

## Documents

- [docs/BOX-GUIDE.md](docs/BOX-GUIDE.md): customs-box, as a user's
  guide; [docs/BOX.md](docs/BOX.md) is its reference.
- [docs/POLICY.md](docs/POLICY.md): the policy document the inspector
  reads.
- [docs/DESIGN.md](docs/DESIGN.md): placing customs, the rules it
  needs, how the workload's DNS is answered, and what the host has to
  do that customs does not, such as keeping the programs off private
  addresses.
- [docs/LOGGING.md](docs/LOGGING.md): what the journal, the record and
  the status files report, and what to look for in them.
- [docs/INTERFACE.md](docs/INTERFACE.md): what stays stable for a
  program that imports the modules or reads the status files.
- `--help` on any of the programs: the flags.

Examples and images:

- [examples/](examples/): the host placement as user units, with the
  one-time setup and a logrotate configuration.
- [examples/quadlet/](examples/quadlet/): the netns placement as a
  quadlet pod.
- [container/](container/): the sidecar image.
- [examples/bootc/](examples/bootc/): a bootc image with customs and
  what it recommends installed.

## Requirements

Python 3.14, standard library only; OpenSSL 3.5 (`openssl` on `PATH`, for
the CA and the per-host certificates); systemd 256 or later for
`LoadCredentialEncrypted=` in a user unit; podman with pasta for the
container placements.

## Building and testing

`just rpm` builds the RPM from the checkout into `rpmbuild/RPMS/`; it
takes `just`, `rpm-build` and `python3-rpm-macros`. The RPM puts the
programs in `/usr/libexec/customs/`, `customs-box` in `/usr/bin/`, and
the `customs` and `customs_box` packages in site-packages. `just
rpm-image` builds and tests it in a container, into
`localhost/customs-rpm:VERSION`, an image holding `/customs.rpm` alone,
for another image's build to copy; a tag `vVERSION` on the forge pushes
it, signed, to the local registry (`.forgejo/workflows/rpm-image.yml`).

`just test` runs the unit tests and `just lint` runs ruff. `just
coverage` runs the suite under coverage of the shipped code alone —
the `customs` package and every entrypoint, including the scripts the
suite executes as subprocesses — and fails below the floor in
`.coveragerc`. `.forgejo/workflows/unit.yml` runs `just lint` and `just
coverage` on every push and pull request.

## Status

Version 0.5.1. Each placement, and customs-box, has a rig that runs it
end to end on a real host: `tests/manual/host_rig.py`, `netns_rig.py`,
`sidecar_rig.py`, `vm_rig.py` and `box_rig.py`
([tests/manual/README.md](tests/manual/README.md)).

## Licence

MIT; see [LICENSE](LICENSE).
