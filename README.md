# moatery

Egress inspection and credential brokering for a sandboxed workload — a
container, a VM, or a VM inside a container — that is never told it is
being inspected and never holds the key it appears to be using.

A *moatery* makes moats: one around each workload, and nothing crosses
it unseen. The inspector watches what goes out over it, and the broker
hands across the credential the workload never sees. `moathut` makes the
huts inside: long-lived containers for command-line work, moated.

---

## What it is

Six programs, stdlib Python. Three run beside each workload and take
everything on the command line but the inspector's policy, one JSON
document; the responder's `--static` map, a file; and the broker's keys,
which systemd hands it in `$CREDENTIALS_DIRECTORY`:

- **moat-inspect** — a transparent egress inspector. Outbound 443
  (and 80) from the workload is redirected into it; it reads the SNI or
  Host, matches an allow-list, terminates TLS under a per-workload CA the
  workload trusts, re-originates the request itself, and applies
  method/path policy. The workload sees no proxy variable and no proxy
  address; an agent that ignores its whole environment is inspected anyway.
- **moat-broker** — holds the real provider key. When a policy entry
  names a credential, the inspector sends that request to the broker
  instead of the origin. The broker discards whatever header the workload
  sent (a placeholder, so the SDK is happy), attaches the real one, and
  dials the provider itself, from outside the workload. The placeholder
  never leaves the host; the key never enters the workload.
- **moat-resolve** — the workload's nameserver. It answers every name
  with the address the redirect catches, or from the `--static` map, and
  asks no one, so the workload's DNS is not a way out.

Two put them in place:

- **moat-mint-ca** makes the per-workload CA once, before the
  inspector first starts.
- **moat-netns-listen** binds the inspector's or the responder's
  listeners inside a rootless container's network namespace and hands
  them over.

And **moathut** puts them all together for command-line work:
`moathut create NAME --policy FILE` makes a long-lived rootless
container with its own home, inspector and responder, and a broker
once its policy names a credential; `moathut enter NAME` runs a
shell or a command in it. A lot like toolbx or distrobox, but a hut
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
how workloadctl runs moatery.

moatery is placed in one of four ways, each run end to end on a real
host ([DESIGN.md](docs/DESIGN.md)):

- **host**: the programs as user units, the listeners on the host's
  loopback;
- **netns**: the same programs, the listeners inside the container's
  network namespace (what moathut uses);
- **sidecar**: the programs as a second container in the workload's
  pod, with no host install;
- **VM**: qemu as the workload of a container in any of the three.

The policy, the trust bundle and the sealed credential are the same in
every placement.

## Documents

- [docs/MOATHUT-GUIDE.md](docs/MOATHUT-GUIDE.md): moathut, as a user's
  guide; [docs/MOATHUT.md](docs/MOATHUT.md) is its reference.
- [docs/POLICY.md](docs/POLICY.md): the policy document the inspector
  reads.
- [docs/DESIGN.md](docs/DESIGN.md): placing moatery, the rules it
  needs, how the workload's DNS is answered, and what the host has to
  do that moatery does not, such as keeping the programs off private
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
- [examples/bootc/](examples/bootc/): a bootc image with moatery and
  what it recommends installed.

## Requirements

Python 3.14, standard library only; OpenSSL 3.5 (`openssl` on `PATH`, for
the CA and the per-host certificates); systemd 256 or later for
`LoadCredentialEncrypted=` in a user unit; podman with pasta for the
container placements, 5.3 or later for moathut.

## Installing

Fedora 44 builds are in Copr, each release built there from its tag:

```bash
sudo dnf copr enable benjamin-coder-smith/moatery
sudo dnf install moatery
```

## Building and testing

`just rpm` builds the RPM from the checkout's tracked files into
`rpmbuild/RPMS/`; it takes `just`, `git`, `rpm-build` and
`python3-rpm-macros`. The RPM puts the programs in
`/usr/libexec/moatery/`, `moathut` in `/usr/bin/`, and the `moatery`
and `moathut` packages in site-packages. `just rpm-image` builds and
tests it in a container, into `localhost/moatery-rpm:VERSION`, an image
holding `/moatery.rpm` alone, for another image's build to copy.

`just test` runs the unit tests and `just lint` runs ruff. `just
coverage` runs the suite under coverage of the shipped code alone —
the `moatery` package and every entrypoint, including the scripts the
suite executes as subprocesses — and fails below the floor in
`.coveragerc`. `.github/workflows/unit.yml` runs `just lint` and `just
coverage` on every push and pull request, in Fedora as an ordinary
user, and `.forgejo/workflows/unit.yml` the same on a Forgejo forge.

## Status

Each placement, and moathut, has a rig that runs it end to end on a
real host: `tests/manual/host_rig.py`, `netns_rig.py`,
`sidecar_rig.py`, `vm_rig.py`, `vm_placement_rig.py` and `hut_rig.py`
([tests/manual/README.md](tests/manual/README.md)).

## Licence

MIT; see [LICENSE](LICENSE).
