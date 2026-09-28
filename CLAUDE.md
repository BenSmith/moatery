# CLAUDE.md

## What this is

`customs` is the egress inspector + credential broker pair for sandboxed
workloads, lifted out of workloadctl into its own project. workloadctl
now requires the customs RPM and runs its programs; there is no second
copy. Read
`README.md`, then `docs/DESIGN.md` (how the pair applies to a rootless
container, a pod sidecar, a VM, and cosy), `docs/POLICY.md` (the policy
document) and `docs/INTERFACE.md` (the names workloadctl imports and
the status file paths it reads).
`examples/` holds shape-1 user units and a logrotate configuration,
installed to `/usr/libexec/customs/` and run end to end on the proving
host.

## Where the code came from

`customs/`, `libexec/` and the tests began as a copy (2026-09-22) of
these, in the hypervisor repo checked out beside this one, and the
responder as a copy (2026-09-24) of workloadctl's. All of them are
deleted there now; the list is for reading its history:

```
../hypervisor/workloadctl/
  libexec/agent-broker                # → customs-broker
  libexec/workload-inspect-listener   # → customs-inspect
  libexec/workload-vm-resolve         # → customs-resolve
  lib/                                # the 24-module closure
  lib/dns_wire.py                     # → resolve_wire.py
  lib/resolve_server.py               # → resolve_serve.py
  tests/test_vm_resolve.py            # → tests/test_resolve.py
  tests/test_broker_closure.py        # holds the broker closure
  tests/test_inspector_closure.py     # holds the inspector closure
```

Design, threat model and operating instructions, still there:

```
../hypervisor/workloadctl/
  docs/agent-broker.md
  docs/egress-and-broker-architecture.md
  docs/vm-egress-walkthrough.md
  tests/manual/README.md   # "Writing a row here" preamble, before any rig
```

workloadctl requires customs and runs its programs: a dependency, not
two copies, because under copies every shared fix is a merge someone
must remember, and the fixes flow one way (the shapes here reach code
paths workloadctl's layouts never do). A fix is made here and reaches
workloadctl with a release ("Releasing for workloadctl", below).

The prose is renamed: nothing under `customs/` or `libexec/` says
"workloadctl", cites its docs, uses its vocabulary (renderer,
`validate`, substrate, SELinux labelling) or narrates history. Module
names, but the responder's two, and every identifier workloadctl imports
are unchanged (`docs/INTERFACE.md` lists them). "Guest" and "workload"
remain as the words for the thing behind the inspector. Diffing against
workloadctl is a diff of prose and messages, the two entrypoints' names,
the `http2` list (customs relays no HTTP/2 and refuses the list), and
the shape-1b and 1n flags: the broker's `--listen unix:PATH`
(`UnixServer`, `peer_uid_unix`), the inspector's `--broker unix:PATH`,
`--caller-uid` and `--netns-pid` (`listed_in`, `netns_tables`,
`namespace_uids`, the lookup's tables and the served uid ranges as
parameters), and the record naming a unix upstream.

`libexec/customs-netns-listen` is customs-only too: it binds the
inspector's planes in a rootless container's network namespace and execs
the inspector with them (shape 1n). The inspector's `--netns-pid` is its
other half and reaches workloadctl with the dependency.

`libexec/customs-mint-ca` is the one CA mint (`egress_mint.mint_ca`):
the sidecar's first start calls it, and so does workloadctl's
`workload-ensure-user`, before it builds the seed that carries the CA.

`container/` is the shape-1b sidecar image: `Containerfile` and
`customs-sidecar`, the entrypoint that is the unit file as a process.
It is customs-only and has no workloadctl counterpart.

`libexec/customs-resolve` is workloadctl's VM responder made a program
of its own: every name answered with `--address`, or from the
`--static` map, counted against the inspector's policy, never
forwarded. `customs/resolve_policy.py` is customs'; `resolve_wire` and
`resolve_serve` began as workloadctl's `dns_wire` and
`resolve_server`.

## Releasing for workloadctl

workloadctl's spec has `Requires: customs >= X.Y.Z`, and its
`hypervisor.Containerfile` pins `ARG CUSTOMS_RPM=<registry>/customs-rpm:X.Y.Z`,
verified against this repo's signing key. A flag, a name or a status key
workloadctl comes to use is therefore a release here first:

- Bump `VERSION`, and push the tag `vX.Y.Z`. Only a tag push publishes
  the signed RPM image (`.forgejo/workflows/rpm-image.yml`); a manual
  run of that workflow builds and tests, and pushes nothing.
- Then, in the hypervisor repo, raise the spec's floor and the image pin
  together.
- `docs/INTERFACE.md` changes when workloadctl's imports or status reads
  do; `tests/test_interface.py` holds it to the code, and workloadctl's
  `tests/test_customs_seam.py` holds its side: the flags its units hand
  each program, the names it imports, the keys it reads.

What workloadctl does differently because of customs: it refuses
`[[vm.network.http2]]` and `[[network.http2]]` by name (customs relays
no HTTP/2 and refuses an `http2` list naming a host), writes the
responder's `--static` map as a file of its own, and mints each
workload's CA with `customs-mint-ca`.

## Conventions carried over from workloadctl

- **Stdlib only.** No third-party imports in anything that ships. System
  `python3` (3.14), `unittest`, no venv, no package manager, no formatter
  (measured and declined; it explodes paired argv lists). 79 columns.
- **Entrypoints are `main()` shims.** Logic lives in importable modules;
  a script owns only what the process boundary owns (argv, signals, fd
  recovery, exit status).
- **No history in shipped source.** Comments state the present constraint
  and why it holds — no "used to be", no incident narrative, no dates or
  bug IDs. History goes in commit messages and test docstrings. Nothing
  under `tests/` ships in the RPM, so the manual rigs' findings are test
  evidence and keep their dates.
- **Unit gates don't see the seam.** Every real defect the pair has had
  was correct code that nothing connected to, or a packet that never
  arrived. Anything with more than one part gets one pass asking "what
  starts, calls or reads this?", and a wiring test that can be broken on
  purpose. A rig row that probes settled state instead of the window a
  control arms in measures nothing.
- **Tracked files name hosts by role, never by name or LAN IP.** This
  repo may be published.
- **Never push, publish, or open a PR without being asked.** Commit
  freely and often; no unsolicited git-logistics commentary.
- **A fix goes here once.** workloadctl has no copy to mirror it into;
  it takes the fix with a release (above).

## Commands

```bash
just test     # all unit tests (unittest discover)
just coverage # the unit suite's coverage of the shipped code (.coveragerc)
just lint     # ruff: syntax, names, imports, 79 columns (ruff.toml)
just rpm      # the RPM, into rpmbuild/RPMS
just rpm-image  # the RPM tested and built in a container (podman)
python3 -m unittest tests.test_closure -v   # one module
python3 tests/manual/shape1_rig.py          # on the proving host, as the user
python3 tests/manual/shape1n_rig.py         # same; listeners in the netns
python3 tests/manual/shape1b_rig.py         # same; builds container/ first
python3 tests/manual/shape2_rig.py          # same; a VM in the container (/dev/kvm)
```

Every push and pull request runs `just lint` and `just coverage`
(`.forgejo/workflows/unit.yml`); the RPM image's build runs `just test`
too.

`customs/` is the package, installed to site-packages; the programs
import `customs.<module>` and the modules import each other relatively.
`tests/__init__.py` puts the checkout root on `sys.path`; test modules
import as `tests.<name>`, and `load_script()` imports the extension-less
entrypoints. `tests/test_closure.py` holds the package to be exactly the
programs' closures, with no TOML, no passwd lookup and no derived value.
The other half, the generator handing every value across, is
workloadctl's `tests/test_customs_seam.py`.
