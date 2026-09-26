# CLAUDE.md

## What this is

`customs` is the egress inspector + credential broker pair for sandboxed
workloads, to be lifted out of workloadctl into its own project. Read
`README.md`, then `docs/DESIGN.md` (how the pair applies to a rootless
container, a pod sidecar, a VM, and cosy), `docs/POLICY.md` (the policy
document) and `docs/INTERFACE.md` (the names workloadctl imports and
the status file paths it reads).
`examples/` holds shape-1 user units and a logrotate configuration,
installed to `/usr/libexec/customs/` and run end to end on the proving
host.

## Where the code came from

`lib/`, `libexec/` and the tests are a copy (2026-09-22) of these, in
the hypervisor repo checked out beside this one, and the responder a
copy (2026-09-24) of workloadctl's:

```
../hypervisor/workloadctl/
  libexec/agent-broker                # → customs-broker
  libexec/workload-inspect-listener   # → customs-inspect
  libexec/workload-vm-resolve         # → customs-resolve
  lib/                                # the 24-module closure
  lib/dns_wire.py                     # → resolve_wire.py  } less the
  lib/resolve_server.py               # → resolve_serve.py } static map
  tests/test_vm_resolve.py            # → tests/test_resolve.py
  tests/test_broker_closure.py        # holds the broker closure
  tests/test_inspector_closure.py     # holds the inspector closure
```

Design, threat model and operating instructions for the pair as it exists:

```
../hypervisor/workloadctl/
  docs/agent-broker.md
  docs/egress-and-broker-architecture.md
  docs/vm-egress-walkthrough.md
  tests/manual/README.md   # "Writing a row here" preamble, before any rig
```

workloadctl will require customs and run its entrypoints: a
dependency, not two copies, because under copies every shared fix is a
merge someone must remember, and the fixes flow one way (the shapes here
reach code paths workloadctl's layouts never do). Until customs has a
first release there is nothing to require, so workloadctl keeps its copy
and a fix that matters to both goes to both ("Until the first release",
below).

The prose is renamed: nothing under `lib/` or `libexec/` says
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
Fixes are mirrored to workloadctl on a branch; the flags reach it with
the dependency, not by mirror.

`libexec/customs-netns-listen` is customs-only too: it binds the
inspector's planes in a rootless container's network namespace and execs
the inspector with them (shape 1n). The inspector's `--netns-pid` is its
other half and reaches workloadctl with the dependency.

`libexec/customs-mint-ca` is customs-only too: the one CA mint
(`egress_mint.mint_ca`), which the sidecar's first start also calls.

`container/` is the shape-1b sidecar image: `Containerfile` and
`customs-sidecar`, the entrypoint that is the unit file as a process.
It is customs-only and has no workloadctl counterpart.

`libexec/customs-resolve` is workloadctl's VM responder made a program
of its own: every name answered with `--address`, counted against the
inspector's policy, never forwarded. `lib/resolve_policy.py` is
customs'; `resolve_wire` and `resolve_serve` are workloadctl's
`dns_wire` and `resolve_server` less the static map, named apart because
workloadctl keeps its pair and, after the switch, has both directories
on its path. A fix to the wire parser or the serve loop that applies to
workloadctl's is mirrored.

## Until the first release

Delete this section at the switch. At the first release (a tag and the
RPM from `just rpm`) the workloadctl copy is deleted, not maintained;
whatever of `customs-mirror` is unmerged is superseded by the
dependency. What the switch costs, all in the hypervisor repo:

- `Requires: customs` in its spec.
- Its units naming the two entrypoints here (or two symlinks under its
  own libexec).
- Its test modules that import partially from the closure importing
  from the installed package.
- Its two closure tests retired in favour of `test_closure.py` here.
- Its `[[vm.network.http2]]` hosts rendered as `splice` entries: customs
  relays no HTTP/2 and refuses an `http2` list that names a host. Its
  `h2_unrecorded` figure retired with it.

Nothing changes in customs. workloadctl's own responder,
`workload-vm-resolve`, is not part of the switch: `customs-resolve` was
taken from it without the static map workloadctl's VMs use to name
non-HTTP destinations, and takes its answers as flags rather than from
a document workloadctl writes.

## Conventions carried over from workloadctl

- **Stdlib only.** No third-party imports in anything that ships. System
  `python3` (3.14), `unittest`, no venv, no package manager, no formatter
  (measured and declined; it explodes paired argv lists). 79 columns.
- **Entrypoints are `main()` shims.** Logic lives in importable modules;
  a script owns only what the process boundary owns (argv, signals, fd
  recovery, exit status).
- **No history in shipped source.** Comments state the present constraint
  and why it holds — no "used to be", no incident narrative, no dates or
  bug IDs. History goes in commit messages and test docstrings.
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
- **A fix that goes to both trees is mirrored.** The workloadctl side
  is committed on the working branch `customs-mirror` in the hypervisor
  repo (cut from its `main` if it is gone), never on `main`, with the
  same change and the same message; merging it there is a separate
  decision.

## Commands

```bash
just test     # all unit tests (unittest discover; 803)
just lint     # ruff: syntax, names, imports, 79 columns (ruff.toml)
python3 -m unittest tests.test_closure -v   # one module
python3 tests/manual/shape1_rig.py          # on the proving host, as the user
python3 tests/manual/shape1n_rig.py         # same; listeners in the netns
python3 tests/manual/shape1b_rig.py         # same; builds container/ first
```

`tests/__init__.py` puts `lib/` on `sys.path`; test modules import as
`tests.<name>`, and `load_script()` imports the extension-less
entrypoints. `tests/test_closure.py` holds lib/ to be exactly the
programs' closures, with no TOML, no passwd lookup and no derived value — it
replaces workloadctl's two closure tests, whose other half (the generator
handing every value across) has no counterpart here.
