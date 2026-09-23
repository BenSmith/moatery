# CLAUDE.md

## What this is

`customs` is the egress inspector + credential broker pair for sandboxed
workloads, to be lifted out of workloadctl into its own project. Read
`README.md`, then `docs/DESIGN.md` (how the pair applies to a rootless
container, a pod sidecar, a VM, and cosy), `docs/POLICY.md` (the policy
document) and `docs/EXTRACTION.md` (the dependency decision, the
identifiers workloadctl imports, and what the first release switches).
`examples/` holds shape-1 user units and a logrotate configuration,
installed to `/usr/libexec/customs/` and run end to end on the proving
host.

## Where the code came from

`lib/`, `libexec/` and the tests are a copy (2026-09-22) of these, in
the hypervisor repo checked out beside this one:

```
../hypervisor/workloadctl/
  libexec/agent-broker                # → customs-broker
  libexec/workload-inspect-listener   # → customs-inspect
  lib/                                # the 24-module closure
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

The decision in `docs/EXTRACTION.md` is dependency: workloadctl will
require customs and run its entrypoints. Until customs has a first
release there is nothing to require, so workloadctl keeps its copy and a
fix that matters to both goes to both. At the release the copy there is
deleted.

The prose is renamed: nothing under `lib/` or `libexec/` says
"workloadctl", cites its docs, uses its vocabulary (renderer, `validate`,
substrate, SELinux labelling) or narrates history. Module names and
every identifier workloadctl imports are unchanged (`docs/EXTRACTION.md`
lists them). "Guest" and "workload" remain as the words for the thing
behind the inspector. Diffing against workloadctl is a diff of prose and
messages, the two entrypoints' names, and the shape-1b flags: the
broker's `--listen unix:PATH` (`UnixServer`, `peer_uid_unix`), the
inspector's `--broker unix:PATH` and `--caller-uid`, and the record
naming a unix upstream. Fixes are mirrored to workloadctl on a branch;
the flags reach it with the dependency, not by mirror.

`libexec/customs-mint-ca` is customs-only too: the one CA mint
(`egress_mint.mint_ca`), which the sidecar's first start also calls.

`container/` is the shape-1b sidecar image: `Containerfile` and
`customs-sidecar`, the entrypoint that is the unit file as a process.
It is customs-only and has no workloadctl counterpart.

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
just test     # all unit tests (unittest discover; 672)
just lint     # ruff: syntax, names, imports, 79 columns (ruff.toml)
python3 -m unittest tests.test_closure -v   # one module
python3 tests/manual/shape1_rig.py          # on the proving host, as the user
python3 tests/manual/shape1b_rig.py         # same; builds container/ first
```

`tests/__init__.py` puts `lib/` on `sys.path`; test modules import as
`tests.<name>`, and `load_script()` imports the extension-less
entrypoints. `tests/test_closure.py` holds lib/ to be exactly the two
closures, with no TOML, no passwd lookup and no derived value — it
replaces workloadctl's two closure tests, whose other half (the generator
handing every value across) has no counterpart here.
