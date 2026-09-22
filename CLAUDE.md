# CLAUDE.md

## What this is

`customs` is the egress inspector + credential broker pair for sandboxed
workloads, to be lifted out of workloadctl into its own project. Read
`README.md`, then `docs/DESIGN.md` (how the pair applies to a rootless
container, a pod sidecar, a VM, and cosy) and `docs/EXTRACTION.md` (which
modules lift, which stay, and the open copy-vs-dependency decision).

## Where the code came from

`lib/`, `libexec/` and the tests are a verbatim copy (2026-09-22) of
these, in the hypervisor repo checked out beside this one:

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

workloadctl still carries its own copy and is not yet a consumer of this
one; the copy-vs-dependency decision in `docs/EXTRACTION.md` is open.
Until it is made, a fix that matters to both goes to both.

The copy is verbatim: module names, docstrings and comments still say
"workload", "workloadctl", "guest" and cite workloadctl docs by path.
Renaming and rewording is owed, and it should be done in the style
below — present-tense reasons, no "used to be".

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
  is committed on a new branch in the hypervisor repo, never its
  `main`, with the same change and the same message; merging it there
  is a separate decision.

## Commands

```bash
just test     # all unit tests (unittest discover; 295 on arrival)
just lint     # py_compile of lib/ and both entrypoints
python3 -m unittest tests.test_closure -v   # one module
```

`tests/__init__.py` puts `lib/` on `sys.path`; test modules import as
`tests.<name>`, and `load_script()` imports the extension-less
entrypoints. `tests/test_closure.py` holds lib/ to be exactly the two
closures, with no TOML, no passwd lookup and no derived value — it
replaces workloadctl's two closure tests, whose other half (the generator
handing every value across) has no counterpart here.
