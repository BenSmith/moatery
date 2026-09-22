# CLAUDE.md

## What this is

`customs` is the egress inspector + credential broker pair for sandboxed
workloads, being lifted out of workloadctl into its own project. Read
`README.md`, then `docs/DESIGN.md` (how the pair applies to a rootless
container, a pod sidecar, a VM, and cosy) and `docs/EXTRACTION.md` (which
modules lift, which stay, and the open copy-vs-dependency decision).

## Where the source of truth is today

The code is not here yet. It lives in the hypervisor repo, which is
checked out beside this one:

```
../hypervisor/workloadctl/libexec/agent-broker              # → customs-broker
../hypervisor/workloadctl/libexec/workload-inspect-listener # → customs-inspect
../hypervisor/workloadctl/lib/                              # the 24-module closure
../hypervisor/workloadctl/tests/test_broker_closure.py      # holds the broker closure
../hypervisor/workloadctl/tests/test_inspector_closure.py   # holds the inspector closure
```

Design, threat model and operating instructions for the pair as it exists:

```
../hypervisor/workloadctl/docs/agent-broker.md
../hypervisor/workloadctl/docs/egress-and-broker-architecture.md
../hypervisor/workloadctl/docs/vm-egress-walkthrough.md
../hypervisor/workloadctl/tests/manual/README.md   # read the "Writing a row here" preamble before writing any rig
```

Until code is lifted, treat those as read-only references: changes to the
programs go into workloadctl on its own terms, not here.

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
- **Never push, publish, or open a PR without being asked.** Commit when
  asked and stop; no unsolicited git-logistics commentary.

## Commands

None yet. When code lands: `just test` (unittest discover), `just lint`
(py_compile), same shape as workloadctl.
