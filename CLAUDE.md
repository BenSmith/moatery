# CLAUDE.md

## What this is

`moatery` is an egress inspector, a credential broker and a nameserver
for sandboxed workloads. Read `README.md`, then `docs/DESIGN.md`
(placing moatery beside a rootless container, as a pod sidecar and for
a VM), `docs/POLICY.md` (the policy document) and
`docs/INTERFACE.md` (the names other programs import and the status
file paths they read). `moathut` lays the netns placement out as
long-lived huts: `docs/MOATHUT-GUIDE.md` is its guide, `docs/MOATHUT.md`
its reference. `examples/` holds the host placement's user units and a
logrotate configuration, the netns placement as a quadlet pod, and a
bootc image; the RPM installs them with the docs.

## Layout

- `moatery/`: the package, installed to site-packages. The programs
  import `moatery.<module>`; the modules import each other relatively.
- `libexec/`: the programs, each a `main()` over the package.
  `moat-inspect` is the inspector, `moat-broker` the broker,
  `moat-resolve` the responder (every name answered with `--address` or
  from the `--static` map, counted against the inspector's policy, never
  forwarded), `moat-mint-ca` the one CA mint, and `moat-netns-listen`
  binds the inspector's or the responder's listeners in a rootless
  container's network namespace and hands them over (the netns
  placement).
- `bin/moathut` and `moathut/`: the hut tool.
- `container/`: the sidecar image; `moat-sidecar` is its entrypoint, the
  unit file as a process.
- `rpm/`: the spec, and a Containerfile that builds and tests the RPM.

## Conventions

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
- **Unit gates don't see the seam.** Every real defect has been correct
  code that nothing connected to, or a packet that never arrived.
  Anything with more than one part gets one pass asking "what starts,
  calls or reads this?", and a wiring test that can be broken on
  purpose. A rig row that probes settled state instead of the window a
  control arms in measures nothing; read `tests/manual/README.md`'s
  "Writing a row here" before writing one.
- **The interface is a promise.** `docs/INTERFACE.md` lists the module
  names, identifiers and status keys other programs use;
  `tests/test_interface.py` holds it to the code. Renaming one is a
  breaking change.

## Releasing

Bump `VERSION` and the spec's `Version` together (a test holds them
equal), tag `vX.Y.Z`, and publish a GitHub release for the tag: Packit
builds it into the Copr project `benjamin-coder-smith/moatery`
(`.packit.yaml`). Pull requests get a Copr test build too.

## Commands

```bash
just test     # all unit tests (unittest discover)
just coverage # the unit suite's coverage of the shipped code (.coveragerc)
just lint     # ruff: syntax, names, imports, 79 columns (ruff.toml)
just rpm      # the RPM, into rpmbuild/RPMS
just rpm-image  # the RPM tested and built in a container (podman)
python3 -m unittest tests.test_closure -v   # one module
python3 tests/manual/host_rig.py            # on a real host, as an ordinary user
python3 tests/manual/netns_rig.py           # same; listeners in the netns
python3 tests/manual/sidecar_rig.py         # same; builds container/ first
python3 tests/manual/vm_rig.py              # same; a VM in the container (/dev/kvm)
python3 tests/manual/vm_placement_rig.py --placement netns  # or sidecar
python3 tests/manual/hut_rig.py             # same; a hut, through moathut
```

`.forgejo/workflows/unit.yml` runs `just lint` and `just coverage` on
every push and pull request; the RPM image's build runs `just test` too.

`tests/__init__.py` puts the checkout root on `sys.path`; test modules
import as `tests.<name>`, and `load_script()` imports the extension-less
entrypoints. `tests/test_closure.py` holds the package to be exactly the
programs' closures, with no TOML, no passwd lookup and no derived value.
