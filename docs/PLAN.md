# Plan

Written 2026-09-22, the day the code arrived. Five steps, in the order
that proves before it polishes and keeps the two trees diffable while
the design is still being tested. Each step names its gate.

## Two facts that shape the order

**The rename has a hard boundary.** Around twenty workloadctl modules
outside the closure import identifiers from inside it: `egress_ca`'s
`CA_BUNDLE_PATH`, `CA_ENV_VARS`, `RESERVED_GUEST_ENV`,
`CA_EXPIRY_WARN_DAYS`, `ca_cert_path`, `leaf_dir`, `LeafRefused`, and
more from `egress_record`, `egress_status`, `inspect_policy`,
`peer_identity`. Under the copy model those constants are dead here —
nothing in the closure reads `CA_BUNDLE_PATH` or the two SELinux types.
Under the dependency model they are the API. So prose, help strings,
log fields and entrypoint-owned code can be renamed freely; module
names and anything workloadctl imports stay until the copy-vs-dependency
decision in `EXTRACTION.md` is made, or the rename makes it by accident.

**The sidecar has a seam `DESIGN.md` does not name.** The inspector
drops any connection whose owning uid is not its own
(`lib/inspect_listener.py`, the `DROP_FOREIGN_CALLER` branch of the
accept path). In shape 1 that holds: pasta re-originates as the user and
the inspector runs as the user. In shape 1b the workload is a different
uid *by design* — that is the discriminator — so every connection is
dropped as foreign. The sidecar needs an inspector `--caller-uid`
mirroring the broker's, which changes the flag set `test_closure.py`
pins exactly. Shape 1b costs three flags, not the two `DESIGN.md`
counts.

## 1. Prove shape 1 as it stands

No code change. On the proving host: rootless podman with pasta,
hand-written user units for both programs, the nft rules loaded through
`podman unshare nsenter`, a placeholder in the container's environment,
one real request that reaches the provider, and the three negative
probes from `DESIGN.md` (dial the broker's address from inside; dial an
unlisted host; the origin with no key).

Start `tests/manual/` here with that as its first row, after reading the
"Writing a row here" preamble in workloadctl's rig README. The unknowns
are all here — pasta's gateway-to-`127.0.0.1` mapping, `LISTEN_FDS` from
a user `.socket`, `LoadCredentialEncrypted=` in a user unit,
`SO_ORIGINAL_DST` on a host socket whose DNAT happened a namespace away
(expected to fall back to `getsockname()` cleanly; check) — and none of
them need the rename first. A fix found now goes to both trees while
they are still byte-identical, which is the cheapest moment to port one.
The workloadctl side of such a fix is a mirrored commit — same change,
same message — on a new branch in the hypervisor repo, never onto its
`main`; merging it there is a separate decision.

Gate: a rig row that is green, and that goes red when the nft rules are
left out.

Done 2026-09-22: `tests/manual/shape1_rig.py`, 16 rows green,
`--without-rules` red. No fix to the pair, so nothing to mirror; the four
defects were in `DESIGN.md`'s recipe (podman's `--no-map-gw`, the DNS
forwarder address, `"terminate"` for `"inspect"`, the fixed plane ports)
and are corrected there. `tests/manual/README.md` has the row.

## 2. Rename, prose and entrypoints only

- Both entrypoint docstrings rewritten present-tense: what the program
  takes, why it derives nothing, why it never binds. No launcher
  history, no clock keeper, no generator.
- The bare-name migration branch in `customs-inspect`'s `main()`
  deleted; argparse's five-missing-flags message is the right one here.
- `Handler.workload_uid`, the `workload=` log field, `--name`'s help
  text, "Installed to /usr/libexec/workloadctl/…" lines, and every
  citation of a workloadctl doc by path: renamed, pointed at `docs/`
  here, or dropped.
- `tests/__init__.py`'s docstring (`bin/`, `generators/` do not exist
  here).
- Long lines rewrapped as they are touched; the closure has ~180 over 79
  columns.
- Kept: every module name, every identifier the first fact lists.

Gate: 295 green; `test_closure.py` unchanged; a check that `lib/` and
`libexec/` contain no `workloadctl`, no "used to be", "once was", "it
was". Then `ruff check` with `E4,E7,E9,F,E501` at 79 columns becomes
`just lint`.

Done 2026-09-22. Also renamed, beyond the list: `AGENT_BROKER_SECRET` →
`CUSTOMS_BROKER_SECRET` (the dev-only fallback), the broker's `Server:`
header and `prog`, `CA_BUNDLE_PATH`'s file name (`customs.crt`), the CA
subject (`customs egress CA`), and every log line that named a
workloadctl TOML table (`[[vm.network.splice]]` → "the `splice` list").
Five tests that pinned those strings were re-derived. "Guest" stays.

## 3. Bring `test_inspect_listener.py` across

229 tests, blocked only on fixtures: a small `tests/fixtures.py` that
builds the policy documents workloadctl's `egress_policy` renders, by
hand, and names `libexec/customs-inspect` where the original names
`workload_addr.INSPECT_LISTENER_BIN`. Before step 4, so the listener's
behavioural suite is here before the listener changes.

Gate: the suite passes here unmodified apart from its imports.

Done 2026-09-22: 228 of 229 (the RPM-spec test has no spec to read);
`tests/policy_document.py` is the writer. Two rows re-derived: the
bare-name one now expects argparse's line, and the union-of-writers one
pins the document's vocabulary against one writer. 523 green.

## 4. Shape 1b: three flags, then the image

Flags first, each with a unit test and a wiring test that can be broken
on purpose:

- Broker `--listen unix:PATH`: a `UnixStreamServer` mix-in beside the
  TCP one, `SO_PEERCRED` in place of `/proc/net/tcp` for the caller
  check. `unix:` is a value form, so the flag name is unchanged.
- Inspector `--broker unix:PATH`: an `AF_UNIX` branch in
  `Upstream.dial_broker`. Same value form.
- Inspector `--caller-uid UID` (second fact). A deliberate change to the
  contract; `test_closure.py` is edited to say so.

Then the packaging `DESIGN.md` describes: the Containerfile carrying
both programs, an entrypoint that starts the broker as uid B and execs
`systemd-socket-activate` as uid A, `--secret` mounted at
`/run/secrets` with `CREDENTIALS_DIRECTORY` pointing at it, the pod
rules with the `skuid` exemption for both uids.

Gate: a second rig row on the proving host, with the same negative
probes plus one more — from the workload container, `connect()` to the
broker's socket path (must be ENOENT, not ECONNREFUSED). Expect the
substrate's seam defect; every substrate so far has had one.

Done 2026-09-22, in two commits: the three flags (each with a wiring
test broken on purpose), then `container/` and
`tests/manual/shape1b_rig.py`, 18 rows green and red without the rules.
The seam defect was the pair's: `peer_identity.userns_ranges` read the
outside column of `uid_map`, which every earlier layout had equal to the
inside one; a rootless container does not, and the broker refused its
own uid. Fixed here and mirrored to workloadctl on a branch. Two more
findings in the pair: SO_PEERCRED on a TCP socket answers uid -1 rather
than failing, and the record's `upstream` was null for a path socket;
both fixed in the flags commit. `systemd-socket-activate` is not used:
the entrypoint binds as root and hands the fds down, then drops uid.
The rigs now share `tests/manual/riglib.py`.

## 5. Decide copy versus dependency

After step 4, not before. Steps 1 and 4 will have shown how many fixes
had to go to both trees, which is the copy model's real cost, against
the dependency model's: an RPM dependency, and the first fact's
constants becoming a published interface. Shapes 2 (a VM inside the
container) and 3 (cosy) follow from whichever is chosen; cosy's half of
shape 3 lives in the cosy repo.
