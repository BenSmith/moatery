# What lifts out of workloadctl

Computed 2026-09-22 from the two entrypoints' import closures in
`workloadctl/lib/` (the closure tests `test_broker_closure.py` and
`test_inspector_closure.py` hold these sets to contain no workload-side
module).

## customs-broker ← `libexec/agent-broker`

4 modules:

```
broker_profiles  broker_request  broker_server  peer_identity
```

## customs-inspect ← `libexec/workload-inspect-listener`

21 modules:

```
egress_ca  egress_mint  egress_plane  egress_record  egress_relay
egress_status  egress_upstream  h2_framing  http_framing  http_request
http_target  inspect_counters  inspect_document  inspect_http
inspect_listener  inspect_policy  inspect_scope  inspect_tls
peer_identity  sd_listen  tls_hello
```

## Union

24 modules, ~358 KB, two entrypoints. `peer_identity` is the one module
both share (caller identification by the uid owning the far end of a TCP
connection, read from `/proc/net/tcp`).

## Not lifted

Anything that renders the policy document or the units: `egress_policy`
(the JSON writer), `broker_config` (the argv builder), `gen_egress`,
`gen_container`, `gen_vm`, `workload_addr`. Those are workloadctl's
opinion about where the values come from; customs takes the values.

Also not lifted: the workloadctl tests. The unit tests for these modules
would come across with them; the manual rigs (`broker_rig.py`,
`container_egress_rig.py`) are workloadctl-shaped and would be replaced
by a customs-shaped one.

## Copied

All 24 modules and both entrypoints, verbatim, on 2026-09-22, plus
`tests/__init__.py`, `tests/covhelper.py` and the six unit-test modules
whose lib imports lie entirely inside the closure:
`test_broker_config`, `test_broker_identity`, `test_broker_request`,
`test_inspect_terminate`, `test_mint`, `test_vm_status`. workloadctl's
two closure tests were replaced by `test_closure.py`.

`test_inspect_listener.py` (228 tests) came across with
`tests/policy_document.py` standing in for `egress_policy`'s renderers --
a hand-written writer of the document, since customs ships only its
reader -- and the one test that read the RPM spec dropped. The other
twelve partial modules are workloadctl's own (arming, diagnose, units,
generator) and stay.

## Decision: dependency

Decided 2026-09-22, with steps 1 and 4 of `PLAN.md` behind it. The two
models were: a copy (two trees, workloadctl keeps its own) or a
dependency (one tree; workloadctl's RPM requires customs and its units
run `customs-broker` and `customs-inspect`).

The copy model's cost was to be measured in fixes that had to go to
both trees. The count is one -- `peer_identity.userns_ranges` reading
the wrong column of `uid_map` -- and it is a caller-identity check in a
credential broker, found by a shape workloadctl does not run, sitting on
an unmerged branch in the hypervisor repo. That is the copy model
working as designed: every shared fix becomes a merge someone must
remember, and the fixes flow one way, since the shapes here exercise
code paths workloadctl's own layouts never reach.

The dependency model's cost was an RPM dependency and the imported
identifiers becoming a published interface. The second half is paid:
the rename kept every module name and every identifier workloadctl
imports, and `test_closure.py` holds that boundary. The flags added
here are off unless given, so workloadctl running this code gains
nothing it has to think about.

### Until the first release

workloadctl cannot require a package that has no release. Until customs
has a tag and an RPM, workloadctl keeps its copy and the mirror rule
holds: a fix that matters to both is committed here and on a new branch
in the hypervisor repo. At the first release the workloadctl copy is
deleted, not maintained; the branch carrying any unmerged mirror is
superseded by the dependency.

What the switch costs on the workloadctl side, all in the hypervisor
repo: `Requires: customs` in its spec; its units naming the two
entrypoints here (or two symlinks under its own libexec); its twelve
test modules that import partially from the closure importing from the
installed package; its two closure tests retired in favour of
`test_closure.py` here. Nothing changes in customs.
