# customs and workloadctl

customs is the egress inspector and credential broker lifted out of
workloadctl, whose copy lives in the hypervisor repo. This is how the two
relate: which is the dependency, what the interface between them is, and
what happens at customs' first release.

## Decision: dependency

There were two models: a copy (two trees, workloadctl keeps its own) or a
dependency (one tree; workloadctl's RPM requires customs and its units
run `customs-broker` and `customs-inspect`).

Under the copy model every shared fix becomes a merge someone must
remember. The fixes also flow one way, because the shapes here exercise
code paths that workloadctl's own layouts never reach. The first such fix
was `peer_identity.userns_ranges` reading the wrong column of `uid_map`: a
caller-identity check in a credential broker, found by a shape
workloadctl does not run.

The dependency model costs an RPM dependency and turns the identifiers
workloadctl imports into a published interface. The flags customs adds
are off unless given, so workloadctl running this code gains nothing it
has to think about.

## The interface

Module names are unchanged from workloadctl, and so is every identifier
its shipped code imports from `lib/`:

```
broker_profiles   BROKER_DEFAULT_AUTH_FORMAT BROKER_DEFAULT_AUTH_HEADER
egress_ca         CA_DIR_NAME DENIAL_DIR_NAME LEAF_DIR_NAME
                  ca_cert_path ca_dir ca_key_path ca_openssl_argv
                  denial_dir leaf_dir
egress_mint       pem_fingerprint
egress_plane      CLEARTEXT PLANES TLS
egress_record     DROP_BROKER_UNREACHABLE DROP_MISDIRECTED
                  DROP_MISDIRECTED_LISTED DROP_NOT_HTTP
                  DROP_NOT_HTTP_POLICY DROP_REASONS LOG_ID_FIELD
                  LOG_REQ_FIELD RECORD_DECISIONS RECORD_MODES
egress_status     BoundedCounts OTHER_KEY STATUS_TOP_N clear_status
                  write_status
inspect_document  INSPECT_DIGEST_KEY TLS_DEFAULT TLS_MODES
                  VmPolicyEntry hostname_control_character
                  hostname_match inspect_policy_digest
                  normalise_hostname patterns_overlap policy_governs
sd_listen         NotSocketActivated inherited_listening_sockets
```

Some of these are unused inside customs (`clear_status`, `leaf_dir`,
`denial_dir`); they are here for workloadctl and are not dead code.
workloadctl's tests import further names from the closure.
`tests/test_extraction.py` holds each name here to be defined in its
module; that workloadctl imports nothing else is checked on its side.

## Until the first release

workloadctl cannot require a package that has no release. Until customs
has a tag and an RPM, workloadctl keeps its copy and the mirror rule
holds: a fix that matters to both is committed here and on the
hypervisor repo's `customs-mirror` branch. At the first release the
workloadctl copy is deleted, not maintained; whatever of that branch is
unmerged is superseded by the dependency.

What the switch costs on the workloadctl side, all in the hypervisor
repo:

- `Requires: customs` in its spec.
- Its units naming the two entrypoints here (or two symlinks under its
  own libexec).
- Its test modules that import partially from the closure importing
  from the installed package.
- Its two closure tests retired in favour of `test_closure.py` here.

Nothing changes in customs.

workloadctl's own responder, `workload-vm-resolve`, is not part of the
switch. `customs-resolve` was taken from it without the static map
workloadctl's VMs use to name non-HTTP destinations, and takes its
answers as flags rather than from a document workloadctl writes; the two
share the wire parser's shape and the no-upstream test, not a module.
