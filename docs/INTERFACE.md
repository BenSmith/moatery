# The interface

What customs keeps stable for a program that imports its modules or
reads its status file. workloadctl is that program: it requires the
customs RPM, runs `customs-broker`, `customs-inspect` and
`customs-resolve`, imports the names below and reads the inspector's
and the responder's status files into its metrics and `workloadctl
doctor`. `tests/test_interface.py` holds the three lists to the code.

## Imported names

customs is a package, `customs`, installed where Python finds it; the
programs are in `/usr/libexec/customs/`. These are the names
workloadctl's shipped code imports:

```
customs.broker_profiles   BROKER_DEFAULT_AUTH_FORMAT
                          BROKER_DEFAULT_AUTH_HEADER
customs.egress_ca         CA_DIR_NAME DENIAL_DIR_NAME LEAF_DIR_NAME
                          ca_cert_path ca_dir ca_key_path
                          ca_openssl_argv denial_dir leaf_dir
customs.egress_mint       pem_fingerprint
customs.egress_plane      CLEARTEXT PLANES TLS
customs.egress_record     DROP_BROKER_UNREACHABLE DROP_MISDIRECTED
                          DROP_MISDIRECTED_LISTED DROP_NOT_HTTP
                          DROP_NOT_HTTP_POLICY DROP_REASONS
                          LOG_ID_FIELD LOG_REQ_FIELD
                          RECORD_DECISIONS RECORD_MODES
customs.egress_status     BoundedCounts OTHER_KEY STATUS_TOP_N
                          clear_status write_status
customs.inspect_document  INSPECT_DIGEST_KEY TLS_DEFAULT TLS_MODES
                          VmPolicyEntry hostname_control_character
                          hostname_match inspect_policy_digest
                          normalise_hostname patterns_overlap
                          policy_governs
customs.sd_listen         NotSocketActivated
                          inherited_listening_sockets
```

Some of these are unused inside customs (`clear_status`, `leaf_dir`,
`denial_dir`); they are here for workloadctl and are not dead code.
workloadctl's tests import further names; that its shipped code
imports nothing else is checked on its side.

## The inspector's status file

`customs-inspect --status PATH` replaces the file every few seconds. A
reader may rely on these paths, dotted through the JSON objects:

```
policy_digest               the policy's digest, "" for none
dispositions.spliced        connections spliced
dispositions.terminated     connections terminated
dispositions.forwarded      requests forwarded
dispositions.dropped        refused; drop_reasons sums to it
drop_reasons                {reason: count}, every DROP_REASONS key
per_host                    {reason: {host: count}}, bounded
per_host_totals             {reason: count}
concurrency.open            connections held now
concurrency.refused         refused at the connection ceiling
internal_refusals_total     per_host_totals' internal destination
caller_unresolved           connections whose caller was not named
credentialed                requests sent to the broker
credential_unauthorized     of those, answered 401 or 403
per_credential              {credential: count}, bounded
lists.policy                the policy entries, as loaded
record_failures             records the request log could not take
bumped                      refusals answered inside terminated TLS
ech.seen                    hellos with the ECH extension
ech.alarm                   of those, to a name on no list
mint.mints                  mint.* only under tls "inspect"
mint.hits
mint.denied_mints
mint.denied_hits
mint.throttled
mint.failed
mint.working_set
mint.denials
```

A key may be added; one of these is not renamed or removed without a
release that says so.

## The responder's status file

`customs-resolve --status PATH` replaces the file every thirty seconds
and on the way out, under the same promise:

```
queries.synthesised         A/AAAA answered with --address/--address6
queries.static              A/AAAA for a --static name
queries.nodata              every other type, and an AAAA with no v6
queries.malformed           queries that were not answerable DNS
unlisted                    A/AAAA for a name on no list and not static
unlisted_names              {name: count}, bounded
written_at                  when the file was written
```

`--static PATH` is a JSON object of name to a list of address strings,
read once at start, and refused whole, at start, over anything else.

## Module names

Within the package the module names are workloadctl's, except the
responder's two: `resolve_wire` and `resolve_serve` are workloadctl's
`dns_wire` and `resolve_server`. `resolve_policy` has workloadctl's
name and not its contents: it takes its answers from flags and the
`--static` file, where workloadctl's reads a document workloadctl
writes.
