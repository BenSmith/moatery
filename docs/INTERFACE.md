# The interface

What moatery keeps stable for a program built on it: one that runs
`moat-broker`, `moat-inspect`, `moat-mint-ca` and
`moat-resolve`, imports the names below (to write a policy the
inspector will accept, say, or to lay out a CA where the inspector
looks for it) and reads the inspector's and the responder's status
files into its own metrics. `tests/test_interface.py` holds the three
lists to the code.

## Imported names

moatery is a package, `moatery`, installed where Python finds it; the
programs are in `/usr/libexec/moatery/`. These are the names a program
may import:

```
moatery.broker_profiles   BROKER_DEFAULT_AUTH_FORMAT
                          BROKER_DEFAULT_AUTH_HEADER
moatery.egress_ca         CA_DIR_NAME DENIAL_DIR_NAME LEAF_DIR_NAME
                          ca_cert_path ca_dir ca_key_path
                          ca_openssl_argv denial_dir leaf_dir
moatery.egress_mint       pem_fingerprint
moatery.egress_plane      CLEARTEXT PLANES TLS
moatery.egress_record     DROP_BROKER_UNREACHABLE DROP_MISDIRECTED
                          DROP_MISDIRECTED_LISTED DROP_NOT_HTTP
                          DROP_NOT_HTTP_POLICY DROP_REASONS
                          LOG_ID_FIELD LOG_REQ_FIELD
                          RECORD_DECISIONS RECORD_MODES
moatery.egress_status     BoundedCounts OTHER_KEY STATUS_TOP_N
                          clear_status write_status
moatery.inspect_document  INSPECT_DIGEST_KEY TLS_DEFAULT TLS_MODES
                          VmPolicyEntry hostname_control_character
                          hostname_match inspect_policy_digest
                          normalize_hostname patterns_overlap
                          policy_governs
moatery.request_filter    REQUEST_FILTERS_DIGEST_KEY
                          load_request_filters
moatery.sd_listen         NotSocketActivated
                          inherited_listening_sockets
```

Some of these are unused inside moatery (`clear_status`, `leaf_dir`,
`denial_dir`); they are here for such a program and are not dead code.
Any other name in the package may be renamed or removed in any release.

## The inspector's status file

`moat-inspect --status PATH` writes the file at start and replaces it
every thirty seconds, at a reload and on the way out. A reader may rely
on these paths, dotted through the JSON objects:

```
policy_digest               the policy's digest, "" for none
request_filters_digest      the request filters' digest, "" for none
dispositions.spliced        connections spliced
dispositions.terminated     connections terminated
dispositions.forwarded      requests forwarded
dispositions.dropped        refused; drop_reasons sums to it
filtered.passed             forwarded by a request filter, unchanged
filtered.rewrote            forwarded by a request filter, changed
drop_reasons                {reason: count}, every DROP_REASONS key
suspects                    of those, the SUSPECT_REASONS
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
lists.request_filters       the request filters, as loaded
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

## A request filter

`moat-inspect --request-filters PATH` runs the program a document
names over each request body to a host it names ([POLICY.md](POLICY.md),
"Request filters"). What the program is given and what its exit means
are kept as stable as the names above:

```
MOAT_ID MOAT_REQ MOAT_HOST MOAT_METHOD MOAT_PATH MOAT_CONTENT_TYPE
MOAT_LENGTH PATH
```

the whole environment, and exit 0 sends its stdout, 77 refuses the
request, and anything else is a failure. `load_request_filters` is the
inspector's own check of a document, and the digest it records is the
SHA-256 of the document's text, as `policy_digest` is the policy's.

## The responder's status file

`moat-resolve --status PATH` replaces the file every thirty seconds
and on the way out, under the same promise:

```
queries.synthesised         A/AAAA answered with --address/--address6
queries.static              A/AAAA for a --static name
queries.nodata              every other type, and an AAAA with no v6
queries.malformed           queries that were not answerable DNS
https                       HTTPS and SVCB, of queries.nodata
unlisted                    A/AAAA for a name on no list and not static
unlisted_names              {name: count}, bounded
written_at                  when the file was written
```

`--static PATH` is a JSON object of name to a list of address strings,
read once at start, and refused whole, at start, over anything else.
