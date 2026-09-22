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

## Open decision

Lift as a copy (two trees, workloadctl keeps its own) or lift and have
workloadctl depend on customs (one tree, an RPM dependency). Not decided.
