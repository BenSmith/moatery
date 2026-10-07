# What moatery reports

The inspector reports in three places, and each answers a different
question:

- **The journal**: a line for each connection and each decision, with
  the reason for every refusal. Use it to ask why something happened.
- **The record**: one JSON line for each request or refused connection.
  It is private to the user, and it is what `moathut log` reads.
  Use it to ask what the workload did.
- **The status file**: counters, replaced every 30 seconds, at a reload
  and at stop. Use it to ask how much, and whether anything is wrong.

The responder writes a status file of its own. The drop chain in the
workload's namespace counts the packets it drops. Where each one lives
depends on how the programs were placed: `examples/README.md` gives the
paths for the user units, and [MOATHUT.md](MOATHUT.md), "Files", gives them for
a hut.

## The journal

Each line begins with a verb, then the connection's key, then fields:

```
drop id=5c0e81a2f4d3 plane=tls local=169.254.1.3:8443 peer=10.0.2.100:40112 req=2 host=evil.example suspect=yes reason="host does not match the server name: the session is for api.example"
```

`id` is the same on every line and record line of one connection.
`req` is the request's ordinal on that connection, and appears on the
lines that concern one request. Every `reason` is quoted, since the
workload's bytes can reach it. A drop's reason begins with the reason as the
status file counts it, so one grep finds both.

| verb | what happened |
|---|---|
| `splice` | a TLS connection passed through, checked by its name only; `alpn=` is what the client offered |
| `terminate` | a TLS connection completed here, its requests then checked one by one |
| `forward` | a request relayed |
| `upgrade` | a request answered `101`; nothing after it is checked |
| `drop` | a connection or a request refused |
| `bump` | a refusal answered inside a completed handshake, so the client sees a status rather than a reset |
| `rejected` | a connection refused before it was read: the connection ceiling, or a caller that is not this workload |
| `note` | something reported that refuses nothing ("Notes") |
| `close` | a kept-alive connection reached its idle bound, or its client reset it between requests |
| `policy reloaded` | SIGUSR1 loaded a new document; a `WARNING:` line if it was refused |

`WARNING:` lines are the inspector's own trouble, such as a status or
record file it could not write.

### Refusals

Every reason, as the journal, the record and `drop_reasons` spell it:

| reason | |
|---|---|
| `not allowlisted` | the name is on no list |
| `not permitted by policy` | the host's `policy` entries refuse this method or path |
| `not TLS` | the TLS port was sent something else (suspect) |
| `malformed ClientHello` | a hello no TLS library writes, or a server name with a character or an empty label no name has (suspect) |
| `ClientHello incomplete` | the hello did not arrive whole: closed, cut short or too slow |
| `no server name` | the hello names no server: a connection to an address (suspect) |
| `ECH on a spliced connection` | a hello that would be spliced carries ECH, so the name it was spliced on may not be the real one |
| `host does not match the server name` | a request inside a session named a host on no list (suspect) |
| `host does not match the server name (allowlisted)` | the same for a listed host: usually a client reusing one connection for two names |
| `not HTTP`, `not HTTP (policy entry)` | a terminated session did not carry HTTP; the host needs `splice` |
| `unreadable request` | a request head this relay does not read |
| `internal destination` | the dial failed and the name resolves to a private address the policy does not expect: most likely the host's rule refused it ([DESIGN.md](DESIGN.md), "Private addresses") |
| `upstream unreachable`, `timed out` | the network, either end |
| `relay failed` | the network, either end, or an origin's answer this relay does not pass on, such as a header that frames the body only for a parser that trims it; the line's text says which |
| `upstream certificate unverified` | the origin's certificate did not verify |
| `upstream wants a client certificate` | the host needs `splice` |
| `credential broker unreachable` | the request needs a key and the broker did not answer; nothing was sent |
| `connection ceiling reached`, `mint rationed`, `could not mint a leaf` | the inspector's own limits |
| `caller is not this workload` | a connection from another uid (suspect) |
| `caller closed before it was identified` | the caller left before its uid was read |

**Suspect** marks what no client following its own configuration
produces: the journal line carries `suspect=yes`, the status file sums
them as `suspects`, and `moathut log` ends the line with `suspect`.
None needs a change to the policy. Each is worth a look.

### Notes

A note refuses nothing. Its reason begins with its kind, and the status
file counts each kind under `notes`:

- `ECH`: a hello carrying encrypted_client_hello. Most are a client's
  GREASE, which looks the same. A terminated connection hides nothing
  either way.
- `h2 only`: a client offered HTTP/2 and not HTTP/1.1, so it will likely
  fail. A gRPC client, most often; its host needs `splice`.
- `h2 preface`: a connection opened with HTTP/2's preface. It was
  answered 400.
- `h2c withheld`: a request offered `Upgrade: h2c`. It went up without
  the offer, as HTTP/1.1, and worked as that.

Two more notes are journal only, uncounted: a redirect to a host no list
admits, and one to a path the host's policy will refuse. Each names both
hosts, which the refusal of the followed redirect cannot.

## The record

One JSON object per line, mode 0600. Every line has every field, null
where it was not measured:

| field | |
|---|---|
| `id`, `req` | the connection and the request's ordinal, as in the journal |
| `ts` | when it began, UTC, to the millisecond |
| `plane` | `tls` or `cleartext` |
| `mode` | `forward` (cleartext), `terminate` or `splice` |
| `host`, `method`, `path`, `query`, `http` | the request; the query apart from the path, since it can carry a secret |
| `decision` | `forward` or `drop` |
| `reason` | a drop's reason, as above |
| `status` | what the client was told, or the origin's status |
| `upstream` | the address actually dialled, or `unix:PATH` for the broker |
| `credential` | the credential's name for a brokered request, never the key |
| `duration_ms` | |

No headers and no bodies, ever. A spliced connection is one line, since
nothing inside it is read.

Past 512 MiB the inspector writes nothing more, counts the lines it
loses as `record_failures`, and warns once. Refusals stop at three
quarters of that, so a flood of them leaves room for the requests let
through. SIGHUP reopens the file at its next write, which is how a
rotation lands: `examples/logrotate/` for the user units, and a hut
rotates its own record at 32 MiB.

## The status file

JSON, replaced whole. [INTERFACE.md](INTERFACE.md) lists the keys a
program may rely on. Those most read by hand:

- `dispositions` and `drop_reasons`: what was decided, and why each
  refusal was made. `drop_reasons` has every reason, zero or not, and
  sums to `dispositions.dropped`.
- `suspects`: the refusals marked suspect.
- `per_host`: for the refusals an operator fixes by naming a host, which
  hosts. Bounded, with the totals exact in `per_host_totals`.
- `notes`, `alpn_offered`, and `ech.seen` and `ech.alarm`: `ech.alarm`
  counts ECH on a hello to a name on no list.
- `record_failures`: lines the record lost. Not zero means the record
  is incomplete.
- `policy_digest` and `lists`: the policy this process enforces, which
  is not always what the file says.

## The responder

moat-resolve writes a line per query, with the name, the type and
what it was answered:

```
  api.example A -> synthesised: 1 record(s)
  api.example HTTPS -> nodata
```

Only A and AAAA are answered; every other type gets an empty answer.
Its status file counts what it answered. `unlisted` counts the queries
for names no list admits, with the first twenty in `unlisted_names`. A
rising `unlisted` is evidence that something is trying, never that
anything left: nothing is asked onward. Some are only lookups a tool
made and did not need.

`https` counts the HTTPS and SVCB queries. A client asks one to learn
whether a host offers HTTP/3 or ECH, and the empty answer tells it
neither is offered. Browsers ask before connecting, so a count here is
normal: it measures the clients that would use HTTP/3 if they could.

## What is not seen

- **HTTP/3.** QUIC is dropped in the kernel, before any program sees it.
  The nft chain's `quic` counter counts the UDP 443 packets it drops
  ([DESIGN.md](DESIGN.md), "The rules"). A client that falls back to TCP is
  then served and logged as usual.
- **Inside a spliced connection.** Only its name, and whether its hello
  carried ECH.
- **After an upgrade.** A WebSocket's frames are relayed unread.

## What to look for

```
journalctl --user -u moat-inspect | grep suspect=yes
journalctl --user -u moat-inspect | grep ' note '
journalctl --user -u moat-inspect | grep 'id=5c0e81a2f4d3'
jq -c 'select(.decision == "drop")' requests.log
jq '{suspects, notes, drop_reasons}' status.json
jq '{unlisted, https, unlisted_names}' resolve-status.json
```

For a hut, `moathut log NAME` follows its record, and
`moathut log NAME --refused` sums what its policy still refuses.
