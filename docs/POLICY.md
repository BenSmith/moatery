# The policy document

A policy says what a workload may send out. moatery denies by default:
the workload's outbound HTTP and HTTPS are redirected to the inspector,
which lets a request through only if the policy admits its host, and,
where the policy narrows that host, the request's method and path.
Everything else is refused. The policy also names the hosts that need a
credential the workload is not given; their requests go to the broker,
which attaches the real one, so the workload never holds it.

A policy names hosts, not addresses, and is checked against the name the
workload asked for: the TLS server name, or the `Host` header in
cleartext. It is one JSON object in a file, written by whoever runs the
workload and handed to `moat-inspect --policy PATH`.
`moat-resolve` reads the same file, to count the names the workload
looks up that no list admits.

```json
{
  "tls": "inspect",
  "hosts": ["pypi.org", "files.pythonhosted.org", "*.github.com",
            "git.corp.example", "updates.example.net"],
  "internal_expected": ["git.corp.example"],
  "splice": ["updates.example.net"],
  "policy": [
    {"host": "api.anthropic.com", "methods": ["POST"],
     "paths": ["/v1/messages"], "credential": "anthropic"},
    {"host": "github.com", "methods": ["GET"]}
  ]
}
```

This one lets the workload:

- make any request to PyPI's two hosts, to any subdomain of
  `github.com`, and to `git.corp.example`, a host on a private address;
- make only GET requests to `github.com` itself, which an entry
  narrows;
- make only a POST to `/v1/messages` on `api.anthropic.com`, which goes
  through the broker, which attaches the credential with the id
  `anthropic`;
- reach `updates.example.net`, whose TLS is passed through undecrypted,
  so its traffic is checked by name only.

Every key is optional. An absent list is an empty one; `{}` is a valid
document that admits nothing.

## Keys

| key | type | meaning |
|---|---|---|
| `tls` | `"inspect"` or `"splice"` | the mode for every TLS connection. Default `"inspect"`, which needs the workload to trust the inspector's CA before it first runs ([DESIGN.md](DESIGN.md), "The parts"). Anything else fails the start. |
| `hosts` | list of patterns | hosts the workload may reach, with any method and any path |
| `internal_expected` | list of names | hosts the operator has deliberately given a private address; changes how a failed dial is reported, and opens nothing |
| `splice` | list of patterns | hosts whose TLS is passed through undecrypted |
| `policy` | list of entries | per-host method and path rules, and brokered credentials |

A **pattern** is an `fnmatch` pattern (`*`, `?`, `[...]`), matched
case-sensitively against a normalised name: lowercased, one trailing dot
removed. `*` matches dots too, so `*.example.com` covers
`a.b.example.com`. It does not cover `example.com` itself; list the apex
separately.

## Which hosts get through

A host is admitted if it matches `hosts` or any `policy` entry's `host`.
Nothing else admits one: a name in `splice` or `internal_expected` must
also be admitted by one of those two.

An unadmitted host under `"inspect"` is not a dropped connection. The
inspector completes the handshake with a certificate for the refused name
and answers `403 Forbidden`, so the client sees a refusal rather than a
network error. The reason is in the record, not the response.

## Policy entries

```json
{"host": "PATTERN", "methods": ["GET", ...], "paths": ["/v1/*", ...],
 "credential": "ID"}
```

- `host` (required): a pattern, as above.
- `methods`: absent or `null` means any method. A list, compared
  uppercased. An empty list permits no method.
- `paths`: absent or `null` means any path. A list of `fnmatch` patterns,
  case-sensitive, matched against the request's path **without its
  query**, after percent-decoding of unreserved characters, dot-segment
  resolution and collapsing of duplicate slashes. `*` matches `/`. An
  empty list permits no path. A path holding an encoded slash is matched
  twice (see "Encoded slashes").
- `credential`: the id of a credential the broker holds for this host.
  It belongs to the HOST, not to the entry: present on any entry matching
  a host, it sends every permitted request to that host to the broker
  instead of the origin (see below).

`methods` and `paths` inside one entry are a cross product: two of each
permit all four combinations.

**The composition rule.** A host that any entry matches is governed by
those entries alone, and `hosts` is not consulted for it. Among the
entries that match, the rule is union: a request is permitted if any one
of them permits it. So:

- a `hosts` wildcard never widens a host a `policy` entry restricts;
- the order of entries never changes what is allowed;
- a narrower entry cannot carve an exception out of a wider one.

Where two matching entries name a `credential`, the first in the file is
used, for every request to the host.

## Brokered hosts

A host that any matching entry gives a `credential` is brokered: every
request to it that the entries permit goes to the broker named by
`moat-inspect --broker`, including a request only a credential-less
entry permits, and the broker attaches the real credential. So
`{"host": "api.x", "methods": ["GET"]}` beside
`{"host": "api.x", "methods": ["POST"], "credential": "k"}` brokers the
GET too. The broker selects the credential by the request's `Host`,
from its own `--host HOST=ID` flags, so the two must agree: the entry's
`credential` names the id in the record, and the broker's flag decides
what is sent. An inspector started without `--broker` refuses every
brokered request with a 502.

A brokered host must be terminated and read, so it cannot be spliced
(next section).

A brokered request needs a `Content-Length`. The broker reads the body
whole before it forwards it, and refuses a chunked one with `411 Length
Required`. The inspector passes that answer to the workload as if the
provider had sent it, and the record shows the request as forwarded with
status 411. A client that streams its upload (`Transfer-Encoding:
chunked`) fails against a brokered host. Provider SDKs send JSON bodies
with a length and are not affected.

Give a brokered entry `paths`. Without them the workload may call any
endpoint on the host with the real credential attached, including any
that echoes a request's headers back in its response, which hands the
workload the key.

## `splice`

A spliced connection is never decrypted: the inspector reads the SNI,
checks it, and replays the client's own bytes to the origin. The name is
checked once per connection and nothing inside it is seen. It is for a
client that cannot be given the CA, and `"tls": "splice"` applies it to
every host.

Nothing inside means the `Host` header too. A spliced name on a shared
front, such as a CDN that routes by `Host`, reaches every other site behind
that front: the workload names the allowed host in its handshake and another
in its request. The name is matched lowercased and without a trailing
dot, and the origin gets the workload's spelling, so a front that reads
`Allowed.Example.` as another name than `allowed.example` serves what it
chooses; the request's `Host` already lets the workload ask it anything.
Splice only names whose servers answer for themselves, and never a
wildcard over a provider's shared domain, which admits every customer on
it.

A hello carrying encrypted_client_hello (ECH) is refused on a connection
that would be spliced, with the reason `ECH on a spliced connection`.
ECH encrypts a second name inside the hello, and a front that supports it
serves that one, whatever the outer name the inspector checked. A
client's GREASE ECH is built to look the same, so both are refused. A
Chromium-based client sends it by default and fails against a spliced
host until it is turned off (`--disable-features=EncryptedClientHello`)
or the host is terminated. Clients on OpenSSL (Python, Node, curl) and
Go send none unless configured to. A terminated connection takes ECH:
the inspector completes that handshake itself.

## HTTP/2

Every terminated host is offered HTTP/1.1 alone, on both legs, whatever
the client or the origin would prefer, so every request is read and the
rules above apply to each one. A client that offers h2 beside HTTP/1.1
takes HTTP/1.1 without a sign.

A client that speaks only h2, a gRPC client say, is left with no protocol
and fails. Its host goes in `splice`, where its h2 runs end to end and the
host is checked by name alone, with everything `splice` says above. Many
gRPC libraries also have a REST transport, which is read like any other
request and keeps the host's rules.

An `http2` list that names a host fails the start, saying so; an empty
one is ignored. HTTP/2 without TLS is not relayed either: an
`Upgrade: h2c` offer is withheld from the origin, and a connection that
opens with the HTTP/2 preface is answered 400.

## Encoded slashes

An encoded slash (`%2F`) goes to the origin as it came, and origins
split on whether it separates two segments or sits inside one. So a
path holding one is matched against `paths` both ways, as sent and with
each `%2F` read as `/`, and is permitted only if both readings are, by
one entry or by two. `/v2/a%2Fb` is permitted by `/v2/*`; `/@types%2Fnode`
is refused by `/@types/*` alone, which the reading as sent does not
match, and permitted by `/@types*`. An entry with no `paths` permits
both, so npm, which asks for every scoped package this way, needs
nothing on its registry's host. A `paths` list there would have to name
every dependency an install fetches, scoped or not, so npm's registry
is best left without one.

A path whose `%2F`, read as `/`, makes a dot or empty segment
(`/v2/..%2Fadmin`, `/a%2F%2Fb`) is refused on every terminated host
before any list is consulted, with the reason `unreadable request`, and
the record has no host for it. An origin that splits on the slash
resolves that segment again, to a path neither reading names.

## Upgrades

A request with `Upgrade` (a WebSocket, say) is authorised like any other,
by its method and path. Once the origin answers `101 Switching Protocols`,
what flows on the connection is relayed without being read, so an entry's
`methods` and `paths` bound the upgrade request and nothing after it. An
upgrade to `h2c` is never forwarded.

## Port 80

Cleartext requests on port 80 are decided by the same rules, by the
`Host` header. `splice` does not apply there. A brokered host
is brokered on port 80 too, and the broker reaches the origin over TLS
either way.

## `internal_expected`

moatery does not block private, loopback or link-local destinations
(see [DESIGN.md](DESIGN.md), "Private addresses"), and
`internal_expected` does not open anything. It matters only on a host that
has a rule blocking them, with an exception for each name deliberately
given a private address. `internal_expected` lists those names — hosts
*expected* to sit in private space. When a dial fails:

- to a name that resolves to a private address and is **not** listed,
  it is reported as `internal destination`: the rule refused it, and the
  name needs an exception;
- to anything else, including a listed name, it is reported as
  `upstream unreachable`.

## Every host

A policy can admit every host and keep the inspector: TLS terminated,
each request recorded, a provider's key held by the broker. Its
`hosts` is `*`:

```json
{
  "hosts": ["*"],
  "policy": [
    {"host": "api.anthropic.com", "methods": ["POST"],
     "paths": ["/v1/messages"], "credential": "anthropic"}
  ]
}
```

`*` matches every name, so a request to any host, with any method and
path, is let through and recorded. The entry still governs its own host,
by the composition rule: the key is attached to a POST to `/v1/messages`,
and every other request to `api.anthropic.com` is refused. Without
`policy`, `{"hosts": ["*"]}` admits everything and brokers nothing.

In a hut this sits between a listed policy and `--network-policy none`
([MOATHUT.md](MOATHUT.md), "A hut with no network policy"), which
reaches every port but has no inspector, record or broker.

`*` opens only what the rules send to the inspector, so it is not an open
network:

- **Only HTTP and HTTPS leave**, on TCP 80 and 443. Every other port,
  UDP 443 (HTTP/3) included, meets the drop ([DESIGN.md](DESIGN.md),
  "The rules"). git over ssh, a database's own protocol and anything else
  that is not HTTP still fail.
- **Names still resolve to the responder's one address**
  ([DESIGN.md](DESIGN.md), "DNS: answered, never forwarded"). A client
  that needs a host's real address, or a record other than A and AAAA,
  gets none.
- **Every TLS connection is terminated**, so every client must trust the
  inspector's CA. One that pins a certificate or carries its own trust
  store fails, and so does one that speaks only h2 ([HTTP/2](#http2)).
  Name those hosts in `splice`, one by one, never as `*` or as a wildcard
  over a shared domain ([`splice`](#splice)).
- **A TLS connection must name its host.** A hello with no server name,
  which is what a client sends when it dials an address, is refused with
  the reason `no server name`. On port 80 an IPv4 address in `Host` is
  a name `*` matches, and the inspector dials it.
- **Private destinations are reached.** The inspector dials whatever an
  admitted name resolves to, local network included
  ([DESIGN.md](DESIGN.md), "Private addresses"). A host rule
  blocking private space is what keeps the workload off the local
  network.

Admitting every host, the inspector refuses no destination: whatever the
workload holds can leave over HTTPS. What `*` keeps is the record of
where it went and the broker: the real key is attached outside the
workload, and the workload never holds it.

## Loading and reloading

The inspector reads the document at start, and again on SIGUSR1
(`ExecReload=kill -USR1 $MAINPID`, and `systemctl reload`). A reload
applies from each connection's next decision: a request already
relaying finishes, and the next one on its connection is decided
against the new document. `tls` is the one key a reload cannot change,
since the minter was built for it; that needs a restart. The running
policy is the last document loaded, and the status file carries the
SHA-256 of its text (`policy_digest`), so the two can be compared.

A document that cannot be read or parsed fails the start, and fails a
reload, which logs why and keeps the document loaded. There is no
fallback to an empty policy.

### Refused

Two combinations describe a rule that could never run, and the document
is refused rather than one half being ignored:

- `policy` entries with `"tls": "splice"` — nothing is decrypted, so no
  method, path or credential applies;
- a `policy` entry whose host overlaps a `splice` pattern.

Also refused: a key of the wrong type (a list that is not a list, a name
that is empty or not a string, an entry with no `host`, `methods` or
`paths` given as a string), and an `http2` list that names a host (see
[HTTP/2](#http2)).

A `credential` that is not a non-empty string is ignored rather than
refused; that request then goes to the origin unbrokered, and its record
line carries no credential.

## Request filters

A second document, `moat-inspect --request-filters PATH`, names hosts
whose request bodies pass through a program before they leave. The
program, the filter, reads the body and either writes the body to send
or refuses the request. The policy still says what the workload can
reach; this document opens nothing, and a host it names is admitted, or
not, by the policy alone. Without the flag nothing is filtered.

```json
{"filters": [
  {"host": "api.example.com", "run": "/usr/local/libexec/example-filter"}
]}
```

`filters` is the only key, and an entry has exactly `host` and `run`.

- `host` is a pattern, as above, matched against the request's host:
  the name the policy decided it on. It follows hosts however they were
  admitted, by `hosts`, by `*` or by a `policy` entry, and brokered or
  not, so a brokered host's broker receives the filtered body. A
  spliced host is never decrypted, so a `splice` pattern carves its
  names out of `host`, as it does out of `hosts`: `*` beside a `splice`
  list filters every host but those.
- `run` is the filter: an absolute path to a regular file the inspector
  can execute and that is not group- or world-writable, checked through
  any link. It is exec'd directly, with no arguments and no shell.

Two entries whose patterns can match one name must have the same `run`,
so the order of entries never matters.

### Loading

The inspector reads the document at start, after the policy, and a
document that is missing or refused fails the start. SIGUSR1 reloads
the two as a pair: both are swapped, or neither is, and the `WARNING:`
line names the document that was refused. So a policy whose `splice`
would cover a filter's whole pattern is refused at a reload, and the
old policy and filters stay; one that covers part of it is enforced,
and that part goes unfiltered. The line that names the document loaded
ends with `spliced=`, the `splice` patterns that leave some of a
filter's hosts unfiltered, when there are any. The status file carries
the SHA-256 of the document's text as `request_filters_digest`, and
its entries under `lists.request_filters`, each with those patterns as
`spliced`.

Refused, naming what:

- a key other than those above, at either level;
- a `host` or `run` that is empty or not a string, or `filters` that is
  not a list;
- two overlapping entries with different `run`;
- any entry under `"tls": "splice"`, and an entry a `splice` pattern
  covers, every host it names spliced: a spliced connection is never
  read, so the filter could never run;
- a `run` that is relative, missing, not a regular file, not
  executable, or group- or world-writable.

### The contract

What a filter is given, and what it answers:

- **stdin** is the body. A chunked body is decoded first, and its
  trailers dropped.
- **stdout** is the body to send. The inspector sends it with a
  `Content-Length` of its own and no `Transfer-Encoding`, so an empty
  output sends an empty body.
- **The environment** is exactly these eight names, and no header
  beyond the content type is ever given:

  | name | |
  |---|---|
  | `MOAT_ID` | the connection's id, as in the journal and the record |
  | `MOAT_REQ` | the request's ordinal on the connection |
  | `MOAT_HOST` | the request's host |
  | `MOAT_METHOD` | its method |
  | `MOAT_PATH` | its path, without the query |
  | `MOAT_CONTENT_TYPE` | its `Content-Type` |
  | `MOAT_LENGTH` | the body's length in bytes, as given on stdin |
  | `PATH` | `/usr/bin:/bin` |

- **The process** has `/` as its working directory, descriptors 0, 1
  and 2 and no other, a session of its own, and no signal ignored.
- **Exit 0** sends stdout. The record shows `passed`, or `rewrote` if
  the output differs from the body.
- **Exit 77** refuses the request. The first line of stderr is the
  reason if it is a token (`[a-z0-9._-]{1,64}`), and `unnamed`
  otherwise.
- **Any other exit**, or a signal, is a failure. A refusal is not 1,
  because an uncaught Python exception and the wrapper's own failure
  both exit 1.

Stderr is never logged: past the reason, it is read and thrown away.

A request with no body, or with `Content-Length: 0`, is sent unfiltered.
The filter runs once per request with a body, and is given 10 seconds.
A body is held whole while it runs, up to 64 MiB, and every body being
filtered, with the filter's output, shares 256 MiB. At most eight
filters run at once; a request waits for one to finish, within its 10
seconds.

### What a filtered host gets

Before anything is read:

- a request offering `Upgrade` is refused, 403: what follows a `101`
  would go unread;
- a body with a `Content-Encoding` other than `identity` is refused,
  415, since a filter of its bytes would pass it unchanged;
- a declared length over 64 MiB is refused, 413.

Then the body is read, `100 Continue` sent first if the client asked
for it, and the filter is run. Nothing is dialled until it has
finished: the origin or the broker hears of a request only once the
filter has said to send it.

| what happened | the client gets | the reason |
|---|---|---|
| exit 0 | the origin's answer | — |
| exit 77 | 403 | `refused by filter` |
| the 10 seconds passed; the filter and its session are killed | 504 | `filter timed out` |
| killed by SIGKILL the inspector did not send (likely the OOM killer), or exit 137 through a wrapper | 503 | `filter unavailable` |
| the start failed for want of a process or memory, or `run` was open for writing (`EAGAIN`, `ENOMEM`, `ETXTBSY`) | 503 | `filter unavailable` |
| the shared 256 MiB, or the eight filters, are taken | 503 | `filter unavailable` |
| `run` is missing, not executable, or not a program (`ENOENT`, `EACCES`, `ENOEXEC`), with a `WARNING:` line | 502 | `filter failed` |
| any other exit, or another signal (exit 128 and over through a wrapper) | 502 | `filter failed` |
| output over 64 MiB | 502 | `filter failed` |
| an upgrade, an encoded body, or a declared length over 64 MiB | 403, 415, 413 | `request not filterable` |

A refusal or a failure comes after the body has been read, so the
connection is kept for the client's next request. A chunked body that
turns out to be over 64 MiB is refused 413 with the connection closed,
since the rest of it is unread.

### What is not covered

- **A spliced connection.** Nothing in it is read, which is why a
  filter over a spliced host is refused.
- **After a `101`.** A filtered host takes no upgrade.
- **A name no pattern matches.** A filter covers its patterns' hosts
  only, so a `*` in `hosts` admits hosts no filter reads.
- **Everything but the body.** The filter sees the eight names above;
  the headers and the query go up as they came. The response is not
  filtered.

### Trusting a filter

The filter decides what leaves, and is trusted to: the inspector checks
how it exited, not what it wrote. It also parses bytes the workload
chose, outside the workload's namespaces and as the inspector's user.
Run bare, a bug in it is a way out of the workload, with the user's
home, network and session bus to hand. A filter inherits the
inspector's unit, so where that unit has `MemoryDenyWriteExecute=`, a
runtime that compiles code as it runs fails there.

### The wrapper

[examples/request-filter/](../examples/request-filter/) holds a
wrapper, `sandboxed`, that `run` names in the filter's place. It runs
the filter named on its `FILTER=` line under `bwrap` with:

- `--unshare-all`, so no network, and namespaces of its own;
- `--unshare-user` and `--disable-userns`, so it makes no user
  namespace of its own;
- `--die-with-parent`, so a filter killed at its deadline takes the
  sandbox with it;
- `--new-session`, so it can push nothing into a terminal;
- `--cap-drop ALL`;
- a filesystem of `/usr` read-only, the filter itself, `/proc`, `/dev`
  and an empty `/tmp`: no home, no runtime directory, no session bus
  and no credentials.

The inspector checks `run`, so it checks the wrapper, not the file the
wrapper names: that file must be just as far from the workload's reach.
The wrapper makes namespaces and mounts, which the inspector's unit has
to allow ([DESIGN.md](DESIGN.md), "Request filters"). Where it is
refused them, bwrap exits 1 and every filtered request fails, 502.
