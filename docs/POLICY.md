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
  empty list permits no path.
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
in its request. Splice only names whose servers answer for themselves,
and never a wildcard over a provider's shared domain, which admits every
customer on it.

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
`paths` given as a string), an `http2` list that names a host (see
[HTTP/2](#http2)), and an `internal` list that names one, which the
error says to rename `internal_expected`.

A `credential` that is not a non-empty string is ignored rather than
refused; that request then goes to the origin unbrokered, and its record
line carries no credential.
