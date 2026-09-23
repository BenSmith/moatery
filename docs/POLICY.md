# The policy document

`customs-inspect --policy PATH` reads one JSON object, once, at start. An
edited document applies on a restart; the running policy is always the
file's as it was when the inspector started, and the status file carries
the SHA-256 of the text it loaded (`policy_digest`) so the two can be
compared.

A document that cannot be read or parsed fails the start. There is no
fallback to an empty policy.

```json
{
  "tls": "inspect",
  "hosts": ["pypi.org", "files.pythonhosted.org", "*.github.com"],
  "internal": ["git.corp.example"],
  "splice": ["updates.example.net"],
  "http2": ["files.pythonhosted.org"],
  "policy": [
    {"host": "api.anthropic.com", "methods": ["POST"],
     "paths": ["/v1/messages"], "credential": "anthropic"},
    {"host": "github.com", "methods": ["GET"]}
  ]
}
```

Every key is optional. An absent list is an empty one; `{}` is a valid
document that admits nothing.

## Keys

| key | type | meaning |
|---|---|---|
| `tls` | `"inspect"` or `"splice"` | the mode for every TLS connection. Default `"inspect"`. Anything else fails the start. |
| `hosts` | list of patterns | hosts the workload may reach, with any method and any path |
| `internal` | list of names | hosts the operator has deliberately given a private address; changes how a failed dial is reported, and opens nothing |
| `splice` | list of patterns | hosts whose TLS is passed through undecrypted |
| `http2` | list of patterns | terminated hosts offered h2 and relayed frame by frame |
| `policy` | list of entries | per-host method and path rules, and brokered credentials |

A **pattern** is an `fnmatch` pattern (`*`, `?`, `[...]`), matched
case-sensitively against a normalised name: lowercased, one trailing dot
removed. `*` matches dots too, so `*.example.com` covers
`a.b.example.com`. It does not cover `example.com` itself; list the apex
separately.

## Which hosts get through

A host is admitted if it matches `hosts` or any `policy` entry's `host`.
Nothing else admits one: a name in `splice`, `http2` or `internal` must
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
`customs-inspect --broker`, including a request only a credential-less
entry permits, and the broker attaches the real credential. So
`{"host": "api.x", "methods": ["GET"]}` beside
`{"host": "api.x", "methods": ["POST"], "credential": "k"}` brokers the
GET too. The broker selects the credential by the request's `Host`,
from its own `--host HOST=ID` flags, so the two must agree: the entry's
`credential` names the id in the record, and the broker's flag decides
what is sent. An inspector started without `--broker` refuses every
brokered request with a 502.

A brokered host must be terminated and read as HTTP/1.1, so it cannot be
spliced or in `http2` (next section).

Give a brokered entry `paths`. Without them the guest may call any
endpoint on the host with the real credential attached, including any
that echoes a request's headers back in its response, which hands the
guest the key.

## Refused at start

Three combinations describe a rule that could never run, and the
document is refused rather than one half being ignored:

- `policy` entries with `"tls": "splice"` — nothing is decrypted, so no
  method, path or credential applies;
- a `policy` entry whose host overlaps a `splice` pattern;
- a `policy` entry whose host overlaps an `http2` pattern — h2 headers
  are relayed compressed, so there is no request line to match.

Also refused: a key of the wrong type (a list that is not a list, a name
that is empty or not a string, an entry with no `host`, `methods` or
`paths` given as a string).

A `credential` that is not a non-empty string is ignored rather than
refused; that request then goes to the origin unbrokered, and its record
line carries no credential.

## `splice`

A spliced connection is never decrypted: the inspector reads the SNI,
checks it, and replays the client's own bytes to the origin. The name is
checked once per connection and nothing inside it is seen. It is for a
client that cannot be given the CA, and `"tls": "splice"` applies it to
every host.

Nothing inside means the `Host` header too. A spliced name on a shared
front, such as a CDN that routes by `Host`, reaches every other site behind
that front: the guest names the allowed host in its handshake and another
in its request. Splice only names whose servers answer for themselves.

Under `"inspect"` the workload must trust the inspector's CA before it
first runs; see [DESIGN.md](DESIGN.md), "The same in every shape".

## `http2`

A host in `http2` is terminated, offered h2, and relayed frame by frame
without decoding. What that gives up, beside `methods` and `paths` (which
is why a `policy` entry cannot name such a host):

- The `:authority` of each request is not read, so it is not held to the
  name the session was opened for, as `Host` is on HTTP/1.1 (a mismatch
  there is answered 421). On a shared front that routes by authority, the
  guest reaches other sites through the listed name, as it can through a
  spliced one.
- The record carries one line for the whole session, not one per request,
  and the status file's `h2_unrecorded` counts those sessions.

List a host here only if it is trusted as a whole, as with `splice`.

## Upgrades

A request with `Upgrade` (a WebSocket, say) is authorised like any other,
by its method and path. Once the origin answers `101 Switching Protocols`,
what flows on the connection is relayed without being read, so an entry's
`methods` and `paths` bound the upgrade request and nothing after it. An
upgrade to `h2c` is never forwarded.

## `internal`

customs does not block private, loopback or link-local destinations
(see [DESIGN.md](DESIGN.md), "Private addresses"), and `internal` does
not open anything. It matters only on a host that has a rule blocking
them, with an exception for each name deliberately given a private
address. `internal` lists those names. When a dial fails:

- to a name that resolves to a private address and is **not** listed,
  it is reported as `internal destination`: the rule refused it, and the
  name needs an exception;
- to anything else, including a listed name, it is reported as
  `upstream unreachable`.

## Port 80

Cleartext requests on port 80 are decided by the same rules, by the
`Host` header. `splice` and `http2` do not apply there. A brokered host
is brokered on port 80 too, and the broker reaches the origin over TLS
either way.
